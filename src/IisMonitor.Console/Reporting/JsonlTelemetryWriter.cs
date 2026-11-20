using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Reporting;

public sealed class JsonlTelemetryWriter : ITelemetryWriter
{
    public const string AnomaliesFileName = "01_INCIDENTS_AND_ANOMALIES.jsonl";
    public const string EventLogFileName = "03_EVENTLOG_FINDINGS.jsonl";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly string _outputDirectory;
    private readonly long _hungRequestThresholdMs;
    private readonly HashSet<string> _generatedFiles = new(StringComparer.OrdinalIgnoreCase);

    private StreamWriter? _timelineWriter;
    private string? _currentTimelineDate;
    private StreamWriter? _anomaliesWriter;
    private StreamWriter? _eventsWriter;
    private bool _disposed;

    public JsonlTelemetryWriter(string outputDirectory, long hungRequestThresholdMs = 10_000)
    {
        _outputDirectory = Path.GetFullPath(outputDirectory);
        _hungRequestThresholdMs = hungRequestThresholdMs;
        Directory.CreateDirectory(_outputDirectory);

        // Pre-create anomalies and eventlog files so the file set is always predictable.
        EnsureAnomaliesWriter();
        EnsureEventsWriter();
    }

    public IReadOnlyList<string> GetGeneratedFiles() =>
        _generatedFiles.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();

    public async Task WriteSnapshotAsync(TelemetrySnapshot snapshot, CancellationToken cancellationToken)
    {
        var writer = EnsureTimelineWriter(snapshot.TimestampUtc);
        var compact = BuildCompactTimelineEntry(snapshot);
        string line = JsonSerializer.Serialize(compact, JsonOptions);
        await writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task WriteAnomaliesAsync(IReadOnlyList<AnomalyEvent> anomalies, CancellationToken cancellationToken)
    {
        if (anomalies.Count == 0) return;

        var writer = EnsureAnomaliesWriter();
        foreach (var anomaly in anomalies)
        {
            string line = JsonSerializer.Serialize(anomaly, JsonOptions);
            await writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task WriteEventFindingsAsync(IReadOnlyList<EventLogFinding> findings, CancellationToken cancellationToken)
    {
        if (findings.Count == 0) return;

        var writer = EnsureEventsWriter();
        foreach (var finding in findings)
        {
            string line = JsonSerializer.Serialize(finding, JsonOptions);
            await writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private object BuildCompactTimelineEntry(TelemetrySnapshot s)
    {
        var workers = s.Iis.Workers.Select(w =>
        {
            s.Tcp.ByPid.TryGetValue(w.Pid, out var tcp);
            var hung = w.ActiveRequests.Where(r => r.TimeElapsedMs >= _hungRequestThresholdMs).ToList();
            return new
            {
                pid = w.Pid,
                appPool = w.AppPoolName,
                wsMb = w.WorkingSetMb,
                threads = w.ThreadCount,
                handles = w.HandleCount,
                activeReqs = w.ActiveRequests.Count,
                hungReqs = hung.Count,
                maxReqMs = w.ActiveRequests.Count > 0 ? w.ActiveRequests.Max(r => r.TimeElapsedMs) : 0,
                topHung = hung.Count > 0
                    ? hung.OrderByDescending(r => r.TimeElapsedMs).Take(3)
                        .Select(r => new { r.Verb, r.Url, r.TimeElapsedMs, r.PipelineState, r.CurrentModule })
                        .ToList()
                    : null,
                dbEstab = tcp?.DbEstablished ?? 0,
                dbCloseWait = tcp?.DbCloseWait ?? 0,
                dbTimeWait = tcp?.DbTimeWait ?? 0,
                totalSockets = tcp?.TotalSockets ?? 0
            };
        }).ToList();

        var adoNet = s.AdoNet.Instances.Select(a => new
        {
            instance = a.InstanceName,
            pid = a.Pid,
            appPool = a.AppPoolName,
            activePools = a.NumberOfActiveConnectionPools,
            pooled = a.NumberOfPooledConnections,
            nonPooled = a.NumberOfNonPooledConnections,
            active = a.NumberOfActiveConnections,
            free = a.NumberOfFreeConnections,
            reclaimed = a.NumberOfReclaimedConnections,
            stasis = a.NumberOfStasisConnections,
            hardConnSec = a.HardConnectsPerSecond,
            softConnSec = a.SoftConnectsPerSecond
        }).ToList();

        var nodeJobs = s.Node.Processes.Select(n => new
        {
            pid = n.Pid,
            job = n.JobLabel,
            uptimeSec = n.UptimeSeconds,
            wsMb = n.WorkingSetMb,
            cpuDeltaMs = n.CpuDeltaMs,
            dbEstab = n.TcpSummary?.DbEstablished ?? 0,
            dbCloseWait = n.TcpSummary?.DbCloseWait ?? 0,
            totalSockets = n.TcpSummary?.TotalSockets ?? 0
        }).ToList();

        var nonZeroQueues = s.AspNetAndClr.HttpQueues
            .Where(q => (q.CurrentQueueSize ?? 0) > 0 || (q.RejectedRequests ?? 0) > 0 || (q.ArrivalRate ?? 0) > 0)
            .ToList();

        return new
        {
            ts = s.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            seq = s.SampleSequence,
            iisSource = s.Iis.Source,
            workers,
            adoNet = adoNet.Count > 0 ? adoNet : null,
            aspNetGlobal = s.AspNetAndClr.AspNetGlobal,
            httpQueues = nonZeroQueues.Count > 0 ? nonZeroQueues : null,
            clr = s.AspNetAndClr.ClrProcesses.Count > 0 ? s.AspNetAndClr.ClrProcesses : null,
            tcpSystem = new
            {
                total = s.Tcp.TotalSystemSockets,
                timeWait = s.Tcp.TotalSystemTimeWait,
                closeWait = s.Tcp.TotalSystemCloseWait,
                dbEstab = s.Tcp.TotalDbEstablished,
                dbCloseWait = s.Tcp.TotalDbCloseWait
            },
            nodeJobs = nodeJobs.Count > 0 ? nodeJobs : null,
            newEvents = s.NewEvents.Count,
            errors = s.CollectorErrors.Count > 0 ? s.CollectorErrors : null
        };
    }

    private StreamWriter EnsureTimelineWriter(DateTimeOffset timestampUtc)
    {
        string dateKey = timestampUtc.UtcDateTime.ToString("yyyy-MM-dd");
        if (_timelineWriter is not null && _currentTimelineDate == dateKey)
        {
            return _timelineWriter;
        }

        _timelineWriter?.Dispose();
        string fileName = $"02_TIMELINE_METRICS_{dateKey}.jsonl";
        string fullPath = Path.Combine(_outputDirectory, fileName);
        _timelineWriter = OpenAppendWriter(fullPath);
        _currentTimelineDate = dateKey;
        _generatedFiles.Add(fileName);
        return _timelineWriter;
    }

    private StreamWriter EnsureAnomaliesWriter()
    {
        if (_anomaliesWriter is not null) return _anomaliesWriter;
        string fullPath = Path.Combine(_outputDirectory, AnomaliesFileName);
        _anomaliesWriter = OpenAppendWriter(fullPath);
        _generatedFiles.Add(AnomaliesFileName);
        return _anomaliesWriter;
    }

    private StreamWriter EnsureEventsWriter()
    {
        if (_eventsWriter is not null) return _eventsWriter;
        string fullPath = Path.Combine(_outputDirectory, EventLogFileName);
        _eventsWriter = OpenAppendWriter(fullPath);
        _generatedFiles.Add(EventLogFileName);
        return _eventsWriter;
    }

    private static StreamWriter OpenAppendWriter(string path)
    {
        var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        return new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timelineWriter?.Dispose();
        _anomaliesWriter?.Dispose();
        _eventsWriter?.Dispose();
    }
}
