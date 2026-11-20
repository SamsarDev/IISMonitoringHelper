using IisMonitor.Abstractions;
using IisMonitor.Analysis;
using IisMonitor.Domain;

namespace IisMonitor.Engine;

public sealed class MonitorRunner
{
    private readonly MonitorConfig _config;
    private readonly IClock _clock;
    private readonly IIisWorkerProcessCollector _iisCollector;
    private readonly IAdoNetPoolCollector _adoNetCollector;
    private readonly IAspNetAndClrCollector _aspNetAndClrCollector;
    private readonly ITcpSocketCollector _tcpCollector;
    private readonly INodeProcessCollector _nodeCollector;
    private readonly IWindowsEventLogCollector _eventLogCollector;
    private readonly IAnomalyDetector _anomalyDetector;
    private readonly ITelemetryWriter _telemetryWriter;
    private readonly IExecutiveSummaryWriter _summaryWriter;
    private readonly Action<string> _log;

    public MonitorRunner(
        MonitorConfig config,
        IClock clock,
        IIisWorkerProcessCollector iisCollector,
        IAdoNetPoolCollector adoNetCollector,
        IAspNetAndClrCollector aspNetAndClrCollector,
        ITcpSocketCollector tcpCollector,
        INodeProcessCollector nodeCollector,
        IWindowsEventLogCollector eventLogCollector,
        IAnomalyDetector anomalyDetector,
        ITelemetryWriter telemetryWriter,
        IExecutiveSummaryWriter summaryWriter,
        Action<string>? log = null)
    {
        _config = config;
        _clock = clock;
        _iisCollector = iisCollector;
        _adoNetCollector = adoNetCollector;
        _aspNetAndClrCollector = aspNetAndClrCollector;
        _tcpCollector = tcpCollector;
        _nodeCollector = nodeCollector;
        _eventLogCollector = eventLogCollector;
        _anomalyDetector = anomalyDetector;
        _telemetryWriter = telemetryWriter;
        _summaryWriter = summaryWriter;
        _log = log ?? Console.WriteLine;
    }

    public async Task<ExecutiveSummaryReport> RunAsync(CancellationToken cancellationToken)
    {
        _config.Normalize();
        var startUtc = _clock.UtcNow;
        var deadlineUtc = startUtc + _config.EffectiveDuration;
        var checkpointInterval = TimeSpan.FromMinutes(_config.CheckpointIntervalMinutes);
        var nextCheckpointUtc = startUtc + checkpointInterval;

        var dbPorts = _config.GetDbPortSet();
        var appPoolFilter = _config.GetAppPoolFilterSet();
        var aggregator = new RollingAggregator(Environment.MachineName, startUtc, _config);

        _log($"[{startUtc:yyyy-MM-ddTHH:mm:ssZ}] IisMonitor started on {Environment.MachineName}. Duration={_config.EffectiveDuration}, Interval={_config.SampleIntervalSeconds}s, Output={Path.GetFullPath(_config.OutputDirectory)}");

        long sampleSeq = 0;
        var interval = TimeSpan.FromSeconds(_config.SampleIntervalSeconds);

        try
        {
            while (!cancellationToken.IsCancellationRequested && (sampleSeq == 0 || _clock.UtcNow < deadlineUtc))
            {
                sampleSeq++;
                var sampleUtc = _clock.UtcNow;

                var snapshot = CollectSnapshotSafe(sampleUtc, sampleSeq, dbPorts, appPoolFilter);
                var anomalies = _anomalyDetector.Analyze(snapshot, _config);

                aggregator.RecordSample(snapshot, anomalies);

                await _telemetryWriter.WriteSnapshotAsync(snapshot, CancellationToken.None).ConfigureAwait(false);
                await _telemetryWriter.WriteAnomaliesAsync(anomalies, CancellationToken.None).ConfigureAwait(false);
                await _telemetryWriter.WriteEventFindingsAsync(snapshot.NewEvents, CancellationToken.None).ConfigureAwait(false);

                if (anomalies.Count > 0)
                {
                    _log($"[{sampleUtc:HH:mm:ss}Z] Sample #{sampleSeq}: {anomalies.Count} anomaly(ies) detected ({string.Join(", ", anomalies.Select(a => a.Code).Distinct())}).");
                }
                else if (sampleSeq == 1 || sampleSeq % 20 == 0)
                {
                    _log($"[{sampleUtc:HH:mm:ss}Z] Sample #{sampleSeq}: OK (w3wp={snapshot.Iis.Workers.Count}, node={snapshot.Node.Processes.Count}, dbEstab={snapshot.Tcp.TotalDbEstablished}, dbCloseWait={snapshot.Tcp.TotalDbCloseWait}).");
                }

                if (sampleUtc >= nextCheckpointUtc)
                {
                    var checkpoint = aggregator.BuildReport(_clock.UtcNow, isFinal: false, _telemetryWriter.GetGeneratedFiles());
                    await _summaryWriter.WriteSummaryAsync(checkpoint, CancellationToken.None).ConfigureAwait(false);
                    nextCheckpointUtc = sampleUtc + checkpointInterval;
                    _log($"[{sampleUtc:HH:mm:ss}Z] Hourly checkpoint written to 00_AI_EXECUTIVE_SUMMARY.txt.");
                }

                if (_config.RunOnce)
                {
                    break;
                }

                var nowAfterSample = _clock.UtcNow;
                if (nowAfterSample >= deadlineUtc)
                {
                    break;
                }

                var remaining = deadlineUtc - nowAfterSample;
                var delay = remaining < interval ? remaining : interval;
                if (delay <= TimeSpan.Zero)
                {
                    break;
                }

                try
                {
                    await _clock.DelayAsync(delay, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        finally
        {
            // Always flush final summary on completion or Ctrl+C / SIGTERM.
            var finalReport = aggregator.BuildReport(_clock.UtcNow, isFinal: true, _telemetryWriter.GetGeneratedFiles());
            await _summaryWriter.WriteSummaryAsync(finalReport, CancellationToken.None).ConfigureAwait(false);
            _log($"[{_clock.UtcNow:yyyy-MM-ddTHH:mm:ssZ}] Final executive summary written. Total samples={finalReport.TotalSamples}.");
        }

        return aggregator.BuildReport(_clock.UtcNow, isFinal: true, _telemetryWriter.GetGeneratedFiles());
    }

    private TelemetrySnapshot CollectSnapshotSafe(
        DateTimeOffset nowUtc,
        long sequence,
        IReadOnlySet<int> dbPorts,
        IReadOnlySet<string> appPoolFilter)
    {
        var errors = new List<string>();

        IisCollectionResult iis;
        try
        {
            iis = _iisCollector.Collect(appPoolFilter);
        }
        catch (Exception ex)
        {
            errors.Add($"IisCollector error: {ex.Message}");
            iis = new IisCollectionResult("ERROR", [], []);
        }

        var pidToAppPool = new Dictionary<int, string>();
        foreach (var w in iis.Workers)
        {
            pidToAppPool[w.Pid] = w.AppPoolName;
        }

        TcpCollectionResult tcp;
        try
        {
            tcp = _tcpCollector.Collect(dbPorts);
        }
        catch (Exception ex)
        {
            errors.Add($"TcpCollector error: {ex.Message}");
            tcp = new TcpCollectionResult(new Dictionary<int, PidTcpSocketSummary>(), 0, 0, 0, 0, 0, []);
        }

        AdoNetCollectionResult adoNet;
        try
        {
            adoNet = _adoNetCollector.Collect(pidToAppPool);
        }
        catch (Exception ex)
        {
            errors.Add($"AdoNetCollector error: {ex.Message}");
            adoNet = new AdoNetCollectionResult(false, false, [], []);
        }

        AspNetAndClrCollectionResult aspClr;
        try
        {
            aspClr = _aspNetAndClrCollector.Collect(pidToAppPool);
        }
        catch (Exception ex)
        {
            errors.Add($"AspNetAndClrCollector error: {ex.Message}");
            aspClr = new AspNetAndClrCollectionResult(null, [], [], [], []);
        }

        NodeCollectionResult node;
        try
        {
            node = _nodeCollector.Collect(nowUtc, tcp.ByPid);
        }
        catch (Exception ex)
        {
            errors.Add($"NodeCollector error: {ex.Message}");
            node = new NodeCollectionResult([], []);
        }

        EventLogCollectionResult events;
        try
        {
            events = _eventLogCollector.Collect(nowUtc);
        }
        catch (Exception ex)
        {
            errors.Add($"EventLogCollector error: {ex.Message}");
            events = new EventLogCollectionResult([], []);
        }

        if (events.Warnings.Count > 0)
        {
            errors.AddRange(events.Warnings);
        }

        return new TelemetrySnapshot(
            TimestampUtc: nowUtc,
            SampleSequence: sequence,
            MachineName: Environment.MachineName,
            Iis: iis,
            AdoNet: adoNet,
            AspNetAndClr: aspClr,
            Tcp: tcp,
            Node: node,
            NewEvents: events.Findings,
            CollectorErrors: errors);
    }
}
