using System.Globalization;
using IisMonitor.Abstractions;
using IisMonitor.Collectors;
using IisMonitor.Domain;

namespace IisMonitor.Analysis;

public sealed class AnomalyDetector : IAnomalyDetector
{
    private static readonly HashSet<string> CooldownExemptCodes = new(StringComparer.Ordinal)
    {
        "APPPOOL_RECYCLE_OR_CRASH",
        "DB_POOL_TIMEOUT_EVENT",
        "ASPNET_REQUESTS_REJECTED",
        "CONNECTION_LEAK_RECLAIMED"
    };

    private readonly Dictionary<string, int> _lastPidByAppPool = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double> _lastReclaimedByInstance = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Code, string Target), (DateTimeOffset EmittedAtUtc, AnomalySeverity Severity)> _cooldownState = new();
    private double? _lastAspNetRequestsRejected;

    public IReadOnlyList<AnomalyEvent> Analyze(TelemetrySnapshot snapshot, MonitorConfig config)
    {
        var rawAnomalies = new List<AnomalyEvent>();
        var t = config.Thresholds;
        var now = snapshot.TimestampUtc;

        AnalyzeAppPoolRecyclesAndHungRequests(snapshot, t, now, rawAnomalies);
        AnalyzeAdoNetPools(snapshot, t, now, rawAnomalies);
        AnalyzeTcpSockets(snapshot, t, now, rawAnomalies);
        AnalyzeQueuesAndClr(snapshot, t, now, rawAnomalies);
        AnalyzeNodeProcesses(snapshot, config, t, now, rawAnomalies);
        AnalyzeEventLogs(snapshot, now, rawAnomalies);

        return ApplyCooldown(rawAnomalies, now, config.AnomalyCooldownSeconds);
    }

    private List<AnomalyEvent> ApplyCooldown(
        List<AnomalyEvent> candidates,
        DateTimeOffset nowUtc,
        int cooldownSeconds)
    {
        if (cooldownSeconds <= 0 || candidates.Count == 0)
        {
            return candidates;
        }

        var cooldown = TimeSpan.FromSeconds(cooldownSeconds);
        var emitted = new List<AnomalyEvent>(candidates.Count);

        foreach (var anomaly in candidates)
        {
            if (CooldownExemptCodes.Contains(anomaly.Code))
            {
                emitted.Add(anomaly);
                continue;
            }

            var key = (anomaly.Code, anomaly.TargetName.ToUpperInvariant());
            var severity = ParseSeverity(anomaly.Severity);

            if (_cooldownState.TryGetValue(key, out var prev))
            {
                bool withinCooldown = (nowUtc - prev.EmittedAtUtc) < cooldown;
                bool escalated = severity > prev.Severity;

                if (withinCooldown && !escalated)
                {
                    continue;
                }
            }

            _cooldownState[key] = (nowUtc, severity);
            emitted.Add(anomaly);
        }

        // Bound cooldown dictionary over long 72h runs.
        if (_cooldownState.Count > 500)
        {
            var expiry = TimeSpan.FromSeconds(Math.Max(cooldownSeconds * 2, 3600));
            var expiredKeys = _cooldownState
                .Where(kv => (nowUtc - kv.Value.EmittedAtUtc) > expiry)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var k in expiredKeys)
            {
                _cooldownState.Remove(k);
            }
        }

        return emitted;
    }

    private static AnomalySeverity ParseSeverity(string severity) =>
        Enum.TryParse<AnomalySeverity>(severity, ignoreCase: true, out var parsed)
            ? parsed
            : AnomalySeverity.MEDIUM;

    private void AnalyzeAppPoolRecyclesAndHungRequests(
        TelemetrySnapshot snapshot,
        ThresholdConfig t,
        DateTimeOffset now,
        List<AnomalyEvent> anomalies)
    {
        var workersByPool = snapshot.Iis.Workers
            .GroupBy(w => w.AppPoolName, StringComparer.OrdinalIgnoreCase);

        foreach (var group in workersByPool)
        {
            string poolName = group.Key;
            var primaryWorker = group.OrderByDescending(w => w.StartTimeUtc ?? DateTimeOffset.MinValue).First();

            if (_lastPidByAppPool.TryGetValue(poolName, out int prevPid) && prevPid != primaryWorker.Pid)
            {
                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: nameof(AnomalySeverity.HIGH),
                    Code: "APPPOOL_RECYCLE_OR_CRASH",
                    TargetType: "AppPool",
                    TargetName: poolName,
                    Pid: primaryWorker.Pid,
                    Summary: $"AppPool '{poolName}' worker PID changed from {prevPid} to {primaryWorker.Pid} (recycle or crash).",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["previousPid"] = prevPid,
                        ["newPid"] = primaryWorker.Pid,
                        ["workerCount"] = group.Count()
                    }));
            }
            _lastPidByAppPool[poolName] = primaryWorker.Pid;

            foreach (var worker in group)
            {
                var hungRequests = worker.ActiveRequests
                    .Where(r => r.TimeElapsedMs >= t.HungRequestThresholdMs)
                    .OrderByDescending(r => r.TimeElapsedMs)
                    .ToList();

                if (hungRequests.Count > 0)
                {
                    long maxElapsed = hungRequests[0].TimeElapsedMs;
                    string severity = maxElapsed >= t.CriticalHungRequestThresholdMs || hungRequests.Count >= 10
                        ? nameof(AnomalySeverity.CRITICAL)
                        : nameof(AnomalySeverity.HIGH);

                    var sampleUrls = hungRequests.Take(3)
                        .Select(r => $"{r.Verb} {r.Url} ({r.TimeElapsedMs}ms, {r.PipelineState}/{r.CurrentModule})")
                        .ToList();

                    anomalies.Add(new AnomalyEvent(
                        TimestampUtc: now,
                        Severity: severity,
                        Code: "HUNG_REQUESTS",
                        TargetType: "AppPool",
                        TargetName: poolName,
                        Pid: worker.Pid,
                        Summary: $"AppPool '{poolName}' (PID {worker.Pid}) has {hungRequests.Count} hung request(s); longest={maxElapsed}ms.",
                        Metrics: new Dictionary<string, object?>
                        {
                            ["hungCount"] = hungRequests.Count,
                            ["totalActiveRequests"] = worker.ActiveRequests.Count,
                            ["maxElapsedMs"] = maxElapsed,
                            ["sampleUrls"] = sampleUrls
                        }));
                }
            }
        }
    }

    private void AnalyzeAdoNetPools(
        TelemetrySnapshot snapshot,
        ThresholdConfig t,
        DateTimeOffset now,
        List<AnomalyEvent> anomalies)
    {
        var activeInstances = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pool in snapshot.AdoNet.Instances)
        {
            activeInstances.Add(pool.InstanceName);
            string target = pool.AppPoolName ?? pool.InstanceName;

            double effectiveCount = Math.Max(
                pool.NumberOfActiveConnections ?? 0,
                pool.NumberOfPooledConnections ?? 0);

            if (effectiveCount >= t.ConnectionPoolWarningCount)
            {
                string severity = effectiveCount >= t.ConnectionPoolCriticalCount
                    ? nameof(AnomalySeverity.CRITICAL)
                    : nameof(AnomalySeverity.HIGH);

                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: severity,
                    Code: "CONNECTION_POOL_EXHAUSTION",
                    TargetType: pool.AppPoolName is not null ? "AppPool" : "AdoNetInstance",
                    TargetName: target,
                    Pid: pool.Pid,
                    Summary: $"ADO.NET pool saturation on '{target}' (pooled={pool.NumberOfPooledConnections}, active={pool.NumberOfActiveConnections}, free={pool.NumberOfFreeConnections}).",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["instance"] = pool.InstanceName,
                        ["pooled"] = pool.NumberOfPooledConnections,
                        ["active"] = pool.NumberOfActiveConnections,
                        ["free"] = pool.NumberOfFreeConnections,
                        ["stasis"] = pool.NumberOfStasisConnections,
                        ["reclaimed"] = pool.NumberOfReclaimedConnections
                    }));
            }

            if (pool.NumberOfReclaimedConnections.HasValue)
            {
                double currentReclaimed = pool.NumberOfReclaimedConnections.Value;
                if (_lastReclaimedByInstance.TryGetValue(pool.InstanceName, out double prevReclaimed))
                {
                    double delta = currentReclaimed - prevReclaimed;
                    if (delta > 0)
                    {
                        anomalies.Add(new AnomalyEvent(
                            TimestampUtc: now,
                            Severity: delta >= 5 ? nameof(AnomalySeverity.CRITICAL) : nameof(AnomalySeverity.HIGH),
                            Code: "CONNECTION_LEAK_RECLAIMED",
                            TargetType: pool.AppPoolName is not null ? "AppPool" : "AdoNetInstance",
                            TargetName: target,
                            Pid: pool.Pid,
                            Summary: $"ADO.NET reclaimed {delta:0} leaked/unclosed DB connection(s) via GC on '{target}' (total={currentReclaimed:0}).",
                            Metrics: new Dictionary<string, object?>
                            {
                                ["instance"] = pool.InstanceName,
                                ["reclaimedDelta"] = delta,
                                ["reclaimedTotal"] = currentReclaimed,
                                ["pooled"] = pool.NumberOfPooledConnections
                            }));
                    }
                }
                _lastReclaimedByInstance[pool.InstanceName] = currentReclaimed;
            }
        }

        // Prune departed instances to keep memory bounded.
        var stale = _lastReclaimedByInstance.Keys.Where(k => !activeInstances.Contains(k)).ToList();
        foreach (string key in stale)
        {
            _lastReclaimedByInstance.Remove(key);
        }
    }

    private static void AnalyzeTcpSockets(
        TelemetrySnapshot snapshot,
        ThresholdConfig t,
        DateTimeOffset now,
        List<AnomalyEvent> anomalies)
    {
        var pidToName = new Dictionary<int, (string Type, string Name)>();
        foreach (var w in snapshot.Iis.Workers)
        {
            pidToName[w.Pid] = ("AppPool", w.AppPoolName);
        }
        foreach (var n in snapshot.Node.Processes)
        {
            pidToName[n.Pid] = ("NodeJob", n.JobLabel);
        }

        foreach (var (pid, tcp) in snapshot.Tcp.ByPid)
        {
            var (targetType, targetName) = pidToName.TryGetValue(pid, out var info)
                ? info
                : ("Process", $"pid_{pid}");

            if (tcp.DbEstablished >= t.DbEstablishedWarningCount)
            {
                string severity = tcp.DbEstablished >= t.DbEstablishedCriticalCount
                    ? nameof(AnomalySeverity.CRITICAL)
                    : nameof(AnomalySeverity.HIGH);

                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: severity,
                    Code: "CONNECTION_POOL_EXHAUSTION",
                    TargetType: targetType,
                    TargetName: targetName,
                    Pid: pid,
                    Summary: $"High DB ESTABLISHED TCP sockets ({tcp.DbEstablished}) held by {targetType} '{targetName}' (PID {pid}).",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["dbEstablished"] = tcp.DbEstablished,
                        ["dbCloseWait"] = tcp.DbCloseWait,
                        ["dbTimeWait"] = tcp.DbTimeWait,
                        ["topEndpoints"] = tcp.TopDbEndpoints.Take(3).Select(e => $"{e.RemoteEndpoint}({e.EstablishedCount}E/{e.CloseWaitCount}CW)").ToList()
                    }));
            }

            if (tcp.DbCloseWait >= t.DbCloseWaitWarningCount)
            {
                string severity = tcp.DbCloseWait >= t.DbCloseWaitCriticalCount
                    ? nameof(AnomalySeverity.CRITICAL)
                    : nameof(AnomalySeverity.HIGH);

                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: severity,
                    Code: "TCP_CLOSE_WAIT_LEAK",
                    TargetType: targetType,
                    TargetName: targetName,
                    Pid: pid,
                    Summary: $"{tcp.DbCloseWait} DB TCP socket(s) stuck in CLOSE_WAIT on {targetType} '{targetName}' (PID {pid}) — indicates unclosed connections.",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["dbCloseWait"] = tcp.DbCloseWait,
                        ["dbEstablished"] = tcp.DbEstablished,
                        ["topEndpoints"] = tcp.TopDbEndpoints.Take(3).Select(e => $"{e.RemoteEndpoint}({e.CloseWaitCount}CW)").ToList()
                    }));
            }
        }

        if (snapshot.Tcp.TotalSystemTimeWait >= t.TimeWaitChurnCount)
        {
            anomalies.Add(new AnomalyEvent(
                TimestampUtc: now,
                Severity: nameof(AnomalySeverity.MEDIUM),
                Code: "TCP_TIME_WAIT_CHURN",
                TargetType: "Server",
                TargetName: snapshot.MachineName,
                Pid: null,
                Summary: $"High system-wide TIME_WAIT socket count ({snapshot.Tcp.TotalSystemTimeWait}) — possible connection churn or disabled pooling.",
                Metrics: new Dictionary<string, object?>
                {
                    ["totalTimeWait"] = snapshot.Tcp.TotalSystemTimeWait,
                    ["totalCloseWait"] = snapshot.Tcp.TotalSystemCloseWait,
                    ["totalSockets"] = snapshot.Tcp.TotalSystemSockets
                }));
        }
    }

    private void AnalyzeQueuesAndClr(
        TelemetrySnapshot snapshot,
        ThresholdConfig t,
        DateTimeOffset now,
        List<AnomalyEvent> anomalies)
    {
        var asp = snapshot.AspNetAndClr.AspNetGlobal;
        if (asp?.RequestsQueued is { } queued && queued >= t.AspNetQueueWarningCount)
        {
            anomalies.Add(new AnomalyEvent(
                TimestampUtc: now,
                Severity: queued >= t.AspNetQueueWarningCount * 3 ? nameof(AnomalySeverity.CRITICAL) : nameof(AnomalySeverity.HIGH),
                Code: "ASPNET_QUEUE_BUILDUP",
                TargetType: "Server",
                TargetName: "ASP.NET v4.0.30319",
                Pid: null,
                Summary: $"ASP.NET global request queue buildup: {queued:0} queued, {asp.RequestsCurrent:0} current, wait={asp.RequestWaitTimeMs:0}ms.",
                Metrics: new Dictionary<string, object?>
                {
                    ["requestsQueued"] = queued,
                    ["requestsCurrent"] = asp.RequestsCurrent,
                    ["requestsRejected"] = asp.RequestsRejected,
                    ["requestWaitTimeMs"] = asp.RequestWaitTimeMs
                }));
        }

        if (asp?.RequestsRejected is { } rejected)
        {
            if (_lastAspNetRequestsRejected.HasValue)
            {
                double delta = rejected - _lastAspNetRequestsRejected.Value;
                if (delta > 0)
                {
                    anomalies.Add(new AnomalyEvent(
                        TimestampUtc: now,
                        Severity: delta >= 10 ? nameof(AnomalySeverity.CRITICAL) : nameof(AnomalySeverity.HIGH),
                        Code: "ASPNET_REQUESTS_REJECTED",
                        TargetType: "Server",
                        TargetName: "ASP.NET v4.0.30319",
                        Pid: null,
                        Summary: $"ASP.NET rejected {delta:0} request(s) since previous sample (total={rejected:0}, queued={asp.RequestsQueued:0}).",
                        Metrics: new Dictionary<string, object?>
                        {
                            ["requestsRejectedDelta"] = delta,
                            ["requestsRejectedTotal"] = rejected,
                            ["requestsQueued"] = asp.RequestsQueued
                        }));
                }
            }
            _lastAspNetRequestsRejected = rejected;
        }

        foreach (var q in snapshot.AspNetAndClr.HttpQueues)
        {
            if (q.CurrentQueueSize is { } qSize && qSize >= t.HttpQueueWarningCount)
            {
                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: qSize >= t.HttpQueueWarningCount * 3 ? nameof(AnomalySeverity.CRITICAL) : nameof(AnomalySeverity.HIGH),
                    Code: "HTTP_QUEUE_BUILDUP",
                    TargetType: "AppPool",
                    TargetName: q.AppPoolName,
                    Pid: null,
                    Summary: $"HTTP.sys request queue buildup for '{q.AppPoolName}': queue={qSize:0}, arrivalRate={q.ArrivalRate:0.##}/s, rejected={q.RejectedRequests:0}.",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["currentQueueSize"] = qSize,
                        ["arrivalRate"] = q.ArrivalRate,
                        ["rejectedRequests"] = q.RejectedRequests
                    }));
            }
        }

        foreach (var clr in snapshot.AspNetAndClr.ClrProcesses)
        {
            string target = clr.AppPoolName ?? clr.InstanceName;
            if (clr.ContentionRatePerSec is { } contention && contention >= t.ThreadContentionPerSecWarning)
            {
                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: nameof(AnomalySeverity.HIGH),
                    Code: "THREAD_CONTENTION",
                    TargetType: clr.AppPoolName is not null ? "AppPool" : "ClrProcess",
                    TargetName: target,
                    Pid: clr.Pid,
                    Summary: $"High CLR lock contention on '{target}': {contention:0.##}/s (queue={clr.CurrentLockQueueLength:0}, logicalThreads={clr.LogicalThreads:0}).",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["contentionRatePerSec"] = contention,
                        ["currentLockQueueLength"] = clr.CurrentLockQueueLength,
                        ["logicalThreads"] = clr.LogicalThreads,
                        ["physicalThreads"] = clr.PhysicalThreads
                    }));
            }

            if (clr.ExceptionsThrownPerSec is { } exRate && exRate >= t.ExceptionsPerSecWarning)
            {
                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: nameof(AnomalySeverity.MEDIUM),
                    Code: "EXCEPTION_STORM",
                    TargetType: clr.AppPoolName is not null ? "AppPool" : "ClrProcess",
                    TargetName: target,
                    Pid: clr.Pid,
                    Summary: $"High CLR exception rate on '{target}': {exRate:0.##} exceptions/sec.",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["exceptionsPerSec"] = exRate,
                        ["percentTimeInGc"] = clr.PercentTimeInGc
                    }));
            }

            if (clr.PercentTimeInGc is { } gcPct && gcPct >= t.HighGcTimeWarningPercent)
            {
                string severity = gcPct >= t.HighGcTimeCriticalPercent
                    ? nameof(AnomalySeverity.CRITICAL)
                    : nameof(AnomalySeverity.HIGH);

                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: severity,
                    Code: "HIGH_GC_TIME",
                    TargetType: clr.AppPoolName is not null ? "AppPool" : "ClrProcess",
                    TargetName: target,
                    Pid: clr.Pid,
                    Summary: $"High CLR GC time on '{target}': {gcPct.ToString("0.#", CultureInfo.InvariantCulture)}% in GC (gen2={clr.Gen2HeapSizeMb?.ToString("0.#", CultureInfo.InvariantCulture) ?? "n/a"}MB, totalHeap={clr.TotalHeapSizeMb?.ToString("0.#", CultureInfo.InvariantCulture) ?? "n/a"}MB).",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["percentTimeInGc"] = gcPct,
                        ["gen2HeapSizeMb"] = clr.Gen2HeapSizeMb,
                        ["totalHeapSizeMb"] = clr.TotalHeapSizeMb
                    }));
            }
        }
    }

    private static void AnalyzeNodeProcesses(
        TelemetrySnapshot snapshot,
        MonitorConfig config,
        ThresholdConfig t,
        DateTimeOffset now,
        List<AnomalyEvent> anomalies)
    {
        double zombieThresholdSec = t.NodeZombieUptimeMinutes * 60.0;
        var ignorePatterns = config.GetNormalizedNodeIgnorePatterns();

        foreach (var node in snapshot.Node.Processes)
        {
            if (ignorePatterns.Count > 0 && MatchesAnyIgnorePattern(node, ignorePatterns))
            {
                continue;
            }

            if (!node.UptimeSeconds.HasValue || node.UptimeSeconds.Value < zombieThresholdSec)
            {
                continue;
            }

            int dbOpen = (node.TcpSummary?.DbEstablished ?? 0) + (node.TcpSummary?.DbCloseWait ?? 0);
            bool cpuStalled = node.CpuDeltaMs.HasValue && node.CpuDeltaMs.Value <= t.NodeStalledCpuDeltaMs;

            if (dbOpen > 0 || cpuStalled)
            {
                string severity = dbOpen > 0
                    ? nameof(AnomalySeverity.HIGH)
                    : nameof(AnomalySeverity.MEDIUM);

                string uptimeText = (node.UptimeSeconds.Value / 60.0).ToString("0.#", CultureInfo.InvariantCulture);
                string cpuDeltaText = node.CpuDeltaMs.HasValue
                    ? $"{node.CpuDeltaMs.Value.ToString("0.#", CultureInfo.InvariantCulture)}ms"
                    : "n/a";

                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: now,
                    Severity: severity,
                    Code: "NODE_ZOMBIE_JOB",
                    TargetType: "NodeJob",
                    TargetName: node.JobLabel,
                    Pid: node.Pid,
                    Summary: $"Long-running Node.js job '{node.JobLabel}' (PID {node.Pid}) uptime={uptimeText}m, DB sockets={dbOpen}, cpuDelta={cpuDeltaText}.",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["uptimeMinutes"] = Math.Round(node.UptimeSeconds.Value / 60.0, 1),
                        ["dbEstablished"] = node.TcpSummary?.DbEstablished ?? 0,
                        ["dbCloseWait"] = node.TcpSummary?.DbCloseWait ?? 0,
                        ["cpuDeltaMs"] = node.CpuDeltaMs,
                        ["workingSetMb"] = node.WorkingSetMb
                    }));
            }
        }
    }

    private static bool MatchesAnyIgnorePattern(NodeProcessSnapshot node, IReadOnlyList<string> patterns)
    {
        foreach (string pattern in patterns)
        {
            if (node.JobLabel.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                node.CommandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static void AnalyzeEventLogs(
        TelemetrySnapshot snapshot,
        DateTimeOffset now,
        List<AnomalyEvent> anomalies)
    {
        foreach (var ev in snapshot.NewEvents)
        {
            if (ev.IsSqlPoolTimeout)
            {
                string snippet = WindowsEventLogCollector.ExtractHighSignalSnippet(ev.Source, ev.EventId, ev.Message, 220);
                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: ev.TimestampUtc,
                    Severity: nameof(AnomalySeverity.CRITICAL),
                    Code: "DB_POOL_TIMEOUT_EVENT",
                    TargetType: "EventLog",
                    TargetName: $"{ev.LogName}/{ev.Source}",
                    Pid: null,
                    Summary: $"EventLog SQL connection pool timeout (EventID {ev.EventId}): {snippet}",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["logName"] = ev.LogName,
                        ["eventId"] = ev.EventId,
                        ["recordId"] = ev.RecordId,
                        ["source"] = ev.Source
                    }));
            }

            if (ev.IsWasRecycleOrCrash)
            {
                string snippet = WindowsEventLogCollector.ExtractHighSignalSnippet(ev.Source, ev.EventId, ev.Message, 220);
                anomalies.Add(new AnomalyEvent(
                    TimestampUtc: ev.TimestampUtc,
                    Severity: nameof(AnomalySeverity.HIGH),
                    Code: "APPPOOL_RECYCLE_OR_CRASH",
                    TargetType: "EventLog",
                    TargetName: $"{ev.LogName}/{ev.Source}",
                    Pid: null,
                    Summary: $"IIS/WAS recycle or crash event (EventID {ev.EventId}): {snippet}",
                    Metrics: new Dictionary<string, object?>
                    {
                        ["logName"] = ev.LogName,
                        ["eventId"] = ev.EventId,
                        ["recordId"] = ev.RecordId,
                        ["source"] = ev.Source
                    }));
            }
        }
    }
}
