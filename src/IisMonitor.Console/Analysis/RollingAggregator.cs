using IisMonitor.Domain;

namespace IisMonitor.Analysis;

public sealed class RollingAggregator
{
    private const int MaxStoredIncidents = 500;
    private const int MaxEnvironmentWarnings = 20;

    private readonly string _machineName;
    private readonly DateTimeOffset _runStartUtc;
    private readonly MonitorConfig _config;

    private readonly Dictionary<string, AppPoolAccumulator> _appPools = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NodeJobAccumulator> _nodeJobs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _anomalyCountsByCode = new(StringComparer.Ordinal);
    private readonly Dictionary<string, double> _lastReclaimedByPool = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _environmentWarnings = new(StringComparer.Ordinal);
    private readonly List<IncidentAccumulator> _incidents = [];

    private IncidentAccumulator? _activeIncident;
    private int _nextIncidentId = 1;
    private long _totalSamples;
    private DateTimeOffset _lastSampleUtc;
    private bool _iisAdminAvailable;
    private bool _adoNetCategoryAvailable;
    private bool _adoNetActiveConnectionsAvailable;

    public RollingAggregator(string machineName, DateTimeOffset runStartUtc, MonitorConfig config)
    {
        _machineName = machineName;
        _runStartUtc = runStartUtc;
        _lastSampleUtc = runStartUtc;
        _config = config;
    }

    public void RecordSample(TelemetrySnapshot snapshot, IReadOnlyList<AnomalyEvent> anomalies)
    {
        _totalSamples++;
        _lastSampleUtc = snapshot.TimestampUtc;

        if (snapshot.Iis.Source == "IIS_ADMIN") _iisAdminAvailable = true;
        if (snapshot.AdoNet.CategoryAvailable) _adoNetCategoryAvailable = true;
        if (snapshot.AdoNet.ActiveConnectionsCounterAvailable) _adoNetActiveConnectionsAvailable = true;

        RecordWarnings(snapshot.Iis.Warnings);
        RecordWarnings(snapshot.AdoNet.Warnings);
        RecordWarnings(snapshot.AspNetAndClr.Warnings);
        RecordWarnings(snapshot.Tcp.Warnings);
        RecordWarnings(snapshot.Node.Warnings);
        RecordWarnings(snapshot.CollectorErrors);

        // Update AppPool stats
        foreach (var w in snapshot.Iis.Workers)
        {
            var acc = GetOrCreateAppPool(w.AppPoolName);
            acc.RecordWorker(w, snapshot.Tcp.ByPid.GetValueOrDefault(w.Pid), _config.Thresholds.HungRequestThresholdMs);
        }

        // Update ADO.NET stats per AppPool
        foreach (var ado in snapshot.AdoNet.Instances)
        {
            string poolKey = ado.AppPoolName ?? ado.InstanceName;
            var acc = GetOrCreateAppPool(poolKey);
            double reclaimedDelta = 0;
            if (ado.NumberOfReclaimedConnections.HasValue)
            {
                if (_lastReclaimedByPool.TryGetValue(ado.InstanceName, out double prev) &&
                    ado.NumberOfReclaimedConnections.Value > prev)
                {
                    reclaimedDelta = ado.NumberOfReclaimedConnections.Value - prev;
                }
                _lastReclaimedByPool[ado.InstanceName] = ado.NumberOfReclaimedConnections.Value;
            }
            acc.RecordAdoNet(ado, reclaimedDelta);
        }

        // Update HTTP queue stats per AppPool
        foreach (var hq in snapshot.AspNetAndClr.HttpQueues)
        {
            if (_appPools.TryGetValue(hq.AppPoolName, out var acc) && hq.CurrentQueueSize.HasValue)
            {
                acc.RecordHttpQueue(hq.CurrentQueueSize.Value);
            }
        }

        // Update Node.js job stats
        foreach (var n in snapshot.Node.Processes)
        {
            if (!_nodeJobs.TryGetValue(n.JobLabel, out var acc))
            {
                acc = new NodeJobAccumulator(n.JobLabel, n.CommandLine);
                _nodeJobs[n.JobLabel] = acc;
            }
            acc.Record(n);
        }

        // Update anomaly counts & cluster into IncidentWindows
        if (anomalies.Count > 0)
        {
            foreach (var anomaly in anomalies)
            {
                _anomalyCountsByCode[anomaly.Code] = _anomalyCountsByCode.TryGetValue(anomaly.Code, out int c) ? c + 1 : 1;

                if (anomaly.Code == "APPPOOL_RECYCLE_OR_CRASH" && anomaly.TargetType == "AppPool")
                {
                    GetOrCreateAppPool(anomaly.TargetName).RecycleCount++;
                }

                if (anomaly.Code == "NODE_ZOMBIE_JOB" && _nodeJobs.TryGetValue(anomaly.TargetName, out var nodeAcc))
                {
                    nodeAcc.ZombieDetections++;
                }
            }

            ClusterAnomaliesIntoIncident(snapshot, anomalies);
        }
    }

    public ExecutiveSummaryReport BuildReport(
        DateTimeOffset generatedAtUtc,
        bool isFinal,
        IReadOnlyList<string> generatedFiles)
    {
        var appPoolSummaries = _appPools.Values
            .OrderByDescending(p => p.MaxHungRequests)
            .ThenByDescending(p => p.MaxPooledConnections)
            .ThenByDescending(p => p.MaxDbEstablishedSockets)
            .ThenBy(p => p.AppPoolName, StringComparer.OrdinalIgnoreCase)
            .Select(p => p.ToSummary())
            .ToList();

        var nodeSummaries = _nodeJobs.Values
            .OrderByDescending(n => n.ZombieDetections)
            .ThenByDescending(n => n.MaxDbEstablishedSockets + n.MaxDbCloseWaitSockets)
            .ThenByDescending(n => n.MaxUptimeMinutes)
            .Select(n => n.ToSummary())
            .ToList();

        var topIncidents = _incidents
            .OrderByDescending(i => SeverityRank(i.MaxSeverity))
            .ThenByDescending(i => i.AnomalyCount)
            .ThenByDescending(i => (i.EndUtc - i.StartUtc).TotalSeconds)
            .Take(20)
            .Select(i => i.ToSummary())
            .ToList();

        var hypotheses = RankRootCauseHypotheses(appPoolSummaries, nodeSummaries);

        return new ExecutiveSummaryReport(
            MachineName: _machineName,
            RunStartUtc: _runStartUtc,
            LastSampleUtc: _lastSampleUtc,
            GeneratedAtUtc: generatedAtUtc,
            IsFinal: isFinal,
            TotalSamples: _totalSamples,
            SampleIntervalSeconds: _config.SampleIntervalSeconds,
            DbPorts: _config.GetDbPortSet().OrderBy(p => p).ToList(),
            IisAdminAvailable: _iisAdminAvailable,
            AdoNetCategoryAvailable: _adoNetCategoryAvailable,
            AdoNetActiveConnectionsAvailable: _adoNetActiveConnectionsAvailable,
            EnvironmentWarnings: _environmentWarnings.OrderBy(w => w, StringComparer.Ordinal).ToList(),
            Hypotheses: hypotheses,
            AnomalyCountsByCode: _anomalyCountsByCode.OrderByDescending(kv => kv.Value).ToDictionary(kv => kv.Key, kv => kv.Value),
            AppPools: appPoolSummaries,
            NodeJobs: nodeSummaries,
            TopIncidents: topIncidents,
            GeneratedFiles: generatedFiles);
    }

    private List<RootCauseHypothesis> RankRootCauseHypotheses(
        List<AppPoolHealthSummary> appPools,
        List<NodeJobHealthSummary> nodeJobs)
    {
        var candidates = new List<(int Score, string Title, List<string> Evidence)>();

        // 1. ADO.NET Connection Pool Exhaustion / Unclosed DB Connections
        {
            int score = 0;
            var ev = new List<string>();
            int poolExhaust = GetCount("CONNECTION_POOL_EXHAUSTION");
            int reclaimedEvents = GetCount("CONNECTION_LEAK_RECLAIMED");
            int dbTimeouts = GetCount("DB_POOL_TIMEOUT_EVENT");
            double totalReclaimed = appPools.Sum(p => p.TotalReclaimedConnectionsDelta);
            double maxPooled = appPools.Count > 0 ? appPools.Max(p => p.MaxPooledConnections) : 0;
            int maxDbEstab = appPools.Count > 0 ? appPools.Max(p => p.MaxDbEstablishedSockets) : 0;

            if (dbTimeouts > 0) { score += 50; ev.Add($"{dbTimeouts} EventLog SQL connection pool timeout error(s) detected."); }
            if (reclaimedEvents > 0 || totalReclaimed > 0) { score += 35; ev.Add($"ADO.NET reclaimed {totalReclaimed:0} unclosed connection(s) via GC across {reclaimedEvents} event(s)."); }
            if (poolExhaust > 0) { score += 30; ev.Add($"{poolExhaust} pool/DB-socket exhaustion anomaly event(s) (max pooled={maxPooled:0}, max DB ESTABLISHED={maxDbEstab})."); }
            if (score > 0)
            {
                candidates.Add((score, "ADO.NET Connection Pool Exhaustion / Unclosed DB Connections", ev));
            }
        }

        // 2. TCP Socket Leak (CLOSE_WAIT / TIME_WAIT) to Database
        {
            int score = 0;
            var ev = new List<string>();
            int closeWaitEvents = GetCount("TCP_CLOSE_WAIT_LEAK");
            int timeWaitEvents = GetCount("TCP_TIME_WAIT_CHURN");
            int maxCloseWait = Math.Max(
                appPools.Count > 0 ? appPools.Max(p => p.MaxDbCloseWaitSockets) : 0,
                nodeJobs.Count > 0 ? nodeJobs.Max(n => n.MaxDbCloseWaitSockets) : 0);

            if (closeWaitEvents > 0) { score += 40; ev.Add($"{closeWaitEvents} TCP CLOSE_WAIT leak event(s) to DB port(s) (peak CLOSE_WAIT={maxCloseWait})."); }
            if (timeWaitEvents > 0) { score += 15; ev.Add($"{timeWaitEvents} high TIME_WAIT churn event(s) indicating rapid socket open/close without pooling."); }
            if (score > 0)
            {
                candidates.Add((score, "TCP Socket Leak (CLOSE_WAIT / TIME_WAIT) on Database Connections", ev));
            }
        }

        // 3. IIS Hung Requests / Pipeline Stall
        {
            int score = 0;
            var ev = new List<string>();
            int hungEvents = GetCount("HUNG_REQUESTS");
            long maxElapsed = appPools.Count > 0 ? appPools.Max(p => p.MaxRequestElapsedMs) : 0;
            int maxHung = appPools.Count > 0 ? appPools.Max(p => p.MaxHungRequests) : 0;

            if (hungEvents > 0)
            {
                score += 30 + (maxElapsed >= _config.Thresholds.CriticalHungRequestThresholdMs ? 20 : 0);
                ev.Add($"{hungEvents} hung-request detection(s); peak simultaneous hung={maxHung}, max elapsed={maxElapsed}ms.");
            }
            if (score > 0)
            {
                candidates.Add((score, "IIS Worker Process Hung Requests / Pipeline Stall", ev));
            }
        }

        // 4. ASP.NET / HTTP.sys Queue Saturation
        {
            int score = 0;
            var ev = new List<string>();
            int aspQ = GetCount("ASPNET_QUEUE_BUILDUP");
            int httpQ = GetCount("HTTP_QUEUE_BUILDUP");
            if (aspQ > 0) { score += 25; ev.Add($"{aspQ} ASP.NET global queue buildup event(s)."); }
            if (httpQ > 0) { score += 25; ev.Add($"{httpQ} HTTP.sys request queue buildup event(s)."); }
            if (score > 0)
            {
                candidates.Add((score, "ASP.NET / HTTP.sys Request Queue Saturation", ev));
            }
        }

        // 5. Zombie Node.js Jobs Holding DB Connections
        {
            int score = 0;
            var ev = new List<string>();
            int zombieEvents = GetCount("NODE_ZOMBIE_JOB");
            int maxNodeDb = nodeJobs.Count > 0 ? nodeJobs.Max(n => n.MaxDbEstablishedSockets + n.MaxDbCloseWaitSockets) : 0;
            if (zombieEvents > 0)
            {
                score += 20 + (maxNodeDb > 0 ? 25 : 0);
                ev.Add($"{zombieEvents} long-running/zombie Node.js job detection(s); peak DB sockets held by Node={maxNodeDb}.");
            }
            if (score > 0)
            {
                candidates.Add((score, "Zombie / Long-Running Node.js Jobs Holding DB Connections", ev));
            }
        }

        // 6. CLR Thread Contention / Exception Storm
        {
            int score = 0;
            var ev = new List<string>();
            int contention = GetCount("THREAD_CONTENTION");
            int exStorm = GetCount("EXCEPTION_STORM");
            if (contention > 0) { score += 25; ev.Add($"{contention} CLR lock/thread contention event(s)."); }
            if (exStorm > 0) { score += 15; ev.Add($"{exStorm} CLR exception storm event(s)."); }
            if (score > 0)
            {
                candidates.Add((score, "CLR ThreadPool / Lock Contention or Exception Storm", ev));
            }
        }

        // 7. AppPool Unplanned Recycles / Crashes
        {
            int recycles = GetCount("APPPOOL_RECYCLE_OR_CRASH");
            if (recycles > 0)
            {
                candidates.Add((25, "Unplanned IIS AppPool Recycles or Worker Crashes",
                    [$"{recycles} AppPool PID change / WAS recycle-or-crash event(s) detected."]));
            }
        }

        if (candidates.Count == 0)
        {
            return
            [
                new RootCauseHypothesis(
                    Rank: 1,
                    Confidence: "NONE",
                    Score: 0,
                    Title: "No anomalies detected during the observation window",
                    Evidence: [$"Observed {_totalSamples} sample(s) without breaching configured thresholds."])
            ];
        }

        return candidates
            .OrderByDescending(c => c.Score)
            .Select((c, idx) => new RootCauseHypothesis(
                Rank: idx + 1,
                Confidence: c.Score >= 50 ? "HIGH" : c.Score >= 25 ? "MEDIUM" : "LOW",
                Score: c.Score,
                Title: c.Title,
                Evidence: c.Evidence))
            .ToList();
    }

    private void ClusterAnomaliesIntoIncident(TelemetrySnapshot snapshot, IReadOnlyList<AnomalyEvent> anomalies)
    {
        var gap = TimeSpan.FromSeconds(Math.Max(1, _config.Thresholds.IncidentMergeGapSeconds));
        var ts = snapshot.TimestampUtc;

        if (_activeIncident is null || (ts - _activeIncident.EndUtc) > gap)
        {
            _activeIncident = new IncidentAccumulator(_nextIncidentId++, ts);
            _incidents.Add(_activeIncident);

            if (_incidents.Count > MaxStoredIncidents)
            {
                // Drop lowest-severity oldest incident to guarantee bounded memory.
                var toRemove = _incidents
                    .Where(i => i != _activeIncident)
                    .OrderBy(i => SeverityRank(i.MaxSeverity))
                    .ThenBy(i => i.AnomalyCount)
                    .ThenBy(i => i.StartUtc)
                    .FirstOrDefault();

                if (toRemove is not null)
                {
                    _incidents.Remove(toRemove);
                }
            }
        }

        _activeIncident.Add(ts, anomalies, snapshot);
    }

    private AppPoolAccumulator GetOrCreateAppPool(string name)
    {
        if (!_appPools.TryGetValue(name, out var acc))
        {
            acc = new AppPoolAccumulator(name);
            _appPools[name] = acc;
        }
        return acc;
    }

    private void RecordWarnings(IReadOnlyList<string> warnings)
    {
        foreach (string w in warnings)
        {
            if (_environmentWarnings.Count >= MaxEnvironmentWarnings) break;
            if (!string.IsNullOrWhiteSpace(w))
            {
                _environmentWarnings.Add(w);
            }
        }
    }

    private int GetCount(string code) => _anomalyCountsByCode.TryGetValue(code, out int c) ? c : 0;

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 3,
        "HIGH" => 2,
        "MEDIUM" => 1,
        _ => 0
    };

    private sealed class AppPoolAccumulator(string appPoolName)
    {
        private readonly HashSet<int> _seenPids = [];
        private readonly Dictionary<string, int> _hungUrlCounts = new(StringComparer.OrdinalIgnoreCase);

        public string AppPoolName { get; } = appPoolName;
        public int SamplesObserved { get; private set; }
        public int? LastKnownPid { get; private set; }
        public int RecycleCount { get; set; }
        public double MaxPooledConnections { get; private set; }
        public double? MaxActiveConnections { get; private set; }
        public double TotalReclaimedConnectionsDelta { get; private set; }
        public int MaxDbEstablishedSockets { get; private set; }
        public int MaxDbCloseWaitSockets { get; private set; }
        public int MaxHungRequests { get; private set; }
        public long MaxRequestElapsedMs { get; private set; }
        public double MaxHttpQueueSize { get; private set; }
        public double MaxWorkingSetMb { get; private set; }

        public void RecordWorker(IisWorkerProcessInfo w, PidTcpSocketSummary? tcp, long hungThresholdMs)
        {
            SamplesObserved++;
            LastKnownPid = w.Pid;
            _seenPids.Add(w.Pid);

            if (w.WorkingSetMb.HasValue && w.WorkingSetMb.Value > MaxWorkingSetMb)
            {
                MaxWorkingSetMb = w.WorkingSetMb.Value;
            }

            if (tcp is not null)
            {
                if (tcp.DbEstablished > MaxDbEstablishedSockets) MaxDbEstablishedSockets = tcp.DbEstablished;
                if (tcp.DbCloseWait > MaxDbCloseWaitSockets) MaxDbCloseWaitSockets = tcp.DbCloseWait;
            }

            int hungCount = 0;
            foreach (var req in w.ActiveRequests)
            {
                if (req.TimeElapsedMs > MaxRequestElapsedMs) MaxRequestElapsedMs = req.TimeElapsedMs;
                if (req.TimeElapsedMs >= hungThresholdMs)
                {
                    hungCount++;
                    string key = $"{req.Verb} {req.Url}";
                    if (_hungUrlCounts.Count < 50 || _hungUrlCounts.ContainsKey(key))
                    {
                        _hungUrlCounts[key] = _hungUrlCounts.TryGetValue(key, out int c) ? c + 1 : 1;
                    }
                }
            }

            if (hungCount > MaxHungRequests) MaxHungRequests = hungCount;
        }

        public void RecordAdoNet(AdoNetPoolMetrics ado, double reclaimedDelta)
        {
            if (ado.Pid.HasValue)
            {
                LastKnownPid = ado.Pid.Value;
                _seenPids.Add(ado.Pid.Value);
            }

            if (ado.NumberOfPooledConnections.HasValue && ado.NumberOfPooledConnections.Value > MaxPooledConnections)
            {
                MaxPooledConnections = ado.NumberOfPooledConnections.Value;
            }

            if (ado.NumberOfActiveConnections.HasValue)
            {
                MaxActiveConnections = MaxActiveConnections.HasValue
                    ? Math.Max(MaxActiveConnections.Value, ado.NumberOfActiveConnections.Value)
                    : ado.NumberOfActiveConnections.Value;
            }

            TotalReclaimedConnectionsDelta += reclaimedDelta;
        }

        public void RecordHttpQueue(double queueSize)
        {
            if (queueSize > MaxHttpQueueSize) MaxHttpQueueSize = queueSize;
        }

        public AppPoolHealthSummary ToSummary() => new(
            AppPoolName: AppPoolName,
            SamplesObserved: SamplesObserved,
            LastKnownPid: LastKnownPid,
            DistinctPidCount: _seenPids.Count,
            RecycleCount: RecycleCount,
            MaxPooledConnections: Math.Round(MaxPooledConnections, 1),
            MaxActiveConnections: MaxActiveConnections.HasValue ? Math.Round(MaxActiveConnections.Value, 1) : null,
            TotalReclaimedConnectionsDelta: Math.Round(TotalReclaimedConnectionsDelta, 1),
            MaxDbEstablishedSockets: MaxDbEstablishedSockets,
            MaxDbCloseWaitSockets: MaxDbCloseWaitSockets,
            MaxHungRequests: MaxHungRequests,
            MaxRequestElapsedMs: MaxRequestElapsedMs,
            MaxHttpQueueSize: Math.Round(MaxHttpQueueSize, 1),
            MaxWorkingSetMb: Math.Round(MaxWorkingSetMb, 1),
            TopHungUrls: _hungUrlCounts
                .OrderByDescending(kv => kv.Value)
                .Take(5)
                .Select(kv => $"{kv.Key} (x{kv.Value})")
                .ToList());
    }

    private sealed class NodeJobAccumulator(string jobLabel, string sampleCommandLine)
    {
        private readonly HashSet<int> _seenPids = [];

        public string JobLabel { get; } = jobLabel;
        public string SampleCommandLine { get; } = sampleCommandLine;
        public int SamplesObserved { get; private set; }
        public double MaxUptimeMinutes { get; private set; }
        public int MaxDbEstablishedSockets { get; private set; }
        public int MaxDbCloseWaitSockets { get; private set; }
        public double MaxWorkingSetMb { get; private set; }
        public int ZombieDetections { get; set; }

        public void Record(NodeProcessSnapshot n)
        {
            SamplesObserved++;
            _seenPids.Add(n.Pid);
            if (n.UptimeSeconds.HasValue)
            {
                double min = n.UptimeSeconds.Value / 60.0;
                if (min > MaxUptimeMinutes) MaxUptimeMinutes = min;
            }

            if (n.WorkingSetMb > MaxWorkingSetMb) MaxWorkingSetMb = n.WorkingSetMb;
            if (n.TcpSummary is not null)
            {
                if (n.TcpSummary.DbEstablished > MaxDbEstablishedSockets) MaxDbEstablishedSockets = n.TcpSummary.DbEstablished;
                if (n.TcpSummary.DbCloseWait > MaxDbCloseWaitSockets) MaxDbCloseWaitSockets = n.TcpSummary.DbCloseWait;
            }
        }

        public NodeJobHealthSummary ToSummary() => new(
            JobLabel: JobLabel,
            SampleCommandLine: SampleCommandLine,
            SamplesObserved: SamplesObserved,
            DistinctPidCount: _seenPids.Count,
            MaxUptimeMinutes: Math.Round(MaxUptimeMinutes, 1),
            MaxDbEstablishedSockets: MaxDbEstablishedSockets,
            MaxDbCloseWaitSockets: MaxDbCloseWaitSockets,
            MaxWorkingSetMb: Math.Round(MaxWorkingSetMb, 1),
            ZombieDetections: ZombieDetections);
    }

    private sealed class IncidentAccumulator(int incidentId, DateTimeOffset startUtc)
    {
        private readonly HashSet<string> _codes = new(StringComparer.Ordinal);
        private readonly HashSet<string> _targets = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _hungUrls = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _eventSnippets = new(StringComparer.Ordinal);

        public int IncidentId { get; } = incidentId;
        public DateTimeOffset StartUtc { get; } = startUtc;
        public DateTimeOffset EndUtc { get; private set; } = startUtc;
        public string MaxSeverity { get; private set; } = nameof(AnomalySeverity.MEDIUM);
        public int AnomalyCount { get; private set; }

        public void Add(DateTimeOffset ts, IReadOnlyList<AnomalyEvent> anomalies, TelemetrySnapshot snapshot)
        {
            if (ts > EndUtc) EndUtc = ts;

            foreach (var a in anomalies)
            {
                AnomalyCount++;
                _codes.Add(a.Code);
                if (_targets.Count < 10) _targets.Add($"{a.TargetType}:{a.TargetName}");
                if (SeverityRank(a.Severity) > SeverityRank(MaxSeverity)) MaxSeverity = a.Severity;
            }

            foreach (var w in snapshot.Iis.Workers)
            {
                foreach (var req in w.ActiveRequests.OrderByDescending(r => r.TimeElapsedMs).Take(3))
                {
                    if (_hungUrls.Count >= 5) break;
                    _hungUrls.Add($"{w.AppPoolName} {req.Verb} {req.Url} ({req.TimeElapsedMs}ms)");
                }
            }

            foreach (var ev in snapshot.NewEvents)
            {
                if (_eventSnippets.Count >= 5) break;
                string snippet = $"[{ev.Source}#{ev.EventId}] {(ev.Message.Length <= 140 ? ev.Message : ev.Message[..140] + "...")}";
                _eventSnippets.Add(snippet);
            }
        }

        public IncidentWindowSummary ToSummary() => new(
            IncidentId: IncidentId,
            StartUtc: StartUtc,
            EndUtc: EndUtc,
            DurationSeconds: Math.Round(Math.Max(0, (EndUtc - StartUtc).TotalSeconds), 1),
            MaxSeverity: MaxSeverity,
            AnomalyCount: AnomalyCount,
            Codes: _codes.OrderBy(c => c, StringComparer.Ordinal).ToList(),
            Targets: _targets.OrderBy(t => t, StringComparer.OrdinalIgnoreCase).ToList(),
            SampleHungUrls: _hungUrls.ToList(),
            CorrelatedEventSnippets: _eventSnippets.ToList());
    }
}
