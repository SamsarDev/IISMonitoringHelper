using System.Text.Json;
using IisMonitor.Analysis;
using IisMonitor.Collectors;
using IisMonitor.Domain;
using IisMonitor.Reporting;

namespace IisMonitor.Tests;

public sealed class ProductionReadinessTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ClrPidShiftTracker_DetectsShift_SuppressesRateSpikes_AndPrunesStale()
    {
        var tracker = new ClrPidShiftTracker();

        Assert.False(tracker.Observe("w3wp#1", 1001));
        Assert.False(tracker.Observe("w3wp#1", 1001));
        Assert.False(tracker.Observe("w3wp#2", 1002));
        Assert.Equal(2, tracker.TrackedCount);

        // Process 1001 exits and w3wp#1 shifts to PID 1002
        bool shifted = tracker.Observe("w3wp#1", 1002);
        Assert.True(shifted);

        var raw = new ClrProcessMetrics(
            InstanceName: "w3wp#1",
            Pid: 1002,
            AppPoolName: "ErpPool",
            ContentionRatePerSec: 120.5,
            CurrentLockQueueLength: 2,
            TotalContentions: 500,
            LogicalThreads: 45,
            PhysicalThreads: 38,
            ExceptionsThrownPerSec: 950.0,
            PercentTimeInGc: 65.0,
            Gen2HeapSizeMb: 120.4,
            TotalHeapSizeMb: 210.8);

        var suppressed = ClrPidShiftTracker.ApplyPidShiftSuppression(raw, pidShifted: true);
        Assert.Equal(0.0, suppressed.ContentionRatePerSec);
        Assert.Equal(0.0, suppressed.ExceptionsThrownPerSec);
        Assert.Equal(0.0, suppressed.PercentTimeInGc);
        Assert.Equal(120.4, suppressed.Gen2HeapSizeMb);
        Assert.Equal(210.8, suppressed.TotalHeapSizeMb);
        Assert.Equal(45, suppressed.LogicalThreads);

        // Prune departed w3wp#2
        tracker.Prune(new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "w3wp#1" });
        Assert.Equal(1, tracker.TrackedCount);
    }

    [Fact]
    public void AnomalyDetector_AppliesCooldown_AndAllowsImmediateEscalation()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig { AnomalyCooldownSeconds = 300 };

        // Sample 1: HIGH GC time (25% >= 20%)
        var snap1 = CreateSnapshot(BaseTime, 1, clrProcesses:
        [
            new ClrProcessMetrics("w3wp", 1001, "ApiPool", 0, 0, 0, 20, 20, 0, 25.0, 80, 150)
        ]);
        var a1 = detector.Analyze(snap1, config);
        Assert.Contains(a1, a => a.Code == "HIGH_GC_TIME" && a.Severity == "HIGH" && a.TargetName == "ApiPool");

        // Sample 2: 30s later, same HIGH severity -> suppressed by cooldown
        var snap2 = CreateSnapshot(BaseTime.AddSeconds(30), 2, clrProcesses:
        [
            new ClrProcessMetrics("w3wp", 1001, "ApiPool", 0, 0, 0, 20, 20, 0, 28.0, 85, 160)
        ]);
        var a2 = detector.Analyze(snap2, config);
        Assert.DoesNotContain(a2, a => a.Code == "HIGH_GC_TIME");

        // Sample 3: 45s later, escalates to CRITICAL (45% >= 40%) -> emitted immediately!
        var snap3 = CreateSnapshot(BaseTime.AddSeconds(45), 3, clrProcesses:
        [
            new ClrProcessMetrics("w3wp", 1001, "ApiPool", 0, 0, 0, 20, 20, 0, 45.0, 95, 180)
        ]);
        var a3 = detector.Analyze(snap3, config);
        Assert.Contains(a3, a => a.Code == "HIGH_GC_TIME" && a.Severity == "CRITICAL" && a.TargetName == "ApiPool");

        // Sample 4: 6 minutes later (outside 300s cooldown) -> re-emitted
        var snap4 = CreateSnapshot(BaseTime.AddMinutes(6), 4, clrProcesses:
        [
            new ClrProcessMetrics("w3wp", 1001, "ApiPool", 0, 0, 0, 20, 20, 0, 25.0, 90, 170)
        ]);
        var a4 = detector.Analyze(snap4, config);
        Assert.Contains(a4, a => a.Code == "HIGH_GC_TIME" && a.Severity == "HIGH");
    }

    [Fact]
    public void AnomalyDetector_FormatsNodeZombieCleanly_AndRespectsNodeIgnorePatterns()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig
        {
            AnomalyCooldownSeconds = 0,
            NodeIgnorePatterns = ["pm2-daemon", "ignored-worker.js"]
        };

        var validZombie = new NodeProcessSnapshot(
            Pid: 5001,
            JobLabel: "stuck-job.js",
            CommandLine: "node.exe C:\\jobs\\stuck-job.js",
            StartTimeUtc: BaseTime.AddMinutes(-302),
            UptimeSeconds: 302 * 60, // 302.0m
            WorkingSetMb: 90.0,
            HandleCount: 200,
            ThreadCount: 8,
            TotalProcessorTimeMs: 1200,
            CpuDeltaMs: null,
            TcpSummary: new PidTcpSocketSummary(
                5001, 2, new Dictionary<string, int> { ["ESTABLISHED"] = 1 },
                1, 1, 0, 0, 0, [new RemoteEndpointCount("10.0.0.5:1433", 1, 1, 0, 0)]));

        var ignoredDaemon = validZombie with
        {
            Pid = 5002,
            JobLabel = "pm2-daemon",
            CommandLine = "node.exe C:\\pm2\\pm2-daemon.js"
        };

        var snap = CreateSnapshot(BaseTime, 1, nodeProcesses: [validZombie, ignoredDaemon]);
        var anomalies = detector.Analyze(snap, config);

        var nodeAnomaly = Assert.Single(anomalies, a => a.Code == "NODE_ZOMBIE_JOB");
        Assert.Equal("stuck-job.js", nodeAnomaly.TargetName);
        Assert.Contains("uptime=302m", nodeAnomaly.Summary);
        Assert.DoesNotContain("3021m", nodeAnomaly.Summary);
        Assert.Contains("cpuDelta=n/a.", nodeAnomaly.Summary);
        Assert.DoesNotContain("n/ams", nodeAnomaly.Summary);
    }

    [Fact]
    public void AnomalyDetector_DetectsAspNetRequestsRejectedDelta()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig { AnomalyCooldownSeconds = 0 };

        var snap1 = CreateSnapshot(BaseTime, 1, aspNetGlobal: new AspNetGlobalMetrics(5, 10, 100, 10, 0));
        var a1 = detector.Analyze(snap1, config);
        Assert.DoesNotContain(a1, a => a.Code == "ASPNET_REQUESTS_REJECTED");

        var snap2 = CreateSnapshot(BaseTime.AddSeconds(15), 2, aspNetGlobal: new AspNetGlobalMetrics(5, 10, 115, 10, 0));
        var a2 = detector.Analyze(snap2, config);
        Assert.Contains(a2, a => a.Code == "ASPNET_REQUESTS_REJECTED" && a.Severity == "CRITICAL");
    }

    [Fact]
    public void RollingAggregator_ScopesNodeAndIisIncidentsSeparately_AndDoesNotInflateIdleNodeScore()
    {
        var config = new MonitorConfig
        {
            AnomalyCooldownSeconds = 0,
            Thresholds = new ThresholdConfig { IncidentMergeGapSeconds = 120 }
        };
        var aggregator = new RollingAggregator("SRV-01", BaseTime, config);
        var detector = new AnomalyDetector();

        var idleNode = new NodeProcessSnapshot(
            Pid: 7001,
            JobLabel: "forever-daemon.js",
            CommandLine: "node.exe forever-daemon.js",
            StartTimeUtc: BaseTime.AddHours(-5),
            UptimeSeconds: 5 * 3600,
            WorkingSetMb: 50,
            HandleCount: 100,
            ThreadCount: 6,
            TotalProcessorTimeMs: 500,
            CpuDeltaMs: 0,
            TcpSummary: null);

        // T=0: Both idle Node daemon and IIS CLR contention fire
        var snap1 = CreateSnapshot(
            BaseTime, 1,
            workers: [CreateWorker(1001, "ErpPool", 200, cpuPct: 12.5)],
            clrProcesses: [new ClrProcessMetrics("w3wp", 1001, "ErpPool", 40.0, 3, 100, 30, 25, 0, 5.0, 50, 100)],
            nodeProcesses: [idleNode]);
        aggregator.RecordSample(snap1, detector.Analyze(snap1, config));

        // T=60s, 120s, 180s, 240s: Only idle Node daemon keeps firing (keeps NODE scope alive for 4m)
        for (int i = 1; i <= 4; i++)
        {
            var t = BaseTime.AddSeconds(60 * i);
            var snapNodeOnly = CreateSnapshot(t, i + 1, nodeProcesses: [idleNode]);
            aggregator.RecordSample(snapNodeOnly, detector.Analyze(snapNodeOnly, config));
        }

        // T=300s (5m after snap1, well past 120s merge gap for IIS): IIS fires again
        var snap6 = CreateSnapshot(
            BaseTime.AddSeconds(300), 6,
            workers: [CreateWorker(1001, "ErpPool", 240, cpuPct: 22.5)],
            clrProcesses: [new ClrProcessMetrics("w3wp", 1001, "ErpPool", 55.0, 5, 200, 35, 28, 0, 8.0, 60, 120)],
            nodeProcesses: [idleNode]);
        aggregator.RecordSample(snap6, detector.Analyze(snap6, config));

        var report = aggregator.BuildReport(BaseTime.AddSeconds(315), isFinal: true, []);

        // Expect 3 incidents: 1 continuous NODE incident + 2 separate IIS incidents (not merged into 1!)
        Assert.Equal(3, report.TopIncidents.Count);
        Assert.Equal(2, report.TopIncidents.Count(inc => inc.Codes.Contains("THREAD_CONTENTION")));
        Assert.Equal(1, report.TopIncidents.Count(inc => inc.Codes.Contains("NODE_ZOMBIE_JOB")));
        Assert.All(report.TopIncidents, inc =>
            Assert.False(inc.Codes.Contains("NODE_ZOMBIE_JOB") && inc.Codes.Contains("THREAD_CONTENTION")));

        // Real IIS CLR contention (score 25) must outrank idle Node daemon with 0 DB sockets (score 5)
        Assert.StartsWith("CLR ThreadPool", report.Hypotheses[0].Title);
        Assert.True(report.Hypotheses[0].Score > report.Hypotheses.Last().Score);
    }

    [Fact]
    public void RollingAggregator_ExcludesNonIisAdoNet_AndTracksMemoryCpuClrTrends()
    {
        var config = new MonitorConfig();
        var aggregator = new RollingAggregator("SRV-01", BaseTime, config);

        var snap1 = CreateSnapshot(
            BaseTime, 1,
            workers: [CreateWorker(1001, "PortalPool", workingSetMb: 200.0, cpuPct: 10.0)],
            adoInstances:
            [
                new AdoNetPoolMetrics("w3wp[1001]", 1001, "PortalPool", 1, 0, 20, 0, 0, 0, 0, 0, 0, 0, null, 20),
                new AdoNetPoolMetrics("reportserver_ssrs[8888]", 8888, null, 1, 0, 50, 0, 0, 0, 0, 0, 0, 0, null, 50)
            ],
            clrProcesses: [new ClrProcessMetrics("w3wp", 1001, "PortalPool", 0, 0, 0, 42, 30, 0, 12.4, 88.5, 160.2)]);

        var snap2 = CreateSnapshot(
            BaseTime.AddSeconds(15), 2,
            workers: [CreateWorker(1001, "PortalPool", workingSetMb: 300.0, cpuPct: 30.0)],
            adoInstances:
            [
                new AdoNetPoolMetrics("w3wp[1001]", 1001, "PortalPool", 1, 0, 25, 0, 0, 0, 0, 0, 0, 0, null, 25)
            ],
            clrProcesses: [new ClrProcessMetrics("w3wp", 1001, "PortalPool", 0, 0, 0, 50, 35, 0, 18.6, 110.0, 210.5)]);

        var snap3 = CreateSnapshot(
            BaseTime.AddSeconds(30), 3,
            workers: [CreateWorker(1001, "PortalPool", workingSetMb: 250.0, cpuPct: 20.0)]);

        aggregator.RecordSample(snap1, []);
        aggregator.RecordSample(snap2, []);
        aggregator.RecordSample(snap3, []);

        var report = aggregator.BuildReport(BaseTime.AddSeconds(45), isFinal: true, []);

        // reportserver_ssrs must NOT appear in AppPools
        var pool = Assert.Single(report.AppPools);
        Assert.Equal("PortalPool", pool.AppPoolName);
        Assert.Equal(200.0, pool.StartWorkingSetMb);
        Assert.Equal(250.0, pool.AvgWorkingSetMb);
        Assert.Equal(300.0, pool.MaxWorkingSetMb);
        Assert.Equal(250.0, pool.EndWorkingSetMb);
        Assert.Equal(20.0, pool.AvgCpuPercent);
        Assert.Equal(30.0, pool.MaxCpuPercent);
        Assert.Equal(18.6, pool.MaxGcPercent);
        Assert.Equal(110.0, pool.MaxGen2HeapMb);
        Assert.Equal(210.5, pool.MaxTotalHeapMb);
        Assert.Equal(50.0, pool.MaxLogicalThreads);

        string formatted = AiExecutiveSummaryWriter.FormatReport(report);
        Assert.Contains("MemMB(start=200 avg=250 max=300 end=250)", formatted);
        Assert.Contains("CLR(maxGC=18.6% maxGen2=110MB maxHeap=210.5MB maxLogThr=50)", formatted);
        Assert.DoesNotContain("reportserver_ssrs", formatted);
    }

    [Fact]
    public void IisWorkerProcessCollector_ComputesCpuPercent_AndPrunesExitedPids()
    {
        var collector = new IisWorkerProcessCollector();

        // First sample establishes baseline -> null
        Assert.Null(collector.ComputeCpuPercent(1001, 5000.0, BaseTime, processorCount: 4));
        Assert.Equal(1, collector.TrackedPidCount);

        // 10s later, 10,000ms CPU time on 4 cores = 10000 / (10000 * 4) * 100 = 25.0%
        double? cpu = collector.ComputeCpuPercent(1001, 15000.0, BaseTime.AddSeconds(10), processorCount: 4);
        Assert.Equal(25.0, cpu);

        // Exited PID is pruned
        collector.PruneExitedPids(new HashSet<int>());
        Assert.Equal(0, collector.TrackedPidCount);
    }

    [Fact]
    public async Task JsonlTelemetryWriter_PersistsCpuPct_AndActiveAspNetApps()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"iismon-jsonl-{Guid.NewGuid():N}");
        try
        {
            using (var writer = new JsonlTelemetryWriter(tempDir))
            {
                var snap = CreateSnapshot(
                    BaseTime, 1,
                    workers: [CreateWorker(1001, "MainPool", 180.0, cpuPct: 14.3)],
                    aspNetApps:
                    [
                        new AspNetAppMetrics("_LM_W3SVC_1_ROOT_Idle", 0, 0, 0, 0),
                        new AspNetAppMetrics("_LM_W3SVC_1_ROOT_Erp", 4, 2, 1, 3)
                    ]);

                await writer.WriteSnapshotAsync(snap, CancellationToken.None);
            }

            string timelinePath = Path.Combine(tempDir, "02_TIMELINE_METRICS_2026-11-20.jsonl");
            string json = (await File.ReadAllLinesAsync(timelinePath))[0];
            using var doc = JsonDocument.Parse(json);

            Assert.Equal(14.3, doc.RootElement.GetProperty("workers")[0].GetProperty("cpuPct").GetDouble());
            var apps = doc.RootElement.GetProperty("aspNetApps");
            Assert.Equal(1, apps.GetArrayLength());
            Assert.Equal("_LM_W3SVC_1_ROOT_Erp", apps[0].GetProperty("instanceName").GetString());
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void WindowsEventLogCollector_BuildsRecordIdXPath_AndExtractsHighSignalSnippet()
    {
        // Initial query uses TimeCreated
        string initialXPath = WindowsEventLogCollector.BuildXPathQuery(-1, BaseTime);
        Assert.Contains("TimeCreated[@SystemTime>='2026-11-20T12:00:00.000Z']", initialXPath);
        Assert.DoesNotContain("EventRecordID", initialXPath);

        // Incremental query uses EventRecordID > lastRecordId
        string nextXPath = WindowsEventLogCollector.BuildXPathQuery(123456, BaseTime);
        Assert.Equal("*[System[(Level=1 or Level=2 or Level=3) and EventRecordID>123456]]", nextXPath);

        // High-signal extraction from ASP.NET 1309 boilerplate
        string aspNetMsg =
            "Event code: 3005 Event message: An unhandled exception has occurred. Event time: 11/20/2026 12:00:00 PM " +
            "Exception information: Exception type: InvalidOperationException Exception message: Multiple types were found that match the controller named 'Orders'. " +
            "at System.Web.Mvc.DefaultControllerFactory.GetControllerType() " +
            "Request information: Request URL: https://erp.local/api/orders/export Request path: /api/orders/export User host address: 10.0.0.1";

        string snippet = WindowsEventLogCollector.ExtractHighSignalSnippet("ASP.NET 4.0.30319.0", 1309, aspNetMsg);
        Assert.Contains("ExType=InvalidOperationException", snippet);
        Assert.Contains("ExMsg=Multiple types were found that match the controller named 'Orders'.", snippet);
        Assert.Contains("Url=https://erp.local/api/orders/export", snippet);
        Assert.DoesNotContain("Event code: 3005", snippet);
    }

    [Fact]
    public void RollingAggregator_GroupsTopEventLogSignatures_AndFormatsSummarySection()
    {
        var config = new MonitorConfig();
        var aggregator = new RollingAggregator("SRV-01", BaseTime, config);

        string msg = "Event code: 3005 Exception information: Exception type: HttpException Exception message: Controller not found. Request information: Request URL: https://erp.local/bad Request path: /bad";
        var ev1 = new EventLogFinding(BaseTime, "Application", 1, 1309, "Warning", "ASP.NET 4.0.30319.0", msg, false, false);
        var ev2 = new EventLogFinding(BaseTime.AddMinutes(5), "Application", 2, 1309, "Warning", "ASP.NET 4.0.30319.0", msg, false, false);

        aggregator.RecordSample(CreateSnapshot(BaseTime, 1, events: [ev1]), []);
        aggregator.RecordSample(CreateSnapshot(BaseTime.AddMinutes(5), 2, events: [ev2]), []);

        var report = aggregator.BuildReport(BaseTime.AddMinutes(6), isFinal: true, []);
        Assert.NotNull(report.TopEventLogSignatures);
        var sig = Assert.Single(report.TopEventLogSignatures);
        Assert.Equal(2, sig.Count);
        Assert.Equal(1309, sig.EventId);
        Assert.Contains("ExType=HttpException", sig.Signature);

        string formatted = AiExecutiveSummaryWriter.FormatReport(report);
        Assert.Contains("=== TOP_EVENTLOG_SIGNATURES ===", formatted);
        Assert.Contains("ASP.NET 4.0.30319.0#1309", formatted);
    }

    [Fact]
    public void Program_ParsesNewCliOptions()
    {
        var config = new MonitorConfig();
        Program.ApplyCliOverrides(config, ["--anomaly-cooldown-seconds", "120", "--node-ignore", "pm2,daemon.js"]);
        config.Normalize();

        Assert.Equal(120, config.AnomalyCooldownSeconds);
        Assert.Equal(["pm2", "daemon.js"], config.NodeIgnorePatterns);
    }

    [Fact]
    public void SustainedOutage_WithDefaultCooldown_MergesIntoSingleContinuousIncident()
    {
        var config = new MonitorConfig
        {
            AnomalyCooldownSeconds = 300,
            SampleIntervalSeconds = 15,
            Thresholds = new ThresholdConfig { IncidentMergeGapSeconds = 180 }
        };
        var detector = new AnomalyDetector();
        var aggregator = new RollingAggregator("SRV-01", BaseTime, config);

        // Simulate a 10-minute sustained HIGH_GC_TIME outage sampled every 15s (41 samples).
        // With 300s cooldown, anomalies emit at T=0s, T=300s, T=600s.
        // Effective merge gap (>= 330s) must keep all of them merged into ONE continuous incident.
        for (int i = 0; i <= 40; i++)
        {
            var ts = BaseTime.AddSeconds(i * 15);
            var snap = CreateSnapshot(ts, i + 1, clrProcesses:
            [
                new ClrProcessMetrics("w3wp", 1001, "ErpPool", 0, 0, 0, 30, 25, 0, 28.0, 90, 180)
            ]);
            aggregator.RecordSample(snap, detector.Analyze(snap, config));
        }

        var report = aggregator.BuildReport(BaseTime.AddSeconds(615), isFinal: true, []);

        var incident = Assert.Single(report.TopIncidents);
        Assert.Equal(3, incident.AnomalyCount);
        Assert.Equal(600.0, incident.DurationSeconds);
        Assert.Contains("HIGH_GC_TIME", incident.Codes);
    }

    [Fact]
    public void DiscreteAndDeltaEvents_AreNotSuppressedByCooldown()
    {
        var config = new MonitorConfig { AnomalyCooldownSeconds = 300 };
        var detector = new AnomalyDetector();
        var aggregator = new RollingAggregator("SRV-01", BaseTime, config);

        // Crash loop: AppPool PID changes every 15s + ASPNET_REQUESTS_REJECTED increments every 15s
        int[] pids = [1001, 1002, 1003, 1004];
        for (int i = 0; i < pids.Length; i++)
        {
            var ts = BaseTime.AddSeconds(i * 15);
            var snap = CreateSnapshot(
                ts, i + 1,
                workers: [CreateWorker(pids[i], "CrashPool", 150.0)],
                aspNetGlobal: new AspNetGlobalMetrics(5, 10, 10 + (i * 3), 20, i));

            var anomalies = detector.Analyze(snap, config);
            aggregator.RecordSample(snap, anomalies);

            if (i > 0)
            {
                Assert.Contains(anomalies, a => a.Code == "APPPOOL_RECYCLE_OR_CRASH" && a.TargetName == "CrashPool");
                Assert.Contains(anomalies, a => a.Code == "ASPNET_REQUESTS_REJECTED");
            }
        }

        var report = aggregator.BuildReport(BaseTime.AddMinutes(1), isFinal: true, []);
        var pool = Assert.Single(report.AppPools);
        Assert.Equal(3, pool.RecycleCount);
        Assert.Equal(3, report.AnomalyCountsByCode["APPPOOL_RECYCLE_OR_CRASH"]);
        Assert.Equal(3, report.AnomalyCountsByCode["ASPNET_REQUESTS_REJECTED"]);
    }

    [Fact]
    public void IntermediateCheckpointBuildReport_DoesNotPrematurelyCloseActiveIncidents()
    {
        var config = new MonitorConfig { AnomalyCooldownSeconds = 0 };
        var detector = new AnomalyDetector();
        var aggregator = new RollingAggregator("SRV-01", BaseTime, config);

        var snap1 = CreateSnapshot(BaseTime, 1, clrProcesses:
        [
            new ClrProcessMetrics("w3wp", 1001, "ErpPool", 40.0, 2, 10, 20, 20, 0, 5.0, 40, 90)
        ]);
        aggregator.RecordSample(snap1, detector.Analyze(snap1, config));

        // Checkpoint report (isFinal: false)
        var checkpoint = aggregator.BuildReport(BaseTime.AddSeconds(10), isFinal: false, []);
        Assert.Single(checkpoint.TopIncidents);
        Assert.Equal(1, checkpoint.TopIncidents[0].AnomalyCount);

        // Next sample 30s later (within merge gap) must continue the SAME active incident
        var snap2 = CreateSnapshot(BaseTime.AddSeconds(30), 2, clrProcesses:
        [
            new ClrProcessMetrics("w3wp", 1001, "ErpPool", 45.0, 3, 20, 22, 20, 0, 6.0, 45, 95)
        ]);
        aggregator.RecordSample(snap2, detector.Analyze(snap2, config));

        var finalReport = aggregator.BuildReport(BaseTime.AddSeconds(45), isFinal: true, []);
        var inc = Assert.Single(finalReport.TopIncidents);
        Assert.Equal(2, inc.AnomalyCount);
        Assert.Equal(30.0, inc.DurationSeconds);
    }

    [Fact]
    public void ComputeCpuPercent_HandlesEdgeCases_ZeroWall_NegativeDelta_AndClamp()
    {
        var collector = new IisWorkerProcessCollector();

        // Baseline
        Assert.Null(collector.ComputeCpuPercent(2001, 10_000.0, BaseTime, processorCount: 4));

        // Zero / negative wall time -> null
        Assert.Null(collector.ComputeCpuPercent(2001, 12_000.0, BaseTime, processorCount: 4));

        // Negative CPU delta (e.g. PID reuse) -> null
        Assert.Null(collector.ComputeCpuPercent(2001, 5_000.0, BaseTime.AddSeconds(10), processorCount: 4));

        // Huge CPU delta (>100%) -> clamped to 100.0
        double? clamped = collector.ComputeCpuPercent(2001, 500_000.0, BaseTime.AddSeconds(11), processorCount: 2);
        Assert.Equal(100.0, clamped);
    }

    [Fact]
    public void ExtractHighSignalSnippet_StripsQueryString_AndFallsBackForNonAspNetMessages()
    {
        string aspNetWithQuery =
            "Event code: 3005 Exception information: Exception type: HttpException Exception message: Not found. " +
            "Request information: Request URL: https://erp.local/api/invoices?token=secret123&page=4 Request path: /api/invoices";

        string snippet = WindowsEventLogCollector.ExtractHighSignalSnippet("ASP.NET 4.0.30319.0", 1309, aspNetWithQuery);
        Assert.Contains("Url=https://erp.local/api/invoices", snippet);
        Assert.DoesNotContain("token=secret123", snippet);

        // Non-ASP.NET message falls back to truncated normalized text
        string longGeneric = new string('X', 300);
        string fallback = WindowsEventLogCollector.ExtractHighSignalSnippet("WAS", 5074, longGeneric, maxLength: 50);
        Assert.Equal(53, fallback.Length); // 50 chars + "..."
        Assert.EndsWith("...", fallback);
    }

    private static IisWorkerProcessInfo CreateWorker(int pid, string appPool, double workingSetMb, double? cpuPct = null) =>
        new(pid, appPool, "Started", "Running", workingSetMb, 400, 30, 1000, BaseTime.AddHours(-1), [], ["Site/"], cpuPct);

    private static TelemetrySnapshot CreateSnapshot(
        DateTimeOffset ts,
        long seq,
        IReadOnlyList<IisWorkerProcessInfo>? workers = null,
        IReadOnlyList<AdoNetPoolMetrics>? adoInstances = null,
        AspNetGlobalMetrics? aspNetGlobal = null,
        IReadOnlyList<AspNetAppMetrics>? aspNetApps = null,
        IReadOnlyList<ClrProcessMetrics>? clrProcesses = null,
        IReadOnlyList<NodeProcessSnapshot>? nodeProcesses = null,
        IReadOnlyList<EventLogFinding>? events = null) =>
        new(
            TimestampUtc: ts,
            SampleSequence: seq,
            MachineName: "SRV-01",
            Iis: new IisCollectionResult("IIS_ADMIN", workers ?? [], []),
            AdoNet: new AdoNetCollectionResult(true, false, adoInstances ?? [], []),
            AspNetAndClr: new AspNetAndClrCollectionResult(aspNetGlobal, aspNetApps ?? [], [], clrProcesses ?? [], []),
            Tcp: new TcpCollectionResult(new Dictionary<int, PidTcpSocketSummary>(), 0, 0, 0, 0, 0, []),
            Node: new NodeCollectionResult(nodeProcesses ?? [], []),
            NewEvents: events ?? [],
            CollectorErrors: []);
}
