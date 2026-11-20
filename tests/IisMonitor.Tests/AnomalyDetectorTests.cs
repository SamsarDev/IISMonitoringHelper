using IisMonitor.Analysis;
using IisMonitor.Domain;

namespace IisMonitor.Tests;

public sealed class AnomalyDetectorTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Detects_ConnectionPoolExhaustion_And_ReclaimedConnectionLeak()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig();

        var snap1 = CreateBaseSnapshot(BaseTime, 1, adoInstances:
        [
            new AdoNetPoolMetrics("w3wp[1001]", 1001, "PortalAppPool", 1, 0, 82, 0, 2, 0, 0, 10, 10, 0, null, 18)
        ]);

        var anomalies1 = detector.Analyze(snap1, config);
        Assert.Contains(anomalies1, a => a.Code == "CONNECTION_POOL_EXHAUSTION" && a.TargetName == "PortalAppPool");
        Assert.DoesNotContain(anomalies1, a => a.Code == "CONNECTION_LEAK_RECLAIMED");

        var snap2 = CreateBaseSnapshot(BaseTime.AddSeconds(15), 2, adoInstances:
        [
            new AdoNetPoolMetrics("w3wp[1001]", 1001, "PortalAppPool", 1, 0, 98, 0, 8, 0, 0, 10, 10, 0, null, 2)
        ]);

        var anomalies2 = detector.Analyze(snap2, config);
        Assert.Contains(anomalies2, a => a.Code == "CONNECTION_POOL_EXHAUSTION" && a.Severity == "CRITICAL");
        Assert.Contains(anomalies2, a => a.Code == "CONNECTION_LEAK_RECLAIMED" && a.Severity == "CRITICAL");
    }

    [Fact]
    public void Detects_TcpCloseWaitLeak_And_DbEstablishedExhaustion()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig();

        var tcpByPid = new Dictionary<int, PidTcpSocketSummary>
        {
            [2002] = new PidTcpSocketSummary(
                Pid: 2002,
                TotalSockets: 130,
                StateCounts: new Dictionary<string, int> { ["ESTABLISHED"] = 105, ["CLOSE_WAIT"] = 18 },
                DbTotalSockets: 123,
                DbEstablished: 105,
                DbCloseWait: 18,
                DbTimeWait: 0,
                DbSynSent: 0,
                TopDbEndpoints: [new RemoteEndpointCount("10.0.0.5:1433", 123, 105, 18, 0)])
        };

        var snap = CreateBaseSnapshot(
            BaseTime,
            1,
            workers: [CreateWorker(2002, "BillingPool")],
            tcp: new TcpCollectionResult(tcpByPid, 130, 0, 18, 105, 18, []));

        var anomalies = detector.Analyze(snap, config);
        Assert.Contains(anomalies, a => a.Code == "CONNECTION_POOL_EXHAUSTION" && a.TargetName == "BillingPool" && a.Severity == "CRITICAL");
        Assert.Contains(anomalies, a => a.Code == "TCP_CLOSE_WAIT_LEAK" && a.TargetName == "BillingPool" && a.Severity == "CRITICAL");
    }

    [Fact]
    public void Detects_HungRequests_And_AppPoolPidChange()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig();

        var hungReq = new ActiveRequestInfo(
            "req-1", "/api/orders/export", "GET", "10.0.1.10", "portal.local",
            "ExecuteRequestHandler", "ManagedPipelineHandler", 45_000, 44_900);

        var snap1 = CreateBaseSnapshot(BaseTime, 1, workers: [CreateWorker(3001, "OrdersPool", [hungReq])]);
        var anomalies1 = detector.Analyze(snap1, config);

        Assert.Contains(anomalies1, a => a.Code == "HUNG_REQUESTS" && a.Severity == "CRITICAL" && a.TargetName == "OrdersPool");

        // Second sample with new PID simulates AppPool recycle/crash
        var snap2 = CreateBaseSnapshot(BaseTime.AddSeconds(15), 2, workers: [CreateWorker(3999, "OrdersPool")]);
        var anomalies2 = detector.Analyze(snap2, config);

        Assert.Contains(anomalies2, a => a.Code == "APPPOOL_RECYCLE_OR_CRASH" && a.TargetName == "OrdersPool" && a.Pid == 3999);
    }

    [Fact]
    public void Detects_DbPoolTimeoutEvent_And_ZombieNodeJob()
    {
        var detector = new AnomalyDetector();
        var config = new MonitorConfig();

        var dbTimeoutEvent = new EventLogFinding(
            TimestampUtc: BaseTime,
            LogName: "Application",
            RecordId: 500,
            EventId: 1309,
            Level: "Warning",
            Source: "ASP.NET 4.0.30319.0",
            Message: "System.InvalidOperationException: Timeout expired. The timeout period elapsed prior to obtaining a connection from the pool. All pooled connections were in use and max pool size was reached.",
            IsSqlPoolTimeout: true,
            IsWasRecycleOrCrash: false);

        var zombieNode = new NodeProcessSnapshot(
            Pid: 4040,
            JobLabel: "sync-invoices.js",
            CommandLine: "node.exe C:\\jobs\\sync-invoices.js",
            StartTimeUtc: BaseTime.AddMinutes(-90),
            UptimeSeconds: 5400,
            WorkingSetMb: 120.5,
            HandleCount: 300,
            ThreadCount: 10,
            TotalProcessorTimeMs: 4500,
            CpuDeltaMs: 0,
            TcpSummary: new PidTcpSocketSummary(
                4040, 4, new Dictionary<string, int> { ["ESTABLISHED"] = 2 },
                2, 2, 0, 0, 0, [new RemoteEndpointCount("10.0.0.5:1433", 2, 2, 0, 0)]));

        var snap = CreateBaseSnapshot(BaseTime, 1, nodeProcesses: [zombieNode], events: [dbTimeoutEvent]);
        var anomalies = detector.Analyze(snap, config);

        Assert.Contains(anomalies, a => a.Code == "DB_POOL_TIMEOUT_EVENT" && a.Severity == "CRITICAL");
        Assert.Contains(anomalies, a => a.Code == "NODE_ZOMBIE_JOB" && a.TargetName == "sync-invoices.js" && a.Severity == "HIGH");
    }

    private static IisWorkerProcessInfo CreateWorker(int pid, string appPool, IReadOnlyList<ActiveRequestInfo>? reqs = null) =>
        new(pid, appPool, "Started", "Running", 250.0, 500, 40, 1000, BaseTime.AddHours(-2), reqs ?? [], ["Default Web Site/"]);

    private static TelemetrySnapshot CreateBaseSnapshot(
        DateTimeOffset ts,
        long seq,
        IReadOnlyList<IisWorkerProcessInfo>? workers = null,
        IReadOnlyList<AdoNetPoolMetrics>? adoInstances = null,
        TcpCollectionResult? tcp = null,
        IReadOnlyList<NodeProcessSnapshot>? nodeProcesses = null,
        IReadOnlyList<EventLogFinding>? events = null) =>
        new(
            TimestampUtc: ts,
            SampleSequence: seq,
            MachineName: "TEST-SRV",
            Iis: new IisCollectionResult("IIS_ADMIN", workers ?? [], []),
            AdoNet: new AdoNetCollectionResult(true, false, adoInstances ?? [], []),
            AspNetAndClr: new AspNetAndClrCollectionResult(null, [], [], [], []),
            Tcp: tcp ?? new TcpCollectionResult(new Dictionary<int, PidTcpSocketSummary>(), 0, 0, 0, 0, 0, []),
            Node: new NodeCollectionResult(nodeProcesses ?? [], []),
            NewEvents: events ?? [],
            CollectorErrors: []);
}
