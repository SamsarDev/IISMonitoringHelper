using IisMonitor.Analysis;
using IisMonitor.Domain;
using IisMonitor.Reporting;

namespace IisMonitor.Tests;

public sealed class RollingAggregatorAndSummaryTests
{
    [Fact]
    public void Aggregates_Incidents_RanksRootCauses_And_FormatsAiExecutiveSummary()
    {
        var start = new DateTimeOffset(2026, 11, 20, 10, 0, 0, TimeSpan.Zero);
        var config = new MonitorConfig();
        var aggregator = new RollingAggregator("SRV-IIS-01", start, config);
        var detector = new AnomalyDetector();

        // Sample 1: Pool saturation + hung request + SQL pool timeout event
        var snap1 = new TelemetrySnapshot(
            TimestampUtc: start,
            SampleSequence: 1,
            MachineName: "SRV-IIS-01",
            Iis: new IisCollectionResult("IIS_ADMIN",
            [
                new IisWorkerProcessInfo(
                    1001, "ErpPool", "Started", "Running", 512.0, 900, 65, 25000, start.AddHours(-5),
                    [new ActiveRequestInfo("r1", "/Reports/Balance", "POST", "10.1.1.2", "erp.local", "ExecuteRequestHandler", "ManagedPipelineHandler", 35000, 34000)],
                    ["ERP/"])
            ], []),
            AdoNet: new AdoNetCollectionResult(true, false,
            [
                new AdoNetPoolMetrics("w3wp[1001]", 1001, "ErpPool", 1, 0, 99, 0, 3, 1, 0, 5, 5, 0, null, 1)
            ], []),
            AspNetAndClr: new AspNetAndClrCollectionResult(
                new AspNetGlobalMetrics(30, 80, 0, 1500, 0), [],
                [new HttpQueueMetrics("ErpPool", 25, 12, 0)], [], []),
            Tcp: new TcpCollectionResult(
                new Dictionary<int, PidTcpSocketSummary>
                {
                    [1001] = new(1001, 120, new Dictionary<string, int> { ["ESTABLISHED"] = 100, ["CLOSE_WAIT"] = 12 },
                        112, 100, 12, 0, 0, [new RemoteEndpointCount("10.0.0.9:1433", 112, 100, 12, 0)])
                },
                120, 5, 12, 100, 12, []),
            Node: new NodeCollectionResult([], []),
            NewEvents:
            [
                new EventLogFinding(start, "Application", 101, 1309, "Error", "ASP.NET 4.0.30319.0",
                    "Timeout expired. The timeout period elapsed prior to obtaining a connection from the pool.", true, false)
            ],
            CollectorErrors: []);

        aggregator.RecordSample(snap1, detector.Analyze(snap1, config));

        // Sample 2: 30 seconds later (within merge gap -> same incident window), reclaimed increases
        var snap2 = snap1 with
        {
            TimestampUtc = start.AddSeconds(30),
            SampleSequence = 2,
            AdoNet = new AdoNetCollectionResult(true, false,
            [
                new AdoNetPoolMetrics("w3wp[1001]", 1001, "ErpPool", 1, 0, 100, 0, 9, 0, 0, 2, 2, 0, null, 0)
            ], []),
            NewEvents = []
        };
        aggregator.RecordSample(snap2, detector.Analyze(snap2, config));

        // Sample 3: 10 minutes later (outside merge gap -> second incident window)
        var snap3 = snap2 with
        {
            TimestampUtc = start.AddMinutes(10),
            SampleSequence = 3
        };
        aggregator.RecordSample(snap3, detector.Analyze(snap3, config));

        var report = aggregator.BuildReport(
            start.AddMinutes(11),
            isFinal: true,
            ["01_INCIDENTS_AND_ANOMALIES.jsonl", "02_TIMELINE_METRICS_2026-11-20.jsonl", "03_EVENTLOG_FINDINGS.jsonl"]);

        Assert.Equal(3, report.TotalSamples);
        Assert.Equal(2, report.TopIncidents.Count);
        Assert.Equal("ADO.NET Connection Pool Exhaustion / Unclosed DB Connections", report.Hypotheses[0].Title);
        Assert.Equal("HIGH", report.Hypotheses[0].Confidence);

        var erpPool = Assert.Single(report.AppPools);
        Assert.Equal("ErpPool", erpPool.AppPoolName);
        Assert.Equal(100, erpPool.MaxPooledConnections);
        Assert.Equal(6, erpPool.TotalReclaimedConnectionsDelta);
        Assert.Equal(12, erpPool.MaxDbCloseWaitSockets);
        Assert.Equal(35000, erpPool.MaxRequestElapsedMs);

        string formatted = AiExecutiveSummaryWriter.FormatReport(report);
        Assert.Contains("=== RUN_METADATA ===", formatted);
        Assert.Contains("=== RANKED_ROOT_CAUSE_HYPOTHESES ===", formatted);
        Assert.Contains("=== APP_POOL_HEALTH_MATRIX ===", formatted);
        Assert.Contains("=== TOP_INCIDENT_WINDOWS ===", formatted);
        Assert.Contains("=== OUTPUT_FILE_INDEX ===", formatted);
        Assert.Contains("ErpPool", formatted);
        Assert.Contains("/Reports/Balance", formatted);
    }
}
