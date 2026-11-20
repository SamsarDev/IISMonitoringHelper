using IisMonitor.Abstractions;
using IisMonitor.Analysis;
using IisMonitor.Domain;
using IisMonitor.Engine;
using IisMonitor.Reporting;

namespace IisMonitor.Tests;

public sealed class MonitorRunnerTests
{
    [Fact]
    public async Task Runner_IsolatesCollectorErrors_And_WritesAllReports()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"iismon-test-{Guid.NewGuid():N}");
        try
        {
            var config = new MonitorConfig
            {
                DurationSecondsOverride = 3,
                SampleIntervalSeconds = 1,
                CheckpointIntervalMinutes = 1,
                OutputDirectory = tempDir
            };

            var clock = new FakeClock(new DateTimeOffset(2026, 11, 20, 14, 0, 0, TimeSpan.Zero));
            using var telemetryWriter = new JsonlTelemetryWriter(tempDir);
            var summaryWriter = new AiExecutiveSummaryWriter(tempDir);

            using var throwingAdo = new ThrowingAdoCollector();
            using var fakeAspClr = new FakeAspNetAndClrCollector();

            var runner = new MonitorRunner(
                config: config,
                clock: clock,
                iisCollector: new FakeIisCollector(),
                adoNetCollector: throwingAdo,
                aspNetAndClrCollector: fakeAspClr,
                tcpCollector: new FakeTcpCollector(),
                nodeCollector: new FakeNodeCollector(),
                eventLogCollector: new FakeEventLogCollector(),
                anomalyDetector: new AnomalyDetector(),
                telemetryWriter: telemetryWriter,
                summaryWriter: summaryWriter,
                log: _ => { });

            var report = await runner.RunAsync(CancellationToken.None);
            telemetryWriter.Dispose();

            Assert.True(report.IsFinal);
            Assert.Equal(3, report.TotalSamples);
            Assert.Contains(report.EnvironmentWarnings, w => w.Contains("AdoNetCollector error"));

            string summaryPath = Path.Combine(tempDir, AiExecutiveSummaryWriter.SummaryFileName);
            string timelinePath = Path.Combine(tempDir, "02_TIMELINE_METRICS_2026-11-20.jsonl");
            string anomaliesPath = Path.Combine(tempDir, JsonlTelemetryWriter.AnomaliesFileName);
            string eventsPath = Path.Combine(tempDir, JsonlTelemetryWriter.EventLogFileName);

            Assert.True(File.Exists(summaryPath));
            Assert.True(File.Exists(timelinePath));
            Assert.True(File.Exists(anomaliesPath));
            Assert.True(File.Exists(eventsPath));

            var timelineLines = await File.ReadAllLinesAsync(timelinePath);
            Assert.Equal(3, timelineLines.Length);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    private sealed class FakeClock(DateTimeOffset start) : IClock
    {
        public DateTimeOffset UtcNow { get; private set; } = start;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            UtcNow += delay;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeIisCollector : IIisWorkerProcessCollector
    {
        public IisCollectionResult Collect(IReadOnlySet<string> appPoolFilter) =>
            new("IIS_ADMIN",
            [
                new IisWorkerProcessInfo(1010, "MainPool", "Started", "Running", 180, 400, 30, 500, null, [], ["Site1/"])
            ], []);
    }

    private sealed class ThrowingAdoCollector : IAdoNetPoolCollector
    {
        public AdoNetCollectionResult Collect(IReadOnlyDictionary<int, string> pidToAppPool) =>
            throw new InvalidOperationException("Simulated PerfCounter failure");
        public void Dispose() { }
    }

    private sealed class FakeAspNetAndClrCollector : IAspNetAndClrCollector
    {
        public AspNetAndClrCollectionResult Collect(IReadOnlyDictionary<int, string> pidToAppPool) =>
            new(null, [], [], [], []);
        public void Dispose() { }
    }

    private sealed class FakeTcpCollector : ITcpSocketCollector
    {
        public TcpCollectionResult Collect(IReadOnlySet<int> dbPorts) =>
            new(new Dictionary<int, PidTcpSocketSummary>(), 10, 0, 0, 2, 0, []);
    }

    private sealed class FakeNodeCollector : INodeProcessCollector
    {
        public NodeCollectionResult Collect(DateTimeOffset nowUtc, IReadOnlyDictionary<int, PidTcpSocketSummary> tcpByPid) =>
            new([], []);
    }

    private sealed class FakeEventLogCollector : IWindowsEventLogCollector
    {
        public EventLogCollectionResult Collect(DateTimeOffset nowUtc) =>
            new([], []);
    }
}
