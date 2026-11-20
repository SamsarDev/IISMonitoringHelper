using IisMonitor.Domain;

namespace IisMonitor.Abstractions;

public interface IClock
{
    DateTimeOffset UtcNow { get; }
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

public interface IIisWorkerProcessCollector
{
    IisCollectionResult Collect(IReadOnlySet<string> appPoolFilter);
}

public interface IAdoNetPoolCollector : IDisposable
{
    AdoNetCollectionResult Collect(IReadOnlyDictionary<int, string> pidToAppPool);
}

public interface IAspNetAndClrCollector : IDisposable
{
    AspNetAndClrCollectionResult Collect(IReadOnlyDictionary<int, string> pidToAppPool);
}

public interface ITcpSocketCollector
{
    TcpCollectionResult Collect(IReadOnlySet<int> dbPorts);
}

public interface INodeProcessCollector
{
    NodeCollectionResult Collect(DateTimeOffset nowUtc, IReadOnlyDictionary<int, PidTcpSocketSummary> tcpByPid);
}

public interface IWindowsEventLogCollector
{
    EventLogCollectionResult Collect(DateTimeOffset nowUtc);
}

public interface IAnomalyDetector
{
    IReadOnlyList<AnomalyEvent> Analyze(TelemetrySnapshot snapshot, MonitorConfig config);
}

public interface ITelemetryWriter : IDisposable
{
    IReadOnlyList<string> GetGeneratedFiles();
    Task WriteSnapshotAsync(TelemetrySnapshot snapshot, CancellationToken cancellationToken);
    Task WriteAnomaliesAsync(IReadOnlyList<AnomalyEvent> anomalies, CancellationToken cancellationToken);
    Task WriteEventFindingsAsync(IReadOnlyList<EventLogFinding> findings, CancellationToken cancellationToken);
}

public interface IExecutiveSummaryWriter
{
    Task WriteSummaryAsync(ExecutiveSummaryReport report, CancellationToken cancellationToken);
}
