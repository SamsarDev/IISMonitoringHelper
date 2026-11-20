namespace IisMonitor.Domain;

public sealed record ActiveRequestInfo(
    string RequestId,
    string Url,
    string Verb,
    string ClientIp,
    string HostName,
    string PipelineState,
    string CurrentModule,
    long TimeElapsedMs,
    long TimeInStateMs);

public sealed record IisWorkerProcessInfo(
    int Pid,
    string AppPoolName,
    string AppPoolState,
    string WorkerState,
    double? WorkingSetMb,
    int? HandleCount,
    int? ThreadCount,
    double? TotalProcessorTimeMs,
    DateTimeOffset? StartTimeUtc,
    IReadOnlyList<ActiveRequestInfo> ActiveRequests,
    IReadOnlyList<string> BoundSites,
    double? CpuPercent = null);

public sealed record IisCollectionResult(
    string Source,
    IReadOnlyList<IisWorkerProcessInfo> Workers,
    IReadOnlyList<string> Warnings);

public sealed record AdoNetPoolMetrics(
    string InstanceName,
    int? Pid,
    string? AppPoolName,
    double? NumberOfActiveConnectionPools,
    double? NumberOfInactiveConnectionPools,
    double? NumberOfPooledConnections,
    double? NumberOfNonPooledConnections,
    double? NumberOfReclaimedConnections,
    double? HardConnectsPerSecond,
    double? HardDisconnectsPerSecond,
    double? SoftConnectsPerSecond,
    double? SoftDisconnectsPerSecond,
    double? NumberOfStasisConnections,
    double? NumberOfActiveConnections,
    double? NumberOfFreeConnections);

public sealed record AdoNetCollectionResult(
    bool CategoryAvailable,
    bool ActiveConnectionsCounterAvailable,
    IReadOnlyList<AdoNetPoolMetrics> Instances,
    IReadOnlyList<string> Warnings);

public sealed record AspNetGlobalMetrics(
    double? RequestsQueued,
    double? RequestsCurrent,
    double? RequestsRejected,
    double? RequestWaitTimeMs,
    double? WorkerProcessRestarts);

public sealed record AspNetAppMetrics(
    string InstanceName,
    double? RequestsExecuting,
    double? RequestsInApplicationQueue,
    double? RequestsTimedOut,
    double? RequestsFailed);

public sealed record HttpQueueMetrics(
    string AppPoolName,
    double? CurrentQueueSize,
    double? ArrivalRate,
    double? RejectedRequests);

public sealed record ClrProcessMetrics(
    string InstanceName,
    int? Pid,
    string? AppPoolName,
    double? ContentionRatePerSec,
    double? CurrentLockQueueLength,
    double? TotalContentions,
    double? LogicalThreads,
    double? PhysicalThreads,
    double? ExceptionsThrownPerSec,
    double? PercentTimeInGc,
    double? Gen2HeapSizeMb,
    double? TotalHeapSizeMb);

public sealed record AspNetAndClrCollectionResult(
    AspNetGlobalMetrics? AspNetGlobal,
    IReadOnlyList<AspNetAppMetrics> AspNetApps,
    IReadOnlyList<HttpQueueMetrics> HttpQueues,
    IReadOnlyList<ClrProcessMetrics> ClrProcesses,
    IReadOnlyList<string> Warnings);

public sealed record RawTcpConnection(
    int Pid,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    bool IsIpv6);

public sealed record RemoteEndpointCount(
    string RemoteEndpoint,
    int TotalCount,
    int EstablishedCount,
    int CloseWaitCount,
    int TimeWaitCount);

public sealed record PidTcpSocketSummary(
    int Pid,
    int TotalSockets,
    IReadOnlyDictionary<string, int> StateCounts,
    int DbTotalSockets,
    int DbEstablished,
    int DbCloseWait,
    int DbTimeWait,
    int DbSynSent,
    IReadOnlyList<RemoteEndpointCount> TopDbEndpoints);

public sealed record TcpCollectionResult(
    IReadOnlyDictionary<int, PidTcpSocketSummary> ByPid,
    int TotalSystemSockets,
    int TotalSystemTimeWait,
    int TotalSystemCloseWait,
    int TotalDbEstablished,
    int TotalDbCloseWait,
    IReadOnlyList<string> Warnings);

public sealed record NodeProcessSnapshot(
    int Pid,
    string JobLabel,
    string CommandLine,
    DateTimeOffset? StartTimeUtc,
    double? UptimeSeconds,
    double WorkingSetMb,
    int HandleCount,
    int ThreadCount,
    double TotalProcessorTimeMs,
    double? CpuDeltaMs,
    PidTcpSocketSummary? TcpSummary);

public sealed record NodeCollectionResult(
    IReadOnlyList<NodeProcessSnapshot> Processes,
    IReadOnlyList<string> Warnings);

public sealed record EventLogFinding(
    DateTimeOffset TimestampUtc,
    string LogName,
    long RecordId,
    int EventId,
    string Level,
    string Source,
    string Message,
    bool IsSqlPoolTimeout,
    bool IsWasRecycleOrCrash);

public sealed record EventLogCollectionResult(
    IReadOnlyList<EventLogFinding> Findings,
    IReadOnlyList<string> Warnings);

public sealed record TelemetrySnapshot(
    DateTimeOffset TimestampUtc,
    long SampleSequence,
    string MachineName,
    IisCollectionResult Iis,
    AdoNetCollectionResult AdoNet,
    AspNetAndClrCollectionResult AspNetAndClr,
    TcpCollectionResult Tcp,
    NodeCollectionResult Node,
    IReadOnlyList<EventLogFinding> NewEvents,
    IReadOnlyList<string> CollectorErrors);

public enum AnomalySeverity
{
    MEDIUM = 1,
    HIGH = 2,
    CRITICAL = 3
}

public sealed record AnomalyEvent(
    DateTimeOffset TimestampUtc,
    string Severity,
    string Code,
    string TargetType,
    string TargetName,
    int? Pid,
    string Summary,
    IReadOnlyDictionary<string, object?> Metrics);

public sealed record RootCauseHypothesis(
    int Rank,
    string Confidence,
    int Score,
    string Title,
    IReadOnlyList<string> Evidence);

public sealed record AppPoolHealthSummary(
    string AppPoolName,
    int SamplesObserved,
    int? LastKnownPid,
    int DistinctPidCount,
    int RecycleCount,
    double MaxPooledConnections,
    double? MaxActiveConnections,
    double TotalReclaimedConnectionsDelta,
    int MaxDbEstablishedSockets,
    int MaxDbCloseWaitSockets,
    int MaxHungRequests,
    long MaxRequestElapsedMs,
    double MaxHttpQueueSize,
    double MaxWorkingSetMb,
    IReadOnlyList<string> TopHungUrls,
    double? StartWorkingSetMb = null,
    double? AvgWorkingSetMb = null,
    double? EndWorkingSetMb = null,
    double? AvgCpuPercent = null,
    double? MaxCpuPercent = null,
    double? MaxGcPercent = null,
    double? MaxGen2HeapMb = null,
    double? MaxTotalHeapMb = null,
    double? MaxLogicalThreads = null);

public sealed record EventLogSignatureSummary(
    string Source,
    int EventId,
    string Level,
    string Signature,
    int Count,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc);

public sealed record NodeJobHealthSummary(
    string JobLabel,
    string SampleCommandLine,
    int SamplesObserved,
    int DistinctPidCount,
    double MaxUptimeMinutes,
    int MaxDbEstablishedSockets,
    int MaxDbCloseWaitSockets,
    double MaxWorkingSetMb,
    int ZombieDetections);

public sealed record IncidentWindowSummary(
    int IncidentId,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    double DurationSeconds,
    string MaxSeverity,
    int AnomalyCount,
    IReadOnlyList<string> Codes,
    IReadOnlyList<string> Targets,
    IReadOnlyList<string> SampleHungUrls,
    IReadOnlyList<string> CorrelatedEventSnippets);

public sealed record ExecutiveSummaryReport(
    string MachineName,
    DateTimeOffset RunStartUtc,
    DateTimeOffset LastSampleUtc,
    DateTimeOffset GeneratedAtUtc,
    bool IsFinal,
    long TotalSamples,
    int SampleIntervalSeconds,
    IReadOnlyList<int> DbPorts,
    bool IisAdminAvailable,
    bool AdoNetCategoryAvailable,
    bool AdoNetActiveConnectionsAvailable,
    IReadOnlyList<string> EnvironmentWarnings,
    IReadOnlyList<RootCauseHypothesis> Hypotheses,
    IReadOnlyDictionary<string, int> AnomalyCountsByCode,
    IReadOnlyList<AppPoolHealthSummary> AppPools,
    IReadOnlyList<NodeJobHealthSummary> NodeJobs,
    IReadOnlyList<IncidentWindowSummary> TopIncidents,
    IReadOnlyList<string> GeneratedFiles,
    IReadOnlyList<EventLogSignatureSummary>? TopEventLogSignatures = null);
