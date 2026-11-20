namespace IisMonitor.Domain;

public sealed class MonitorConfig
{
    public double DurationHours { get; set; } = 72;
    public int? DurationSecondsOverride { get; set; }
    public int SampleIntervalSeconds { get; set; } = 15;
    public int CheckpointIntervalMinutes { get; set; } = 60;
    public string OutputDirectory { get; set; } = "./monitor-output";
    public List<int> DbPorts { get; set; } = [1433];
    public List<string> AppPoolFilter { get; set; } = [];
    public int EventLogLookbackMinutes { get; set; } = 5;
    public bool RunOnce { get; set; }
    public ThresholdConfig Thresholds { get; set; } = new();

    public TimeSpan EffectiveDuration =>
        DurationSecondsOverride.HasValue
            ? TimeSpan.FromSeconds(Math.Max(1, DurationSecondsOverride.Value))
            : TimeSpan.FromHours(Math.Max(0.001, DurationHours));

    public HashSet<int> GetDbPortSet() =>
        DbPorts.Count > 0 ? new HashSet<int>(DbPorts) : [1433];

    public HashSet<string> GetAppPoolFilterSet() =>
        new(AppPoolFilter.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

    public void Normalize()
    {
        if (SampleIntervalSeconds < 1)
        {
            SampleIntervalSeconds = 1;
        }

        if (CheckpointIntervalMinutes < 1)
        {
            CheckpointIntervalMinutes = 1;
        }

        if (EventLogLookbackMinutes < 0)
        {
            EventLogLookbackMinutes = 0;
        }

        if (string.IsNullOrWhiteSpace(OutputDirectory))
        {
            OutputDirectory = "./monitor-output";
        }

        Thresholds ??= new ThresholdConfig();
    }
}

public sealed class ThresholdConfig
{
    public int ConnectionPoolWarningCount { get; set; } = 75;
    public int ConnectionPoolCriticalCount { get; set; } = 95;
    public int DbEstablishedWarningCount { get; set; } = 80;
    public int DbEstablishedCriticalCount { get; set; } = 100;
    public int DbCloseWaitWarningCount { get; set; } = 5;
    public int DbCloseWaitCriticalCount { get; set; } = 15;
    public int TimeWaitChurnCount { get; set; } = 200;
    public long HungRequestThresholdMs { get; set; } = 10_000;
    public long CriticalHungRequestThresholdMs { get; set; } = 30_000;
    public int AspNetQueueWarningCount { get; set; } = 20;
    public int HttpQueueWarningCount { get; set; } = 20;
    public double ThreadContentionPerSecWarning { get; set; } = 25.0;
    public double ExceptionsPerSecWarning { get; set; } = 20.0;
    public int NodeZombieUptimeMinutes { get; set; } = 30;
    public double NodeStalledCpuDeltaMs { get; set; } = 100.0;
    public int IncidentMergeGapSeconds { get; set; } = 180;
}
