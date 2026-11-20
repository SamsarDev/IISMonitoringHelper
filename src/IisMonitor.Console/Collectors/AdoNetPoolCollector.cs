using System.Diagnostics;
using System.Text.RegularExpressions;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Collectors;

public sealed partial class AdoNetPoolCollector : IAdoNetPoolCollector
{
    public const string CategoryName = ".NET Data Provider for SqlServer";

    private static readonly string[] CounterNames =
    [
        "NumberOfActiveConnectionPools",
        "NumberOfInactiveConnectionPools",
        "NumberOfPooledConnections",
        "NumberOfNonPooledConnections",
        "NumberOfReclaimedConnections",
        "HardConnectsPerSecond",
        "HardDisconnectsPerSecond",
        "SoftConnectsPerSecond",
        "SoftDisconnectsPerSecond",
        "NumberOfStasisConnections",
        "NumberOfActiveConnections",
        "NumberOfFreeConnections"
    ];

    private readonly Dictionary<(string Instance, string Counter), PerformanceCounter> _counterCache = new();
    private bool _disposed;

    [GeneratedRegex(@"\[(\d+)\]$", RegexOptions.Compiled)]
    private static partial Regex TrailingPidRegex();

    public AdoNetCollectionResult Collect(IReadOnlyDictionary<int, string> pidToAppPool)
    {
        var warnings = new List<string>();

        bool categoryExists;
        try
        {
            categoryExists = PerformanceCounterCategory.Exists(CategoryName);
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed checking PerfCounter category '{CategoryName}': {ex.Message}");
            return new AdoNetCollectionResult(false, false, [], warnings);
        }

        if (!categoryExists)
        {
            warnings.Add($"Performance counter category '{CategoryName}' does not exist on this machine.");
            return new AdoNetCollectionResult(false, false, [], warnings);
        }

        string[] instanceNames;
        bool activeCounterExists = false;
        try
        {
            var category = new PerformanceCounterCategory(CategoryName);
            activeCounterExists = category.CounterExists("NumberOfActiveConnections");
            instanceNames = category.GetInstanceNames();
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed enumerating instances for '{CategoryName}': {ex.Message}");
            return new AdoNetCollectionResult(true, false, [], warnings);
        }

        var activeInstances = new HashSet<string>(instanceNames, StringComparer.OrdinalIgnoreCase);
        PruneStaleCounters(activeInstances);

        var results = new List<AdoNetPoolMetrics>();
        bool anyActiveValueRead = false;

        foreach (string instance in instanceNames)
        {
            int? pid = ParsePidFromInstanceName(instance);
            string? appPool = pid.HasValue && pidToAppPool.TryGetValue(pid.Value, out var ap) ? ap : null;

            double? activePools = ReadCounter(instance, "NumberOfActiveConnectionPools");
            double? inactivePools = ReadCounter(instance, "NumberOfInactiveConnectionPools");
            double? pooled = ReadCounter(instance, "NumberOfPooledConnections");
            double? nonPooled = ReadCounter(instance, "NumberOfNonPooledConnections");
            double? reclaimed = ReadCounter(instance, "NumberOfReclaimedConnections");
            double? hardConn = ReadCounter(instance, "HardConnectsPerSecond");
            double? hardDisc = ReadCounter(instance, "HardDisconnectsPerSecond");
            double? softConn = ReadCounter(instance, "SoftConnectsPerSecond");
            double? softDisc = ReadCounter(instance, "SoftDisconnectsPerSecond");
            double? stasis = ReadCounter(instance, "NumberOfStasisConnections");
            double? activeConns = activeCounterExists ? ReadCounter(instance, "NumberOfActiveConnections") : null;
            double? freeConns = ReadCounter(instance, "NumberOfFreeConnections");

            if (activeConns.HasValue)
            {
                anyActiveValueRead = true;
            }

            results.Add(new AdoNetPoolMetrics(
                InstanceName: instance,
                Pid: pid,
                AppPoolName: appPool,
                NumberOfActiveConnectionPools: activePools,
                NumberOfInactiveConnectionPools: inactivePools,
                NumberOfPooledConnections: pooled,
                NumberOfNonPooledConnections: nonPooled,
                NumberOfReclaimedConnections: reclaimed,
                HardConnectsPerSecond: hardConn,
                HardDisconnectsPerSecond: hardDisc,
                SoftConnectsPerSecond: softConn,
                SoftDisconnectsPerSecond: softDisc,
                NumberOfStasisConnections: stasis,
                NumberOfActiveConnections: activeConns,
                NumberOfFreeConnections: freeConns));
        }

        bool activeAvailable = activeCounterExists && (instanceNames.Length == 0 || anyActiveValueRead);
        if (!activeAvailable)
        {
            warnings.Add(
                "ADO.NET 'NumberOfActiveConnections' counter is unavailable or disabled (common default in .NET Framework 4.5 unless enabled in machine.config). Use NumberOfPooledConnections, NumberOfReclaimedConnections, and TCP DB socket counts.");
        }

        return new AdoNetCollectionResult(true, activeAvailable, results, warnings);
    }

    public static int? ParsePidFromInstanceName(string instanceName)
    {
        if (string.IsNullOrWhiteSpace(instanceName)) return null;
        var match = TrailingPidRegex().Match(instanceName);
        if (match.Success && int.TryParse(match.Groups[1].Value, out int pid))
        {
            return pid;
        }
        return null;
    }

    private double? ReadCounter(string instanceName, string counterName)
    {
        var key = (instanceName, counterName);
        try
        {
            if (!_counterCache.TryGetValue(key, out var counter))
            {
                counter = new PerformanceCounter(CategoryName, counterName, instanceName, readOnly: true);
                _counterCache[key] = counter;
            }

            return Math.Round(counter.NextValue(), 2);
        }
        catch
        {
            if (_counterCache.Remove(key, out var failed))
            {
                failed.Dispose();
            }
            return null;
        }
    }

    private void PruneStaleCounters(HashSet<string> activeInstances)
    {
        var staleKeys = _counterCache.Keys
            .Where(k => !activeInstances.Contains(k.Instance))
            .ToList();

        foreach (var key in staleKeys)
        {
            if (_counterCache.Remove(key, out var counter))
            {
                counter.Dispose();
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var counter in _counterCache.Values)
        {
            counter.Dispose();
        }
        _counterCache.Clear();
    }
}
