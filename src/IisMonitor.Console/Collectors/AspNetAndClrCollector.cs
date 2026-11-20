using System.Diagnostics;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Collectors;

public sealed class AspNetAndClrCollector : IAspNetAndClrCollector
{
    private const string AspNetGlobalCategory = "ASP.NET v4.0.30319";
    private const string AspNetAppsCategory = "ASP.NET Apps v4.0.30319";
    private const string HttpQueueCategory = "HTTP Service Request Queues";
    private const string ClrLocksCategory = ".NET CLR LocksAndThreads";
    private const string ClrExceptionsCategory = ".NET CLR Exceptions";
    private const string ClrMemoryCategory = ".NET CLR Memory";

    private readonly Dictionary<(string Category, string Counter, string Instance), PerformanceCounter> _cache = new();
    private bool _disposed;

    public AspNetAndClrCollectionResult Collect(IReadOnlyDictionary<int, string> pidToAppPool)
    {
        var warnings = new List<string>();
        var activeKeys = new HashSet<(string Category, string Counter, string Instance)>();

        AspNetGlobalMetrics? globalMetrics = CollectAspNetGlobal(activeKeys, warnings);
        var appMetrics = CollectAspNetApps(activeKeys, warnings);
        var httpQueues = CollectHttpQueues(activeKeys, warnings);
        var clrProcesses = CollectClrProcesses(pidToAppPool, activeKeys, warnings);

        PruneStaleCounters(activeKeys);

        return new AspNetAndClrCollectionResult(
            AspNetGlobal: globalMetrics,
            AspNetApps: appMetrics,
            HttpQueues: httpQueues,
            ClrProcesses: clrProcesses,
            Warnings: warnings);
    }

    private AspNetGlobalMetrics? CollectAspNetGlobal(
        HashSet<(string, string, string)> activeKeys,
        List<string> warnings)
    {
        try
        {
            if (!PerformanceCounterCategory.Exists(AspNetGlobalCategory))
            {
                return null;
            }

            return new AspNetGlobalMetrics(
                RequestsQueued: ReadCounter(AspNetGlobalCategory, "Requests Queued", string.Empty, activeKeys),
                RequestsCurrent: ReadCounter(AspNetGlobalCategory, "Requests Current", string.Empty, activeKeys),
                RequestsRejected: ReadCounter(AspNetGlobalCategory, "Requests Rejected", string.Empty, activeKeys),
                RequestWaitTimeMs: ReadCounter(AspNetGlobalCategory, "Request Wait Time", string.Empty, activeKeys),
                WorkerProcessRestarts: ReadCounter(AspNetGlobalCategory, "Worker Process Restarts", string.Empty, activeKeys));
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed reading '{AspNetGlobalCategory}': {ex.Message}");
            return null;
        }
    }

    private List<AspNetAppMetrics> CollectAspNetApps(
        HashSet<(string, string, string)> activeKeys,
        List<string> warnings)
    {
        var list = new List<AspNetAppMetrics>();
        try
        {
            if (!PerformanceCounterCategory.Exists(AspNetAppsCategory))
            {
                return list;
            }

            var category = new PerformanceCounterCategory(AspNetAppsCategory);
            var instances = category.GetInstanceNames();

            // Always include __Total__ plus up to 25 individual app instances to stay bounded.
            foreach (string instance in instances
                         .OrderByDescending(i => i.Equals("__Total__", StringComparison.OrdinalIgnoreCase))
                         .ThenBy(i => i, StringComparer.OrdinalIgnoreCase)
                         .Take(26))
            {
                list.Add(new AspNetAppMetrics(
                    InstanceName: instance,
                    RequestsExecuting: ReadCounter(AspNetAppsCategory, "Requests Executing", instance, activeKeys),
                    RequestsInApplicationQueue: ReadCounter(AspNetAppsCategory, "Requests In Application Queue", instance, activeKeys),
                    RequestsTimedOut: ReadCounter(AspNetAppsCategory, "Requests Timed Out", instance, activeKeys),
                    RequestsFailed: ReadCounter(AspNetAppsCategory, "Requests Failed", instance, activeKeys)));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed reading '{AspNetAppsCategory}': {ex.Message}");
        }

        return list;
    }

    private List<HttpQueueMetrics> CollectHttpQueues(
        HashSet<(string, string, string)> activeKeys,
        List<string> warnings)
    {
        var list = new List<HttpQueueMetrics>();
        try
        {
            if (!PerformanceCounterCategory.Exists(HttpQueueCategory))
            {
                return list;
            }

            var category = new PerformanceCounterCategory(HttpQueueCategory);
            foreach (string instance in category.GetInstanceNames().Take(50))
            {
                list.Add(new HttpQueueMetrics(
                    AppPoolName: instance,
                    CurrentQueueSize: ReadCounter(HttpQueueCategory, "CurrentQueueSize", instance, activeKeys),
                    ArrivalRate: ReadCounter(HttpQueueCategory, "ArrivalRate", instance, activeKeys),
                    RejectedRequests: ReadCounter(HttpQueueCategory, "RejectedRequests", instance, activeKeys)));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed reading '{HttpQueueCategory}': {ex.Message}");
        }

        return list;
    }

    private List<ClrProcessMetrics> CollectClrProcesses(
        IReadOnlyDictionary<int, string> pidToAppPool,
        HashSet<(string, string, string)> activeKeys,
        List<string> warnings)
    {
        var list = new List<ClrProcessMetrics>();
        try
        {
            if (!PerformanceCounterCategory.Exists(ClrMemoryCategory))
            {
                return list;
            }

            var memCategory = new PerformanceCounterCategory(ClrMemoryCategory);
            var w3wpInstances = memCategory.GetInstanceNames()
                .Where(i => i.StartsWith("w3wp", StringComparison.OrdinalIgnoreCase))
                .ToList();

            bool hasLocks = PerformanceCounterCategory.Exists(ClrLocksCategory);
            bool hasExceps = PerformanceCounterCategory.Exists(ClrExceptionsCategory);

            foreach (string instance in w3wpInstances)
            {
                double? pidVal = ReadCounter(ClrMemoryCategory, "Process ID", instance, activeKeys);
                int? pid = pidVal.HasValue ? (int)Math.Round(pidVal.Value) : null;
                string? appPool = pid.HasValue && pidToAppPool.TryGetValue(pid.Value, out var ap) ? ap : null;

                double? gen2Bytes = ReadCounter(ClrMemoryCategory, "Gen 2 heap size", instance, activeKeys);
                double? totalBytes = ReadCounter(ClrMemoryCategory, "# Bytes in all Heaps", instance, activeKeys);

                list.Add(new ClrProcessMetrics(
                    InstanceName: instance,
                    Pid: pid,
                    AppPoolName: appPool,
                    ContentionRatePerSec: hasLocks ? ReadCounter(ClrLocksCategory, "Contention Rate / sec", instance, activeKeys) : null,
                    CurrentLockQueueLength: hasLocks ? ReadCounter(ClrLocksCategory, "Current Queue Length", instance, activeKeys) : null,
                    TotalContentions: hasLocks ? ReadCounter(ClrLocksCategory, "Total # of Contentions", instance, activeKeys) : null,
                    LogicalThreads: hasLocks ? ReadCounter(ClrLocksCategory, "# of current logical Threads", instance, activeKeys) : null,
                    PhysicalThreads: hasLocks ? ReadCounter(ClrLocksCategory, "# of current physical Threads", instance, activeKeys) : null,
                    ExceptionsThrownPerSec: hasExceps ? ReadCounter(ClrExceptionsCategory, "# of Exceps Thrown / sec", instance, activeKeys) : null,
                    PercentTimeInGc: ReadCounter(ClrMemoryCategory, "% Time in GC", instance, activeKeys),
                    Gen2HeapSizeMb: gen2Bytes.HasValue ? Math.Round(gen2Bytes.Value / (1024.0 * 1024.0), 2) : null,
                    TotalHeapSizeMb: totalBytes.HasValue ? Math.Round(totalBytes.Value / (1024.0 * 1024.0), 2) : null));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed reading CLR performance counters: {ex.Message}");
        }

        return list;
    }

    private double? ReadCounter(
        string category,
        string counterName,
        string instance,
        HashSet<(string, string, string)> activeKeys)
    {
        var key = (category, counterName, instance);
        activeKeys.Add(key);

        try
        {
            if (!_cache.TryGetValue(key, out var counter))
            {
                counter = string.IsNullOrEmpty(instance)
                    ? new PerformanceCounter(category, counterName, readOnly: true)
                    : new PerformanceCounter(category, counterName, instance, readOnly: true);
                _cache[key] = counter;
            }

            return Math.Round(counter.NextValue(), 2);
        }
        catch
        {
            if (_cache.Remove(key, out var failed))
            {
                failed.Dispose();
            }
            return null;
        }
    }

    private void PruneStaleCounters(HashSet<(string, string, string)> activeKeys)
    {
        var stale = _cache.Keys.Where(k => !activeKeys.Contains(k)).ToList();
        foreach (var key in stale)
        {
            if (_cache.Remove(key, out var counter))
            {
                counter.Dispose();
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var counter in _cache.Values)
        {
            counter.Dispose();
        }
        _cache.Clear();
    }
}
