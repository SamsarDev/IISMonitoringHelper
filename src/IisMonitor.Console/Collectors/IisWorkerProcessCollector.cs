using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using IisMonitor.Abstractions;
using IisMonitor.Domain;
using Microsoft.Web.Administration;

namespace IisMonitor.Collectors;

public sealed partial class IisWorkerProcessCollector : IIisWorkerProcessCollector
{
    private const int MaxRequestsPerWorker = 100;

    private readonly Dictionary<int, (double TotalCpuMs, DateTimeOffset SampleUtc)> _prevCpuByPid = new();

    [GeneratedRegex(@"(?i)-ap\s+""([^""]+)""|(?i)-ap\s+(\S+)", RegexOptions.Compiled)]
    private static partial Regex AppPoolArgRegex();

    public IisCollectionResult Collect(IReadOnlySet<string> appPoolFilter)
    {
        var warnings = new List<string>();
        var sampleUtc = DateTimeOffset.UtcNow;

        IisCollectionResult result;
        try
        {
            result = CollectViaServerManager(appPoolFilter, sampleUtc, warnings);
        }
        catch (Exception ex)
        {
            warnings.Add($"IIS ServerManager unavailable ({ex.GetType().Name}: {ex.Message}). Falling back to WMI w3wp.exe discovery.");
            result = CollectViaWmiFallback(appPoolFilter, sampleUtc, warnings);
        }

        PruneExitedPids(result.Workers.Select(w => w.Pid).ToHashSet());
        return result;
    }

    internal double? ComputeCpuPercent(int pid, double? totalProcessorTimeMs, DateTimeOffset sampleUtc, int processorCount)
    {
        if (!totalProcessorTimeMs.HasValue)
        {
            return null;
        }

        double currentCpuMs = totalProcessorTimeMs.Value;
        double? cpuPercent = null;

        if (_prevCpuByPid.TryGetValue(pid, out var prev))
        {
            double deltaWallMs = (sampleUtc - prev.SampleUtc).TotalMilliseconds;
            double deltaCpuMs = currentCpuMs - prev.TotalCpuMs;
            if (deltaWallMs > 0 && deltaCpuMs >= 0 && processorCount > 0)
            {
                double rawPct = (deltaCpuMs / (deltaWallMs * processorCount)) * 100.0;
                cpuPercent = Math.Round(Math.Clamp(rawPct, 0.0, 100.0), 1);
            }
        }

        _prevCpuByPid[pid] = (currentCpuMs, sampleUtc);
        return cpuPercent;
    }

    internal void PruneExitedPids(IReadOnlySet<int> activePids)
    {
        var stale = _prevCpuByPid.Keys.Where(pid => !activePids.Contains(pid)).ToList();
        foreach (int pid in stale)
        {
            _prevCpuByPid.Remove(pid);
        }
    }

    internal int TrackedPidCount => _prevCpuByPid.Count;

    private IisCollectionResult CollectViaServerManager(
        IReadOnlySet<string> appPoolFilter,
        DateTimeOffset sampleUtc,
        List<string> warnings)
    {
        using var serverManager = new ServerManager();

        var poolStates = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pool in serverManager.ApplicationPools)
        {
            try
            {
                poolStates[pool.Name] = pool.State.ToString();
            }
            catch
            {
                poolStates[pool.Name] = "Unknown";
            }
        }

        var sitesByPool = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var site in serverManager.Sites)
        {
            try
            {
                foreach (var app in site.Applications)
                {
                    if (string.IsNullOrWhiteSpace(app.ApplicationPoolName)) continue;
                    if (!sitesByPool.TryGetValue(app.ApplicationPoolName, out var siteSet))
                    {
                        siteSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        sitesByPool[app.ApplicationPoolName] = siteSet;
                    }
                    siteSet.Add($"{site.Name}{app.Path}");
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Failed reading site '{site.Name}' bindings: {ex.Message}");
            }
        }

        var workers = new List<IisWorkerProcessInfo>();
        foreach (var wp in serverManager.WorkerProcesses)
        {
            string appPoolName;
            int pid;
            string workerState;
            try
            {
                appPoolName = wp.AppPoolName ?? "Unknown";
                pid = wp.ProcessId;
                workerState = wp.State.ToString();
            }
            catch (Exception ex)
            {
                warnings.Add($"Failed reading WorkerProcess metadata: {ex.Message}");
                continue;
            }

            if (appPoolFilter.Count > 0 && !appPoolFilter.Contains(appPoolName))
            {
                continue;
            }

            var activeRequests = new List<ActiveRequestInfo>();
            try
            {
                var requests = wp.GetRequests(0);
                foreach (var req in requests
                             .OrderByDescending(r => r.TimeElapsed)
                             .Take(MaxRequestsPerWorker))
                {
                    activeRequests.Add(new ActiveRequestInfo(
                        RequestId: req.RequestId ?? string.Empty,
                        Url: Truncate(req.Url ?? string.Empty, 300),
                        Verb: req.Verb ?? string.Empty,
                        ClientIp: req.ClientIPAddr ?? string.Empty,
                        HostName: req.HostName ?? string.Empty,
                        PipelineState: req.PipelineState.ToString(),
                        CurrentModule: req.CurrentModule ?? string.Empty,
                        TimeElapsedMs: req.TimeElapsed,
                        TimeInStateMs: req.TimeInState));
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"WorkerProcess.GetRequests failed for AppPool '{appPoolName}' (PID {pid}): {ex.Message}");
            }

            var procStats = TryReadProcessMetrics(pid);
            double? cpuPct = ComputeCpuPercent(pid, procStats.TotalProcessorTimeMs, sampleUtc, Environment.ProcessorCount);
            var boundSites = sitesByPool.TryGetValue(appPoolName, out var sites)
                ? sites.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).Take(10).ToList()
                : [];

            workers.Add(new IisWorkerProcessInfo(
                Pid: pid,
                AppPoolName: appPoolName,
                AppPoolState: poolStates.TryGetValue(appPoolName, out var st) ? st : "Unknown",
                WorkerState: workerState,
                WorkingSetMb: procStats.WorkingSetMb,
                HandleCount: procStats.HandleCount,
                ThreadCount: procStats.ThreadCount,
                TotalProcessorTimeMs: procStats.TotalProcessorTimeMs,
                StartTimeUtc: procStats.StartTimeUtc,
                ActiveRequests: activeRequests,
                BoundSites: boundSites,
                CpuPercent: cpuPct));
        }

        return new IisCollectionResult("IIS_ADMIN", workers, warnings);
    }

    private IisCollectionResult CollectViaWmiFallback(
        IReadOnlySet<string> appPoolFilter,
        DateTimeOffset sampleUtc,
        List<string> warnings)
    {
        var workers = new List<IisWorkerProcessInfo>();
        var pidToPool = new Dictionary<int, string>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'w3wp.exe'");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            {
                int pid = Convert.ToInt32(obj["ProcessId"]);
                string cmdLine = obj["CommandLine"]?.ToString() ?? string.Empty;
                string appPool = ParseAppPoolFromCommandLine(cmdLine) ?? $"w3wp_pid_{pid}";
                pidToPool[pid] = appPool;
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"WMI w3wp.exe query failed ({ex.Message}). Trying Process.GetProcessesByName fallback.");
            try
            {
                foreach (var proc in Process.GetProcessesByName("w3wp"))
                {
                    using (proc)
                    {
                        pidToPool[proc.Id] = $"w3wp_pid_{proc.Id}";
                    }
                }
            }
            catch (Exception inner)
            {
                warnings.Add($"Process.GetProcessesByName('w3wp') failed: {inner.Message}");
            }
        }

        foreach (var (pid, appPoolName) in pidToPool)
        {
            if (appPoolFilter.Count > 0 && !appPoolFilter.Contains(appPoolName))
            {
                continue;
            }

            var procStats = TryReadProcessMetrics(pid);
            double? cpuPct = ComputeCpuPercent(pid, procStats.TotalProcessorTimeMs, sampleUtc, Environment.ProcessorCount);
            workers.Add(new IisWorkerProcessInfo(
                Pid: pid,
                AppPoolName: appPoolName,
                AppPoolState: "Unknown",
                WorkerState: "Running",
                WorkingSetMb: procStats.WorkingSetMb,
                HandleCount: procStats.HandleCount,
                ThreadCount: procStats.ThreadCount,
                TotalProcessorTimeMs: procStats.TotalProcessorTimeMs,
                StartTimeUtc: procStats.StartTimeUtc,
                ActiveRequests: [],
                BoundSites: [],
                CpuPercent: cpuPct));
        }

        return new IisCollectionResult("WMI_FALLBACK", workers, warnings);
    }

    public static string? ParseAppPoolFromCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var match = AppPoolArgRegex().Match(commandLine);
        if (!match.Success) return null;
        return !string.IsNullOrEmpty(match.Groups[1].Value)
            ? match.Groups[1].Value
            : match.Groups[2].Value;
    }

    private static (double? WorkingSetMb, int? HandleCount, int? ThreadCount, double? TotalProcessorTimeMs, DateTimeOffset? StartTimeUtc)
        TryReadProcessMetrics(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            double wsMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 2);
            int handles = proc.HandleCount;
            int threads = proc.Threads.Count;

            double? cpuMs = null;
            DateTimeOffset? startUtc = null;
            try { cpuMs = Math.Round(proc.TotalProcessorTime.TotalMilliseconds, 1); } catch { }
            try { startUtc = new DateTimeOffset(proc.StartTime.ToUniversalTime(), TimeSpan.Zero); } catch { }

            return (wsMb, handles, threads, cpuMs, startUtc);
        }
        catch
        {
            return (null, null, null, null, null);
        }
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];
}
