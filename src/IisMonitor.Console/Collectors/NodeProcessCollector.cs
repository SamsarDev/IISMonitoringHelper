using System.Diagnostics;
using System.Management;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Collectors;

public sealed class NodeProcessCollector : INodeProcessCollector
{
    private readonly Dictionary<int, double> _previousCpuMsByPid = new();

    public NodeCollectionResult Collect(
        DateTimeOffset nowUtc,
        IReadOnlyDictionary<int, PidTcpSocketSummary> tcpByPid)
    {
        var warnings = new List<string>();
        var commandLines = QueryNodeCommandLines(warnings);
        var snapshots = new List<NodeProcessSnapshot>();
        var activePids = new HashSet<int>();

        Process[] processes;
        try
        {
            processes = Process.GetProcessesByName("node");
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to enumerate node.exe processes: {ex.Message}");
            return new NodeCollectionResult([], warnings);
        }

        foreach (var proc in processes)
        {
            using (proc)
            {
                try
                {
                    int pid = proc.Id;
                    activePids.Add(pid);

                    double wsMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 2);
                    int handles = proc.HandleCount;
                    int threads = proc.Threads.Count;

                    double totalCpuMs = 0;
                    try { totalCpuMs = Math.Round(proc.TotalProcessorTime.TotalMilliseconds, 1); } catch { }

                    DateTimeOffset? startUtc = null;
                    double? uptimeSec = null;
                    try
                    {
                        startUtc = new DateTimeOffset(proc.StartTime.ToUniversalTime(), TimeSpan.Zero);
                        uptimeSec = Math.Max(0, Math.Round((nowUtc - startUtc.Value).TotalSeconds, 1));
                    }
                    catch { }

                    double? cpuDelta = null;
                    if (_previousCpuMsByPid.TryGetValue(pid, out double prevCpu))
                    {
                        cpuDelta = Math.Max(0, Math.Round(totalCpuMs - prevCpu, 1));
                    }
                    _previousCpuMsByPid[pid] = totalCpuMs;

                    string cmdLine = commandLines.TryGetValue(pid, out var cl) ? cl : string.Empty;
                    string label = ExtractJobLabel(cmdLine, pid);
                    tcpByPid.TryGetValue(pid, out var tcpSummary);

                    snapshots.Add(new NodeProcessSnapshot(
                        Pid: pid,
                        JobLabel: label,
                        CommandLine: Truncate(cmdLine, 350),
                        StartTimeUtc: startUtc,
                        UptimeSeconds: uptimeSec,
                        WorkingSetMb: wsMb,
                        HandleCount: handles,
                        ThreadCount: threads,
                        TotalProcessorTimeMs: totalCpuMs,
                        CpuDeltaMs: cpuDelta,
                        TcpSummary: tcpSummary));
                }
                catch
                {
                    // Process may have exited mid-enumeration.
                }
            }
        }

        // Prune exited PIDs to keep memory bounded over 72 hours.
        var stalePids = _previousCpuMsByPid.Keys.Where(pid => !activePids.Contains(pid)).ToList();
        foreach (int stale in stalePids)
        {
            _previousCpuMsByPid.Remove(stale);
        }

        return new NodeCollectionResult(snapshots, warnings);
    }

    private static Dictionary<int, string> QueryNodeCommandLines(List<string> warnings)
    {
        var map = new Dictionary<int, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'node.exe'");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            {
                int pid = Convert.ToInt32(obj["ProcessId"]);
                string cmd = obj["CommandLine"]?.ToString() ?? string.Empty;
                map[pid] = cmd;
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"WMI node.exe command line query failed: {ex.Message}");
        }

        return map;
    }

    public static string ExtractJobLabel(string commandLine, int pid)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return $"node_pid_{pid}";
        }

        var tokens = SplitArgs(commandLine);
        // Skip executable (index 0) and leading node flags (-*, --*)
        for (int i = 1; i < tokens.Count; i++)
        {
            string token = tokens[i];
            if (token.StartsWith('-')) continue;
            string fileName = Path.GetFileName(token);
            if (!string.IsNullOrWhiteSpace(fileName))
            {
                return fileName;
            }
        }

        return $"node_pid_{pid}";
    }

    private static List<string> SplitArgs(string commandLine)
    {
        var result = new List<string>();
        bool inQuotes = false;
        int start = -1;

        for (int i = 0; i < commandLine.Length; i++)
        {
            char c = commandLine[i];
            if (c == '"')
            {
                if (!inQuotes)
                {
                    inQuotes = true;
                    start = i + 1;
                }
                else
                {
                    inQuotes = false;
                    if (start >= 0 && i >= start)
                    {
                        result.Add(commandLine[start..i]);
                    }
                    start = -1;
                }
            }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (start >= 0)
                {
                    result.Add(commandLine[start..i]);
                    start = -1;
                }
            }
            else if (start < 0)
            {
                start = i;
            }
        }

        if (start >= 0 && start < commandLine.Length)
        {
            result.Add(commandLine[start..]);
        }

        return result;
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];
}
