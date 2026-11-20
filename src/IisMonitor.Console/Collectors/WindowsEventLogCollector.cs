using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Collectors;

public sealed partial class WindowsEventLogCollector : IWindowsEventLogCollector
{
    public const int MaxStoredMessageLength = 4000;

    [GeneratedRegex(@"Exception type:\s*(?<val>.+?)(?=\s+Exception message:|\s+Request information:|\s+Thread information:|\r|\n|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ExceptionTypeRegex();

    [GeneratedRegex(@"Exception message:\s*(?<val>.+?)(?=\s+at\s+\S+|\s+Request information:|\s+Thread information:|\s+Custom event details:|\r|\n|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ExceptionMessageRegex();

    [GeneratedRegex(@"Request URL:\s*(?<val>\S+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex RequestUrlRegex();
    private static readonly string[] TargetLogs = ["Application", "System"];

    private static readonly string[] RelevantSourcePrefixes =
    [
        "ASP.NET",
        ".NET Runtime",
        "WAS",
        "W3SVC",
        "IIS",
        "Application Error",
        "HTTP",
        "SqlClient",
        "MSSQL",
        "Node",
        "Windows Error Reporting"
    ];

    private static readonly HashSet<int> WasRecycleOrCrashEventIds =
    [
        5002, 5009, 5011, 5074, 5075, 5076, 5077, 5079, 5080, 5139
    ];

    private readonly Dictionary<string, long> _lastRecordIdByLog = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _lastTimestampByLog = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _lookbackMinutes;
    private bool _initialized;

    public WindowsEventLogCollector(int lookbackMinutes = 5)
    {
        _lookbackMinutes = Math.Max(0, lookbackMinutes);
    }

    public EventLogCollectionResult Collect(DateTimeOffset nowUtc)
    {
        if (!_initialized)
        {
            var initialCursor = nowUtc.AddMinutes(-_lookbackMinutes);
            foreach (string log in TargetLogs)
            {
                _lastTimestampByLog[log] = initialCursor;
            }
            _initialized = true;
        }

        var findings = new List<EventLogFinding>();
        var warnings = new List<string>();

        foreach (string logName in TargetLogs)
        {
            try
            {
                ReadLogIncremental(logName, findings);
            }
            catch (Exception ex)
            {
                warnings.Add($"EventLog '{logName}' read failed: {ex.Message}");
            }
        }

        return new EventLogCollectionResult(
            findings.OrderBy(f => f.TimestampUtc).ThenBy(f => f.RecordId).ToList(),
            warnings);
    }

    private void ReadLogIncremental(string logName, List<EventLogFinding> findings)
    {
        DateTimeOffset cursorTime = _lastTimestampByLog[logName];
        long lastRecordId = _lastRecordIdByLog.TryGetValue(logName, out long rid) ? rid : -1;

        string xpath = BuildXPathQuery(lastRecordId, cursorTime);

        var query = new EventLogQuery(logName, PathType.LogName, xpath);
        using var reader = new EventLogReader(query);

        long maxRecordIdSeen = lastRecordId;
        DateTimeOffset maxTimeSeen = cursorTime;
        int readCount = 0;

        while (reader.ReadEvent() is { } record)
        {
            using (record)
            {
                readCount++;
                if (readCount > 500) break; // Bound per-sample work.

                long recordId = record.RecordId ?? 0;
                if (lastRecordId >= 0 && recordId <= lastRecordId)
                {
                    continue;
                }

                var timeCreated = record.TimeCreated.HasValue
                    ? new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime(), TimeSpan.Zero)
                    : DateTimeOffset.UtcNow;

                if (recordId > maxRecordIdSeen) maxRecordIdSeen = recordId;
                if (timeCreated > maxTimeSeen) maxTimeSeen = timeCreated;

                string source = record.ProviderName ?? "Unknown";
                int eventId = record.Id;
                string level = MapLevel(record.Level);

                string message;
                try
                {
                    message = record.FormatDescription() ?? string.Empty;
                }
                catch
                {
                    message = string.Join(" | ", record.Properties.Select(p => p.Value?.ToString() ?? string.Empty));
                }

                bool isSqlPoolTimeout = IsSqlConnectionPoolTimeout(message);
                bool isWasRecycle = IsWasRecycleOrCrash(source, eventId);

                if (!IsRelevantSource(source) && !isSqlPoolTimeout && !isWasRecycle)
                {
                    continue;
                }

                findings.Add(new EventLogFinding(
                    TimestampUtc: timeCreated,
                    LogName: logName,
                    RecordId: recordId,
                    EventId: eventId,
                    Level: level,
                    Source: source,
                    Message: CompactMessage(message, MaxStoredMessageLength),
                    IsSqlPoolTimeout: isSqlPoolTimeout,
                    IsWasRecycleOrCrash: isWasRecycle));
            }
        }

        if (maxRecordIdSeen > lastRecordId)
        {
            _lastRecordIdByLog[logName] = maxRecordIdSeen;
        }
        else if (lastRecordId >= 0 && readCount == 0)
        {
            DetectLogClearedAndResetCursor(logName, lastRecordId);
        }
        _lastTimestampByLog[logName] = maxTimeSeen;
    }

    private void DetectLogClearedAndResetCursor(string logName, long lastRecordId)
    {
        try
        {
            var reverseQuery = new EventLogQuery(logName, PathType.LogName, "*")
            {
                ReverseDirection = true
            };
            using var reverseReader = new EventLogReader(reverseQuery);
            using var latest = reverseReader.ReadEvent();
            if (latest is null || (latest.RecordId.HasValue && latest.RecordId.Value < lastRecordId))
            {
                _lastRecordIdByLog.Remove(logName);
            }
        }
        catch
        {
            // Ignore permission or transient EventLog errors during clear detection.
        }
    }

    public static string BuildXPathQuery(long lastRecordId, DateTimeOffset cursorTime)
    {
        if (lastRecordId >= 0)
        {
            return $"*[System[(Level=1 or Level=2 or Level=3) and EventRecordID>{lastRecordId}]]";
        }

        string isoTime = cursorTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        return $"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[@SystemTime>='{isoTime}']]]";
    }

    public static string ExtractHighSignalSnippet(string source, int eventId, string message, int maxLength = 220)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return string.Empty;
        }

        string normalized = message.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim();

        var parts = new List<string>(3);

        var exTypeMatch = ExceptionTypeRegex().Match(normalized);
        if (exTypeMatch.Success)
        {
            string val = exTypeMatch.Groups["val"].Value.Trim();
            if (!string.IsNullOrEmpty(val))
            {
                parts.Add($"ExType={val}");
            }
        }

        var exMsgMatch = ExceptionMessageRegex().Match(normalized);
        if (exMsgMatch.Success)
        {
            string val = exMsgMatch.Groups["val"].Value.Trim();
            if (!string.IsNullOrEmpty(val))
            {
                if (val.Length > 140) val = val[..140] + "...";
                parts.Add($"ExMsg={val}");
            }
        }

        var urlMatch = RequestUrlRegex().Match(normalized);
        if (urlMatch.Success)
        {
            string val = urlMatch.Groups["val"].Value.Trim();
            int queryIdx = val.IndexOf('?');
            if (queryIdx >= 0)
            {
                val = val[..queryIdx];
            }
            if (!string.IsNullOrEmpty(val))
            {
                if (val.Length > 100) val = val[..100] + "...";
                parts.Add($"Url={val}");
            }
        }

        if (parts.Count > 0)
        {
            string combined = string.Join(" | ", parts);
            return combined.Length <= maxLength ? combined : combined[..maxLength] + "...";
        }

        return normalized.Length <= maxLength ? normalized : normalized[..maxLength] + "...";
    }

    public static bool IsRelevantSource(string source) =>
        RelevantSourcePrefixes.Any(prefix => source.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    public static bool IsSqlConnectionPoolTimeout(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return false;
        return message.Contains("obtaining a connection from the pool", StringComparison.OrdinalIgnoreCase)
               || message.Contains("max pool size was reached", StringComparison.OrdinalIgnoreCase)
               || message.Contains("connection pool", StringComparison.OrdinalIgnoreCase) && message.Contains("timeout", StringComparison.OrdinalIgnoreCase)
               || message.Contains("pooled connections were in use", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsWasRecycleOrCrash(string source, int eventId) =>
        (source.Contains("WAS", StringComparison.OrdinalIgnoreCase)
         || source.Contains("W3SVC", StringComparison.OrdinalIgnoreCase))
        && WasRecycleOrCrashEventIds.Contains(eventId);

    private static string MapLevel(byte? level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        _ => "Info"
    };

    private static string CompactMessage(string raw, int maxLen)
    {
        string normalized = raw.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim();
        return normalized.Length <= maxLen ? normalized : normalized[..maxLen] + "...";
    }
}
