using System.Diagnostics.Eventing.Reader;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Collectors;

public sealed class WindowsEventLogCollector : IWindowsEventLogCollector
{
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

        string isoTime = cursorTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        string xpath = $"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[@SystemTime>='{isoTime}']]]";

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
                    Message: CompactMessage(message, 1000),
                    IsSqlPoolTimeout: isSqlPoolTimeout,
                    IsWasRecycleOrCrash: isWasRecycle));
            }
        }

        if (maxRecordIdSeen > lastRecordId)
        {
            _lastRecordIdByLog[logName] = maxRecordIdSeen;
        }
        _lastTimestampByLog[logName] = maxTimeSeen;
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
