using System.Globalization;
using System.Text;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Reporting;

public sealed class AiExecutiveSummaryWriter : IExecutiveSummaryWriter
{
    public const string SummaryFileName = "00_AI_EXECUTIVE_SUMMARY.txt";

    private readonly string _outputDirectory;

    public AiExecutiveSummaryWriter(string outputDirectory)
    {
        _outputDirectory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(_outputDirectory);
    }

    public async Task WriteSummaryAsync(ExecutiveSummaryReport report, CancellationToken cancellationToken)
    {
        string content = FormatReport(report);
        string targetPath = Path.Combine(_outputDirectory, SummaryFileName);
        string tempPath = Path.Combine(_outputDirectory, $"{SummaryFileName}.tmp");

        await File.WriteAllTextAsync(tempPath, content, new UTF8Encoding(false), cancellationToken)
            .ConfigureAwait(false);
        File.Move(tempPath, targetPath, overwrite: true);
    }

    public static string FormatReport(ExecutiveSummaryReport r)
    {
        var sb = new StringBuilder(4096);
        var inv = CultureInfo.InvariantCulture;

        sb.AppendLine("================================================================================");
        sb.AppendLine("IIS (.NET 4.5) & NODE.JS DIAGNOSTIC MONITOR - AI EXECUTIVE SUMMARY");
        sb.AppendLine("================================================================================");
        sb.AppendLine();

        sb.AppendLine("=== RUN_METADATA ===");
        sb.AppendLine($"Machine:                         {r.MachineName}");
        sb.AppendLine($"Status:                          {(r.IsFinal ? "FINAL" : "CHECKPOINT (IN PROGRESS)")}");
        sb.AppendLine($"RunStartUtc:                     {r.RunStartUtc:yyyy-MM-ddTHH:mm:ssZ}");
        sb.AppendLine($"LastSampleUtc:                   {r.LastSampleUtc:yyyy-MM-ddTHH:mm:ssZ}");
        sb.AppendLine($"GeneratedAtUtc:                  {r.GeneratedAtUtc:yyyy-MM-ddTHH:mm:ssZ}");
        sb.AppendLine($"ObservedSpanHours:               {((r.LastSampleUtc - r.RunStartUtc).TotalHours).ToString("0.00", inv)}");
        sb.AppendLine($"TotalSamples:                    {r.TotalSamples}");
        sb.AppendLine($"SampleIntervalSeconds:           {r.SampleIntervalSeconds}");
        sb.AppendLine($"MonitoredDbPorts:                {string.Join(", ", r.DbPorts)}");
        sb.AppendLine($"IisAdminApiAvailable:            {r.IisAdminAvailable}");
        sb.AppendLine($"AdoNetPerfCounterAvailable:      {r.AdoNetCategoryAvailable}");
        sb.AppendLine($"AdoNetActiveConnectionsCounter:  {r.AdoNetActiveConnectionsAvailable}");

        if (r.EnvironmentWarnings.Count > 0)
        {
            sb.AppendLine("EnvironmentWarnings:");
            foreach (string warn in r.EnvironmentWarnings)
            {
                string singleLine = warn.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim();
                sb.AppendLine($"  - {singleLine}");
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== RANKED_ROOT_CAUSE_HYPOTHESES ===");
        foreach (var h in r.Hypotheses)
        {
            sb.AppendLine($"#{h.Rank} [{h.Confidence} | score={h.Score}] {h.Title}");
            foreach (string ev in h.Evidence)
            {
                sb.AppendLine($"    - {ev}");
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== ANOMALY_SUMMARY_BY_CODE ===");
        if (r.AnomalyCountsByCode.Count == 0)
        {
            sb.AppendLine("None (0 anomalies detected).");
        }
        else
        {
            foreach (var (code, count) in r.AnomalyCountsByCode)
            {
                sb.AppendLine($"  {code,-32} : {count}");
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== APP_POOL_HEALTH_MATRIX ===");
        if (r.AppPools.Count == 0)
        {
            sb.AppendLine("No IIS w3wp.exe AppPools observed.");
        }
        else
        {
            sb.AppendLine(string.Format(inv,
                "{0,-26} {1,6} {2,4} {3,7} {4,9} {5,7} {6,7} {7,6} {8,8} {9,6} {10,8}",
                "AppPool", "PIDs", "Rec", "MaxPool", "Reclaim+", "DbEstab", "DbClWt", "Hung#", "MaxReqMs", "HttpQ", "MaxMemMB"));
            sb.AppendLine(new string('-', 106));

            foreach (var p in r.AppPools)
            {
                string name = p.AppPoolName.Length <= 26 ? p.AppPoolName : p.AppPoolName[..23] + "...";
                sb.AppendLine(string.Format(inv,
                    "{0,-26} {1,6} {2,4} {3,7:0.#} {4,9:0.#} {5,7} {6,7} {7,6} {8,8} {9,6:0.#} {10,8:0.#}",
                    name,
                    p.DistinctPidCount,
                    p.RecycleCount,
                    p.MaxPooledConnections,
                    p.TotalReclaimedConnectionsDelta,
                    p.MaxDbEstablishedSockets,
                    p.MaxDbCloseWaitSockets,
                    p.MaxHungRequests,
                    p.MaxRequestElapsedMs,
                    p.MaxHttpQueueSize,
                    p.MaxWorkingSetMb));

                if (p.TopHungUrls.Count > 0)
                {
                    sb.AppendLine($"    TopHungUrls: {string.Join(" | ", p.TopHungUrls)}");
                }
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== NODE_JS_JOB_SUMMARY ===");
        if (r.NodeJobs.Count == 0)
        {
            sb.AppendLine("No node.exe processes observed.");
        }
        else
        {
            sb.AppendLine(string.Format(inv,
                "{0,-28} {1,5} {2,10} {3,7} {4,7} {5,8} {6,7}",
                "JobLabel", "PIDs", "MaxUpMin", "DbEstab", "DbClWt", "MaxMemMB", "Zombie#"));
            sb.AppendLine(new string('-', 78));

            foreach (var n in r.NodeJobs)
            {
                string label = n.JobLabel.Length <= 28 ? n.JobLabel : n.JobLabel[..25] + "...";
                sb.AppendLine(string.Format(inv,
                    "{0,-28} {1,5} {2,10:0.0} {3,7} {4,7} {5,8:0.0} {6,7}",
                    label,
                    n.DistinctPidCount,
                    n.MaxUptimeMinutes,
                    n.MaxDbEstablishedSockets,
                    n.MaxDbCloseWaitSockets,
                    n.MaxWorkingSetMb,
                    n.ZombieDetections));
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== TOP_INCIDENT_WINDOWS ===");
        if (r.TopIncidents.Count == 0)
        {
            sb.AppendLine("No incident windows recorded.");
        }
        else
        {
            foreach (var inc in r.TopIncidents)
            {
                sb.AppendLine(string.Format(inv,
                    "[INC-{0:D3}] {1:yyyy-MM-ddTHH:mm:ssZ} .. {2:yyyy-MM-ddTHH:mm:ssZ} ({3:0.#}s) | MaxSev={4} | Anomalies={5}",
                    inc.IncidentId, inc.StartUtc, inc.EndUtc, inc.DurationSeconds, inc.MaxSeverity, inc.AnomalyCount));
                sb.AppendLine($"  Codes:   {string.Join(", ", inc.Codes)}");
                sb.AppendLine($"  Targets: {string.Join(", ", inc.Targets)}");
                if (inc.SampleHungUrls.Count > 0)
                {
                    sb.AppendLine($"  HungURLs: {string.Join(" ; ", inc.SampleHungUrls)}");
                }
                if (inc.CorrelatedEventSnippets.Count > 0)
                {
                    sb.AppendLine($"  Events:   {string.Join(" ; ", inc.CorrelatedEventSnippets)}");
                }
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== OUTPUT_FILE_INDEX ===");
        sb.AppendLine($"  {SummaryFileName,-38} : This executive summary (start here for AI analysis)");
        foreach (string file in r.GeneratedFiles)
        {
            string desc = file switch
            {
                JsonlTelemetryWriter.AnomaliesFileName => "Chronological stream of detected anomalies (JSONL)",
                JsonlTelemetryWriter.EventLogFileName => "Filtered IIS/ASP.NET/CLR/SQL EventLog warnings & errors (JSONL)",
                _ when file.StartsWith("02_TIMELINE_METRICS_", StringComparison.OrdinalIgnoreCase) => "Daily rotated telemetry snapshots (JSONL)",
                _ => "Output artifact"
            };
            sb.AppendLine($"  {file,-38} : {desc}");
        }

        return sb.ToString();
    }
}
