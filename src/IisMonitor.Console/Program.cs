using System.Globalization;
using System.Text.Json;
using IisMonitor.Abstractions;
using IisMonitor.Analysis;
using IisMonitor.Collectors;
using IisMonitor.Domain;
using IisMonitor.Engine;
using IisMonitor.Reporting;

namespace IisMonitor;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Any(a => a is "-h" or "--help" or "/?"))
        {
            PrintUsage();
            return 0;
        }

        MonitorConfig config;
        try
        {
            config = LoadConfiguration(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Configuration error: {ex.Message}");
            PrintUsage();
            return 2;
        }

        using var cts = new CancellationTokenSource();
        using var shutdownCompleted = new ManualResetEventSlim(false);
        ConsoleCancelEventHandler cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("Shutdown signal received (Ctrl+C). Flushing final summary...");
            try { cts.Cancel(); } catch (ObjectDisposedException) { }
        };
        EventHandler exitHandler = (_, _) =>
        {
            try
            {
                if (!cts.IsCancellationRequested)
                {
                    cts.Cancel();
                }
                shutdownCompleted.Wait(TimeSpan.FromSeconds(3));
            }
            catch (ObjectDisposedException) { }
        };

        Console.CancelKeyPress += cancelHandler;
        AppDomain.CurrentDomain.ProcessExit += exitHandler;

        try
        {
            using var adoNetCollector = new AdoNetPoolCollector();
            using var aspNetAndClrCollector = new AspNetAndClrCollector();
            using var telemetryWriter = new JsonlTelemetryWriter(config.OutputDirectory, config.Thresholds.HungRequestThresholdMs);

            var runner = new MonitorRunner(
                config: config,
                clock: new SystemClock(),
                iisCollector: new IisWorkerProcessCollector(),
                adoNetCollector: adoNetCollector,
                aspNetAndClrCollector: aspNetAndClrCollector,
                tcpCollector: new TcpSocketCollector(),
                nodeCollector: new NodeProcessCollector(),
                eventLogCollector: new WindowsEventLogCollector(config.EventLogLookbackMinutes),
                anomalyDetector: new AnomalyDetector(),
                telemetryWriter: telemetryWriter,
                summaryWriter: new AiExecutiveSummaryWriter(config.OutputDirectory));

            await runner.RunAsync(cts.Token).ConfigureAwait(false);
        }
        finally
        {
            shutdownCompleted.Set();
            Console.CancelKeyPress -= cancelHandler;
            AppDomain.CurrentDomain.ProcessExit -= exitHandler;
        }

        return 0;
    }

    internal static MonitorConfig LoadConfiguration(string[] args)
    {
        MonitorConfig config = new();

        string baseDirConfig = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        string cwdConfig = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");
        string? configPath = File.Exists(cwdConfig) ? cwdConfig : File.Exists(baseDirConfig) ? baseDirConfig : null;

        if (configPath is not null)
        {
            string json = File.ReadAllText(configPath);
            var loaded = JsonSerializer.Deserialize<MonitorConfig>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
            if (loaded is not null)
            {
                config = loaded;
            }
        }

        ApplyCliOverrides(config, args);
        config.Normalize();
        return config;
    }

    internal static void ApplyCliOverrides(MonitorConfig config, string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg.ToLowerInvariant())
            {
                case "--duration-hours":
                    config.DurationHours = double.Parse(RequireValue(args, ref i, arg), CultureInfo.InvariantCulture);
                    config.DurationSecondsOverride = null;
                    break;
                case "--duration-seconds":
                    config.DurationSecondsOverride = int.Parse(RequireValue(args, ref i, arg), CultureInfo.InvariantCulture);
                    break;
                case "--interval-seconds":
                    config.SampleIntervalSeconds = int.Parse(RequireValue(args, ref i, arg), CultureInfo.InvariantCulture);
                    break;
                case "--checkpoint-minutes":
                    config.CheckpointIntervalMinutes = int.Parse(RequireValue(args, ref i, arg), CultureInfo.InvariantCulture);
                    break;
                case "--output":
                    config.OutputDirectory = RequireValue(args, ref i, arg);
                    break;
                case "--db-ports":
                    config.DbPorts = RequireValue(args, ref i, arg)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(p => int.Parse(p, CultureInfo.InvariantCulture))
                        .ToList();
                    break;
                case "--app-pools":
                    config.AppPoolFilter = RequireValue(args, ref i, arg)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                    break;
                case "--anomaly-cooldown-seconds":
                    config.AnomalyCooldownSeconds = int.Parse(RequireValue(args, ref i, arg), CultureInfo.InvariantCulture);
                    break;
                case "--node-ignore":
                    config.NodeIgnorePatterns = RequireValue(args, ref i, arg)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                    break;
                case "--once":
                    config.RunOnce = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: '{arg}'");
            }
        }
    }

    private static string RequireValue(string[] args, ref int index, string flag)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Missing value for '{flag}'.");
        }
        return args[++index];
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            IisMonitor - IIS (.NET Framework 4.5) & Node.js Diagnostic Monitor

            Usage:
              IisMonitor [options]

            Options:
              --duration-hours <num>      Total monitoring duration in hours (default: 72)
              --duration-seconds <num>    Total monitoring duration in seconds (overrides hours)
              --interval-seconds <num>    Sampling interval in seconds (default: 15)
              --checkpoint-minutes <num>  Executive summary checkpoint interval (default: 60)
              --output <path>             Output directory for reports (default: ./monitor-output)
              --db-ports <p1,p2>                 Comma-separated DB ports to track (default: 1433)
              --app-pools <a1,a2>                Comma-separated IIS AppPool names to filter (default: all)
              --anomaly-cooldown-seconds <num>   Cooldown per (Code, Target) in seconds (default: 300)
              --node-ignore <p1,p2>              Comma-separated Node job/cmdline substrings to ignore
              --once                             Capture a single sample and exit
              -h, --help                  Show this help message
            """);
    }
}
