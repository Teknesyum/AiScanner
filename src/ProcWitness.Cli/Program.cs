using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcWitness.Core;
using ProcWitness.Infrastructure;

return await Cli.RunAsync(args);

internal static class Cli
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0) return Usage();
        if (args[0] is "--version" or "-v")
        {
            Console.WriteLine(typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "unknown");
            return 0;
        }
        try
        {
            using var session = new CaptureSession();
            return args[0].ToLowerInvariant() switch
            {
                "scan" => await ScanAsync(session, args[1..]),
                "capture" => await CaptureAsync(session, args[1..]),
                "persistence" => await PersistenceAsync(session, args[1..]),
                "baseline" => await BaselineAsync(session, args[1..]),
                "prompt" => await PromptAsync(args[1..]),
                "mcp" => await new McpServer(session).RunAsync(),
                _ => Usage()
            };
        }
        catch (ArgumentException ex) { Console.Error.WriteLine(ex.Message); return 2; }
        catch (Exception ex) { Console.Error.WriteLine($"Error: {ex.Message}"); return 1; }
    }

    private static async Task<int> ScanAsync(CaptureSession session, string[] args)
    {
        EnsureKnown(args, "--json", "--exit-code-on-high");
        var result = await session.ScanAsync();
        if (args.Contains("--json")) Console.WriteLine(JsonSerializer.Serialize(result.Assessments.Select(ToJson), JsonOptions));
        else
        {
            Console.WriteLine($"{"PID",7}  {"SCORE",5}  {"RISK",8}  PROCESS");
            foreach (var item in result.Assessments) Console.WriteLine($"{item.Process.ProcessId,7}  {item.Score,5}  {item.Level,8}  {item.Process.Name}");
        }
        return args.Contains("--exit-code-on-high") && result.Assessments.Any(x => x.Level >= RiskLevel.High) ? 1 : 0;
    }

    private static async Task<int> CaptureAsync(CaptureSession session, string[] args)
    {
        var minutesText = Option(args, "--minutes") ?? throw new ArgumentException("capture requires --minutes <value>.");
        if (!double.TryParse(minutesText, NumberStyles.Float, CultureInfo.InvariantCulture, out var minutes) || minutes <= 0 || minutes > 10080)
            throw new ArgumentException("--minutes must be between 0 and 10080.");
        var output = Option(args, "--out");
        var format = (Option(args, "--format") ?? "json").ToLowerInvariant();
        if (format is not ("json" or "md" or "text")) throw new ArgumentException("--format must be json, md, or text.");
        EnsureKnown(args, "--minutes", "--out", "--format");
        var progress = new Progress<CaptureProgress>(x => Console.Error.Write($"\rRemaining {x.Remaining:mm\\:ss}   "));
        var result = await session.CaptureAsync(TimeSpan.FromMinutes(minutes), progress);
        Console.Error.WriteLine();
        var destination = output is null ? null : Path.GetFullPath(output);
        if (destination is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            if (format == "json") File.Copy(result.Path, destination, true);
            else await File.WriteAllTextAsync(destination, format == "md" ? $"# ProcWitness capture report\n\n```text\n{result.LocalReport}\n```\n" : result.LocalReport);
            Console.Error.WriteLine($"Saved: {destination}");
        }
        else if (format == "json") Console.WriteLine(await File.ReadAllTextAsync(result.Path));
        else Console.WriteLine(result.LocalReport);
        return 0;
    }

    private static async Task<int> PersistenceAsync(CaptureSession session, string[] args)
    {
        EnsureKnown(args, "--json");
        await session.ScanAsync();
        var inventory = await session.RefreshPersistenceAsync();
        if (args.Contains("--json")) Console.WriteLine(JsonSerializer.Serialize(inventory, JsonOptions));
        else
        {
            foreach (var source in inventory.Sources)
            {
                Console.WriteLine($"[{source.Source}] {(source.Available ? $"{source.Entries.Count} entries" : $"unavailable: {source.Status}")}");
                foreach (var entry in source.Entries) Console.WriteLine($"  {(entry.Enabled ? "+" : "-")} {entry.Name}: {entry.Command}");
            }
        }
        return 0;
    }

    private static async Task<int> BaselineAsync(CaptureSession session, string[] args)
    {
        if (args.Length == 0 || args[0] is not ("save" or "compare")) throw new ArgumentException("baseline requires save or compare.");
        EnsureKnown(args[1..], "--file", "--json");
        var manager = new BaselineManager(session.Store.DataDirectory);
        await session.ScanAsync();
        var persistence = await session.RefreshPersistenceAsync();
        if (args[0] == "save")
        {
            var listening = session.GetListeningEndpoints();
            Console.WriteLine(await manager.SaveAsync(session.LatestProcesses, persistence, listening.Endpoints, listening.Available));
            return 0;
        }
        var baseline = Option(args[1..], "--file") ?? manager.List().FirstOrDefault() ?? throw new ArgumentException("No baseline exists; run baseline save first.");
        var comparison = await manager.CompareAsync(baseline, session.LatestProcesses, persistence);
        if (args.Contains("--json")) Console.WriteLine(JsonSerializer.Serialize(comparison, JsonOptions));
        else Console.WriteLine($"Added {comparison.Added.Count}, removed {comparison.Removed.Count}, changed {comparison.Changed.Count}, new persistence {comparison.NewPersistence.Count}");
        return 0;
    }

    private static async Task<int> PromptAsync(string[] args)
    {
        var bundle = Option(args, "--bundle") ?? throw new ArgumentException("prompt requires --bundle <path>.");
        EnsureKnown(args, "--bundle");
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(bundle));
        var meta = document.RootElement.GetProperty("meta");
        var minutes = meta.TryGetProperty("requestedMinutes", out var minutesValue) ? minutesValue.GetDouble() : 0;
        var snapshots = meta.TryGetProperty("snapshotCount", out var snapshotValue) ? snapshotValue.GetInt32() : 0;
        var observations = meta.TryGetProperty("observationCount", out var observationValue) ? observationValue.GetInt32() : 0;
        Console.WriteLine(new AiAnalysisPromptBuilder().BuildForLocalBundle(Path.GetFullPath(bundle), TimeSpan.FromMinutes(minutes), snapshots, observations));
        return 0;
    }

    private static object ToJson(ProcessAssessment item) => new
    {
        pid = item.Process.ProcessId,
        name = item.Process.Name,
        path = item.Process.ExecutablePath,
        item.Process.Sha256,
        item.Process.SignatureStatus,
        item.Process.ParentProcessId,
        item.Process.ParentName,
        item.Process.CommandLine,
        item.Score,
        item.Level,
        item.Findings,
        item.SuppressedFindings
    };

    private static string? Option(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0) return null;
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"{name} requires a value.");
        return args[index + 1];
    }

    private static void EnsureKnown(string[] args, params string[] known)
    {
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (!argument.StartsWith("--", StringComparison.Ordinal)) continue;
            if (!known.Contains(argument)) throw new ArgumentException($"Unknown option: {argument}");
            if (argument is "--minutes" or "--out" or "--format" or "--file" or "--bundle") index++;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("Usage: procwitness scan [--json] | capture --minutes N [--out file] [--format json|md|text] | persistence [--json] | baseline save|compare [--file path] [--json] | prompt --bundle path | mcp | --version");
        return 2;
    }
}
