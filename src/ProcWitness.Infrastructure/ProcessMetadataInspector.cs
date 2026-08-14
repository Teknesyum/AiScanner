using System.Diagnostics;
using System.Text.Json;
using ProcWitness.Core;

namespace ProcWitness.Infrastructure;

internal sealed record ProcessMetadata(int? ParentProcessId, string? CommandLine, bool CommandLineAvailable, bool ProcessTreeAvailable);

internal sealed class ProcessMetadataInspector
{
    private readonly Dictionary<int, ProcessMetadata> _cache = [];

    public async Task<IReadOnlyDictionary<int, ProcessMetadata>> ReadAsync(IReadOnlyCollection<int> processIds, CancellationToken cancellationToken)
    {
        var active = processIds.ToHashSet();
        foreach (var stale in _cache.Keys.Where(x => !active.Contains(x)).ToArray()) _cache.Remove(stale);
        if (OperatingSystem.IsLinux()) ReadLinux(active);
        else if (OperatingSystem.IsMacOS()) await ReadMacAsync(active, cancellationToken);
        else if (OperatingSystem.IsWindows()) await ReadWindowsAsync(active, cancellationToken);
        return _cache;
    }

    private async Task ReadWindowsAsync(IReadOnlySet<int> processIds, CancellationToken cancellationToken)
    {
        var missing = processIds.Where(x => !_cache.ContainsKey(x)).ToArray();
        if (missing.Length == 0) return;
        var filter = string.Join(" OR ", missing.Select(x => $"ProcessId={x}"));
        var command = $"Get-CimInstance Win32_Process -Filter '{filter}' | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress";
        var output = await RunAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], cancellationToken);
        if (output is null)
        {
            foreach (var pid in missing) _cache[pid] = new(null, null, false, false);
            return;
        }
        try
        {
            using var document = JsonDocument.Parse(output);
            var rows = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray().ToArray()
                : [document.RootElement];
            foreach (var row in rows)
            {
                var pid = row.GetProperty("ProcessId").GetInt32();
                var parent = row.TryGetProperty("ParentProcessId", out var parentValue) && parentValue.ValueKind == JsonValueKind.Number ? (int?)parentValue.GetInt32() : null;
                var commandLine = row.TryGetProperty("CommandLine", out var commandValue) && commandValue.ValueKind == JsonValueKind.String ? commandValue.GetString() : null;
                _cache[pid] = new(parent, CommandLineRedactor.Redact(commandLine), commandLine is not null, true);
            }
        }
        catch (JsonException) { }
        foreach (var pid in missing) _cache.TryAdd(pid, new(null, null, false, false));
    }

    private void ReadLinux(IEnumerable<int> processIds)
    {
        foreach (var pid in processIds.Where(x => !_cache.ContainsKey(x)))
        {
            int? parent = null;
            string? commandLine = null;
            var treeAvailable = false;
            var commandAvailable = false;
            try
            {
                var stat = File.ReadAllText($"/proc/{pid}/stat");
                var endName = stat.LastIndexOf(')');
                var fields = endName >= 0 ? stat[(endName + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries) : [];
                if (fields.Length > 1 && int.TryParse(fields[1], out var ppid))
                {
                    parent = ppid;
                    treeAvailable = true;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            try
            {
                var bytes = File.ReadAllBytes($"/proc/{pid}/cmdline");
                commandLine = CommandLineRedactor.Redact(System.Text.Encoding.UTF8.GetString(bytes).Replace('\0', ' ').Trim());
                commandAvailable = bytes.Length > 0;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            _cache[pid] = new(parent, commandLine, commandAvailable, treeAvailable);
        }
    }

    private async Task ReadMacAsync(IReadOnlySet<int> processIds, CancellationToken cancellationToken)
    {
        var output = await RunAsync("/bin/ps", ["-axo", "pid=,ppid=,command="], cancellationToken);
        if (output is null)
        {
            foreach (var pid in processIds) _cache.TryAdd(pid, new(null, null, false, false));
            return;
        }
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !int.TryParse(parts[0], out var pid) || !processIds.Contains(pid) || !int.TryParse(parts[1], out var parent)) continue;
            var commandLine = parts.Length == 3 ? CommandLineRedactor.Redact(parts[2]) : null;
            _cache[pid] = new(parent, commandLine, commandLine is not null, true);
        }
        foreach (var pid in processIds) _cache.TryAdd(pid, new(null, null, false, false));
    }

    private static async Task<string?> RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        try
        {
            using var process = new Process { StartInfo = new(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
            foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
            if (!process.Start()) return null;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(4));
            var output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            return process.ExitCode == 0 ? output : null;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException) { return null; }
    }
}
