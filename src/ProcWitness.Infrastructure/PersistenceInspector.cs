using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using ProcWitness.Core;

namespace ProcWitness.Infrastructure;

public sealed class PersistenceInspector
{
    public async Task<PersistenceInventory> ScanAsync(IReadOnlyCollection<ProcessObservation>? processes = null, CancellationToken cancellationToken = default)
    {
        var sources = OperatingSystem.IsWindows()
            ? await ReadWindowsAsync(cancellationToken)
            : OperatingSystem.IsLinux()
                ? await ReadLinuxAsync(cancellationToken)
                : OperatingSystem.IsMacOS()
                    ? await ReadMacAsync(cancellationToken)
                    : [Unavailable("platform", "Unsupported platform")];
        var enriched = new List<PersistenceSourceResult>();
        foreach (var source in sources)
        {
            var entries = new List<PersistenceEntry>();
            foreach (var entry in source.Entries) entries.Add(await EnrichAsync(entry, processes ?? [], cancellationToken));
            enriched.Add(source with { Entries = entries });
        }
        return new(DateTimeOffset.UtcNow, enriched);
    }

    [SupportedOSPlatform("windows")]
    private static async Task<IReadOnlyList<PersistenceSourceResult>> ReadWindowsAsync(CancellationToken cancellationToken)
    {
        var results = new List<PersistenceSourceResult>
        {
            ReadRegistryRun("registry-run-hkcu", RegistryHive.CurrentUser, RegistryView.Default),
            ReadRegistryRun("registry-run-hklm64", RegistryHive.LocalMachine, RegistryView.Registry64),
            ReadRegistryRun("registry-run-hklm32", RegistryHive.LocalMachine, RegistryView.Registry32),
            ReadStartupFolders(),
            await ReadScheduledTasksAsync(cancellationToken),
            ReadServices(),
            ReadWinlogon()
        };
        return results;
    }

    [SupportedOSPlatform("windows")]
    private static PersistenceSourceResult ReadRegistryRun(string source, RegistryHive hive, RegistryView view)
    {
        try
        {
            var entries = new List<PersistenceEntry>();
            using var root = RegistryKey.OpenBaseKey(hive, view);
            foreach (var keyPath in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            using (var key = root.OpenSubKey(keyPath, false))
            {
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    var command = key.GetValue(name)?.ToString();
                    if (!string.IsNullOrWhiteSpace(command)) entries.Add(Raw(source, name, command, true));
                }
            }
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { return Unavailable(source, ex.Message); }
    }

    private static PersistenceSourceResult ReadStartupFolders()
    {
        const string source = "startup-folders";
        try
        {
            var folders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };
            var entries = folders.Where(Directory.Exists).SelectMany(folder => Directory.EnumerateFiles(folder))
                .Select(path => Raw(source, Path.GetFileName(path), path, true)).ToArray();
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return Unavailable(source, ex.Message); }
    }

    private static async Task<PersistenceSourceResult> ReadScheduledTasksAsync(CancellationToken cancellationToken)
    {
        const string source = "scheduled-tasks";
        var output = await RunAsync("schtasks.exe", ["/query", "/fo", "CSV", "/v", "/nh"], cancellationToken);
        if (output is null) return Unavailable(source, "schtasks query failed");
        var entries = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(ParseCsv).Where(x => x.Count > 8)
            .Select(row => Raw(source, row[1], row[8], !row[3].Contains("Disabled", StringComparison.OrdinalIgnoreCase))).ToArray();
        return Available(source, entries);
    }

    [SupportedOSPlatform("windows")]
    private static PersistenceSourceResult ReadServices()
    {
        const string source = "services";
        try
        {
            var entries = new List<PersistenceEntry>();
            using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (root is null) return Available(source, entries);
            foreach (var name in root.GetSubKeyNames())
            using (var service = root.OpenSubKey(name, false))
            {
                var command = service?.GetValue("ImagePath")?.ToString();
                var start = service?.GetValue("Start") is int value ? value : 4;
                if (!string.IsNullOrWhiteSpace(command)) entries.Add(Raw(source, name, command, start != 4));
            }
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { return Unavailable(source, ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static PersistenceSourceResult ReadWinlogon()
    {
        const string source = "winlogon";
        try
        {
            var entries = new List<PersistenceEntry>();
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false);
            foreach (var name in new[] { "Userinit", "Shell" })
            {
                var command = key?.GetValue(name)?.ToString();
                if (!string.IsNullOrWhiteSpace(command)) entries.Add(Raw(source, name, command, true));
            }
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { return Unavailable(source, ex.Message); }
    }

    private static async Task<IReadOnlyList<PersistenceSourceResult>> ReadLinuxAsync(CancellationToken cancellationToken)
    {
        var results = new List<PersistenceSourceResult>();
        results.Add(await ReadCommandLinesAsync("systemd-user", "systemctl", ["list-unit-files", "--user", "--no-legend", "--no-pager"], cancellationToken));
        results.Add(await ReadCommandLinesAsync("systemd-system", "systemctl", ["list-unit-files", "--no-legend", "--no-pager"], cancellationToken));
        results.Add(ReadDesktopEntries());
        results.Add(await ReadCommandLinesAsync("user-crontab", "crontab", ["-l"], cancellationToken, allowFailureAsEmpty: true));
        results.Add(ReadCronDirectories());
        results.Add(ReadShellProfiles());
        return results;
    }

    private static PersistenceSourceResult ReadDesktopEntries()
    {
        const string source = "xdg-autostart";
        try
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "autostart");
            var entries = Directory.Exists(folder) ? Directory.EnumerateFiles(folder, "*.desktop").Select(path =>
            {
                var lines = File.ReadAllLines(path);
                var command = lines.FirstOrDefault(x => x.StartsWith("Exec=", StringComparison.Ordinal))?[5..] ?? path;
                var enabled = !lines.Any(x => x.Equals("Hidden=true", StringComparison.OrdinalIgnoreCase));
                return Raw(source, Path.GetFileNameWithoutExtension(path), command, enabled);
            }).ToArray() : [];
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return Unavailable(source, ex.Message); }
    }

    private static PersistenceSourceResult ReadCronDirectories()
    {
        const string source = "cron-directories";
        try
        {
            string[] roots = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
            var entries = roots.Where(Directory.Exists).SelectMany(x => Directory.EnumerateFiles(x)).Select(path => Raw(source, Path.GetFileName(path), path, true)).ToArray();
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return Unavailable(source, ex.Message); }
    }

    private static PersistenceSourceResult ReadShellProfiles()
    {
        const string source = "shell-profiles";
        try
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var paths = new[] { Path.Combine(profile, ".bashrc"), Path.Combine(profile, ".profile") };
            var entries = paths.Where(File.Exists).SelectMany(path => File.ReadLines(path)
                .Select((line, index) => (line: line.Trim(), index))
                .Where(x => x.line.Length > 0 && !x.line.StartsWith('#') && !x.line.StartsWith("export ") && !x.line.StartsWith("alias "))
                .Select(x => Raw(source, $"{Path.GetFileName(path)}:{x.index + 1}", x.line, true))).ToArray();
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return Unavailable(source, ex.Message); }
    }

    private static async Task<IReadOnlyList<PersistenceSourceResult>> ReadMacAsync(CancellationToken cancellationToken)
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var launch = ReadLaunchItems([
            Path.Combine(profile, "Library", "LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons"]);
        var login = await ReadCommandLinesAsync("login-items", "/usr/bin/osascript", ["-e", "tell application \"System Events\" to get the name of every login item"], cancellationToken, true);
        return [launch, login];
    }

    private static PersistenceSourceResult ReadLaunchItems(IEnumerable<string> folders)
    {
        const string source = "launchd";
        try
        {
            var entries = folders.Where(Directory.Exists).SelectMany(x => Directory.EnumerateFiles(x, "*.plist"))
                .Select(path => Raw(source, Path.GetFileNameWithoutExtension(path), path, true)).ToArray();
            return Available(source, entries);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return Unavailable(source, ex.Message); }
    }

    private static async Task<PersistenceSourceResult> ReadCommandLinesAsync(string source, string fileName, IReadOnlyList<string> arguments, CancellationToken cancellationToken, bool allowFailureAsEmpty = false)
    {
        var output = await RunAsync(fileName, arguments, cancellationToken);
        if (output is null) return allowFailureAsEmpty ? Available(source, []) : Unavailable(source, $"{fileName} query failed");
        var entries = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select((line, index) => Raw(source, $"{source}-{index + 1}", line.Trim(), true)).ToArray();
        return Available(source, entries);
    }

    private static async Task<PersistenceEntry> EnrichAsync(PersistenceEntry entry, IReadOnlyCollection<ProcessObservation> processes, CancellationToken cancellationToken)
    {
        var path = ResolvePath(entry.Command);
        var hash = await HashAsync(path, cancellationToken);
        var signature = ProcessScanner.GetSignature(path);
        var linked = path is null ? [] : processes.Where(x => PathsEqual(x.ExecutablePath, path) || hash is not null && string.Equals(x.Sha256, hash, StringComparison.OrdinalIgnoreCase)).Select(x => x.ProcessId).Distinct().ToArray();
        DateTimeOffset? created = null;
        try { if (path is not null && File.Exists(path)) created = File.GetCreationTimeUtc(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return entry with { ResolvedPath = path, Sha256 = hash, SignatureStatus = signature.Status, Publisher = signature.Publisher, CreatedAt = created, LinkedProcessIds = linked };
    }

    internal static string? ResolvePath(string command)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith('"'))
        {
            var end = expanded.IndexOf('"', 1);
            if (end > 1) expanded = expanded[1..end];
        }
        else expanded = expanded.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        expanded = expanded.Trim('"', '\'');
        if (File.Exists(expanded)) return Path.GetFullPath(expanded);
        if (!Path.IsPathRooted(expanded))
        {
            var path = Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator).Select(x => Path.Combine(x, expanded)).FirstOrDefault(File.Exists);
            if (path is not null) return Path.GetFullPath(path);
        }
        return null;
    }

    private static bool PathsEqual(string? left, string right) => left is not null && string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static async Task<string?> HashAsync(string? path, CancellationToken cancellationToken)
    {
        if (path is null) return null;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 81920, true);
            return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException) { return null; }
    }

    private static PersistenceEntry Raw(string source, string name, string command, bool enabled) => new(source, name, CommandLineRedactor.Redact(command) ?? command, null, null, SignatureStatus.Unavailable, null, enabled, null, []);
    private static PersistenceSourceResult Available(string source, IReadOnlyList<PersistenceEntry> entries) => new(source, true, null, entries);
    private static PersistenceSourceResult Unavailable(string source, string status) => new(source, false, status, []);

    private static async Task<string?> RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        try
        {
            using var process = new Process { StartInfo = new(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
            foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
            if (!process.Start()) return null;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            var output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            return process.ExitCode == 0 ? output : null;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException) { return null; }
    }

    private static List<string> ParseCsv(string line)
    {
        var values = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character == '"' && quoted && index + 1 < line.Length && line[index + 1] == '"') { current.Append('"'); index++; }
            else if (character == '"') quoted = !quoted;
            else if (character == ',' && !quoted) { values.Add(current.ToString()); current.Clear(); }
            else current.Append(character);
        }
        values.Add(current.ToString());
        return values;
    }
}
