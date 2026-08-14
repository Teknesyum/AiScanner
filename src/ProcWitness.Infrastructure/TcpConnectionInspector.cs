using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace ProcWitness.Infrastructure;

public sealed record ListeningPortSnapshot(IReadOnlyDictionary<int, IReadOnlyList<string>> Endpoints, bool Available);

public sealed class TcpConnectionInspector
{
    public ListeningPortSnapshot GetListeningEndpoints()
    {
        if (OperatingSystem.IsWindows()) return new(GetWindowsListeningEndpoints(), true);
        if (OperatingSystem.IsLinux()) return new(GetLinuxListeningEndpoints(), File.Exists("/proc/net/tcp"));
        if (OperatingSystem.IsMacOS()) return new(GetMacListeningEndpoints(), File.Exists("/usr/sbin/lsof"));
        return new(Empty(), false);
    }

    public IReadOnlyDictionary<int, IReadOnlyList<string>> GetRemoteEndpoints()
    {
        if (OperatingSystem.IsWindows()) return GetWindowsEndpoints();
        if (OperatingSystem.IsLinux()) return GetLinuxEndpoints();
        if (OperatingSystem.IsMacOS()) return GetMacEndpoints();
        return new Dictionary<int, IReadOnlyList<string>>();
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> GetMacEndpoints()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("/usr/sbin/lsof", "-nP -iTCP -sTCP:ESTABLISHED") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });
            if (p is null) return Empty();
            string output;
            try
            {
                output = p.StandardOutput.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
                if (!p.WaitForExit(1000)) p.Kill(true);
            }
            catch (TimeoutException)
            {
                try { p.Kill(true); } catch (InvalidOperationException) { }
                return Empty();
            }
            var lines = output.Split('\n');
            var result = new Dictionary<int, HashSet<string>>();
            foreach (var line in lines.Skip(1))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 9 || !int.TryParse(parts[1], out var pid)) continue;
                var arrow = parts[^2].Contains("->", StringComparison.Ordinal) ? parts[^2] : parts[^1];
                var endpoint = arrow.Split("->").LastOrDefault();
                if (string.IsNullOrWhiteSpace(endpoint)) continue;
                if (!result.TryGetValue(pid, out var set)) result[pid] = set = [];
                set.Add(endpoint);
            }
            return Freeze(result);
        }
        catch { return Empty(); }
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> GetMacListeningEndpoints()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("/usr/sbin/lsof", "-nP -iTCP -sTCP:LISTEN") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });
            if (process is null) return Empty();
            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(3000)) { process.Kill(true); return Empty(); }
            var result = new Dictionary<int, HashSet<string>>();
            foreach (var line in output.Split('\n').Skip(1))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 9 || !int.TryParse(parts[1], out var pid)) continue;
                if (!result.TryGetValue(pid, out var set)) result[pid] = set = [];
                set.Add(parts[^2].Contains(':') ? parts[^2] : parts[^1]);
            }
            return Freeze(result);
        }
        catch { return Empty(); }
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> GetLinuxEndpoints()
    {
        try
        {
            var inodeEndpoints = new Dictionary<string, string>();
            foreach (var file in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
            {
                if (!File.Exists(file)) continue;
                foreach (var line in File.ReadLines(file).Skip(1))
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 10 || parts[3] != "01") continue;
                    inodeEndpoints[parts[9]] = DecodeProcEndpoint(parts[2]);
                }
            }
            var result = new Dictionary<int, HashSet<string>>();
            foreach (var procDir in Directory.EnumerateDirectories("/proc").Where(x => int.TryParse(Path.GetFileName(x), out _)))
            {
                if (!int.TryParse(Path.GetFileName(procDir), out var pid)) continue;
                try
                {
                    foreach (var fd in Directory.EnumerateFiles(Path.Combine(procDir, "fd")))
                    {
                        var target = new FileInfo(fd).LinkTarget;
                        if (target is null || !target.StartsWith("socket:[", StringComparison.Ordinal)) continue;
                        var inode = target[8..^1];
                        if (!inodeEndpoints.TryGetValue(inode, out var endpoint)) continue;
                        if (!result.TryGetValue(pid, out var set)) result[pid] = set = [];
                        set.Add(endpoint);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            return Freeze(result);
        }
        catch { return Empty(); }
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> GetLinuxListeningEndpoints()
    {
        try
        {
            var inodeEndpoints = new Dictionary<string, string>();
            foreach (var file in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
            {
                if (!File.Exists(file)) continue;
                foreach (var line in File.ReadLines(file).Skip(1))
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 10 || parts[3] != "0A") continue;
                    inodeEndpoints[parts[9]] = DecodeProcEndpoint(parts[1]);
                }
            }
            return MapLinuxSockets(inodeEndpoints);
        }
        catch { return Empty(); }
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> MapLinuxSockets(IReadOnlyDictionary<string, string> inodeEndpoints)
    {
        var result = new Dictionary<int, HashSet<string>>();
        foreach (var procDir in Directory.EnumerateDirectories("/proc").Where(x => int.TryParse(Path.GetFileName(x), out _)))
        {
            if (!int.TryParse(Path.GetFileName(procDir), out var pid)) continue;
            try
            {
                foreach (var fd in Directory.EnumerateFiles(Path.Combine(procDir, "fd")))
                {
                    var target = new FileInfo(fd).LinkTarget;
                    if (target is null || !target.StartsWith("socket:[", StringComparison.Ordinal)) continue;
                    var inode = target[8..^1];
                    if (!inodeEndpoints.TryGetValue(inode, out var endpoint)) continue;
                    if (!result.TryGetValue(pid, out var set)) result[pid] = set = [];
                    set.Add(endpoint);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return Freeze(result);
    }

    private static string DecodeProcEndpoint(string value)
    {
        var pair = value.Split(':');
        if (pair.Length != 2) return value;
        if (pair[0].Length == 8)
        {
            var bytes = Convert.FromHexString(pair[0]); Array.Reverse(bytes);
            return $"{new IPAddress(bytes)}:{Convert.ToInt32(pair[1], 16)}";
        }
        if (pair[0].Length == 32)
        {
            var raw = Convert.FromHexString(pair[0]);
            for (var offset = 0; offset < raw.Length; offset += 4) Array.Reverse(raw, offset, 4);
            return $"[{new IPAddress(raw)}]:{Convert.ToInt32(pair[1], 16)}";
        }
        return value;
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> GetWindowsEndpoints()
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0) != 0) return Empty();
            var result = new Dictionary<int, HashSet<string>>();
            var count = Marshal.ReadInt32(buffer); var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buffer + sizeof(int) + i * rowSize);
                if (row.State != 5 || row.RemoteAddress == 0) continue;
                if (!result.TryGetValue((int)row.ProcessId, out var set)) result[(int)row.ProcessId] = set = [];
                var bytes = BitConverter.GetBytes(row.RemotePort); set.Add($"{new IPAddress(row.RemoteAddress)}:{(bytes[0] << 8) + bytes[1]}");
            }
            return Freeze(result);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> GetWindowsListeningEndpoints()
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0) != 0) return Empty();
            var result = new Dictionary<int, HashSet<string>>();
            var count = Marshal.ReadInt32(buffer); var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            for (var index = 0; index < count; index++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buffer + sizeof(int) + index * rowSize);
                if (row.State != 2) continue;
                if (!result.TryGetValue((int)row.ProcessId, out var set)) result[(int)row.ProcessId] = set = [];
                var bytes = BitConverter.GetBytes(row.LocalPort); set.Add($"{new IPAddress(row.LocalAddress)}:{(bytes[0] << 8) + bytes[1]}");
            }
            return Freeze(result);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> Freeze(Dictionary<int, HashSet<string>> source) => source.ToDictionary(x => x.Key, x => (IReadOnlyList<string>)x.Value.Order().ToArray());
    private static IReadOnlyDictionary<int, IReadOnlyList<string>> Empty() => new Dictionary<int, IReadOnlyList<string>>();
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);
    [StructLayout(LayoutKind.Sequential)] private struct MibTcpRowOwnerPid { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort, ProcessId; }
}
