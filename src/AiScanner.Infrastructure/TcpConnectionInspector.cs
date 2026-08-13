using System.Net;
using System.Runtime.InteropServices;

namespace AiScanner.Infrastructure;

public sealed class TcpConnectionInspector
{
    public IReadOnlyDictionary<int, IReadOnlyList<string>> GetRemoteEndpoints()
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, TcpTableOwnerPidAll, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, TcpTableOwnerPidAll, 0) != 0) return new Dictionary<int, IReadOnlyList<string>>();
            var count = Marshal.ReadInt32(buffer);
            var rowPointer = buffer + sizeof(int);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var result = new Dictionary<int, HashSet<string>>();
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPointer + i * rowSize);
                if (row.State != 5 || row.RemoteAddress == 0) continue; // ESTABLISHED
                var address = new IPAddress(row.RemoteAddress);
                var endpoint = $"{address}:{ConvertPort(row.RemotePort)}";
                if (!result.TryGetValue((int)row.ProcessId, out var endpoints)) result[(int)row.ProcessId] = endpoints = [];
                endpoints.Add(endpoint);
            }
            return result.ToDictionary(x => x.Key, x => (IReadOnlyList<string>)x.Value.Order().ToArray());
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static int ConvertPort(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        return (bytes[0] << 8) + bytes[1];
    }

    private const int TcpTableOwnerPidAll = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint ProcessId;
    }
}
