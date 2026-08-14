using System.Collections.Concurrent;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace ProcWitness.Infrastructure;

public sealed record ProcessNetworkUsage(long SentBytes, long ReceivedBytes);

public sealed class NetworkTelemetryCollector : IDisposable
{
    private readonly ConcurrentDictionary<int, Counters> _usage = new();
    private TraceEventSession? _session;
    private Task? _processingTask;
    public bool IsAvailable { get; private set; }
    public string Status { get; private set; } = "ETW ağ izleyicisi başlatılmadı";

    public void Start()
    {
        if (!OperatingSystem.IsWindows())
        {
            Status = OperatingSystem.IsLinux()
                ? "Linux: süreç başına ağ baytı ölçümü ayrıcalıklı eBPF gerektirir; bağlantılar /proc üzerinden izleniyor"
                : "macOS: süreç başına ağ baytı ölçümü Network Extension yetkisi gerektirir; bağlantılar lsof üzerinden izleniyor";
            return;
        }
        try
        {
            _session = new TraceEventSession($"ProcWitness-Network-{Environment.ProcessId}") { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            _session.Source.Kernel.TcpIpSend += data => AddSent(data.ProcessID, data.size);
            _session.Source.Kernel.TcpIpRecv += data => AddReceived(data.ProcessID, data.size);
            _session.Source.Kernel.TcpIpSendIPV6 += data => AddSent(data.ProcessID, data.size);
            _session.Source.Kernel.TcpIpRecvIPV6 += data => AddReceived(data.ProcessID, data.size);
            _processingTask = Task.Run(() => _session.Source.Process());
            IsAvailable = true;
            Status = "ETW süreç ağ baytları etkin";
        }
        catch (UnauthorizedAccessException)
        {
            Status = "Ağ bayt ölçümü için yönetici yetkisi gerekiyor";
            _session?.Dispose();
            _session = null;
        }
        catch (Exception ex)
        {
            Status = $"Ağ bayt ölçümü kullanılamıyor: {ex.Message}";
            _session?.Dispose();
            _session = null;
        }
    }

    public ProcessNetworkUsage GetUsage(int processId) => _usage.TryGetValue(processId, out var counters)
        ? new(Interlocked.Read(ref counters.Sent), Interlocked.Read(ref counters.Received))
        : new(0, 0);

    private void AddSent(int processId, int bytes)
    {
        if (processId <= 0 || bytes <= 0) return;
        Interlocked.Add(ref _usage.GetOrAdd(processId, _ => new()).Sent, bytes);
    }

    private void AddReceived(int processId, int bytes)
    {
        if (processId <= 0 || bytes <= 0) return;
        Interlocked.Add(ref _usage.GetOrAdd(processId, _ => new()).Received, bytes);
    }

    public void Dispose()
    {
        _session?.Dispose();
        try { _processingTask?.Wait(TimeSpan.FromSeconds(2)); } catch (AggregateException) { }
    }

    private sealed class Counters { public long Sent; public long Received; }
}
