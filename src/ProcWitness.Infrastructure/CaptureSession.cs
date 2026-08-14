using ProcWitness.Core;

namespace ProcWitness.Infrastructure;

public sealed record CaptureScanResult(
    IReadOnlyList<ProcessAssessment> Assessments,
    IReadOnlyList<ProcessObservation> Processes,
    string NetworkStatus,
    bool NetworkByteTelemetryAvailable);

public sealed record CaptureProgress(TimeSpan Remaining, CaptureScanResult Latest);

public sealed class CaptureSession : IDisposable
{
    private readonly ProcessScanner _scanner = new();
    private readonly IRiskEngine _riskEngine;
    private readonly NetworkTelemetryCollector _network = new();
    private readonly TcpConnectionInspector _connections = new();
    private readonly PersistenceInspector _persistenceInspector = new();
    private readonly List<UsageSample> _history = [];
    private DateTimeOffset? _taskManagerStart;
    private HashSet<string> _persistentPaths = new(PathComparer);
    private HashSet<string> _newPaths = new(PathComparer);
    private HashSet<string> _changedPaths = new(PathComparer);
    private HashSet<string> _newPersistencePaths = new(PathComparer);

    public TelemetryStore Store { get; }
    public PersistenceInventory? PersistenceInventory { get; private set; }
    public BaselineComparison? BaselineComparison { get; private set; }
    public IReadOnlyList<ProcessObservation> LatestProcesses { get; private set; } = [];
    public TimeSpan SampleInterval { get; set; } = TimeSpan.FromSeconds(4);
    public bool PersistenceEnabled { get; set; } = true;
    public int RetentionDays { get; set; } = 7;
    public bool PublisherAllowlistEnabled { get => (_riskEngine as RiskEngine)?.PublisherAllowlistEnabled ?? true; set { if (_riskEngine is RiskEngine engine) engine.PublisherAllowlistEnabled = value; } }
    public bool IncludeRawSnapshots { get => Store.IncludeRawSnapshots; set => Store.IncludeRawSnapshots = value; }

    private static StringComparer PathComparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    public CaptureSession(string? dataDirectory = null, IRiskEngine? riskEngine = null)
    {
        _riskEngine = riskEngine ?? new RiskEngine();
        Store = new(_riskEngine, dataDirectory);
        _network.Start();
    }

    public async Task<CaptureScanResult> ScanAsync(bool persist = false, CancellationToken cancellationToken = default)
    {
        var endpoints = _connections.GetRemoteEndpoints();
        var processes = (await _scanner.ScanAsync(cancellationToken)).Select(process =>
        {
            var usage = _network.GetUsage(process.ProcessId);
            var remote = endpoints.TryGetValue(process.ProcessId, out var values) ? values : [];
            return process with { SentBytes = usage.SentBytes, ReceivedBytes = usage.ReceivedBytes, ActiveConnections = remote.Count, RemoteEndpoints = remote };
        }).ToArray();
        LatestProcesses = processes;
        if (persist) await Store.AppendAsync(processes, _network.IsAvailable, _network.Status, cancellationToken);
        var taskManager = processes.FirstOrDefault(x => x.Name.Equals("Taskmgr", StringComparison.OrdinalIgnoreCase));
        if (taskManager?.StartedAt is { } start) _taskManagerStart = start;
        _history.AddRange(processes.Select(x => new UsageSample(x.ProcessId, x.Name, x.CpuPercent, x.ObservedAt)));
        _history.RemoveAll(x => x.Timestamp < DateTimeOffset.UtcNow.AddMinutes(-2));
        var context = new RiskContext(_taskManagerStart, _persistentPaths, _newPaths, _changedPaths, _newPersistencePaths);
        var assessments = processes.Select(x => _riskEngine.Assess(x, _history, context)).OrderByDescending(x => x.Score).ThenBy(x => x.Process.Name).ToArray();
        return new(assessments, processes, _network.Status, _network.IsAvailable);
    }

    public async Task<PersistenceInventory> RefreshPersistenceAsync(CancellationToken cancellationToken = default)
    {
        PersistenceInventory = await _persistenceInspector.ScanAsync(LatestProcesses, cancellationToken);
        Store.SetPersistenceInventory(PersistenceInventory);
        _persistentPaths = PersistenceInventory.Entries.Select(x => x.ResolvedPath).Where(x => x is not null).Cast<string>().ToHashSet(PathComparer);
        return PersistenceInventory;
    }

    public void ApplyBaselineComparison(BaselineComparison? comparison)
    {
        BaselineComparison = comparison;
        Store.SetBaselineComparison(comparison);
        _newPaths = Paths(comparison?.Added);
        _changedPaths = Paths(comparison?.Changed);
        _newPersistencePaths = Paths(comparison?.NewPersistence);
    }

    public ListeningPortSnapshot GetListeningEndpoints() => _connections.GetListeningEndpoints();

    public async Task<AnalysisBundleResult> CaptureAsync(TimeSpan duration, IProgress<CaptureProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        if (duration <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(duration));
        Store.Prune(RetentionDays);
        if (PersistenceEnabled) await RefreshPersistenceAsync(cancellationToken); else Store.SetPersistenceInventory(null);
        var started = DateTimeOffset.UtcNow;
        var ends = started + duration;
        var latest = await ScanAsync(true, cancellationToken);
        var nextSample = started + SampleInterval;
        while (DateTimeOffset.UtcNow < ends)
        {
            var now = DateTimeOffset.UtcNow;
            if (now >= nextSample)
            {
                latest = await ScanAsync(true, cancellationToken);
                nextSample = now + SampleInterval;
            }
            progress?.Report(new(ends - now, latest));
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(1, Math.Max(.05, (ends - now).TotalSeconds))), cancellationToken);
        }
        latest = await ScanAsync(true, cancellationToken);
        progress?.Report(new(TimeSpan.Zero, latest));
        if (PersistenceEnabled) await RefreshPersistenceAsync(cancellationToken);
        return await Store.CreateAnalysisBundleAsync(started, DateTimeOffset.UtcNow, duration, cancellationToken);
    }

    private static HashSet<string> Paths(IReadOnlyList<BaselineDifferenceItem>? items) =>
        items?.Select(x => x.Path).Where(x => x is not null).Cast<string>().ToHashSet(PathComparer) ?? new(PathComparer);

    public void Dispose() => _network.Dispose();
}
