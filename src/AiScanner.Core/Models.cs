namespace AiScanner.Core;

public enum RiskLevel { Clean, Low, Medium, High, Critical }

public sealed record ProcessObservation(
    int ProcessId,
    string Name,
    string? ExecutablePath,
    DateTimeOffset? StartedAt,
    double CpuPercent,
    long WorkingSetBytes,
    bool HasVisibleWindow,
    bool IsSigned,
    string? Publisher,
    string? Sha256,
    DateTimeOffset ObservedAt)
{
    public bool SignatureVerificationAvailable { get; init; } = true;
    public bool WindowVisibilityAvailable { get; init; } = true;
    public long SentBytes { get; init; }
    public long ReceivedBytes { get; init; }
    public int ActiveConnections { get; init; }
    public IReadOnlyList<string> RemoteEndpoints { get; init; } = [];
    public DateTimeOffset? FileCreatedAt { get; init; }
    public double SentMegabytes => SentBytes / 1024d / 1024d;
    public double ReceivedMegabytes => ReceivedBytes / 1024d / 1024d;
}

public sealed record Finding(string Code, string Title, string Explanation, int Score);

public sealed record ProcessAssessment(
    ProcessObservation Process,
    int Score,
    RiskLevel Level,
    IReadOnlyList<Finding> Findings)
{
    public string FindingsSummary => Findings.Count == 0
        ? "Belirgin risk sinyali bulunamadı."
        : string.Join(" • ", Findings.Select(x => x.Title));
}

public sealed record UsageSample(int ProcessId, string Name, double CpuPercent, DateTimeOffset Timestamp);

public interface IRiskEngine
{
    ProcessAssessment Assess(ProcessObservation process, IReadOnlyCollection<UsageSample> history, DateTimeOffset? lastTaskManagerStart);
}
