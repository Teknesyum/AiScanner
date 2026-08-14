namespace ProcWitness.Core;

public enum RiskLevel { Clean, Low, Medium, High, Critical }
public enum SignatureStatus { Valid, ValidButExpired, Invalid, Unavailable }

public sealed record ProcessObservation(
    int ProcessId,
    string Name,
    string? ExecutablePath,
    DateTimeOffset? StartedAt,
    double CpuPercent,
    long WorkingSetBytes,
    bool HasVisibleWindow,
    SignatureStatus SignatureStatus,
    string? Publisher,
    string? Sha256,
    DateTimeOffset ObservedAt)
{
    public bool SignatureVerificationAvailable => SignatureStatus != SignatureStatus.Unavailable;
    public bool WindowVisibilityAvailable { get; init; } = true;
    public long SentBytes { get; init; }
    public long ReceivedBytes { get; init; }
    public int ActiveConnections { get; init; }
    public IReadOnlyList<string> RemoteEndpoints { get; init; } = [];
    public DateTimeOffset? FileCreatedAt { get; init; }
    public int? ParentProcessId { get; init; }
    public string? ParentName { get; init; }
    public string? CommandLine { get; init; }
    public bool CommandLineAvailable { get; init; }
    public bool ProcessTreeAvailable { get; init; }
    public double SentMegabytes => SentBytes / 1024d / 1024d;
    public double ReceivedMegabytes => ReceivedBytes / 1024d / 1024d;
}

public sealed record Finding(string Code, string Title, string Explanation, int Score);
public sealed record SuppressedFinding(string Code, string Reason);

public sealed record ProcessAssessment(
    ProcessObservation Process,
    int Score,
    RiskLevel Level,
    IReadOnlyList<Finding> Findings)
{
    public IReadOnlyList<SuppressedFinding> SuppressedFindings { get; init; } = [];

    public string RiskColor => Level switch
    {
        RiskLevel.Critical => "#FF385C",
        RiskLevel.High => "#FF7139",
        RiskLevel.Medium => "#FFCA55",
        RiskLevel.Low => "#7CCBFF",
        _ => "#7CFF68"
    };

    public string FindingsSummary => Findings.Count == 0
        ? "Belirgin risk sinyali bulunamadı."
        : string.Join(" • ", Findings.Select(x => x.Title));
}

public sealed record UsageSample(int ProcessId, string Name, double CpuPercent, DateTimeOffset Timestamp);

public sealed record ProcessMilestone(
    DateTimeOffset AtUtc,
    double Cpu,
    double RamMb,
    long SentBytes,
    long ReceivedBytes,
    int ActiveConnections);

public sealed record ProcessTreeNode(
    int ProcessId,
    string Name,
    int? ParentProcessId,
    string? ParentName,
    string? CommandLine,
    bool CommandLineAvailable,
    bool ProcessTreeAvailable);

public sealed record ProcessWindowSummary(
    string Identity,
    string Name,
    string? Path,
    string? Sha256,
    int Samples,
    double MaxCpu,
    double AvgCpu,
    double CpuRange,
    double MaxRamMb,
    SignatureStatus SignatureStatus,
    bool WindowVisibilityAvailable,
    bool Hidden,
    IReadOnlyList<string> Publishers,
    IReadOnlyList<string> ParentNames,
    IReadOnlyList<string> CommandLines,
    bool CommandLineAvailable,
    bool ProcessTreeAvailable,
    bool SuspiciousLaunchChain,
    long SentBytesInWindow,
    long ReceivedBytesInWindow,
    int MaxConnections,
    IReadOnlyList<string> RemoteEndpoints,
    bool RecentFile,
    int PidCount,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<ProcessMilestone> Milestones);

public sealed record WindowAssessment(
    ProcessWindowSummary Summary,
    int Score,
    RiskLevel Level,
    bool Meaningful,
    IReadOnlyList<Finding> Findings)
{
    public IReadOnlyList<SuppressedFinding> SuppressedFindings { get; init; } = [];
}

public sealed record RuleDefinition(string Code, string Title, int Weight, bool Enabled = true);

public static class RuleSet
{
    public static readonly IReadOnlyDictionary<string, RuleDefinition> Rules = new RuleDefinition[]
    {
        new("unsigned", "Dijital imza doğrulanamadı", 15),
        new("user-writable-path", "Kullanıcı tarafından yazılabilir dizinden çalışıyor", 15),
        new("elevated-cpu", "Yüksek CPU kullanımı", 10),
        new("high-cpu", "Çok yüksek CPU kullanımı", 20),
        new("hidden-load", "Görünür pencere olmadan yoğun çalışıyor", 10),
        new("unsigned-network", "İmzasız süreç dış ağ bağlantısı kuruyor", 20),
        new("recent-network-binary", "Yeni oluşturulmuş dosya ağ kullanıyor", 15),
        new("background-upload", "Arka planda yüksek veri gönderimi", 20),
        new("taskmgr-evasion", "Görev Yöneticisi açılınca yükünü kesti", 30),
        new("cpu-spike", "Belirgin CPU sıçraması", 15),
        new("meaningful-upload", "Anlamlı upload", 8),
        new("high-download", "Yüksek download", 8),
        new("pid-respawn", "Aynı dosya farklı PID ile gözlendi", 10)
        ,new("suspicious-launch-chain", "Şüpheli başlatma zinciri", 20)
    }.ToDictionary(x => x.Code, StringComparer.Ordinal);

    public static class MeaningfulThresholds
    {
        public const double PeakCpu = 15;
        public const double CpuRange = 12;
        public const long SentBytes = 256 * 1024;
        public const long ReceivedBytes = 1024 * 1024;
        public const int RecentFileDays = 7;
        public const double MilestoneCpuChange = 10;
        public const int MaxMilestones = 80;
        public const int MaxRemoteEndpoints = 50;
    }
}

public interface IRiskEngine
{
    ProcessAssessment Assess(ProcessObservation process, IReadOnlyCollection<UsageSample> history, DateTimeOffset? lastTaskManagerStart);
    WindowAssessment AssessWindow(ProcessWindowSummary summary);
}
