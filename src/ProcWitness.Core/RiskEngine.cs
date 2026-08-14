namespace ProcWitness.Core;

public sealed class RiskEngine : IRiskEngine
{
    public bool PublisherAllowlistEnabled { get; set; } = true;
    private static readonly string[] SuspiciousRoots =
    [
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
    ];

    public ProcessAssessment Assess(ProcessObservation process, IReadOnlyCollection<UsageSample> history, DateTimeOffset? lastTaskManagerStart)
        => Assess(process, history, new RiskContext(lastTaskManagerStart, new HashSet<string>()));

    public ProcessAssessment Assess(ProcessObservation process, IReadOnlyCollection<UsageSample> history, RiskContext context)
    {
        var findings = new List<Finding>();
        var suppressed = new List<SuppressedFinding>();
        var trustedPublisher = PublisherAllowlistEnabled && PublisherTrustList.IsTrusted(process.SignatureStatus, process.Publisher);
        if (process.SignatureStatus == SignatureStatus.Invalid && process.ExecutablePath is not null)
            Add(findings, "unsigned", "Dosyanın doğrulanabilir bir yayıncı imzası yok.");
        if (process.ExecutablePath is not null && SuspiciousRoots.Any(root =>
                !string.IsNullOrWhiteSpace(root) && process.ExecutablePath.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            AddOrSuppress(findings, suppressed, "user-writable-path", process.ExecutablePath, trustedPublisher);
        if (process.CpuPercent >= 70)
            Add(findings, "high-cpu", $"Anlık CPU kullanımı %{process.CpuPercent:F1}.");
        else if (process.CpuPercent >= 35)
            Add(findings, "elevated-cpu", $"Anlık CPU kullanımı %{process.CpuPercent:F1}.");
        if (process.WindowVisibilityAvailable && !process.HasVisibleWindow && process.CpuPercent >= 35)
            AddOrSuppress(findings, suppressed, "hidden-load", "Arka plandaki süreç anlamlı işlemci gücü tüketiyor.", trustedPublisher);
        if (process.SignatureStatus == SignatureStatus.Invalid && process.ActiveConnections > 0)
            Add(findings, "unsigned-network", $"{process.ActiveConnections} etkin uzak bağlantı gözlendi.");
        if (process.FileCreatedAt is { } created && created >= DateTimeOffset.UtcNow.AddDays(-7) && process.ActiveConnections > 0)
            Add(findings, "recent-network-binary", $"Dosya oluşturma zamanı: {created.LocalDateTime:g}.");
        if (process.WindowVisibilityAvailable && process.SentBytes >= 10 * 1024 * 1024 && !process.HasVisibleWindow)
            Add(findings, "background-upload", $"İzleme başladığından beri {process.SentMegabytes:F1} MB gönderildi.");
        if (IsSuspiciousLaunch(process.Name, process.ParentName, process.CommandLine))
            Add(findings, "suspicious-launch-chain", $"Ebeveyn: {process.ParentName ?? "bilinmiyor"}; komut satırında şüpheli başlatma deseni gözlendi.");
        AddTaskManagerEvasionFinding(process, history, context.LastTaskManagerStart, findings);
        var persistent = process.ExecutablePath is not null && context.PersistentPaths.Contains(process.ExecutablePath);
        if (persistent) Add(findings, "persistent", "Çalışan dosya bir otomatik başlatma kaydıyla eşleşti.");
        if (persistent && process.SignatureStatus == SignatureStatus.Invalid && process.ActiveConnections > 0)
            Add(findings, "persistent-unsigned-network", "İmzasız kalıcı süreç etkin dış bağlantı kurdu.");
        if (process.ExecutablePath is { } path && context.NewSinceBaseline?.Contains(path) == true)
            Add(findings, "new-since-baseline", "Bu çalıştırılabilir dosya seçili baseline kaydında yoktu.");
        if (process.ExecutablePath is { } changedPath && context.ChangedSinceBaseline?.Contains(changedPath) == true)
            Add(findings, "binary-changed-since-baseline", "Aynı yoldaki dosyanın SHA-256 değeri baseline sonrasında değişti.");
        if (process.ExecutablePath is { } persistencePath && context.NewPersistenceSinceBaseline?.Contains(persistencePath) == true)
            Add(findings, "new-persistence-since-baseline", "Bu dosyaya ait kalıcılık kaydı baseline sonrasında eklendi.");
        var (score, level) = Score(findings);
        return new(process, score, level, findings) { SuppressedFindings = suppressed };
    }

    public WindowAssessment AssessWindow(ProcessWindowSummary summary)
    {
        var findings = new List<Finding>();
        var suppressed = new List<SuppressedFinding>();
        var trustedPublisher = PublisherAllowlistEnabled && summary.Publishers.Any(x => PublisherTrustList.IsTrusted(summary.SignatureStatus, x));
        if (summary.SignatureStatus == SignatureStatus.Invalid && summary.Path is not null)
            Add(findings, "unsigned", "Dosyanın doğrulanabilir bir yayıncı imzası yok.");
        if (summary.Path is not null && SuspiciousRoots.Any(root =>
                !string.IsNullOrWhiteSpace(root) && summary.Path.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            AddOrSuppress(findings, suppressed, "user-writable-path", summary.Path, trustedPublisher);
        if (summary.MaxCpu >= 70 && summary.AvgCpu >= 35)
            Add(findings, "high-cpu", $"Sürekli yüksek CPU: ort. %{summary.AvgCpu:F1}, tepe %{summary.MaxCpu:F1}.");
        else if (summary.MaxCpu >= 40 && summary.CpuRange >= 25)
            Add(findings, "cpu-spike", $"CPU aralığı {summary.CpuRange:F1} puan.");
        else if (summary.MaxCpu >= 35)
            Add(findings, "elevated-cpu", $"Tepe CPU kullanımı %{summary.MaxCpu:F1}.");
        if (summary.SignatureStatus == SignatureStatus.Invalid && summary.MaxConnections > 0)
            Add(findings, "unsigned-network", $"{summary.MaxConnections} etkin uzak bağlantı gözlendi.");
        if (summary.RecentFile && summary.MaxConnections > 0)
            Add(findings, "recent-network-binary", "Son 7 günde oluşturulmuş dosya ağ kullandı.");
        if (summary.SentBytesInWindow >= 10 * 1024 * 1024)
            Add(findings, "background-upload", $"Seçili aralıkta {summary.SentBytesInWindow / 1048576d:F1} MB gönderildi.");
        else if (summary.SentBytesInWindow >= RuleSet.MeaningfulThresholds.SentBytes)
            Add(findings, "meaningful-upload", $"Seçili aralıkta {summary.SentBytesInWindow / 1048576d:F2} MB gönderildi.");
        if (summary.ReceivedBytesInWindow >= 25 * 1024 * 1024)
            Add(findings, "high-download", $"Seçili aralıkta {summary.ReceivedBytesInWindow / 1048576d:F1} MB alındı.");
        if (summary.WindowVisibilityAvailable && summary.Hidden &&
            (summary.MaxCpu >= 35 || summary.SentBytesInWindow >= 1024 * 1024))
            AddOrSuppress(findings, suppressed, "hidden-load", "Görünür pencere olmadan yoğun kaynak veya ağ kullanımı gözlendi.", trustedPublisher);
        if (summary.PidCount > 1)
            Add(findings, "pid-respawn", $"Aynı dosya {summary.PidCount} farklı PID ile gözlendi.");
        if (summary.SuspiciousLaunchChain)
            Add(findings, "suspicious-launch-chain", "Şüpheli ebeveyn/çocuk ilişkisi veya komut satırı deseni gözlendi.");
        if (summary.Persistent)
            Add(findings, "persistent", "Çalışan dosya bir otomatik başlatma kaydıyla eşleşti.");
        if (summary.Persistent && summary.SignatureStatus == SignatureStatus.Invalid && summary.MaxConnections > 0)
            Add(findings, "persistent-unsigned-network", "İmzasız kalıcı süreç etkin dış bağlantı kurdu.");
        if (summary.NewSinceBaseline) Add(findings, "new-since-baseline", "Bu çalıştırılabilir dosya seçili baseline kaydında yoktu.");
        if (summary.BinaryChangedSinceBaseline) Add(findings, "binary-changed-since-baseline", "Aynı yoldaki dosyanın SHA-256 değeri baseline sonrasında değişti.");
        if (summary.NewPersistenceSinceBaseline) Add(findings, "new-persistence-since-baseline", "Bu dosyaya ait kalıcılık kaydı baseline sonrasında eklendi.");
        var meaningful = summary.MaxCpu >= RuleSet.MeaningfulThresholds.PeakCpu ||
                         summary.CpuRange >= RuleSet.MeaningfulThresholds.CpuRange ||
                         summary.SentBytesInWindow >= RuleSet.MeaningfulThresholds.SentBytes ||
                         summary.ReceivedBytesInWindow >= RuleSet.MeaningfulThresholds.ReceivedBytes ||
                         findings.Count > 0 || suppressed.Count > 0;
        var (score, level) = Score(findings);
        return new(summary, score, level, meaningful, findings) { SuppressedFindings = suppressed };
    }

    private static void AddOrSuppress(
        ICollection<Finding> findings,
        ICollection<SuppressedFinding> suppressed,
        string code,
        string explanation,
        bool trustedPublisher)
    {
        if (trustedPublisher) suppressed.Add(new(code, "trusted-publisher"));
        else Add(findings, code, explanation);
    }

    public static bool IsSuspiciousLaunch(string processName, string? parentName, string? commandLine)
    {
        var child = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
        var parent = Path.GetFileNameWithoutExtension(parentName ?? string.Empty).ToLowerInvariant();
        string[] interpreters = ["powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bash", "curl"];
        string[] launchers = ["winword", "excel", "powerpnt", "outlook", "chrome", "msedge", "firefox", "7z", "winrar"];
        if (interpreters.Contains(child) && launchers.Contains(parent)) return true;
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        string[] patterns = ["-enc", "-encodedcommand", "frombase64string", "iex", "downloadstring", "-w hidden", "-windowstyle hidden"];
        return patterns.Any(x => commandLine.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    private static void Add(ICollection<Finding> findings, string code, string explanation)
    {
        var rule = RuleSet.Rules[code];
        if (rule.Enabled) findings.Add(new(rule.Code, rule.Title, explanation, rule.Weight));
    }

    private static (int Score, RiskLevel Level) Score(IEnumerable<Finding> findings)
    {
        var score = Math.Min(100, findings.Sum(x => x.Score));
        return (score, score switch
        {
            >= 80 => RiskLevel.Critical,
            >= 55 => RiskLevel.High,
            >= 30 => RiskLevel.Medium,
            >= 15 => RiskLevel.Low,
            _ => RiskLevel.Clean
        });
    }

    private static void AddTaskManagerEvasionFinding(
        ProcessObservation process,
        IReadOnlyCollection<UsageSample> history,
        DateTimeOffset? taskManagerStart,
        ICollection<Finding> findings)
    {
        if (taskManagerStart is null) return;
        var before = history.Where(x => x.ProcessId == process.ProcessId && x.Timestamp >= taskManagerStart.Value.AddSeconds(-20) && x.Timestamp < taskManagerStart).ToArray();
        var after = history.Where(x => x.ProcessId == process.ProcessId && x.Timestamp >= taskManagerStart && x.Timestamp <= taskManagerStart.Value.AddSeconds(15)).ToArray();
        if (before.Length < 2 || after.Length < 1) return;
        var beforeAverage = before.Average(x => x.CpuPercent);
        var afterAverage = after.Average(x => x.CpuPercent);
        if (beforeAverage >= 30 && afterAverage <= Math.Max(5, beforeAverage * .20))
            Add(findings, "taskmgr-evasion", $"CPU ortalaması %{beforeAverage:F1} seviyesinden %{afterAverage:F1} seviyesine düştü.");
    }
}
