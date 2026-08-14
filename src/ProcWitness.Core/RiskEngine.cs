namespace ProcWitness.Core;

public sealed class RiskEngine : IRiskEngine
{
    private static readonly string[] SuspiciousRoots =
    [
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
    ];

    public ProcessAssessment Assess(ProcessObservation process, IReadOnlyCollection<UsageSample> history, DateTimeOffset? lastTaskManagerStart)
    {
        var findings = new List<Finding>();
        if (process.SignatureVerificationAvailable && !process.IsSigned && process.ExecutablePath is not null)
            Add(findings, "unsigned", "Dosyanın doğrulanabilir bir yayıncı imzası yok.");
        if (process.ExecutablePath is not null && SuspiciousRoots.Any(root =>
                !string.IsNullOrWhiteSpace(root) && process.ExecutablePath.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            Add(findings, "user-writable-path", process.ExecutablePath);
        if (process.CpuPercent >= 70)
            Add(findings, "high-cpu", $"Anlık CPU kullanımı %{process.CpuPercent:F1}.");
        else if (process.CpuPercent >= 35)
            Add(findings, "elevated-cpu", $"Anlık CPU kullanımı %{process.CpuPercent:F1}.");
        if (process.WindowVisibilityAvailable && !process.HasVisibleWindow && process.CpuPercent >= 35)
            Add(findings, "hidden-load", "Arka plandaki süreç anlamlı işlemci gücü tüketiyor.");
        if (process.SignatureVerificationAvailable && !process.IsSigned && process.ActiveConnections > 0)
            Add(findings, "unsigned-network", $"{process.ActiveConnections} etkin uzak bağlantı gözlendi.");
        if (process.FileCreatedAt is { } created && created >= DateTimeOffset.UtcNow.AddDays(-7) && process.ActiveConnections > 0)
            Add(findings, "recent-network-binary", $"Dosya oluşturma zamanı: {created.LocalDateTime:g}.");
        if (process.WindowVisibilityAvailable && process.SentBytes >= 10 * 1024 * 1024 && !process.HasVisibleWindow)
            Add(findings, "background-upload", $"İzleme başladığından beri {process.SentMegabytes:F1} MB gönderildi.");
        AddTaskManagerEvasionFinding(process, history, lastTaskManagerStart, findings);
        var (score, level) = Score(findings);
        return new(process, score, level, findings);
    }

    public WindowAssessment AssessWindow(ProcessWindowSummary summary)
    {
        var findings = new List<Finding>();
        if (summary.SignatureVerificationAvailable && !summary.Signed && summary.Path is not null)
            Add(findings, "unsigned", "Dosyanın doğrulanabilir bir yayıncı imzası yok.");
        if (summary.Path is not null && SuspiciousRoots.Any(root =>
                !string.IsNullOrWhiteSpace(root) && summary.Path.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            Add(findings, "user-writable-path", summary.Path);
        if (summary.MaxCpu >= 70 && summary.AvgCpu >= 35)
            Add(findings, "high-cpu", $"Sürekli yüksek CPU: ort. %{summary.AvgCpu:F1}, tepe %{summary.MaxCpu:F1}.");
        else if (summary.MaxCpu >= 40 && summary.CpuRange >= 25)
            Add(findings, "cpu-spike", $"CPU aralığı {summary.CpuRange:F1} puan.");
        else if (summary.MaxCpu >= 35)
            Add(findings, "elevated-cpu", $"Tepe CPU kullanımı %{summary.MaxCpu:F1}.");
        if (summary.SignatureVerificationAvailable && !summary.Signed && summary.MaxConnections > 0)
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
            Add(findings, "hidden-load", "Görünür pencere olmadan yoğun kaynak veya ağ kullanımı gözlendi.");
        if (summary.PidCount > 1)
            Add(findings, "pid-respawn", $"Aynı dosya {summary.PidCount} farklı PID ile gözlendi.");
        var meaningful = summary.MaxCpu >= RuleSet.MeaningfulThresholds.PeakCpu ||
                         summary.CpuRange >= RuleSet.MeaningfulThresholds.CpuRange ||
                         summary.SentBytesInWindow >= RuleSet.MeaningfulThresholds.SentBytes ||
                         summary.ReceivedBytesInWindow >= RuleSet.MeaningfulThresholds.ReceivedBytes ||
                         findings.Count > 0;
        var (score, level) = Score(findings);
        return new(summary, score, level, meaningful, findings);
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
