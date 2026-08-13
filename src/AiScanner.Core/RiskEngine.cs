namespace AiScanner.Core;

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
            findings.Add(new("unsigned", "Dijital imza doğrulanamadı", "Dosyanın doğrulanabilir bir yayıncı imzası yok.", 15));

        if (process.ExecutablePath is not null && SuspiciousRoots.Any(root =>
                !string.IsNullOrWhiteSpace(root) && process.ExecutablePath.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            findings.Add(new("user-writable-path", "Kullanıcı tarafından yazılabilir dizinden çalışıyor", process.ExecutablePath, 15));

        if (process.CpuPercent >= 70)
            findings.Add(new("high-cpu", "Çok yüksek CPU kullanımı", $"Anlık CPU kullanımı %{process.CpuPercent:F1}.", 20));
        else if (process.CpuPercent >= 35)
            findings.Add(new("elevated-cpu", "Yüksek CPU kullanımı", $"Anlık CPU kullanımı %{process.CpuPercent:F1}.", 10));

        if (process.WindowVisibilityAvailable && !process.HasVisibleWindow && process.CpuPercent >= 35)
            findings.Add(new("hidden-load", "Görünür pencere olmadan yoğun çalışıyor", "Arka plandaki süreç anlamlı işlemci gücü tüketiyor.", 10));

        if (process.SignatureVerificationAvailable && !process.IsSigned && process.ActiveConnections > 0)
            findings.Add(new("unsigned-network", "İmzasız süreç dış ağ bağlantısı kuruyor", $"{process.ActiveConnections} etkin uzak bağlantı gözlendi.", 20));

        if (process.FileCreatedAt is { } created && created >= DateTimeOffset.UtcNow.AddDays(-7) && process.ActiveConnections > 0)
            findings.Add(new("recent-network-binary", "Yeni oluşturulmuş dosya ağ kullanıyor", $"Dosya oluşturma zamanı: {created.LocalDateTime:g}.", 15));

        if (process.WindowVisibilityAvailable && process.SentBytes >= 10 * 1024 * 1024 && !process.HasVisibleWindow)
            findings.Add(new("background-upload", "Arka planda yüksek veri gönderimi", $"İzleme başladığından beri {process.SentBytes / 1024d / 1024d:F1} MB gönderildi.", 20));

        AddTaskManagerEvasionFinding(process, history, lastTaskManagerStart, findings);

        var score = Math.Min(100, findings.Sum(x => x.Score));
        var level = score switch
        {
            >= 80 => RiskLevel.Critical,
            >= 55 => RiskLevel.High,
            >= 30 => RiskLevel.Medium,
            >= 15 => RiskLevel.Low,
            _ => RiskLevel.Clean
        };

        return new(process, score, level, findings);
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
            findings.Add(new("taskmgr-evasion", "Görev Yöneticisi açılınca yükünü kesti", $"CPU ortalaması %{beforeAverage:F1} seviyesinden %{afterAverage:F1} seviyesine düştü.", 30));
    }
}
