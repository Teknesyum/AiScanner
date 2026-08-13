using AiScanner.Core;
using Xunit;

namespace AiScanner.Tests;

public sealed class RiskEngineTests
{
    private readonly RiskEngine _engine = new();

    [Fact]
    public void CleanSignedProcess_HasNoFindings()
    {
        var process = Observation(path: @"C:\Program Files\Safe\safe.exe", cpu: 2, signed: true);
        var result = _engine.Assess(process, [], null);
        Assert.Equal(RiskLevel.Clean, result.Level);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void UnsignedHiddenHighCpuProcess_IsHighRisk()
    {
        var process = Observation(path: Path.Combine(Path.GetTempPath(), "worker.exe"), cpu: 85, signed: false, visible: false);
        var result = _engine.Assess(process, [], null);
        Assert.True(result.Level >= RiskLevel.High);
        Assert.Contains(result.Findings, x => x.Code == "hidden-load");
    }

    [Fact]
    public void CpuDropAfterTaskManager_IsDetected()
    {
        var started = DateTimeOffset.UtcNow;
        var process = Observation(path: @"C:\Tools\worker.exe", cpu: 2, signed: false) with { ObservedAt = started.AddSeconds(4) };
        UsageSample[] history =
        [
            new(42, "worker", 80, started.AddSeconds(-8)),
            new(42, "worker", 75, started.AddSeconds(-3)),
            new(42, "worker", 3, started.AddSeconds(3))
        ];
        var result = _engine.Assess(process, history, started);
        Assert.Contains(result.Findings, x => x.Code == "taskmgr-evasion");
    }

    [Fact]
    public void UnavailablePlatformSignals_AreNotTreatedAsUnsignedOrHidden()
    {
        var process = Observation(@"/usr/bin/worker", 40, false, false) with
        {
            SignatureVerificationAvailable = false,
            WindowVisibilityAvailable = false,
            ActiveConnections = 2
        };

        var result = _engine.Assess(process, [], null);

        Assert.DoesNotContain(result.Findings, x => x.Code is "unsigned" or "unsigned-network" or "hidden-load");
        Assert.Contains(result.Findings, x => x.Code == "elevated-cpu");
    }

    [Fact]
    public void AiPrompt_ContainsOnlyRiskyCandidatesAndInstructions()
    {
        var risky = _engine.Assess(Observation(Path.Combine(Path.GetTempPath(), "worker.exe"), 80, false, false), [], null);
        var clean = _engine.Assess(Observation(@"C:\Program Files\Safe\safe.exe", 1, true), [], null);
        var prompt = new AiAnalysisPromptBuilder().Build([risky, clean], DateTimeOffset.UtcNow);
        Assert.Contains("TELEMETRİ_JSON", prompt);
        Assert.Contains("worker", prompt);
        Assert.DoesNotContain("safe.exe", prompt);
        Assert.Contains("%USERPROFILE%", prompt);
    }

    [Fact]
    public void LongAnalysisPrompt_ContainsBundlePathAndReadingOrder()
    {
        var path = @"C:\Data\analysis-10m.json";
        var prompt = new AiAnalysisPromptBuilder().BuildForLocalBundle(path, TimeSpan.FromMinutes(10), 120, 5000);
        Assert.Contains(path, prompt);
        Assert.Contains("processSummaries", prompt);
        Assert.Contains("snapshots", prompt);
        Assert.Contains("5000 süreç gözlemi", prompt);
    }

    private static ProcessObservation Observation(string path, double cpu, bool signed, bool visible = true) =>
        new(42, "worker", path, DateTimeOffset.UtcNow.AddMinutes(-1), cpu, 1024, visible, signed, signed ? "Safe Publisher" : null, "ABC", DateTimeOffset.UtcNow);
}
