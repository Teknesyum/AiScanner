using ProcWitness.Core;
using Xunit;

namespace ProcWitness.Tests;

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
            SignatureStatus = SignatureStatus.Unavailable,
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

    public static TheoryData<string> RuleCodes => new(RuleSet.Rules.Keys.ToArray());

    [Theory]
    [MemberData(nameof(RuleCodes))]
    public void EveryRule_HasTriggeringAndNonTriggeringCase(string code)
    {
        if (code == "taskmgr-evasion")
        {
            var started = DateTimeOffset.UtcNow;
            var process = Observation(@"C:\Tools\worker.exe", 2, true) with { ObservedAt = started.AddSeconds(4) };
            UsageSample[] triggering =
            [
                new(42, "worker", 80, started.AddSeconds(-8)),
                new(42, "worker", 75, started.AddSeconds(-3)),
                new(42, "worker", 3, started.AddSeconds(3))
            ];
            Assert.Contains(_engine.Assess(process, triggering, started).Findings, x => x.Code == code);
            Assert.DoesNotContain(_engine.Assess(process, [], null).Findings, x => x.Code == code);
            return;
        }

        Assert.Contains(_engine.AssessWindow(TriggerWindow(code)).Findings, x => x.Code == code);
        Assert.DoesNotContain(_engine.AssessWindow(CleanWindow()).Findings, x => x.Code == code);
    }

    private static ProcessObservation Observation(string path, double cpu, bool signed, bool visible = true) =>
        new(42, "worker", path, DateTimeOffset.UtcNow.AddMinutes(-1), cpu, 1024, visible, signed ? SignatureStatus.Valid : SignatureStatus.Invalid, signed ? "Safe Publisher" : null, "ABC", DateTimeOffset.UtcNow);

    private static ProcessWindowSummary TriggerWindow(string code) => code switch
    {
        "unsigned" => CleanWindow() with { SignatureStatus = SignatureStatus.Invalid },
        "user-writable-path" => CleanWindow() with { Path = Path.Combine(Path.GetTempPath(), "worker.exe") },
        "elevated-cpu" => CleanWindow() with { MaxCpu = 40, AvgCpu = 20, CpuRange = 10 },
        "high-cpu" => CleanWindow() with { MaxCpu = 80, AvgCpu = 50, CpuRange = 35 },
        "hidden-load" => CleanWindow() with { Hidden = true, MaxCpu = 40, AvgCpu = 20 },
        "unsigned-network" => CleanWindow() with { SignatureStatus = SignatureStatus.Invalid, MaxConnections = 1 },
        "recent-network-binary" => CleanWindow() with { RecentFile = true, MaxConnections = 1 },
        "background-upload" => CleanWindow() with { SentBytesInWindow = 11 * 1024 * 1024 },
        "cpu-spike" => CleanWindow() with { MaxCpu = 50, AvgCpu = 10, CpuRange = 30 },
        "meaningful-upload" => CleanWindow() with { SentBytesInWindow = 300 * 1024 },
        "high-download" => CleanWindow() with { ReceivedBytesInWindow = 26 * 1024 * 1024 },
        "pid-respawn" => CleanWindow() with { PidCount = 2 },
        "suspicious-launch-chain" => CleanWindow() with { SuspiciousLaunchChain = true },
        "persistent" => CleanWindow() with { Persistent = true },
        "persistent-unsigned-network" => CleanWindow() with { Persistent = true, SignatureStatus = SignatureStatus.Invalid, MaxConnections = 1 },
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, null)
    };

    internal static ProcessWindowSummary CleanWindow() => new(
        "worker|safe|ABC", "worker", @"C:\Program Files\Safe\safe.exe", "ABC", 3,
        2, 2, 0, 1, SignatureStatus.Valid, true, false, ["Safe Publisher"], [], [], true, true, false, false,
        0, 0, 0, [], false, 1, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow,
        [new(DateTimeOffset.UtcNow, 2, 1, 0, 0, 0)]);
}
