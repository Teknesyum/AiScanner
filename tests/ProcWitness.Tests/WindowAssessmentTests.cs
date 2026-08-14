using ProcWitness.Core;
using Xunit;

namespace ProcWitness.Tests;

public sealed class WindowAssessmentTests
{
    private readonly RiskEngine _engine = new();

    [Fact]
    public void StableLowActivityWindow_IsNotMeaningful()
    {
        var result = _engine.AssessWindow(RiskEngineTests.CleanWindow());

        Assert.False(result.Meaningful);
        Assert.Equal(RiskLevel.Clean, result.Level);
    }

    [Fact]
    public void SustainedHighCpu_IsConsistentWithInstantAssessment()
    {
        var window = RiskEngineTests.CleanWindow() with { MaxCpu = 85, AvgCpu = 70, CpuRange = 20 };
        var instant = new ProcessObservation(42, "worker", window.Path, null, 85, 1024, true, SignatureStatus.Valid, "Safe Publisher", "ABC", DateTimeOffset.UtcNow);

        var windowResult = _engine.AssessWindow(window);
        var instantResult = _engine.Assess(instant, [], null);

        Assert.True(windowResult.Meaningful);
        Assert.NotEqual(RiskLevel.Clean, windowResult.Level);
        Assert.False(instantResult.Level >= RiskLevel.Critical && windowResult.Level == RiskLevel.Clean);
        Assert.Contains(windowResult.Findings, x => x.Code == "high-cpu");
    }

    [Fact]
    public void MissingCapabilities_DoNotCreateUnsignedOrHiddenFindings()
    {
        var window = RiskEngineTests.CleanWindow() with
        {
            SignatureStatus = SignatureStatus.Unavailable,
            WindowVisibilityAvailable = false,
            Hidden = true,
            MaxConnections = 2
        };

        var result = _engine.AssessWindow(window);

        Assert.DoesNotContain(result.Findings, x => x.Code is "unsigned" or "unsigned-network" or "hidden-load");
    }
}
