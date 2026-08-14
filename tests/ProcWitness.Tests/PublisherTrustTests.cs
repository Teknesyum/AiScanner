using System.Security.Cryptography.X509Certificates;
using ProcWitness.Core;
using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class PublisherTrustTests
{
    private readonly RiskEngine _engine = new();

    [Theory]
    [InlineData("Microsoft Corporation")]
    [InlineData("Discord Inc.")]
    [InlineData("GitHub, Inc.")]
    public void TrustedValidPublisher_SuppressesOnlyWritablePathAndHiddenLoad(string publisher)
    {
        var process = new ProcessObservation(
            42, "worker", Path.Combine(Path.GetTempPath(), "worker.exe"), null, 80, 1024,
            false, SignatureStatus.Valid, publisher, "ABC", DateTimeOffset.UtcNow)
        {
            ActiveConnections = 1,
            WindowVisibilityAvailable = true
        };

        var result = _engine.Assess(process, [], null);

        Assert.DoesNotContain(result.Findings, x => x.Code is "user-writable-path" or "hidden-load");
        Assert.Contains(result.SuppressedFindings, x => x is { Code: "user-writable-path", Reason: "trusted-publisher" });
        Assert.Contains(result.SuppressedFindings, x => x is { Code: "hidden-load", Reason: "trusted-publisher" });
        Assert.Contains(result.Findings, x => x.Code == "high-cpu");
    }

    [Fact]
    public void PublisherNameWithoutValidSignature_DoesNotSuppressFindings()
    {
        var process = new ProcessObservation(
            42, "worker", Path.Combine(Path.GetTempPath(), "worker.exe"), null, 40, 1024,
            false, SignatureStatus.Invalid, "Microsoft Corporation", "ABC", DateTimeOffset.UtcNow);

        var result = _engine.Assess(process, [], null);

        Assert.Contains(result.Findings, x => x.Code == "user-writable-path");
        Assert.Empty(result.SuppressedFindings);
    }

    [Fact]
    public void ExpiredOnlyCertificateChain_IsNotReportedAsUnsigned()
    {
        Assert.Equal(
            SignatureStatus.ValidButExpired,
            ProcessScanner.ClassifyChain(false, [X509ChainStatusFlags.NotTimeValid]));

        var process = new ProcessObservation(
            42, "worker", @"C:\Program Files\Safe\safe.exe", null, 1, 1024,
            true, SignatureStatus.ValidButExpired, "Microsoft Corporation", "ABC", DateTimeOffset.UtcNow);
        var result = _engine.Assess(process, [], null);

        Assert.DoesNotContain(result.Findings, x => x.Code == "unsigned");
    }

    [Fact]
    public void NonTimeChainFailure_IsInvalid()
    {
        Assert.Equal(
            SignatureStatus.Invalid,
            ProcessScanner.ClassifyChain(false, [X509ChainStatusFlags.UntrustedRoot]));
    }
}
