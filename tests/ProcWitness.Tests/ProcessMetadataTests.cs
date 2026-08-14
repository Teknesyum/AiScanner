using ProcWitness.Core;
using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class ProcessMetadataTests
{
    [Theory]
    [InlineData("tool --password=hunter2", "tool --password=***")]
    [InlineData("tool --token secret", "tool --token secret")]
    [InlineData("tool --token=abc123", "tool --token=***")]
    [InlineData("tool -p hunter2", "tool -p ***")]
    [InlineData("tool apikey=secret", "tool apikey=***")]
    [InlineData("curl -H Bearer abc.def", "curl -H Bearer ***")]
    public void CommandLineRedactor_MasksSupportedSecrets(string input, string expected)
    {
        Assert.Equal(expected, CommandLineRedactor.Redact(input));
    }

    [Fact]
    public void EncodedCommand_TriggersSuspiciousLaunchFinding()
    {
        var process = new ProcessObservation(
            42, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", null,
            1, 1024, false, SignatureStatus.Valid, "Microsoft Corporation", "ABC", DateTimeOffset.UtcNow)
        {
            ParentName = "explorer.exe",
            CommandLine = "powershell.exe -NoP -EncodedCommand SQBFAFgA",
            CommandLineAvailable = true,
            ProcessTreeAvailable = true
        };

        var result = new RiskEngine().Assess(process, [], null);

        Assert.Contains(result.Findings, x => x.Code == "suspicious-launch-chain");
    }

    [Fact]
    public async Task CurrentProcess_HasPlatformMetadataOrExplicitUnavailableFlags()
    {
        var metadata = await new ProcessMetadataInspector().ReadAsync([Environment.ProcessId], CancellationToken.None);
        Assert.True(metadata.TryGetValue(Environment.ProcessId, out var current));

        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            Assert.True(current!.CommandLineAvailable || current.ProcessTreeAvailable);
        if (!current!.CommandLineAvailable) Assert.Null(current.CommandLine);
    }
}
