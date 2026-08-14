using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class PersistenceInspectorTests
{
    [Fact]
    public void ResolvePath_ExtractsQuotedExecutableWithoutArguments()
    {
        var executable = Environment.ProcessPath!;
        var resolved = PersistenceInspector.ResolvePath($"\"{executable}\" --background");

        Assert.Equal(Path.GetFullPath(executable), resolved);
    }

    [Fact]
    public async Task Inventory_ReportsPlatformSourcesAndAvailability()
    {
        var inventory = await new PersistenceInspector().ScanAsync();

        Assert.NotEmpty(inventory.Sources);
        Assert.All(inventory.Sources, source => Assert.False(string.IsNullOrWhiteSpace(source.Source)));
        if (OperatingSystem.IsWindows())
        {
            Assert.Contains(inventory.Sources, x => x.Source == "winlogon" && x.Available);
            Assert.Contains(inventory.Entries, x => x.Source == "winlogon");
        }
    }
}
