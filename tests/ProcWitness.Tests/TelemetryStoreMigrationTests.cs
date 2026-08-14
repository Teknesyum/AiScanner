using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class TelemetryStoreMigrationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "procwitness-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void MigrateLegacyDataMovesExistingEvidenceWhenTargetDoesNotExist()
    {
        var legacy = Path.Combine(_root, "legacy", "data");
        var target = Path.Combine(_root, "current", "data");
        Directory.CreateDirectory(legacy);
        File.WriteAllText(Path.Combine(legacy, "analysis-existing.json"), "{}");

        TelemetryStore.MigrateLegacyData(legacy, target);

        Assert.False(Directory.Exists(legacy));
        Assert.True(File.Exists(Path.Combine(target, "analysis-existing.json")));
    }

    [Fact]
    public void MigrateLegacyDataKeepsBothDirectoriesWhenTargetAlreadyExists()
    {
        var legacy = Path.Combine(_root, "legacy", "data");
        var target = Path.Combine(_root, "current", "data");
        Directory.CreateDirectory(legacy);
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(legacy, "analysis-existing.json"), "{}");

        TelemetryStore.MigrateLegacyData(legacy, target);

        Assert.True(File.Exists(Path.Combine(legacy, "analysis-existing.json")));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}
