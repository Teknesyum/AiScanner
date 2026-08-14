using ProcWitness.Core;
using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class BaselineManagerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "procwitness-baseline-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Compare_FindsAddedRemovedChangedAndNewPersistence()
    {
        var manager = new BaselineManager(_root);
        var oldProcesses = new[]
        {
            Observation("stable", Path.Combine(_root, "stable.exe"), "OLD"),
            Observation("removed", Path.Combine(_root, "removed.exe"), "REMOVED")
        };
        var oldPersistence = Inventory(Entry("old", Path.Combine(_root, "stable.exe"), "OLD"));
        var baselinePath = await manager.SaveAsync(oldProcesses, oldPersistence);
        var currentProcesses = new[]
        {
            Observation("stable", Path.Combine(_root, "stable.exe"), "NEW"),
            Observation("added", Path.Combine(_root, "added.exe"), "ADDED")
        };
        var newPersistence = Inventory(
            Entry("old", Path.Combine(_root, "stable.exe"), "OLD"),
            Entry("new", Path.Combine(_root, "added.exe"), "ADDED"));

        var comparison = await manager.CompareAsync(baselinePath, currentProcesses, newPersistence);

        Assert.Contains(comparison.Added, x => x.Name == "added");
        Assert.Contains(comparison.Removed, x => x.Name == "removed");
        Assert.Contains(comparison.Changed, x => x.Name == "stable" && x.PreviousSha256 == "OLD" && x.CurrentSha256 == "NEW");
        Assert.Contains(comparison.NewPersistence, x => x.Name == "new");
    }

    [Fact]
    public void NoBaselineFiles_ReturnsEmptyList()
    {
        Assert.Empty(new BaselineManager(_root).List());
    }

    private static ProcessObservation Observation(string name, string path, string hash) =>
        new(1, name, path, null, 0, 1, true, SignatureStatus.Valid, "Publisher", hash, DateTimeOffset.UtcNow);

    private static PersistenceEntry Entry(string name, string path, string hash) =>
        new("test", name, path, path, hash, SignatureStatus.Valid, "Publisher", true, DateTimeOffset.UtcNow, []);

    private static PersistenceInventory Inventory(params PersistenceEntry[] entries) =>
        new(DateTimeOffset.UtcNow, [new("test", true, null, entries)]);

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}
