using System.Text.Json;
using ProcWitness.Core;

namespace ProcWitness.Infrastructure;

public sealed class BaselineManager(string dataDirectory)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly StringComparer _pathComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    public IReadOnlyList<string> List() => Directory.Exists(dataDirectory)
        ? Directory.EnumerateFiles(dataDirectory, "baseline-*.json").OrderByDescending(x => x).ToArray()
        : [];

    public async Task<string> SaveAsync(
        IReadOnlyCollection<ProcessObservation> processes,
        PersistenceInventory? persistence,
        IReadOnlyDictionary<int, IReadOnlyList<string>>? listeningPorts = null,
        bool listeningPortsAvailable = false,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(dataDirectory);
        var snapshot = new BaselineSnapshot(
            "procwitness.baseline.v1",
            DateTimeOffset.UtcNow,
            processes.GroupBy(Identity).Select(group =>
            {
                var first = group.OrderBy(x => x.ObservedAt).First();
                var ports = group.SelectMany(x => listeningPorts?.GetValueOrDefault(x.ProcessId) ?? []).Distinct().Order().ToArray();
                return new BaselineProcess(group.Key, first.Name, AnonymizePath(first.ExecutablePath), first.Sha256,
                    AggregateSignature(group.Select(x => x.SignatureStatus)), group.Min(x => x.ObservedAt), ports, listeningPortsAvailable);
            }).OrderBy(x => x.Name).ToArray(),
            persistence);
        var path = Path.Combine(dataDirectory, $"baseline-{DateTime.Now:yyyyMMdd-HHmmss}.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(snapshot, JsonOptions), cancellationToken);
        return path;
    }

    public async Task<BaselineComparison> CompareAsync(
        string baselinePath,
        IReadOnlyCollection<ProcessObservation> currentProcesses,
        PersistenceInventory? currentPersistence,
        CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(baselinePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var baseline = await JsonSerializer.DeserializeAsync<BaselineSnapshot>(stream, JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("Baseline file is invalid.");
        var previousByPath = baseline.Processes.Where(x => x.Path is not null).ToDictionary(x => x.Path!, _pathComparer);
        var currentByPath = currentProcesses.Where(x => x.ExecutablePath is not null).GroupBy(x => AnonymizePath(x.ExecutablePath)!, _pathComparer).ToDictionary(x => x.Key, x => x.First(), _pathComparer);
        var added = currentByPath.Where(x => !previousByPath.ContainsKey(x.Key)).Select(x => Item("added", x.Key, x.Value.Name, x.Value.ExecutablePath, null, x.Value.Sha256)).ToArray();
        var removed = previousByPath.Where(x => !currentByPath.ContainsKey(x.Key)).Select(x => Item("removed", x.Key, x.Value.Name, x.Value.Path, x.Value.Sha256, null)).ToArray();
        var changed = currentByPath.Where(x => previousByPath.TryGetValue(x.Key, out var previous) && previous.Sha256 is not null && x.Value.Sha256 is not null && !string.Equals(previous.Sha256, x.Value.Sha256, StringComparison.OrdinalIgnoreCase))
            .Select(x => Item("changed", x.Key, x.Value.Name, x.Value.ExecutablePath, previousByPath[x.Key].Sha256, x.Value.Sha256)).ToArray();
        var oldPersistence = (baseline.Persistence?.Entries ?? []).Select(PersistenceIdentity).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newPersistence = (currentPersistence?.Entries ?? []).Where(x => !oldPersistence.Contains(PersistenceIdentity(x)))
            .Select(x => Item("new-persistence", PersistenceIdentity(x), x.Name, x.ResolvedPath, null, x.Sha256)).ToArray();
        return new(baselinePath, DateTimeOffset.UtcNow, added, removed, changed, newPersistence);
    }

    private static BaselineDifferenceItem Item(string category, string identity, string name, string? path, string? oldHash, string? newHash) => new(category, identity, name, path, oldHash, newHash);
    private static string Identity(ProcessObservation process) => $"{process.Name}|{AnonymizePath(process.ExecutablePath)}|{process.Sha256}";
    private static string PersistenceIdentity(PersistenceEntry entry) => $"{entry.Source}|{entry.Name}|{entry.Command}|{entry.Sha256}";

    private static SignatureStatus AggregateSignature(IEnumerable<SignatureStatus> statuses)
    {
        var values = statuses.ToArray();
        if (values.Contains(SignatureStatus.Valid)) return SignatureStatus.Valid;
        if (values.Contains(SignatureStatus.ValidButExpired)) return SignatureStatus.ValidButExpired;
        if (values.Contains(SignatureStatus.Invalid)) return SignatureStatus.Invalid;
        return SignatureStatus.Unavailable;
    }

    private static string? AnonymizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return !string.IsNullOrWhiteSpace(profile) && path.StartsWith(profile, StringComparison.OrdinalIgnoreCase)
            ? "%USERPROFILE%" + path[profile.Length..]
            : path;
    }
}
