using System.Text.Json;

namespace ProcWitness.Core;

public sealed class AiAnalysisPromptBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    public string Build(IReadOnlyCollection<ProcessAssessment> assessments, DateTimeOffset generatedAt, string? language = null)
    {
        var candidates = assessments.Where(x => x.Score > 0).OrderByDescending(x => x.Score).ThenByDescending(x => x.Process.CpuPercent).Take(35).Select(x => new
        {
            pid = x.Process.ProcessId,
            name = x.Process.Name,
            path = AnonymizePath(x.Process.ExecutablePath),
            sha256 = x.Process.Sha256,
            signatureStatus = x.Process.SignatureStatus,
            publisher = x.Process.Publisher,
            parentProcessId = x.Process.ParentProcessId,
            parentName = x.Process.ParentName,
            commandLine = x.Process.CommandLine,
            commandLineAvailable = x.Process.CommandLineAvailable,
            processTreeAvailable = x.Process.ProcessTreeAvailable,
            cpu = Math.Round(x.Process.CpuPercent, 1),
            ramMb = Math.Round(x.Process.WorkingSetBytes / 1024d / 1024d, 1),
            visible = x.Process.HasVisibleWindow,
            windowVisibilityAvailable = x.Process.WindowVisibilityAvailable,
            localScore = x.Score,
            localLevel = x.Level.ToString(),
            findings = x.Findings.Select(f => new { f.Code, f.Score, f.Explanation }),
            suppressedFindings = x.SuppressedFindings
        }).ToArray();
        var payload = new
        {
            schema = "procwitness.process-assessment.v2",
            generatedAtUtc = generatedAt.UtcDateTime,
            device = new { os = Environment.OSVersion.VersionString, logicalCpu = Environment.ProcessorCount, totalProcesses = assessments.Count, suspiciousProcesses = candidates.Length },
            candidates
        };
        return CoreLocalization.GetFor(language ?? "en", "Prompt.Instant", JsonSerializer.Serialize(payload, JsonOptions));
    }

    public string BuildForLocalBundle(string bundlePath, TimeSpan duration, int snapshots, int observations, string? language = null)
    {
        return CoreLocalization.GetFor(language ?? "en", "Prompt.Bundle", bundlePath, duration.TotalMinutes, snapshots, observations);
    }

    internal static string? AnonymizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return !string.IsNullOrWhiteSpace(userProfile) && path.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase) ? "%USERPROFILE%" + path[userProfile.Length..] : path;
    }
}
