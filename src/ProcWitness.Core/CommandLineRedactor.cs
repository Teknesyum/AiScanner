using System.Text.RegularExpressions;

namespace ProcWitness.Core;

public static partial class CommandLineRedactor
{
    public static string? Redact(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return commandLine;
        var redacted = AssignmentSecret().Replace(commandLine, "$1***");
        redacted = SpaceSecret().Replace(redacted, "$1***");
        redacted = BearerSecret().Replace(redacted, "$1***");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return !string.IsNullOrWhiteSpace(profile)
            ? redacted.Replace(profile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase)
            : redacted;
    }

    [GeneratedRegex("""(?i)((?:--?(?:password|token)|apikey)\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s]+)""")]
    private static partial Regex AssignmentSecret();

    [GeneratedRegex("""(?i)((?:^|\s)(?:-p|--?(?:password|token)|apikey)\s+)(?:"[^"]*"|'[^']*'|[^\s]+)""")]
    private static partial Regex SpaceSecret();

    [GeneratedRegex(@"(?i)(Bearer\s+)[A-Za-z0-9._~+\-/=]+")]
    private static partial Regex BearerSecret();
}
