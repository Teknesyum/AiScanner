namespace ProcWitness.Core;

public static class PublisherTrustList
{
    private static readonly string[] TrustedPublishers =
    [
        "microsoft", "googlellc", "mozilla", "valve", "discordinc", "spotifyab", "appleinc",
        "canonical", "jetbrains", "dockerinc", "nvidia", "intel", "amd", "adobe", "zoom",
        "slacktechnologies", "github", "oracle", "dropbox", "logitech", "razer", "steelseries",
        "epicgames", "riotgames", "blizzard"
    ];

    public static bool IsTrusted(SignatureStatus status, string? publisher)
    {
        if (status is not (SignatureStatus.Valid or SignatureStatus.ValidButExpired) || string.IsNullOrWhiteSpace(publisher)) return false;
        var normalized = new string(publisher.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
        return TrustedPublishers.Any(normalized.Contains);
    }
}
