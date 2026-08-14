using System.Globalization;
using System.Resources;

namespace ProcWitness.Core;

public static class CoreLocalization
{
    private static readonly ResourceManager Resources = new("ProcWitness.Core.Resources.Strings", typeof(CoreLocalization).Assembly);
    private static CultureInfo _culture = CultureInfo.GetCultureInfo("en");
    public static string Language => _culture.TwoLetterISOLanguageName;

    public static void SetLanguage(string? language)
    {
        var selected = language?.ToLowerInvariant() switch
        {
            "tr" or "türkçe" => "tr",
            "en" or "english" => "en",
            _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "tr" ? "tr" : "en"
        };
        _culture = CultureInfo.GetCultureInfo(selected);
    }

    public static string Get(string key, params object?[] arguments)
    {
        var value = Resources.GetString(key, _culture) ?? Resources.GetString(key, CultureInfo.GetCultureInfo("en")) ?? key;
        return arguments.Length == 0 ? value : string.Format(_culture, value, arguments);
    }

    public static string GetFor(string? language, string key, params object?[] arguments)
    {
        var culture = CultureInfo.GetCultureInfo(language?.StartsWith("tr", StringComparison.OrdinalIgnoreCase) == true ? "tr" : "en");
        var value = Resources.GetString(key, culture) ?? Resources.GetString(key, CultureInfo.GetCultureInfo("en")) ?? key;
        return arguments.Length == 0 ? value : string.Format(culture, value, arguments);
    }
}
