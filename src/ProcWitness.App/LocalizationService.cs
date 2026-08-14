using System.Globalization;
using System.Resources;

namespace ProcWitness.App;

internal static class LocalizationService
{
    public const string TurkishName = "T\u00FCrk\u00E7e";
    private static readonly ResourceManager Resources = new("ProcWitness.App.Resources.Strings", typeof(LocalizationService).Assembly);
    private static readonly ResourceManager SettingsResources = new("ProcWitness.App.Resources.Settings", typeof(LocalizationService).Assembly);
    private static readonly IReadOnlyDictionary<string, string> KeysByEnglish = BuildEnglishIndex();

    public static string Translate(string english, bool useEnglish)
    {
        if (useEnglish || !KeysByEnglish.TryGetValue(english, out var key)) return english;
        return Resources.GetString(key, CultureInfo.GetCultureInfo("tr")) ?? SettingsResources.GetString(key, CultureInfo.GetCultureInfo("tr")) ?? english;
    }

    private static IReadOnlyDictionary<string, string> BuildEnglishIndex()
    {
        var index = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var manager in new[] { Resources, SettingsResources })
        {
            var set = manager.GetResourceSet(CultureInfo.GetCultureInfo("en"), true, true);
            if (set is null) continue;
            foreach (System.Collections.DictionaryEntry entry in set)
                if (entry.Key is string key && entry.Value is string value) index.TryAdd(value, key);
        }
        return index;
    }
}
