using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ProcWitness.Core;
using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class AiSettingsTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"ProcWitness-ai-{Guid.NewGuid():N}");

    [Fact]
    public async Task SettingsRoundTripWithoutSecret()
    {
        var path = Path.Combine(_directory, "settings.json");
        var store = new AppSettingsStore(path);
        var expected = new AppSettings { Language = "tr", SampleIntervalSeconds = 8, RetentionDays = 30, AiEnabled = true, AiProvider = AiProvider.OpenAI, AiModel = "model-x" };
        await store.SaveAsync(expected);
        var actual = await store.LoadAsync();
        Assert.Equal(expected, actual);
        Assert.DoesNotContain("api-key-value", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public async Task SecretIsNotStoredAsPlaintext()
    {
        const string secret = "api-key-value-123456";
        var store = new SecretStore(_directory);
        var result = await store.SaveAsync(secret);
        Assert.Equal(secret, await store.LoadAsync());
        if (result.Persisted)
            foreach (var file in Directory.EnumerateFiles(_directory)) Assert.DoesNotContain(secret, Encoding.UTF8.GetString(await File.ReadAllBytesAsync(file)));
        await store.ClearAsync();
    }

    [Fact]
    public async Task AiPayloadIsMinimizedAnonymizedAndRedacted()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var bundle = await WriteBundleAsync(new JsonObject
        {
            ["schema"] = "procwitness.analysis-bundle.v2",
            ["meta"] = new JsonObject { ["snapshotCount"] = 1 },
            ["processSummaries"] = new JsonArray(new JsonObject { ["name"] = "editor", ["executablePath"] = Path.Combine(profile, "bin", "editor"), ["commandLine"] = "editor --password hunter2" }),
            ["persistence"] = new JsonObject { ["collectedAtUtc"] = "now", ["sources"] = new JsonArray(), ["extra"] = "drop" },
            ["baselineComparison"] = new JsonObject(),
            ["snapshots"] = new JsonArray(new JsonObject { ["secret"] = "raw" }),
            ["processTree"] = new JsonArray()
        });
        var payload = await AiReportService.BuildPayloadAsync(bundle, false);
        var json = payload.ToJsonString();
        Assert.DoesNotContain("snapshots", json);
        Assert.DoesNotContain("processTree", json);
        Assert.DoesNotContain(profile, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hunter2", json);
        Assert.DoesNotContain("drop", json);
    }

    [Fact]
    public async Task ReportIsSavedAndAuthorizationIsNotInBody()
    {
        var bundle = await WriteBundleAsync(new JsonObject { ["schema"] = "v2", ["meta"] = new JsonObject(), ["processSummaries"] = new JsonArray(), ["persistence"] = new JsonObject(), ["baselineComparison"] = new JsonObject() });
        var handler = new StubHandler(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"output_text\":\"# Safe report\"}") });
        var service = new AiReportService(new HttpClient(handler));
        var result = await service.GenerateAsync(bundle, new AppSettings { AiProvider = AiProvider.OpenAI, AiEndpoint = "https://example.invalid", AiModel = "test" }, "super-secret");
        Assert.Equal("# Safe report", result.Markdown);
        Assert.True(File.Exists(result.Path));
        Assert.DoesNotContain("super-secret", handler.Body);
        Assert.Equal("Bearer", handler.AuthorizationScheme);
    }

    private async Task<string> WriteBundleAsync(JsonObject value)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, $"bundle-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, value.ToJsonString());
        return path;
    }

    public void Dispose() { try { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); } catch { } }

    private sealed class StubHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public string Body { get; private set; } = string.Empty;
        public string? AuthorizationScheme { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            AuthorizationScheme = request.Headers.Authorization?.Scheme;
            return response;
        }
    }
}
