using System.Text.Json;
using ProcWitness.Infrastructure;
using Xunit;

namespace ProcWitness.Tests;

public sealed class CaptureSessionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "procwitness-capture-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task HeadlessCapture_ProducesGuiCompatibleBundle()
    {
        using var session = new CaptureSession(_root) { SampleInterval = TimeSpan.FromMilliseconds(50) };

        var result = await session.CaptureAsync(TimeSpan.FromMilliseconds(150));
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(result.Path));

        Assert.Equal("procwitness.analysis-bundle.v2", document.RootElement.GetProperty("schema").GetString());
        Assert.True(document.RootElement.TryGetProperty("processSummaries", out _));
        Assert.True(document.RootElement.TryGetProperty("persistence", out _));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}
