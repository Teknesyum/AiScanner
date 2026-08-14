using Xunit;
using System.Text.Json;
using ProcWitness.Infrastructure;

namespace ProcWitness.Tests;

[Collection("Console MCP")]
public sealed class McpServerTests
{
    [Fact]
    public void ToolList_ContainsOnlyReadAndCaptureOperations()
    {
        Assert.Equal(7, McpServer.ToolNames.Count);
        Assert.Contains("list_processes", McpServer.ToolNames);
        Assert.Contains("start_capture", McpServer.ToolNames);
        Assert.Contains("get_bundle", McpServer.ToolNames);
        Assert.DoesNotContain(McpServer.ToolNames, x => x.Contains("kill", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(McpServer.ToolNames, x => x.Contains("delete", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(McpServer.ToolNames, x => x.Contains("disable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task InitializeAndToolList_ReturnValidJsonRpcResponses()
    {
        var originalIn = Console.In;
        var originalOut = Console.Out;
        using var session = new CaptureSession(Path.Combine(Path.GetTempPath(), "procwitness-mcp-tests", Guid.NewGuid().ToString("N")));
        try
        {
            Console.SetIn(new StringReader("\uFEFF{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{not-json}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"));
            using var output = new StringWriter();
            Console.SetOut(output);

            Assert.Equal(0, await new McpServer(session).RunAsync());

            var responses = output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(3, responses.Length);
            using var initialize = JsonDocument.Parse(responses[0]);
            using var parseError = JsonDocument.Parse(responses[1]);
            using var tools = JsonDocument.Parse(responses[2]);
            Assert.Equal("2.0", initialize.RootElement.GetProperty("jsonrpc").GetString());
            Assert.Equal(-32700, parseError.RootElement.GetProperty("error").GetProperty("code").GetInt32());
            Assert.Equal(7, tools.RootElement.GetProperty("result").GetProperty("tools").GetArrayLength());
        }
        finally
        {
            Console.SetIn(originalIn);
            Console.SetOut(originalOut);
        }
    }
}

[CollectionDefinition("Console MCP", DisableParallelization = true)]
public sealed class ConsoleMcpCollection;
