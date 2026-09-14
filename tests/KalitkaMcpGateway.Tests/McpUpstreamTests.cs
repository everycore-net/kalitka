using System.Text.Json;
using KalitkaMcpGateway;
using ModelContextProtocol.Protocol;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The real upstream adapter's job is a faithful mapping — the SDK owns the wire. These pin the
/// two mappings that matter: a tool's name + raw input schema (the gateway's contract identity),
/// and a call result's error flag + content (a missing isError is success, the MCP default).
/// </summary>
public class McpUpstreamTests
{
    [Fact]
    public void ToUpstreamTool_maps_name_and_raw_input_schema()
    {
        var schema = "{\"type\":\"object\",\"properties\":{\"vm\":{\"type\":\"string\"}}}";
        var tool = new Tool { Name = "restart_vm", InputSchema = JsonDocument.Parse(schema).RootElement };
        var u = McpUpstream.ToUpstreamTool(tool);
        Assert.Equal("restart_vm", u.Name);
        Assert.Equal(schema, u.InputSchemaJson);
    }

    [Fact]
    public void ToToolResult_maps_the_error_flag_missing_is_success()
    {
        Assert.True(McpUpstream.ToToolResult(new CallToolResult { IsError = true, Content = new List<ContentBlock>() }).IsError);
        Assert.False(McpUpstream.ToToolResult(new CallToolResult { Content = new List<ContentBlock>() }).IsError);
    }

    [Fact]
    public void ToToolResult_serializes_content_as_json()
    {
        var r = McpUpstream.ToToolResult(new CallToolResult { Content = new List<ContentBlock>() });
        Assert.Equal("[]", r.ContentJson);
    }
}
