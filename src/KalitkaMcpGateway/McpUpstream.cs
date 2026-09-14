using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KalitkaMcpGateway;

/// <summary>
/// A real upstream MCP server behind <see cref="IUpstream"/>, using the official MCP client SDK.
/// The SDK owns the wire (stdio / HTTP, initialize, pagination); this adapter only maps the SDK's
/// tool/result shapes to the gateway's, so the security logic above stays transport-agnostic. The
/// discovery step (<see cref="ListToolsAsync"/>) is separable from execution
/// (<see cref="CallToolAsync"/>): a gateway can inventory + classify tools before the first real
/// <c>tools/call</c> ever flows through fingerprint → renderer → Core approval → durable claim.
/// </summary>
public sealed class McpUpstream : IUpstream, IAsyncDisposable
{
    private readonly McpClient _client;

    public McpUpstream(McpClient client) => _client = client;

    /// <summary>Connect to an upstream MCP server launched as a local process (stdio). The command
    /// and arguments are the server's launch line.</summary>
    public static async Task<McpUpstream> ConnectStdioAsync(string name, string command, IList<string>? arguments, CancellationToken ct)
    {
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = name,
            Command = command,
            Arguments = arguments,
        });
        return new McpUpstream(await McpClient.CreateAsync(transport, cancellationToken: ct));
    }

    public async Task<IReadOnlyList<UpstreamTool>> ListToolsAsync(CancellationToken ct)
    {
        var tools = await _client.ListToolsAsync(cancellationToken: ct);
        return tools.Select(t => ToUpstreamTool(t.ProtocolTool)).ToList();
    }

    public async Task<ToolResult> CallToolAsync(string tool, string argumentsJson, CancellationToken ct)
    {
        var args = JsonSerializer.Deserialize<Dictionary<string, object?>>(argumentsJson) ?? new();
        var result = await _client.CallToolAsync(tool, args, cancellationToken: ct);
        return ToToolResult(result);
    }

    public ValueTask DisposeAsync() => _client.DisposeAsync();

    // ---- pure mapping (unit-tested) -------------------------------------------

    /// <summary>Map an MCP protocol tool to the gateway's view: its name and the raw JSON of its
    /// input schema (the real schema, the gateway's contract identity).</summary>
    public static UpstreamTool ToUpstreamTool(Tool tool) =>
        new(tool.Name, tool.InputSchema.GetRawText());

    /// <summary>Map an MCP call result to the gateway's: a definite error flag and the content as
    /// JSON. A missing <c>isError</c> is treated as success (the MCP default).</summary>
    public static ToolResult ToToolResult(CallToolResult result) =>
        new(result.IsError ?? false, JsonSerializer.Serialize(result.Content));
}
