namespace KalitkaMcpGateway;

/// <summary>A tool as the upstream MCP server advertises it: its name and its JSON-Schema
/// <c>inputSchema</c> (the real schema, not the server's self-reported version string).</summary>
public sealed record UpstreamTool(string Name, string InputSchemaJson);

/// <summary>The upstream's answer to a forwarded tool call.</summary>
public sealed record ToolResult(bool IsError, string ContentJson);

/// <summary>
/// The gateway's view of the upstream MCP server, behind a seam so the proxy orchestration is
/// testable without a live server. A real implementation (stdio/HTTP MCP client) is a later
/// slice; the security logic — fingerprint, classification, gate, at-most-once forward — lives
/// above this interface and does not depend on the transport.
/// </summary>
public interface IUpstream
{
    Task<IReadOnlyList<UpstreamTool>> ListToolsAsync(CancellationToken ct);
    Task<ToolResult> CallToolAsync(string tool, string argumentsJson, CancellationToken ct);
}
