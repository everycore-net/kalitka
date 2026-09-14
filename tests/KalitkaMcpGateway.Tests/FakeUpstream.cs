using KalitkaMcpGateway;

namespace KalitkaMcpGateway.Tests;

/// <summary>An in-memory upstream: advertises a mutable tool set and records forwarded calls, so
/// the proxy orchestration is tested without a live MCP server.</summary>
public sealed class FakeUpstream : IUpstream
{
    public List<UpstreamTool> Tools { get; } = new();
    public int CallCount { get; private set; }
    public List<(string Tool, string Args)> Calls { get; } = new();
    public ToolResult NextResult { get; set; } = new(IsError: false, ContentJson: "{\"ok\":true}");
    public Exception? ThrowOnCall { get; set; }

    public Task<IReadOnlyList<UpstreamTool>> ListToolsAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<UpstreamTool>>(Tools.ToList());

    public Task<ToolResult> CallToolAsync(string tool, string argumentsJson, CancellationToken ct)
    {
        CallCount++;
        Calls.Add((tool, argumentsJson));
        if (ThrowOnCall is not null) throw ThrowOnCall;
        return Task.FromResult(NextResult);
    }
}
