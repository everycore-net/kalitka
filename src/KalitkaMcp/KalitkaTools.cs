using System.ComponentModel;
using ModelContextProtocol.Server;

namespace KalitkaMcp;

/// <summary>
/// The control-plane MCP tools an AI may use to talk to Kalitka <b>itself</b>: raise an access
/// request, poll it, end a session. There is deliberately <b>no</b> <c>approve_request</c> tool —
/// a workload that could both ask for and grant access would make the human in the loop
/// decoration. Approval stays in human channels (console, Telegram, Teams, app). These tools
/// only ever <i>ask</i>; a human decides.
/// </summary>
[McpServerToolType]
public class KalitkaTools
{
    [McpServerTool(Name = "kalitka.request_access")]
    [Description("Ask a human to approve access to a resource. Returns a request id and a state that is "
        + "almost always 'waiting' — a human must approve in a Kalitka channel first. This tool NEVER "
        + "grants access itself; poll kalitka.get_request until the state is 'approved' (which yields a "
        + "one-time grant) or 'denied'. A 409 with a state like 'subject-required' means policy refused "
        + "the request up front.")]
    public static async Task<object> RequestAccess(
        CoreClient core,
        [Description("The resource to access, e.g. ssh:prod-01, db:sql01/orders, mcp:github/merge_pull_request")]
        string resource,
        [Description("Optional grant profile, e.g. sql-dba")] string? profile,
        [Description("Optional identity of the human this acts for, e.g. os:CONTOSO\\anna. Used only to route "
            + "the approval to the right person; it is treated as claimed, never trusted for self-approval.")]
        string? subjectIdentity,
        CancellationToken ct)
    {
        var r = await core.RequestAccessAsync(resource, profile, subjectIdentity, ct);
        return new { request_id = r.Id, state = r.State, refused = r.Status == 409 };
    }

    [McpServerTool(Name = "kalitka.get_request")]
    [Description("Poll a previously raised request by id. Returns its state: 'waiting' (a human has not "
        + "decided yet), 'approved' (with a one-time grant to redeem), 'denied', or 'gone'. Poll rather "
        + "than block — a human takes minutes.")]
    public static async Task<object> GetRequest(
        CoreClient core,
        [Description("The request id returned by kalitka.request_access")] string requestId,
        CancellationToken ct)
    {
        var r = await core.GetRequestAsync(requestId, ct);
        return new { state = r.State, grant = r.Grant };
    }

    [McpServerTool(Name = "kalitka.end_session")]
    [Description("End an active session early by its id, releasing the access before it would expire.")]
    public static async Task<object> EndSession(
        CoreClient core,
        [Description("The session id (from redeeming a grant)")] string sessionId,
        [Description("A short outcome note for the audit log, e.g. 'done' or 'aborted'")] string? outcome,
        CancellationToken ct)
    {
        var ok = await core.EndSessionAsync(sessionId, outcome ?? "done", ct);
        return new { ended = ok };
    }
}
