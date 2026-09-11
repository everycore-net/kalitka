using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Kalitka;

/// <summary>
/// The admin control plane is permission-based, not role-checked: every endpoint
/// requires a fine-grained permission, and roles are only convenient bundles of
/// permissions. New capabilities (e.g. a future policy/config surface) add a new
/// permission and a bundle without touching the auth model.
/// </summary>
public static class Perm
{
    public const string RequestsRead    = "requests.read";
    public const string RequestsDecide  = "requests.decide";
    public const string HistoryRead     = "history.read";
    public const string AgentsRead      = "agents.read";
    public const string AgentsManage    = "agents.manage";
    public const string ProfilesManage  = "profiles.manage";
    public const string EnrollmentManage = "enrollment.manage";
    public const string PoliciesRead    = "policies.read";
    public const string PoliciesManage  = "policies.manage";

    /// <summary>Read/approve/deny access requests + read history.</summary>
    public static readonly IReadOnlySet<string> Approver =
        new HashSet<string> { RequestsRead, RequestsDecide, HistoryRead };

    /// <summary>Manage agents, profiles, enrollment and reconciliation.</summary>
    public static readonly IReadOnlySet<string> AgentAdmin =
        new HashSet<string> { AgentsRead, AgentsManage, ProfilesManage, EnrollmentManage };

    /// <summary>Read and manage access policies.</summary>
    public static readonly IReadOnlySet<string> PolicyAdmin =
        new HashSet<string> { PoliciesRead, PoliciesManage };

    /// <summary>Full admin — every permission there is.</summary>
    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(Approver.Concat(AgentAdmin).Concat(PolicyAdmin));
}

public static class AdminRouting
{
    /// <summary>
    /// Gate an endpoint on a permission. Runs after the group's auth filter (which
    /// stashes the request-scoped <see cref="AdminIdentity"/> with its freshly
    /// resolved permissions). A missing permission is a hard boundary: a mutating
    /// request gets 403; a page GET is redirected to the dashboard (which every admin
    /// can see) rather than showing an ugly 403. Hidden nav is UX; this is the fence.
    /// </summary>
    public static RouteHandlerBuilder RequirePermission(this RouteHandlerBuilder builder, string permission) =>
        builder.AddEndpointFilter(async (ctx, next) =>
        {
            var who = ctx.HttpContext.Items["admin"] as AdminIdentity;
            if (who is null || !who.Can(permission))
                return HttpMethods.IsGet(ctx.HttpContext.Request.Method)
                    ? Results.Redirect("/admin/dashboard", false)
                    : Results.StatusCode(403);
            return await next(ctx);
        });
}
