using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Admin RBAC: endpoints are gated on permissions, roles are permission bundles.
/// approver@ (Approver bundle) may work requests + history; agentadmin@ (AgentAdmin
/// bundle) may work agents/profiles/reconcile; admin@ (full) may do everything. The
/// permission filter is the boundary — a denied page GET redirects to the dashboard,
/// a denied mutation is 403. Nav visibility is UX only.
/// </summary>
public class RbacTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public RbacTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private string CookieFor(string email)
    {
        var auth = _f.Services.GetRequiredService<AdminAuth>();
        return auth.IssueCookie(new AdminIdentity("sub-" + email, email));
    }

    private async Task<HttpResponseMessage> Get(string email, string path)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={CookieFor(email)}");
        return await Client().SendAsync(req);
    }

    private async Task<HttpResponseMessage> Post(string email, string path)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path)
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["csrf"] = "x" }) };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={CookieFor(email)}");
        return await Client().SendAsync(req);
    }

    private static void RedirectsTo(HttpResponseMessage res, string path)
    {
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.StartsWith(path, res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Approver_can_work_requests_and_history_but_not_agents()
    {
        Assert.Equal(HttpStatusCode.OK, (await Get("approver@example.com", "/admin/requests")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Get("approver@example.com", "/admin/history")).StatusCode);
        // Denied page GET → bounced to a page they can see; mutation → hard 403.
        RedirectsTo(await Get("approver@example.com", "/admin/agents"), "/admin/dashboard");
        Assert.Equal(HttpStatusCode.Forbidden, (await Post("approver@example.com", "/admin/agents/create")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Post("approver@example.com", "/admin/reconcile/apply")).StatusCode);
    }

    [Fact]
    public async Task AgentAdmin_can_work_agents_but_not_requests()
    {
        Assert.Equal(HttpStatusCode.OK, (await Get("agentadmin@example.com", "/admin/agents")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Get("agentadmin@example.com", "/admin/profiles")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Get("agentadmin@example.com", "/admin/reconcile")).StatusCode);
        RedirectsTo(await Get("agentadmin@example.com", "/admin/requests"), "/admin/dashboard");
        RedirectsTo(await Get("agentadmin@example.com", "/admin/history"), "/admin/dashboard");
        Assert.Equal(HttpStatusCode.Forbidden, (await Post("agentadmin@example.com", "/admin/requests/decide")).StatusCode);
    }

    [Fact]
    public async Task Full_admin_reaches_everything()
    {
        foreach (var p in new[] { "/admin/requests", "/admin/history", "/admin/agents", "/admin/profiles", "/admin/reconcile", "/admin/policies" })
            Assert.Equal(HttpStatusCode.OK, (await Get("admin@example.com", p)).StatusCode);
    }

    [Fact]
    public async Task Policies_are_full_admin_only()
    {
        RedirectsTo(await Get("approver@example.com", "/admin/policies"), "/admin/dashboard");
        RedirectsTo(await Get("agentadmin@example.com", "/admin/policies"), "/admin/dashboard");
        Assert.Equal(HttpStatusCode.Forbidden, (await Post("agentadmin@example.com", "/admin/policies/create")).StatusCode);
    }

    [Fact]
    public async Task An_unlisted_account_is_not_admitted_at_all()
    {
        // A validly-signed cookie for an address on no allowlist: the guard refuses it
        // (empty permissions) and bounces to login — not to the dashboard.
        RedirectsTo(await Get("nobody@example.com", "/admin/agents"), "/admin/login");
    }

    [Fact]
    public async Task Nav_mirrors_permissions()
    {
        var approver = await (await Get("approver@example.com", "/admin/dashboard")).Content.ReadAsStringAsync();
        Assert.Contains("/admin/requests", approver);
        Assert.DoesNotContain("/admin/agents", approver);   // no Agents nav for an approver

        var agentAdmin = await (await Get("agentadmin@example.com", "/admin/dashboard")).Content.ReadAsStringAsync();
        Assert.Contains("/admin/agents", agentAdmin);
        Assert.DoesNotContain(">Requests<", agentAdmin);

        var admin = await (await Get("admin@example.com", "/admin/dashboard")).Content.ReadAsStringAsync();
        Assert.Contains("/admin/requests", admin);
        Assert.Contains("/admin/agents", admin);
    }
}
