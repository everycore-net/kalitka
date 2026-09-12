using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The SQL Server resource model and provisioning protocol (0.23.2). A database agent
/// raises requests for a <c>db:</c> resource (not just <c>ssh:</c>), an access policy can
/// raise the bar on a specific grant profile (e.g. four-eyes for <c>sql-dba</c>), and the
/// connector reports the provisioning outcome — applied is audited, failed closes the
/// session, because access was never really granted. Kalitka brokers authority, never
/// database credentials.
/// </summary>
public class DbResourceTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public DbResourceTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    // A DB agent, as a profile would register it: the scheme-agnostic operation
    // capabilities (request/redeem/end), scoped to db:* resources (and tagged).
    private void RegisterDb(string id, string secret, string[]? tags = null, string[]? resources = null) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "windows", "sql01", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { AgentCapabilities.Request, AgentCapabilities.Redeem, AgentCapabilities.SessionEnd },
            resources ?? new[] { "db:*" }, "", _f.Clock.GetUtcNow(), null, "", null)
        { Tags = tags ?? Array.Empty<string>() });

    private static HttpRequestMessage AgentReq(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = form is null ? null : new FormUrlEncodedContent(form) };
        req.Headers.Add("X-Kalitka-Agent-Id", id);
        req.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return req;
    }

    private static string? Field(string j, string n)
    {
        using var d = JsonDocument.Parse(j);
        if (!d.RootElement.TryGetProperty(n, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String => v.GetString(),
            _ => v.GetRawText(),   // number / true / false
        };
    }

    private (string cookie, string csrf) Admin(string email = "admin@example.com")
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-" + email, email);
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    private async Task ApproveAsAdmin(string id, string email = "admin@example.com")
    {
        var (cookie, csrf) = Admin(email);
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = id, ["verb"] = "ok", ["csrf"] = csrf }) };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        await Client().SendAsync(req);
    }

    private async Task<string> RaiseDb(string agentId, string secret, string resource, string profile = "", int maxUses = 0)
    {
        var form = new Dictionary<string, string> { ["resource"] = resource, ["user"] = "sergej", ["ip"] = "203.0.113.7" };
        if (profile.Length > 0) form["profile"] = profile;
        if (maxUses > 0) form["max_uses"] = maxUses.ToString();
        var resp = await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/requests", agentId, secret, form));
        return Field(await resp.Content.ReadAsStringAsync(), "id")!;
    }

    // Full flow to an open session on a db: resource; returns (session_id, profile).
    private async Task<(string sid, string profile)> StartDbSession(string agentId, string secret, string resource, string profile = "", int maxUses = 0)
    {
        var id = await RaiseDb(agentId, secret, resource, profile, maxUses);
        await ApproveAsAdmin(id);
        var status = await (await Client().SendAsync(AgentReq(HttpMethod.Get, $"/agent/v1/requests/{id}", agentId, secret))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var redeem = await (await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/grants/redeem", agentId, secret,
            new() { ["grant"] = grant, ["agent"] = "sql01" }))).Content.ReadAsStringAsync();
        return (Field(redeem, "session_id")!, Field(redeem, "profile") ?? "");
    }

    [Fact]
    public async Task A_db_resource_flows_all_the_way_to_a_redeemed_session()
    {
        RegisterDb("db-agent", "s");
        var (sid, profile) = await StartDbSession("db-agent", "s", "db:sql01/orders", "sql-writer");

        Assert.False(string.IsNullOrEmpty(sid));               // a grant was issued and redeemed
        Assert.Equal("sql-writer", profile);

        var session = _f.Services.GetRequiredService<ISessionStore>().Get(sid)!;
        Assert.Equal("db:sql01/orders", session.Resource);
        Assert.Equal("sql-writer", session.Profile);
    }

    [Fact]
    public async Task An_agent_may_not_raise_a_resource_outside_its_scope()
    {
        // Scoped to exactly one database — it may not speak for a different one.
        RegisterDb("db-narrow", "s", resources: new[] { "db:sql01/orders" });

        var ok = await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/requests", "db-narrow", "s",
            new() { ["resource"] = "db:sql01/orders", ["user"] = "sergej" }));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var denied = await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/requests", "db-narrow", "s",
            new() { ["resource"] = "db:sql09/secret", ["user"] = "sergej" }));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task An_ssh_only_agent_may_not_raise_a_db_resource()
    {
        // The capability, not just the resource glob, is checked: an ssh agent scoped
        // to db:* by mistake still cannot represent a db resource (no database cap).
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            "ssh-only", "ssh-only", "linux", "h", AgentStatus.Active, AgentSecrets.Hash("s"),
            new[] { "ssh" }, new[] { "db:*" }, "", _f.Clock.GetUtcNow(), null, "", null));

        var denied = await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/requests", "ssh-only", "s",
            new() { ["resource"] = "db:sql01/orders", ["user"] = "sergej" }));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task A_policy_on_the_grant_profile_raises_the_quorum()
    {
        // Four-eyes for the sql-dba profile only: two distinct approvers required.
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("dba-4eyes", "db:*", Array.Empty<string>(), 2, 0) { MatchProfile = "sql-dba" },
                "google:admin", default);
        RegisterDb("db-dba", "s");

        // A sql-dba request needs both approvers.
        var dbaId = await RaiseDb("db-dba", "s", "db:sql01/master", "sql-dba");
        await ApproveAsAdmin(dbaId, "admin@example.com");
        Assert.Equal("waiting", Field(await (await Client().SendAsync(
            AgentReq(HttpMethod.Get, $"/agent/v1/requests/{dbaId}", "db-dba", "s"))).Content.ReadAsStringAsync(), "state"));
        await ApproveAsAdmin(dbaId, "approver@example.com");
        Assert.Equal("approved", Field(await (await Client().SendAsync(
            AgentReq(HttpMethod.Get, $"/agent/v1/requests/{dbaId}", "db-dba", "s"))).Content.ReadAsStringAsync(), "state"));

        // A sql-readonly request on the same server is untouched — one approval is enough.
        var roId = await RaiseDb("db-dba", "s", "db:sql01/orders", "sql-readonly");
        await ApproveAsAdmin(roId, "admin@example.com");
        Assert.Equal("approved", Field(await (await Client().SendAsync(
            AgentReq(HttpMethod.Get, $"/agent/v1/requests/{roId}", "db-dba", "s"))).Content.ReadAsStringAsync(), "state"));
    }

    [Fact]
    public async Task Provisioning_applied_is_audited_and_leaves_the_session_open()
    {
        RegisterDb("db-prov-ok", "s");
        var (sid, _) = await StartDbSession("db-prov-ok", "s", "db:sql01/orders", "sql-writer");

        var resp = await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/sessions/provisioned", "db-prov-ok", "s",
            new() { ["session_id"] = sid }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("true", Field(await resp.Content.ReadAsStringAsync(), "provisioned"));

        var sessions = _f.Services.GetRequiredService<ISessionStore>();
        Assert.Null(sessions.Get(sid)!.EndedAt);   // provisioned, still open

        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(EventType: AuditEvents.SessionProvisioned), default);
        Assert.Contains(events, e => e.Metadata.StartsWith(sid) && e.Resource == "db:sql01/orders");
    }

    [Fact]
    public async Task Provisioning_failed_closes_the_session_as_provision_failed()
    {
        RegisterDb("db-prov-fail", "s");
        var (sid, _) = await StartDbSession("db-prov-fail", "s", "db:sql01/orders", "sql-dba");

        var resp = await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/sessions/provisioned", "db-prov-fail", "s",
            new() { ["session_id"] = sid, ["error"] = "GRANT failed: login exists" }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("false", Field(await resp.Content.ReadAsStringAsync(), "provisioned"));

        var closed = _f.Services.GetRequiredService<ISessionStore>().Get(sid)!;
        Assert.NotNull(closed.EndedAt);
        Assert.Equal("provision-failed", closed.Outcome);
    }
}
