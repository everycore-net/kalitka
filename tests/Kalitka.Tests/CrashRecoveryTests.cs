using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The Core half of crash recovery (0.23.4): the session carries the grant's
/// <c>expires_at</c>, a connector can ask a session's liveness on restart, and a
/// crash-recovery cleanup is auditable with a distinct reason — even a cleanup made
/// WITHOUT Core confirmation (orphan-max-age). This is what lets an agent revoke an
/// orphaned SQL principal on a locally-known expiry without guessing.
/// </summary>
public class CrashRecoveryTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public CrashRecoveryTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void RegisterDb(string id, string secret, string[]? resources = null) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "windows", "sql01", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { AgentCapabilities.Request, AgentCapabilities.Redeem, AgentCapabilities.SessionEnd },
            resources ?? new[] { "db:*" }, "", _f.Clock.GetUtcNow(), null, "", null));

    private static HttpRequestMessage Req(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
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
        return v.ValueKind switch { JsonValueKind.Null => null, JsonValueKind.String => v.GetString(), _ => v.GetRawText() };
    }

    private (string cookie, string csrf) Admin(string email = "admin@example.com")
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-" + email, email);
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    // request -> approve -> redeem; returns (session_id, expires_at unix seconds or null).
    private async Task<(string sid, long? exp)> Start(string agentId, string secret, string resource)
    {
        var id = Field(await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", agentId, secret,
            new() { ["resource"] = resource, ["user"] = "sergej" }))).Content.ReadAsStringAsync(), "id")!;
        var (cookie, csrf) = Admin();
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = id, ["verb"] = "ok", ["csrf"] = csrf }) };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        await Client().SendAsync(decide);
        var status = await (await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/requests/{id}", agentId, secret))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var red = await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/grants/redeem", agentId, secret,
            new() { ["grant"] = grant, ["agent"] = "sql01" }))).Content.ReadAsStringAsync();
        var exp = Field(red, "expires_at");
        return (Field(red, "session_id")!, exp is null ? null : long.Parse(exp));
    }

    [Fact]
    public async Task Redeem_returns_expires_at_and_the_session_carries_it()
    {
        RegisterDb("cr-exp", "s");
        var (sid, exp) = await Start("cr-exp", "s", "db:sql01/orders");
        Assert.NotNull(exp);

        var rec = _f.Services.GetRequiredService<ISessionStore>().Get(sid)!;
        Assert.NotNull(rec.ExpiresAt);
        Assert.Equal(exp, rec.ExpiresAt!.Value.ToUnixTimeSeconds());
        Assert.True(rec.ExpiresAt > _f.Clock.GetUtcNow());   // in the future at redeem time
    }

    [Fact]
    public async Task Liveness_reports_open_then_expired_then_unknown()
    {
        RegisterDb("cr-live", "s");
        var (sid, exp) = await Start("cr-live", "s", "db:sql01/orders");

        var open = await (await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/sessions/{sid}", "cr-live", "s"))).Content.ReadAsStringAsync();
        Assert.Equal("open", Field(open, "state"));
        Assert.Equal(exp, long.Parse(Field(open, "expires_at")!));

        // Past the grant's own expiry, liveness reads "expired" even before any sweep runs.
        _f.Clock.Advance(TimeSpan.FromSeconds(exp!.Value - _f.Clock.GetUtcNow().ToUnixTimeSeconds() + 1));
        var expired = await (await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/sessions/{sid}", "cr-live", "s"))).Content.ReadAsStringAsync();
        Assert.Equal("expired", Field(expired, "state"));

        // A session Core never knew is "unknown" (nothing to confirm against).
        var unknown = await (await Client().SendAsync(Req(HttpMethod.Get, "/agent/v1/sessions/does-not-exist", "cr-live", "s"))).Content.ReadAsStringAsync();
        Assert.Equal("unknown", Field(unknown, "state"));
    }

    [Fact]
    public async Task Liveness_of_a_session_outside_the_agent_scope_is_forbidden()
    {
        RegisterDb("cr-owner", "s", resources: new[] { "db:sql01/orders" });
        var (sid, _) = await Start("cr-owner", "s", "db:sql01/orders");

        // A different agent, scoped elsewhere, may not probe this session.
        RegisterDb("cr-other", "s2", resources: new[] { "db:sql09/other" });
        var resp = await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/sessions/{sid}", "cr-other", "s2"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Reconciled_closes_the_session_and_audits_the_reason()
    {
        RegisterDb("cr-rec", "s");
        var (sid, _) = await Start("cr-rec", "s", "db:sql01/orders");

        var resp = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/sessions/reconciled", "cr-rec", "s",
            new() { ["session_id"] = sid, ["reason"] = "local-expiry", ["principal"] = "kalitka_" + sid }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var closed = _f.Services.GetRequiredService<ISessionStore>().Get(sid)!;
        Assert.NotNull(closed.EndedAt);
        Assert.Equal("local-expiry", closed.Outcome);

        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(EventType: AuditEvents.SessionReconciled), default);
        Assert.Contains(events, e => e.Metadata.Contains(sid) && e.Metadata.Contains("local-expiry") && e.Metadata.Contains("kalitka_" + sid));
    }

    [Fact]
    public async Task Reconciled_rejects_an_unknown_reason()
    {
        RegisterDb("cr-bad", "s");
        var (sid, _) = await Start("cr-bad", "s", "db:sql01/orders");
        var resp = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/sessions/reconciled", "cr-bad", "s",
            new() { ["session_id"] = sid, ["reason"] = "because-i-said-so" }));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Orphan_max_age_cleanup_is_audited_even_for_a_session_core_forgot()
    {
        // No live session at all: an orphan whose Core session is gone must still be
        // recorded, because it is a security cleanup made without Core confirmation.
        RegisterDb("cr-orphan", "s");
        var resp = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/sessions/reconciled", "cr-orphan", "s",
            new() { ["session_id"] = "gone-session", ["reason"] = "orphan-max-age", ["principal"] = "kalitka_gone-session" }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(EventType: AuditEvents.SessionReconciled), default);
        Assert.Contains(events, e => e.Metadata.Contains("orphan-max-age") && e.Metadata.Contains("kalitka_gone-session"));
    }
}
