using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The universal bounded-grant model (0.23.1, DB-agnostic): a grant carries a
/// server-side profile the connector applies, and an optional use budget. The grant
/// ends on the first of its TTL/expiry, its uses being spent, or an explicit revoke.
/// Kalitka carries the authority (profile + bounds); it holds no DB credentials.
/// </summary>
public class BoundedGrantTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public BoundedGrantTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Register(string id, string secret) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null));

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
        return v.ValueKind == JsonValueKind.Number ? v.GetRawText() : v.ValueKind == JsonValueKind.Null ? null : v.GetString();
    }

    // Raise with a profile + use budget, approve, redeem — return (session_id, profile).
    private async Task<(string sid, string profile)> StartBounded(string agentId, string secret, string host, string profile, int maxUses)
    {
        var raiseForm = new Dictionary<string, string>
        { ["host"] = host, ["user"] = "sergej", ["ip"] = "203.0.113.7", ["profile"] = profile, ["max_uses"] = maxUses.ToString() };
        var id = Field(await (await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/request", agentId, secret, raiseForm))).Content.ReadAsStringAsync(), "id")!;

        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) }) };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);

        var status = await (await Client().SendAsync(AgentReq(HttpMethod.Get, $"/agent/status?id={id}", agentId, secret))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var redeem = await (await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/redeem", agentId, secret,
            new() { ["grant"] = grant, ["agent"] = host }))).Content.ReadAsStringAsync();
        return (Field(redeem, "session_id")!, Field(redeem, "profile") ?? "");
    }

    private async Task<HttpResponseMessage> Use(string agentId, string secret, string sid) =>
        await Client().SendAsync(AgentReq(HttpMethod.Post, "/agent/v1/sessions/use", agentId, secret, new() { ["session_id"] = sid }));

    [Fact]
    public async Task Redeem_carries_the_profile_and_the_use_budget_is_spent_down()
    {
        Register("bg-uses", "s");
        var (sid, profile) = await StartBounded("bg-uses", "s", "db-01", "sql-order-correction", 2);
        Assert.Equal("sql-order-correction", profile);

        var sessions = _f.Services.GetRequiredService<ISessionStore>();
        Assert.Equal(2, sessions.Get(sid)!.RemainingUses);
        Assert.Equal("sql-order-correction", sessions.Get(sid)!.Profile);

        // Two uses spend the grant; on the second the session closes as "spent".
        Assert.Equal("1", Field(await (await Use("bg-uses", "s", sid)).Content.ReadAsStringAsync(), "remaining_uses"));
        Assert.Equal("0", Field(await (await Use("bg-uses", "s", sid)).Content.ReadAsStringAsync(), "remaining_uses"));
        Assert.Equal("spent", sessions.Get(sid)!.Outcome);
        Assert.NotNull(sessions.Get(sid)!.EndedAt);

        // A third use is refused — the session is closed.
        Assert.Equal(HttpStatusCode.Conflict, (await Use("bg-uses", "s", sid)).StatusCode);
    }

    [Fact]
    public async Task An_unbounded_grant_reports_unlimited_and_stays_open()
    {
        Register("bg-unl", "s");
        var (sid, _) = await StartBounded("bg-unl", "s", "db-02", "sql-readonly", 0);   // no use cap

        var sessions = _f.Services.GetRequiredService<ISessionStore>();
        Assert.Equal(-1, sessions.Get(sid)!.RemainingUses);

        Assert.Equal("-1", Field(await (await Use("bg-unl", "s", sid)).Content.ReadAsStringAsync(), "remaining_uses"));
        Assert.Null(sessions.Get(sid)!.EndedAt);   // unlimited use does not close it
    }
}
