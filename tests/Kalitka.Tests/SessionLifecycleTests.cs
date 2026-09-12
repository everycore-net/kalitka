using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// SSH session correctness (0.22): a session can be revoked out of band by an admin,
/// and a session left open past its max lifetime is auto-closed as <c>expired</c> — so
/// a crashed or missed close hook never leaks a permanently-open session. Its own
/// fixture, because one test advances the clock.
/// </summary>
public class SessionLifecycleTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public SessionLifecycleTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Register(string id, string secret) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null));

    private static HttpRequestMessage Agent(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = form is null ? null : new FormUrlEncodedContent(form) };
        req.Headers.Add("X-Kalitka-Agent-Id", id);
        req.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return req;
    }

    private static string? Field(string j, string n)
    {
        using var d = JsonDocument.Parse(j);
        return d.RootElement.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
    }

    private (string cookie, string csrf) Admin(string email = "admin@example.com")
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-" + email, email);
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    // Full flow: agent raises → admin approves → agent redeems → returns the session id.
    private async Task<string> StartSession(string agentId, string secret, string host)
    {
        var id = Field(await (await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request", agentId, secret,
            new() { ["host"] = host, ["user"] = "sergej", ["ip"] = "203.0.113.7" }))).Content.ReadAsStringAsync(), "id")!;

        var (cookie, csrf) = Admin();
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = id, ["verb"] = "ok", ["csrf"] = csrf }) };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        await Client().SendAsync(decide);

        var status = await (await Client().SendAsync(Agent(HttpMethod.Get, $"/agent/status?id={id}", agentId, secret))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var redeem = await (await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem", agentId, secret,
            new() { ["grant"] = grant, ["agent"] = host }))).Content.ReadAsStringAsync();
        return Field(redeem, "session_id")!;
    }

    [Fact]
    public async Task Admin_can_revoke_an_open_session()
    {
        Register("sess-rev", "s");
        var sid = await StartSession("sess-rev", "s", "rev-01");
        var sessions = _f.Services.GetRequiredService<ISessionStore>();
        Assert.Null(sessions.Get(sid)!.EndedAt);   // open

        var (cookie, csrf) = Admin();
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/sessions/revoke")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = sid, ["csrf"] = csrf }) };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        Assert.Equal(HttpStatusCode.Found, (await Client().SendAsync(req)).StatusCode);

        var closed = sessions.Get(sid)!;
        Assert.NotNull(closed.EndedAt);
        Assert.Equal("revoked", closed.Outcome);
    }

    [Fact]
    public async Task A_session_left_open_past_its_max_lifetime_is_auto_expired()
    {
        Register("sess-exp", "s");
        var sid = await StartSession("sess-exp", "s", "exp-01");
        var sessions = _f.Services.GetRequiredService<ISessionStore>();
        Assert.Null(sessions.Get(sid)!.EndedAt);

        _f.Clock.Advance(TimeSpan.FromHours(25));   // past the 24h default

        // Viewing the sessions page runs the sweep.
        var (cookie, _) = Admin();
        var view = new HttpRequestMessage(HttpMethod.Get, "/admin/sessions");
        view.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        Assert.Equal(HttpStatusCode.OK, (await Client().SendAsync(view)).StatusCode);

        var expired = sessions.Get(sid)!;
        Assert.NotNull(expired.EndedAt);
        Assert.Equal("expired", expired.Outcome);
    }

    [Fact]
    public async Task Sessions_view_needs_requests_read_and_revoke_needs_requests_decide()
    {
        // AgentAdmin has neither requests.read nor requests.decide.
        var (cookie, csrf) = Admin("agentadmin@example.com");
        var view = new HttpRequestMessage(HttpMethod.Get, "/admin/sessions");
        view.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        var vr = await Client().SendAsync(view);
        Assert.Equal(HttpStatusCode.Found, vr.StatusCode);
        Assert.StartsWith("/admin/dashboard", vr.Headers.Location!.ToString());   // bounced

        var rev = new HttpRequestMessage(HttpMethod.Post, "/admin/sessions/revoke")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = "x", ["csrf"] = csrf }) };
        rev.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        Assert.Equal(HttpStatusCode.Forbidden, (await Client().SendAsync(rev)).StatusCode);
    }
}
