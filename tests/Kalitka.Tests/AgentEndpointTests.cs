using System.Net;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The /agent endpoints an SSH host's PAM hook uses: raise a request for
/// ssh:&lt;host&gt;, poll it, and see it flip to approved once a human decides.
/// </summary>
public class AgentEndpointTests : IClassFixture<GateFactory>
{
    private const string Secret = "agent-secret";
    private readonly GateFactory _f;
    public AgentEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private async Task<(string id, string state)> Raise(string host, string user, string ip)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/agent/request")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["host"] = host, ["user"] = user, ["ip"] = ip
            })
        };
        req.Headers.Add("X-Kalitka-Agent", Secret);
        var json = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        return (root.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "", root.GetProperty("state").GetString() ?? "");
    }

    private async Task<string> Status(string id)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"/agent/status?id={id}");
        req.Headers.Add("X-Kalitka-Agent", Secret);
        var json = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("state").GetString() ?? "";
    }

    [Fact]
    public async Task Without_the_agent_secret_it_is_refused()
    {
        var res = await Client().PostAsync("/agent/request",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["host"] = "prod-01", ["user"] = "x" }));
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task The_administrative_internal_secret_is_not_accepted_on_agent()
    {
        // The split is the point: a host holding the agent secret cannot reach
        // /internal/*, and the internal secret cannot drive /agent/*.
        var req = new HttpRequestMessage(HttpMethod.Post, "/agent/request")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["host"] = "prod-01", ["user"] = "x" })
        };
        req.Headers.Add("X-Kalitka-Internal", "internal-secret");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Raise_wait_then_human_approval_flips_status()
    {
        var (id, state) = await Raise("prod-01", "sergej", "203.0.113.80");
        Assert.Equal("waiting", state);
        Assert.Equal("waiting", await Status(id));

        // A human approves through the web plane.
        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub)
            })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);

        Assert.Equal("approved", await Status(id));

        // And it was recorded against the ssh resource, not a web host.
        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(Resource: "ssh:prod-01"), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.AccessApproved && e.RequestId == id);
    }
}
