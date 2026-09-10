using System.Net;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The full SSH grant lifecycle: approval issues a one-time grant, the agent
/// redeems it once to start a session, a second redeem is refused, and the agent
/// closes the session — with grant.* / session.* recorded.
/// </summary>
public class GrantFlowTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public GrantFlowTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private HttpRequestMessage Agent(HttpMethod m, string url, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url);
        if (form is not null) req.Content = new FormUrlEncodedContent(form);
        req.Headers.Add("X-Kalitka-Agent", "agent-secret");
        return req;
    }

    private static string? Field(string json, string name)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null
            ? v.GetString() : null;
    }

    [Fact]
    public async Task Approval_issues_a_one_time_grant_that_starts_and_ends_a_session()
    {
        // Raise an SSH request via the agent.
        var raise = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request",
            new() { ["host"] = "prod-01", ["user"] = "sergej", ["ip"] = "203.0.113.90" }));
        var id = Field(await raise.Content.ReadAsStringAsync(), "id")!;

        // A human approves through the web plane.
        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);

        // Status now carries a one-time grant.
        var status = await (await Client().SendAsync(Agent(HttpMethod.Get, $"/agent/status?id={id}"))).Content.ReadAsStringAsync();
        Assert.Equal("approved", Field(status, "state"));
        var grant = Field(status, "grant");
        Assert.False(string.IsNullOrEmpty(grant));

        // Redeem it → a session starts.
        var redeem = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant!, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.OK, redeem.StatusCode);
        var sessionId = Field(await redeem.Content.ReadAsStringAsync(), "session_id")!;
        Assert.False(string.IsNullOrEmpty(sessionId));

        // The same grant cannot be redeemed twice.
        var again = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant!, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        // Close the session.
        var end = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/session/end",
            new() { ["session_id"] = sessionId, ["outcome"] = "ok" }));
        Assert.Equal(HttpStatusCode.OK, end.StatusCode);

        // The lifecycle is in the audit log, resource-scoped to the SSH host.
        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(Resource: "ssh:prod-01"), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.GrantRedeemed && e.RequestId == id);
        Assert.Contains(events, e => e.EventType == AuditEvents.SessionStarted);
        Assert.Contains(events, e => e.EventType == AuditEvents.SessionEnded);
    }
}
