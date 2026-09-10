using System.Text.RegularExpressions;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The request lifecycle is recorded to the audit store end to end.</summary>
public class AuditFlowTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AuditFlowTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private async Task<string> RaiseRequest(string clientIp)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/request")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["target"] = "app.example.com",
                ["input"] = "someone@example.com"
            })
        };
        req.Headers.Add("X-Test-Peer", "10.0.0.5");
        req.Headers.Add("X-Forwarded-For", clientIp);
        var html = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();
        return Regex.Match(html, "var id=\"([0-9A-Fa-f]+)\"").Groups[1].Value;
    }

    [Fact]
    public async Task Request_then_web_approval_are_both_recorded()
    {
        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var id = await RaiseRequest("203.0.113.70");

        var afterRequest = await audit.Query(new AuditQuery(), default);
        Assert.Contains(afterRequest, e =>
            e.EventType == AuditEvents.AccessRequested && e.RequestId == id && e.Resource == "web:app.example.com");

        // Approve through the web plane.
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["id"] = id, ["verb"] = "ok", ["csrf"] = a.IssueCsrf(who.Sub)
            })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={a.IssueCookie(who)}");
        await Client().SendAsync(decide);

        var afterApprove = await audit.Query(new AuditQuery(EventType: AuditEvents.AccessApproved), default);
        Assert.Contains(afterApprove, e => e.RequestId == id && e.Actor == "google:sub-test");
    }
}
