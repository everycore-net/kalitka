using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The enrolment endpoints: admins issue invites; the public landing rejects a bad invite;
/// an invite link is produced for a valid request.</summary>
public class EnrollEndpointTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public EnrollEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private (string cookie, string csrf) AdminSession()
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    [Fact]
    public async Task Enroll_admin_page_requires_a_session()
    {
        var res = await Client().GetAsync("/admin/enroll");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("/admin/login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task An_admin_can_issue_an_invite_link()
    {
        var (cookie, csrf) = AdminSession();
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/enroll/invite")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["email"] = "newperson@example.com", ["displayName"] = "New Person", ["csrf"] = csrf,
            }),
        };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        var res = await Client().SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("/enroll?t=", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_bad_invite_link_shows_a_notice_not_a_redirect_loop()
    {
        var res = await Client().GetAsync("/enroll?t=not-a-valid-token");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("invalid or has expired", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Revoking_a_device_for_others_needs_the_csrf_token()
    {
        var (cookie, _) = AdminSession();
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/devices/remove-any")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["credentialId"] = "whatever", ["csrf"] = "wrong",
            }),
        };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }
}
