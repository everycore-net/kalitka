using System.Net;
using System.Text.RegularExpressions;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

public class AdminPlaneTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AdminPlaneTests(GateFactory f) => _f = f;

    // HandleCookies=false: the approved /wait/status sets the visitor session
    // cookie on Domain=.example.com, which the client's CookieContainer rejects
    // against the localhost test host. We manage the admin cookie by header, so
    // the container is not needed.
    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    // A valid admin cookie + CSRF, minted through the app's own AdminAuth (same
    // TokenSigner singleton and fake clock as the pipeline), so no OIDC needed.
    private (string cookie, string csrf) Admin()
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    private static void WithCookie(HttpRequestMessage req, string cookie) =>
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");

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
    public async Task Unauthenticated_dashboard_redirects_to_login()
    {
        var res = await Client().GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Contains("/admin/login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Login_page_offers_google_when_configured()
    {
        var res = await Client().GetAsync("/admin/login");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("Sign in with Google", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Authenticated_dashboard_renders()
    {
        var (cookie, _) = Admin();
        var req = new HttpRequestMessage(HttpMethod.Get, "/admin/dashboard");
        WithCookie(req, cookie);
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var html = await res.Content.ReadAsStringAsync();
        Assert.Contains("Overview", html);
        Assert.Contains("admin@example.com", html);
    }

    [Fact]
    public async Task Approve_from_the_web_plane_resolves_the_request()
    {
        var id = await RaiseRequest("203.0.113.40");
        var (cookie, csrf) = Admin();

        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["id"] = id, ["verb"] = "ok", ["csrf"] = csrf
            })
        };
        WithCookie(decide, cookie);
        var res = await Client().SendAsync(decide);
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);

        var status = await (await Client().GetAsync($"/wait/status?id={id}")).Content.ReadAsStringAsync();
        Assert.Contains("\"approved\"", status);
    }

    [Fact]
    public async Task Decide_without_a_valid_csrf_is_refused()
    {
        var id = await RaiseRequest("203.0.113.41");
        var (cookie, _) = Admin();

        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["id"] = id, ["verb"] = "ok", ["csrf"] = "forged"
            })
        };
        WithCookie(decide, cookie);
        var res = await Client().SendAsync(decide);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

        // and the request is still waiting
        var status = await (await Client().GetAsync($"/wait/status?id={id}")).Content.ReadAsStringAsync();
        Assert.Contains("\"waiting\"", status);
    }
}
