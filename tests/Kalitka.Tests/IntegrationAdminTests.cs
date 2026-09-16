using System.Net;
using System.Text.RegularExpressions;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Admin CRUD for runtime integration keys: create (bearer token shown once, only the hash stored),
/// the created key then authenticates the request API, rotate invalidates the old token, delete closes
/// it — plus the CSRF and permission fences. Store-backed keys resolve alongside config-defined clients.
/// </summary>
public class IntegrationAdminTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public IntegrationAdminTests(GateFactory f) => _f = f;

    private HttpClient Client() => _f.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = false,
    });

    private (string cookie, string csrf) Admin()
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    private async Task<HttpResponseMessage> Post(string path, string cookie, IDictionary<string, string> form)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(form) };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        return await Client().SendAsync(req);
    }

    // The minted token is 24 random bytes hex (AgentSecrets.NewSecret): 48 uppercase hex chars.
    private static string ExtractToken(string html) => Regex.Match(html, "[0-9A-F]{48}").Value;

    private async Task<(HttpStatusCode code, string body)> Raise(string token, string resource, string subject)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/requests")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["resource"] = resource, ["subject"] = subject }) };
        req.Headers.Add("Authorization", "Bearer " + token);
        req.Headers.Add("X-Test-Peer", "10.0.0.9");
        req.Headers.Add("X-Forwarded-For", "203.0.113.20");
        var res = await Client().SendAsync(req);
        return (res.StatusCode, await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task An_admin_creates_a_key_shown_once_and_it_authenticates_the_api()
    {
        var (cookie, csrf) = Admin();
        var res = await Post("/admin/integrations/save", cookie, new Dictionary<string, string>
        {
            ["csrf"] = csrf, ["id"] = "jira-admin", ["scope"] = "rdp:*", ["rpm"] = "100",
        });
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);   // the "token shown once" page
        var token = ExtractToken(await res.Content.ReadAsStringAsync());
        Assert.NotEqual("", token);

        // The key exists, storing the hash — never the plaintext.
        var key = _f.Services.GetRequiredService<IntegrationKeyService>().Get("jira-admin");
        Assert.NotNull(key);
        Assert.NotEqual(token, key!.TokenHash);
        Assert.Contains("rdp:*", key.Scope);

        // The freshly minted token authenticates the request API for an in-scope resource.
        var (code, body) = await Raise(token, "rdp:WIN-9", "os:contoso\\zoe");
        Assert.Equal(HttpStatusCode.Accepted, code);
        Assert.Contains("\"status\":\"pending\"", body);

        // Out of scope is refused even with a valid token.
        Assert.Equal(HttpStatusCode.Forbidden, (await Raise(token, "db:secret", "os:x")).code);
    }

    [Fact]
    public async Task Rotate_mints_a_new_token_and_the_old_stops_working()
    {
        var keys = _f.Services.GetRequiredService<IntegrationKeyService>();
        var (old, err) = await keys.Save("rot-key", new[] { "rdp:*" }, 100, "admin", default);
        Assert.Null(err);
        Assert.NotNull(old);
        Assert.Equal(HttpStatusCode.Accepted, (await Raise(old!, "rdp:R1", "os:a")).code);

        var (cookie, csrf) = Admin();
        var res = await Post("/admin/integrations/rotate", cookie, new Dictionary<string, string> { ["csrf"] = csrf, ["id"] = "rot-key" });
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var fresh = ExtractToken(await res.Content.ReadAsStringAsync());
        Assert.NotEqual("", fresh);
        Assert.NotEqual(old, fresh);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Raise(old!, "rdp:R2", "os:a")).code);   // old token dead
        Assert.Equal(HttpStatusCode.Accepted, (await Raise(fresh, "rdp:R3", "os:a")).code);        // new token works
    }

    [Fact]
    public async Task Delete_closes_the_key()
    {
        var keys = _f.Services.GetRequiredService<IntegrationKeyService>();
        var (tok, _) = await keys.Save("del-key", new[] { "rdp:*" }, 100, "admin", default);
        Assert.Equal(HttpStatusCode.Accepted, (await Raise(tok!, "rdp:D1", "os:a")).code);

        var (cookie, csrf) = Admin();
        var res = await Post("/admin/integrations/delete", cookie, new Dictionary<string, string> { ["csrf"] = csrf, ["id"] = "del-key" });
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Null(keys.Get("del-key"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Raise(tok!, "rdp:D2", "os:a")).code);
    }

    [Fact]
    public async Task Save_needs_a_valid_csrf()
    {
        var (cookie, _) = Admin();
        var res = await Post("/admin/integrations/save", cookie, new Dictionary<string, string>
        {
            ["csrf"] = "nope", ["id"] = "x", ["scope"] = "rdp:*",
        });
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task The_integrations_page_requires_the_permission()
    {
        // No cookie → the guard redirects to login, not the page.
        var res = await Client().GetAsync("/admin/integrations");
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Contains("/admin/login", res.Headers.Location!.ToString());
    }
}
