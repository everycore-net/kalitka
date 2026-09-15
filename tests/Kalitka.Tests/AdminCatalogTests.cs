using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The admin surfaces that make the portal configurable: catalogue CRUD and setting a principal's
/// groups. These are the settings without which the portal shows and offers nothing.
/// </summary>
public class AdminCatalogTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AdminCatalogTests(GateFactory f) => _f = f;

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

    [Fact]
    public async Task An_admin_can_add_a_catalogue_unit()
    {
        var (cookie, csrf) = Admin();
        var res = await Post("/admin/catalog/save", cookie, new Dictionary<string, string>
        {
            ["csrf"] = csrf, ["id"] = "fin-share", ["resource"] = "share:\\\\fs01\\finance",
            ["category"] = "File shares", ["display"] = "Finance share", ["groups"] = "finance",
        });
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);

        var item = _f.Services.GetRequiredService<CatalogService>().Get("fin-share");
        Assert.NotNull(item);
        Assert.Equal("share:\\\\fs01\\finance", item!.Resource);
        Assert.Equal(new[] { "finance" }, item.Groups);
    }

    [Fact]
    public async Task Saving_a_unit_needs_a_valid_csrf()
    {
        var (cookie, _) = Admin();
        var res = await Post("/admin/catalog/save", cookie, new Dictionary<string, string>
        {
            ["csrf"] = "nope", ["id"] = "x", ["resource"] = "rdp:A", ["category"] = "c", ["display"] = "d", ["groups"] = "g",
        });
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task The_catalogue_page_requires_the_permission()
    {
        // No cookie → the guard redirects to login (not the page).
        var res = await Client().GetAsync("/admin/catalog");
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Contains("/admin/login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task An_admin_can_set_a_principals_groups()
    {
        var (cookie, csrf) = Admin();
        var res = await Post("/admin/principals/create", cookie, new Dictionary<string, string>
        {
            ["csrf"] = csrf, ["id"] = "emp1", ["display"] = "Employee One",
            ["identities"] = "google:emp1-sub", ["groups"] = "finance devs",
        });
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);

        var p = _f.Services.GetRequiredService<PrincipalService>().Get("emp1");
        Assert.NotNull(p);
        Assert.Equal(new[] { "devs", "finance" }, p!.Groups);   // normalised, sorted
    }
}
