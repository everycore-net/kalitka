using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>A gate with the self-service catalogue open (Full), for the portal request flow.</summary>
public sealed class PortalFactory : GateFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Kalitka:PortalCatalogVisibility", "Full");
    }
}

/// <summary>
/// The portal request action end to end: a signed-in employee can raise a request for a unit they are
/// entitled to and shown; the CSRF token is required; and a unit they are not entitled to cannot be
/// requested even by id. The request surface is exactly the disclosure surface.
/// </summary>
public class PortalRequestTests : IClassFixture<PortalFactory>
{
    private readonly PortalFactory _f;
    public PortalRequestTests(PortalFactory f) => _f = f;

    private HttpClient Client() => _f.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = false,
    });

    // Seed a principal (linked to google:<sub>, in group "devs") and a catalogue item offered to devs.
    private async Task Seed(string sub, string itemId, string resource, string group)
    {
        using var scope = _f.Services.CreateScope();
        var principals = scope.ServiceProvider.GetRequiredService<PrincipalService>();
        var catalog = scope.ServiceProvider.GetRequiredService<CatalogService>();
        await principals.Save("emp", "Employee", new[] { $"google:{sub}" }, "admin", default, groups: new[] { "devs" });
        await catalog.Save(itemId, resource, "Dev servers", "A dev box", new[] { group }, "admin", default);
    }

    private string PortalCookie(string sub) =>
        _f.Services.GetRequiredService<PortalAuth>().IssueCookie("google", sub, "emp@example.com");

    private string Csrf() =>
        _f.Services.GetRequiredService<PortalAuth>().IssueCsrf("emp");   // bound to the principal id

    private HttpRequestMessage Post(string cookie, IDictionary<string, string> form)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/portal/request") { Content = new FormUrlEncodedContent(form) };
        req.Headers.Add("Cookie", $"{PortalAuth.CookieName}={cookie}");
        req.Headers.Add("X-Test-Peer", "10.0.0.5");
        req.Headers.Add("X-Forwarded-For", "203.0.113.7");
        return req;
    }

    [Fact]
    public async Task An_entitled_unit_can_be_requested()
    {
        await Seed("sub-a", "devbox", "ssh:dev-01", "devs");
        var res = await Client().SendAsync(Post(PortalCookie("sub-a"),
            new Dictionary<string, string> { ["csrf"] = Csrf(), ["item"] = "devbox" }));

        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("msg=requested", res.Headers.Location!.ToString());

        var gate = _f.Services.GetRequiredService<GateService>();
        Assert.Contains(gate.PendingSnapshot(), r => r.Target == "ssh:dev-01" && r.State == "waiting");
    }

    [Fact]
    public async Task A_missing_or_wrong_csrf_is_refused()
    {
        await Seed("sub-b", "devbox2", "ssh:dev-02", "devs");
        var res = await Client().SendAsync(Post(PortalCookie("sub-b"),
            new Dictionary<string, string> { ["csrf"] = "not-valid", ["item"] = "devbox2" }));
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task A_unit_the_person_is_not_entitled_to_cannot_be_requested()
    {
        // The person is in "devs"; the item is offered only to "finance" — not shown, not requestable.
        using (var scope = _f.Services.CreateScope())
        {
            var principals = scope.ServiceProvider.GetRequiredService<PrincipalService>();
            var catalog = scope.ServiceProvider.GetRequiredService<CatalogService>();
            await principals.Save("emp", "Employee", new[] { "google:sub-c" }, "admin", default, groups: new[] { "devs" });
            await catalog.Save("finbox", "ssh:fin-01", "Finance", "Finance box", new[] { "finance" }, "admin", default);
        }
        var res = await Client().SendAsync(Post(PortalCookie("sub-c"),
            new Dictionary<string, string> { ["csrf"] = Csrf(), ["item"] = "finbox" }));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("msg=not-available", res.Headers.Location!.ToString());
    }
}
