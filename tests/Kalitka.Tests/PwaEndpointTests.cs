using System.Net;
using System.Text;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The PWA surface: public installable assets, the guarded app shell, and the push
/// subscription round-trip that binds a browser's subscription to the operator.</summary>
public class PwaEndpointTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public PwaEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private (string cookie, string csrf) AdminSession()
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    [Fact]
    public async Task The_manifest_is_public_and_declares_the_app_start_url()
    {
        var res = await Client().GetAsync("/manifest.webmanifest");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.Contains("\"start_url\":\"/admin/app\"", body);
        Assert.Contains("\"display\":\"standalone\"", body);
    }

    [Fact]
    public async Task The_service_worker_is_public_javascript()
    {
        var res = await Client().GetAsync("/sw.js");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("text/javascript", res.Content.Headers.ContentType!.MediaType);
        Assert.Contains("addEventListener('push'", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_icon_is_public_png()
    {
        var res = await Client().GetAsync("/icon.png");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("image/png", res.Content.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task The_app_shell_requires_a_session()
    {
        var res = await Client().GetAsync("/admin/app");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("/admin/login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Subscribing_stores_a_subscription_bound_to_the_operator()
    {
        var (cookie, csrf) = AdminSession();
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/app/subscribe")
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                endpoint = "https://push.example.com/send/unit-test",
                p256dh = "BExampleP256dhKeyValue",
                auth = "AuthSecretValue",
                csrf,
            }), Encoding.UTF8, "application/json"),
        };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var subs = _f.Services.GetRequiredService<PushSubscriptionStore>();
        var stored = subs.All().SingleOrDefault(s => s.Endpoint == "https://push.example.com/send/unit-test");
        Assert.NotNull(stored);
        var principals = _f.Services.GetRequiredService<PrincipalService>();
        Assert.Equal(principals.Resolve("google:sub-test"), stored!.PrincipalId);
    }
}
