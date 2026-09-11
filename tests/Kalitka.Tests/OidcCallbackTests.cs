using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The admin OIDC callback end to end, with a stubbed identity (no Google network).
/// This is the flow the direct-cookie admin tests skip — it guards the exact
/// login-loop regression: the admin cookie must be SameSite=Lax (not Strict), so it
/// survives the cross-site redirect back from Google. Also checks the state-nonce.
/// </summary>
public class OidcCallbackTests : IClassFixture<OidcCallbackTests.OidcFactory>
{
    private readonly OidcFactory _f;
    public OidcCallbackTests(OidcFactory f) => _f = f;

    // A GoogleAuth that resolves a fixed, allow-listed admin identity without a network call.
    private sealed class StubGoogle : GoogleAuth
    {
        public StubGoogle(IOptions<GateOptions> opts) : base(new HttpClient(), opts, NullLogger<GoogleAuth>.Instance) { }
        public override Task<(string Email, string Sub)?> ResolveIdentity(string code, string redirectUri, CancellationToken ct)
            => Task.FromResult<(string Email, string Sub)?>(("admin@example.com", "sub-admin"));
    }

    public sealed class OidcFactory : GateFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<GoogleAuth>();
                services.AddSingleton<GoogleAuth>(sp => new StubGoogle(sp.GetRequiredService<IOptions<GateOptions>>()));
            });
        }
    }

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private static string CookieValue(HttpResponseMessage res, string name)
    {
        foreach (var c in res.Headers.GetValues("Set-Cookie"))
            if (c.StartsWith(name + "=", StringComparison.Ordinal))
                return c[(name.Length + 1)..c.IndexOf(';')];
        return "";
    }

    private static string SetCookie(HttpResponseMessage res, string name) =>
        res.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(name + "=", StringComparison.Ordinal));

    private static string StateParam(string url)
    {
        var start = url.IndexOf("state=", StringComparison.Ordinal) + "state=".Length;
        var end = url.IndexOf('&', start);
        return Uri.UnescapeDataString(end < 0 ? url[start..] : url[start..end]);
    }

    [Fact]
    public async Task Admin_callback_sets_a_lax_cookie_and_lands_in_the_console()
    {
        // 1. Start login: gives us the state (in the Google URL) and the nonce cookie.
        var start = await Client().GetAsync("/admin/login/google?return=/admin/dashboard");
        Assert.Equal(HttpStatusCode.Found, start.StatusCode);
        var state = StateParam(start.Headers.Location!.ToString());
        var nonce = CookieValue(start, "kalitka_admin_state");
        Assert.NotEqual("", nonce);

        // 2. Google redirects back to the callback; the browser carries the nonce cookie.
        var cb = new HttpRequestMessage(HttpMethod.Get, $"/admin/oauth2/callback?code=x&state={Uri.EscapeDataString(state)}");
        cb.Headers.Add("Cookie", $"kalitka_admin_state={nonce}");
        var res = await Client().SendAsync(cb);

        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Equal("/admin/dashboard", res.Headers.Location!.ToString());

        var adminCookie = SetCookie(res, AdminAuth.CookieName).ToLowerInvariant();
        Assert.Contains("samesite=lax", adminCookie);   // the regression guard: NOT Strict
        Assert.Contains("secure", adminCookie);
        Assert.Contains("httponly", adminCookie);
        Assert.Contains("path=/admin", adminCookie);
    }

    [Fact]
    public async Task Admin_callback_without_the_nonce_cookie_is_refused()
    {
        var start = await Client().GetAsync("/admin/login/google?return=/admin/dashboard");
        var state = StateParam(start.Headers.Location!.ToString());

        // No kalitka_admin_state cookie on the callback → login-CSRF defence trips.
        var cb = new HttpRequestMessage(HttpMethod.Get, $"/admin/oauth2/callback?code=x&state={Uri.EscapeDataString(state)}");
        var res = await Client().SendAsync(cb);

        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.StartsWith("/admin/login", res.Headers.Location!.ToString());   // bounced, not signed in
    }
}
