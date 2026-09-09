using System.Net;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The status-only frontend for nginx `auth_request` and friends. Same verdict
/// as /auth, but a challenge is always a 401 — never a redirect, whatever the
/// request kind — because those proxies act on the status code alone.
/// </summary>
public class AuthzEndpointTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AuthzEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

    private static HttpRequestMessage Authz(string host, string? peer = null, string? xff = null, string? secFetch = "navigate")
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/authz");
        req.Headers.Add("X-Forwarded-Host", host);
        if (peer is not null) req.Headers.Add("X-Test-Peer", peer);
        if (xff is not null) req.Headers.Add("X-Forwarded-For", xff);
        if (secFetch is not null) req.Headers.Add("Sec-Fetch-Mode", secFetch);
        return req;
    }

    [Fact]
    public async Task Unarmed_host_passes_through()
    {
        var res = await Client().SendAsync(Authz("unarmed.example.com", peer: "10.0.0.5", xff: "203.0.113.9"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Bypass_network_passes_when_it_comes_via_a_trusted_proxy()
    {
        var res = await Client().SendAsync(Authz("app.example.com", peer: "10.0.0.5", xff: "192.168.1.10"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Armed_navigation_without_cookie_is_401_not_a_redirect()
    {
        // /auth would answer a navigation with a 302; /authz never does — the
        // proxy turns the 401 into its own redirect.
        var res = await Client().SendAsync(Authz("app.example.com", peer: "10.0.0.5", xff: "203.0.113.9"));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Contains("gate.example.com/request", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Armed_sub_resource_without_cookie_is_also_401()
    {
        var res = await Client().SendAsync(
            Authz("app.example.com", peer: "10.0.0.5", xff: "203.0.113.9", secFetch: "cors"));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }
}
