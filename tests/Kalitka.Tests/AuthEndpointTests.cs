using System.Net;
using Xunit;

namespace Kalitka.Tests;

public class AuthEndpointTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AuthEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

    private static HttpRequestMessage Auth(string host, string? peer = null, string? xff = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/auth");
        req.Headers.Add("X-Forwarded-Host", host);
        if (peer is not null) req.Headers.Add("X-Test-Peer", peer);
        if (xff is not null) req.Headers.Add("X-Forwarded-For", xff);
        return req;
    }

    [Fact]
    public async Task Unarmed_host_passes_through()
    {
        var res = await Client().SendAsync(Auth("unarmed.example.com", peer: "10.0.0.5", xff: "203.0.113.9"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Armed_host_without_cookie_is_sent_to_the_gate()
    {
        var res = await Client().SendAsync(Auth("app.example.com", peer: "10.0.0.5", xff: "203.0.113.9"));
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Contains("gate.example.com/request", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Bypass_network_passes_when_it_comes_via_a_trusted_proxy()
    {
        // Real client is in the bypass range; it reaches us through the proxy.
        var res = await Client().SendAsync(Auth("app.example.com", peer: "10.0.0.5", xff: "192.168.1.10"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Forged_bypass_prepended_to_XFF_does_not_pass()
    {
        // Through the trusted proxy, but the caller prepended a bypass IP to
        // X-Forwarded-For. The proxy appended the real hop (203.0.113.9) on the
        // right, which is what counts — so the visitor is not bypassed and is
        // sent to the gate. Prepending a trusted-looking address buys nothing.
        var res = await Client().SendAsync(
            Auth("app.example.com", peer: "10.0.0.5", xff: "192.168.1.10, 203.0.113.9"));
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
    }
}
