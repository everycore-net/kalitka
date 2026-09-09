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

    // secFetch defaults to "navigate" so the common case is a document
    // navigation — the only request kind a redirect to the gate can act on.
    // The sub-resource cases pass "websocket"/"cors"/"no-cors" explicitly.
    private static HttpRequestMessage Auth(
        string host, string? peer = null, string? xff = null,
        string? secFetch = "navigate", string? accept = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/auth");
        req.Headers.Add("X-Forwarded-Host", host);
        if (peer is not null) req.Headers.Add("X-Test-Peer", peer);
        if (xff is not null) req.Headers.Add("X-Forwarded-For", xff);
        if (secFetch is not null) req.Headers.Add("Sec-Fetch-Mode", secFetch);
        if (accept is not null) req.Headers.Add("Accept", accept);
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

    [Fact]
    public async Task Auth_check_ignores_a_prepended_path_prefix()
    {
        // Envoy ext_authz prepends its path_prefix to the original request path,
        // so the check arrives as /auth/<something>. The verdict is the same —
        // an armed navigation without a cookie is still sent to the gate.
        var req = new HttpRequestMessage(HttpMethod.Get, "/auth/some/original/path");
        req.Headers.Add("X-Forwarded-Host", "app.example.com");
        req.Headers.Add("X-Test-Peer", "10.0.0.5");
        req.Headers.Add("X-Forwarded-For", "203.0.113.9");
        req.Headers.Add("Sec-Fetch-Mode", "navigate");

        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Contains("gate.example.com/request", res.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("websocket")]   // a SignalR/WebSocket handshake
    [InlineData("cors")]        // an XHR/fetch
    [InlineData("no-cors")]     // a sub-resource (script, style, image)
    public async Task Sub_resource_without_cookie_gets_401_not_a_redirect(string mode)
    {
        // A redirect to the gate's HTML is useless to these: the handshake
        // cannot follow it, the fetch would read HTML as its payload, and a
        // single-page app hangs on a blank screen. 401 lets it fail cleanly.
        var res = await Client().SendAsync(
            Auth("app.example.com", peer: "10.0.0.5", xff: "203.0.113.9", secFetch: mode));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Old_client_without_fetch_metadata_is_a_navigation_when_it_asks_for_html()
    {
        // No Sec-Fetch-* (e.g. an older browser): a document navigation still
        // advertises text/html in Accept, so it is redirected to the gate.
        var res = await Client().SendAsync(
            Auth("app.example.com", peer: "10.0.0.5", xff: "203.0.113.9",
                 secFetch: null, accept: "text/html,application/xhtml+xml"));
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
    }

    [Fact]
    public async Task Old_client_fetch_without_html_accept_gets_401()
    {
        // No Sec-Fetch-* and no text/html in Accept: an XHR from an older
        // browser. Nothing to redirect, so it is refused, not sent to the gate.
        var res = await Client().SendAsync(
            Auth("app.example.com", peer: "10.0.0.5", xff: "203.0.113.9",
                 secFetch: null, accept: "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }
}
