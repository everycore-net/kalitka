using System.Net;
using Kalitka;
using Xunit;

namespace Kalitka.Tests;

public class ClientIpTests
{
    private static List<IPNetwork> Trusted(params string[] cidrs) => ClientIp.ParseNetworks(cidrs);

    [Fact]
    public void Forged_XFF_from_untrusted_peer_is_ignored()
    {
        // No trusted proxies: the header is hearsay, use the socket address.
        var r = ClientIp.Resolve("203.0.113.9", "1.2.3.4", null, Trusted());
        Assert.Equal("203.0.113.9", r.Ip);
        Assert.False(r.ForwardedHonoured);
    }

    [Fact]
    public void Untrusted_direct_client_uses_socket_address()
    {
        // Peer is not in the trusted set, so its claimed XFF means nothing.
        var r = ClientIp.Resolve("203.0.113.9", "10.9.9.9", null, Trusted("10.0.0.0/8"));
        Assert.Equal("203.0.113.9", r.Ip);
        Assert.False(r.ForwardedHonoured);
    }

    [Fact]
    public void Valid_trusted_proxy_yields_the_real_client()
    {
        // client -> proxy(10.0.0.5). XFF holds the client; peer is the proxy.
        var r = ClientIp.Resolve("10.0.0.5", "203.0.113.9", null, Trusted("10.0.0.0/8"));
        Assert.Equal("203.0.113.9", r.Ip);
        Assert.True(r.ForwardedHonoured);
    }

    [Fact]
    public void Forged_left_entries_are_skipped_behind_a_trusted_proxy()
    {
        // The caller prepended 1.1.1.1; the rightmost non-proxy hop is the truth.
        var r = ClientIp.Resolve("10.0.0.5", "1.1.1.1, 203.0.113.9", null, Trusted("10.0.0.0/8"));
        Assert.Equal("203.0.113.9", r.Ip);
    }

    [Fact]
    public void IPv4_mapped_and_port_forms_parse()
    {
        var r = ClientIp.Resolve("::ffff:10.0.0.5", "203.0.113.9:51234", null, Trusted("10.0.0.0/8"));
        Assert.Equal("203.0.113.9", r.Ip);
        Assert.True(r.ForwardedHonoured);
    }
}
