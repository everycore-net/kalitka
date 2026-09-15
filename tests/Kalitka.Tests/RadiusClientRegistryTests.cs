using System.Net;
using Kalitka;
using Microsoft.Extensions.Options;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The RADIUS client registry: a datagram source is matched to a client (exact IP or CIDR, most
/// specific wins), each with its own secret and resource. An unknown source matches nothing, and a
/// legacy single-secret config still resolves via a synthesised catch-all.
/// </summary>
public class RadiusClientRegistryTests
{
    private static RadiusClientRegistry Registry(GateOptions o) => new(Options.Create(o));

    [Fact]
    public void Matches_an_exact_source_and_carries_its_resource()
    {
        var reg = Registry(new GateOptions
        {
            RadiusClients =
            {
                new RadiusClientOptions { Source = "10.0.0.10", Secret = "s1", Resource = "rdp:rdgw-prod" },
                new RadiusClientOptions { Source = "10.0.0.20", Secret = "s2", Resource = "vpn:office" },
            },
        });
        Assert.Equal("rdp:rdgw-prod", reg.Match(IPAddress.Parse("10.0.0.10"))?.Resource);
        Assert.Equal("vpn:office", reg.Match(IPAddress.Parse("10.0.0.20"))?.Resource);
        Assert.Null(reg.Match(IPAddress.Parse("10.0.0.99")));   // unknown source
    }

    [Fact]
    public void Matches_a_cidr_range()
    {
        var reg = Registry(new GateOptions
        {
            RadiusClients = { new RadiusClientOptions { Source = "10.1.0.0/16", Secret = "s", Resource = "network:wifi" } },
        });
        Assert.Equal("network:wifi", reg.Match(IPAddress.Parse("10.1.5.7"))?.Resource);
        Assert.Null(reg.Match(IPAddress.Parse("10.2.5.7")));    // outside the range
    }

    [Fact]
    public void The_most_specific_match_wins()
    {
        var reg = Registry(new GateOptions
        {
            RadiusClients =
            {
                new RadiusClientOptions { Source = "10.0.0.0/8", Secret = "broad", Resource = "network:site" },
                new RadiusClientOptions { Source = "10.0.0.10", Secret = "exact", Resource = "rdp:rdgw" },
            },
        });
        Assert.Equal("rdp:rdgw", reg.Match(IPAddress.Parse("10.0.0.10"))?.Resource);   // exact beats the /8
        Assert.Equal("network:site", reg.Match(IPAddress.Parse("10.9.9.9"))?.Resource);
    }

    [Fact]
    public void A_legacy_single_secret_synthesises_a_catch_all_client()
    {
        var reg = Registry(new GateOptions { RadiusSharedSecret = "legacy", RadiusResource = "rdp:gateway" });
        var c = reg.Match(IPAddress.Parse("203.0.113.9"));
        Assert.NotNull(c);
        Assert.Equal("legacy", c!.Secret);
        Assert.Equal("rdp:gateway", c.Resource);
    }

    [Fact]
    public void Nothing_configured_matches_nothing()
    {
        var reg = Registry(new GateOptions());
        Assert.False(reg.HasAny);
        Assert.Null(reg.Match(IPAddress.Parse("10.0.0.1")));
    }
}
