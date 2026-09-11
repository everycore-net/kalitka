using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The geo seam: the no-op provider, and the on-box MaxMind provider against a real
/// (synthetic) .mmdb. The HTTP provider is exercised indirectly elsewhere (tests run
/// with GeoUrl empty so nothing hits the network).
/// </summary>
public class GeoLookupTests
{
    private static string Db => Path.Combine(AppContext.BaseDirectory, "testdata", "GeoIP2-City-Test.mmdb");

    [Fact]
    public async Task Null_provider_is_always_unknown()
    {
        var p = await new NullGeoLookup().Locate("81.2.69.142", default);
        Assert.False(p.IsKnown);
        Assert.Equal(Place.Unknown, p);
    }

    [Fact]
    public async Task MaxMind_resolves_a_known_ip_on_the_box()
    {
        using var geo = new MaxMindGeoLookup(Db, NullLogger<MaxMindGeoLookup>.Instance);
        var p = await geo.Locate("81.2.69.142", default);
        Assert.True(p.IsKnown);
        Assert.Equal("GB", p.CountryCode);
    }

    [Fact]
    public async Task MaxMind_skips_private_and_absent_addresses()
    {
        using var geo = new MaxMindGeoLookup(Db, NullLogger<MaxMindGeoLookup>.Instance);
        Assert.False((await geo.Locate("10.0.0.5", default)).IsKnown);       // private → skipped, no read
        Assert.False((await geo.Locate("203.0.113.7", default)).IsKnown);    // public but not in the db
        Assert.False((await geo.Locate("", default)).IsKnown);
        Assert.False((await geo.Locate("not-an-ip", default)).IsKnown);
    }

    [Fact]
    public void MaxMind_missing_file_throws_so_DI_falls_back()
    {
        // The DI factory guards with File.Exists and falls back; the reader itself
        // throwing on a bad path is the behaviour that guard relies on.
        Assert.ThrowsAny<Exception>(() =>
            new MaxMindGeoLookup(Path.Combine(AppContext.BaseDirectory, "does-not-exist.mmdb"),
                NullLogger<MaxMindGeoLookup>.Instance));
    }
}
