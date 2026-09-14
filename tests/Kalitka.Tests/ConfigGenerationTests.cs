using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The config-cache tightening guard (audit follow-up #3). The 10s cache TTL is safe when a rule is
/// relaxed but not when it is tightened: a snapshot that has not yet seen a tightening made on
/// another instance would wrongly grant authority. The guard is asymmetric — only the direction that
/// grants authority (bypass an armed gate, honour an allow) confirms freshness via the store's
/// generation counter; the deny/enforce direction rides the slower TTL. No cluster exists today, so
/// this proves the property against a shared in-memory backend that models two instances.
/// </summary>
public class ConfigGenerationTests
{
    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(1);

    // ---- the primitive ----------------------------------------------------------

    [Fact]
    public void Within_the_window_the_snapshot_is_trusted_without_reading_the_store()
    {
        var store = new InMemoryConfigStore();
        var clock = ClockAt();
        var g = new ConfigGeneration(store, clock, Window);
        g.Mark();

        store.Mutate("k", _ => "x");   // a tightening lands, but we are still inside the window
        Assert.True(g.Fresh());        // trusted outright — the counter is not even consulted
    }

    [Fact]
    public void Past_the_window_an_unchanged_generation_is_still_fresh()
    {
        var store = new InMemoryConfigStore();
        var clock = ClockAt();
        var g = new ConfigGeneration(store, clock, Window);
        g.Mark();

        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(g.Fresh());        // nothing changed → still current, and the window re-arms
    }

    [Fact]
    public void Past_the_window_a_bumped_generation_is_stale()
    {
        var store = new InMemoryConfigStore();
        var clock = ClockAt();
        var g = new ConfigGeneration(store, clock, Window);
        g.Mark();

        store.Mutate("k", _ => "x");                 // superseded
        clock.Advance(TimeSpan.FromSeconds(2));      // past the window, so the counter is consulted
        Assert.False(g.Fresh());                     // caller must reload and re-decide
    }

    // ---- AccessLists: revoking an allow is a tightening -------------------------

    [Fact]
    public void A_revoked_allow_reaches_the_auto_permit_path_before_the_ttl()
    {
        var store = new InMemoryConfigStore();
        var clock = ClockAt();
        var o = Options.Create(new GateOptions());
        var a = new AccessLists(o, NullLogger<AccessLists>.Instance, store, clock);
        var b = new AccessLists(o, NullLogger<AccessLists>.Instance, store, clock);

        a.Add("allow", "web:*", "ip", "1.2.3.4", "now");
        clock.Advance(TimeSpan.FromSeconds(11));                 // both instances now see the allow
        Assert.True(b.IsAllowed("web:app", "1.2.3.4", ""));

        // A revokes it (a tightening). Within the TTL but past the confirm window, B must not still
        // wave the request straight through: the generation guard makes it reload and re-decide.
        a.RemoveAt("allow", 0);
        clock.Advance(TimeSpan.FromSeconds(2));                  // past the 1s window, well under the 10s TTL
        Assert.False(b.IsAllowed("web:app", "1.2.3.4", ""));
    }

    [Fact]
    public void Granting_a_new_allow_is_a_loosening_and_rides_the_ttl()
    {
        var store = new InMemoryConfigStore();
        var clock = ClockAt();
        var o = Options.Create(new GateOptions());
        var a = new AccessLists(o, NullLogger<AccessLists>.Instance, store, clock);
        var b = new AccessLists(o, NullLogger<AccessLists>.Instance, store, clock);

        a.Add("allow", "web:*", "ip", "1.2.3.4", "now");        // a loosening

        // B is on the safe (not-allowed) direction — it does not rush; the new allow arrives at the
        // TTL, not the confirm window. The extra delay only means "keep asking", which is harmless.
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.False(b.IsAllowed("web:app", "1.2.3.4", ""));
        clock.Advance(TimeSpan.FromSeconds(9));                  // past the TTL
        Assert.True(b.IsAllowed("web:app", "1.2.3.4", ""));
    }

    // ---- ApprovalEngine: arming a host is a tightening -------------------------

    private static ApprovalEngine Engine(IConfigStore store, TimeProvider clock)
    {
        var o = new GateOptions();
        var lists = new AccessLists(Options.Create(o), NullLogger<AccessLists>.Instance, store, clock);
        return new ApprovalEngine(new NullGeoLookup(), lists, o, NullLogger<ApprovalEngine>.Instance,
            clock, new InMemoryRequestStore(), new InMemoryAuditStore(), config: store);
    }

    [Fact]
    public void A_newly_armed_host_reaches_the_bypass_path_before_the_ttl()
    {
        var store = new InMemoryConfigStore();   // shared backend
        var clock = ClockAt();
        var a = Engine(store, clock);
        var b = Engine(store, clock);

        Assert.False(b.IsEnforced("host.example.com"));   // neither instance arms it yet

        a.SetEnforced("host.example.com", true);          // A arms it (a tightening)

        // B would otherwise let traffic bypass the gate for up to the TTL. Past the confirm window
        // the generation guard makes B reload before permitting, so the arming is honoured.
        clock.Advance(TimeSpan.FromSeconds(2));           // past the 1s window, well under the 10s TTL
        Assert.True(b.IsEnforced("host.example.com"));
    }

    [Fact]
    public void Disarming_a_host_is_a_loosening_and_rides_the_ttl()
    {
        var store = new InMemoryConfigStore();
        var clock = ClockAt();
        var a = Engine(store, clock);
        a.SetEnforced("host.example.com", true);
        clock.Advance(TimeSpan.FromSeconds(11));
        var b = Engine(store, clock);
        Assert.True(b.IsEnforced("host.example.com"));    // both see it armed

        a.SetEnforced("host.example.com", false);         // A disarms it (a loosening)

        // B stays on the safe (armed) side: it keeps asking for approval until the TTL, then relaxes.
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(b.IsEnforced("host.example.com"));
        clock.Advance(TimeSpan.FromSeconds(9));           // past the TTL
        Assert.False(b.IsEnforced("host.example.com"));
    }
}
