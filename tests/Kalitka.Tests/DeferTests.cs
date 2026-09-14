using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The defer semantics: a request raised with <c>require_signed</c> (the iOS-shield case) can be
/// approved only by a device signature — a chat tap / session click is refused — while a denial stays
/// unsigned (fail-safe).
/// </summary>
public class DeferTests
{
    private static ApprovalEngine Engine()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var o = new GateOptions();
        var store = new InMemoryConfigStore();
        var lists = new AccessLists(Options.Create(o), NullLogger<AccessLists>.Instance, store, clock);
        return new ApprovalEngine(new NullGeoLookup(), lists, o, NullLogger<ApprovalEngine>.Instance,
            clock, new InMemoryRequestStore(), new InMemoryAuditStore(), config: store);
    }

    private static async Task<string> Defer(ApprovalEngine e)
    {
        var (state, id, _) = await e.RaiseAction("ssh:prod-01", "sergej", "203.0.113.5", "agent:shield", default,
            requireSigned: true);
        Assert.Equal("waiting", state);
        return id;
    }

    [Fact]
    public async Task An_unsigned_approval_is_refused()
    {
        var e = Engine();
        var id = await Defer(e);
        var res = await e.Decide(id, "ok", "telegram:1");   // a chat tap, no proof
        Assert.Equal(CallbackOutcome.Pending, res.Outcome);
        Assert.Equal("waiting", e.StateOf(id));             // still open
    }

    [Fact]
    public async Task A_device_signed_approval_is_accepted()
    {
        var e = Engine();
        var id = await Defer(e);
        var res = await e.Decide(id, "ok", "app:cred-1", proof: "wa1:proof-bytes");
        Assert.Equal(CallbackOutcome.Decided, res.Outcome);
        Assert.Equal("approved", e.StateOf(id));
    }

    [Fact]
    public async Task An_unsigned_denial_is_allowed()
    {
        var e = Engine();
        var id = await Defer(e);
        var res = await e.Decide(id, "no", "telegram:1");   // a deny needs no signature — fail-safe
        Assert.Equal(CallbackOutcome.Decided, res.Outcome);
        Assert.Equal("denied", e.StateOf(id));
    }
}
