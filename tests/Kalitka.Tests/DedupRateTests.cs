using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Agent-request hardening for the RDP-JIT path: repeated logon-denied events for the same person and
/// host must fold onto one pending request (dedup), and a stuck client must be throttled per-subject
/// (every user behind one agent shares that agent's IP, so a per-IP limit alone cannot).
/// </summary>
public class DedupRateTests
{
    private static ApprovalEngine Engine(int maxPerIp = 5)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var o = new GateOptions { MaxRequestsPerIp = maxPerIp, RateWindowMinutes = 10, MaxPending = 100, PendingMinutes = 5 };
        var store = new InMemoryConfigStore();
        var lists = new AccessLists(Options.Create(o), NullLogger<AccessLists>.Instance, store, clock);
        return new ApprovalEngine(new NullGeoLookup(), lists, o, NullLogger<ApprovalEngine>.Instance,
            clock, new InMemoryRequestStore(), new InMemoryAuditStore(), config: store);
    }

    private static Task<(string state, string id, PendingRequest? request)> Raise(
        ApprovalEngine e, string resource, string ip, string subjectIdentity) =>
        e.RaiseAction(resource, "anna", ip, "agent:rdp", default, subjectIdentity: subjectIdentity);

    [Fact]
    public async Task Repeated_identical_agent_requests_fold_onto_one()
    {
        var e = Engine();
        var first = await Raise(e, "rdp:WIN-01", "10.0.0.9", "sid:S-1-5-21-1");
        var again = await Raise(e, "rdp:WIN-01", "10.0.0.9", "sid:S-1-5-21-1");

        Assert.Equal("waiting", first.state);
        Assert.Equal(first.id, again.id);        // same request
        Assert.Null(again.request);              // null → the caller does not re-notify
        Assert.Equal(1, e.PendingCount());       // just one
    }

    [Fact]
    public async Task Different_subject_or_resource_is_a_distinct_request()
    {
        var e = Engine();
        await Raise(e, "rdp:WIN-01", "10.0.0.9", "sid:S-1");
        await Raise(e, "rdp:WIN-01", "10.0.0.9", "sid:S-2");   // another user
        await Raise(e, "rdp:WIN-02", "10.0.0.9", "sid:S-1");   // another host
        Assert.Equal(3, e.PendingCount());
    }

    [Fact]
    public async Task A_request_without_a_subject_identity_is_never_deduped()
    {
        var e = Engine();
        await e.RaiseAction("ssh:box", "anna", "10.0.0.9", "agent", default);
        await e.RaiseAction("ssh:box", "anna", "10.0.0.9", "agent", default);
        Assert.Equal(2, e.PendingCount());   // web/plain agent requests stay distinct
    }

    [Fact]
    public async Task Requests_that_differ_in_the_authority_do_not_fold()
    {
        // Same resource and subject, but a different command is a different authority — the fingerprint
        // keeps them apart, so an admin approves each command, not one for both.
        var e = Engine();
        await e.RaiseAction("ssh:box", "anna", "10.0.0.9", "agent", default, subjectIdentity: "sid:S-1", command: "ls");
        await e.RaiseAction("ssh:box", "anna", "10.0.0.9", "agent", default, subjectIdentity: "sid:S-1", command: "rm -rf /");
        Assert.Equal(2, e.PendingCount());
    }

    [Fact]
    public async Task A_stuck_user_is_throttled_per_subject_even_across_ips()
    {
        var e = Engine(maxPerIp: 2);
        // Distinct resources (so no dedup) and distinct IPs (so the per-IP limit never fires) — only
        // the per-subject limit can stop the third.
        Assert.Equal("waiting", (await Raise(e, "rdp:A", "1.1.1.1", "sid:S-1")).state);
        Assert.Equal("waiting", (await Raise(e, "rdp:B", "2.2.2.2", "sid:S-1")).state);
        Assert.Equal("blocked", (await Raise(e, "rdp:C", "3.3.3.3", "sid:S-1")).state);
    }

    [Fact]
    public async Task Folding_onto_a_pending_request_does_not_spend_the_rate_budget()
    {
        var e = Engine(maxPerIp: 2);
        // Same request five times: all dedup to one, none counts against the limit.
        for (var i = 0; i < 5; i++)
            Assert.Equal("waiting", (await Raise(e, "rdp:WIN-01", "10.0.0.9", "sid:S-1")).state);
        Assert.Equal(1, e.PendingCount());
    }
}
