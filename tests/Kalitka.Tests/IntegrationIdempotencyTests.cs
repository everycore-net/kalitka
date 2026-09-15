using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The reserve/settle protocol that makes one ticket map to one request even under concurrent first
/// calls: a reservation is planted before the request is raised, replaced by the real id once raised,
/// and reclaimed if the reserver crashes mid-raise (stale after <see cref="IntegrationIdempotency.ReservationTtl"/>).
/// </summary>
public class IntegrationIdempotencyTests
{
    private static (IntegrationIdempotency idem, FakeTimeProvider clock) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        return (new IntegrationIdempotency(new InMemoryConfigStore(), clock), clock);
    }

    private static string Key => IntegrationIdempotency.Compose("jira", "TICKET-1");

    [Fact]
    public void A_reservation_is_not_yet_a_settled_id()
    {
        var (idem, _) = Fresh();
        Assert.True(idem.TryReserve(Key));
        Assert.Null(idem.Lookup(Key));   // reserved, but not raised — no id to hand back yet
    }

    [Fact]
    public void Record_settles_the_reservation_and_a_second_reserve_loses()
    {
        var (idem, _) = Fresh();
        Assert.True(idem.TryReserve(Key));
        idem.Record(Key, "req-1");

        Assert.Equal("req-1", idem.Lookup(Key));
        Assert.False(idem.TryReserve(Key));   // already settled — never re-claimable
    }

    [Fact]
    public void A_live_reservation_blocks_a_second_reserver()
    {
        var (idem, clock) = Fresh();
        Assert.True(idem.TryReserve(Key));

        clock.Advance(TimeSpan.FromSeconds(5));      // still within the TTL
        Assert.False(idem.TryReserve(Key));
    }

    [Fact]
    public void A_stale_reservation_is_reclaimed_so_a_dropped_request_is_retryable()
    {
        var (idem, clock) = Fresh();
        Assert.True(idem.TryReserve(Key));           // winner then "crashes" before Record

        clock.Advance(IntegrationIdempotency.ReservationTtl + TimeSpan.FromSeconds(1));
        Assert.True(idem.TryReserve(Key));           // abandoned reservation reclaimed
    }

    [Fact]
    public void Record_never_overwrites_an_id_another_caller_already_settled()
    {
        var (idem, _) = Fresh();
        idem.Record(Key, "req-first");
        idem.Record(Key, "req-second");
        Assert.Equal("req-first", idem.Lookup(Key));
    }

    [Fact]
    public void Release_drops_a_reservation_so_the_next_caller_can_claim()
    {
        var (idem, _) = Fresh();
        Assert.True(idem.TryReserve(Key));
        idem.Release(Key);
        Assert.True(idem.TryReserve(Key));   // freed, not settled
    }

    [Fact]
    public void Release_leaves_a_settled_id_intact()
    {
        var (idem, _) = Fresh();
        Assert.True(idem.TryReserve(Key));
        idem.Record(Key, "req-1");
        idem.Release(Key);                    // must not undo a real request
        Assert.Equal("req-1", idem.Lookup(Key));
    }

    [Fact]
    public async Task AwaitSettled_returns_the_id_once_recorded()
    {
        var (idem, _) = Fresh();
        Assert.True(idem.TryReserve(Key));
        idem.Record(Key, "req-1");
        Assert.Equal("req-1", await idem.AwaitSettled(Key, TimeSpan.FromSeconds(1), default));
    }

    [Fact]
    public async Task AwaitSettled_gives_up_when_nothing_settles()
    {
        var (idem, _) = Fresh();
        Assert.True(idem.TryReserve(Key));   // reserved but never recorded
        Assert.Null(await idem.AwaitSettled(Key, TimeSpan.FromMilliseconds(100), default));
    }
}
