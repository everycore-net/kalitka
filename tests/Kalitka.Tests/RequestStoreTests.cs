using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The in-memory request store, and above all its atomic resolve-once.</summary>
public class RequestStoreTests
{
    private static (InMemoryRequestStore store, DateTimeOffset ok) Fresh(string id = "r1")
    {
        var store = new InMemoryRequestStore();
        var raised = DateTimeOffset.UtcNow;
        store.Add(new PendingRequest { Id = id, Target = "app", Input = "x", Ip = "1.2.3.4", Raised = raised, State = "waiting" });
        return (store, raised.AddMinutes(-5));   // notOlderThan well before Raised
    }

    [Fact]
    public void Resolves_once_then_refuses()
    {
        var (store, ok) = Fresh();

        Assert.True(store.TryResolve("r1", "approved", ok, out var r));
        Assert.Equal("approved", r!.State);

        Assert.False(store.TryResolve("r1", "denied", ok, out _));   // already resolved
        Assert.Equal("approved", store.Get("r1")!.State);            // not flipped
    }

    [Fact]
    public void Too_old_is_not_resolved()
    {
        var (store, _) = Fresh();
        var future = DateTimeOffset.UtcNow.AddMinutes(5);            // notOlderThan after Raised
        Assert.False(store.TryResolve("r1", "approved", future, out _));
        Assert.Equal("waiting", store.Get("r1")!.State);
    }

    [Fact]
    public void Unknown_id_is_not_resolved()
    {
        var (store, ok) = Fresh();
        Assert.False(store.TryResolve("nope", "approved", ok, out _));
    }

    [Fact]
    public void Concurrent_approve_and_deny_only_one_wins()
    {
        var (store, ok) = Fresh();

        var wins = 0;
        Parallel.For(0, 200, i =>
        {
            var state = i % 2 == 0 ? "approved" : "denied";
            if (store.TryResolve("r1", state, ok, out _)) Interlocked.Increment(ref wins);
        });

        Assert.Equal(1, wins);                                       // exactly one transition
        Assert.NotEqual("waiting", store.Get("r1")!.State);         // and it stuck
    }
}
