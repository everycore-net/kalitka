using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The durable state stores: state written by one instance is seen by another on
/// the same file (the single-node "durable + shared" claim), and the atomic
/// transitions — resolve-once, grant-once, redeem-once, close-once — hold when
/// enforced by SQLite instead of a lock.
/// </summary>
public sealed class SqliteStoreTests : IDisposable
{
    private readonly string _dir;
    private readonly string _db;

    public SqliteStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "kalitka-sql-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "state.db");
    }

    public void Dispose()
    {
        try { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); Directory.Delete(_dir, true); }
        catch { /* best effort in a temp dir */ }
    }

    private static PendingRequest Req(string id, DateTimeOffset raised, string state = "waiting") => new()
    {
        Id = id, Target = "prod-01", Input = "sergej", Ip = "203.0.113.5", Resource = "ssh:prod-01",
        Country = "Germany", CountryCode = "DE", City = "Berlin", Raised = raised, State = state
    };

    // ---- Requests -----------------------------------------------------------

    [Fact]
    public void Request_survives_a_new_store_on_the_same_file()
    {
        var raised = DateTimeOffset.UtcNow;
        new SqliteRequestStore(_db).Add(Req("r1", raised));

        // A second instance — a restart, or another process — reads what the first wrote.
        var got = new SqliteRequestStore(_db).Get("r1");
        Assert.NotNull(got);
        Assert.Equal("ssh:prod-01", got!.Resource);
        Assert.Equal("sergej", got.Input);
        Assert.Equal(raised.ToUnixTimeMilliseconds(), got.Raised.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void Request_round_trips_its_covering_scope()
    {
        var r = Req("r1", DateTimeOffset.UtcNow);
        r.Scope = "rdp:site-a/*";
        new SqliteRequestStore(_db).Add(r);
        Assert.Equal("rdp:site-a/*", new SqliteRequestStore(_db).Get("r1")!.Scope);
    }

    [Fact]
    public void TryCreateOrGetPending_folds_a_second_identical_waiting_request()
    {
        var raised = DateTimeOffset.UtcNow;
        var fresh = raised.AddMinutes(-5);
        var store = new SqliteRequestStore(_db);

        var a = Req("r1", raised); a.DedupKey = "fp-1";
        var b = Req("r2", raised); b.DedupKey = "fp-1";   // same authority

        Assert.True(store.TryCreateOrGetPending(a, fresh, out var first));
        Assert.Equal("r1", first.Id);
        Assert.False(store.TryCreateOrGetPending(b, fresh, out var folded));   // folds onto the winner
        Assert.Equal("r1", folded.Id);
        Assert.Single(store.Snapshot());
    }

    [Fact]
    public void TryCreateOrGetPending_with_no_key_always_creates()
    {
        var raised = DateTimeOffset.UtcNow;
        var fresh = raised.AddMinutes(-5);
        var store = new SqliteRequestStore(_db);

        Assert.True(store.TryCreateOrGetPending(Req("r1", raised), fresh, out _));
        Assert.True(store.TryCreateOrGetPending(Req("r2", raised), fresh, out _));   // empty key never folds
        Assert.Equal(2, store.Snapshot().Count);
    }

    [Fact]
    public void Resolves_once_across_instances()
    {
        var raised = DateTimeOffset.UtcNow;
        var ok = raised.AddMinutes(-5);
        new SqliteRequestStore(_db).Add(Req("r1", raised));

        Assert.True(new SqliteRequestStore(_db).TryResolve("r1", "approved", ok, out var r));
        Assert.Equal("approved", r!.State);

        // A different instance cannot resolve it again.
        Assert.False(new SqliteRequestStore(_db).TryResolve("r1", "denied", ok, out _));
        Assert.Equal("approved", new SqliteRequestStore(_db).Get("r1")!.State);
    }

    [Fact]
    public void Too_old_is_not_resolved()
    {
        var raised = DateTimeOffset.UtcNow;
        new SqliteRequestStore(_db).Add(Req("r1", raised));
        var future = raised.AddMinutes(5);            // notOlderThan after Raised
        Assert.False(new SqliteRequestStore(_db).TryResolve("r1", "approved", future, out _));
        Assert.Equal("waiting", new SqliteRequestStore(_db).Get("r1")!.State);
    }

    [Fact]
    public void Grant_is_set_once_and_then_returned_unchanged()
    {
        var store = new SqliteRequestStore(_db);
        store.Add(Req("r1", DateTimeOffset.UtcNow));

        Assert.True(store.TrySetGrant("r1", "grant-A", out var first));
        Assert.Equal("grant-A", first);

        // A racing poll on another instance gets the same grant, not a new one.
        Assert.False(new SqliteRequestStore(_db).TrySetGrant("r1", "grant-B", out var second));
        Assert.Equal("grant-A", second);
    }

    [Fact]
    public void Grant_on_unknown_id_reports_nothing()
    {
        Assert.False(new SqliteRequestStore(_db).TrySetGrant("nope", "g", out var grant));
        Assert.Equal("", grant);
    }

    [Fact]
    public void Count_and_drop_respect_state_and_age()
    {
        var store = new SqliteRequestStore(_db);
        var now = DateTimeOffset.UtcNow;
        store.Add(Req("fresh", now));
        store.Add(Req("stale", now.AddMinutes(-30)));
        store.Add(Req("done", now, state: "approved"));

        Assert.Equal(1, store.CountWaiting(now.AddMinutes(-5)));   // only "fresh": stale too old, done not waiting

        store.DropOlderThan(now.AddMinutes(-10));
        Assert.Null(store.Get("stale"));
        Assert.NotNull(store.Get("fresh"));
        Assert.Equal(2, store.Snapshot().Count);
    }

    [Fact]
    public void Concurrent_resolve_only_one_wins()
    {
        var raised = DateTimeOffset.UtcNow;
        var ok = raised.AddMinutes(-5);
        new SqliteRequestStore(_db).Add(Req("r1", raised));

        var wins = 0;
        Parallel.For(0, 50, i =>
        {
            var state = i % 2 == 0 ? "approved" : "denied";
            if (new SqliteRequestStore(_db).TryResolve("r1", state, ok, out _)) Interlocked.Increment(ref wins);
        });

        Assert.Equal(1, wins);
        Assert.NotEqual("waiting", new SqliteRequestStore(_db).Get("r1")!.State);
    }

    // ---- Replay -------------------------------------------------------------

    [Fact]
    public async Task Jti_is_consumable_once_across_instances()
    {
        var exp = DateTimeOffset.UtcNow.AddMinutes(15);
        Assert.True(await new SqliteReplayStore(_db).TryConsumeAsync("jti-1", exp, default));
        // A different instance sees it already consumed.
        Assert.False(await new SqliteReplayStore(_db).TryConsumeAsync("jti-1", exp, default));
    }

    [Fact]
    public async Task Concurrent_consume_only_one_wins()
    {
        var store = new SqliteReplayStore(_db);
        var exp = DateTimeOffset.UtcNow.AddMinutes(15);

        var wins = 0;
        await Parallel.ForAsync(0, 50, async (_, ct) =>
        {
            if (await store.TryConsumeAsync("jti-hot", exp, ct)) Interlocked.Increment(ref wins);
        });

        Assert.Equal(1, wins);
    }

    // ---- Sessions -----------------------------------------------------------

    [Fact]
    public void Session_starts_persists_and_closes_once()
    {
        var start = DateTimeOffset.UtcNow;
        new SqliteSessionStore(_db).Start(new SessionRecord(
            "s1", "g1", "r1", "sergej", "ssh:prod-01", "linux-prod-03", start, null, "", ""));

        // Visible to another instance, still open.
        var got = new SqliteSessionStore(_db).Get("s1");
        Assert.NotNull(got);
        Assert.Null(got!.EndedAt);

        Assert.True(new SqliteSessionStore(_db).End("s1", "ok", start.AddMinutes(3)));
        Assert.False(new SqliteSessionStore(_db).End("s1", "again", start.AddMinutes(4)));   // close-once

        var closed = new SqliteSessionStore(_db).Get("s1");
        Assert.Equal("ok", closed!.Outcome);
        Assert.NotNull(closed.EndedAt);
    }

    [Fact]
    public void Ending_an_unknown_session_is_false()
    {
        Assert.False(new SqliteSessionStore(_db).End("nope", "ok", DateTimeOffset.UtcNow));
    }
}
