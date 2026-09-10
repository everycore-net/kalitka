using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

public class OneTimeTokenTests
{
    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private static OneTimeTokenService Svc(FakeTimeProvider clock, string secret = "unit-test-signing-key-0123456789")
        => new(new TokenSigner(secret), clock);

    [Fact]
    public void Mint_then_read_round_trips_the_claims()
    {
        var s = Svc(ClockAt());
        var token = s.Mint("approve", "web:app.example.com", "req-1", "a", 15);

        var cap = s.Read(token);
        Assert.NotNull(cap);
        Assert.Equal("approve", cap!.Purpose);
        Assert.Equal("web:app.example.com", cap.Resource);
        Assert.Equal("req-1", cap.RequestId);
        Assert.Equal("a", cap.Action);
        Assert.Equal("ok", OneTimeTokenService.VerbFor(cap.Purpose, cap.Action));
    }

    [Fact]
    public void Tampered_token_is_rejected()
    {
        var s = Svc(ClockAt());
        var token = s.Mint("approve", "web:x", "req-1", "a", 15);
        var tampered = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');
        Assert.Null(s.Read(tampered));
    }

    [Fact]
    public void Expired_token_is_rejected()
    {
        var clock = ClockAt();
        var s = Svc(clock);
        var token = s.Mint("approve", "web:x", "req-1", "a", 15);
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Null(s.Read(token));
    }

    [Fact]
    public void Token_from_another_key_is_rejected()
    {
        var clock = ClockAt();
        var token = Svc(clock, "old-secret-aaaaaaaaaaaaaaaaaaaa").Mint("approve", "web:x", "r", "a", 15);
        Assert.Null(Svc(clock, "new-secret-bbbbbbbbbbbbbbbbbbbb").Read(token));
    }

    [Fact]
    public void Verb_resolves_only_known_actions()
    {
        Assert.Equal("ok", OneTimeTokenService.VerbFor("approve", "a"));
        Assert.Equal("no", OneTimeTokenService.VerbFor("approve", "d"));
        Assert.Null(OneTimeTokenService.VerbFor("approve", "x"));
        Assert.Null(OneTimeTokenService.VerbFor("invite", "a"));
    }
}

public class ReplayStoreTests
{
    private static DateTimeOffset Soon => DateTimeOffset.UtcNow.AddMinutes(15);

    [Fact]
    public async Task Consumes_once_then_refuses()
    {
        var store = new InMemoryReplayStore();
        Assert.True(await store.TryConsumeAsync("jti-1", Soon, default));
        Assert.False(await store.TryConsumeAsync("jti-1", Soon, default));
    }

    [Fact]
    public async Task Concurrent_consume_only_one_wins()
    {
        var store = new InMemoryReplayStore();
        var wins = 0;
        await Parallel.ForEachAsync(Enumerable.Range(0, 200), async (_, ct) =>
        {
            if (await store.TryConsumeAsync("jti-hot", Soon, ct)) Interlocked.Increment(ref wins);
        });
        Assert.Equal(1, wins);
    }
}
