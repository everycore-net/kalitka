using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The signed-token crypto on its own, no HTTP and no engine — sign, verify,
/// expiry, scope, rotation, and the OAuth state round-trip.
/// </summary>
public class SessionServiceTests
{
    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private static SessionService Svc(FakeTimeProvider clock, string secret = "unit-test-signing-key-0123456789")
        => new(secret, clock);

    [Fact]
    public void Host_session_is_valid_for_its_host_only()
    {
        var s = Svc(ClockAt());
        var token = s.BuildHost("app.example.com", 60);
        Assert.True(s.IsValid(token, "app.example.com"));
        Assert.False(s.IsValid(token, "other.example.com"));
    }

    [Fact]
    public void Domain_session_is_valid_for_any_host()
    {
        var s = Svc(ClockAt());
        var token = s.BuildDomain(60);
        Assert.True(s.IsValid(token, "app.example.com"));
        Assert.True(s.IsValid(token, "other.example.com"));
    }

    [Fact]
    public void Tampered_token_is_rejected()
    {
        var s = Svc(ClockAt());
        var token = s.BuildHost("app.example.com", 60);
        var tampered = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');
        Assert.False(s.IsValid(tampered, "app.example.com"));
    }

    [Fact]
    public void Expired_token_is_rejected()
    {
        var clock = ClockAt();
        var s = Svc(clock);
        var token = s.BuildHost("app.example.com", 60);
        clock.Advance(TimeSpan.FromMinutes(61));
        Assert.False(s.IsValid(token, "app.example.com"));
    }

    [Fact]
    public void Token_from_another_key_is_rejected()
    {
        var clock = ClockAt();
        var token = Svc(clock, "old-secret-aaaaaaaaaaaaaaaaaaaa").BuildHost("app.example.com", 60);
        Assert.False(Svc(clock, "new-secret-bbbbbbbbbbbbbbbbbbbb").IsValid(token, "app.example.com"));
    }

    [Fact]
    public void State_round_trips_and_rejects_tamper_and_expiry()
    {
        var clock = ClockAt();
        var s = Svc(clock);

        var state = s.BuildState("app.example.com");
        Assert.True(s.TryReadState(state, out var target));
        Assert.Equal("app.example.com", target);

        Assert.False(s.TryReadState(state[..^1] + (state[^1] == 'a' ? 'b' : 'a'), out _));

        clock.Advance(TimeSpan.FromMinutes(11));   // state lives 10 minutes
        Assert.False(s.TryReadState(state, out _));
    }
}
