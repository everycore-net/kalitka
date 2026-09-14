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

        var state = s.BuildState("app.example.com", "nonce-abc");
        Assert.True(s.TryReadState(state, "nonce-abc", out var target));
        Assert.Equal("app.example.com", target);

        Assert.False(s.TryReadState(state[..^1] + (state[^1] == 'a' ? 'b' : 'a'), "nonce-abc", out _));

        clock.Advance(TimeSpan.FromMinutes(11));   // state lives 10 minutes
        Assert.False(s.TryReadState(state, "nonce-abc", out _));
    }

    [Fact]
    public void State_requires_the_matching_browser_nonce()
    {
        var clock = ClockAt();
        var s = Svc(clock);

        var state = s.BuildState("app.example.com", "nonce-abc");
        Assert.False(s.TryReadState(state, "nonce-xyz", out _));   // wrong browser
        Assert.False(s.TryReadState(state, "", out _));            // no login cookie
        Assert.True(s.TryReadState(state, "nonce-abc", out _));    // right browser
    }

    // ---- rotation overlap: previous secret accepted on verify only --------------

    private const string OldSecret = "old-secret-aaaaaaaaaaaaaaaaaaaa";
    private const string NewSecret = "new-secret-bbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void A_session_from_the_previous_key_still_verifies_during_the_overlap()
    {
        var clock = ClockAt();
        var oldToken = new SessionService(OldSecret, clock).BuildHost("app.example.com", 60);

        // new master, old kept as previous: existing sessions survive the rotation.
        var rotated = new SessionService(NewSecret, clock, previousSecret: OldSecret);
        Assert.True(rotated.IsValid(oldToken, "app.example.com"));
    }

    [Fact]
    public void A_new_session_is_signed_with_the_current_key_only()
    {
        var clock = ClockAt();
        var rotated = new SessionService(NewSecret, clock, previousSecret: OldSecret);
        var fresh = rotated.BuildHost("app.example.com", 60);

        // Signed with the new key, so it verifies under the new key with no previous set...
        Assert.True(new SessionService(NewSecret, clock).IsValid(fresh, "app.example.com"));
        // ...and not under the old key.
        Assert.False(new SessionService(OldSecret, clock).IsValid(fresh, "app.example.com"));
    }

    [Fact]
    public void Once_the_overlap_window_closes_previous_sessions_are_rejected()
    {
        var clock = ClockAt();
        var oldToken = new SessionService(OldSecret, clock).BuildHost("app.example.com", 60);

        // previous dropped: only the current key is accepted.
        Assert.False(new SessionService(NewSecret, clock).IsValid(oldToken, "app.example.com"));
    }

    [Fact]
    public void OAuth_state_from_the_previous_key_verifies_during_the_overlap()
    {
        var clock = ClockAt();
        var state = new SessionService(OldSecret, clock).BuildState("app.example.com", "nonce-abc");

        var rotated = new SessionService(NewSecret, clock, previousSecret: OldSecret);
        Assert.True(rotated.TryReadState(state, "nonce-abc", out var target));
        Assert.Equal("app.example.com", target);
    }
}
