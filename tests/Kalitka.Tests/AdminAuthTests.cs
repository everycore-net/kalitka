using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The allowlist rules, the admin session cookie, and CSRF — no network.</summary>
public class AdminAuthTests
{
    private static AdminAuth Auth(FakeTimeProvider clock, string[]? emails = null, string[]? domains = null,
        string secret = "unit-test-signing-key-0123456789")
    {
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = secret,
            GateHost = "gate.example.com",
            GoogleClientId = "cid",
            GoogleClientSecret = "csecret",
            AdminEmails = emails ?? Array.Empty<string>(),
            AdminDomains = domains ?? Array.Empty<string>(),
            AdminSessionMinutes = 480,
        });
        var google = new GoogleAuth(new HttpClient(), opts, NullLogger<GoogleAuth>.Instance);
        return new AdminAuth(google, new TokenSigner(secret), opts, clock);
    }

    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));

    [Fact]
    public void Neither_list_means_fail_closed()
    {
        var a = Auth(ClockAt());
        Assert.False(a.Enabled);
        Assert.False(a.IsPermitted("anyone@example.com"));
    }

    [Fact]
    public void Emails_match_exactly()
    {
        var a = Auth(ClockAt(), emails: new[] { "sergej@example.com" });
        Assert.True(a.Enabled);
        Assert.True(a.IsPermitted("sergej@example.com"));
        Assert.True(a.IsPermitted("SERGEJ@example.com"));        // case-insensitive
        Assert.False(a.IsPermitted("someone@example.com"));      // not the whole domain
    }

    [Fact]
    public void Domains_are_the_broader_explicit_mode()
    {
        var a = Auth(ClockAt(), domains: new[] { "example.com" });
        Assert.True(a.IsPermitted("anyone@example.com"));
        Assert.False(a.IsPermitted("anyone@other.com"));
    }

    [Fact]
    public void Both_lists_are_ORed()
    {
        var a = Auth(ClockAt(), emails: new[] { "sergej@other.com" }, domains: new[] { "example.com" });
        Assert.True(a.IsPermitted("sergej@other.com"));   // email
        Assert.True(a.IsPermitted("anyone@example.com")); // domain
        Assert.False(a.IsPermitted("nope@nope.com"));
    }

    [Fact]
    public void Session_cookie_round_trips_and_expires()
    {
        var clock = ClockAt();
        var a = Auth(clock, emails: new[] { "admin@example.com" });

        var cookie = a.IssueCookie(new AdminIdentity("sub-123", "admin@example.com"));
        var who = a.ReadCookie(cookie);
        Assert.NotNull(who);
        Assert.Equal("sub-123", who!.Sub);
        Assert.Equal("admin@example.com", who.Email);
        Assert.Equal("google:admin@example.com", who.Actor);

        clock.Advance(TimeSpan.FromMinutes(481));   // past the 480-min absolute life
        Assert.Null(a.ReadCookie(cookie));
    }

    [Fact]
    public void Session_cookie_from_another_key_is_rejected()
    {
        var clock = ClockAt();
        var cookie = Auth(clock, emails: new[] { "a@b.c" }, secret: "old-secret-aaaaaaaaaaaaaaaaaaaa")
            .IssueCookie(new AdminIdentity("s", "a@b.c"));
        Assert.Null(Auth(clock, emails: new[] { "a@b.c" }, secret: "new-secret-bbbbbbbbbbbbbbbbbbbb").ReadCookie(cookie));
    }

    [Fact]
    public void Csrf_is_bound_to_the_subject()
    {
        var a = Auth(ClockAt(), emails: new[] { "admin@example.com" });
        var token = a.IssueCsrf("sub-123");
        Assert.True(a.ValidateCsrf(token, "sub-123"));
        Assert.False(a.ValidateCsrf(token, "someone-else"));   // not this subject
        Assert.False(a.ValidateCsrf("", "sub-123"));           // missing
        Assert.False(a.ValidateCsrf("garbage", "sub-123"));    // unsigned
    }
}
