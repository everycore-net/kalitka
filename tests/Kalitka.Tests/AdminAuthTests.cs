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
        Assert.Equal("google:sub-123", who.Actor);   // stable sub, not the e-mail

        clock.Advance(TimeSpan.FromMinutes(481));   // past the 480-min absolute life
        Assert.Null(a.ReadCookie(cookie));
    }

    [Fact]
    public void Session_is_revoked_when_removed_from_the_allowlist()
    {
        var clock = ClockAt();
        var cookie = Auth(clock, emails: new[] { "admin@example.com" })
            .IssueCookie(new AdminIdentity("sub", "admin@example.com"));

        // Same signing key (same secret), so the signature still verifies — but the
        // allowlist no longer lists this address, so the session is refused now.
        var revoked = Auth(clock, emails: new[] { "someone-else@example.com" });
        Assert.Null(revoked.ReadCookie(cookie));
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

    [Fact]
    public void Csrf_token_expires_with_the_session()
    {
        var clock = ClockAt();
        var a = Auth(clock, emails: new[] { "admin@example.com" });   // AdminSessionMinutes = 480
        var token = a.IssueCsrf("sub-123");
        Assert.True(a.ValidateCsrf(token, "sub-123"));
        clock.Advance(TimeSpan.FromMinutes(481));
        Assert.False(a.ValidateCsrf(token, "sub-123"));   // no longer valid forever
    }

    // ---- Login callback (fake identity, no network) -------------------------

    private const string Secret = "unit-test-signing-key-0123456789";

    private sealed class FakeGoogle : GoogleAuth
    {
        private readonly (string Email, string Sub)? _identity;
        public FakeGoogle((string Email, string Sub)? identity, IOptions<GateOptions> opts)
            : base(new HttpClient(), opts, NullLogger<GoogleAuth>.Instance) => _identity = identity;
        public override Task<(string Email, string Sub)?> ResolveIdentity(string code, string redirectUri, CancellationToken ct)
            => Task.FromResult(_identity);
    }

    private static (AdminAuth auth, FakeTimeProvider clock) LoginAuth((string Email, string Sub)? identity, string[] emails)
    {
        var clock = ClockAt();
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = Secret, GateHost = "gate.example.com",
            GoogleClientId = "cid", GoogleClientSecret = "csecret",
            AdminEmails = emails, AdminSessionMinutes = 480,
        });
        return (new AdminAuth(new FakeGoogle(identity, opts), new TokenSigner(Secret), opts, clock), clock);
    }

    private static string StateFrom(string authorizationUrl)
    {
        var start = authorizationUrl.IndexOf("state=", StringComparison.Ordinal) + "state=".Length;
        var end = authorizationUrl.IndexOf('&', start);
        return Uri.UnescapeDataString(end < 0 ? authorizationUrl[start..] : authorizationUrl[start..end]);
    }

    [Fact]
    public async Task Login_completes_for_a_permitted_identity_with_the_matching_nonce()
    {
        var (a, _) = LoginAuth(("admin@example.com", "sub-1"), new[] { "admin@example.com" });
        var state = StateFrom(a.LoginUrl("/admin/agents", "nonce1"));

        var r = await a.CompleteLogin("code", state, "nonce1", default);
        Assert.True(r.Ok);
        Assert.Equal("sub-1", r.Identity!.Sub);
        Assert.Equal("/admin/agents", r.ReturnPath);
    }

    [Fact]
    public async Task Login_requires_the_matching_browser_nonce()
    {
        var (a, _) = LoginAuth(("admin@example.com", "sub-1"), new[] { "admin@example.com" });
        var state = StateFrom(a.LoginUrl("/admin/dashboard", "nonce1"));

        Assert.False((await a.CompleteLogin("code", state, "wrong-nonce", default)).Ok);   // another browser
        Assert.False((await a.CompleteLogin("code", state, "", default)).Ok);              // no login cookie
    }

    [Fact]
    public async Task Login_rejects_tampered_or_expired_state_and_empty_code()
    {
        var (a, clock) = LoginAuth(("admin@example.com", "sub-1"), new[] { "admin@example.com" });
        var state = StateFrom(a.LoginUrl("/admin/dashboard", "n"));

        var tampered = state[..^1] + (state[^1] == 'a' ? 'b' : 'a');
        Assert.False((await a.CompleteLogin("code", tampered, "n", default)).Ok);
        Assert.False((await a.CompleteLogin("", state, "n", default)).Ok);   // no code

        clock.Advance(TimeSpan.FromMinutes(11));   // state lives 10 minutes
        Assert.False((await a.CompleteLogin("code", state, "n", default)).Ok);
    }

    [Fact]
    public async Task Login_refuses_an_identity_not_on_the_allowlist_or_unresolved()
    {
        var notListed = LoginAuth(("nope@other.com", "s"), new[] { "admin@example.com" }).auth;
        Assert.False((await notListed.CompleteLogin("code", StateFrom(notListed.LoginUrl("/", "n")), "n", default)).Ok);

        var unresolved = LoginAuth(null, new[] { "admin@example.com" }).auth;   // Google returned nothing
        Assert.False((await unresolved.CompleteLogin("code", StateFrom(unresolved.LoginUrl("/", "n")), "n", default)).Ok);
    }

    [Fact]
    public async Task Login_never_returns_to_an_off_site_path()
    {
        var (a, _) = LoginAuth(("admin@example.com", "sub-1"), new[] { "admin@example.com" });
        var state = StateFrom(a.LoginUrl("//evil.com/x", "n"));   // protocol-relative open redirect

        var r = await a.CompleteLogin("code", state, "n", default);
        Assert.True(r.Ok);
        Assert.Equal("/admin/dashboard", r.ReturnPath);   // rejected → safe default
    }
}
