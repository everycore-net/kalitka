using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Portal sign-in is its own population: it resolves an identity to an operator principal (no admin
/// allowlist), mints a cookie under its own signing purpose, and refuses a verified person who is not
/// linked to any principal. The cookie is resolved fresh on each read, so removing the principal ends
/// the session at once.
/// </summary>
public class PortalAuthTests
{
    private const string Secret = "unit-test-signing-key-0123456789";

    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));

    private sealed class FakeGoogle : GoogleAuth
    {
        private readonly (string Email, string Sub)? _identity;
        public FakeGoogle((string Email, string Sub)? identity, IOptions<GateOptions> opts)
            : base(new HttpClient(), opts, NullLogger<GoogleAuth>.Instance) => _identity = identity;
        public override Task<(string Email, string Sub)?> ResolveIdentity(string code, string redirectUri, CancellationToken ct)
            => Task.FromResult(_identity);
    }

    private static IOptions<GateOptions> Opts() => Options.Create(new GateOptions
    {
        HmacSecret = Secret, GateHost = "gate.example.com",
        GoogleClientId = "cid", GoogleClientSecret = "csecret", AdminSessionMinutes = 480,
    });

    // A principals service with an optional pre-linked person (google:<sub> → principal).
    private static PrincipalService Principals(FakeTimeProvider clock, string? linkSub = null)
    {
        var svc = new PrincipalService(new InMemoryConfigStore(), new InMemoryAuditStore(), clock);
        if (linkSub is not null)
            svc.Save("anna", "Anna", new[] { $"google:{linkSub}" }, "admin", default).GetAwaiter().GetResult();
        return svc;
    }

    private static PortalAuth Auth(FakeTimeProvider clock, PrincipalService principals, (string Email, string Sub)? identity = null)
    {
        var opts = Opts();
        var provider = new FakeGoogle(identity, opts);
        return new PortalAuth(new IdentityProviders(new[] { (IIdentityProvider)provider }), principals,
            new TokenSigner(Secret), opts, clock);
    }

    private static string StateFrom(string url)
    {
        var start = url.IndexOf("state=", StringComparison.Ordinal) + "state=".Length;
        var end = url.IndexOf('&', start);
        return Uri.UnescapeDataString(end < 0 ? url[start..] : url[start..end]);
    }

    [Fact]
    public void Cookie_round_trips_to_the_resolved_principal_and_expires()
    {
        var clock = ClockAt();
        var a = Auth(clock, Principals(clock, linkSub: "sub-1"));

        var cookie = a.IssueCookie("google", "sub-1", "anna@example.com");
        var who = a.ReadCookie(cookie);
        Assert.NotNull(who);
        Assert.Equal("anna", who!.Principal.Id);
        Assert.Equal("anna@example.com", who.Email);

        clock.Advance(TimeSpan.FromMinutes(481));
        Assert.Null(a.ReadCookie(cookie));
    }

    [Fact]
    public void A_cookie_for_an_unlinked_identity_is_not_a_session()
    {
        var clock = ClockAt();
        var a = Auth(clock, Principals(clock));   // nobody linked
        var cookie = a.IssueCookie("google", "sub-1", "anna@example.com");
        Assert.Null(a.ReadCookie(cookie));         // no principal → no session
    }

    [Fact]
    public async Task Removing_the_principal_ends_the_session_now()
    {
        var clock = ClockAt();
        var principals = Principals(clock, linkSub: "sub-1");
        var a = Auth(clock, principals);
        var cookie = a.IssueCookie("google", "sub-1", "anna@example.com");
        Assert.NotNull(a.ReadCookie(cookie));

        await principals.Delete("anna", "admin", default);
        Assert.Null(a.ReadCookie(cookie));   // resolved fresh each read
    }

    [Fact]
    public void A_portal_cookie_is_useless_under_the_admin_key()
    {
        var clock = ClockAt();
        var portalCookie = Auth(clock, Principals(clock, linkSub: "sub-1")).IssueCookie("google", "sub-1", "a@b.c");
        // Admin auth uses a different signing purpose (admin:v1); the portal cookie must not verify.
        var admin = new AdminAuth(new IdentityProviders(new[] { (IIdentityProvider)new FakeGoogle(null, Opts()) }),
            new TokenSigner(Secret), Opts(), clock);
        Assert.Null(admin.ReadCookie(portalCookie));
    }

    [Fact]
    public async Task Login_completes_to_a_principal_when_linked()
    {
        var clock = ClockAt();
        var a = Auth(clock, Principals(clock, linkSub: "sub-1"), identity: ("anna@example.com", "sub-1"));
        var r = await a.CompleteLogin("code", StateFrom(a.LoginUrl("google", "/portal", "n")), "n", default);
        Assert.True(r.Authenticated);
        Assert.Equal("anna", r.PrincipalId);
    }

    [Fact]
    public async Task Login_is_authenticated_but_principal_less_for_an_unlinked_person()
    {
        var clock = ClockAt();
        var a = Auth(clock, Principals(clock), identity: ("stranger@example.com", "sub-9"));
        var r = await a.CompleteLogin("code", StateFrom(a.LoginUrl("google", "/portal", "n")), "n", default);
        Assert.True(r.Authenticated);
        Assert.Null(r.PrincipalId);                 // signed in, but no access → the refuse page
        Assert.Equal("stranger@example.com", r.Email);
    }

    [Fact]
    public async Task Login_fails_on_an_unresolved_identity_or_wrong_nonce()
    {
        var clock = ClockAt();
        var unresolved = Auth(clock, Principals(clock, linkSub: "sub-1"), identity: null);
        Assert.False((await unresolved.CompleteLogin("code", StateFrom(unresolved.LoginUrl("google", "/portal", "n")), "n", default)).Authenticated);

        var a = Auth(clock, Principals(clock, linkSub: "sub-1"), identity: ("anna@example.com", "sub-1"));
        Assert.False((await a.CompleteLogin("code", StateFrom(a.LoginUrl("google", "/portal", "n")), "wrong", default)).Authenticated);
    }

    [Fact]
    public async Task Login_never_returns_off_site_or_outside_the_portal()
    {
        var clock = ClockAt();
        var a = Auth(clock, Principals(clock, linkSub: "sub-1"), identity: ("anna@example.com", "sub-1"));
        var r = await a.CompleteLogin("code", StateFrom(a.LoginUrl("google", "/admin/dashboard", "n")), "n", default);
        Assert.Equal("/portal", r.ReturnPath);   // not a control-plane path
    }

    [Fact]
    public void Csrf_is_bound_to_the_subject()
    {
        var a = Auth(ClockAt(), Principals(ClockAt()));
        var token = a.IssueCsrf("sub-1");
        Assert.True(a.ValidateCsrf(token, "sub-1"));
        Assert.False(a.ValidateCsrf(token, "other"));
        Assert.False(a.ValidateCsrf("garbage", "sub-1"));
    }
}
