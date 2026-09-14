using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The identity-provider seam: the registry, and a second (non-Google) provider driving an
/// admin login end to end — the actor and session carry the provider scheme, so a Microsoft admin is
/// a first-class operator (and can satisfy the quorum).</summary>
public class ProviderSeamTests
{
    private sealed class FakeProvider(string scheme, string name, ProvenIdentity? identity, bool enabled = true) : IIdentityProvider
    {
        public string Scheme => scheme;
        public string DisplayName => name;
        public bool Enabled => enabled;
        public string AuthorizationUrl(string state, string redirectUri) => $"https://idp/authorize?state={Uri.EscapeDataString(state)}";
        public Task<ProvenIdentity?> Resolve(string code, string redirectUri, CancellationToken ct) => Task.FromResult(identity);
    }

    [Fact]
    public void The_registry_lists_and_resolves_only_enabled_providers()
    {
        var reg = new IdentityProviders(new IIdentityProvider[]
        {
            new FakeProvider("google", "Google", null),
            new FakeProvider("ms", "Microsoft", null),
            new FakeProvider("okta", "Okta", null, enabled: false),
        });
        Assert.True(reg.Any);
        Assert.Equal(2, reg.Enabled.Count);
        Assert.Equal("Microsoft", reg.ByScheme("ms")!.DisplayName);
        Assert.Null(reg.ByScheme("okta"));    // present but disabled
        Assert.Null(reg.ByScheme("nope"));
    }

    [Fact]
    public async Task A_microsoft_admin_logs_in_through_the_seam_and_carries_the_scheme()
    {
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = "unit-test-signing-key-0123456789", GateHost = "gate.example.com",
            AdminEmails = new[] { "boss@corp.com" }, AdminSessionMinutes = 480,
        });
        var ms = new FakeProvider("ms", "Microsoft", new ProvenIdentity("ms", "T1:O1", "boss@corp.com"));
        var auth = new AdminAuth(new IdentityProviders(new IIdentityProvider[] { ms }),
            new TokenSigner("unit-test-signing-key-0123456789"), opts, new FakeTimeProvider());

        var url = auth.LoginUrl("ms", "/admin/dashboard", "nonce1");
        var state = Uri.UnescapeDataString(url["https://idp/authorize?state=".Length..]);

        var r = await auth.CompleteLogin("code", state, "nonce1", default);
        Assert.True(r.Ok);
        Assert.Equal("ms", r.Identity!.Scheme);
        Assert.Equal("ms:T1:O1", r.Identity.Actor);     // scheme-qualified, not google:

        // The session cookie round-trips the scheme, so the actor is stable across requests.
        var who = auth.ReadCookie(auth.IssueCookie(r.Identity));
        Assert.Equal("ms:T1:O1", who!.Actor);
    }

    [Fact]
    public void A_pre_seam_google_cookie_still_reads_as_google()
    {
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = "unit-test-signing-key-0123456789", GateHost = "gate.example.com",
            AdminEmails = new[] { "a@b.c" }, AdminSessionMinutes = 480,
        });
        var signer = new TokenSigner("unit-test-signing-key-0123456789");
        var auth = new AdminAuth(new IdentityProviders(new IIdentityProvider[]
            { new FakeProvider("google", "Google", null) }), signer, opts, new FakeTimeProvider());

        // A legacy 3-part cookie (exp|sub|email), as issued before the scheme was added.
        var exp = new FakeTimeProvider().GetUtcNow().AddMinutes(480).ToUnixTimeSeconds();
        var legacy = signer.Sign($"{exp}|sub-legacy|a@b.c", "admin:v1");
        var who = auth.ReadCookie(legacy);
        Assert.NotNull(who);
        Assert.Equal("google:sub-legacy", who!.Actor);
    }
}
