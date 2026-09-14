using System.Text.RegularExpressions;
using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Device enrolment: the invite is one-time and its completion must be an IdP sign-in as the invited
/// account. The load-bearing checks — e-mail match, single use, browser binding — verified with a
/// fake IdP.
/// </summary>
public class EnrollServiceTests
{
    private sealed class FakeGoogle : GoogleAuth
    {
        public (string Email, string Sub)? Next;
        public FakeGoogle(GateOptions o) : base(new HttpClient(), Options.Create(o), NullLogger<GoogleAuth>.Instance) { }
        public override Task<(string Email, string Sub)?> ResolveIdentity(string code, string redirectUri, CancellationToken ct)
            => Task.FromResult(Next);
    }

    private sealed class Kit
    {
        public readonly FakeGoogle Google;
        public readonly EnrollService Enroll;
        public readonly OperatorApprovers Approvers;
        public readonly PrincipalService Principals;

        public Kit()
        {
            var opts = new GateOptions { GateHost = "gate.example.com", GoogleClientId = "cid", GoogleClientSecret = "sec" };
            var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
            var config = new InMemoryConfigStore();
            var audit = new InMemoryAuditStore();
            Google = new FakeGoogle(opts);
            var signer = new TokenSigner("unit-test-master-0123456789");
            Principals = new PrincipalService(config, audit, clock);
            Approvers = new OperatorApprovers(config, audit, clock);
            Enroll = new EnrollService(new IdentityProviders(new IIdentityProvider[] { Google }), new OneTimeTokenService(signer, clock), new InMemoryReplayStore(clock),
                Principals, Approvers, signer, audit, Options.Create(opts), clock);
        }
    }

    private static string Param(string url, string name) =>
        Uri.UnescapeDataString(Regex.Match(url, "[?&]" + name + "=([^&]*)").Groups[1].Value);

    [Fact]
    public async Task An_invite_completed_by_the_matching_account_enrols_and_grants_approve()
    {
        var k = new Kit();
        var link = await k.Enroll.Invite("Bob@Example.com", "Bob", "admin", default);
        var url = k.Enroll.StartUrl("google", Param(link, "t"), "nonce1");
        Assert.NotNull(url);

        k.Google.Next = ("bob@example.com", "sub-bob");
        var res = await k.Enroll.Complete("code", Param(url!, "state"), "nonce1", default);

        Assert.True(res.Ok, res.Error);
        Assert.Equal("bob@example.com", res.Identity!.Email);
        Assert.True(k.Approvers.Contains("bob@example.com"));
        Assert.NotNull(k.Principals.Resolve("google:sub-bob"));
    }

    [Fact]
    public async Task An_invite_completed_by_a_different_account_is_refused()
    {
        var k = new Kit();
        var link = await k.Enroll.Invite("alice@example.com", "Alice", "admin", default);
        var url = k.Enroll.StartUrl("google", Param(link, "t"), "n2");

        k.Google.Next = ("bob@example.com", "sub-bob");   // a different person clicked
        var res = await k.Enroll.Complete("code", Param(url!, "state"), "n2", default);

        Assert.False(res.Ok);
        Assert.Contains("different account", res.Error);
        Assert.False(k.Approvers.Contains("bob@example.com"));
    }

    [Fact]
    public async Task An_invite_cannot_be_used_twice()
    {
        var k = new Kit();
        var link = await k.Enroll.Invite("bob@example.com", "Bob", "admin", default);
        var state = Param(k.Enroll.StartUrl("google", Param(link, "t"), "n")!, "state");
        k.Google.Next = ("bob@example.com", "sub-bob");

        Assert.True((await k.Enroll.Complete("code", state, "n", default)).Ok);
        var again = await k.Enroll.Complete("code", state, "n", default);
        Assert.False(again.Ok);
        Assert.Contains("already been used", again.Error);
    }

    [Fact]
    public async Task The_invite_must_be_completed_in_the_same_browser()
    {
        var k = new Kit();
        var link = await k.Enroll.Invite("bob@example.com", "Bob", "admin", default);
        var state = Param(k.Enroll.StartUrl("google", Param(link, "t"), "the-nonce")!, "state");
        k.Google.Next = ("bob@example.com", "sub-bob");

        var res = await k.Enroll.Complete("code", state, "a-different-nonce", default);
        Assert.False(res.Ok);
        Assert.Contains("same browser", res.Error);
    }

    [Fact]
    public void A_garbage_invite_yields_no_start_url()
    {
        Assert.Null(new Kit().Enroll.StartUrl("google", "not-a-real-token", "n"));
    }
}
