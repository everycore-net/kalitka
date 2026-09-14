using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Registration (fido2 slice 1) and device-signed approval (slice 2) end to end against a real
/// software authenticator: the happy paths, and the checks that make the signature mean something —
/// origin, challenge binding, replay, expiry, policy drift, clone detection, assurance.
/// </summary>
public class WebAuthnServiceTests
{
    private const string RpId = "gate.example.com";
    private const string Origin = "https://gate.example.com";
    private static readonly AdminIdentity Who = new("sub-1", "admin@example.com");

    private static (WebAuthnService svc, PrincipalService prin, WebAuthnStore store, FakeTimeProvider clock)
        Build(GateOptions? o = null)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var config = new InMemoryConfigStore();
        var audit = new InMemoryAuditStore();
        var prin = new PrincipalService(config, audit, clock);
        var store = new WebAuthnStore(config);
        var signer = new TokenSigner("unit-test-master-0123456789");
        var replay = new InMemoryReplayStore(clock);
        o ??= new GateOptions { GateHost = RpId };
        return (new WebAuthnService(store, prin, signer, replay, audit, Options.Create(o), clock), prin, store, clock);
    }

    private static async Task Register(WebAuthnService svc, SoftAuthenticator auth)
    {
        var begin = svc.RegisterBegin(Who);
        var (att, cdj) = auth.Register(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson));
        var err = await svc.RegisterFinish(Who, begin.State, auth.CredentialIdB64u, att, cdj, "my phone", default);
        Assert.Null(err);
    }

    private static ApprovalContext Ctx(int required = 1) =>
        new("req-1", "web:app.example.com", required, "Optional", "", "", "");

    [Fact]
    public async Task Register_links_the_device_to_the_operator_and_stores_the_key()
    {
        var (svc, prin, store, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var cred = store.ByCredentialId(auth.CredentialIdB64u);
        Assert.NotNull(cred);
        // The device's identity resolves to a principal, so its decisions count in a quorum...
        var pid = prin.Resolve("app:" + auth.CredentialIdB64u);
        Assert.NotNull(pid);
        // ...and it is the same principal as the admin's Google login (provably the same human).
        Assert.Equal(pid, prin.Resolve(Who.Actor));
    }

    [Fact]
    public async Task A_signed_approval_verifies_and_yields_a_proof_bound_to_the_credential()
    {
        var (svc, _, _, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(), "ok");
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson), 1);
        var res = await svc.ApproveVerify(Who, Ctx(), "ok", new SignedDecisionInput(begin.State, cid, ad, cdj, sig), default);

        Assert.True(res.Ok, res.Error);
        Assert.Equal("app:" + auth.CredentialIdB64u, res.Actor);
        Assert.StartsWith("wa1:", res.Proof);
    }

    [Fact]
    public async Task A_tampered_signature_does_not_verify()
    {
        var (svc, _, _, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(), "ok");
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson), 1);
        var bad = sig[..^2] + (sig[^1] == 'A' ? "BB" : "AA");
        var res = await svc.ApproveVerify(Who, Ctx(), "ok", new SignedDecisionInput(begin.State, cid, ad, cdj, bad), default);
        Assert.False(res.Ok);
    }

    [Fact]
    public async Task A_wrong_origin_is_rejected()
    {
        var (svc, _, _, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(), "ok");
        var (cid, ad, cdj, sig) = auth.Sign(RpId, "https://evil.example.com", SoftAuthenticator.ChallengeOf(begin.OptionsJson), 1);
        var res = await svc.ApproveVerify(Who, Ctx(), "ok", new SignedDecisionInput(begin.State, cid, ad, cdj, sig), default);
        Assert.False(res.Ok);
        Assert.Contains("origin", res.Error);
    }

    [Fact]
    public async Task An_assertion_cannot_be_replayed()
    {
        var (svc, _, _, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(), "ok");
        var input = Assertion(auth, begin, 1);
        Assert.True((await svc.ApproveVerify(Who, Ctx(), "ok", input, default)).Ok);
        var again = await svc.ApproveVerify(Who, Ctx(), "ok", input, default);
        Assert.False(again.Ok);
        Assert.Contains("already used", again.Error);
    }

    [Fact]
    public async Task An_expired_challenge_is_rejected()
    {
        var (svc, _, _, clock) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(), "ok");
        clock.Advance(TimeSpan.FromMinutes(6));   // default challenge lifetime is 5 minutes
        var res = await svc.ApproveVerify(Who, Ctx(), "ok", Assertion(auth, begin, 1), default);
        Assert.False(res.Ok);
        Assert.Contains("expired", res.Error);
    }

    [Fact]
    public async Task A_policy_change_between_begin_and_finish_invalidates_the_signature()
    {
        var (svc, _, _, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(required: 1), "ok");
        var input = Assertion(auth, begin, 1);
        // The request now needs a quorum of 2 — different terms than were signed.
        var res = await svc.ApproveVerify(Who, Ctx(required: 2), "ok", input, default);
        Assert.False(res.Ok);
        Assert.Contains("changed", res.Error);
    }

    [Fact]
    public async Task A_regressed_signature_counter_raises_a_clone_alarm()
    {
        var (svc, _, _, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth);

        // First approval at counter 5 succeeds and advances the stored counter.
        var b1 = svc.ApproveBegin(Who, Ctx(), "ok");
        Assert.True((await svc.ApproveVerify(Who, Ctx(), "ok", Assertion(auth, b1, 5), default)).Ok);

        // A fresh (non-replay) approval at a lower counter means a second copy of the key.
        var b2 = svc.ApproveBegin(Who, Ctx(), "ok");
        var res = await svc.ApproveVerify(Who, Ctx(), "ok", Assertion(auth, b2, 3), default);
        Assert.False(res.Ok);
        Assert.Contains("counter", res.Error);
    }

    [Fact]
    public async Task A_synced_passkey_is_refused_when_policy_requires_device_bound()
    {
        var (svc, _, _, _) = Build(new GateOptions { GateHost = RpId, WebAuthnRequireDeviceBound = true });
        var auth = new SoftAuthenticator { BackupEligible = true };   // cloud-synced
        await Register(svc, auth);

        var begin = svc.ApproveBegin(Who, Ctx(), "ok");
        var res = await svc.ApproveVerify(Who, Ctx(), "ok", Assertion(auth, begin, 1), default);
        Assert.False(res.Ok);
        Assert.Contains("device-bound", res.Error);
    }

    private static SignedDecisionInput Assertion(SoftAuthenticator auth, WebAuthnBegin begin, uint count)
    {
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson), count);
        return new SignedDecisionInput(begin.State, cid, ad, cdj, sig);
    }
}
