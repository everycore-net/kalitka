using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Passkey as a way past the gate (fido2 slice 1), visitor side: register "remember this device" and
/// later log in with it, plus the checks that keep it an allowlist and not a bypass — scope, revoke
/// (= blocked), replay, tamper, and the device-bound policy.
/// </summary>
public class VisitorPasskeyServiceTests
{
    private const string RpId = "gate.example.com";
    private const string Origin = "https://gate.example.com";

    private static (VisitorPasskeyService svc, VisitorPasskeyStore store) Build(SessionScope scope = SessionScope.Application, bool requireBound = false)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var config = new InMemoryConfigStore();
        var store = new VisitorPasskeyStore(config);
        var o = new GateOptions { GateHost = RpId, SessionScope = scope, WebAuthnRequireDeviceBound = requireBound };
        return (new VisitorPasskeyService(store, new TokenSigner("unit-test-master-0123456789"),
            new InMemoryReplayStore(clock), new InMemoryAuditStore(), Options.Create(o), clock), store);
    }

    private static async Task Register(VisitorPasskeyService svc, SoftAuthenticator auth, string target)
    {
        var begin = svc.RegisterBegin(target, "sergej");
        var (att, cdj) = auth.Register(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson));
        Assert.Null(await svc.RegisterFinish(target, begin.State, att, cdj, default));
    }

    private static Task<VisitorLoginResult> Login(VisitorPasskeyService svc, SoftAuthenticator auth, string target, uint count = 1)
    {
        var begin = svc.LoginBegin(target);
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson), count);
        return svc.LoginFinish(target, begin.State, cid, ad, cdj, sig, default);
    }

    [Fact]
    public async Task Remember_then_pass_the_gate_on_the_same_host()
    {
        var (svc, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth, "app-01.example.com");
        var res = await Login(svc, auth, "app-01.example.com");
        Assert.True(res.Ok, res.Error);
        Assert.False(res.DomainScope);   // per-host by default
    }

    [Fact]
    public async Task A_per_host_device_does_not_work_on_another_host()
    {
        var (svc, _) = Build(SessionScope.Application);
        var auth = new SoftAuthenticator();
        await Register(svc, auth, "app-01.example.com");
        var res = await Login(svc, auth, "app-02.example.com");
        Assert.False(res.Ok);
        Assert.Contains("not remembered for this host", res.Error);
    }

    [Fact]
    public async Task A_domain_scoped_device_works_across_hosts_and_mints_a_domain_session()
    {
        var (svc, _) = Build(SessionScope.Domain);
        var auth = new SoftAuthenticator();
        await Register(svc, auth, "app-01.example.com");
        var res = await Login(svc, auth, "app-02.example.com");
        Assert.True(res.Ok, res.Error);
        Assert.True(res.DomainScope);
    }

    [Fact]
    public async Task A_revoked_device_is_blocked()
    {
        var (svc, store) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth, "app-01.example.com");
        Assert.True(store.Revoke(auth.CredentialIdB64u));
        var res = await Login(svc, auth, "app-01.example.com");
        Assert.False(res.Ok);
        Assert.Contains("blocked", res.Error);
    }

    [Fact]
    public async Task A_login_cannot_be_replayed()
    {
        var (svc, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth, "app-01.example.com");
        var begin = svc.LoginBegin("app-01.example.com");
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson), 1);
        Assert.True((await svc.LoginFinish("app-01.example.com", begin.State, cid, ad, cdj, sig, default)).Ok);
        var again = await svc.LoginFinish("app-01.example.com", begin.State, cid, ad, cdj, sig, default);
        Assert.False(again.Ok);
    }

    [Fact]
    public async Task A_tampered_signature_does_not_pass()
    {
        var (svc, _) = Build();
        var auth = new SoftAuthenticator();
        await Register(svc, auth, "app-01.example.com");
        var begin = svc.LoginBegin("app-01.example.com");
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, SoftAuthenticator.ChallengeOf(begin.OptionsJson), 1);
        var bad = sig[..^2] + (sig[^1] == 'A' ? "BB" : "AA");
        Assert.False((await svc.LoginFinish("app-01.example.com", begin.State, cid, ad, cdj, bad, default)).Ok);
    }

    [Fact]
    public async Task A_synced_passkey_is_refused_when_the_host_requires_device_bound()
    {
        var (svc, _) = Build(requireBound: true);
        var auth = new SoftAuthenticator { BackupEligible = true };
        await Register(svc, auth, "app-01.example.com");
        var res = await Login(svc, auth, "app-01.example.com");
        Assert.False(res.Ok);
        Assert.Contains("device-bound", res.Error);
    }
}
