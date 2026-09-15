using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The RADIUS approval exchange end to end against a real (in-memory) engine: first request →
/// Access-Challenge (waiting), the human approves, the re-sent request → Access-Accept; plus bad
/// credentials, denial, timeout, and a tampered State.
/// </summary>
public class RadiusApprovalTests
{
    private const string Secret = "unit-test-radius-secret";

    private static (RadiusApproval approval, GateService gate) Build(
        ICredentialVerifier? verifier = null, bool requireMac = true)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = "unit-test-signing-key-0123456789",
            RadiusSharedSecret = Secret, RadiusResource = "rdp:gateway", RadiusChallengeSeconds = 120,
            RadiusAcceptAnyCredentials = true, RadiusRequireMessageAuthenticator = requireMac,
        });
        var gate = new GateService(new FakeTelegram(), new NullGeoLookup(),
            new AccessLists(opts, NullLogger<AccessLists>.Instance, new InMemoryConfigStore(), clock),
            opts, NullLogger<GateService>.Instance, clock, null, new InMemoryAuditStore(),
            new InMemoryRequestStore(), null, new InMemoryConfigStore(), null, null);
        var approval = new RadiusApproval(gate, verifier ?? new AcceptAnyCredentialVerifier(),
            new TokenSigner("unit-test-signing-key-0123456789"), new InMemoryReplayStore(clock),
            new LoginThrottle(opts, clock), opts, clock, NullLogger<RadiusApproval>.Instance);
        return (approval, gate);
    }

    private static byte[] Initial(string user, string password, bool mac = true)
    {
        var auth = RadiusPacket.NewAuthenticator();
        return RadiusPacket.BuildAccessRequest(1, auth, new[]
        {
            new RadiusAttribute(RadiusAttr.UserName, System.Text.Encoding.UTF8.GetBytes(user)),
            new RadiusAttribute(RadiusAttr.UserPassword, RadiusPacket.EncryptPassword(password, Secret, auth)),
        }, Secret, withMessageAuthenticator: mac);
    }

    private static byte[] Resume(byte[] state, string user = "anna")
    {
        var auth = RadiusPacket.NewAuthenticator();
        return RadiusPacket.BuildAccessRequest(2, auth, new[]
        {
            new RadiusAttribute(RadiusAttr.UserName, System.Text.Encoding.UTF8.GetBytes(user)),
            new RadiusAttribute(RadiusAttr.State, state),
        }, Secret, withMessageAuthenticator: true);
    }

    private static async Task<RadiusPacket> Handle(RadiusApproval a, byte[] raw, string remoteIp = "203.0.113.9") =>
        RadiusPacket.Parse(await a.Handle(RadiusPacket.Parse(raw)!, raw, remoteIp, default))!;

    [Fact]
    public async Task First_request_challenges_and_the_approved_resend_accepts()
    {
        var (a, gate) = Build();
        var raw = Initial("anna", "pw");
        var challenge = await Handle(a, raw);
        Assert.Equal(RadiusCode.AccessChallenge, challenge.Code);
        var state = challenge.Get(RadiusAttr.State)!;

        // Still waiting → still a challenge.
        Assert.Equal(RadiusCode.AccessChallenge, (await Handle(a, Resume(state))).Code);

        // A human approves the one waiting request; the next resend is accepted.
        var id = gate.PendingSnapshot().Single(r => r.State == "waiting").Id;
        await gate.Decide(id, "ok", "telegram:1");
        Assert.Equal(RadiusCode.AccessAccept, (await Handle(a, Resume(state))).Code);
    }

    [Fact]
    public async Task Bad_credentials_are_rejected_before_anyone_is_asked()
    {
        var (a, gate) = Build();
        var res = await Handle(a, Initial("anna", ""));   // empty password fails the verifier
        Assert.Equal(RadiusCode.AccessReject, res.Code);
        Assert.Empty(gate.PendingSnapshot());             // nothing was raised
    }

    [Fact]
    public async Task A_denied_request_rejects_on_resend()
    {
        var (a, gate) = Build();
        var state = (await Handle(a, Initial("anna", "pw"))).Get(RadiusAttr.State)!;
        var id = gate.PendingSnapshot().Single(r => r.State == "waiting").Id;
        await gate.Decide(id, "no", "telegram:1");
        Assert.Equal(RadiusCode.AccessReject, (await Handle(a, Resume(state))).Code);
    }

    [Fact]
    public async Task A_tampered_state_is_rejected()
    {
        var (a, _) = Build();
        var state = (await Handle(a, Initial("anna", "pw"))).Get(RadiusAttr.State)!;
        state[^1] ^= 0xFF;
        Assert.Equal(RadiusCode.AccessReject, (await Handle(a, Resume(state))).Code);
    }

    [Fact]
    public async Task A_wrong_shared_secret_message_authenticator_is_rejected()
    {
        var (a, _) = Build();
        var auth = RadiusPacket.NewAuthenticator();
        var raw = RadiusPacket.BuildAccessRequest(1, auth, new[]
        {
            new RadiusAttribute(RadiusAttr.UserName, System.Text.Encoding.UTF8.GetBytes("anna")),
            new RadiusAttribute(RadiusAttr.UserPassword, RadiusPacket.EncryptPassword("pw", Secret, auth)),
        }, "the-wrong-secret", withMessageAuthenticator: true);
        Assert.Equal(RadiusCode.AccessReject, (await Handle(a, raw)).Code);
    }

    [Fact]
    public async Task A_request_without_a_message_authenticator_is_rejected_by_default()
    {
        var (a, gate) = Build();
        var res = await Handle(a, Initial("anna", "pw", mac: false));   // BlastRADIUS: MA now required
        Assert.Equal(RadiusCode.AccessReject, res.Code);
        Assert.Empty(gate.PendingSnapshot());
    }

    [Fact]
    public async Task A_legacy_gateway_may_be_exempted_from_the_message_authenticator()
    {
        var (a, _) = Build(requireMac: false);
        Assert.Equal(RadiusCode.AccessChallenge, (await Handle(a, Initial("anna", "pw", mac: false))).Code);
    }

    [Fact]
    public async Task A_state_minted_for_one_user_cannot_accept_another()
    {
        // The State is bound to the attempt: quoting anna's State under a different User-Name is
        // refused before the decision is ever consulted (this is the v1 bypass, closed).
        var (a, gate) = Build();
        var state = (await Handle(a, Initial("anna", "pw"))).Get(RadiusAttr.State)!;
        var id = gate.PendingSnapshot().Single(r => r.State == "waiting").Id;
        await gate.Decide(id, "ok", "telegram:1");
        Assert.Equal(RadiusCode.AccessReject, (await Handle(a, Resume(state, user: "bob"))).Code);
    }

    [Fact]
    public async Task A_state_bound_to_a_different_client_is_rejected()
    {
        // A resume from a different datagram source than the one the State was minted for is refused.
        var (a, gate) = Build();
        var state = (await Handle(a, Initial("anna", "pw"))).Get(RadiusAttr.State)!;
        var id = gate.PendingSnapshot().Single(r => r.State == "waiting").Id;
        await gate.Decide(id, "ok", "telegram:1");
        Assert.Equal(RadiusCode.AccessReject, (await Handle(a, Resume(state), remoteIp: "198.51.100.7")).Code);
    }

    [Fact]
    public async Task An_approved_state_is_burned_and_cannot_be_replayed()
    {
        var (a, gate) = Build();
        var state = (await Handle(a, Initial("anna", "pw"))).Get(RadiusAttr.State)!;
        var id = gate.PendingSnapshot().Single(r => r.State == "waiting").Id;
        await gate.Decide(id, "ok", "telegram:1");

        Assert.Equal(RadiusCode.AccessAccept, (await Handle(a, Resume(state))).Code);   // first accept
        Assert.Equal(RadiusCode.AccessReject, (await Handle(a, Resume(state))).Code);   // replay refused
    }
}
