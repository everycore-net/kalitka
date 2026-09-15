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

    private static (RadiusApproval approval, GateService gate) Build(ICredentialVerifier? verifier = null)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = "unit-test-signing-key-0123456789",
            RadiusSharedSecret = Secret, RadiusResource = "rdp:gateway", RadiusChallengeSeconds = 120,
            RadiusAcceptAnyCredentials = true,
        });
        var gate = new GateService(new FakeTelegram(), new NullGeoLookup(),
            new AccessLists(opts, NullLogger<AccessLists>.Instance, new InMemoryConfigStore(), clock),
            opts, NullLogger<GateService>.Instance, clock, null, new InMemoryAuditStore(),
            new InMemoryRequestStore(), null, new InMemoryConfigStore(), null, null);
        var approval = new RadiusApproval(gate, verifier ?? new AcceptAnyCredentialVerifier(),
            new TokenSigner("unit-test-signing-key-0123456789"), opts, clock, NullLogger<RadiusApproval>.Instance);
        return (approval, gate);
    }

    private static byte[] Initial(string user, string password)
    {
        var auth = RadiusPacket.NewAuthenticator();
        return RadiusPacket.BuildAccessRequest(1, auth, new[]
        {
            new RadiusAttribute(RadiusAttr.UserName, System.Text.Encoding.UTF8.GetBytes(user)),
            new RadiusAttribute(RadiusAttr.UserPassword, RadiusPacket.EncryptPassword(password, Secret, auth)),
        }, Secret, withMessageAuthenticator: false);
    }

    private static byte[] Resume(byte[] state)
    {
        var auth = RadiusPacket.NewAuthenticator();
        return RadiusPacket.BuildAccessRequest(2, auth, new[]
        {
            new RadiusAttribute(RadiusAttr.UserName, System.Text.Encoding.UTF8.GetBytes("anna")),
            new RadiusAttribute(RadiusAttr.State, state),
        }, Secret, withMessageAuthenticator: false);
    }

    private static async Task<RadiusPacket> Handle(RadiusApproval a, byte[] raw) =>
        RadiusPacket.Parse(await a.Handle(RadiusPacket.Parse(raw)!, raw, "203.0.113.9", default))!;

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
}
