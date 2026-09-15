using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The RADIUS approval exchange, Duo-shaped: on the first Access-Request we verify the primary
/// credentials and raise an approval, answering Access-Challenge to hold the wait (a human thinks
/// longer than one RADIUS timeout, so the gateway re-sends with our State and we answer Challenge
/// again until the decision lands — then Access-Accept or Access-Reject). Stateless across rounds:
/// the State attribute carries a signed request id, so there is no per-connection server state.
///
/// RADIUS gates the <b>perimeter</b>, not a host — it rarely knows the target machine — so the
/// approval names the gateway, and this composes with a host agent (which gates the specific machine).
/// The subject travels for routing so the person acting is asked, not the global admins.
/// </summary>
public sealed class RadiusApproval
{
    private const string StateKey = "radius:v1";

    private readonly GateService _gate;
    private readonly ICredentialVerifier _verifier;
    private readonly TokenSigner _signer;
    private readonly GateOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<RadiusApproval> _log;

    public RadiusApproval(GateService gate, ICredentialVerifier verifier, TokenSigner signer,
        IOptions<GateOptions> options, TimeProvider clock, ILogger<RadiusApproval> log)
    {
        _gate = gate;
        _verifier = verifier;
        _signer = signer;
        _options = options.Value;
        _clock = clock;
        _log = log;
    }

    /// <summary>Handle one Access-Request datagram and produce the response datagram.</summary>
    public async Task<byte[]> Handle(RadiusPacket req, byte[] raw, string remoteIp, CancellationToken ct)
    {
        var secret = _options.RadiusSharedSecret;
        var withMac = req.Get(RadiusAttr.MessageAuthenticator) is not null;

        if (!req.VerifyMessageAuthenticator(raw, secret))
            return Reject(req, secret, withMac, "bad message authenticator");

        var user = req.GetString(RadiusAttr.UserName);
        if (string.IsNullOrWhiteSpace(user)) return Reject(req, secret, withMac, "no user");

        // Resume: a re-sent request carrying our State — check the decision.
        if (req.Get(RadiusAttr.State) is { } stateBytes)
        {
            if (!_signer.Verify(Encoding.UTF8.GetString(stateBytes), StateKey, out var payload))
                return Reject(req, secret, withMac, "invalid state");
            var parts = payload.Split('|');
            if (parts.Length != 2 || !long.TryParse(parts[1], out var exp)) return Reject(req, secret, withMac, "bad state");
            if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return Reject(req, secret, withMac, "approval timed out");

            return _gate.StateOf(parts[0]) switch
            {
                "approved" => Accept(req, secret, withMac),
                "denied" => Reject(req, secret, withMac, "denied"),
                null => Reject(req, secret, withMac, "approval expired"),
                _ => Challenge(req, secret, withMac, Encoding.UTF8.GetString(stateBytes)),   // still waiting
            };
        }

        // Initial: verify the password, then raise the approval and hold via Challenge.
        var password = req.DecryptPassword(secret);
        if (password is null || !await _verifier.Verify(user, password, ct))
            return Reject(req, secret, withMac, "bad credentials");

        var clientIp = req.GetString(RadiusAttr.CallingStationId) ?? remoteIp;
        var (state, id) = await _gate.RaiseAction(Resource(req), user, clientIp, "radius", ct,
            subjectIdentity: "os:" + user);

        if (state == "allowed") return Accept(req, secret, withMac);        // allow-list: straight through
        if (state != "waiting") return Reject(req, secret, withMac, state); // blocked / policy-refused

        var token = _signer.Sign($"{id}|{_clock.GetUtcNow().AddSeconds(_options.RadiusChallengeSeconds).ToUnixTimeSeconds()}", StateKey);
        return Challenge(req, secret, withMac, token);
    }

    // The gateway (NAS-Identifier) refines the perimeter label shown to the approver; else the config
    // default. Kept to a sane charset — it lands in audit and the notification.
    private string Resource(RadiusPacket req)
    {
        var nas = req.GetString(RadiusAttr.NasIdentifier);
        if (string.IsNullOrWhiteSpace(nas)) return _options.RadiusResource;
        var clean = new string(nas.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_').Take(60).ToArray());
        return clean.Length == 0 ? _options.RadiusResource : "rdp:" + clean;
    }

    private static byte[] Accept(RadiusPacket req, string secret, bool mac) =>
        RadiusPacket.BuildResponse(RadiusCode.AccessAccept, req.Identifier, req.Authenticator,
            new[] { Reply("Approved") }, secret, mac);

    private static byte[] Reject(RadiusPacket req, string secret, bool mac, string why) =>
        RadiusPacket.BuildResponse(RadiusCode.AccessReject, req.Identifier, req.Authenticator,
            new[] { Reply(why) }, secret, mac);

    private static byte[] Challenge(RadiusPacket req, string secret, bool mac, string stateToken) =>
        RadiusPacket.BuildResponse(RadiusCode.AccessChallenge, req.Identifier, req.Authenticator,
            new[]
            {
                new RadiusAttribute(RadiusAttr.State, Encoding.UTF8.GetBytes(stateToken)),
                Reply("Approve the sign-in on your phone."),
            }, secret, mac);

    private static RadiusAttribute Reply(string text) =>
        new(RadiusAttr.ReplyMessage, Encoding.UTF8.GetBytes(text));
}
