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
    // radius-state-v2: the State is a bearer token for the wait window, so it must be bound to the
    // exact attempt it was minted for — not just a request id. We frame (and sign) the request id
    // together with the subject, the RADIUS client (the datagram source), the resource, the calling
    // station and the expiry, and re-check every one on each resume. A v1 token (id|exp only) let any
    // packet quoting the State of an already-approved request collect an Accept.
    private const string StateKey = "radius-state-v2";

    private readonly GateService _gate;
    private readonly ICredentialVerifier _verifier;
    private readonly TokenSigner _signer;
    private readonly IReplayStore _replay;
    private readonly LoginThrottle _throttle;
    private readonly GateOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<RadiusApproval> _log;

    public RadiusApproval(GateService gate, ICredentialVerifier verifier, TokenSigner signer,
        IReplayStore replay, LoginThrottle throttle, IOptions<GateOptions> options, TimeProvider clock, ILogger<RadiusApproval> log)
    {
        _gate = gate;
        _verifier = verifier;
        _signer = signer;
        _replay = replay;
        _throttle = throttle;
        _options = options.Value;
        _clock = clock;
        _log = log;
    }

    private sealed record RadiusState(string RequestId, string SubjectIdentity, string Client,
        string Resource, string CallingStation, long ExpiresAtUnix);

    /// <summary>Handle one Access-Request datagram and produce the response datagram.
    /// <paramref name="remoteIp"/> is the datagram source (the RADIUS client), which is what binds and
    /// identifies the client — never a packet attribute the sender chose.</summary>
    public async Task<byte[]> Handle(RadiusPacket req, byte[] raw, string remoteIp, CancellationToken ct)
    {
        var secret = _options.RadiusSharedSecret;

        // BlastRADIUS: require a Message-Authenticator on the request (unless a legacy gateway is
        // explicitly exempted), and always emit one on the response.
        if (req.Get(RadiusAttr.MessageAuthenticator) is null && _options.RadiusRequireMessageAuthenticator)
            return Reject(req, secret, "message-authenticator required");
        if (!req.VerifyMessageAuthenticator(raw, secret))
            return Reject(req, secret, "bad message authenticator");

        var user = req.GetString(RadiusAttr.UserName);
        if (string.IsNullOrWhiteSpace(user)) return Reject(req, secret, "no user");

        var subjectIdentity = "os:" + user;
        var resource = Resource(req);
        var callingStation = req.GetString(RadiusAttr.CallingStationId) ?? remoteIp;

        // Resume: a re-sent request carrying our State — check it is the SAME attempt, then the decision.
        if (req.Get(RadiusAttr.State) is { } stateBytes)
        {
            var token = Encoding.UTF8.GetString(stateBytes);
            if (!TryReadState(token, out var st)) return Reject(req, secret, "invalid state");

            // The State must belong to this exact attempt: same subject, client, resource and station.
            if (st.SubjectIdentity != subjectIdentity || st.Client != remoteIp ||
                st.Resource != resource || st.CallingStation != callingStation)
                return Reject(req, secret, "state does not match this request");
            if (_clock.GetUtcNow().ToUnixTimeSeconds() > st.ExpiresAtUnix) return Reject(req, secret, "approval timed out");

            switch (_gate.StateOf(st.RequestId))
            {
                case "approved":
                    // Terminal: burn the State so the same token cannot be replayed for a second Accept.
                    if (!await _replay.TryConsumeAsync(StateJti(token), Expiry(st.ExpiresAtUnix), ct))
                        return Reject(req, secret, "state already used");
                    return Accept(req, secret);
                case "denied":
                    await _replay.TryConsumeAsync(StateJti(token), Expiry(st.ExpiresAtUnix), ct);   // terminal: burn too
                    return Reject(req, secret, "denied");
                case null:
                    return Reject(req, secret, "approval expired");
                default:
                    return Challenge(req, secret, token);   // still waiting → hold with the same State
            }
        }

        // Initial: verify the password (throttled so a bad-password flood can neither lock the
        // account out at the DC nor avalanche binds), then raise the approval and hold via Challenge.
        var permit = await _throttle.AcquireAsync(user, ct);
        if (permit is null) return Reject(req, secret, "too many attempts, try again later");
        bool verified;
        try
        {
            var password = req.DecryptPassword(secret);
            verified = password is not null && await _verifier.Verify(user, password, ct);
            permit.Record(verified);
        }
        finally { permit.Dispose(); }
        if (!verified) return Reject(req, secret, "bad credentials");

        var (state, id) = await _gate.RaiseAction(resource, user, callingStation, "radius", ct,
            subjectIdentity: subjectIdentity);

        if (state == "allowed") return Accept(req, secret);        // allow-list: straight through
        if (state != "waiting") return Reject(req, secret, state); // blocked / policy-refused

        var exp = _clock.GetUtcNow().AddSeconds(_options.RadiusChallengeSeconds).ToUnixTimeSeconds();
        var newState = MintState(new RadiusState(id, subjectIdentity, remoteIp, resource, callingStation, exp));
        return Challenge(req, secret, newState);
    }

    private string MintState(RadiusState st) => _signer.Sign(Base64Url.Encode(
        Framing.Encode("v2", st.RequestId, st.SubjectIdentity, st.Client, st.Resource, st.CallingStation,
            st.ExpiresAtUnix.ToString())), StateKey);

    private bool TryReadState(string token, out RadiusState st)
    {
        st = null!;
        if (!_signer.Verify(token, StateKey, out var payload) || !Base64Url.TryDecode(payload, out var framed))
            return false;
        string[] f;
        try { f = Framing.Decode(framed); }
        catch (FormatException) { return false; }
        if (f.Length != 7 || f[0] != "v2" || !long.TryParse(f[6], out var exp)) return false;
        st = new RadiusState(f[1], f[2], f[3], f[4], f[5], exp);
        return true;
    }

    private static string StateJti(string token) => "radius-state:" + AgentSignatures.Sha256Hex(Encoding.UTF8.GetBytes(token));
    private static DateTimeOffset Expiry(long unix) => DateTimeOffset.FromUnixTimeSeconds(unix);

    // The gateway (NAS-Identifier) refines the perimeter label shown to the approver; else the config
    // default. Kept to a sane charset — it lands in audit and the notification.
    private string Resource(RadiusPacket req)
    {
        var nas = req.GetString(RadiusAttr.NasIdentifier);
        if (string.IsNullOrWhiteSpace(nas)) return _options.RadiusResource;
        var clean = new string(nas.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_').Take(60).ToArray());
        return clean.Length == 0 ? _options.RadiusResource : "rdp:" + clean;
    }

    // Responses always carry a Message-Authenticator (RFC 2869), the BlastRADIUS-hardened default,
    // whether or not the request had one.
    private static byte[] Accept(RadiusPacket req, string secret) =>
        RadiusPacket.BuildResponse(RadiusCode.AccessAccept, req.Identifier, req.Authenticator,
            new[] { Reply("Approved") }, secret, withMessageAuthenticator: true);

    private static byte[] Reject(RadiusPacket req, string secret, string why) =>
        RadiusPacket.BuildResponse(RadiusCode.AccessReject, req.Identifier, req.Authenticator,
            new[] { Reply(why) }, secret, withMessageAuthenticator: true);

    private static byte[] Challenge(RadiusPacket req, string secret, string stateToken) =>
        RadiusPacket.BuildResponse(RadiusCode.AccessChallenge, req.Identifier, req.Authenticator,
            new[]
            {
                new RadiusAttribute(RadiusAttr.State, Encoding.UTF8.GetBytes(stateToken)),
                Reply("Approve the sign-in on your phone."),
            }, secret, withMessageAuthenticator: true);

    private static RadiusAttribute Reply(string text) =>
        new(RadiusAttr.ReplyMessage, Encoding.UTF8.GetBytes(text));
}
