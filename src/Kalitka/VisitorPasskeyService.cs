using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>The outcome of a passkey login: whether it passed, and the scope of the session to mint
/// (domain-wide when the credential was remembered domain-wide).</summary>
public sealed record VisitorLoginResult(bool Ok, string? Error = null, bool DomainScope = false, string Label = "");

/// <summary>
/// Passkey as a way past the gate (fido2 slice 1) — the visitor side. A visitor cannot self-register:
/// a passkey is bound only after a normal approval (the register endpoints require a valid session for
/// the target), so this is "remember this device" made cryptographic, not an identity provider. On a
/// later visit the assertion proves a credential we registered and the gate mints the same session a
/// manual approval would. Reuses every crypto primitive (<see cref="WebAuthn"/>, the signature suites,
/// <see cref="TokenSigner"/>, <see cref="IReplayStore"/>); it shares nothing with the operator/agent
/// populations — a visitor credential only lets its holder in.
/// </summary>
public sealed class VisitorPasskeyService
{
    private const string RegKey = "visitor-reg:v1";
    private const string LoginKey = "visitor-login:v1";

    private readonly VisitorPasskeyStore _store;
    private readonly TokenSigner _signer;
    private readonly IReplayStore _replay;
    private readonly IAuditStore _audit;
    private readonly GateOptions _options;
    private readonly TimeProvider _clock;

    public VisitorPasskeyService(VisitorPasskeyStore store, TokenSigner signer, IReplayStore replay,
        IAuditStore audit, IOptions<GateOptions> options, TimeProvider clock)
    {
        _store = store;
        _signer = signer;
        _replay = replay;
        _audit = audit;
        _options = options.Value;
        _clock = clock;
    }

    private string RpId => string.IsNullOrEmpty(_options.WebAuthnRpId) ? _options.GateHost : _options.WebAuthnRpId;
    private string Origin => string.IsNullOrEmpty(_options.WebAuthnOrigin) ? "https://" + _options.GateHost : _options.WebAuthnOrigin;
    private string Uv => _options.WebAuthnUserVerification == "required" ? "required" : "preferred";
    private int TimeoutMs => Math.Max(1, _options.WebAuthnChallengeMinutes) * 60_000;

    // ---- Register "remember this device" (only after approval) --------------

    public WebAuthnBegin RegisterBegin(string target, string label)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var userId = RandomNumberGenerator.GetBytes(16);   // no server identity for a visitor; a random handle
        var options = new
        {
            rp = new { id = RpId, name = "kalitka" },
            user = new { id = Base64Url.Encode(userId), name = $"{label}@{target}", displayName = label },
            challenge = Base64Url.Encode(challenge),
            pubKeyCredParams = new[] { new { type = "public-key", alg = -7 }, new { type = "public-key", alg = -8 } },
            // Resident/discoverable: at login we have no identity to pre-select, so the authenticator
            // must offer its own stored credentials.
            authenticatorSelection = new { userVerification = Uv, residentKey = "required", requireResidentKey = true },
            attestation = "none",
            timeout = TimeoutMs,
        };
        var state = new RegState(Base64Url.Encode(challenge), target, label, Exp());
        return new WebAuthnBegin(JsonSerializer.Serialize(options), _signer.Sign(JsonSerializer.Serialize(state), RegKey));
    }

    public async Task<string?> RegisterFinish(string target, string state, string attestationObject, string clientDataJson, CancellationToken ct)
    {
        if (!_signer.Verify(state, RegKey, out var payload)) return "registration challenge invalid";
        var st = JsonSerializer.Deserialize<RegState>(payload);
        if (st is null || !string.Equals(st.target, target, StringComparison.OrdinalIgnoreCase)) return "registration challenge not for this host";
        if (Expired(st.exp)) return "registration challenge expired";

        if (!Base64Url.TryDecode(clientDataJson, out var cdj)) return "bad clientDataJSON";
        ClientData cd;
        try { cd = WebAuthn.ParseClientData(cdj); } catch (WebAuthnException e) { return e.Message; }
        if (cd.Type != "webauthn.create") return "wrong ceremony type";
        if (!ChallengeMatches(cd.Challenge, st.c)) return "challenge mismatch";
        if (!string.Equals(cd.Origin, Origin, StringComparison.Ordinal)) return "origin mismatch";

        if (!Base64Url.TryDecode(attestationObject, out var att)) return "bad attestationObject";
        AuthData ad;
        try { ad = WebAuthn.ParseAttestationObject(att); } catch (WebAuthnException e) { return e.Message; }
        if (!RpIdMatches(ad.RpIdHash)) return "RP ID mismatch";
        if (!ad.UserPresent) return "user not present";
        if (Uv == "required" && !ad.UserVerified) return "user verification required";
        if (ad.CredentialId is null || ad.CosePublicKey is null) return "no attested credential";

        string spki; int alg;
        try { (spki, alg) = WebAuthn.CoseKeyToSpki(ad.CosePublicKey); } catch (WebAuthnException e) { return e.Message; }

        // The scope follows SessionScope, exactly like a minted session: one host by default, the
        // whole guarded domain only on explicit opt-in (the 0.4.0 lesson).
        var scope = _options.SessionScope == SessionScope.Domain ? "web:*" : "web:" + target;
        _store.Add(new VisitorPasskey(Base64Url.Encode(ad.CredentialId), spki, alg, ad.SignCount, scope,
            st.label, ad.BackupEligible, Revoked: false, Now(), Now()));
        await _audit.Append(Ev(AuditEvents.PasskeyRemembered, "web:" + target, st.label, scope), ct);
        return null;
    }

    // ---- Login: prove a remembered device, get past the gate ---------------

    public WebAuthnBegin LoginBegin(string target)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var nonce = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
        var options = new
        {
            challenge = Base64Url.Encode(challenge),
            rpId = RpId,
            // Discoverable: no allowCredentials — the authenticator offers its own stored keys.
            userVerification = Uv,
            timeout = TimeoutMs,
        };
        var state = new LoginState(Base64Url.Encode(challenge), target, nonce, Exp());
        return new WebAuthnBegin(JsonSerializer.Serialize(options), _signer.Sign(JsonSerializer.Serialize(state), LoginKey));
    }

    public async Task<VisitorLoginResult> LoginFinish(string target, string state, string credentialId,
        string authenticatorData, string clientDataJson, string signature, CancellationToken ct)
    {
        if (!_signer.Verify(state, LoginKey, out var payload)) return Fail("login challenge invalid");
        var st = JsonSerializer.Deserialize<LoginState>(payload);
        if (st is null || !string.Equals(st.target, target, StringComparison.OrdinalIgnoreCase)) return Fail("login challenge not for this host");
        if (Expired(st.exp)) return Fail("login challenge expired");

        if (!Base64Url.TryDecode(clientDataJson, out var cdj)) return Fail("bad clientDataJSON");
        ClientData cd;
        try { cd = WebAuthn.ParseClientData(cdj); } catch (WebAuthnException e) { return Fail(e.Message); }
        if (cd.Type != "webauthn.get") return Fail("wrong ceremony type");
        if (!string.Equals(cd.Origin, Origin, StringComparison.Ordinal)) return Fail("origin mismatch");
        if (!ChallengeMatches(cd.Challenge, st.c)) return Fail("challenge mismatch");

        if (!Base64Url.TryDecode(authenticatorData, out var authData)) return Fail("bad authenticatorData");
        AuthData ad;
        try { ad = WebAuthn.ParseAuthData(authData); } catch (WebAuthnException e) { return Fail(e.Message); }
        if (!RpIdMatches(ad.RpIdHash)) return Fail("RP ID mismatch");
        if (!ad.UserPresent) return Fail("user not present");
        if (Uv == "required" && !ad.UserVerified) return Fail("user verification required");

        var cred = _store.ByCredentialId(credentialId);
        if (cred is null) return Fail("unknown device");
        if (cred.Revoked) return Fail("this device has been blocked");     // revoked = blocked
        if (!cred.Covers(target)) return Fail("this device is not remembered for this host");
        if (_options.WebAuthnRequireDeviceBound && cred.BackupEligible) return Fail("this host requires a device-bound key");

        // One-time: burn the login nonce so a captured assertion cannot be replayed.
        if (!await _replay.TryConsumeAsync("vp:" + st.nonce, _clock.GetUtcNow().AddMinutes(_options.WebAuthnChallengeMinutes + 1), ct))
            return Fail("login already used");

        if (!Base64Url.TryDecode(signature, out var sig)) return Fail("bad signature");
        byte[] spki;
        try { spki = Convert.FromBase64String(cred.PublicKeySpki); } catch { return Fail("stored key corrupt"); }
        var suite = AgentSignatureSuites.For(spki);
        if (suite is null) return Fail("no verifier for this key");
        var message = WebAuthn.SignedMessage(authData, cdj);
        var wireSig = suite.Name == "ecdsa-p256" ? WebAuthn.DerToP1363(sig) : sig;
        if (!suite.Verify(spki, message, wireSig)) return Fail("signature did not verify");

        if (cred.SignCount > 0 && ad.SignCount != 0 && ad.SignCount <= cred.SignCount)
        {
            await _audit.Append(Ev(AuditEvents.WebAuthnCloneAlarm, "web:" + target, cred.Label, $"counter {ad.SignCount} <= {cred.SignCount}"), ct);
            return Fail("signature counter regressed — possible cloned key");
        }
        _store.RecordUse(cred.CredentialId, ad.SignCount, Now());
        await _audit.Append(Ev(AuditEvents.PasskeyUsed, "web:" + target, cred.Label, cred.Fingerprint), ct);
        return new VisitorLoginResult(true, DomainScope: string.Equals(cred.Scope, "web:*", StringComparison.OrdinalIgnoreCase), Label: cred.Label);
    }

    // ---- helpers -----------------------------------------------------------

    private long Exp() => _clock.GetUtcNow().AddMinutes(_options.WebAuthnChallengeMinutes).ToUnixTimeSeconds();
    private bool Expired(long exp) => _clock.GetUtcNow().ToUnixTimeSeconds() > exp;
    private string Now() => _clock.GetUtcNow().ToString("O");

    private bool RpIdMatches(byte[] rpIdHash) =>
        CryptographicOperations.FixedTimeEquals(rpIdHash, SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(RpId)));

    private static bool ChallengeMatches(string fromClient, string expectedB64Url)
    {
        if (!Base64Url.TryDecode(fromClient, out var a) || !Base64Url.TryDecode(expectedB64Url, out var b)) return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static VisitorLoginResult Fail(string error) => new(false, error);

    private AuditEvent Ev(string type, string resource, string label, string metadata) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, "passkey",
            Subject: label, Resource: resource, RequestId: "", GrantId: "", Channel: "gate", Metadata: metadata);

    private sealed record RegState(string c, string target, string label, long exp);
    private sealed record LoginState(string c, string target, string nonce, long exp);
}
