using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>Options for a WebAuthn ceremony, plus the stateless signed state token the client echoes
/// back so the server keeps no per-ceremony storage.</summary>
public sealed record WebAuthnBegin(string OptionsJson, string State);

/// <summary>The fields a browser returns from <c>navigator.credentials.get</c>, base64url.</summary>
public sealed record SignedDecisionInput(
    string State, string CredentialId, string AuthenticatorData, string ClientDataJson, string Signature);

/// <summary>The outcome of verifying a signed decision: the actor to record (the device identity),
/// and the proof to store with the audit event; or an error.</summary>
public sealed record SignedDecisionResult(bool Ok, string? Error, string Actor = "", string Proof = "");

/// <summary>
/// Passkey registration (fido2 slice 1) and device-signed approval (slice 2). The WebAuthn challenge
/// for an approval <b>is</b> the <see cref="ApprovalEnvelope"/>, so the assertion signs this exact
/// decision. Ceremonies are stateless: the challenge and its binding travel in a
/// <see cref="TokenSigner"/> token the client returns, and the approval nonce is burned once via
/// <see cref="IReplayStore"/>. Signatures are verified through the same <see cref="IAgentSignatureSuite"/>
/// as agents.
/// </summary>
public sealed class WebAuthnService
{
    private const string RegKey = "webauthn-reg:v1";
    private const string ApproveKey = "webauthn-approve:v1";

    private readonly WebAuthnStore _store;
    private readonly PrincipalService _principals;
    private readonly TokenSigner _signer;
    private readonly IReplayStore _replay;
    private readonly IAuditStore _audit;
    private readonly GateOptions _options;
    private readonly TimeProvider _clock;
    private readonly PushSubscriptionStore? _push;

    public WebAuthnService(WebAuthnStore store, PrincipalService principals, TokenSigner signer,
        IReplayStore replay, IAuditStore audit, IOptions<GateOptions> options, TimeProvider clock,
        PushSubscriptionStore? push = null)
    {
        _store = store;
        _principals = principals;
        _signer = signer;
        _replay = replay;
        _audit = audit;
        _options = options.Value;
        _clock = clock;
        _push = push;
    }

    private string RpId => string.IsNullOrEmpty(_options.WebAuthnRpId) ? _options.GateHost : _options.WebAuthnRpId;
    private string Origin => string.IsNullOrEmpty(_options.WebAuthnOrigin) ? "https://" + _options.GateHost : _options.WebAuthnOrigin;
    private string Uv => _options.WebAuthnUserVerification == "required" ? "required" : "preferred";
    private int TimeoutMs => Math.Max(1, _options.WebAuthnChallengeMinutes) * 60_000;

    public IReadOnlyList<WebAuthnCredential> DevicesFor(AdminIdentity who)
    {
        var pid = _principals.Resolve(who.Actor);
        return pid is null ? Array.Empty<WebAuthnCredential>() : _store.ForPrincipal(pid);
    }

    // ---- Registration (fido2 slice 1) --------------------------------------

    public WebAuthnBegin RegisterBegin(AdminIdentity who)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var exclude = DevicesFor(who).Select(c => new { type = "public-key", id = c.CredentialId }).ToArray();
        var options = new
        {
            rp = new { id = RpId, name = "kalitka" },
            user = new { id = Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(who.Sub)), name = who.Email, displayName = who.Email },
            challenge = Base64Url.Encode(challenge),
            pubKeyCredParams = new[] { new { type = "public-key", alg = -7 }, new { type = "public-key", alg = -8 } },
            authenticatorSelection = new { userVerification = Uv, residentKey = "preferred" },
            attestation = "none",
            excludeCredentials = exclude,
            timeout = TimeoutMs,
        };
        var state = new { c = Base64Url.Encode(challenge), sub = who.Sub, exp = Exp() };
        return new WebAuthnBegin(JsonSerializer.Serialize(options), _signer.Sign(JsonSerializer.Serialize(state), RegKey));
    }

    public async Task<string?> RegisterFinish(AdminIdentity who, string state, string credentialId,
        string attestationObject, string clientDataJson, string displayName, CancellationToken ct)
    {
        if (!_signer.Verify(state, RegKey, out var payload)) return "registration challenge invalid";
        var st = JsonSerializer.Deserialize<RegState>(payload);
        if (st is null || st.sub != who.Sub) return "registration challenge not for this session";
        if (Expired(st.exp)) return "registration challenge expired";

        if (!Base64Url.TryDecode(clientDataJson, out var cdjBytes)) return "bad clientDataJSON";
        ClientData cd;
        try { cd = WebAuthn.ParseClientData(cdjBytes); } catch (WebAuthnException e) { return e.Message; }
        if (cd.Type != "webauthn.create") return "wrong ceremony type";
        if (!ChallengeMatches(cd.Challenge, st.c)) return "challenge mismatch";
        if (!string.Equals(cd.Origin, Origin, StringComparison.Ordinal)) return "origin mismatch";

        if (!Base64Url.TryDecode(attestationObject, out var attObj)) return "bad attestationObject";
        AuthData ad;
        try { ad = WebAuthn.ParseAttestationObject(attObj); } catch (WebAuthnException e) { return e.Message; }
        if (!RpIdMatches(ad.RpIdHash)) return "RP ID mismatch";
        if (!ad.UserPresent) return "user not present";
        if (Uv == "required" && !ad.UserVerified) return "user verification required";
        if (ad.CredentialId is null || ad.CosePublicKey is null) return "no attested credential";

        string spki; int alg;
        try { (spki, alg) = WebAuthn.CoseKeyToSpki(ad.CosePublicKey); } catch (WebAuthnException e) { return e.Message; }

        var credId = Base64Url.Encode(ad.CredentialId);
        var principalId = await LinkDevice(who, credId, ct);

        _store.Add(new WebAuthnCredential(credId, spki, alg, ad.SignCount, principalId,
            string.IsNullOrWhiteSpace(displayName) ? "device" : displayName.Trim(),
            ad.BackupEligible, Now(), Now()));

        await _audit.Append(Ev(AuditEvents.WebAuthnRegistered, who.Actor, principalId,
            $"{(ad.BackupEligible ? "synced" : "device-bound")} alg={alg}"), ct);
        return null;
    }

    // Ensure the operator has a principal and link this device's identity to it, so a decision the
    // device signs counts as that human in the quorum — and is provably the same person as their
    // admin login.
    private async Task<string> LinkDevice(AdminIdentity who, string credId, CancellationToken ct)
    {
        var identity = "app:" + credId;
        var pid = _principals.Resolve(who.Actor);
        if (pid is not null)
        {
            var p = _principals.Get(pid)!;
            await _principals.Save(pid, p.DisplayName, p.Identities.Append(identity), who.Actor, ct);
            return pid;
        }
        pid = "op-" + who.Sub;
        await _principals.Save(pid, who.Email, new[] { who.Actor, identity }, who.Actor, ct);
        return pid;
    }

    public async Task<bool> RemoveDevice(AdminIdentity who, string credentialId, CancellationToken ct)
    {
        var cred = _store.ByCredentialId(credentialId);
        if (cred is null || !string.Equals(cred.PrincipalId, _principals.Resolve(who.Actor), StringComparison.OrdinalIgnoreCase))
            return false;   // only the owner may revoke their own device
        // Unlink the identity too, so it no longer resolves in the quorum.
        var p = _principals.Get(cred.PrincipalId);
        if (p is not null)
            await _principals.Save(p.Id, p.DisplayName, p.Identities.Where(i => i != cred.Identity), who.Actor, ct);
        var removed = _store.Remove(credentialId);
        if (removed)
        {
            _push?.RemoveForPrincipal(cred.PrincipalId);   // a revoked device stops receiving pushes
            await _audit.Append(Ev(AuditEvents.WebAuthnRemoved, who.Actor, cred.PrincipalId, cred.DisplayName), ct);
        }
        return removed;
    }

    /// <summary>Every registered device across all operators — for an admin's device management.</summary>
    public IReadOnlyList<WebAuthnCredential> AllDevices() => _store.All();

    /// <summary>An admin revokes any device (not just their own): remove it and unlink its identity so
    /// it no longer resolves in the quorum. Audited under the acting admin.</summary>
    public async Task<bool> AdminRemove(string credentialId, string actor, CancellationToken ct)
    {
        var cred = _store.ByCredentialId(credentialId);
        if (cred is null) return false;
        var p = _principals.Get(cred.PrincipalId);
        if (p is not null)
            await _principals.Save(p.Id, p.DisplayName, p.Identities.Where(i => i != cred.Identity), actor, ct);
        var removed = _store.Remove(credentialId);
        if (removed)
        {
            _push?.RemoveForPrincipal(cred.PrincipalId);   // a revoked device stops receiving pushes
            await _audit.Append(Ev(AuditEvents.WebAuthnRemoved, actor, cred.PrincipalId, cred.DisplayName), ct);
        }
        return removed;
    }

    // ---- Signed approval (fido2 slice 2) -----------------------------------

    public WebAuthnBegin ApproveBegin(AdminIdentity who, ApprovalContext req, string verb)
    {
        var ts = _clock.GetUtcNow().ToUnixTimeMilliseconds();
        var nonce = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
        var policyHash = ApprovalEnvelope.PolicyContextHash(req);
        var challenge = ApprovalEnvelope.Build(req.Id, verb, ts, policyHash, nonce);
        var allow = DevicesFor(who).Select(c => new { type = "public-key", id = c.CredentialId }).ToArray();

        var options = new
        {
            challenge = Base64Url.Encode(challenge),
            rpId = RpId,
            allowCredentials = allow,
            userVerification = Uv,
            timeout = TimeoutMs,
        };
        var state = new ApproveState(req.Id, verb, ts, policyHash, nonce, who.Sub, Exp());
        return new WebAuthnBegin(JsonSerializer.Serialize(options), _signer.Sign(JsonSerializer.Serialize(state), ApproveKey));
    }

    public async Task<SignedDecisionResult> ApproveVerify(AdminIdentity who, ApprovalContext req, string verb,
        SignedDecisionInput input, CancellationToken ct)
    {
        if (!_signer.Verify(input.State, ApproveKey, out var payload)) return Fail("approval challenge invalid");
        var st = JsonSerializer.Deserialize<ApproveState>(payload);
        if (st is null) return Fail("approval challenge unreadable");
        if (st.sub != who.Sub) return Fail("approval challenge not for this session");
        if (st.reqId != req.Id || st.verb != verb) return Fail("approval challenge does not match this decision");
        if (Expired(st.exp)) return Fail("approval challenge expired");
        // The policy terms must not have changed between begin and finish.
        if (!string.Equals(st.policyHash, ApprovalEnvelope.PolicyContextHash(req), StringComparison.Ordinal))
            return Fail("the request changed since the challenge was issued");

        if (!Base64Url.TryDecode(input.ClientDataJson, out var cdjBytes)) return Fail("bad clientDataJSON");
        ClientData cd;
        try { cd = WebAuthn.ParseClientData(cdjBytes); } catch (WebAuthnException e) { return Fail(e.Message); }
        if (cd.Type != "webauthn.get") return Fail("wrong ceremony type");
        if (!string.Equals(cd.Origin, Origin, StringComparison.Ordinal)) return Fail("origin mismatch");
        var expectedChallenge = ApprovalEnvelope.Build(st.reqId, st.verb, st.ts, st.policyHash, st.nonce);
        if (!ChallengeMatches(cd.Challenge, Base64Url.Encode(expectedChallenge))) return Fail("challenge mismatch");

        if (!Base64Url.TryDecode(input.AuthenticatorData, out var authData)) return Fail("bad authenticatorData");
        AuthData ad;
        try { ad = WebAuthn.ParseAuthData(authData); } catch (WebAuthnException e) { return Fail(e.Message); }
        if (!RpIdMatches(ad.RpIdHash)) return Fail("RP ID mismatch");
        if (!ad.UserPresent) return Fail("user not present");
        if (Uv == "required" && !ad.UserVerified) return Fail("user verification required");

        var cred = _store.ByCredentialId(input.CredentialId);
        if (cred is null) return Fail("unknown credential");
        if (!string.Equals(cred.PrincipalId, _principals.Resolve(who.Actor), StringComparison.OrdinalIgnoreCase))
            return Fail("credential does not belong to this operator");
        if (_options.WebAuthnRequireDeviceBound && cred.BackupEligible)
            return Fail("this resource requires a device-bound key; this passkey is cloud-synced");

        // Burn the nonce exactly once — a captured assertion cannot be replayed.
        if (!await _replay.TryConsumeAsync("wa:" + st.nonce, _clock.GetUtcNow().AddMinutes(_options.WebAuthnChallengeMinutes + 1), ct))
            return Fail("approval already used");

        if (!Base64Url.TryDecode(input.Signature, out var sig)) return Fail("bad signature");
        byte[] spki;
        try { spki = Convert.FromBase64String(cred.PublicKeySpki); } catch { return Fail("stored key corrupt"); }

        var suite = AgentSignatureSuites.For(spki);
        if (suite is null) return Fail("no verifier for this key");
        var message = WebAuthn.SignedMessage(authData, cdjBytes);
        // ES256 assertions are DER; the P-256 suite wants IEEE-P1363. EdDSA is raw already.
        byte[] wireSig = suite.Name == "ecdsa-p256" ? WebAuthn.DerToP1363(sig) : sig;
        if (!suite.Verify(spki, message, wireSig)) return Fail("signature did not verify");

        // Clone detection: a counter that goes backwards (when the authenticator uses one at all)
        // means two copies of the key are in use. Zero/absent is normal for many authenticators.
        if (cred.SignCount > 0 && ad.SignCount != 0 && ad.SignCount <= cred.SignCount)
        {
            await _audit.Append(Ev(AuditEvents.WebAuthnCloneAlarm, cred.Identity, cred.PrincipalId,
                $"counter {ad.SignCount} <= stored {cred.SignCount}"), ct);
            return Fail("signature counter regressed — possible cloned key");
        }
        _store.RecordUse(cred.CredentialId, ad.SignCount, Now());

        var proof = new WebAuthnProof(Base64Url.Decode(input.CredentialId), authData, cdjBytes, sig).Encode();
        return new SignedDecisionResult(true, null, cred.Identity, proof);
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

    private static SignedDecisionResult Fail(string error) => new(false, error);

    private AuditEvent Ev(string type, string actor, string principalId, string metadata) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: principalId, Resource: "", RequestId: "", GrantId: "", Channel: "web", Metadata: metadata);

    private sealed record RegState(string c, string sub, long exp);
    private sealed record ApproveState(string reqId, string verb, long ts, string policyHash, string nonce, string sub, long exp);
}
