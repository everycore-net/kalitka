using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Device enrolment: an admin issues a one-time invite for a person (by IdP e-mail); the person
/// opens it, <b>signs in through the corporate IdP</b>, and — only if the proven identity matches the
/// invite — is granted approve rights and a session, from which they register a passkey (Slice A) and
/// enable push (Slice B). The IdP sign-in is the load-bearing check: an intercepted invite cannot
/// enrol a stranger's device, because the invite is bound to a specific account and burned once.
///
/// The invite is a stateless one-time capability (<see cref="OneTimeTokenService"/> + replay burn);
/// nothing is stored server-side until the person actually enrols.
/// </summary>
public sealed class EnrollService
{
    private const string Purpose = "enroll";
    private const string StateKey = "enroll-state:v1";
    private const int StateMinutes = 15;

    private readonly GoogleAuth _google;
    private readonly OneTimeTokenService _tokens;
    private readonly IReplayStore _replay;
    private readonly PrincipalService _principals;
    private readonly OperatorApprovers _approvers;
    private readonly TokenSigner _signer;
    private readonly IAuditStore _audit;
    private readonly GateOptions _options;
    private readonly TimeProvider _clock;

    public EnrollService(GoogleAuth google, OneTimeTokenService tokens, IReplayStore replay,
        PrincipalService principals, OperatorApprovers approvers, TokenSigner signer, IAuditStore audit,
        IOptions<GateOptions> options, TimeProvider? clock = null)
    {
        _google = google;
        _tokens = tokens;
        _replay = replay;
        _principals = principals;
        _approvers = approvers;
        _signer = signer;
        _audit = audit;
        _options = options.Value;
        _clock = clock ?? TimeProvider.System;
    }

    public bool Enabled => _google.Enabled;

    /// <summary>Mint an invite for <paramref name="email"/> and return the link to send. The display
    /// name rides in the capability so the created principal is labelled.</summary>
    public async Task<string> Invite(string email, string displayName, string actor, CancellationToken ct)
    {
        var e = Norm(email);
        var token = _tokens.Mint(Purpose, e, Guid.NewGuid().ToString("N"), (displayName ?? "").Trim(), _options.EnrollmentInviteMinutes);
        await _audit.Append(Ev(AuditEvents.EnrollInvited, actor, e), ct);
        return $"https://{_options.GateHost}/enroll?t={Uri.EscapeDataString(token)}";
    }

    /// <summary>The Google URL to send the invitee to, carrying a signed state (the invite token +
    /// browser nonce + expiry). Null if the invite is not a valid, unexpired enrol capability.</summary>
    public string? StartUrl(string inviteToken, string nonce)
    {
        var cap = _tokens.Read(inviteToken);
        if (cap is null || cap.Purpose != Purpose) return null;
        var exp = _clock.GetUtcNow().AddMinutes(StateMinutes).ToUnixTimeSeconds();
        var state = _signer.Sign($"{exp}|{nonce}|{inviteToken}", StateKey);
        return _google.AuthorizationUrl(state, _google.EnrollRedirectUri);
    }

    public sealed record EnrollResult(bool Ok, string? Error = null, AdminIdentity? Identity = null);

    /// <summary>Complete the callback: the state must be intact and browser-bound, the invite still
    /// valid and unused, and the IdP-proven e-mail must match the invite. Grants approve rights and
    /// links the principal, then returns the identity for a session.</summary>
    public async Task<EnrollResult> Complete(string code, string state, string nonce, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(code) || !_signer.Verify(state, StateKey, out var payload))
            return new EnrollResult(false, "This enrolment link is invalid.");
        var parts = payload.Split('|', 3);
        if (parts.Length != 3 || !long.TryParse(parts[0], out var exp)) return new EnrollResult(false, "This enrolment link is invalid.");
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return new EnrollResult(false, "This enrolment link has expired.");
        if (!SessionService.NonceMatches(parts[1], nonce)) return new EnrollResult(false, "Open the invite in the same browser.");

        var cap = _tokens.Read(parts[2]);
        if (cap is null || cap.Purpose != Purpose) return new EnrollResult(false, "This invite has expired.");

        var identity = await _google.ResolveIdentity(code, _google.EnrollRedirectUri, ct);
        if (identity is null) return new EnrollResult(false, "Sign-in was not accepted.");
        if (!string.Equals(Norm(identity.Value.Email), cap.Resource, StringComparison.Ordinal))
            return new EnrollResult(false, "This invite is for a different account.");

        // One-time: burn the invite so it cannot enrol a second device later.
        if (!await _replay.TryConsumeAsync("enroll:" + cap.Jti, cap.ExpiresAt, ct))
            return new EnrollResult(false, "This invite has already been used.");

        var actor = "google:" + identity.Value.Sub;
        await _approvers.Grant(identity.Value.Email, actor, ct);
        await EnsurePrincipal(identity.Value.Sub, identity.Value.Email, cap.Action, ct);
        await _audit.Append(Ev(AuditEvents.EnrollCompleted, actor, identity.Value.Email), ct);
        return new EnrollResult(true, Identity: new AdminIdentity(identity.Value.Sub, identity.Value.Email));
    }

    private async Task EnsurePrincipal(string sub, string email, string displayName, CancellationToken ct)
    {
        var actor = "google:" + sub;
        if (_principals.Resolve(actor) is not null) return;
        await _principals.Save("op-" + sub, string.IsNullOrWhiteSpace(displayName) ? email : displayName,
            new[] { actor }, actor, ct);
    }

    private static string Norm(string email) => (email ?? "").Trim().ToLowerInvariant();

    private AuditEvent Ev(string type, string actor, string email) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: email, Resource: "", RequestId: "", GrantId: "", Channel: "admin", Metadata: "");
}
