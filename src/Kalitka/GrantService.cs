using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The bridge between "an admin approved" and "the access was used". On an
/// approved SSH request it issues a short-lived, single-use grant; the agent
/// redeems it exactly once to start a session; the agent reports when the session
/// ends. This is where <see cref="IReplayStore"/> gets its PAM consumer and where
/// the grant.* / session.* audit events come from — so the log no longer pretends
/// that an approval is the same thing as an SSH session.
/// </summary>
public sealed class GrantService
{
    private readonly GateService _gate;
    private readonly OneTimeTokenService _tokens;
    private readonly IReplayStore _replay;
    private readonly ISessionStore _sessions;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly int _grantMinutes;

    public GrantService(GateService gate, OneTimeTokenService tokens, IReplayStore replay,
        ISessionStore sessions, IAuditStore audit, IOptions<GateOptions> options, TimeProvider? clock = null)
    {
        _gate = gate;
        _tokens = tokens;
        _replay = replay;
        _sessions = sessions;
        _audit = audit;
        _grantMinutes = options.Value.OneTimeMinutes;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>The grant for an approved SSH request, issued once. Null if the
    /// request is not approved or is not an agent resource.</summary>
    public async Task<string?> IssueGrant(string id, CancellationToken ct)
    {
        if (_gate.StateOf(id) != "approved") return null;
        var resource = _gate.ResourceOf(id) ?? "";
        if (!resource.StartsWith("ssh:", StringComparison.Ordinal)) return null;

        var subject = _gate.SubjectOf(id) ?? "";
        var (grant, created) = _gate.EnsureGrant(id, _tokens.MintGrant(resource, id, subject, _grantMinutes));
        if (created && _tokens.Read(grant) is { } cap)
            await _audit.Append(Event(AuditEvents.GrantCreated, subject, resource, id, cap.GrantId, ""), ct);
        return grant;
    }

    public sealed record RedeemResult(bool Ok, string? SessionId = null, string? Error = null);

    /// <summary>Redeem a grant exactly once and start a session.</summary>
    public async Task<RedeemResult> Redeem(string token, string agentId, CancellationToken ct)
    {
        var cap = _tokens.Read(token);
        if (cap is null || cap.Purpose != "ssh-grant") return new(false, Error: "invalid");

        // The approval must still stand and the resource must be the one granted.
        if (_gate.StateOf(cap.RequestId) != "approved" || _gate.ResourceOf(cap.RequestId) != cap.Resource)
            return new(false, Error: "not-approved");

        // Single use — the one atomic step that makes a grant a capability.
        if (!await _replay.TryConsumeAsync(cap.Jti, cap.ExpiresAt, ct)) return new(false, Error: "used");

        var sessionId = Guid.NewGuid().ToString("N");
        _sessions.Start(new SessionRecord(sessionId, cap.GrantId, cap.RequestId, cap.Subject,
            cap.Resource, string.IsNullOrEmpty(agentId) ? "-" : agentId, _clock.GetUtcNow(), null, "", ""));

        await _audit.Append(Event(AuditEvents.GrantRedeemed, cap.Subject, cap.Resource, cap.RequestId, cap.GrantId, ""), ct);
        await _audit.Append(Event(AuditEvents.SessionStarted, cap.Subject, cap.Resource, cap.RequestId, cap.GrantId, sessionId), ct);
        return new(true, sessionId);
    }

    /// <summary>Close a session the agent reports as ended.</summary>
    public async Task<bool> EndSession(string sessionId, string outcome, CancellationToken ct)
    {
        var s = _sessions.Get(sessionId);
        if (s is null || !_sessions.End(sessionId, outcome, _clock.GetUtcNow())) return false;
        await _audit.Append(Event(AuditEvents.SessionEnded, s.Subject, s.Resource, s.RequestId, s.GrantId, sessionId,
            outcome), ct);
        return true;
    }

    private AuditEvent Event(string type, string subject, string resource, string requestId,
        string grantId, string sessionId, string outcome = "") =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, "agent", subject, resource,
            requestId, grantId, "ssh", string.IsNullOrEmpty(outcome) ? sessionId : $"{sessionId} {outcome}");
}
