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
    private readonly IAtomicWork? _atomic;   // present only when state + audit share a transactional backend
    private readonly PolicyService? _policies;

    public GrantService(GateService gate, OneTimeTokenService tokens, IReplayStore replay,
        ISessionStore sessions, IAuditStore audit, IOptions<GateOptions> options,
        TimeProvider? clock = null, IAtomicWork? atomic = null, PolicyService? policies = null)
    {
        _gate = gate;
        _tokens = tokens;
        _replay = replay;
        _sessions = sessions;
        _audit = audit;
        _grantMinutes = options.Value.OneTimeMinutes;
        _clock = clock ?? TimeProvider.System;
        _atomic = atomic;
        _policies = policies;
    }

    /// <summary>The grant for an approved agent request (ssh:, db:, …), issued once. Null
    /// if the request is not approved, is not an agent resource, or the requesting agent is
    /// not scoped to redeem that resource — a valid credential is not a licence to
    /// collect the grant for a resource outside the agent's scope (this mirrors the
    /// check <see cref="Redeem"/> makes, so the grant is never even handed out to the
    /// wrong agent, and the <c>grant.created</c> event is attributed correctly).</summary>
    public async Task<string?> IssueGrant(string id, AgentIdentity agent, CancellationToken ct)
    {
        if (_gate.StateOf(id) != "approved") return null;
        var resource = _gate.ResourceOf(id) ?? "";
        // Any agent-brokered resource can be granted (ssh:, db:, sudo:, …) — but never a
        // web: visitor request, which is served by the gate flow, not a redeemable grant.
        if (resource.StartsWith("web:", StringComparison.Ordinal) || !resource.Contains(':')) return null;
        if (!agent.MayRepresent(resource, AgentCapabilities.Redeem)) return null;

        var subject = _gate.SubjectOf(id) ?? "";
        // A matching access policy may only SHORTEN the grant, never extend it beyond
        // the global lifetime (restrict-only), so the effective TTL is the min. The
        // request's profile lets the policy pick per operation class (e.g. sql-dba).
        var ttl = _grantMinutes;
        var policyTtl = _policies?.Effective(resource, agent.Tags, _gate.ProfileOf(id)).GrantTtlMinutes;
        if (policyTtl is > 0) ttl = Math.Min(ttl, policyTtl.Value);
        var (grant, created) = _gate.EnsureGrant(id, _tokens.MintGrant(resource, id, subject, ttl));
        if (created && _tokens.Read(grant) is { } cap)
            await _audit.Append(Event(AuditEvents.GrantCreated, agent.Actor, subject, resource, id, cap.GrantId, ""), ct);
        return grant;
    }

    public sealed record RedeemResult(bool Ok, string? SessionId = null, string? Error = null,
        string Profile = "", DateTimeOffset? ExpiresAt = null, string Subject = "", string Command = "",
        string SourceAddress = "");

    /// <summary>Redeem a grant exactly once and start a session. The redeeming agent
    /// must itself be allowed to represent the granted resource — a valid grant is not
    /// enough if this agent is not scoped to it. The canonical <c>agent_id</c> is
    /// recorded on the session; the self-reported hostname is only metadata. The
    /// session carries the bounded-grant profile and use budget, and the result returns
    /// the profile so the connector knows what to provision.</summary>
    public async Task<RedeemResult> Redeem(string token, AgentIdentity agent, string reportedHostname, CancellationToken ct)
    {
        var cap = _tokens.Read(token);
        if (cap is null || cap.Purpose != "ssh-grant") return new(false, Error: "invalid");

        // The approval must still stand and the resource must be the one granted.
        if (_gate.StateOf(cap.RequestId) != "approved" || _gate.ResourceOf(cap.RequestId) != cap.Resource)
            return new(false, Error: "not-approved");

        // The redeeming agent must be scoped to this resource, valid grant or not.
        if (!agent.MayRepresent(cap.Resource, AgentCapabilities.Redeem)) return new(false, Error: "forbidden");

        var profile = _gate.ProfileOf(cap.RequestId);
        var maxUses = _gate.MaxUsesOf(cap.RequestId);
        var command = _gate.CommandOf(cap.RequestId);
        var sourceAddr = _gate.SourceAddrOf(cap.RequestId);
        var sessionId = Guid.NewGuid().ToString("N");
        var session = new SessionRecord(sessionId, cap.GrantId, cap.RequestId, cap.Subject,
            cap.Resource, agent.IsLegacy ? "-" : agent.AgentId, _clock.GetUtcNow(), null, "", reportedHostname)
        { Profile = profile, RemainingUses = maxUses > 0 ? maxUses : -1, ExpiresAt = cap.ExpiresAt };
        var redeemed = Event(AuditEvents.GrantRedeemed, agent.Actor, cap.Subject, cap.Resource, cap.RequestId, cap.GrantId, "");
        var started = Event(AuditEvents.SessionStarted, agent.Actor, cap.Subject, cap.Resource, cap.RequestId, cap.GrantId, sessionId);

        // The invariant: if the grant is consumed, the started session and both
        // audit events exist too. When state and audit share a transactional
        // backend all four commit together — a failure of any one rolls back the
        // rest, so there is never a consumed grant without its session and history.
        // Otherwise the consume is the single atomic step and the rest are
        // best-effort (in-memory would lose them together on a crash anyway).
        if (_atomic is not null)
        {
            var ok = await _atomic.Do(scope =>
            {
                if (!scope.TryConsumeReplay(cap.Jti, cap.ExpiresAt)) return false;   // already used
                scope.StartSession(session);
                scope.AppendAudit(redeemed);
                scope.AppendAudit(started);
                return true;
            }, ct);
            return ok ? new(true, sessionId, Profile: profile, ExpiresAt: cap.ExpiresAt, Subject: cap.Subject, Command: command, SourceAddress: sourceAddr) : new(false, Error: "used");
        }

        if (!await _replay.TryConsumeAsync(cap.Jti, cap.ExpiresAt, ct)) return new(false, Error: "used");
        _sessions.Start(session);
        await _audit.Append(redeemed, ct);
        await _audit.Append(started, ct);
        return new(true, sessionId, Profile: profile, ExpiresAt: cap.ExpiresAt, Subject: cap.Subject, Command: command, SourceAddress: sourceAddr);
    }

    /// <summary>The connector reports the provisioning outcome for a session: applied
    /// (audited <c>session.provisioned</c>) or failed (the session is closed as
    /// <c>provision-failed</c>, since access was never really granted). Returns whether
    /// provisioning is considered applied. Revoking is reported via <see cref="EndSession"/>.</summary>
    public async Task<bool> ReportProvisioned(string sessionId, string? error, string actor, CancellationToken ct)
    {
        var s = _sessions.Get(sessionId);
        if (s is null) return false;
        if (!string.IsNullOrEmpty(error))
        {
            await EndSession(sessionId, "provision-failed", ct, actor);
            return false;
        }
        await _audit.Append(Event(AuditEvents.SessionProvisioned, actor, s.Subject, s.Resource,
            s.RequestId, s.GrantId, sessionId, s.Profile), ct);
        return true;
    }

    /// <summary>Report one use of a granted operation (the bounded-grant `max_uses`).
    /// Returns the uses left; when it hits 0 the session is closed (`spent`) — the
    /// connector then revokes provisioning. Unlimited sessions (no `max_uses`) always
    /// report -1. Null = no such open session (or already spent).</summary>
    public async Task<int?> ReportUse(string sessionId, string actor, CancellationToken ct)
    {
        var remaining = _sessions.TrySpendUse(sessionId);
        if (remaining is 0) await EndSession(sessionId, "spent", ct, actor);
        return remaining;
    }

    /// <summary>A live, queryable view of sessions (open and recently closed).</summary>
    public IReadOnlyList<SessionRecord> Sessions() => _sessions.Snapshot();

    /// <summary>One session by id, or null — used to authorize a connector's session
    /// operations against the session's resource.</summary>
    public SessionRecord? Session(string sessionId) => _sessions.Get(sessionId);

    /// <summary>Session liveness for a connector's crash-recovery pass: the effective
    /// state honouring the grant's own <see cref="SessionRecord.ExpiresAt"/> (a session
    /// past its expiry reads <c>expired</c> even before the sweep closes it), and that
    /// expiry so the agent can cache it. <c>unknown</c> = no such session.</summary>
    public (string State, DateTimeOffset? ExpiresAt) Liveness(string sessionId)
    {
        var s = _sessions.Get(sessionId);
        if (s is null) return ("unknown", null);
        if (s.EndedAt is not null) return (string.IsNullOrEmpty(s.Outcome) ? "ended" : s.Outcome, s.ExpiresAt);
        if (s.ExpiresAt is { } exp && exp <= _clock.GetUtcNow()) return ("expired", s.ExpiresAt);
        return ("open", s.ExpiresAt);
    }

    /// <summary>A connector reports a crash-recovery decision: it revoked provisioned access
    /// out of band, for <paramref name="reason"/> (<c>core-confirmed</c> | <c>local-expiry</c>
    /// | <c>orphan-max-age</c>). Always audits <c>session.reconciled</c> — so a cleanup made
    /// WITHOUT Core confirmation (orphan-max-age) is visible with its reason and the SQL
    /// principal that was removed — and closes the session if it was still open. Idempotent.</summary>
    public async Task<bool> ReconcileSession(string sessionId, string reason, string principal, string actor, CancellationToken ct)
    {
        var s = _sessions.Get(sessionId);
        if (s is not null && s.EndedAt is null) await EndSession(sessionId, reason, ct, actor);
        var meta = string.IsNullOrEmpty(principal) ? $"{sessionId} {reason}" : $"{sessionId} {reason} {principal}";
        await _audit.Append(new AuditEvent(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(),
            AuditEvents.SessionReconciled, actor, s?.Subject ?? "", s?.Resource ?? "",
            s?.RequestId ?? "", s?.GrantId ?? "", "ssh", meta), ct);
        return true;
    }

    /// <summary>Admin-close an open session out of band (outcome <c>revoked</c>),
    /// attributed to the admin, not the agent.</summary>
    public Task<bool> RevokeSession(string sessionId, string actor, CancellationToken ct) =>
        EndSession(sessionId, "revoked", ct, actor);

    /// <summary>Auto-close sessions left open longer than <paramref name="maxAge"/> — a
    /// crashed or missed close hook must not leave a session open forever. Each close is
    /// the same atomic, audited transition as a normal end (outcome <c>expired</c>).</summary>
    public async Task<int> ExpireStaleSessions(TimeSpan maxAge, CancellationToken ct)
    {
        if (maxAge <= TimeSpan.Zero) return 0;
        var cutoff = _clock.GetUtcNow() - maxAge;
        var n = 0;
        foreach (var s in _sessions.Snapshot())
            if (s.EndedAt is null && s.StartedAt < cutoff && await EndSession(s.SessionId, "expired", ct, "system"))
                n++;
        return n;
    }

    /// <summary>Close a session the agent reports as ended (or, with an explicit
    /// <paramref name="actor"/>, an admin revoke / system expiry).</summary>
    public async Task<bool> EndSession(string sessionId, string outcome, CancellationToken ct, string? actor = null)
    {
        var s = _sessions.Get(sessionId);
        if (s is null) return false;
        actor ??= string.IsNullOrEmpty(s.AgentId) || s.AgentId == "-" ? "agent" : $"agent:{s.AgentId}";
        var ended = Event(AuditEvents.SessionEnded, actor, s.Subject, s.Resource, s.RequestId, s.GrantId, sessionId, outcome);

        // Close and its event commit together when transactional; otherwise the
        // append is the best-effort second step. A repeat close matches no open row
        // and returns false — harmless, not a second transition.
        if (_atomic is not null)
        {
            return await _atomic.Do(scope =>
            {
                if (!scope.EndSession(sessionId, outcome, _clock.GetUtcNow())) return false;
                scope.AppendAudit(ended);
                return true;
            }, ct);
        }

        if (!_sessions.End(sessionId, outcome, _clock.GetUtcNow())) return false;
        await _audit.Append(ended, ct);
        return true;
    }

    private AuditEvent Event(string type, string actor, string subject, string resource, string requestId,
        string grantId, string sessionId, string outcome = "") =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor, subject, resource,
            requestId, grantId, "ssh", string.IsNullOrEmpty(outcome) ? sessionId : $"{sessionId} {outcome}");
}
