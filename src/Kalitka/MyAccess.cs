namespace Kalitka;

/// <summary>One thing a person currently holds: a live session, with when it ends and the bounds it
/// carries. "Access I have, until when, under which constraints."</summary>
public sealed record HeldAccess(
    string Resource, string SessionId, DateTimeOffset StartedAt, DateTimeOffset? ExpiresAt,
    string Profile, int RemainingUses);

/// <summary>An access request the person has in flight, still waiting on a human.</summary>
public sealed record PendingAsk(string Resource, string RequestId, DateTimeOffset Raised, string State);

/// <summary>The portal's "My access" view for one person.</summary>
public sealed record MyAccess(IReadOnlyList<HeldAccess> Held, IReadOnlyList<PendingAsk> Pending);

/// <summary>
/// Answers "what do I hold, and what have I asked for?" for a portal user, by matching a person's
/// operator-principal identities against the subject identity recorded on sessions and requests. A
/// principal with no console permission is simply an employee; this is the read surface that lets them
/// see their own access without being able to approve anything. Read-only; no new state.
/// </summary>
public sealed class MyAccessService
{
    private readonly ISessionStore _sessions;
    private readonly IRequestStore _requests;
    private readonly TimeProvider _clock;

    public MyAccessService(ISessionStore sessions, IRequestStore requests, TimeProvider? clock = null)
    {
        _sessions = sessions;
        _requests = requests;
        _clock = clock ?? TimeProvider.System;
    }

    public MyAccess For(OperatorPrincipal principal)
    {
        // The person's identities, normalised the same way subject identities are stored — a session
        // or request with no subject identity (pre-0.48, or a channel that asserts none) matches no
        // one, which is correct: it cannot be attributed to a person.
        var mine = new HashSet<string>(
            (principal.Identities ?? Array.Empty<string>()).Select(OperatorPrincipal.Normalize),
            StringComparer.Ordinal);
        var now = _clock.GetUtcNow();

        bool IsMine(string subjectIdentity) =>
            subjectIdentity.Length > 0 && mine.Contains(OperatorPrincipal.Normalize(subjectIdentity));

        var held = _sessions.Snapshot()
            .Where(s => s.EndedAt is null && (s.ExpiresAt is null || s.ExpiresAt > now) && IsMine(s.SubjectIdentity))
            .OrderByDescending(s => s.StartedAt)
            .Select(s => new HeldAccess(s.Resource, s.SessionId, s.StartedAt, s.ExpiresAt, s.Profile, s.RemainingUses))
            .ToList();

        var pending = _requests.Snapshot()
            .Where(r => r.State == "waiting" && IsMine(r.SubjectIdentity))
            .OrderByDescending(r => r.Raised)
            .Select(r => new PendingAsk(r.Resource, r.Id, r.Raised, r.State))
            .ToList();

        return new MyAccess(held, pending);
    }
}
