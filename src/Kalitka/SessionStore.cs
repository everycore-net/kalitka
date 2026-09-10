using System.Collections.Concurrent;

namespace Kalitka;

/// <summary>
/// A record of an actually-used grant — the thing that proves access happened, as
/// opposed to merely being approved. Populated at redemption (start) and closed
/// when the agent reports the session ended.
/// </summary>
public sealed record SessionRecord(
    string SessionId,
    string GrantId,
    string RequestId,
    string Subject,
    string Resource,
    string AgentId,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    string Outcome,
    string Metadata);

/// <summary>
/// Where sessions live. In-memory for now; a durable/shared implementation is
/// part of the multi-instance step. The durable *trail* is already the audit log
/// (session.started / session.ended) — this store is the live, queryable view.
/// </summary>
public interface ISessionStore
{
    void Start(SessionRecord session);
    bool End(string sessionId, string outcome, DateTimeOffset at);
    SessionRecord? Get(string sessionId);
    IReadOnlyList<SessionRecord> Snapshot();
}

public sealed class InMemorySessionStore : ISessionStore
{
    private readonly ConcurrentDictionary<string, SessionRecord> _sessions = new();

    public void Start(SessionRecord session) => _sessions[session.SessionId] = session;

    public bool End(string sessionId, string outcome, DateTimeOffset at)
    {
        while (_sessions.TryGetValue(sessionId, out var s))
        {
            if (s.EndedAt is not null) return false;                       // already closed
            var closed = s with { EndedAt = at, Outcome = outcome };
            if (_sessions.TryUpdate(sessionId, closed, s)) return true;    // atomic close-once
        }
        return false;
    }

    public SessionRecord? Get(string sessionId) => _sessions.TryGetValue(sessionId, out var s) ? s : null;

    public IReadOnlyList<SessionRecord> Snapshot() =>
        _sessions.Values.OrderByDescending(s => s.StartedAt).ToList();
}
