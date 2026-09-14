using System.Collections.Concurrent;

namespace Kalitka;

/// <summary>
/// Append-only audit events, with a narrow query for the history view. A seam of
/// its own, not folded into <see cref="IRequestStore"/>: audit outlives a request
/// and has different durability needs. In-memory by default; SQLite when a path
/// is configured. No SIEM, retention, or export here — just record and read back.
/// </summary>
public interface IAuditStore
{
    Task Append(AuditEvent e, CancellationToken ct);
    Task<IReadOnlyList<AuditEvent>> Query(AuditQuery query, CancellationToken ct);

    /// <summary>Recompute the hash chain over the stored events and report whether it is intact.
    /// The proof a compliance export rests on — a tampered or reordered event breaks it.</summary>
    Task<AuditVerification> VerifyChain(CancellationToken ct);
}

/// <summary>
/// Default store: a bounded ring in memory. Survives nothing, which is exactly
/// why the SQLite store exists — but it keeps kalitka working with zero config
/// and is fine for a home instance that does not need history across restarts.
/// </summary>
public sealed class InMemoryAuditStore : IAuditStore
{
    private const int Cap = 5000;
    private readonly LinkedList<AuditEvent> _events = new();
    private readonly object _lock = new();
    private long _headSeq;
    private string _headHash = AuditHash.Genesis;

    public Task Append(AuditEvent e, CancellationToken ct)
    {
        lock (_lock)
        {
            var linked = AuditHash.Link(e, _headSeq, _headHash);   // chain under the lock — no gaps or forks
            _headSeq = linked.Seq;
            _headHash = linked.Hash;
            _events.AddFirst(linked);                  // newest first
            while (_events.Count > Cap) _events.RemoveLast();
        }
        return Task.CompletedTask;
    }

    public Task<AuditVerification> VerifyChain(CancellationToken ct)
    {
        lock (_lock)
        {
            // Oldest-first over the retained window. Each event's own hash must recompute, and each
            // must link to the prior one (the very first retained event's PrevHash may point at an
            // event already dropped from the ring, so only its self-hash is checked).
            var ordered = _events.Reverse().ToList();
            return Task.FromResult(AuditChain.Verify(ordered));
        }
    }

    public Task<IReadOnlyList<AuditEvent>> Query(AuditQuery q, CancellationToken ct)
    {
        lock (_lock)
        {
            IEnumerable<AuditEvent> hits = _events;    // already newest-first

            if (!string.IsNullOrEmpty(q.Actor)) hits = hits.Where(e => e.Actor.Contains(q.Actor, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(q.Resource)) hits = hits.Where(e => e.Resource.Contains(q.Resource, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(q.EventType)) hits = hits.Where(e => e.EventType == q.EventType);
            if (q.Since is { } s) hits = hits.Where(e => e.Timestamp >= s);
            if (q.Until is { } u) hits = hits.Where(e => e.Timestamp <= u);

            var page = hits.Skip(Math.Max(0, q.Offset)).Take(Math.Clamp(q.Limit, 1, 500)).ToList();
            return Task.FromResult<IReadOnlyList<AuditEvent>>(page);
        }
    }
}
