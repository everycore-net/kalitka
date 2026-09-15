using System.Collections.Concurrent;

namespace Kalitka;

/// <summary>
/// The single-process request store: a concurrent dictionary, with the resolve
/// transition guarded per request so exactly one caller can win it. A restart
/// forgets in-flight requests, which is fine — a door nobody answered should
/// close by itself. A durable implementation of <see cref="IRequestStore"/> is
/// what a multi-instance deployment would add.
/// </summary>
public sealed class InMemoryRequestStore : IRequestStore
{
    private readonly ConcurrentDictionary<string, PendingRequest> _requests = new();
    private readonly ConcurrentDictionary<string, HashSet<string>> _approvals = new();
    private readonly object _createGate = new();

    public void Add(PendingRequest request) => _requests[request.Id] = request;

    public bool TryCreateOrGetPending(PendingRequest candidate, DateTimeOffset notOlderThan, out PendingRequest effective)
    {
        if (string.IsNullOrEmpty(candidate.DedupKey)) { _requests[candidate.Id] = candidate; effective = candidate; return true; }

        // The check and the insert are one step under a lock, so two identical raises cannot both
        // create — the second finds the first. (A durable backend does this with a unique index.)
        lock (_createGate)
        {
            var existing = _requests.Values.FirstOrDefault(r =>
                r.State == "waiting" && r.Raised >= notOlderThan &&
                string.Equals(r.DedupKey, candidate.DedupKey, StringComparison.Ordinal));
            if (existing is not null) { effective = existing; return false; }
            _requests[candidate.Id] = candidate;
            effective = candidate;
            return true;
        }
    }

    public PendingRequest? Get(string id) => _requests.TryGetValue(id, out var r) ? r : null;

    public void Remove(string id) { _requests.TryRemove(id, out _); _approvals.TryRemove(id, out _); }

    public IReadOnlyList<PendingRequest> Snapshot() => _requests.Values.ToList();

    public int CountWaiting(DateTimeOffset since) =>
        _requests.Count(kv => kv.Value.State == "waiting" && kv.Value.Raised >= since);

    public void DropOlderThan(DateTimeOffset cutoff)
    {
        foreach (var kv in _requests)
            if (kv.Value.Raised < cutoff) { _requests.TryRemove(kv.Key, out _); _approvals.TryRemove(kv.Key, out _); }
    }

    public int AddApprovalAndCount(string id, string principal)
    {
        var set = _approvals.GetOrAdd(id, _ => new HashSet<string>(StringComparer.Ordinal));
        lock (set) { set.Add(principal); return set.Count; }
    }

    public int ApprovalCount(string id) =>
        _approvals.TryGetValue(id, out var set) ? Lock(set) : 0;

    public bool HasApproval(string id, string principal) =>
        _approvals.TryGetValue(id, out var set) && Has(set, principal);

    private static int Lock(HashSet<string> set) { lock (set) return set.Count; }
    private static bool Has(HashSet<string> set, string principal) { lock (set) return set.Contains(principal); }

    public bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
    {
        request = null;
        if (!_requests.TryGetValue(id, out var r)) return false;

        // Lock the request itself: the check and the write are one step, so a
        // second Approve/Deny racing this one cannot also pass the check.
        lock (r)
        {
            if (r.State != "waiting") return false;
            if (r.Raised < notOlderThan) return false;
            r.State = toState;
        }

        request = r;
        return true;
    }

    public bool TrySetGrant(string id, string candidate, out string grant)
    {
        grant = "";
        if (!_requests.TryGetValue(id, out var r)) return false;

        // Same shape as TryResolve: the check-and-write is one step so racing
        // status polls settle on a single grant.
        lock (r)
        {
            if (r.Grant.Length == 0) { r.Grant = candidate; grant = candidate; return true; }
            grant = r.Grant;
            return false;
        }
    }
}
