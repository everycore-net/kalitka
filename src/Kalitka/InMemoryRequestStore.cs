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

    public void Add(PendingRequest request) => _requests[request.Id] = request;

    public PendingRequest? Get(string id) => _requests.TryGetValue(id, out var r) ? r : null;

    public void Remove(string id) => _requests.TryRemove(id, out _);

    public IReadOnlyList<PendingRequest> Snapshot() => _requests.Values.ToList();

    public int CountWaiting(DateTimeOffset since) =>
        _requests.Count(kv => kv.Value.State == "waiting" && kv.Value.Raised >= since);

    public void DropOlderThan(DateTimeOffset cutoff)
    {
        foreach (var kv in _requests)
            if (kv.Value.Raised < cutoff) _requests.TryRemove(kv.Key, out _);
    }

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
}
