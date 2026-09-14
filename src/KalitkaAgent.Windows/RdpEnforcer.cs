using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace KalitkaAgent;

/// <summary>One active RDP lease: a member of Remote Desktop Users that Kalitka added and must
/// remove when the grant expires. Keyed by the Core session id so an early end can find it.</summary>
public sealed record RdpLease(string SessionId, string Sid, string Account, DateTimeOffset ExpiresAt);

/// <summary>
/// A durable write-ahead journal of RDP leases. The intent is recorded <b>before</b> the group
/// membership is changed, so a crash between the two never leaves a membership Kalitka has
/// forgotten about — reconcile re-asserts from the journal. Just a JSON list; RDP leases are
/// few and human-paced.
/// </summary>
public sealed class RdpJournal
{
    private readonly string _path;
    private readonly object _gate = new();

    public RdpJournal(string path) => _path = path;

    public IReadOnlyList<RdpLease> All()
    {
        lock (_gate)
        {
            try { return JsonSerializer.Deserialize<List<RdpLease>>(File.ReadAllText(_path)) ?? new(); }
            catch (FileNotFoundException) { return new List<RdpLease>(); }
            catch (DirectoryNotFoundException) { return new List<RdpLease>(); }
            catch (JsonException) { return new List<RdpLease>(); }
        }
    }

    public void Upsert(RdpLease lease)
    {
        lock (_gate)
        {
            var list = MutableAll();
            list.RemoveAll(l => l.SessionId == lease.SessionId);
            list.Add(lease);
            Write(list);
        }
    }

    public void Remove(string sessionId)
    {
        lock (_gate)
        {
            var list = MutableAll();
            if (list.RemoveAll(l => l.SessionId == sessionId) > 0) Write(list);
        }
    }

    private List<RdpLease> MutableAll() => new(All());

    private void Write(List<RdpLease> list)
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(_path, JsonSerializer.Serialize(list));
    }
}

/// <summary>
/// RDP JIT enforcement: on an approved+redeemed grant, add the approved subject to the local
/// Remote Desktop Users group until the grant expires, then remove — and do it in a way that
/// survives a service restart. The journal is written before the group changes (write-ahead),
/// so the invariant is "everything in the group that Kalitka put there is journaled, and every
/// journaled lease is removed at its expiry, Core reachable or not".
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpEnforcer
{
    private readonly ILocalGroup _group;
    private readonly RdpJournal _journal;
    private readonly TimeProvider _clock;
    private readonly ILogger<RdpEnforcer> _log;

    public RdpEnforcer(ILocalGroup group, RdpJournal journal, TimeProvider clock, ILogger<RdpEnforcer> log)
    {
        _group = group;
        _journal = journal;
        _clock = clock;
        _log = log;
    }

    /// <summary>Grant RDP: journal the lease first (intent), then add the member. Idempotent on
    /// the session id.</summary>
    public void Grant(RdpLease lease)
    {
        _journal.Upsert(lease);                         // write-ahead: intent before effect
        _group.Add(new SecurityIdentifier(lease.Sid));
        _log.LogInformation("RDP granted to {Account} (sid {Sid}) until {Expiry:u}", lease.Account, lease.Sid, lease.ExpiresAt);
    }

    /// <summary>End a lease early (session ended): remove the member and forget it.</summary>
    public void Revoke(string sessionId)
    {
        var lease = _journal.All().FirstOrDefault(l => l.SessionId == sessionId);
        if (lease is null) return;
        _group.Remove(new SecurityIdentifier(lease.Sid));
        _journal.Remove(sessionId);
        _log.LogInformation("RDP revoked for {Account} (session {Session})", lease.Account, sessionId);
    }

    /// <summary>Remove every lease whose expiry has passed. A Core outage never extends access:
    /// expiry is a locally known time, enforced without asking anyone.</summary>
    public int Sweep()
    {
        var now = _clock.GetUtcNow();
        var removed = 0;
        foreach (var lease in _journal.All().Where(l => l.ExpiresAt <= now))
        {
            _group.Remove(new SecurityIdentifier(lease.Sid));
            _journal.Remove(lease.SessionId);
            _log.LogInformation("RDP expired for {Account} (session {Session})", lease.Account, lease.SessionId);
            removed++;
        }
        return removed;
    }

    /// <summary>Startup crash-recovery: drop anything already expired, and re-assert membership
    /// for anything still valid (idempotent) in case the add was lost to a crash after the
    /// journal write.</summary>
    public void Reconcile()
    {
        var now = _clock.GetUtcNow();
        foreach (var lease in _journal.All())
        {
            var sid = new SecurityIdentifier(lease.Sid);
            if (lease.ExpiresAt <= now)
            {
                _group.Remove(sid);
                _journal.Remove(lease.SessionId);
                _log.LogInformation("RDP lease already expired at startup, removed for {Account}", lease.Account);
            }
            else
            {
                _group.Add(sid);   // re-assert; idempotent
            }
        }
    }
}
