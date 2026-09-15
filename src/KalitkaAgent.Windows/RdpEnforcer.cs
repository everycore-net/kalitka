using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace KalitkaAgent;

/// <summary>One active RDP lease: a subject Kalitka enabled for RDP and must deny again when the
/// grant expires. Keyed by the Core session id so an early end can find it.</summary>
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
/// RDP JIT enforcement: on an approved+redeemed grant, make the approved subject able to sign in
/// over RDP until the grant expires, then make them unable again — and do it in a way that survives
/// a service restart. <i>How</i> access is toggled (add to Remote Desktop Users, or lift out of a
/// deny group) is the <see cref="IRdpAccess"/> strategy; this class owns the lease lifecycle. The
/// journal is written before the access change (write-ahead), so the invariant is "every access
/// Kalitka granted is journaled, and every journaled lease is denied at its expiry, Core reachable
/// or not". Closing a lease also terminates the live session, because removing access does not
/// eject a token already assembled at logon.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpEnforcer
{
    private readonly IRdpAccess _access;
    private readonly RdpJournal _journal;
    private readonly ISessionKiller _sessions;
    private readonly TimeProvider _clock;
    private readonly ILogger<RdpEnforcer> _log;

    public RdpEnforcer(IRdpAccess access, RdpJournal journal, ISessionKiller sessions, TimeProvider clock, ILogger<RdpEnforcer> log)
    {
        _access = access;
        _journal = journal;
        _sessions = sessions;
        _clock = clock;
        _log = log;
    }

    /// <summary>Grant RDP: journal the lease first (intent), then enable access. Idempotent on
    /// the session id.</summary>
    public void Grant(RdpLease lease)
    {
        _journal.Upsert(lease);                         // write-ahead: intent before effect
        _access.Grant(new SecurityIdentifier(lease.Sid));
        _log.LogInformation("RDP granted to {Account} (sid {Sid}) until {Expiry:u}", lease.Account, lease.Sid, lease.ExpiresAt);
    }

    /// <summary>End a lease early (revoked or session ended): deny access, terminate any live
    /// session so a token assembled at logon cannot outlive the grant, and forget it.</summary>
    public void Revoke(string sessionId)
    {
        var lease = _journal.All().FirstOrDefault(l => l.SessionId == sessionId);
        if (lease is null) return;
        _access.Deny(new SecurityIdentifier(lease.Sid));
        EndSessions(lease);
        _journal.Remove(sessionId);
        _log.LogInformation("RDP revoked for {Account} (session {Session})", lease.Account, sessionId);
    }

    /// <summary>Deny every lease whose expiry has passed. A Core outage never extends access:
    /// expiry is a locally known time, enforced without asking anyone.</summary>
    public int Sweep()
    {
        var now = _clock.GetUtcNow();
        var removed = 0;
        foreach (var lease in _journal.All().Where(l => l.ExpiresAt <= now))
        {
            _access.Deny(new SecurityIdentifier(lease.Sid));
            EndSessions(lease);
            _journal.Remove(lease.SessionId);
            _log.LogInformation("RDP expired for {Account} (session {Session})", lease.Account, lease.SessionId);
            removed++;
        }
        return removed;
    }

    /// <summary>Startup crash-recovery: provision the access model (idempotent), drop anything
    /// already expired, and re-assert access for anything still valid in case the grant was lost to
    /// a crash after the journal write.</summary>
    public void Reconcile()
    {
        _access.Initialize();
        var now = _clock.GetUtcNow();
        foreach (var lease in _journal.All())
        {
            var sid = new SecurityIdentifier(lease.Sid);
            if (lease.ExpiresAt <= now)
            {
                _access.Deny(sid);
                EndSessions(lease);
                _journal.Remove(lease.SessionId);
                _log.LogInformation("RDP lease already expired at startup, removed for {Account}", lease.Account);
            }
            else
            {
                _access.Grant(sid);   // re-assert; idempotent
            }
        }
    }

    // Terminate any interactive session the beneficiary still holds. Best-effort by design: the
    // group membership is already gone (no new logon), so a session that cannot be killed is the
    // lesser, logged failure — it must never block dejournaling and leave a phantom lease behind.
    private void EndSessions(RdpLease lease)
    {
        try
        {
            var ended = _sessions.LogoffBySid(new SecurityIdentifier(lease.Sid));
            if (ended > 0)
                _log.LogInformation("Terminated {Count} live session(s) for {Account} on lease close", ended, lease.Account);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Could not terminate session(s) for {Account}; membership already removed", lease.Account);
        }
    }
}
