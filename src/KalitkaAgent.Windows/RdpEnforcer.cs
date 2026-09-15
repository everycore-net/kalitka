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
/// <summary>The journal file exists but cannot be parsed — its contents are unknown. Callers must
/// <b>fail closed</b> (refuse new grants, log loudly) rather than treat it as "no leases": an unknown
/// state silently read as empty would strand active memberships that never get swept, leaving access
/// forever. Distinct from a missing file, which legitimately means "nothing granted yet".</summary>
public sealed class JournalUnreadableException : Exception
{
    public JournalUnreadableException(string path, Exception inner)
        : base($"RDP lease journal at '{path}' is unreadable; state is unknown", inner) { }
}

public sealed class RdpJournal
{
    private readonly string _path;
    private readonly object _gate = new();

    public RdpJournal(string path) => _path = path;

    /// <summary>All journaled leases. A missing file is an empty list (nothing granted yet); a file
    /// that exists but does not parse throws <see cref="JournalUnreadableException"/> — never an empty
    /// list, because "unknown" must not be mistaken for "none".</summary>
    public IReadOnlyList<RdpLease> All()
    {
        lock (_gate)
        {
            string text;
            try { text = File.ReadAllText(_path); }
            catch (FileNotFoundException) { return new List<RdpLease>(); }
            catch (DirectoryNotFoundException) { return new List<RdpLease>(); }

            try { return JsonSerializer.Deserialize<List<RdpLease>>(text) ?? new(); }
            catch (JsonException e) { throw new JournalUnreadableException(_path, e); }
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

    // Write-ahead durability: serialize to a temp file, then atomically replace, so a crash mid-write
    // leaves either the whole old file or the whole new one — never a truncated, unparseable journal
    // (which would strand active leases). File.Replace is atomic on NTFS; the first write has no
    // destination to replace, so it moves into place.
    private void Write(List<RdpLease> list)
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(list));
        if (File.Exists(_path)) File.Replace(tmp, _path, destinationBackupFileName: null);
        else File.Move(tmp, _path);
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
    private readonly ISessionLiveness _liveness;
    private readonly TimeProvider _clock;
    private readonly ILogger<RdpEnforcer> _log;

    public RdpEnforcer(IRdpAccess access, RdpJournal journal, ISessionKiller sessions, ISessionLiveness liveness,
        TimeProvider clock, ILogger<RdpEnforcer> log)
    {
        _access = access;
        _journal = journal;
        _sessions = sessions;
        _liveness = liveness;
        _clock = clock;
        _log = log;
    }

    /// <summary>Grant RDP: journal the lease first (intent), then enable access. Idempotent on
    /// the session id. Fails closed if the journal is unreadable — no access is enabled that we could
    /// not later find to revoke.</summary>
    public void Grant(RdpLease lease)
    {
        try { _journal.Upsert(lease); }                 // write-ahead: intent before effect
        catch (JournalUnreadableException ex)
        {
            _log.LogCritical(ex, "RDP journal unreadable; refusing to grant {Account} until it is repaired", lease.Account);
            throw;   // fail closed: never enable access we cannot journal (and so cannot later revoke)
        }
        try
        {
            _access.Grant(new SecurityIdentifier(lease.Sid));
        }
        catch
        {
            // Enforce failed after the write-ahead. Undo the journal entry so the invariant holds — no
            // journaled lease without real access — otherwise reconcile would re-assert a grant that
            // never took, hammering the same failure, and the lease would read as live access. Rethrow so
            // the caller reports the failure to Core.
            _journal.Remove(lease.SessionId);
            throw;
        }
        _log.LogInformation("RDP granted to {Account} (sid {Sid}) until {Expiry:u}", lease.Account, lease.Sid, lease.ExpiresAt);
    }

    /// <summary>The active lease for a subject SID, if any — used to end a lease early when its
    /// owner logs off (the logoff names the SID; the lease names the Core session).</summary>
    public RdpLease? LeaseForSid(string sid) =>
        _journal.All()
            .Where(l => string.Equals(l.Sid, sid, StringComparison.OrdinalIgnoreCase))
            .MaxBy(l => l.ExpiresAt);

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
        IReadOnlyList<RdpLease> leases;
        try { leases = _journal.All(); }
        catch (JournalUnreadableException ex)
        {
            // Unknown state: we cannot know what to remove. Fail loud and leave it for reconcile /
            // an operator — never proceed as if there were nothing to sweep.
            _log.LogCritical(ex, "RDP journal unreadable; cannot sweep expired leases until it is repaired");
            return 0;
        }
        foreach (var lease in leases.Where(l => l.ExpiresAt <= now))
        {
            _access.Deny(new SecurityIdentifier(lease.Sid));
            EndSessions(lease);
            _journal.Remove(lease.SessionId);
            _log.LogInformation("RDP expired for {Account} (session {Session})", lease.Account, lease.SessionId);
            removed++;
        }
        return removed;
    }

    /// <summary>Startup crash-recovery, reconciled against Core as a second source. Provision the
    /// access model (idempotent), then for each journaled lease decide with Core:
    /// <list type="bullet">
    ///   <item>Core reachable and the session is <c>open</c> (and not locally expired) → re-assert;</item>
    ///   <item>Core reachable and the session is gone (<c>expired</c>/<c>revoked</c>/<c>ended</c>) →
    ///     deny + terminate + dejournal, so an admin's revoke made while we were down is honoured and
    ///     never reverted by the restart;</item>
    ///   <item>Core unreachable, or has no record (<c>unknown</c>) → fall back to the locally-known
    ///     expiry: a Core outage must never revoke a still-valid lease, nor extend an expired one.</item>
    /// </list>
    /// Local expiry is a hard bound in every case.</summary>
    public async Task ReconcileAsync(CancellationToken ct)
    {
        _access.Initialize();
        var now = _clock.GetUtcNow();
        IReadOnlyList<RdpLease> leases;
        try { leases = _journal.All(); }
        catch (JournalUnreadableException ex)
        {
            // The journal is our only local record; if it is corrupt we cannot safely re-assert or
            // remove anything. Fail loud and leave the box frozen for JIT until it is repaired.
            _log.LogCritical(ex, "RDP journal unreadable at startup; cannot reconcile leases until it is repaired");
            return;
        }

        foreach (var lease in leases)
        {
            var sid = new SecurityIdentifier(lease.Sid);
            var locallyValid = lease.ExpiresAt > now;
            var live = await _liveness.OfAsync(lease.SessionId, ct);

            // Deny when Core authoritatively says the session is gone; otherwise honour local expiry.
            var keep = locallyValid && (!live.Reached || live.State is "unknown" or "open");
            if (keep)
            {
                _access.Grant(sid);   // re-assert; idempotent
            }
            else
            {
                _access.Deny(sid);
                EndSessions(lease);
                _journal.Remove(lease.SessionId);
                _log.LogInformation("RDP lease closed at startup for {Account} (core={State}, expiry {Expiry:u})",
                    lease.Account, live.Reached ? live.State : "unreachable", lease.ExpiresAt);
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
