using System.Security.Principal;
using KalitkaAgent;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// RDP JIT enforcement without touching a real machine: the local group is a fake, but the
/// logic that matters — add on grant, remove exactly at expiry (Core or not), survive a
/// restart, no lease outlives its journal — is exercised deterministically with a fake clock.
/// </summary>
public class RdpEnforcerTests
{
    // A stand-in for Remote Desktop Users membership; records adds/removes by SID.
    private sealed class FakeGroup : ILocalGroup
    {
        public readonly HashSet<string> Members = new(StringComparer.OrdinalIgnoreCase);
        public bool ThrowOnAdd;   // simulate an enforce failure (e.g. the netapi32 2220) to test rollback
        public void EnsureExists() { }
        public SecurityIdentifier GroupSid() => new("S-1-5-32-555");
        public void Add(SecurityIdentifier m)
        {
            if (ThrowOnAdd) throw new InvalidOperationException("local-group membership change failed (rc=2220)");
            Members.Add(m.Value);
        }
        public void Remove(SecurityIdentifier m) => Members.Remove(m.Value);
    }

    // A stand-in for WTS: records which SIDs were asked to be logged off, and can be made to fail
    // to prove a kill failure never blocks group removal or journal cleanup.
    private sealed class FakeSessions : ISessionKiller
    {
        public readonly List<string> LoggedOff = new();
        public bool Throw;
        public int LogoffBySid(SecurityIdentifier sid)
        {
            if (Throw) throw new InvalidOperationException("boom");
            LoggedOff.Add(sid.Value);
            return 1;
        }
    }

    // A stand-in for Core liveness. Default: Core unreachable, so reconcile falls back to local
    // expiry (the pre-Core behaviour these tests assert). Set Reachable + States for Core-confirmed
    // cases.
    private sealed class FakeLiveness : ISessionLiveness
    {
        public bool Reachable;
        public readonly Dictionary<string, string> States = new();
        public Task<CoreClient.LivenessResult> OfAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(Reachable
                ? new CoreClient.LivenessResult(true, States.TryGetValue(sessionId, out var s) ? s : "unknown")
                : new CoreClient.LivenessResult(false, "unknown"));
    }

    private const string Sid = "S-1-5-21-1-2-3-1001";
    private const string Sid2 = "S-1-5-21-1-2-3-1002";

    private static (RdpEnforcer enf, FakeGroup grp, FakeSessions ses, RdpJournal jrn, FakeTimeProvider clock, string path) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var grp = new FakeGroup();
        var ses = new FakeSessions();
        var path = Path.Combine(Path.GetTempPath(), "rdp-jrn-" + Guid.NewGuid().ToString("N") + ".json");
        var jrn = new RdpJournal(path);
        // Drive the enforcer through the real soft-mode strategy, so grant/deny map to group
        // add/remove; Core unreachable so reconcile uses local expiry, as before.
        var enf = new RdpEnforcer(new AllowListAccess(grp), jrn, ses, new FakeLiveness(), clock, NullLogger<RdpEnforcer>.Instance);
        return (enf, grp, ses, jrn, clock, path);
    }

    private static RdpLease Lease(string session, string sid, DateTimeOffset expires) =>
        new(session, sid, "CONTOSO\\anna", expires);

    [Fact]
    public void A_failed_enforce_rolls_back_the_write_ahead_lease()
    {
        var (enf, grp, _, jrn, clock, path) = Fresh();
        try
        {
            grp.ThrowOnAdd = true;   // the group change fails after the lease is journaled
            Assert.Throws<InvalidOperationException>(() => enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(30))));

            // The invariant: no journaled lease may outlive a grant that never took — otherwise reconcile
            // re-asserts it forever and it reads as live access.
            Assert.Empty(jrn.All());
            Assert.DoesNotContain(Sid, grp.Members);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Grant_adds_the_member_and_journals_write_ahead()
    {
        var (enf, grp, ses, jrn, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(30)));
            Assert.Contains(Sid, grp.Members);
            Assert.Single(jrn.All());
            Assert.Equal("s1", jrn.All()[0].SessionId);
            Assert.Empty(ses.LoggedOff);   // granting never terminates a session
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Sweep_removes_only_expired_leases()
    {
        var (enf, grp, ses, _, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("short", Sid, clock.GetUtcNow().AddMinutes(15)));
            enf.Grant(Lease("long", Sid2, clock.GetUtcNow().AddHours(2)));

            clock.Advance(TimeSpan.FromMinutes(20));   // short expired, long still valid
            var removed = enf.Sweep();

            Assert.Equal(1, removed);
            Assert.DoesNotContain(Sid, grp.Members);
            Assert.Contains(Sid2, grp.Members);
            Assert.Equal(new[] { Sid }, ses.LoggedOff);   // only the expired lease's session ended
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Revoke_removes_the_member_and_forgets_the_lease()
    {
        var (enf, grp, ses, jrn, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(30)));
            enf.Revoke("s1");
            Assert.DoesNotContain(Sid, grp.Members);
            Assert.Empty(jrn.All());
            Assert.Equal(new[] { Sid }, ses.LoggedOff);   // the live session is ejected, not just the right
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Reconcile_after_restart_drops_expired_and_reasserts_valid()
    {
        var (enf, _, _, jrn, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("gone", Sid, clock.GetUtcNow().AddMinutes(10)));
            enf.Grant(Lease("live", Sid2, clock.GetUtcNow().AddHours(3)));

            // Simulate a crash+restart: the OS forgot our in-memory group, time moved on. A new
            // enforcer over the SAME journal must repair the group state. Core unreachable here, so
            // reconcile uses local expiry.
            clock.Advance(TimeSpan.FromMinutes(30));   // 'gone' has expired
            var freshGroup = new FakeGroup();
            var freshSessions = new FakeSessions();
            var enf2 = new RdpEnforcer(new AllowListAccess(freshGroup), new RdpJournal(path), freshSessions, new FakeLiveness(), clock, NullLogger<RdpEnforcer>.Instance);
            await enf2.ReconcileAsync(default);

            Assert.DoesNotContain(Sid, freshGroup.Members);   // expired lease removed + dejournaled
            Assert.Contains(Sid2, freshGroup.Members);         // valid lease re-asserted
            Assert.Equal(new[] { Sid }, freshSessions.LoggedOff);   // and its stale session ended
            Assert.Single(new RdpJournal(path).All());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Reconcile_honours_a_core_revoke_even_when_locally_still_valid()
    {
        // An admin revoked the session in Core while the agent was down. On restart the lease is
        // still locally valid, but Core says it is gone — reconcile must close it, not re-assert it.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var grp = new FakeGroup();
        var ses = new FakeSessions();
        var path = Path.Combine(Path.GetTempPath(), "rdp-jrn-" + Guid.NewGuid().ToString("N") + ".json");
        var live = new FakeLiveness { Reachable = true };
        live.States["revoked-session"] = "revoked";
        live.States["live-session"] = "open";
        try
        {
            var jrn = new RdpJournal(path);
            jrn.Upsert(Lease("revoked-session", Sid, clock.GetUtcNow().AddHours(2)));   // still valid locally
            jrn.Upsert(Lease("live-session", Sid2, clock.GetUtcNow().AddHours(2)));
            var enf = new RdpEnforcer(new AllowListAccess(grp), jrn, ses, live, clock, NullLogger<RdpEnforcer>.Instance);

            await enf.ReconcileAsync(default);

            Assert.DoesNotContain(Sid, grp.Members);        // Core revoke honoured
            Assert.Equal(new[] { Sid }, ses.LoggedOff);      // and the session torn down
            Assert.Contains(Sid2, grp.Members);              // the still-open one re-asserted
            Assert.Single(new RdpJournal(path).All());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_core_outage_never_extends_access_expiry_is_local()
    {
        // Sweep uses only the local clock and journal — no Core call — so an expired lease is
        // removed regardless of whether Core is reachable.
        var (enf, grp, _, _, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(5)));
            clock.Advance(TimeSpan.FromMinutes(6));
            enf.Sweep();
            Assert.DoesNotContain(Sid, grp.Members);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void LeaseForSid_finds_the_active_lease_and_is_empty_once_revoked()
    {
        var (enf, _, _, _, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(30)));
            Assert.Equal("s1", enf.LeaseForSid(Sid)?.SessionId);   // found by subject SID
            Assert.Null(enf.LeaseForSid(Sid2));                    // a different subject has none
            enf.Revoke("s1");
            Assert.Null(enf.LeaseForSid(Sid));                     // gone after the lease closes
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Grant_fails_closed_when_the_journal_is_corrupt()
    {
        // A corrupt journal is "state unknown", not "no leases": Grant must refuse rather than enable
        // access it could not journal (and so could never find to revoke).
        var (enf, grp, _, _, clock, path) = Fresh();
        try
        {
            File.WriteAllText(path, "not json at all");
            Assert.Throws<JournalUnreadableException>(() => enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(30))));
            Assert.DoesNotContain(Sid, grp.Members);   // no access was enabled
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Sweep_and_reconcile_fail_closed_on_a_corrupt_journal()
    {
        var (enf, grp, _, _, _, path) = Fresh();
        try
        {
            grp.Members.Add(Sid);                       // some pre-existing membership
            File.WriteAllText(path, "{ broken");
            Assert.Equal(0, enf.Sweep());               // cannot sweep unknown state
            await enf.ReconcileAsync(default);          // does not throw, does not guess
            Assert.Contains(Sid, grp.Members);          // left untouched, not silently cleared or granted
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_session_kill_failure_still_removes_the_right_and_dejournals()
    {
        // Defense in depth: if WTS logoff fails, the group membership is already gone (no new
        // logon) and the lease must not linger in the journal — the failure is logged, not fatal.
        var (enf, grp, ses, jrn, clock, path) = Fresh();
        try
        {
            enf.Grant(Lease("s1", Sid, clock.GetUtcNow().AddMinutes(30)));
            ses.Throw = true;
            enf.Revoke("s1");
            Assert.DoesNotContain(Sid, grp.Members);
            Assert.Empty(jrn.All());
        }
        finally { File.Delete(path); }
    }
}
