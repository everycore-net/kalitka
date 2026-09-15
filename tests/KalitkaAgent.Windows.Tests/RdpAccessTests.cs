using System.Security.Principal;
using KalitkaAgent;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The two RDP access models, off-box. Soft mode is an allow-list (grant adds to Remote Desktop
/// Users); hard mode is a deny-list (grant lifts out of a Kalitka-owned deny group that carries the
/// deny-logon right). The point of the tests is the <b>inversion</b>: the same enforcer lifecycle
/// produces opposite group operations, and hard mode provisions the deny group + privilege once.
/// </summary>
public class RdpAccessTests
{
    private sealed class FakeGroup : ILocalGroup
    {
        public readonly HashSet<string> Members = new(StringComparer.OrdinalIgnoreCase);
        public bool Created;
        private readonly string _sid;
        public FakeGroup(string sid = "S-1-5-32-999") => _sid = sid;
        public void EnsureExists() => Created = true;
        public SecurityIdentifier GroupSid() => new(_sid);
        public void Add(SecurityIdentifier m) => Members.Add(m.Value);
        public void Remove(SecurityIdentifier m) => Members.Remove(m.Value);
    }

    private sealed class FakeLsa : ILsaPolicy
    {
        public readonly List<(string sid, string right)> Granted = new();
        public void GrantPrivilege(SecurityIdentifier sid, string privilege) => Granted.Add((sid.Value, privilege));
    }

    private sealed class FakeSessions : ISessionKiller
    {
        public readonly List<string> LoggedOff = new();
        public int LogoffBySid(SecurityIdentifier sid) { LoggedOff.Add(sid.Value); return 1; }
    }

    private const string User = "S-1-5-21-1-2-3-1001";

    [Fact]
    public void Soft_mode_grant_adds_and_deny_removes()
    {
        var rdu = new FakeGroup();
        var access = new AllowListAccess(rdu);
        access.Initialize();                       // nothing to provision
        access.Grant(new SecurityIdentifier(User));
        Assert.Contains(User, rdu.Members);
        access.Deny(new SecurityIdentifier(User));
        Assert.DoesNotContain(User, rdu.Members);
    }

    [Fact]
    public void Hard_mode_initialize_creates_the_deny_group_and_grants_the_right()
    {
        var deny = new FakeGroup("S-1-5-21-9-9-9-1050");
        var lsa = new FakeLsa();
        var access = new DenyListAccess(deny, lsa, NullLogger<DenyListAccess>.Instance);

        access.Initialize();

        Assert.True(deny.Created);
        Assert.Equal(("S-1-5-21-9-9-9-1050", LsaRights.DenyRemoteInteractiveLogon), Assert.Single(lsa.Granted));
    }

    [Fact]
    public void Hard_mode_inverts_soft_grant_lifts_out_of_deny_deny_puts_back()
    {
        // Default-deny: the subject is in the deny group at rest.
        var deny = new FakeGroup();
        deny.Add(new SecurityIdentifier(User));
        var access = new DenyListAccess(deny, new FakeLsa(), NullLogger<DenyListAccess>.Instance);

        access.Grant(new SecurityIdentifier(User));
        Assert.DoesNotContain(User, deny.Members);   // grant lifts them out → login allowed

        access.Deny(new SecurityIdentifier(User));
        Assert.Contains(User, deny.Members);          // expiry puts them back → default-denied again
    }

    [Fact]
    public void Enforcer_in_hard_mode_denies_by_returning_to_the_group_and_kills_the_session()
    {
        // End to end through the enforcer: on expiry the lease's subject is put BACK into the deny
        // group (the opposite of soft mode's remove) and the live session is torn down.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var deny = new FakeGroup();
        deny.Add(new SecurityIdentifier(User));       // at rest: denied
        var sessions = new FakeSessions();
        var path = Path.Combine(Path.GetTempPath(), "rdp-hard-" + Guid.NewGuid().ToString("N") + ".json");
        var enf = new RdpEnforcer(new DenyListAccess(deny, new FakeLsa(), NullLogger<DenyListAccess>.Instance),
            new RdpJournal(path), sessions, clock, NullLogger<RdpEnforcer>.Instance);
        try
        {
            enf.Grant(new RdpLease("s1", User, "CONTOSO\\anna", clock.GetUtcNow().AddMinutes(15)));
            Assert.DoesNotContain(User, deny.Members);   // granted → not denied

            clock.Advance(TimeSpan.FromMinutes(20));
            Assert.Equal(1, enf.Sweep());
            Assert.Contains(User, deny.Members);          // expired → back in the deny group
            Assert.Equal(new[] { User }, sessions.LoggedOff);   // and the live session ended
        }
        finally { File.Delete(path); }
    }
}
