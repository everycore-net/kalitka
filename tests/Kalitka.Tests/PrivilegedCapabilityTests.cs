using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// subject.assert became a sudo-grade capability: an agent that holds it can assert who
/// the subject of a request is, which feeds authorization and the quorum. Granting or
/// revoking it must never be a quiet line — it earns its own conspicuous, queryable audit
/// event (at create, at enrolment-token mint, and at reconcile) and is surfaced distinctly
/// in the reconcile diff. The snapshot/reconcile model (0.16-0.17) already guarantees a
/// profile edit alone never arms an existing agent; here we make the deliberate grant loud.
/// </summary>
public class PrivilegedCapabilityTests
{
    private const string Actor = "google:admin";

    private static (AgentService svc, ProfileService profiles, ReconcileService reconcile,
        InMemoryAgentStore store, InMemoryAuditStore audit) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var config = new InMemoryConfigStore();
        var audit = new InMemoryAuditStore();
        var profiles = new ProfileService(config, audit, clock);
        var store = new InMemoryAgentStore();
        var svc = new AgentService(store, new OneTimeTokenService(new TokenSigner("unit-test-signing-key-0123456789"), clock),
            new InMemoryReplayStore(clock), audit, Options.Create(new GateOptions()), clock);
        var reconcile = new ReconcileService(store, profiles, audit, clock);
        return (svc, profiles, reconcile, store, audit);
    }

    private static async Task<AgentProfile> SaveGet(ProfileService profiles, AgentProfile p)
    {
        await profiles.Save(p, Actor, default);
        return profiles.Get(p.Name)!;
    }

    private static AgentProfile Win(params string[] caps) =>
        new("winsvc", "windows", caps, new[] { "ssh:{hostname}" }, Array.Empty<string>());

    private static async Task<int> PrivEvents(InMemoryAuditStore audit) =>
        (await audit.Query(new AuditQuery(EventType: AuditEvents.AgentPrivilegedCapability), default)).Count;

    [Fact]
    public void Only_subject_assert_is_privileged_today()
    {
        Assert.True(AgentCapabilities.IsPrivileged(AgentCapabilities.AssertSubject));
        Assert.True(AgentCapabilities.IsPrivileged("SUBJECT.ASSERT"));   // case-insensitive
        Assert.False(AgentCapabilities.IsPrivileged(AgentCapabilities.Request));
        Assert.False(AgentCapabilities.IsPrivileged("ssh"));
    }

    [Fact]
    public async Task Creating_an_agent_with_subject_assert_emits_a_distinct_audit_event()
    {
        var (svc, _, _, _, audit) = Fresh();
        var c = await svc.Create("win", "windows",
            new[] { "ssh", AgentCapabilities.AssertSubject }, new[] { "ssh:*" }, Actor, default);

        var ev = Assert.Single(await audit.Query(new AuditQuery(EventType: AuditEvents.AgentPrivilegedCapability), default));
        Assert.Equal(c.Agent.Id, ev.Subject);
        Assert.Contains("granted", ev.Metadata);
        Assert.Contains(AgentCapabilities.AssertSubject, ev.Metadata);
    }

    [Fact]
    public async Task Creating_an_ordinary_agent_emits_no_privileged_event()
    {
        var (svc, _, _, _, audit) = Fresh();
        await svc.Create("plain", "linux", new[] { "ssh" }, new[] { "ssh:*" }, Actor, default);
        Assert.Equal(0, await PrivEvents(audit));
    }

    [Fact]
    public async Task Minting_an_enrollment_token_with_subject_assert_emits_the_event()
    {
        var (svc, _, _, _, audit) = Fresh();
        await svc.CreateEnrollmentToken("pending-win", "windows",
            new[] { "ssh", AgentCapabilities.AssertSubject }, new[] { "ssh:*" }, Actor, default);
        Assert.Equal(1, await PrivEvents(audit));
    }

    [Fact]
    public async Task Reconcile_granting_subject_assert_is_an_expansion_marked_privileged()
    {
        var (svc, profiles, reconcile, _, _) = Fresh();
        var p = await SaveGet(profiles, Win("ssh"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);

        await SaveGet(profiles, Win("ssh", AgentCapabilities.AssertSubject));   // grant sudo-grade cap

        var plan = reconcile.Preview(c.Agent.Id)!;
        Assert.True(plan.IsExpansion);                                   // still needs confirmation
        Assert.True(plan.TouchesPrivileged);
        Assert.Equal(new[] { AgentCapabilities.AssertSubject }, plan.PrivilegedGranted);
        Assert.Empty(plan.PrivilegedRevoked);
        Assert.Contains("+!" + AgentCapabilities.AssertSubject, plan.Diff());   // marked in the diff
    }

    [Fact]
    public async Task Reconcile_granting_subject_assert_still_requires_confirmation()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Win("ssh"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Win("ssh", AgentCapabilities.AssertSubject));

        var blocked = await reconcile.Apply(c.Agent.Id, confirmExpansion: false, Actor, default);
        Assert.False(blocked.Applied);
        Assert.True(blocked.NeedsConfirmation);
        Assert.DoesNotContain(AgentCapabilities.AssertSubject, store.GetById(c.Agent.Id)!.Capabilities);
    }

    [Fact]
    public async Task Applying_the_grant_emits_a_distinct_privileged_event_beside_the_profile_diff()
    {
        var (svc, profiles, reconcile, _, audit) = Fresh();
        var p = await SaveGet(profiles, Win("ssh"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Win("ssh", AgentCapabilities.AssertSubject));

        await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);

        // The ordinary profile-applied diff still marks it,
        var applied = Assert.Single(await audit.Query(new AuditQuery(EventType: AuditEvents.AgentProfileApplied), default));
        Assert.Contains("+!" + AgentCapabilities.AssertSubject, applied.Metadata);
        // and a separate, queryable privileged event records the grant on its own.
        var priv = Assert.Single(await audit.Query(new AuditQuery(EventType: AuditEvents.AgentPrivilegedCapability), default));
        Assert.Equal(c.Agent.Id, priv.Subject);
        Assert.Contains("granted " + AgentCapabilities.AssertSubject, priv.Metadata);
    }

    [Fact]
    public async Task Revoking_subject_assert_is_surfaced_and_audited_as_revoked()
    {
        var (svc, profiles, reconcile, store, audit) = Fresh();
        var p = await SaveGet(profiles, Win("ssh", AgentCapabilities.AssertSubject));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Win("ssh"));   // take the sudo-grade cap away

        var plan = reconcile.Preview(c.Agent.Id)!;
        Assert.False(plan.IsExpansion);            // a removal, applies without confirmation
        Assert.True(plan.TouchesPrivileged);
        Assert.Equal(new[] { AgentCapabilities.AssertSubject }, plan.PrivilegedRevoked);
        Assert.Contains("-!" + AgentCapabilities.AssertSubject, plan.Diff());

        await reconcile.Apply(c.Agent.Id, confirmExpansion: false, Actor, default);
        Assert.DoesNotContain(AgentCapabilities.AssertSubject, store.GetById(c.Agent.Id)!.Capabilities);
        // Create-from-profile already logged the initial grant; the reconcile adds a revoke.
        var events = await audit.Query(new AuditQuery(EventType: AuditEvents.AgentPrivilegedCapability), default);
        var revoke = Assert.Single(events, e => e.Metadata.Contains("revoked"));
        Assert.Contains("revoked " + AgentCapabilities.AssertSubject, revoke.Metadata);
    }
}
