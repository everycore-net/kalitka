using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Reconciliation is the deliberate, audited application of profile changes to
/// already-enrolled agents. It is a three-way merge anchored to the revision the
/// agent was last synced to: only what the profile changed is applied, local
/// overrides survive, and any expansion (a new capability/resource) needs explicit
/// confirmation. A deleted profile leaves the agent untouched.
/// </summary>
public class ReconcileTests
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

    // Save a profile and return the stored copy (with its real revision), the way the
    // admin create handler does — provenance must anchor on the stored revision.
    private static async Task<AgentProfile> SaveGet(ProfileService profiles, AgentProfile p)
    {
        await profiles.Save(p, Actor, default);
        return profiles.Get(p.Name)!;
    }

    private static AgentProfile Ssh(params string[] templates) =>
        new("ls", "linux", new[] { AgentCapabilities.Request }, templates, Array.Empty<string>());

    [Fact]
    public async Task Created_agent_starts_in_sync()
    {
        var (svc, profiles, reconcile, _, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);

        Assert.Equal(p.Revision, c.Agent.AppliedProfileRevision);
        Assert.Equal("ls", c.Agent.ProfileId);
        Assert.Equal("srv-01", c.Agent.ProfileHostname);
        var plan = reconcile.Preview(c.Agent.Id);
        Assert.NotNull(plan);
        Assert.False(plan!.HasChanges);   // nothing to do right after creation
        Assert.Empty(reconcile.PreviewAll());
    }

    [Fact]
    public async Task Widening_the_profile_is_drift_flagged_as_expansion()
    {
        var (svc, profiles, reconcile, _, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);

        await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));   // widen

        var plan = reconcile.Preview(c.Agent.Id)!;
        Assert.True(plan.HasChanges);
        Assert.True(plan.IsExpansion);
        Assert.Equal(new[] { "sudo:srv-01" }, plan.AddedResources);
        Assert.Empty(plan.RemovedResources);
        Assert.Single(reconcile.PreviewAll());
    }

    [Fact]
    public async Task Expansion_needs_confirmation()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));

        var blocked = await reconcile.Apply(c.Agent.Id, confirmExpansion: false, Actor, default);
        Assert.False(blocked.Applied);
        Assert.True(blocked.NeedsConfirmation);
        Assert.Equal(new[] { "ssh:srv-01" }, store.GetById(c.Agent.Id)!.AllowedResources);   // unchanged

        var done = await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);
        Assert.True(done.Applied);
        Assert.Equal(new[] { "ssh:srv-01", "sudo:srv-01" }, store.GetById(c.Agent.Id)!.AllowedResources);
        Assert.Equal(2, store.GetById(c.Agent.Id)!.AppliedProfileRevision);
    }

    [Fact]
    public async Task Reduction_applies_without_confirmation()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Ssh("ssh:{hostname}"));   // narrow

        var plan = reconcile.Preview(c.Agent.Id)!;
        Assert.False(plan.IsExpansion);
        Assert.True(plan.RemovesPrivilege);

        var done = await reconcile.Apply(c.Agent.Id, confirmExpansion: false, Actor, default);
        Assert.True(done.Applied);
        Assert.Equal(new[] { "ssh:srv-01" }, store.GetById(c.Agent.Id)!.AllowedResources);
    }

    [Fact]
    public async Task Apply_preserves_a_locally_added_resource()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);

        // Admin hand-adds a resource that is in no profile revision.
        store.Create(store.GetById(c.Agent.Id)! with
        {
            AllowedResources = new[] { "ssh:srv-01", "ssh:jump" }
        });

        await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));   // widen

        var done = await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);
        Assert.True(done.Applied);
        var res = store.GetById(c.Agent.Id)!.AllowedResources;
        Assert.Contains("ssh:jump", res);       // local override kept
        Assert.Contains("sudo:srv-01", res);    // profile addition applied
        Assert.Contains("ssh:srv-01", res);
    }

    [Fact]
    public async Task Apply_preserves_a_locally_removed_resource_while_pushing_new_ones()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);

        // Admin removes sudo by hand.
        store.Create(store.GetById(c.Agent.Id)! with { AllowedResources = new[] { "ssh:srv-01" } });

        // Profile then adds a third resource (base still has sudo).
        await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}", "rdp:{hostname}"));

        var done = await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);
        Assert.True(done.Applied);
        var res = store.GetById(c.Agent.Id)!.AllowedResources;
        Assert.Contains("rdp:srv-01", res);        // profile addition applied
        Assert.DoesNotContain("sudo:srv-01", res); // local removal preserved, not re-pushed
    }

    [Fact]
    public async Task Local_override_alone_is_not_a_pending_change()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);

        // Admin removes sudo by hand; profile itself is unchanged.
        store.Create(store.GetById(c.Agent.Id)! with { AllowedResources = new[] { "ssh:srv-01" } });

        var plan = reconcile.Preview(c.Agent.Id)!;
        Assert.False(plan.HasChanges);   // reconcile does not undo a local override
    }

    [Fact]
    public async Task Deleting_a_profile_leaves_the_agent_intact_and_unreconcilable()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        var before = store.GetById(c.Agent.Id)!.AllowedResources;

        Assert.True(await profiles.Delete("ls", Actor, default));

        Assert.Null(reconcile.Preview(c.Agent.Id));   // nothing to reconcile against
        var apply = await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);
        Assert.False(apply.Applied);
        Assert.Equal(before, store.GetById(c.Agent.Id)!.AllowedResources);   // snapshot untouched
    }

    [Fact]
    public async Task Unmanaged_agent_has_no_plan()
    {
        var (svc, _, reconcile, _, _) = Fresh();
        var c = await svc.Create("free", "linux", new[] { AgentCapabilities.Request }, new[] { "ssh:x" }, Actor, default);
        Assert.Null(reconcile.Preview(c.Agent.Id));
    }

    [Fact]
    public async Task Apply_audits_the_diff()
    {
        var (svc, profiles, reconcile, _, audit) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));

        await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);

        var events = await audit.Query(new AuditQuery(), default);
        var ev = Assert.Single(events, e => e.EventType == AuditEvents.AgentProfileApplied);
        Assert.Equal(c.Agent.Id, ev.Subject);
        Assert.Equal("ls", ev.Resource);
        Assert.Contains("sudo:srv-01", ev.Metadata);   // the diff, not just the fact
        Assert.Contains("rev 1->2", ev.Metadata);
    }

    [Fact]
    public async Task Applying_twice_is_idempotent()
    {
        var (svc, profiles, reconcile, store, _) = Fresh();
        var p = await SaveGet(profiles, Ssh("ssh:{hostname}"));
        var c = await svc.CreateFromProfile(p, "srv-01", null, Actor, default);
        await SaveGet(profiles, Ssh("ssh:{hostname}", "sudo:{hostname}"));

        await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);
        var second = await reconcile.Apply(c.Agent.Id, confirmExpansion: true, Actor, default);

        Assert.False(second.Applied);   // already in sync
        Assert.False(reconcile.Preview(c.Agent.Id)!.HasChanges);
        Assert.Equal(new[] { "ssh:srv-01", "sudo:srv-01" }, store.GetById(c.Agent.Id)!.AllowedResources);
    }
}
