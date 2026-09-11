using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Profiles are templates + classification, snapshotted onto the agent at create —
/// so the agent's capabilities/resources/tags are the source of truth, and editing
/// a profile must never silently re-grant an already-created agent. Plus the
/// operation-capability model and tag storage.
/// </summary>
public class AgentProfileTests
{
    private static (AgentService svc, ProfileService profiles, InMemoryAgentStore store, InMemoryAuditStore audit) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var config = new InMemoryConfigStore();
        var audit = new InMemoryAuditStore();
        var profiles = new ProfileService(config, audit, clock);
        var store = new InMemoryAgentStore();
        var svc = new AgentService(store, new OneTimeTokenService(new TokenSigner("unit-test-signing-key-0123456789"), clock),
            new InMemoryReplayStore(clock), audit, Options.Create(new GateOptions()), clock);
        return (svc, profiles, store, audit);
    }

    private static AgentProfile LinuxServer => new(
        "linux-server", "linux",
        new[] { AgentCapabilities.Request, AgentCapabilities.Redeem, AgentCapabilities.SessionEnd },
        new[] { "ssh:{hostname}", "sudo:{hostname}" },
        new[] { "env:prod", "role:web" });

    [Fact]
    public void Expand_fills_hostname_and_copies_caps_and_tags()
    {
        var (caps, resources, tags) = LinuxServer.Expand("srv-web-01");
        Assert.Equal(new[] { "ssh:srv-web-01", "sudo:srv-web-01" }, resources);
        Assert.Equal(LinuxServer.Capabilities, caps);
        Assert.Equal(new[] { "env:prod", "role:web" }, tags);
    }

    [Fact]
    public void Expand_drops_templates_with_unfilled_placeholders()
    {
        var p = new AgentProfile("db", "gateway", new[] { AgentCapabilities.Request },
            new[] { "ssh:{hostname}", "db:{database}" }, Array.Empty<string>());
        var (_, resources, _) = p.Expand("host-1");
        Assert.Equal(new[] { "ssh:host-1" }, resources);   // db:{database} left unfilled → dropped
    }

    [Fact]
    public async Task Create_from_profile_snapshots_onto_the_agent()
    {
        var (svc, profiles, store, _) = Fresh();
        await profiles.Save(LinuxServer, "google:admin", default);

        var created = await svc.CreateFromProfile(LinuxServer, "srv-web-01", null, "google:admin", default);
        var a = store.GetById(created.Agent.Id)!;
        Assert.Equal("srv-web-01", a.DisplayName);
        Assert.Equal(new[] { "ssh:srv-web-01", "sudo:srv-web-01" }, a.AllowedResources);
        Assert.Equal(LinuxServer.Capabilities, a.Capabilities);
        Assert.Equal(new[] { "env:prod", "role:web" }, a.Tags);
        Assert.Equal(AgentStatus.Active, a.Status);
    }

    [Fact]
    public async Task Editing_a_profile_does_not_change_existing_agents()
    {
        var (svc, profiles, store, _) = Fresh();
        var p1 = new AgentProfile("ls", "linux", new[] { AgentCapabilities.Request },
            new[] { "ssh:{hostname}" }, Array.Empty<string>());
        await profiles.Save(p1, "google:admin", default);

        var created = await svc.CreateFromProfile(p1, "srv-01", null, "google:admin", default);
        var before = store.GetById(created.Agent.Id)!.AllowedResources;

        // Admin later widens the profile to also grant sudo.
        await profiles.Save(p1 with { ResourceTemplates = new[] { "ssh:{hostname}", "sudo:{hostname}" } }, "google:admin", default);

        // The already-created agent is untouched — no silent privilege expansion.
        var after = store.GetById(created.Agent.Id)!.AllowedResources;
        Assert.Equal(before, after);
        Assert.Equal(new[] { "ssh:srv-01" }, after);
    }

    [Fact]
    public async Task Profile_crud_is_audited()
    {
        var (_, profiles, _, audit) = Fresh();
        await profiles.Save(LinuxServer, "google:admin", default);                 // created
        // A real content change — an identical re-save is intentionally a no-op now.
        await profiles.Save(LinuxServer with { Tags = new[] { "env:prod" } }, "google:admin", default); // updated
        Assert.True(await profiles.Delete("linux-server", "google:admin", default)); // deleted

        var events = await audit.Query(new AuditQuery(), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.AgentProfileCreated && e.Subject == "linux-server");
        Assert.Contains(events, e => e.EventType == AuditEvents.AgentProfileUpdated && e.Subject == "linux-server");
        Assert.Contains(events, e => e.EventType == AuditEvents.AgentProfileDeleted && e.Subject == "linux-server");
    }

    [Fact]
    public void Operation_and_scheme_capabilities_both_authorize()
    {
        // Operation-style (what profiles use).
        var op = new AgentIdentity("a", new[] { AgentCapabilities.Request }, new[] { "ssh:srv-01" }, IsLegacy: false);
        Assert.True(op.MayRepresent("ssh:srv-01", AgentCapabilities.Request));
        Assert.False(op.MayRepresent("ssh:other", AgentCapabilities.Request));       // resource not in scope
        Assert.False(op.MayRepresent("ssh:srv-01", AgentCapabilities.SessionEnd));   // operation not held

        // Scheme-style (pre-0.16 agents) keeps working for any operation.
        var scheme = new AgentIdentity("b", new[] { "ssh" }, new[] { "ssh:srv-01" }, IsLegacy: false);
        Assert.True(scheme.MayRepresent("ssh:srv-01", AgentCapabilities.Request));
        Assert.True(scheme.MayRepresent("ssh:srv-01", AgentCapabilities.Redeem));
    }
}
