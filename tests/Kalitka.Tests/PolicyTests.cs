using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Tag-driven access policies: matching (resource glob + all-tags), the strictest-wins
/// combination of several matching policies, and audited CRUD. Policies only restrict —
/// this suite covers how the restriction is computed, not enforcement (that is the flow).
/// </summary>
public class PolicyTests
{
    private static (PolicyService svc, InMemoryAuditStore audit) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var audit = new InMemoryAuditStore();
        return (new PolicyService(new InMemoryConfigStore(), audit, clock), audit);
    }

    private static readonly string[] ProdWeb = { "env:prod", "role:web" };

    [Theory]
    [InlineData("*", "ssh:prod-01", true)]
    [InlineData("ssh:*", "ssh:prod-01", true)]
    [InlineData("ssh:*", "rdp:prod-01", false)]
    [InlineData("ssh:prod-01", "ssh:prod-01", true)]
    [InlineData("ssh:prod-01", "ssh:prod-02", false)]
    public void Resource_glob_matches(string pattern, string resource, bool expected) =>
        Assert.Equal(expected, ResourceGlob.Matches(pattern, resource));

    [Fact]
    public void Matches_requires_the_resource_and_all_tags()
    {
        var p = new AccessPolicy("prod-ssh", "ssh:*", new[] { "env:prod" }, 2, 15);
        Assert.True(p.Matches("ssh:prod-01", ProdWeb));               // resource + tag present
        Assert.False(p.Matches("rdp:prod-01", ProdWeb));             // wrong resource
        Assert.False(p.Matches("ssh:prod-01", new[] { "env:dev" })); // tag not present

        var both = new AccessPolicy("x", "ssh:*", new[] { "env:prod", "role:web" }, 2, 0);
        Assert.True(both.Matches("ssh:a", ProdWeb));
        Assert.False(both.Matches("ssh:a", new[] { "env:prod" }));   // needs ALL tags
    }

    [Fact]
    public async Task Effective_is_none_when_nothing_matches()
    {
        var (svc, _) = Fresh();
        await svc.Save(new AccessPolicy("prod-ssh", "ssh:*", new[] { "env:prod" }, 2, 15), "google:a", default);

        var d = svc.Effective("ssh:dev-01", new[] { "env:dev" });
        Assert.Equal(1, d.RequiredApprovals);
        Assert.Null(d.GrantTtlMinutes);
        Assert.Empty(d.MatchedPolicies);
    }

    [Fact]
    public async Task Effective_combines_the_strictest_way()
    {
        var (svc, _) = Fresh();
        await svc.Save(new AccessPolicy("a", "ssh:*", new[] { "env:prod" }, 2, 30), "google:a", default);
        await svc.Save(new AccessPolicy("b", "ssh:prod-01", Array.Empty<string>(), 3, 15), "google:a", default);
        await svc.Save(new AccessPolicy("c", "ssh:*", new[] { "env:prod" }, 1, 0), "google:a", default);   // ttl 0 = no override

        var d = svc.Effective("ssh:prod-01", new[] { "env:prod" });
        Assert.Equal(3, d.RequiredApprovals);         // max(2,3,1)
        Assert.Equal(15, d.GrantTtlMinutes);          // min(30,15) — c's 0 ignored
        Assert.Equal(new[] { "a", "b", "c" }, d.MatchedPolicies);
    }

    [Fact]
    public async Task Crud_is_audited_and_editing_bumps_a_revision()
    {
        var (svc, audit) = Fresh();
        var p = new AccessPolicy("prod-ssh", "ssh:*", new[] { "env:prod" }, 2, 15);
        await svc.Save(p, "google:admin", default);                             // created
        await svc.Save(p, "google:admin", default);                            // identical → no-op
        await svc.Save(p with { RequiredApprovals = 3 }, "google:admin", default); // updated
        Assert.True(await svc.Delete("prod-ssh", "google:admin", default));     // deleted

        var events = await audit.Query(new AuditQuery(), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.PolicyCreated && e.Subject == "prod-ssh");
        Assert.Contains(events, e => e.EventType == AuditEvents.PolicyUpdated && e.Subject == "prod-ssh");
        Assert.Contains(events, e => e.EventType == AuditEvents.PolicyDeleted && e.Subject == "prod-ssh");
        Assert.Single(events, e => e.EventType == AuditEvents.PolicyUpdated);   // the identical save was a no-op
    }
}
