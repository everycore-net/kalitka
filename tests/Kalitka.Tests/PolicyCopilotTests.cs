using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The policy copilot's deterministic backbone — the "kalitka produces authority" half. A proposed
/// change is simulated across the whole fleet, classified, and only applied by a human; anything
/// that expands effective authority for any agent needs an explicit confirmation. The copilot never
/// decides what is allowed — it retells a deterministic impact and gates the apply.
/// </summary>
public class PolicyCopilotTests
{
    private const string Actor = "google:admin";

    private static (PolicyCopilot copilot, PolicyService policies, InMemoryAgentStore agents) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var policies = new PolicyService(new InMemoryConfigStore(), new InMemoryAuditStore(), clock);
        var agents = new InMemoryAgentStore();
        return (new PolicyCopilot(policies, agents), policies, agents);
    }

    private static void AddAgent(InMemoryAgentStore agents, string id, params string[] tags) =>
        agents.Create(new Agent(id, id, "linux", "h", AgentStatus.Active, "hash",
            new[] { "ssh" }, new[] { "ssh:*" }, "", DateTimeOffset.UnixEpoch, null, "", null) { Tags = tags });

    private static AccessPolicy P(string name, int required) =>
        new(name, "ssh:*", new[] { "env:prod" }, required, 0);

    [Fact]
    public void Lowering_approvals_is_an_authority_expansion_that_needs_confirmation()
    {
        var (copilot, policies, agents) = Fresh();
        policies.Save(P("p", 2), Actor, default).GetAwaiter().GetResult();
        AddAgent(agents, "prod-a", "env:prod");
        AddAgent(agents, "dev-a", "env:dev");   // not matched — should be unaffected

        var preview = copilot.Preview(new PolicyChange.Upsert(P("p", 1)));

        Assert.Equal(PolicyImpactClass.AuthorityExpansion, preview.Overall);
        Assert.True(preview.RequiresApproval);
        var affected = Assert.Single(preview.Affected);
        Assert.Equal("prod-a", affected.AgentId);   // only the matching agent
    }

    [Fact]
    public void Raising_approvals_is_a_restriction_and_applies_without_confirmation()
    {
        var (copilot, policies, agents) = Fresh();
        policies.Save(P("p", 2), Actor, default).GetAwaiter().GetResult();
        AddAgent(agents, "prod-a", "env:prod");

        var preview = copilot.Preview(new PolicyChange.Upsert(P("p", 3)));
        Assert.Equal(PolicyImpactClass.Restriction, preview.Overall);
        Assert.False(preview.RequiresApproval);
    }

    [Fact]
    public void A_change_that_matches_no_agent_is_no_effective_change()
    {
        var (copilot, _, agents) = Fresh();
        AddAgent(agents, "dev-a", "env:dev");
        var preview = copilot.Preview(new PolicyChange.Upsert(P("p", 1)));   // requires env:prod, nobody has it
        Assert.Equal(PolicyImpactClass.NoChange, preview.Overall);
        Assert.Empty(preview.Affected);
    }

    [Fact]
    public async Task Apply_refuses_an_expansion_without_confirmation_then_applies_with_it()
    {
        var (copilot, policies, agents) = Fresh();
        await policies.Save(P("p", 2), Actor, default);
        AddAgent(agents, "prod-a", "env:prod");

        var blocked = await copilot.Apply(new PolicyChange.Upsert(P("p", 1)), confirmExpansion: false, Actor, default);
        Assert.False(blocked.Applied);
        Assert.True(blocked.NeedsConfirmation);
        Assert.Equal(2, policies.Get("p")!.RequiredApprovals);   // unchanged

        var done = await copilot.Apply(new PolicyChange.Upsert(P("p", 1)), confirmExpansion: true, Actor, default);
        Assert.True(done.Applied);
        Assert.Equal(1, policies.Get("p")!.RequiredApprovals);
    }

    [Fact]
    public async Task Apply_of_a_restriction_needs_no_confirmation()
    {
        var (copilot, policies, agents) = Fresh();
        await policies.Save(P("p", 2), Actor, default);
        AddAgent(agents, "prod-a", "env:prod");

        var done = await copilot.Apply(new PolicyChange.Upsert(P("p", 3)), confirmExpansion: false, Actor, default);
        Assert.True(done.Applied);
        Assert.Equal(3, policies.Get("p")!.RequiredApprovals);
    }

    [Fact]
    public async Task Removing_a_restricting_policy_is_an_expansion_that_needs_confirmation()
    {
        var (copilot, policies, agents) = Fresh();
        await policies.Save(P("guard", 2), Actor, default);
        AddAgent(agents, "prod-a", "env:prod");

        var blocked = await copilot.Apply(new PolicyChange.Remove("guard"), confirmExpansion: false, Actor, default);
        Assert.False(blocked.Applied);
        Assert.True(blocked.NeedsConfirmation);
        Assert.NotNull(policies.Get("guard"));   // still there

        var done = await copilot.Apply(new PolicyChange.Remove("guard"), confirmExpansion: true, Actor, default);
        Assert.True(done.Applied);
        Assert.Null(policies.Get("guard"));
    }
}
