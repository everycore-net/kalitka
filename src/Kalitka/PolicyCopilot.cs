namespace Kalitka;

/// <summary>How a proposed change lands on one agent (by its tags), at the probe resource.</summary>
public sealed record AgentImpact(string AgentId, string DisplayName, string[] Tags, PolicyImpact Impact);

/// <summary>The deterministic preview of a proposed policy change across the current fleet: the
/// per-agent impact, the worst-case class, and whether it expands anyone's effective authority.</summary>
public sealed record CopilotPreview(
    string Resource,
    PolicyImpactClass Overall,
    bool RequiresApproval,
    AgentImpact[] Affected);

/// <summary>The outcome of applying a change through the copilot.</summary>
public sealed record CopilotApplyResult(bool Applied, bool NeedsConfirmation, PolicyImpactClass Overall, string? Error = null);

/// <summary>
/// The deterministic backbone of the policy copilot — the "kalitka produces authority" half. A
/// proposed change (whatever produced it — a human in the console, or later an LLM translating
/// intent) is never trusted to be safe: it is run through <see cref="PolicyService.Simulate"/>
/// against every current agent, classified (No change / Restriction / Authority expansion / Mixed),
/// and only applied by a human — with an explicit confirmation whenever it would <b>expand</b>
/// anyone's effective authority. The copilot never decides what is allowed; it retells a
/// deterministic impact and gates the apply.
/// </summary>
public sealed class PolicyCopilot
{
    private readonly PolicyService _policies;
    private readonly IAgentStore _agents;

    public PolicyCopilot(PolicyService policies, IAgentStore agents)
    {
        _policies = policies;
        _agents = agents;
    }

    /// <summary>Preview a change across the fleet. The probe resource is derived from the change's
    /// own match resource (a <c>scheme:*</c> glob becomes a concrete probe under that scheme, so
    /// scheme-wide policies are captured but unrelated concrete policies are not), and every agent's
    /// tag-set is evaluated — so an expansion cannot hide in a context the caller forgot to pass.</summary>
    public CopilotPreview Preview(PolicyChange change)
    {
        var resource = ResourceOf(change);
        var probe = Probe(resource);
        var affected = new List<AgentImpact>();
        var classes = new List<PolicyImpactClass>();
        foreach (var a in _agents.Snapshot())
        {
            var impact = _policies.Simulate(change, probe, a.Tags);
            classes.Add(impact.Class);
            if (impact.Class != PolicyImpactClass.NoChange)
                affected.Add(new AgentImpact(a.Id, a.DisplayName, a.Tags, impact));
        }
        var overall = Aggregate(classes);
        return new CopilotPreview(resource, overall,
            overall is PolicyImpactClass.AuthorityExpansion or PolicyImpactClass.MixedChange, affected.ToArray());
    }

    /// <summary>Apply a change. If it would expand effective authority anywhere it needs an explicit
    /// <paramref name="confirmExpansion"/>; without it nothing changes and the caller is told
    /// confirmation is required. A pure restriction (or no effective change) applies directly.</summary>
    public async Task<CopilotApplyResult> Apply(PolicyChange change, bool confirmExpansion, string actor, CancellationToken ct)
    {
        var preview = Preview(change);
        if (preview.RequiresApproval && !confirmExpansion)
            return new CopilotApplyResult(false, true, preview.Overall);

        switch (change)
        {
            case PolicyChange.Upsert u:
                await _policies.Save(u.Policy, actor, ct);
                return new CopilotApplyResult(true, false, preview.Overall);
            case PolicyChange.Remove r:
                var removed = await _policies.Delete(r.Name, actor, ct);
                return removed
                    ? new CopilotApplyResult(true, false, preview.Overall)
                    : new CopilotApplyResult(false, false, preview.Overall, "no-such-policy");
            default:
                return new CopilotApplyResult(false, false, preview.Overall, "unknown-change");
        }
    }

    private string ResourceOf(PolicyChange change) => change switch
    {
        PolicyChange.Upsert u => u.Policy.MatchResource,
        PolicyChange.Remove r => _policies.Get(r.Name)?.MatchResource ?? "",
        _ => "",
    };

    // A concrete probe that a scheme-wide policy matches but unrelated concrete policies do not.
    private static string Probe(string matchResource)
    {
        if (string.IsNullOrEmpty(matchResource) || matchResource == "*") return "probe:__probe__";
        if (matchResource.EndsWith(":*", StringComparison.Ordinal)) return matchResource[..^1] + "__probe__";
        return matchResource;   // already concrete
    }

    private static PolicyImpactClass Aggregate(IEnumerable<PolicyImpactClass> classes)
    {
        bool restricts = false, expands = false;
        foreach (var c in classes)
        {
            if (c is PolicyImpactClass.Restriction or PolicyImpactClass.MixedChange) restricts = true;
            if (c is PolicyImpactClass.AuthorityExpansion or PolicyImpactClass.MixedChange) expands = true;
        }
        return restricts && expands ? PolicyImpactClass.MixedChange
            : expands ? PolicyImpactClass.AuthorityExpansion
            : restricts ? PolicyImpactClass.Restriction
            : PolicyImpactClass.NoChange;
    }
}
