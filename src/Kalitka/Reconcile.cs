using System.Text;

namespace Kalitka;

/// <summary>
/// Deliberate, audited application of profile changes to already-enrolled agents.
/// This is <b>not</b> a policy engine: the agent's own snapshot stays the source of
/// truth. Reconciliation is a three-way merge anchored to the profile revision the
/// agent was last synced to (<see cref="Agent.AppliedProfileRevision"/>):
/// <list type="bullet">
///   <item>base = the profile at that revision, expanded against the agent's hostname;</item>
///   <item>theirs = the profile now, expanded against the same hostname;</item>
///   <item>mine = the agent's current snapshot.</item>
/// </list>
/// Only what the <i>profile</i> changed between base and theirs is applied; anything
/// the admin changed locally on the agent (added or removed by hand) is preserved.
/// Anything that would <b>grant</b> the agent a new capability or resource is an
/// expansion and never applies without explicit confirmation.
/// </summary>
public sealed class ReconcileService
{
    private static readonly StringComparer Cmp = StringComparer.OrdinalIgnoreCase;

    private readonly IAgentStore _agents;
    private readonly ProfileService _profiles;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public ReconcileService(IAgentStore agents, ProfileService profiles, IAuditStore audit, TimeProvider? clock = null)
    {
        _agents = agents;
        _profiles = profiles;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>What reconciling one agent would do. The diff is expressed as changes
    /// to the <i>agent</i> (not the profile): capabilities/resources it gains or loses
    /// and tag changes, plus the revision it moves from and to.</summary>
    public sealed record Plan(
        string AgentId,
        string ProfileId,
        string Hostname,
        int FromRevision,
        int ToRevision,
        string[] AddedCapabilities,
        string[] RemovedCapabilities,
        string[] AddedResources,
        string[] RemovedResources,
        string[] AddedTags,
        string[] RemovedTags,
        Agent Target)
    {
        /// <summary>Grants the agent a capability or resource it does not currently
        /// have — must be confirmed. Tag additions are metadata, not privilege.</summary>
        public bool IsExpansion => AddedCapabilities.Length > 0 || AddedResources.Length > 0;

        public bool RemovesPrivilege => RemovedCapabilities.Length > 0 || RemovedResources.Length > 0;

        /// <summary>Sudo-grade capabilities this plan grants / revokes (e.g. <c>subject.assert</c>)
        /// — surfaced on their own so a privilege-over-the-decision change is never a quiet
        /// line in a profile diff.</summary>
        public string[] PrivilegedGranted => AddedCapabilities.Where(AgentCapabilities.IsPrivileged).ToArray();
        public string[] PrivilegedRevoked => RemovedCapabilities.Where(AgentCapabilities.IsPrivileged).ToArray();
        public bool TouchesPrivileged => PrivilegedGranted.Length > 0 || PrivilegedRevoked.Length > 0;

        /// <summary>Anything to do at all — a content change or just moving the revision
        /// pointer forward after drift was fully absorbed by local overrides.</summary>
        public bool HasChanges =>
            AddedCapabilities.Length + RemovedCapabilities.Length +
            AddedResources.Length + RemovedResources.Length +
            AddedTags.Length + RemovedTags.Length > 0 || FromRevision != ToRevision;

        /// <summary>A compact, queryable diff for the audit log — the profile change
        /// that was applied, not a JSON dump.</summary>
        public string Diff()
        {
            var sb = new StringBuilder();
            sb.Append("rev ").Append(FromRevision).Append("->").Append(ToRevision);
            Part(sb, "caps", AddedCapabilities, RemovedCapabilities);
            Part(sb, "res", AddedResources, RemovedResources);
            Part(sb, "tags", AddedTags, RemovedTags);
            return sb.ToString();

            static void Part(StringBuilder sb, string label, string[] added, string[] removed)
            {
                if (added.Length == 0 && removed.Length == 0) return;
                sb.Append("; ").Append(label).Append(':');
                // A privileged capability is marked with '!' so it stands out in the audit line.
                foreach (var a in added) sb.Append(AgentCapabilities.IsPrivileged(a) ? " +!" : " +").Append(a);
                foreach (var r in removed) sb.Append(AgentCapabilities.IsPrivileged(r) ? " -!" : " -").Append(r);
            }
        }
    }

    /// <summary>Compute the plan for one agent, or null if it is not profile-managed
    /// or its profile no longer exists (a deleted profile leaves the snapshot intact —
    /// nothing to reconcile against).</summary>
    public Plan? Preview(string agentId)
    {
        var agent = _agents.GetById(agentId);
        if (agent is null || string.IsNullOrEmpty(agent.ProfileId)) return null;
        var current = _profiles.Get(agent.ProfileId);
        if (current is null) return null;
        return Preview(agent, current);
    }

    /// <summary>Every managed agent that has pending changes against its current
    /// profile — the reconcile overview.</summary>
    public IReadOnlyList<Plan> PreviewAll()
    {
        var byName = _profiles.All().ToDictionary(p => p.Name, p => p, Cmp);
        var plans = new List<Plan>();
        foreach (var a in _agents.Snapshot())
        {
            if (string.IsNullOrEmpty(a.ProfileId) || !byName.TryGetValue(a.ProfileId, out var p)) continue;
            var plan = Preview(a, p);
            if (plan.HasChanges) plans.Add(plan);
        }
        return plans;
    }

    private Plan Preview(Agent agent, AgentProfile current)
    {
        var hostname = agent.ProfileHostname;

        // Base = the revision the agent was last synced to. If it can no longer be
        // found (e.g. profile deleted and recreated) anchor on an empty base, so the
        // whole current profile shows up as additions needing confirmation.
        var applied = _profiles.GetRevision(agent.ProfileId, agent.AppliedProfileRevision);
        var (baseCaps, baseRes, baseTags) = applied?.Expand(hostname) ?? (Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());
        var (curCaps, curRes, curTags) = current.Expand(hostname);

        // Three-way merge: apply only what the profile changed, keep local overrides.
        var newCaps = Merge(agent.Capabilities, baseCaps, curCaps);
        var newRes = Merge(agent.AllowedResources, baseRes, curRes);
        var newTags = Merge(agent.Tags, baseTags, curTags);

        var target = agent with
        {
            Capabilities = newCaps,
            AllowedResources = newRes,
            Tags = newTags,
            AppliedProfileRevision = current.Revision,
        };

        return new Plan(
            agent.Id, agent.ProfileId, hostname,
            agent.AppliedProfileRevision, current.Revision,
            Only(newCaps, agent.Capabilities), Only(agent.Capabilities, newCaps),
            Only(newRes, agent.AllowedResources), Only(agent.AllowedResources, newRes),
            Only(newTags, agent.Tags), Only(agent.Tags, newTags),
            target);
    }

    public sealed record ApplyResult(bool Applied, bool NeedsConfirmation, Plan? Plan, string? Error = null);

    /// <summary>Apply the plan. An expansion (new capability/resource) requires
    /// <paramref name="confirmExpansion"/>; without it the caller is told confirmation
    /// is needed and nothing changes. The applied diff is written to the audit log.</summary>
    public async Task<ApplyResult> Apply(string agentId, bool confirmExpansion, string actor, CancellationToken ct)
    {
        var plan = Preview(agentId);
        if (plan is null) return new(false, false, null, "not-managed");
        if (!plan.HasChanges) return new(false, false, plan);
        if (plan.IsExpansion && !confirmExpansion) return new(false, true, plan);

        _agents.Create(plan.Target);   // upsert
        await _audit.Append(new AuditEvent(
            Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), AuditEvents.AgentProfileApplied, actor,
            Subject: agentId, Resource: plan.ProfileId, RequestId: "", GrantId: agentId,
            Channel: "agent", Metadata: plan.Diff()), ct);
        // A sudo-grade capability changing hands gets its own conspicuous, queryable event —
        // not just a marker inside the profile-applied diff.
        if (plan.TouchesPrivileged)
            await _audit.Append(new AuditEvent(
                Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), AuditEvents.AgentPrivilegedCapability, actor,
                Subject: agentId, Resource: plan.ProfileId, RequestId: "", GrantId: agentId, Channel: "agent",
                Metadata: Privileged(plan.PrivilegedGranted, plan.PrivilegedRevoked)), ct);
        return new(true, false, plan);
    }

    // mine ∪ (theirs \ base)  −  (base \ theirs): take the profile's additions and
    // removals between base and theirs, apply them to the agent's own set.
    private static string[] Merge(string[] mine, string[] @base, string[] theirs)
    {
        var added = Only(theirs, @base);
        var removed = Only(@base, theirs);
        return Except(mine.Concat(added).Distinct(Cmp), removed);
    }

    // A compact description of a privileged-capability change for the audit log.
    internal static string Privileged(string[] granted, string[] revoked)
    {
        var sb = new StringBuilder();
        foreach (var g in granted) sb.Append(sb.Length > 0 ? " " : "").Append("granted ").Append(g);
        foreach (var r in revoked) sb.Append(sb.Length > 0 ? " " : "").Append("revoked ").Append(r);
        return sb.ToString();
    }

    private static string[] Only(string[] a, string[] b) => a.Where(x => !b.Contains(x, Cmp)).ToArray();
    private static string[] Except(IEnumerable<string> a, string[] remove) => a.Where(x => !remove.Contains(x, Cmp)).ToArray();
}
