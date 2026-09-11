using System.Text.Json;

namespace Kalitka;

/// <summary>
/// A tag-driven access policy. A policy <b>only ever restricts</b> — it can raise the
/// number of approvals a request needs or shorten the grant's life, but it can never
/// grant an agent a capability or resource. The agent's own authority (capability +
/// allowed resource) is always checked first; a matching policy is applied on top.
///
/// It matches a request by its resource (glob, e.g. <c>ssh:*</c>) and by tags that
/// must all be present on the requesting agent (<c>env:prod</c>). Several matching
/// policies combine the <i>most-restrictive</i> way (see <see cref="PolicyService"/>),
/// so there is no rule ordering to reason about.
/// </summary>
public sealed record AccessPolicy(
    string Name,
    string MatchResource,      // "ssh:*" | "ssh:prod-01" | "*"
    string[] MatchTags,        // key:value tokens; ALL must be present on the agent
    int RequiredApprovals,     // >= 1
    int GrantTtlMinutes)       // 0 = no override (keep the global grant lifetime)
{
    /// <summary>Bumped on each content change (append-only history in the store).</summary>
    public int Revision { get; init; }

    public bool SameContent(AccessPolicy other) =>
        string.Equals(MatchResource, other.MatchResource, StringComparison.OrdinalIgnoreCase)
        && MatchTags.SequenceEqual(other.MatchTags)
        && RequiredApprovals == other.RequiredApprovals
        && GrantTtlMinutes == other.GrantTtlMinutes;

    /// <summary>Does this policy apply to a request for <paramref name="resource"/>
    /// raised by an agent carrying <paramref name="tags"/>? The resource must match the
    /// glob and every <see cref="MatchTags"/> entry must be present on the agent.</summary>
    public bool Matches(string resource, IReadOnlyCollection<string> tags) =>
        ResourceGlob.Matches(MatchResource, resource)
        && MatchTags.All(t => tags.Any(x => string.Equals(x, t, StringComparison.OrdinalIgnoreCase)));
}

/// <summary>Resource glob matching, shared with the agent authority model: an exact
/// name, a <c>scheme:*</c> prefix, or the catch-all <c>*</c>.</summary>
public static class ResourceGlob
{
    public static bool Matches(string pattern, string resource)
    {
        if (pattern == "*") return true;
        if (string.Equals(pattern, resource, StringComparison.OrdinalIgnoreCase)) return true;
        return pattern.EndsWith(":*", StringComparison.Ordinal)
            && resource.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>The constraints in force for a request, after combining every matching
/// policy. Empty/default (<see cref="RequiredApprovals"/> = 1, no TTL override) when
/// nothing matches.</summary>
public sealed record PolicyDecision(int RequiredApprovals, int? GrantTtlMinutes, string[] MatchedPolicies)
{
    public static readonly PolicyDecision None = new(1, null, Array.Empty<string>());
}

/// <summary>
/// Where access policies live — one JSON blob in the shared <see cref="IConfigStore"/>,
/// so they are durable and cluster-wide, with the same append-only revision history as
/// profiles. CRUD is audited. Policies grant nothing, so there is no authorization here
/// beyond the admin console (<c>policies.manage</c>).
/// </summary>
public sealed class PolicyService
{
    private const string Key = "access-policies";

    private readonly IConfigStore _config;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public PolicyService(IConfigStore config, IAuditStore audit, TimeProvider? clock = null)
    {
        _config = config;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    public IReadOnlyList<AccessPolicy> All() =>
        History().GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                 .Select(g => g.OrderByDescending(p => p.Revision).First())
                 .OrderBy(p => p.Name).ToList();

    public AccessPolicy? Get(string name) =>
        History().Where(p => Eq(p.Name, name)).OrderByDescending(p => p.Revision).FirstOrDefault();

    /// <summary>
    /// The effective constraints for a request: the strictest combination of every
    /// matching policy. Restrictive numeric constraints compose cleanly — more
    /// approvals wins (<c>max</c>), a shorter grant wins (<c>min</c>) — so there is no
    /// priority or first-match to reason about. Never returns fewer approvals than 1.
    /// </summary>
    public PolicyDecision Effective(string resource, IReadOnlyCollection<string> agentTags)
    {
        var matched = All().Where(p => p.Matches(resource, agentTags)).ToList();
        if (matched.Count == 0) return PolicyDecision.None;

        var required = Math.Max(1, matched.Max(p => p.RequiredApprovals));
        var ttls = matched.Where(p => p.GrantTtlMinutes > 0).Select(p => p.GrantTtlMinutes).ToList();
        int? ttl = ttls.Count > 0 ? ttls.Min() : null;
        return new PolicyDecision(required, ttl, matched.Select(p => p.Name).OrderBy(n => n).ToArray());
    }

    public async Task Save(AccessPolicy policy, string actor, CancellationToken ct)
    {
        string? outcome = null;   // "created" | "updated" | null (no-op)
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            var latest = hist.Where(p => Eq(p.Name, policy.Name)).OrderByDescending(p => p.Revision).FirstOrDefault();
            if (latest is not null && latest.SameContent(policy)) return JsonSerializer.Serialize(hist);
            hist.Add(policy with { Revision = (latest?.Revision ?? 0) + 1 });
            outcome = latest is null ? "created" : "updated";
            return JsonSerializer.Serialize(hist);
        });
        if (outcome == "created") await _audit.Append(Ev(AuditEvents.PolicyCreated, actor, policy.Name), ct);
        else if (outcome == "updated") await _audit.Append(Ev(AuditEvents.PolicyUpdated, actor, policy.Name), ct);
    }

    public async Task<bool> Delete(string name, string actor, CancellationToken ct)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            removed = hist.RemoveAll(p => Eq(p.Name, name)) > 0;
            return JsonSerializer.Serialize(hist);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.PolicyDeleted, actor, name), ct);
        return removed;
    }

    private List<AccessPolicy> History() => Parse(_config.Get(Key));
    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static List<AccessPolicy> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<AccessPolicy>>(blob) ?? new());

    private AuditEvent Ev(string type, string actor, string policyName) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: policyName, Resource: "", RequestId: "", GrantId: "", Channel: "admin", Metadata: "");
}
