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

    /// <summary>Optional grant-profile glob this policy applies to (e.g. <c>sql-dba</c>,
    /// <c>sql-*</c>); empty = any profile. Lets the operational model raise the bar per
    /// operation class — e.g. a DDL profile needs more approvers than read-only.</summary>
    public string MatchProfile { get; init; } = "";

    /// <summary>When set, a matching request MUST carry a command (0.26): no open-shell /
    /// interactive access to this resource — only a specific, approved command (an SSH
    /// cert with a <c>force-command</c>). Restrict-only: it can forbid the open shell, never
    /// grant one.</summary>
    public bool RequireCommand { get; init; }

    /// <summary>When set, a matching request MUST carry a source address (0.26.1): access
    /// to this resource is pinned to an approved source CIDR (an SSH cert
    /// <c>source-address</c>). Restrict-only.</summary>
    public bool RequireSourceAddress { get; init; }

    /// <summary>Optional allow-list of principals (target logins) a matching request may
    /// ask for (0.26.1); empty = no constraint. Restrict-only: the requested login must be
    /// in it, so a policy can permit <c>deploy</c>/<c>readonly</c> but never <c>root</c> for
    /// a resource. Several matching policies intersect (a login must satisfy every one).</summary>
    public string[] AllowedPrincipals { get; init; } = Array.Empty<string>();

    public bool SameContent(AccessPolicy other) =>
        string.Equals(MatchResource, other.MatchResource, StringComparison.OrdinalIgnoreCase)
        && MatchTags.SequenceEqual(other.MatchTags)
        && string.Equals(MatchProfile, other.MatchProfile, StringComparison.OrdinalIgnoreCase)
        && RequireCommand == other.RequireCommand
        && RequireSourceAddress == other.RequireSourceAddress
        && AllowedPrincipals.SequenceEqual(other.AllowedPrincipals)
        && RequiredApprovals == other.RequiredApprovals
        && GrantTtlMinutes == other.GrantTtlMinutes;

    /// <summary>Does this policy apply to a request for <paramref name="resource"/> with
    /// grant <paramref name="profile"/> raised by an agent carrying <paramref name="tags"/>?
    /// The resource must match the glob, every <see cref="MatchTags"/> entry must be on the
    /// agent, and (if set) the profile must match <see cref="MatchProfile"/>.</summary>
    public bool Matches(string resource, IReadOnlyCollection<string> tags, string profile = "") =>
        ResourceGlob.Matches(MatchResource, resource)
        && MatchTags.All(t => tags.Any(x => string.Equals(x, t, StringComparison.OrdinalIgnoreCase)))
        && (MatchProfile.Length == 0 || ResourceGlob.Matches(MatchProfile, profile));
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
public sealed record PolicyDecision(int RequiredApprovals, int? GrantTtlMinutes, string[] MatchedPolicies,
    bool RequireCommand = false, bool RequireSourceAddress = false, string[]? AllowedPrincipals = null)
{
    public static readonly PolicyDecision None = new(1, null, Array.Empty<string>());

    /// <summary>Effective principal allow-list (intersection across matching policies);
    /// null/empty = no constraint. A requested login must be in it (case-insensitive).</summary>
    public bool PrincipalAllowed(string login) =>
        AllowedPrincipals is not { Length: > 0 } allow
        || allow.Any(p => string.Equals(p, login, StringComparison.OrdinalIgnoreCase));
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
    public PolicyDecision Effective(string resource, IReadOnlyCollection<string> agentTags, string profile = "")
    {
        var matched = All().Where(p => p.Matches(resource, agentTags, profile)).ToList();
        if (matched.Count == 0) return PolicyDecision.None;

        var required = Math.Max(1, matched.Max(p => p.RequiredApprovals));
        var ttls = matched.Where(p => p.GrantTtlMinutes > 0).Select(p => p.GrantTtlMinutes).ToList();
        int? ttl = ttls.Count > 0 ? ttls.Min() : null;
        var requireCommand = matched.Any(p => p.RequireCommand);   // most-restrictive: any wins
        var requireSource = matched.Any(p => p.RequireSourceAddress);
        // Principal allow-lists intersect: a login must be permitted by EVERY constraining
        // policy (those that set one). Policies with no list impose no constraint.
        var constraints = matched.Where(p => p.AllowedPrincipals.Length > 0)
            .Select(p => (ISet<string>)new HashSet<string>(p.AllowedPrincipals, StringComparer.OrdinalIgnoreCase))
            .ToList();
        string[]? allowed = null;
        if (constraints.Count > 0)
        {
            var inter = constraints.Aggregate((a, b) => { a.IntersectWith(b); return a; });
            allowed = inter.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        return new PolicyDecision(required, ttl, matched.Select(p => p.Name).OrderBy(n => n).ToArray(),
            requireCommand, requireSource, allowed);
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
