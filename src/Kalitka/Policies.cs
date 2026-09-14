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
/// <summary>How a request's own subject relates to its approval (0.30.1).</summary>
public enum SubjectApproval { Optional, Required, Forbidden }

/// <summary>Persisting <see cref="SubjectApproval"/> as a short string (empty = optional),
/// so an older row without the column reads as the safe default.</summary>
public static class SubjectModes
{
    public static string ToDb(SubjectApproval s) => s == SubjectApproval.Optional ? "" : s.ToString().ToLowerInvariant();
    public static SubjectApproval FromDb(string? s) => s switch
    {
        "required" => SubjectApproval.Required,
        "forbidden" => SubjectApproval.Forbidden,
        _ => SubjectApproval.Optional,
    };
}

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

    /// <summary>How the request's own subject relates to approval (0.30.1), orthogonal to
    /// <see cref="RequiredApprovals"/>: <c>Optional</c> (default) the subject may approve and
    /// counts as one principal; <c>Required</c> the subject MUST approve AND `required`
    /// distinct principals in total (requester-confirmation composed with four-eyes);
    /// <c>Forbidden</c> the requester may not approve at all (clean four-eyes by others). For
    /// Required/Forbidden the subject is trusted only when a capable agent ASSERTED it (see
    /// <see cref="AgentCapabilities.AssertSubject"/>), never a requester string. Distinctness
    /// is by operator principal, never by channel.</summary>
    public SubjectApproval Subject { get; init; } = SubjectApproval.Optional;

    public bool SameContent(AccessPolicy other) =>
        string.Equals(MatchResource, other.MatchResource, StringComparison.OrdinalIgnoreCase)
        && MatchTags.SequenceEqual(other.MatchTags)
        && string.Equals(MatchProfile, other.MatchProfile, StringComparison.OrdinalIgnoreCase)
        && RequireCommand == other.RequireCommand
        && RequireSourceAddress == other.RequireSourceAddress
        && Subject == other.Subject
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
    bool RequireCommand = false, bool RequireSourceAddress = false, string[]? AllowedPrincipals = null,
    SubjectApproval Subject = SubjectApproval.Optional)
{
    public static readonly PolicyDecision None = new(1, null, Array.Empty<string>());

    /// <summary>Effective principal allow-list (intersection across matching policies);
    /// null/empty = no constraint. A requested login must be in it (case-insensitive).</summary>
    public bool PrincipalAllowed(string login) =>
        AllowedPrincipals is not { Length: > 0 } allow
        || allow.Any(p => string.Equals(p, login, StringComparison.OrdinalIgnoreCase));
}

/// <summary>One policy in an <see cref="PolicyExplanation"/>: whether it matched the request
/// context and, in plain words, why (the first failing clause, or "matched").</summary>
public sealed record PolicyMatch(string Name, int Revision, bool Matched, string Reason);

/// <summary>Which matched policy/policies set one effective value — the provenance that turns
/// a decision into an explanation ("approvals=2 from prod-ddl").</summary>
public sealed record EffectiveSource(string Field, string Value, string[] FromPolicies);

/// <summary>A deterministic trace of the effective decision for one concrete request context.</summary>
public sealed record PolicyExplanation(
    string Resource,
    string[] AgentTags,
    string Profile,
    PolicyMatch[] Considered,
    PolicyDecision Effective,
    EffectiveSource[] Sources);

/// <summary>How a proposed change moves effective authority. A policy set only restricts an
/// agent's own authority, so a change is deterministically one of these — and the last two
/// (a request that was harder is now easier) are what must earn a separate approval.</summary>
public enum PolicyImpactClass { NoChange, Restriction, AuthorityExpansion, MixedChange }

/// <summary>A proposed edit to the policy set, evaluated by <see cref="PolicyService.Simulate"/>
/// without being saved.</summary>
public abstract record PolicyChange
{
    private PolicyChange() { }
    /// <summary>Create or replace the policy of this name.</summary>
    public sealed record Upsert(AccessPolicy Policy) : PolicyChange;
    /// <summary>Delete the policy of this name.</summary>
    public sealed record Remove(string Name) : PolicyChange;
}

/// <summary>One field's before/after in an impact analysis and how it moved.</summary>
public sealed record FieldDelta(string Field, string Before, string After, PolicyImpactClass Class);

/// <summary>The impact of a proposed change on one concrete request context.</summary>
public sealed record PolicyImpact(
    string Resource,
    string[] AgentTags,
    string Profile,
    PolicyDecision Before,
    PolicyDecision After,
    FieldDelta[] Deltas,
    PolicyImpactClass Class,
    bool RequiresApproval);

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
    public PolicyDecision Effective(string resource, IReadOnlyCollection<string> agentTags, string profile = "") =>
        Compose(All(), resource, agentTags, profile).Decision;

    /// <summary>
    /// The one composition of policies into an effective decision — the single code path the
    /// request engine, <see cref="Explain"/> and <see cref="Simulate"/> all go through, so a
    /// trace or an impact analysis can never disagree with what the engine would actually do.
    /// Pure over its inputs (takes the policy set explicitly), so <see cref="Simulate"/> can
    /// run it against a hypothetical set without touching the store.
    /// </summary>
    internal static (PolicyDecision Decision, List<AccessPolicy> Matched) Compose(
        IReadOnlyList<AccessPolicy> policies, string resource, IReadOnlyCollection<string> agentTags, string profile = "")
    {
        var matched = policies.Where(p => p.Matches(resource, agentTags, profile)).ToList();
        if (matched.Count == 0) return (PolicyDecision.None, matched);

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
        // Most-restrictive wins: Forbidden (requester can't vote) beats Required beats Optional.
        var subject = matched.Any(p => p.Subject == SubjectApproval.Forbidden) ? SubjectApproval.Forbidden
            : matched.Any(p => p.Subject == SubjectApproval.Required) ? SubjectApproval.Required
            : SubjectApproval.Optional;
        var decision = new PolicyDecision(required, ttl, matched.Select(p => p.Name).OrderBy(n => n).ToArray(),
            requireCommand, requireSource, allowed, subject);
        return (decision, matched);
    }

    /// <summary>
    /// A deterministic, human-readable trace of the decision for one concrete request context:
    /// which policies were considered and why each did or did not match, the composed effective
    /// decision, and — the part an operator actually wants — which policy set each strictest
    /// value. Valuable on its own in the console, and the ground truth a policy copilot may
    /// only ever retell, never invent.
    /// </summary>
    public PolicyExplanation Explain(string resource, IReadOnlyCollection<string> agentTags, string profile = "")
    {
        var all = All();
        var (decision, matched) = Compose(all, resource, agentTags, profile);
        var matchedNames = matched.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var considered = all.Select(p => new PolicyMatch(
            p.Name, p.Revision, matchedNames.Contains(p.Name),
            MatchReason(p, resource, agentTags, profile))).ToArray();

        // Attribution reads the already-composed decision — it never re-derives the numbers,
        // so it cannot drift from what the engine decided.
        var sources = matched.Count == 0 ? Array.Empty<EffectiveSource>() : Attribute(decision, matched);
        return new PolicyExplanation(resource, agentTags.ToArray(), profile, considered, decision, sources);
    }

    // Why a policy matched or not — the first failing clause, so the trace is actionable.
    private static string MatchReason(AccessPolicy p, string resource, IReadOnlyCollection<string> tags, string profile)
    {
        if (!ResourceGlob.Matches(p.MatchResource, resource))
            return $"resource {resource} not matched by {p.MatchResource}";
        var missing = p.MatchTags.FirstOrDefault(t => !tags.Any(x => string.Equals(x, t, StringComparison.OrdinalIgnoreCase)));
        if (missing is not null) return $"agent lacks tag {missing}";
        if (p.MatchProfile.Length > 0 && !ResourceGlob.Matches(p.MatchProfile, profile))
            return $"profile {(profile.Length == 0 ? "(none)" : profile)} not matched by {p.MatchProfile}";
        return "matched";
    }

    // Which matched policy/policies is responsible for each strictest effective value.
    private static EffectiveSource[] Attribute(PolicyDecision d, List<AccessPolicy> matched)
    {
        var sources = new List<EffectiveSource>
        {
            new("approvals", d.RequiredApprovals.ToString(),
                From(matched, p => Math.Max(1, p.RequiredApprovals) == d.RequiredApprovals)),
        };
        if (d.GrantTtlMinutes is { } ttl)
            sources.Add(new("grant_ttl_minutes", ttl.ToString(),
                From(matched, p => p.GrantTtlMinutes == ttl)));
        if (d.Subject != SubjectApproval.Optional)
            sources.Add(new("subject", d.Subject.ToString().ToLowerInvariant(),
                From(matched, p => p.Subject == d.Subject)));
        if (d.RequireCommand)
            sources.Add(new("require_command", "true", From(matched, p => p.RequireCommand)));
        if (d.RequireSourceAddress)
            sources.Add(new("require_source_address", "true", From(matched, p => p.RequireSourceAddress)));
        if (d.AllowedPrincipals is { Length: > 0 } allow)
            sources.Add(new("allowed_principals", string.Join(",", allow),
                From(matched, p => p.AllowedPrincipals.Length > 0)));
        return sources.ToArray();
    }

    private static string[] From(List<AccessPolicy> matched, Func<AccessPolicy, bool> pick) =>
        matched.Where(pick).Select(p => p.Name).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToArray();

    /// <summary>
    /// The impact of a proposed policy change on one concrete request context — the before and
    /// after effective decisions and a deterministic classification. A policy set only ever
    /// restricts an agent's own authority, so a <i>change</i> to it is comparable field by
    /// field: it either leaves effective authority unchanged, tightens it, loosens it, or both.
    /// <see cref="PolicyImpactClass.AuthorityExpansion"/> and <see cref="PolicyImpactClass.MixedChange"/>
    /// mean a request that was harder is now easier — that is what must earn its own approval.
    /// </summary>
    public PolicyImpact Simulate(PolicyChange change, string resource, IReadOnlyCollection<string> agentTags, string profile = "")
    {
        var current = All();
        var proposed = Apply(current, change);
        var before = Compose(current, resource, agentTags, profile).Decision;
        var after = Compose(proposed, resource, agentTags, profile).Decision;
        var deltas = Delta(before, after);
        var cls = Classify(deltas.Select(x => x.Class));
        return new PolicyImpact(resource, agentTags.ToArray(), profile, before, after, deltas, cls,
            RequiresApproval: cls is PolicyImpactClass.AuthorityExpansion or PolicyImpactClass.MixedChange);
    }

    // The proposed policy set: an upsert replaces the same-named latest, a remove drops it.
    private static List<AccessPolicy> Apply(IReadOnlyList<AccessPolicy> current, PolicyChange change) => change switch
    {
        PolicyChange.Remove r => current.Where(p => !Eq(p.Name, r.Name)).ToList(),
        PolicyChange.Upsert u => current.Where(p => !Eq(p.Name, u.Policy.Name)).Append(u.Policy).ToList(),
        _ => current.ToList(),
    };

    // Field-by-field classification of before -> after. Each field is a restriction, an
    // expansion, both (only principals can be), or nothing; the overall class combines them.
    private static FieldDelta[] Delta(PolicyDecision a, PolicyDecision b)
    {
        var d = new List<FieldDelta>();
        Add(d, "approvals", a.RequiredApprovals, b.RequiredApprovals,
            restricts: b.RequiredApprovals > a.RequiredApprovals, expands: b.RequiredApprovals < a.RequiredApprovals);
        // TTL: null = no override = the longest life, so least restrictive.
        var at = a.GrantTtlMinutes ?? int.MaxValue;
        var bt = b.GrantTtlMinutes ?? int.MaxValue;
        Add(d, "grant_ttl_minutes", Ttl(a.GrantTtlMinutes), Ttl(b.GrantTtlMinutes),
            restricts: bt < at, expands: bt > at);
        var ar = (int)a.Subject; var br = (int)b.Subject;   // Optional<Required<Forbidden
        Add(d, "subject", a.Subject.ToString().ToLowerInvariant(), b.Subject.ToString().ToLowerInvariant(),
            restricts: br > ar, expands: br < ar);
        Add(d, "require_command", a.RequireCommand, b.RequireCommand,
            restricts: b.RequireCommand && !a.RequireCommand, expands: a.RequireCommand && !b.RequireCommand);
        Add(d, "require_source_address", a.RequireSourceAddress, b.RequireSourceAddress,
            restricts: b.RequireSourceAddress && !a.RequireSourceAddress, expands: a.RequireSourceAddress && !b.RequireSourceAddress);
        AddPrincipals(d, a.AllowedPrincipals, b.AllowedPrincipals);
        return d.Where(x => x.Class != PolicyImpactClass.NoChange).ToArray();
    }

    private static string Ttl(int? t) => t is { } v ? v.ToString() : "(none)";

    private static void Add(List<FieldDelta> d, string field, object before, object after, bool restricts, bool expands) =>
        d.Add(new FieldDelta(field, before.ToString() ?? "", after.ToString() ?? "", ClassOf(restricts, expands)));

    // Allowed-principals is the one field where a single change can both add and remove
    // permitted logins: a wider set expands (allows more), a narrower set restricts, and an
    // incomparable set does both.
    private static void AddPrincipals(List<FieldDelta> d, string[]? aArr, string[]? bArr)
    {
        var a = new HashSet<string>(aArr ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var b = new HashSet<string>(bArr ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        bool aNone = a.Count == 0, bNone = b.Count == 0;
        bool restricts, expands;
        if (aNone && bNone) { restricts = expands = false; }
        else if (aNone) { restricts = true; expands = false; }        // added a constraint where none was
        else if (bNone) { restricts = false; expands = true; }        // dropped the constraint entirely
        else { expands = !b.IsSubsetOf(a); restricts = !a.IsSubsetOf(b); }  // superset expands, subset restricts
        d.Add(new FieldDelta("allowed_principals",
            aNone ? "(any)" : string.Join(",", a.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)),
            bNone ? "(any)" : string.Join(",", b.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)),
            ClassOf(restricts, expands)));
    }

    private static PolicyImpactClass ClassOf(bool restricts, bool expands) =>
        restricts && expands ? PolicyImpactClass.MixedChange
        : expands ? PolicyImpactClass.AuthorityExpansion
        : restricts ? PolicyImpactClass.Restriction
        : PolicyImpactClass.NoChange;

    private static PolicyImpactClass Classify(IEnumerable<PolicyImpactClass> fields)
    {
        bool restricts = false, expands = false;
        foreach (var c in fields)
        {
            if (c is PolicyImpactClass.Restriction or PolicyImpactClass.MixedChange) restricts = true;
            if (c is PolicyImpactClass.AuthorityExpansion or PolicyImpactClass.MixedChange) expands = true;
        }
        return ClassOf(restricts, expands);
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
