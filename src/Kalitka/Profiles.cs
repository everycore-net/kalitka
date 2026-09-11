using System.Text.Json;

namespace Kalitka;

/// <summary>
/// An agent profile: a reusable <b>template + classification</b>, not a policy
/// system. It carries the capabilities and resource <i>templates</i> (e.g.
/// <c>ssh:{hostname}</c>) and default tags a class of agents should get. At create
/// or enrollment time the templates are expanded against a concrete hostname and
/// the result is <b>snapshotted onto the Agent</b> — the agent's own capabilities,
/// resources and tags remain the source of truth. Editing a profile afterwards
/// therefore never silently changes what an already-enrolled agent may do; applying
/// profile changes to existing agents will be a deliberate, audited action later.
/// </summary>
public sealed record AgentProfile(
    string Name,
    string Platform,
    string[] Capabilities,
    string[] ResourceTemplates,
    string[] Tags)
{
    /// <summary>Bumped each time the profile's content changes. An agent stores the
    /// revision it was last synced to, so drift (template changed) can be told apart
    /// from a deliberate local override on the agent.</summary>
    public int Revision { get; init; }

    /// <summary>True if the substantive content (not the revision) is the same.</summary>
    public bool SameContent(AgentProfile other) =>
        Platform == other.Platform
        && Capabilities.SequenceEqual(other.Capabilities)
        && ResourceTemplates.SequenceEqual(other.ResourceTemplates)
        && Tags.SequenceEqual(other.Tags);

    /// <summary>Expand the resource templates against a hostname (<c>{hostname}</c>).
    /// Capabilities and tags are copied as-is.</summary>
    public (string[] Capabilities, string[] Resources, string[] Tags) Expand(string hostname)
    {
        var h = hostname.Trim();
        var resources = ResourceTemplates
            .Select(t => t.Replace("{hostname}", h))
            .Where(r => !string.IsNullOrWhiteSpace(r) && !r.Contains('{'))   // drop unfilled templates
            .ToArray();
        return (Capabilities, resources, Tags);
    }
}

/// <summary>
/// Where profiles live — one JSON blob in the shared <see cref="IConfigStore"/>, so
/// they are durable and cluster-wide like the other config. CRUD is audited; the
/// profiles themselves grant nothing (they only shape new agents), so there is no
/// authorization here beyond the admin console that calls it.
/// </summary>
public sealed class ProfileService
{
    private const string Key = "agent-profiles";

    private readonly IConfigStore _config;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public ProfileService(IConfigStore config, IAuditStore audit, TimeProvider? clock = null)
    {
        _config = config;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    // The stored blob is the append-only revision history. All()/Get() return the
    // latest revision per name; GetRevision fetches a specific one so a reconcile
    // diff can be anchored to the revision an agent was last synced to.
    public IReadOnlyList<AgentProfile> All() =>
        History().GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                 .Select(Latest).OrderBy(p => p.Name).ToList();

    public AgentProfile? Get(string name) =>
        History().Where(p => Eq(p.Name, name)).OrderByDescending(p => p.Revision).FirstOrDefault();

    public AgentProfile? GetRevision(string name, int revision) =>
        History().FirstOrDefault(p => Eq(p.Name, name) && p.Revision == revision);

    public async Task Save(AgentProfile profile, string actor, CancellationToken ct)
    {
        string? outcome = null;   // "created" | "updated" | null (no-op)
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            var latest = hist.Where(p => Eq(p.Name, profile.Name)).OrderByDescending(p => p.Revision).FirstOrDefault();
            if (latest is not null && latest.SameContent(profile)) return JsonSerializer.Serialize(hist);   // unchanged
            hist.Add(profile with { Revision = (latest?.Revision ?? 0) + 1 });
            outcome = latest is null ? "created" : "updated";
            return JsonSerializer.Serialize(hist);
        });
        if (outcome == "created") await _audit.Append(Ev(AuditEvents.AgentProfileCreated, actor, profile.Name), ct);
        else if (outcome == "updated") await _audit.Append(Ev(AuditEvents.AgentProfileUpdated, actor, profile.Name), ct);
    }

    public async Task<bool> Delete(string name, string actor, CancellationToken ct)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            removed = hist.RemoveAll(p => Eq(p.Name, name)) > 0;   // drop all revisions; agents keep their snapshot
            return JsonSerializer.Serialize(hist);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.AgentProfileDeleted, actor, name), ct);
        return removed;
    }

    private List<AgentProfile> History() => Parse(_config.Get(Key));

    private static AgentProfile Latest(IGrouping<string, AgentProfile> g) => g.OrderByDescending(p => p.Revision).First();
    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static List<AgentProfile> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<AgentProfile>>(blob) ?? new());

    private AuditEvent Ev(string type, string actor, string profileName) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: profileName, Resource: "", RequestId: "", GrantId: "", Channel: "agent", Metadata: "");
}
