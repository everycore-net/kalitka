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

    public IReadOnlyList<AgentProfile> All() => Parse(_config.Get(Key));

    public AgentProfile? Get(string name) =>
        All().FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));

    public async Task Save(AgentProfile profile, string actor, CancellationToken ct)
    {
        var existed = false;
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            existed = list.RemoveAll(p => string.Equals(p.Name, profile.Name, StringComparison.OrdinalIgnoreCase)) > 0;
            list.Add(profile);
            return JsonSerializer.Serialize(list);
        });
        await _audit.Append(Ev(existed ? AuditEvents.AgentProfileUpdated : AuditEvents.AgentProfileCreated, actor, profile.Name), ct);
    }

    public async Task<bool> Delete(string name, string actor, CancellationToken ct)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            removed = list.RemoveAll(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) > 0;
            return JsonSerializer.Serialize(list);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.AgentProfileDeleted, actor, name), ct);
        return removed;
    }

    private static List<AgentProfile> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<AgentProfile>>(blob) ?? new());

    private AuditEvent Ev(string type, string actor, string profileName) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: profileName, Resource: "", RequestId: "", GrantId: "", Channel: "agent", Metadata: "");
}
