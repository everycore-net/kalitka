using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Kalitka;

/// <summary>An agent's lifecycle. Only <see cref="Active"/> may authenticate;
/// <see cref="Disabled"/> is temporary, <see cref="Revoked"/> is permanent.</summary>
public enum AgentStatus { Pending, Active, Disabled, Revoked }

/// <summary>Profile provenance persisted as one column (see <see cref="Agent"/>).</summary>
internal sealed record AgentProvenance(string ProfileId, string ProfileHostname, int AppliedProfileRevision);

/// <summary>Operation capabilities — what an agent may <i>do</i>, distinct from the
/// resources it may do it to. Profiles express capabilities in this form.</summary>
public static class AgentCapabilities
{
    public const string Request = "access.request";
    public const string Redeem = "grant.redeem";
    public const string SessionEnd = "session.end";
}

/// <summary>
/// A registered workload/device identity Kalitka trusts to create and redeem
/// requests — but only for the capabilities and resources it is scoped to. The
/// stable <see cref="Id"/> is the identity; <see cref="Hostname"/> and the metadata
/// are self-reported and advisory. The secret is never stored, only its hash.
/// </summary>
public sealed record Agent(
    string Id,
    string DisplayName,
    string Platform,          // linux | windows | macos | gateway | generic
    string Hostname,          // self-reported, advisory
    AgentStatus Status,
    string SecretHash,
    string[] Capabilities,    // ssh | sudo | interactive-login | rdp | database | …
    string[] AllowedResources,// ssh:prod-01 | sudo:prod-01 | ssh:* | …
    string Metadata,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt,
    string LastIp,
    DateTimeOffset? RevokedAt)
{
    /// <summary>Free-form <c>key=value</c> tags (e.g. <c>environment=prod</c>) — grouping
    /// metadata for now; policy semantics (per-group approver rules) come later.</summary>
    public string[] Tags { get; init; } = Array.Empty<string>();

    // ---- Profile provenance -------------------------------------------------
    // The agent's capabilities/resources/tags above are the source of truth. These
    // record where they came from so profile drift can be reconciled deliberately:
    // which profile, the hostname its templates were expanded with, and the profile
    // revision this agent was last synced to. Empty ProfileId = not profile-managed.

    public string ProfileId { get; init; } = "";
    public string ProfileHostname { get; init; } = "";
    public int AppliedProfileRevision { get; init; }

    /// <summary>Stamp profile provenance onto a copy; a null provenance leaves the
    /// agent unmanaged (empty <see cref="ProfileId"/>).</summary>
    internal Agent WithProvenance(AgentProvenance? p) => p is null ? this : this with
    {
        ProfileId = p.ProfileId,
        ProfileHostname = p.ProfileHostname,
        AppliedProfileRevision = p.AppliedProfileRevision,
    };
}

/// <summary>
/// The authenticated caller on an <c>/agent/*</c> endpoint: either a registered
/// <see cref="Agent"/> or the legacy global-secret caller (kept only for migration).
/// Authorization asks this — never a self-reported value — whether the caller may
/// represent a resource, requiring both the capability and the resource scope.
/// </summary>
public sealed record AgentIdentity(
    string AgentId, IReadOnlyList<string> Capabilities, IReadOnlyList<string> AllowedResources, bool IsLegacy)
{
    /// <summary>The audit actor: <c>agent:&lt;id&gt;</c>, or <c>agent</c> for the legacy caller.</summary>
    public string Actor => IsLegacy ? "agent" : $"agent:{AgentId}";

    public static AgentIdentity FromAgent(Agent a) => new(a.Id, a.Capabilities, a.AllowedResources, false);

    /// <summary>Legacy global-secret caller: no capability model; empty resource
    /// binding means "any" (the pre-registry behaviour).</summary>
    public static AgentIdentity Legacy(string[] resources) => new("", Array.Empty<string>(), resources, true);

    /// <summary>
    /// May this caller act on the resource? Registry agents need a covering
    /// allowed-resource AND a capability — either the resource <i>scheme</i>
    /// (<c>ssh</c>, the pre-0.16 style) or the <i>operation</i> (<c>access.request</c>,
    /// what profiles use); passing either form keeps both kinds of agent working. The
    /// legacy global-secret caller keeps its resource-only binding.
    /// </summary>
    public bool MayRepresent(string resource, string operation = "")
    {
        if (IsLegacy) return AllowedResources.Count == 0 || Covered(resource);
        if (!Covered(resource)) return false;
        return HasCap(SchemeOf(resource)) || (operation.Length > 0 && HasCap(operation));
    }

    private bool HasCap(string c) => Capabilities.Any(x => string.Equals(x, c, StringComparison.OrdinalIgnoreCase));

    private bool Covered(string resource)
    {
        foreach (var r in AllowedResources)
        {
            if (string.Equals(r, resource, StringComparison.OrdinalIgnoreCase)) return true;
            if (r.EndsWith(":*", StringComparison.Ordinal) &&
                resource.StartsWith(r[..^1], StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string SchemeOf(string resource)
    {
        var i = resource.IndexOf(':');
        return i > 0 ? resource[..i] : resource;
    }
}

/// <summary>Agent secret at rest: PBKDF2-SHA256 with a random salt, fixed-time
/// verify. Agent secrets are high-entropy random strings; this is the standard-safe
/// choice and leaves room for public-key / mTLS credentials later.</summary>
public static class AgentSecrets
{
    private const int Iterations = 100_000;

    public static string NewSecret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24));

    public static string Hash(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }

    public static bool Verify(string secret, string stored)
    {
        var parts = stored.Split(':');
        if (parts.Length != 2) return false;
        try
        {
            var salt = Convert.FromBase64String(parts[0]);
            var expected = Convert.FromBase64String(parts[1]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch { return false; }
    }
}

/// <summary>
/// Where agents live — the durable registry, separate from <see cref="IRequestStore"/>.
/// In-memory by default; SQLite / Postgres behind the same backend selection as the
/// other stores, so a revoked agent is revoked across every node.
/// </summary>
public interface IAgentStore
{
    Agent? GetById(string id);
    void Create(Agent agent);
    bool SetStatus(string id, AgentStatus status, DateTimeOffset at);
    bool RotateSecret(string id, string newHash);
    void TouchLastSeen(string id, DateTimeOffset at, string ip);
    IReadOnlyList<Agent> Snapshot();
}

public sealed class InMemoryAgentStore : IAgentStore
{
    private readonly ConcurrentDictionary<string, Agent> _agents = new();

    public Agent? GetById(string id) => _agents.TryGetValue(id, out var a) ? a : null;

    public void Create(Agent agent) => _agents[agent.Id] = agent;

    public bool SetStatus(string id, AgentStatus status, DateTimeOffset at)
    {
        if (!_agents.TryGetValue(id, out var a)) return false;
        _agents[id] = a with { Status = status, RevokedAt = status == AgentStatus.Revoked ? at : a.RevokedAt };
        return true;
    }

    public bool RotateSecret(string id, string newHash)
    {
        if (!_agents.TryGetValue(id, out var a)) return false;
        _agents[id] = a with { SecretHash = newHash };
        return true;
    }

    public void TouchLastSeen(string id, DateTimeOffset at, string ip)
    {
        if (_agents.TryGetValue(id, out var a)) _agents[id] = a with { LastSeenAt = at, LastIp = ip };
    }

    public IReadOnlyList<Agent> Snapshot() => _agents.Values.OrderBy(a => a.DisplayName).ToList();
}
