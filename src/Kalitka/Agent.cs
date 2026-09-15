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

    /// <summary>The agent is trusted to ASSERT the subject of a request (its OS security
    /// context — SID / account), not merely relay a requester-typed hint. Only such an
    /// agent's <c>subject_identity</c> may gate a subject-approval policy: otherwise a
    /// caller could name someone else's identity as the subject and approve their own
    /// privileged action. The Windows agent, which derives the SID from the login session,
    /// carries this; a generic CLI agent does not (its subject is fine for notification
    /// routing, but never trusted for subject approval).</summary>
    public const string AssertSubject = "subject.assert";

    /// <summary>Capabilities that confer authority over the approval decision itself, not
    /// just the ability to raise/redeem — sudo-grade. Granting or revoking one is surfaced
    /// distinctly in the reconcile diff, the audit log and the agent UI, so it is never a
    /// quiet line in a profile change. (An agent with <c>subject.assert</c> can assert who
    /// the subject is, which feeds authorization and the quorum.)</summary>
    public static readonly IReadOnlySet<string> Privileged =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { AssertSubject };

    public static bool IsPrivileged(string capability) => Privileged.Contains(capability);

    /// <summary>The full closed set, for a checkbox UI — a typo in free text just leaves an agent
    /// silently without a right, discovered later as a confusing error.</summary>
    public static readonly IReadOnlyList<string> All = new[] { Request, Redeem, SessionEnd, AssertSubject };
}

/// <summary>The platforms an agent declares — a closed set, for a dropdown.</summary>
public static class AgentPlatforms
{
    public static readonly IReadOnlyList<string> All = new[] { "linux", "windows", "macos", "gateway", "generic" };
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

    /// <summary>Registered Ed25519 public keys (0.20). An agent that has any signs its
    /// requests instead of sending the shared secret; the secret stays valid in
    /// parallel through the migration window.</summary>
    public IReadOnlyList<AgentKey> Keys { get; init; } = Array.Empty<AgentKey>();

    // ---- Migration observability (0.21.2) -----------------------------------
    // How the agent last authenticated, so an operator can see — before removing
    // shared secrets — which agents have moved to signatures and which still use the
    // fallback. Set on every authenticated call; empty until the first.

    public string LastAuthMethod { get; init; } = "";   // "signature" | "secret" | ""
    public string LastKeyId { get; init; } = "";        // the key that signed, when signature
    public DateTimeOffset? LastSignedAt { get; init; }  // last time it authenticated by signature

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

    /// <summary>The agent's tags (e.g. <c>env:prod</c>) — used to select the access
    /// policies that apply to its requests. Empty for the legacy global-secret caller.</summary>
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    public static AgentIdentity FromAgent(Agent a) => new(a.Id, a.Capabilities, a.AllowedResources, false) { Tags = a.Tags };

    /// <summary>May this caller's <c>subject_identity</c> be trusted to gate a subject-approval
    /// policy? Only when it holds <see cref="AgentCapabilities.AssertSubject"/> — the legacy
    /// global-secret caller never can.</summary>
    public bool CanAssertSubject =>
        !IsLegacy && Capabilities.Any(c => string.Equals(c, AgentCapabilities.AssertSubject, StringComparison.OrdinalIgnoreCase));

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
    public bool MayRepresent(string resource, string operation = "") => RepresentDenial(resource, operation) is null;

    /// <summary>Why <see cref="MayRepresent"/> would refuse, or null when it allows. A diagnostic reason
    /// safe to hand back to an <i>already-authenticated</i> agent — it holds a valid credential, so naming
    /// its own missing scope leaks nothing to an outsider. <c>resource-not-allowed</c>: no covering
    /// allowed-resource; <c>capability-missing</c>: the resource is in scope but the agent lacks the
    /// capability for the operation.</summary>
    public string? RepresentDenial(string resource, string operation = "")
    {
        if (IsLegacy)
            return (AllowedResources.Count == 0 || Covered(resource)) ? null : "resource-not-allowed";
        if (!Covered(resource)) return "resource-not-allowed";
        if (HasCap(SchemeOf(resource)) || (operation.Length > 0 && HasCap(operation))) return null;
        return "capability-missing";
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

    /// <summary>Record an authenticated call: updates last-seen/ip and how it
    /// authenticated (<paramref name="method"/> = "signature" | "secret", the signing
    /// <paramref name="keyId"/> when applicable), stamping last-signed only for signatures.</summary>
    void RecordAuth(string id, DateTimeOffset at, string ip, string method, string keyId);

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

    public void RecordAuth(string id, DateTimeOffset at, string ip, string method, string keyId)
    {
        if (_agents.TryGetValue(id, out var a))
            _agents[id] = a with
            {
                LastSeenAt = at, LastIp = ip, LastAuthMethod = method, LastKeyId = keyId,
                LastSignedAt = method == "signature" ? at : a.LastSignedAt,
            };
    }

    public IReadOnlyList<Agent> Snapshot() => _agents.Values.OrderBy(a => a.DisplayName).ToList();
}
