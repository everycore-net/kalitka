using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The management side of the agent registry: create an agent (secret shown once),
/// mint a single-use enrollment token, let an agent self-enrol, and
/// disable/enable/revoke/rotate — each with an <c>agent.*</c> audit event.
/// Authentication and per-request authorization live in the <c>/agent/*</c>
/// endpoints; this is everything the control plane and enrollment need.
/// </summary>
public sealed class AgentService
{
    private readonly IAgentStore _agents;
    private readonly OneTimeTokenService _tokens;
    private readonly IReplayStore _replay;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly int _enrollMinutes;

    public AgentService(IAgentStore agents, OneTimeTokenService tokens, IReplayStore replay,
        IAuditStore audit, IOptions<GateOptions> options, TimeProvider? clock = null)
    {
        _agents = agents;
        _tokens = tokens;
        _replay = replay;
        _audit = audit;
        _enrollMinutes = options.Value.EnrollmentTokenMinutes;
        _clock = clock ?? TimeProvider.System;
    }

    public IReadOnlyList<Agent> All() => _agents.Snapshot();
    public Agent? Get(string id) => _agents.GetById(id);

    public sealed record Created(Agent Agent, string Secret);

    /// <summary>Create an active agent with a server-generated secret — returned once.</summary>
    public Task<Created> Create(string displayName, string platform, string[] caps, string[] resources,
        string actor, CancellationToken ct, string[]? tags = null) =>
        CreateCore(displayName, platform, caps, resources, actor, ct, tags, null);

    private async Task<Created> CreateCore(string displayName, string platform, string[] caps, string[] resources,
        string actor, CancellationToken ct, string[]? tags, AgentProvenance? prov)
    {
        var id = NewId();
        var secret = AgentSecrets.NewSecret();
        var agent = new Agent(id, Clean(displayName, id), Clean(platform, "generic"), "", AgentStatus.Active,
            AgentSecrets.Hash(secret), Norm(caps), Norm(resources), "", _clock.GetUtcNow(), null, "", null)
        { Tags = Norm(tags ?? Array.Empty<string>()) }.WithProvenance(prov);
        _agents.Create(agent);
        await _audit.Append(Ev(AuditEvents.AgentEnrolled, actor, id), ct);
        return new Created(agent, secret);
    }

    /// <summary>Create a pending agent and a single-use enrollment token for it. The
    /// token is returned once; the agent self-enrols to become active.</summary>
    public Task<string> CreateEnrollmentToken(string displayName, string platform, string[] caps,
        string[] resources, string actor, CancellationToken ct, string[]? tags = null) =>
        CreateEnrollmentTokenCore(displayName, platform, caps, resources, actor, ct, tags, null);

    private async Task<string> CreateEnrollmentTokenCore(string displayName, string platform, string[] caps,
        string[] resources, string actor, CancellationToken ct, string[]? tags, AgentProvenance? prov)
    {
        var id = NewId();
        var agent = new Agent(id, Clean(displayName, id), Clean(platform, "generic"), "", AgentStatus.Pending,
            "", Norm(caps), Norm(resources), "", _clock.GetUtcNow(), null, "", null)
        { Tags = Norm(tags ?? Array.Empty<string>()) }.WithProvenance(prov);
        _agents.Create(agent);
        var token = _tokens.Mint("agent-enrollment", id, "", "", _enrollMinutes);
        await _audit.Append(Ev(AuditEvents.AgentEnrollmentCreated, actor, id), ct);
        return token;
    }

    // Profile-based creation: expand the profile's resource templates against the
    // hostname ONCE and snapshot the result (capabilities, concrete resources, tags)
    // onto the agent, recording the profile provenance (which profile, which hostname,
    // which revision). The agent then owns the snapshot — editing the profile later
    // never changes an already-created/enrolled agent until it is deliberately
    // reconciled (see ReconcileService).

    public Task<Created> CreateFromProfile(AgentProfile p, string hostname, string? displayName, string actor, CancellationToken ct)
    {
        var (caps, resources, tags) = p.Expand(hostname);
        return CreateCore(Clean(displayName, hostname), p.Platform, caps, resources, actor, ct, tags,
            new AgentProvenance(p.Name, hostname.Trim(), p.Revision));
    }

    public Task<string> CreateEnrollmentTokenFromProfile(AgentProfile p, string hostname, string actor, CancellationToken ct)
    {
        var (caps, resources, tags) = p.Expand(hostname);
        return CreateEnrollmentTokenCore(hostname, p.Platform, caps, resources, actor, ct, tags,
            new AgentProvenance(p.Name, hostname.Trim(), p.Revision));
    }

    public sealed record EnrollResult(bool Ok, string? AgentId = null, string? Error = null);

    /// <summary>Self-enrolment: the agent presents its token plus metadata and a
    /// credential — an Ed25519 public key, a generated secret, or both. **Key-only is
    /// secretless**: no usable shared secret is stored, so the agent can authenticate
    /// only by signature. The token is single-use; the pending agent goes active.</summary>
    public async Task<EnrollResult> Enroll(string token, string secret, string hostname, string metadata,
        CancellationToken ct, string? publicKey = null)
    {
        var cap = _tokens.Read(token);
        if (cap is null || cap.Purpose != "agent-enrollment") return new(false, Error: "invalid");

        var hasKey = !string.IsNullOrEmpty(publicKey);
        if (hasKey && !AgentSignatures.IsValidPublicKey(publicKey!)) return new(false, Error: "bad-key");
        var hasSecret = !string.IsNullOrWhiteSpace(secret);
        if (hasSecret && secret.Length < 16) return new(false, Error: "weak-secret");
        if (!hasKey && !hasSecret) return new(false, Error: "no-credential");   // need a key or a secret

        var agent = _agents.GetById(cap.Resource);
        if (agent is null || agent.Status != AgentStatus.Pending) return new(false, Error: "not-pending");

        // Single-use: burn the token before activating, so a replayed token cannot
        // re-enrol (or overwrite the secret of) an already-active agent.
        if (!await _replay.TryConsumeAsync(cap.Jti, cap.ExpiresAt, ct)) return new(false, Error: "used");

        var keys = hasKey
            ? agent.Keys.Append(new AgentKey(AgentSignatures.NewKeyId(), publicKey!, _clock.GetUtcNow())).ToArray()
            : agent.Keys;

        _agents.Create(agent with
        {
            Status = AgentStatus.Active,
            // Secretless when only a key was given: an empty hash never verifies, so the
            // agent has no usable shared secret — signatures are the only way in.
            SecretHash = hasSecret ? AgentSecrets.Hash(secret) : "",
            Hostname = Clean(hostname, agent.Hostname),
            Metadata = metadata ?? "",
            LastSeenAt = _clock.GetUtcNow(),
            Keys = keys,
        });
        await _audit.Append(Ev(AuditEvents.AgentEnrolled, $"agent:{agent.Id}", agent.Id), ct);
        if (hasKey) await _audit.Append(Ev(AuditEvents.AgentKeyAdded, $"agent:{agent.Id}", agent.Id), ct);
        return new(true, agent.Id);
    }

    public Task<bool> Disable(string id, string actor, CancellationToken ct) =>
        SetStatus(id, AgentStatus.Disabled, AuditEvents.AgentDisabled, actor, ct);

    public Task<bool> Enable(string id, string actor, CancellationToken ct) =>
        SetStatus(id, AgentStatus.Active, AuditEvents.AgentEnabled, actor, ct);

    public Task<bool> Revoke(string id, string actor, CancellationToken ct) =>
        SetStatus(id, AgentStatus.Revoked, AuditEvents.AgentRevoked, actor, ct);

    private async Task<bool> SetStatus(string id, AgentStatus status, string evt, string actor, CancellationToken ct)
    {
        if (!_agents.SetStatus(id, status, _clock.GetUtcNow())) return false;
        await _audit.Append(Ev(evt, actor, id), ct);
        return true;
    }

    /// <summary>Rotate to a fresh server-generated secret — returned once; the old
    /// one stops working immediately.</summary>
    public async Task<string?> Rotate(string id, string actor, CancellationToken ct)
    {
        var secret = AgentSecrets.NewSecret();
        if (!_agents.RotateSecret(id, AgentSecrets.Hash(secret))) return null;
        await _audit.Append(Ev(AuditEvents.AgentCredentialRotated, actor, id), ct);
        return secret;
    }

    /// <summary>Register an Ed25519 public key (base64, 32 bytes) for an agent, so it
    /// can sign its requests instead of sending the shared secret. Add-only here;
    /// rotation/revocation manage the set later. Idempotent on the same key.</summary>
    public async Task<bool> AddKey(string id, string publicKeyBase64, string actor, CancellationToken ct)
    {
        var agent = _agents.GetById(id);
        if (agent is null || !AgentSignatures.IsValidPublicKey(publicKeyBase64)) return false;
        if (agent.Keys.Any(k => k.PublicKey == publicKeyBase64)) return true;   // already registered
        var key = new AgentKey(AgentSignatures.NewKeyId(), publicKeyBase64, _clock.GetUtcNow());
        _agents.Create(agent with { Keys = agent.Keys.Append(key).ToArray() });
        await _audit.Append(Ev(AuditEvents.AgentKeyAdded, actor, id), ct);
        return true;
    }

    /// <summary>Remove (revoke) one registered key by id; the agent's other keys and
    /// its shared secret keep working. Rotation is add-the-new then remove-the-old —
    /// both keys are valid in the overlap, so there is no window without a working key.</summary>
    public async Task<bool> RemoveKey(string id, string keyId, string actor, CancellationToken ct)
    {
        var agent = _agents.GetById(id);
        if (agent is null) return false;
        var remaining = agent.Keys.Where(k => k.KeyId != keyId).ToArray();
        if (remaining.Length == agent.Keys.Count) return false;   // no such key
        _agents.Create(agent with { Keys = remaining });
        await _audit.Append(Ev(AuditEvents.AgentKeyRemoved, actor, id), ct);
        return true;
    }

    private AuditEvent Ev(string type, string actor, string agentId) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: agentId, Resource: "", RequestId: "", GrantId: agentId, Channel: "agent", Metadata: "");

    private static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    private static string[] Norm(string[] xs) =>
        xs.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private static string Clean(string? s, string fallback) => string.IsNullOrWhiteSpace(s) ? fallback : s.Trim();
}
