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
    public async Task<Created> Create(string displayName, string platform, string[] caps, string[] resources,
        string actor, CancellationToken ct)
    {
        var id = NewId();
        var secret = AgentSecrets.NewSecret();
        var agent = new Agent(id, Clean(displayName, id), Clean(platform, "generic"), "", AgentStatus.Active,
            AgentSecrets.Hash(secret), Norm(caps), Norm(resources), "", _clock.GetUtcNow(), null, "", null);
        _agents.Create(agent);
        await _audit.Append(Ev(AuditEvents.AgentEnrolled, actor, id), ct);
        return new Created(agent, secret);
    }

    /// <summary>Create a pending agent and a single-use enrollment token for it. The
    /// token is returned once; the agent self-enrols to become active.</summary>
    public async Task<string> CreateEnrollmentToken(string displayName, string platform, string[] caps,
        string[] resources, string actor, CancellationToken ct)
    {
        var id = NewId();
        var agent = new Agent(id, Clean(displayName, id), Clean(platform, "generic"), "", AgentStatus.Pending,
            "", Norm(caps), Norm(resources), "", _clock.GetUtcNow(), null, "", null);
        _agents.Create(agent);
        var token = _tokens.Mint("agent-enrollment", id, "", "", _enrollMinutes);
        await _audit.Append(Ev(AuditEvents.AgentEnrollmentCreated, actor, id), ct);
        return token;
    }

    public sealed record EnrollResult(bool Ok, string? AgentId = null, string? Error = null);

    /// <summary>Self-enrolment: the agent presents its token and its own generated
    /// secret plus metadata. The token is single-use; the pending agent goes active.</summary>
    public async Task<EnrollResult> Enroll(string token, string secret, string hostname, string metadata, CancellationToken ct)
    {
        var cap = _tokens.Read(token);
        if (cap is null || cap.Purpose != "agent-enrollment") return new(false, Error: "invalid");
        if (string.IsNullOrWhiteSpace(secret) || secret.Length < 16) return new(false, Error: "weak-secret");

        var agent = _agents.GetById(cap.Resource);
        if (agent is null || agent.Status != AgentStatus.Pending) return new(false, Error: "not-pending");

        // Single-use: burn the token before activating, so a replayed token cannot
        // re-enrol (or overwrite the secret of) an already-active agent.
        if (!await _replay.TryConsumeAsync(cap.Jti, cap.ExpiresAt, ct)) return new(false, Error: "used");

        _agents.Create(agent with
        {
            Status = AgentStatus.Active,
            SecretHash = AgentSecrets.Hash(secret),
            Hostname = Clean(hostname, agent.Hostname),
            Metadata = metadata ?? "",
            LastSeenAt = _clock.GetUtcNow(),
        });
        await _audit.Append(Ev(AuditEvents.AgentEnrolled, $"agent:{agent.Id}", agent.Id), ct);
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

    private AuditEvent Ev(string type, string actor, string agentId) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: agentId, Resource: "", RequestId: "", GrantId: agentId, Channel: "agent", Metadata: "");

    private static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    private static string[] Norm(string[] xs) =>
        xs.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private static string Clean(string? s, string fallback) => string.IsNullOrWhiteSpace(s) ? fallback : s.Trim();
}
