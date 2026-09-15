namespace KalitkaAgent;

/// <summary>
/// The second provenance source for reconcile: what Core says about a session. Behind an interface
/// so the enforcer's startup reconcile is testable without a live Core — and so "Core is unreachable"
/// (fall back to local expiry) is a first-class outcome, not an exception to guess at.
/// </summary>
public interface ISessionLiveness
{
    Task<CoreClient.LivenessResult> OfAsync(string sessionId, CancellationToken ct);
}

/// <summary>Backs <see cref="ISessionLiveness"/> with Core, using the enrolled agent id. Before
/// enrolment (no id yet) it reports unreachable, so a pre-enrolment reconcile safely uses local
/// expiry.</summary>
public sealed class CoreSessionLiveness : ISessionLiveness
{
    private readonly CoreClient _core;
    private readonly AgentIdentity _identity;

    public CoreSessionLiveness(CoreClient core, AgentIdentity identity)
    {
        _core = core;
        _identity = identity;
    }

    public Task<CoreClient.LivenessResult> OfAsync(string sessionId, CancellationToken ct) =>
        _identity.Current is { } agentId
            ? _core.LivenessAsync(agentId, sessionId, ct)
            : Task.FromResult(new CoreClient.LivenessResult(false, "unknown"));
}
