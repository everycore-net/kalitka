namespace KalitkaAgent;

/// <summary>
/// The enrolled agent id, shared from the <see cref="Worker"/> (which owns enrollment) to any other
/// service that needs it — the security-log watcher raises requests too. A one-shot handoff: the
/// watcher awaits it rather than racing startup order or re-reading state, and enrollment happens
/// exactly once in one place.
/// </summary>
public sealed class AgentIdentity
{
    private readonly TaskCompletionSource<string> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Publish the id once enrolled. Idempotent; later calls are ignored.</summary>
    public void Set(string agentId) => _ready.TrySetResult(agentId);

    /// <summary>The id if already published, else null (does not block).</summary>
    public string? Current => _ready.Task.IsCompletedSuccessfully ? _ready.Task.Result : null;

    /// <summary>Wait until the id is published (or cancellation).</summary>
    public Task<string> WaitAsync(CancellationToken ct) => _ready.Task.WaitAsync(ct);
}
