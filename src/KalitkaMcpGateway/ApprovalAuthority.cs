namespace KalitkaMcpGateway;

/// <summary>What the authority says to do with a call right now.</summary>
public enum AuthorityOutcome { Pending, Approved, Denied }

/// <summary>The authority's decision for a call, plus a state for display/audit.</summary>
public sealed record AuthorityDecision(AuthorityOutcome Outcome, CallState State, string? Reason = null);

/// <summary>The proven outcome of a forwarded execution.</summary>
public enum ExecutionOutcome { Executed, Failed, Unknown }

/// <summary>
/// Who decides whether a call may run and owns the once-only execution claim. The gateway is
/// deliberately agnostic here: it does the fingerprint, classification, inventory and forwarding,
/// and asks the authority to <see cref="EvaluateAsync"/> (decide / raise for approval),
/// <see cref="ClaimAsync"/> (win the single execution slot) and record the
/// <see cref="CompleteAsync"/> outcome. A standalone deployment uses <see cref="LocalAuthority"/>;
/// the real one is Core, which already owns principals, subject rules, quorum, TTL and — via a
/// redeem-once grant — a durable, cross-instance claim.
/// </summary>
public interface IApprovalAuthority
{
    Task<AuthorityDecision> EvaluateAsync(Call call, ToolClass cls, CancellationToken ct);
    Task<ClaimOutcome> ClaimAsync(Call call, CancellationToken ct);
    Task<CallState> CompleteAsync(Call call, ExecutionOutcome outcome, CancellationToken ct);
}

/// <summary>The in-process authority: the local <see cref="CallGate"/>. Used standalone (no Core)
/// and in tests. Core does not decide here; the gate's own decide/quorum/claim apply.</summary>
public sealed class LocalAuthority : IApprovalAuthority
{
    private readonly CallGate _gate;
    public LocalAuthority(CallGate gate) => _gate = gate;

    public Task<AuthorityDecision> EvaluateAsync(Call call, ToolClass cls, CancellationToken ct)
    {
        var d = _gate.Evaluate(call, cls);
        var outcome = d.Outcome switch
        {
            GatewayOutcome.Approved => AuthorityOutcome.Approved,
            GatewayOutcome.Denied => AuthorityOutcome.Denied,
            _ => AuthorityOutcome.Pending,
        };
        return Task.FromResult(new AuthorityDecision(outcome, d.State, d.Reason));
    }

    public Task<ClaimOutcome> ClaimAsync(Call call, CancellationToken ct) =>
        Task.FromResult(_gate.Claim(call.Fingerprint));

    public Task<CallState> CompleteAsync(Call call, ExecutionOutcome outcome, CancellationToken ct) =>
        Task.FromResult(outcome == ExecutionOutcome.Unknown
            ? _gate.MarkOutcomeUnknown(call.Fingerprint)
            : _gate.Complete(call.Fingerprint, success: outcome == ExecutionOutcome.Executed));
}
