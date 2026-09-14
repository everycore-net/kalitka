namespace KalitkaMcpGateway;

/// <summary>One MCP tool call the gateway is asked to broker, already fingerprinted (the grant
/// binds to <see cref="Fingerprint"/>).</summary>
public sealed record Call(string UpstreamAlias, string Tool, string Subject, string Workload, string Fingerprint, string CallId);

/// <summary>
/// The lifecycle of a brokered call. <c>ExecutionClaimed</c> sits between approval and outcome so
/// that two automatic retries after an approval cannot execute a destructive tool twice: only one
/// claim wins (at-most-once dispatch). A claim that never reports an outcome expires to
/// <c>OutcomeUnknown</c> — the grant is spent and a human who approved it can see it ended unknown,
/// rather than the gateway silently pretending success or re-running it.
/// </summary>
public enum CallState { Pending, Approved, Denied, Expired, ExecutionClaimed, Executed, Failed, OutcomeUnknown }

/// <summary>What <see cref="CallGate.Evaluate"/> tells the caller to do now.</summary>
public enum GatewayOutcome { Pending, Approved, Denied }

public sealed record CallDecision(GatewayOutcome Outcome, CallState State, string CallId, string? Reason = null);

/// <summary>The result of trying to claim a call for execution — the at-most-once gate.</summary>
public enum ClaimOutcome { Claimed, NotApproved, AlreadyClaimed, Gone }

/// <summary>Tunables. Both TTLs are deliberately short-ish and independent: an approval a human
/// never acts on expires, and a claim an executor never completes expires to an unknown outcome.</summary>
public sealed record CallGateOptions
{
    /// <summary>How long a raised request may wait for a human before it expires.</summary>
    public TimeSpan ApprovalTtl { get; init; } = TimeSpan.FromMinutes(10);
    /// <summary>How long an approval stays claimable before it expires — an approval is not a
    /// standing permission; a call approved now cannot be executed much later.</summary>
    public TimeSpan ApprovedTtl { get; init; } = TimeSpan.FromMinutes(5);
    /// <summary>How long a claimed execution has to report an outcome before it becomes
    /// OutcomeUnknown (the grant is spent).</summary>
    public TimeSpan ClaimTtl { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>Strict deployments deny an unclassified tool outright; otherwise it needs manual
    /// approval. Either way it is never auto-allowed.</summary>
    public bool DenyUnclassified { get; init; }
}

/// <summary>
/// The gateway's decision + execution state machine, keyed by call fingerprint. Re-issue-safe:
/// the AI is expected to re-send the same call after a human approves, and because the grant is
/// bound to the canonical fingerprint, the re-issued call resolves to the same record — a changed
/// argument is simply a different fingerprint, hence a different (un-approved) call.
///
/// In-memory for this slice (a clock, no persistence, no wire). The upstream MCP proxy and the
/// Core-notification path are later slices; this is the part where the security lives.
/// </summary>
public sealed class CallGate
{
    private sealed class Record
    {
        public required Call Call;
        public CallState State;
        public DateTimeOffset? ApprovalExpiresAt;
        public DateTimeOffset? ApprovedExpiresAt;
        public DateTimeOffset? ClaimExpiresAt;
        public int RequiredApprovals;
        public readonly HashSet<string> Approvers = new(StringComparer.OrdinalIgnoreCase);
        public string? Outcome;
    }

    private readonly Dictionary<string, Record> _records = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly TimeProvider _clock;
    private readonly CallGateOptions _opt;

    public CallGate(TimeProvider clock, CallGateOptions? options = null)
    {
        _clock = clock;
        _opt = options ?? new CallGateOptions();
    }

    /// <summary>Decide what to do with a call given its policy class. Idempotent while a record is
    /// active (Pending/Approved); a terminal record (Executed/Failed/Expired/OutcomeUnknown) starts
    /// a fresh attempt, while a Denied one stays denied.</summary>
    public CallDecision Evaluate(Call call, ToolClass cls)
    {
        lock (_gate)
        {
            var effective = cls.Kind switch
            {
                ClassKind.Unclassified when _opt.DenyUnclassified => (ToolClass?)null,   // strict → deny
                ClassKind.Unclassified => ToolClass.Approval(1),                          // else → manual approval
                _ => cls,
            };
            if (effective is null)
                return new CallDecision(GatewayOutcome.Denied, CallState.Denied, call.CallId, "unclassified");

            // Idempotent while a record is active — for BOTH classes. This is what stops two
            // parallel auto-allowed calls from each overwriting the record and both being dispatched:
            // the second sees the active record (Approved/ExecutionClaimed) and does not start fresh.
            if (_records.TryGetValue(call.Fingerprint, out var existing) && !IsTerminalForRetry(existing.State))
                return Map(existing);

            var now = _clock.GetUtcNow();
            var rec = Fresh(call, effective.Kind == ClassKind.NoApproval ? 0 : effective.RequiredApprovals);
            if (effective.Kind == ClassKind.NoApproval)
            {
                // Recorded (audit + uniform claim/outcome) and auto-approved, but still time-bounded.
                rec.State = CallState.Approved;
                rec.Approvers.Add("policy:auto");
                rec.ApprovedExpiresAt = now + _opt.ApprovedTtl;
            }
            else
            {
                rec.State = CallState.Pending;
                rec.ApprovalExpiresAt = now + _opt.ApprovalTtl;
            }
            return Map(rec);
        }
    }

    /// <summary>Record one approver's approval. Distinct principals only; reaching the required
    /// count moves the call to Approved. A no-op if the approval window has passed.</summary>
    public CallState Approve(string fingerprint, string approver)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(fingerprint, out var r)) return CallState.Expired;
            if (r.State != CallState.Pending) return r.State;
            if (Expired(r.ApprovalExpiresAt)) { r.State = CallState.Expired; return r.State; }
            r.Approvers.Add(approver);
            if (r.Approvers.Count >= r.RequiredApprovals)
            {
                r.State = CallState.Approved;
                r.ApprovedExpiresAt = _clock.GetUtcNow() + _opt.ApprovedTtl;
            }
            return r.State;
        }
    }

    public CallState Deny(string fingerprint, string approver)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(fingerprint, out var r)) return CallState.Expired;
            if (r.State == CallState.Pending) r.State = CallState.Denied;
            return r.State;
        }
    }

    /// <summary>Claim an approved call for execution — the at-most-once gate. Exactly one claim
    /// succeeds; a second (a retry) is refused, so a destructive tool cannot run twice.</summary>
    public ClaimOutcome Claim(string fingerprint)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(fingerprint, out var r)) return ClaimOutcome.Gone;
            switch (r.State)
            {
                case CallState.Approved:
                    // The approval expiry is checked here, atomically with the claim — an approval is
                    // not a standing permission, so a stale one cannot be executed.
                    if (Expired(r.ApprovedExpiresAt)) { r.State = CallState.Expired; return ClaimOutcome.NotApproved; }
                    r.State = CallState.ExecutionClaimed;
                    r.ClaimExpiresAt = _clock.GetUtcNow() + _opt.ClaimTtl;
                    return ClaimOutcome.Claimed;
                case CallState.ExecutionClaimed or CallState.Executed or CallState.Failed or CallState.OutcomeUnknown:
                    return ClaimOutcome.AlreadyClaimed;
                default:
                    return ClaimOutcome.NotApproved;
            }
        }
    }

    /// <summary>Report the outcome of a claimed execution. A late outcome (claim already expired)
    /// is not accepted — it stays OutcomeUnknown, since the gateway can no longer prove exactly-once.</summary>
    public CallState Complete(string fingerprint, bool success, string? detail = null)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(fingerprint, out var r)) return CallState.Expired;
            if (r.State != CallState.ExecutionClaimed) return r.State;
            if (Expired(r.ClaimExpiresAt)) { r.State = CallState.OutcomeUnknown; return r.State; }
            r.State = success ? CallState.Executed : CallState.Failed;
            r.Outcome = detail;
            return r.State;
        }
    }

    /// <summary>Mark a claimed execution's outcome as unknown — for when dispatch reached the
    /// upstream but no definite result came back (a timeout, cancellation, or broken connection
    /// after the call may already have run). The grant is spent; there is no automatic retry, and
    /// this is never silently treated as success or as a proven failure.</summary>
    public CallState MarkOutcomeUnknown(string fingerprint, string? detail = null)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(fingerprint, out var r)) return CallState.Expired;
            if (r.State == CallState.ExecutionClaimed) { r.State = CallState.OutcomeUnknown; r.Outcome = detail; }
            return r.State;
        }
    }

    /// <summary>Time-based transitions, callable on a cadence: expire un-acted approvals and stale
    /// approvals, and turn a claim that never reported an outcome into OutcomeUnknown (fail closed —
    /// the grant is spent).</summary>
    public int Sweep()
    {
        lock (_gate)
        {
            var n = 0;
            foreach (var r in _records.Values)
            {
                if (r.State == CallState.Pending && Expired(r.ApprovalExpiresAt)) { r.State = CallState.Expired; n++; }
                else if (r.State == CallState.Approved && Expired(r.ApprovedExpiresAt)) { r.State = CallState.Expired; n++; }
                else if (r.State == CallState.ExecutionClaimed && Expired(r.ClaimExpiresAt)) { r.State = CallState.OutcomeUnknown; n++; }
            }
            return n;
        }
    }

    /// <summary>The current state of a call, or null if unknown.</summary>
    public CallState? StateOf(string fingerprint)
    {
        lock (_gate) return _records.TryGetValue(fingerprint, out var r) ? r.State : null;
    }

    private Record Fresh(Call call, int requiredApprovals)
    {
        var r = new Record { Call = call, RequiredApprovals = requiredApprovals };
        _records[call.Fingerprint] = r;
        return r;
    }

    private bool Expired(DateTimeOffset? at) => at is { } t && _clock.GetUtcNow() >= t;

    // A record a re-issue should restart from (a completed or lapsed attempt), vs. one still in
    // flight. Denied is intentionally NOT here: "no" stands until it is swept away.
    private static bool IsTerminalForRetry(CallState s) =>
        s is CallState.Executed or CallState.Failed or CallState.Expired or CallState.OutcomeUnknown;

    private static CallDecision Map(Record r) => r.State switch
    {
        CallState.Approved => new(GatewayOutcome.Approved, r.State, r.Call.CallId),
        CallState.Denied => new(GatewayOutcome.Denied, r.State, r.Call.CallId, "denied"),
        CallState.Expired => new(GatewayOutcome.Denied, r.State, r.Call.CallId, "expired"),
        _ => new(GatewayOutcome.Pending, r.State, r.Call.CallId),
    };
}
