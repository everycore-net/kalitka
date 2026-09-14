namespace KalitkaMcpGateway;

/// <summary>What the gateway did with a forwarded call.</summary>
public enum HandleKind { Result, Pending, Denied, UnknownTool, BadArguments, AlreadyHandled, OutcomeUnknown }

/// <summary>The gateway's answer to a <c>tools/call</c>. <see cref="HandleKind.Pending"/> carries a
/// Call ID for the human to approve and for the AI to poll/re-issue against; it is a normal
/// result, not an error.</summary>
public sealed record HandleResult(
    HandleKind Kind, string CallId, CallState? State = null, ToolResult? Result = null, string? Reason = null);

/// <summary>
/// The gateway proxy: it turns a <c>tools/call</c> into a decision and, only when a human has
/// approved the exact call, forwards it to the upstream exactly once. Classification is bound to
/// the observed tool contract (so drift is unclassified and never auto-allowed); the grant is
/// bound to the call fingerprint (so nothing changes between approval and execution); and the
/// at-most-once claim guards the single forward. Transport to the upstream is behind
/// <see cref="IUpstream"/>.
/// </summary>
public sealed class GatewayProxy
{
    private readonly IUpstream _upstream;
    private readonly IToolClassifier _classifier;
    private readonly CallGate _gate;
    private readonly string _alias;
    private readonly string _upstreamId;
    private readonly object _invGate = new();
    private ToolInventory _inventory;

    public GatewayProxy(IUpstream upstream, IToolClassifier classifier, CallGate gate, string upstreamAlias, string upstreamId)
    {
        _upstream = upstream;
        _classifier = classifier;
        _gate = gate;
        _alias = upstreamAlias;
        _upstreamId = upstreamId;
        _inventory = ToolInventory.Empty(upstreamAlias, upstreamId);
    }

    public ToolInventory Inventory { get { lock (_invGate) return _inventory; } }

    /// <summary>Snapshot the upstream's tools. If they differ from the current snapshot the
    /// revision is bumped (invalidating not-yet-approved requests against the old inventory) and
    /// the diff is returned for audit; otherwise nothing changes.</summary>
    public async Task<InventoryDiff> RefreshInventoryAsync(CancellationToken ct)
    {
        var tools = await _upstream.ListToolsAsync(ct);
        lock (_invGate)
        {
            if (!_inventory.DiffersFrom(tools)) return new InventoryDiff([], [], []);
            var next = ToolInventory.Build(_alias, _upstreamId, _inventory.Revision + 1, tools);
            var diff = ToolInventory.Diff(_inventory, next);
            _inventory = next;
            return diff;
        }
    }

    /// <summary>Handle one <c>tools/call</c>. Called every time the AI issues the call: the first
    /// time it returns Pending; after a human approves, the re-issued call is claimed and forwarded
    /// exactly once.</summary>
    public async Task<HandleResult> HandleAsync(string tool, string argumentsJson, AuthenticatedCallContext ctx, CancellationToken ct)
    {
        var inv = Inventory;
        if (!inv.TryGet(tool, out var invTool))
            return new HandleResult(HandleKind.UnknownTool, "", Reason: "unknown or withdrawn tool");

        byte[] canonicalArgs;
        try { canonicalArgs = Jcs.Canonicalize(argumentsJson); }
        catch (JcsException e) { return new HandleResult(HandleKind.BadArguments, "", Reason: e.Message); }
        // Forward exactly the bytes that were fingerprinted, not the caller's original text, so what
        // a human approved is byte-for-byte what runs upstream — no split between fingerprint and
        // execution (unsafe integers were already rejected by the canonicalizer).
        var canonicalArgsJson = System.Text.Encoding.UTF8.GetString(canonicalArgs);

        var contractId = inv.ContractId(tool);
        var fp = CallFingerprint.Compute(_alias, tool, contractId, ctx, canonicalArgs);
        var fp64 = CallFingerprint.ToBase64Url(fp);
        var callId = CallFingerprint.CallId(fp);

        var cls = _classifier.Classify(_alias, tool, invTool.ContractHashHex);
        var call = new Call(_alias, tool, ctx.Subject.Id, ctx.Workload.Id, fp64, callId);
        var decision = _gate.Evaluate(call, cls);

        switch (decision.Outcome)
        {
            case GatewayOutcome.Pending:
                return new HandleResult(HandleKind.Pending, callId, decision.State);
            case GatewayOutcome.Denied:
                return new HandleResult(HandleKind.Denied, callId, decision.State, Reason: decision.Reason);
        }

        // Approved: exactly one claim may forward. A lost race (already claimed/executed) does not
        // forward again — the at-most-once guarantee.
        var claim = _gate.Claim(fp64);
        if (claim != ClaimOutcome.Claimed)
            return new HandleResult(HandleKind.AlreadyHandled, callId, _gate.StateOf(fp64));

        try
        {
            var result = await _upstream.CallToolAsync(tool, canonicalArgsJson, ct);
            // An upstream that returns a definite result — success or an MCP error — is a proven outcome.
            _gate.Complete(fp64, success: !result.IsError);
            return new HandleResult(HandleKind.Result, callId, _gate.StateOf(fp64), result);
        }
        catch (Exception e)
        {
            // A timeout / cancellation / broken connection after dispatch is NOT a proven failure —
            // the call may already have run. Burn the grant as OutcomeUnknown; no automatic retry.
            var state = _gate.MarkOutcomeUnknown(fp64, "transport error after dispatch: " + e.GetType().Name);
            return new HandleResult(HandleKind.OutcomeUnknown, callId, state,
                Reason: "dispatch reached the upstream but no definite outcome was received");
        }
    }
}
