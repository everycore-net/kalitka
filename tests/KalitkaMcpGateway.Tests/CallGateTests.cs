using KalitkaMcpGateway;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The gateway's decision + execution state machine — where the security lives. The properties
/// that matter: a human is asked when policy says so; an approved call executes at most once even
/// under retries; a claim that never completes fails to an unknown outcome rather than silent
/// success; an unclassified tool is never auto-allowed; and re-issue resolves by fingerprint.
/// </summary>
public class CallGateTests
{
    private static (CallGate gate, FakeTimeProvider clock) Fresh(CallGateOptions? opt = null)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        return (new CallGate(clock, opt), clock);
    }

    private static Call C(string fp = "fp-1", string tool = "restart_vm") =>
        new("azure-prod", tool, "operator:sergej", "ai:claude:i1", fp, "7DM4-R9KT-2F81");

    [Fact]
    public void No_approval_tool_is_auto_approved_and_runs_once()
    {
        var (gate, _) = Fresh();
        var d = gate.Evaluate(C(), ToolClass.NoApproval);
        Assert.Equal(GatewayOutcome.Approved, d.Outcome);
        Assert.Equal(ClaimOutcome.Claimed, gate.Claim("fp-1"));
        Assert.Equal(CallState.Executed, gate.Complete("fp-1", success: true));
    }

    [Fact]
    public void A_call_needing_approval_waits_then_proceeds_after_a_human_approves()
    {
        var (gate, _) = Fresh();
        Assert.Equal(GatewayOutcome.Pending, gate.Evaluate(C(), ToolClass.Approval()).Outcome);
        // Re-issuing the same call while pending stays pending (no duplicate request).
        Assert.Equal(GatewayOutcome.Pending, gate.Evaluate(C(), ToolClass.Approval()).Outcome);

        Assert.Equal(CallState.Approved, gate.Approve("fp-1", "operator:anna"));
        // The AI re-issues the same call; now it resolves as approved and may claim.
        Assert.Equal(GatewayOutcome.Approved, gate.Evaluate(C(), ToolClass.Approval()).Outcome);
        Assert.Equal(ClaimOutcome.Claimed, gate.Claim("fp-1"));
        Assert.Equal(CallState.Executed, gate.Complete("fp-1", success: true));
    }

    [Fact]
    public void A_second_claim_is_refused_at_most_once_dispatch()
    {
        var (gate, _) = Fresh();
        gate.Evaluate(C(), ToolClass.Approval());
        gate.Approve("fp-1", "operator:anna");
        Assert.Equal(ClaimOutcome.Claimed, gate.Claim("fp-1"));
        Assert.Equal(ClaimOutcome.AlreadyClaimed, gate.Claim("fp-1"));   // a retry cannot run it twice
    }

    [Fact]
    public void Required_two_needs_two_distinct_principals()
    {
        var (gate, _) = Fresh();
        gate.Evaluate(C(), ToolClass.Approval(required: 2));
        Assert.Equal(CallState.Pending, gate.Approve("fp-1", "operator:anna"));
        Assert.Equal(CallState.Pending, gate.Approve("fp-1", "operator:anna"));   // same person, still one
        Assert.Equal(CallState.Approved, gate.Approve("fp-1", "operator:bob"));
    }

    [Fact]
    public void Unclassified_defaults_to_manual_approval_and_is_never_auto_allowed()
    {
        var (gate, _) = Fresh();
        Assert.Equal(GatewayOutcome.Pending, gate.Evaluate(C(), ToolClass.Unclassified).Outcome);
    }

    [Fact]
    public void Unclassified_is_denied_in_strict_mode()
    {
        var (gate, _) = Fresh(new CallGateOptions { DenyUnclassified = true });
        var d = gate.Evaluate(C(), ToolClass.Unclassified);
        Assert.Equal(GatewayOutcome.Denied, d.Outcome);
        Assert.Equal("unclassified", d.Reason);
    }

    [Fact]
    public void An_unacted_approval_expires_and_can_be_retried_fresh()
    {
        var (gate, clock) = Fresh(new CallGateOptions { ApprovalTtl = TimeSpan.FromMinutes(10) });
        gate.Evaluate(C(), ToolClass.Approval());
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal(1, gate.Sweep());
        Assert.Equal(CallState.Expired, gate.StateOf("fp-1"));
        // A later re-issue starts a fresh pending request.
        Assert.Equal(GatewayOutcome.Pending, gate.Evaluate(C(), ToolClass.Approval()).Outcome);
        Assert.Equal(CallState.Pending, gate.StateOf("fp-1"));
    }

    [Fact]
    public void A_claim_that_never_completes_becomes_outcome_unknown_and_no_late_success()
    {
        var (gate, clock) = Fresh(new CallGateOptions { ClaimTtl = TimeSpan.FromSeconds(60) });
        gate.Evaluate(C(), ToolClass.Approval());
        gate.Approve("fp-1", "operator:anna");
        Assert.Equal(ClaimOutcome.Claimed, gate.Claim("fp-1"));

        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(1, gate.Sweep());
        Assert.Equal(CallState.OutcomeUnknown, gate.StateOf("fp-1"));
        // A late outcome is not accepted — the gateway can no longer prove exactly-once.
        Assert.Equal(CallState.OutcomeUnknown, gate.Complete("fp-1", success: true));
    }

    [Fact]
    public void A_denied_call_stays_denied_on_re_issue()
    {
        var (gate, _) = Fresh();
        gate.Evaluate(C(), ToolClass.Approval());
        Assert.Equal(CallState.Denied, gate.Deny("fp-1", "operator:anna"));
        Assert.Equal(GatewayOutcome.Denied, gate.Evaluate(C(), ToolClass.Approval()).Outcome);   // "no" stands
    }

    [Fact]
    public void Claiming_before_approval_or_an_unknown_call_is_refused()
    {
        var (gate, _) = Fresh();
        gate.Evaluate(C(), ToolClass.Approval());
        Assert.Equal(ClaimOutcome.NotApproved, gate.Claim("fp-1"));   // still pending
        Assert.Equal(ClaimOutcome.Gone, gate.Claim("nonexistent"));
    }

    [Fact]
    public void Different_fingerprints_are_independent_calls()
    {
        var (gate, _) = Fresh();
        gate.Evaluate(C(fp: "fp-a"), ToolClass.Approval());
        gate.Evaluate(C(fp: "fp-b"), ToolClass.Approval());
        gate.Approve("fp-a", "operator:anna");
        Assert.Equal(CallState.Approved, gate.StateOf("fp-a"));
        Assert.Equal(CallState.Pending, gate.StateOf("fp-b"));   // approving one does not touch the other
    }

    [Fact]
    public void Classifier_resolves_absent_or_retyped_tools_as_unclassified()
    {
        var classifier = new DictionaryToolClassifier()
            .Set("github", "read_issue", "hashA", ToolClass.NoApproval)
            .Set("github", "merge_pull_request", "hashB", ToolClass.Approval(1));
        Assert.Equal(ClassKind.NoApproval, classifier.Classify("github", "read_issue", "hashA").Kind);
        Assert.Equal(ClassKind.NeedsApproval, classifier.Classify("github", "merge_pull_request", "hashB").Kind);
        Assert.Equal(ClassKind.Unclassified, classifier.Classify("github", "delete_repository", "hashX").Kind); // new tool
        Assert.Equal(ClassKind.Unclassified, classifier.Classify("github", "read_issue", "hashZ").Kind);        // schema changed
    }
}
