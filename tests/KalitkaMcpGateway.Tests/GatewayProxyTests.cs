using KalitkaMcpGateway;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The proxy orchestration: fingerprint → classification (bound to the observed contract) → gate →
/// forward at most once, only after a human approved the exact call. Nothing is forwarded while
/// pending; an unclassified or drifted tool is never auto-allowed; the bytes forwarded are the
/// canonical bytes that were fingerprinted; and a transport failure after dispatch is OutcomeUnknown.
/// </summary>
public class GatewayProxyTests
{
    private const string Alias = "azure-prod";
    private const string UpstreamId = "uid-1234";

    private static readonly AuthenticatedCallContext Ctx =
        new(new WorkloadRef("ai:claude:i1"), new SubjectRef("operator:sergej", Asserted: false));

    private static UpstreamTool Tool(string name, string schema = "{\"type\":\"object\"}") => new(name, schema);

    private sealed class Harness
    {
        public required FakeUpstream Upstream;
        public required DictionaryToolClassifier Classifier;
        public required CallGate Gate;
        public required GatewayProxy Proxy;

        public string Fingerprint(string tool, string args)
        {
            var inv = Proxy.Inventory;
            inv.TryGet(tool, out var t);
            var fp = CallFingerprint.Compute(Alias, tool, inv.ContractId(tool), Ctx, Jcs.Canonicalize(args));
            return CallFingerprint.ToBase64Url(fp);
        }

        public string ContractHash(string tool)
        {
            Proxy.Inventory.TryGet(tool, out var t);
            return t.ContractHashHex;
        }
    }

    private static async Task<Harness> Setup(bool denyUnclassified = false, params UpstreamTool[] tools)
    {
        var upstream = new FakeUpstream();
        upstream.Tools.AddRange(tools);
        var classifier = new DictionaryToolClassifier();
        var gate = new CallGate(new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero)),
            new CallGateOptions { DenyUnclassified = denyUnclassified });
        var proxy = new GatewayProxy(upstream, classifier, gate, Alias, UpstreamId);
        await proxy.RefreshInventoryAsync(default);
        return new Harness { Upstream = upstream, Classifier = classifier, Gate = gate, Proxy = proxy };
    }

    [Fact]
    public async Task An_unknown_tool_is_refused_without_touching_the_upstream()
    {
        var h = await Setup(tools: Tool("read_issue"));
        var r = await h.Proxy.HandleAsync("delete_everything", "{}", Ctx, default);
        Assert.Equal(HandleKind.UnknownTool, r.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task Malformed_or_unsafe_arguments_are_rejected()
    {
        var h = await Setup(tools: Tool("read_issue"));
        h.Classifier.Set(Alias, "read_issue", h.ContractHash("read_issue"), ToolClass.NoApproval);
        Assert.Equal(HandleKind.BadArguments, (await h.Proxy.HandleAsync("read_issue", "{ not json", Ctx, default)).Kind);
        // An unsafe integer argument is rejected by the canonicalizer, not forwarded.
        Assert.Equal(HandleKind.BadArguments, (await h.Proxy.HandleAsync("read_issue", "{\"id\":1234567890123456789}", Ctx, default)).Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_no_approval_tool_is_forwarded_immediately_with_canonical_arguments()
    {
        var h = await Setup(tools: Tool("read_issue"));
        h.Classifier.Set(Alias, "read_issue", h.ContractHash("read_issue"), ToolClass.NoApproval);
        var r = await h.Proxy.HandleAsync("read_issue", "{ \"b\":2, \"a\":1 }", Ctx, default);
        Assert.Equal(HandleKind.Result, r.Kind);
        Assert.Equal(CallState.Executed, r.State);
        Assert.Equal(1, h.Upstream.CallCount);
        // The bytes forwarded are the canonical bytes that were fingerprinted, not the caller's text.
        Assert.Equal("{\"a\":1,\"b\":2}", h.Upstream.Calls[0].Args);
    }

    [Fact]
    public async Task A_tool_needing_approval_is_pending_and_not_forwarded_until_approved()
    {
        var h = await Setup(tools: Tool("merge_pull_request"));
        h.Classifier.Set(Alias, "merge_pull_request", h.ContractHash("merge_pull_request"), ToolClass.Approval(1));

        var pending = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);
        Assert.Equal(HandleKind.Pending, pending.Kind);
        Assert.Equal(0, h.Upstream.CallCount);

        h.Gate.Approve(h.Fingerprint("merge_pull_request", "{\"pr\":42}"), "operator:anna");
        var done = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);
        Assert.Equal(HandleKind.Result, done.Kind);
        Assert.Equal(1, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_completed_call_re_issued_needs_fresh_approval_no_double_forward()
    {
        var h = await Setup(tools: Tool("merge_pull_request"));
        h.Classifier.Set(Alias, "merge_pull_request", h.ContractHash("merge_pull_request"), ToolClass.Approval(1));
        var fp = h.Fingerprint("merge_pull_request", "{\"pr\":42}");

        await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);
        h.Gate.Approve(fp, "operator:anna");
        await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);   // forwarded
        var again = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);

        Assert.Equal(1, h.Upstream.CallCount);
        Assert.Equal(HandleKind.Pending, again.Kind);
    }

    [Fact]
    public async Task An_unclassified_tool_is_never_auto_allowed()
    {
        var h = await Setup(denyUnclassified: true, tools: Tool("delete_repository"));
        var r = await h.Proxy.HandleAsync("delete_repository", "{}", Ctx, default);
        Assert.Equal(HandleKind.Denied, r.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_retyped_tool_loses_its_classification_until_reclassified()
    {
        var h = await Setup(denyUnclassified: true, tools: Tool("merge_pull_request", "{\"type\":\"object\"}"));
        h.Classifier.Set(Alias, "merge_pull_request", h.ContractHash("merge_pull_request"), ToolClass.Approval(1));
        Assert.Equal(HandleKind.Pending,
            (await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":1}", Ctx, default)).Kind);

        h.Upstream.Tools.Clear();
        h.Upstream.Tools.Add(Tool("merge_pull_request", "{\"type\":\"object\",\"required\":[\"pr\"]}"));
        var diff = await h.Proxy.RefreshInventoryAsync(default);
        Assert.Equal(new[] { "merge_pull_request" }, diff.Changed);

        var afterDrift = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":1}", Ctx, default);
        Assert.Equal(HandleKind.Denied, afterDrift.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_transport_failure_after_dispatch_is_outcome_unknown_not_failed()
    {
        var h = await Setup(tools: Tool("restart_vm"));
        h.Classifier.Set(Alias, "restart_vm", h.ContractHash("restart_vm"), ToolClass.NoApproval);
        h.Upstream.ThrowOnCall = new TimeoutException("connection dropped after send");

        var r = await h.Proxy.HandleAsync("restart_vm", "{\"vm\":\"x\"}", Ctx, default);
        Assert.Equal(HandleKind.OutcomeUnknown, r.Kind);
        Assert.Equal(CallState.OutcomeUnknown, r.State);
        Assert.Equal(1, h.Upstream.CallCount);   // dispatched once; no automatic retry
    }

    [Fact]
    public async Task Refresh_reports_added_tools_and_bumps_the_revision()
    {
        var h = await Setup(tools: Tool("a"));
        Assert.Equal(1, h.Proxy.Inventory.Revision);

        h.Upstream.Tools.Add(Tool("b"));
        var diff = await h.Proxy.RefreshInventoryAsync(default);
        Assert.Equal(new[] { "b" }, diff.Added);
        Assert.Equal(2, h.Proxy.Inventory.Revision);

        var noop = await h.Proxy.RefreshInventoryAsync(default);
        Assert.False(noop.Any);
        Assert.Equal(2, h.Proxy.Inventory.Revision);
    }
}
