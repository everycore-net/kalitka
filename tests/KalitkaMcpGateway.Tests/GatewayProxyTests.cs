using KalitkaMcpGateway;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The proxy orchestration: fingerprint → classification (bound to the observed contract) → gate →
/// forward at most once, only after a human approved the exact call. Nothing is forwarded while
/// pending; an unclassified or drifted tool is never auto-allowed.
/// </summary>
public class GatewayProxyTests
{
    private const string Alias = "azure-prod";
    private const string UpstreamId = "uid-1234";
    private const string Subject = "operator:sergej";
    private const string Workload = "ai:claude:i1";

    private static UpstreamTool Tool(string name, string schema = "{\"type\":\"object\"}") => new(name, schema);

    private sealed class Harness
    {
        public required FakeUpstream Upstream;
        public required DictionaryToolClassifier Classifier;
        public required CallGate Gate;
        public required GatewayProxy Proxy;

        // The fingerprint the proxy will compute for this call — recomputed via the public API so
        // a test can drive approval through the shared gate (and this cross-checks the proxy).
        public string Fingerprint(string tool, string args)
        {
            var inv = Proxy.Inventory;
            inv.TryGet(tool, out var t);
            var fp = CallFingerprint.Compute(Alias, tool, inv.ContractId(tool), Subject, Workload, Jcs.Canonicalize(args));
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
        var r = await h.Proxy.HandleAsync("delete_everything", "{}", Subject, Workload, default);
        Assert.Equal(HandleKind.UnknownTool, r.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task Malformed_arguments_are_rejected()
    {
        var h = await Setup(tools: Tool("read_issue"));
        h.Classifier.Set(Alias, "read_issue", h.ContractHash("read_issue"), ToolClass.NoApproval);
        var r = await h.Proxy.HandleAsync("read_issue", "{ not json", Subject, Workload, default);
        Assert.Equal(HandleKind.BadArguments, r.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_no_approval_tool_is_forwarded_immediately()
    {
        var h = await Setup(tools: Tool("read_issue"));
        h.Classifier.Set(Alias, "read_issue", h.ContractHash("read_issue"), ToolClass.NoApproval);
        var r = await h.Proxy.HandleAsync("read_issue", "{\"id\":7}", Subject, Workload, default);
        Assert.Equal(HandleKind.Result, r.Kind);
        Assert.Equal(CallState.Executed, r.State);
        Assert.Equal(1, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_tool_needing_approval_is_pending_and_not_forwarded_until_approved()
    {
        var h = await Setup(tools: Tool("merge_pull_request"));
        h.Classifier.Set(Alias, "merge_pull_request", h.ContractHash("merge_pull_request"), ToolClass.Approval(1));

        var pending = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Subject, Workload, default);
        Assert.Equal(HandleKind.Pending, pending.Kind);
        Assert.Equal(0, h.Upstream.CallCount);   // nothing forwarded while a human decides

        // A human approves the exact call (out of band); the re-issued call is forwarded once.
        h.Gate.Approve(h.Fingerprint("merge_pull_request", "{\"pr\":42}"), "operator:anna");
        var done = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Subject, Workload, default);
        Assert.Equal(HandleKind.Result, done.Kind);
        Assert.Equal(1, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_completed_call_re_issued_needs_fresh_approval_no_double_forward()
    {
        var h = await Setup(tools: Tool("merge_pull_request"));
        h.Classifier.Set(Alias, "merge_pull_request", h.ContractHash("merge_pull_request"), ToolClass.Approval(1));
        var fp = h.Fingerprint("merge_pull_request", "{\"pr\":42}");

        await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Subject, Workload, default);
        h.Gate.Approve(fp, "operator:anna");
        await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Subject, Workload, default);   // forwarded
        var again = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Subject, Workload, default);

        Assert.Equal(1, h.Upstream.CallCount);        // not forwarded twice on the approval
        Assert.Equal(HandleKind.Pending, again.Kind); // consumed grant -> a re-issue needs fresh approval
    }

    [Fact]
    public async Task An_unclassified_tool_is_never_auto_allowed()
    {
        // No classifier entry at all -> unclassified. Strict mode denies it outright.
        var h = await Setup(denyUnclassified: true, tools: Tool("delete_repository"));
        var r = await h.Proxy.HandleAsync("delete_repository", "{}", Subject, Workload, default);
        Assert.Equal(HandleKind.Denied, r.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task A_retyped_tool_loses_its_classification_until_reclassified()
    {
        // Classify merge_pull_request at its current contract; strict mode so unclassified => Denied.
        var h = await Setup(denyUnclassified: true, tools: Tool("merge_pull_request", "{\"type\":\"object\"}"));
        h.Classifier.Set(Alias, "merge_pull_request", h.ContractHash("merge_pull_request"), ToolClass.Approval(1));
        Assert.Equal(HandleKind.Pending,
            (await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":1}", Subject, Workload, default)).Kind);

        // The upstream changes the tool's schema; refresh detects the drift and the contract hash
        // moves, so the old classification no longer applies -> unclassified -> denied.
        h.Upstream.Tools.Clear();
        h.Upstream.Tools.Add(Tool("merge_pull_request", "{\"type\":\"object\",\"required\":[\"pr\"]}"));
        var diff = await h.Proxy.RefreshInventoryAsync(default);
        Assert.Equal(new[] { "merge_pull_request" }, diff.Changed);

        var afterDrift = await h.Proxy.HandleAsync("merge_pull_request", "{\"pr\":1}", Subject, Workload, default);
        Assert.Equal(HandleKind.Denied, afterDrift.Kind);
        Assert.Equal(0, h.Upstream.CallCount);
    }

    [Fact]
    public async Task Refresh_reports_added_tools_and_bumps_the_revision()
    {
        var h = await Setup(tools: Tool("a"));
        Assert.Equal(1, h.Proxy.Inventory.Revision);   // first refresh, empty -> {a}

        h.Upstream.Tools.Add(Tool("b"));
        var diff = await h.Proxy.RefreshInventoryAsync(default);
        Assert.Equal(new[] { "b" }, diff.Added);
        Assert.Equal(2, h.Proxy.Inventory.Revision);

        // No change -> no revision bump.
        var noop = await h.Proxy.RefreshInventoryAsync(default);
        Assert.False(noop.Any);
        Assert.Equal(2, h.Proxy.Inventory.Revision);
    }
}
