using System.Text;
using KalitkaMcpGateway;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// Reviewability limits: small payloads are shown in full; a large one is not silently trimmed under
/// an Approve button — it is TooLarge with its size + digest + a bounded preview, and a tool that
/// requires reviewable arguments refuses it rather than let a human rubber-stamp what they can't see.
/// </summary>
public class ReviewabilityTests
{
    [Fact]
    public void A_small_payload_is_reviewable_in_full()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"vm\":\"dev-01\"}");
        var r = ArgumentReviewer.Review(bytes);
        Assert.Equal(Reviewability.Reviewable, r.Verdict);
        Assert.False(r.Truncated);
        Assert.Equal("{\"vm\":\"dev-01\"}", r.Preview);
        Assert.Equal(bytes.Length, r.SizeBytes);
    }

    [Fact]
    public void A_large_payload_is_too_large_with_an_honest_summary()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"blob\":\"" + new string('x', 20_000) + "\"}");
        var r = ArgumentReviewer.Review(bytes);
        Assert.Equal(Reviewability.TooLarge, r.Verdict);
        Assert.True(r.Truncated);
        Assert.True(r.Preview.Length <= ArgumentReviewer.DefaultPreviewChars);
        Assert.Equal(64, r.Sha256Hex.Length);   // full digest of the whole payload
        Assert.Equal(bytes.Length, r.SizeBytes);
    }

    [Fact]
    public async Task A_tool_requiring_reviewable_arguments_refuses_an_oversized_payload()
    {
        var upstream = new FakeUpstream();
        upstream.Tools.Add(new UpstreamTool("bulk_delete", "{\"type\":\"object\"}"));
        var classifier = new DictionaryToolClassifier();
        var gate = new CallGate(new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero)));
        var proxy = new GatewayProxy(upstream, classifier, gate, "svc", "uid");
        await proxy.RefreshInventoryAsync(default);
        proxy.Inventory.TryGet("bulk_delete", out var t);
        classifier.Set("svc", "bulk_delete", t.ContractHashHex, ToolClass.Approval(1, requireReviewable: true));

        var ctx = new AuthenticatedCallContext(new WorkloadRef("ai:x"), new SubjectRef("operator:s", false));
        var big = "{\"ids\":\"" + new string('9', 20_000) + "\"}";
        var r = await proxy.HandleAsync("bulk_delete", big, ctx, default);

        Assert.Equal(HandleKind.Denied, r.Kind);
        Assert.Equal("arguments-not-reviewable", r.Reason);
        Assert.Equal(Reviewability.TooLarge, r.Review!.Verdict);
        Assert.Equal(0, upstream.CallCount);
    }
}
