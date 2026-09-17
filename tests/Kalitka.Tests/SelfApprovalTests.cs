using Kalitka;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The <c>self_approved</c> audit mark: when the approver and the request's subject resolve to the same
/// operator principal, the <c>AccessApproved</c> event is stamped so a "person opened their own door" is
/// distinguishable from a four-eyes decision forever — the audit is a sealed hash chain, so a record
/// written without the mark can never gain it later. Independent of policy: the default single-approver
/// path (which skips the subject/quorum branch) records it too.
/// </summary>
public class SelfApprovalTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public SelfApprovalTests(GateFactory f) => _f = f;

    private async Task<string?> ApprovedMeta(string requestId)
    {
        var events = await _f.Services.GetRequiredService<IAuditStore>()
            .Query(new AuditQuery(EventType: AuditEvents.AccessApproved), default);
        return events.Where(e => e.RequestId == requestId).Select(e => e.Metadata).FirstOrDefault();
    }

    [Fact]
    public async Task Approving_your_own_request_is_stamped_self_approved()
    {
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("anna", "Anna", new[] { "os:contoso\\anna", "telegram:551" }, "google:admin", default);
        var gate = _f.Services.GetRequiredService<GateService>();
        var (state, id) = await gate.RaiseAction("ssh:selfhost", "anna", "1.2.3.4", "agent:x", default,
            subjectIdentity: "os:contoso\\anna", subjectTrusted: true);
        Assert.Equal("waiting", state);

        // Anna approves her own request via one of her linked channels — the default (Optional) path.
        await gate.Decide(id, "ok", "telegram:551");

        var meta = await ApprovedMeta(id);
        Assert.NotNull(meta);
        Assert.Contains("self_approved", meta!);
    }

    [Fact]
    public async Task A_verified_four_eyes_approval_is_blank_not_unknown()
    {
        // Both parties are linked principals and different — the only case where absence of a mark is
        // the correct, positive statement "checked, different people".
        var principals = _f.Services.GetRequiredService<PrincipalService>();
        await principals.Save("bob", "Bob", new[] { "os:contoso\\bob", "telegram:552" }, "google:admin", default);
        await principals.Save("cid", "Cid", new[] { "telegram:553" }, "google:admin", default);
        var gate = _f.Services.GetRequiredService<GateService>();
        var (_, id) = await gate.RaiseAction("ssh:otherhost", "bob", "1.2.3.4", "agent:x", default,
            subjectIdentity: "os:contoso\\bob", subjectTrusted: true);

        await gate.Decide(id, "ok", "telegram:553");   // Cid approves Bob's request — different people

        var meta = await ApprovedMeta(id);
        Assert.NotNull(meta);
        Assert.DoesNotContain("self_approved", meta!);
        Assert.DoesNotContain("self_unknown", meta!);   // verified different — blank, not unknown
    }

    [Fact]
    public async Task A_request_without_a_subject_identity_is_self_unknown()
    {
        // No asserted subject: we cannot say whether approver == subject, so it must read UNKNOWN, never
        // silently blank (which would be indistinguishable from a verified four-eyes decision).
        var gate = _f.Services.GetRequiredService<GateService>();
        var (_, id) = await gate.RaiseAction("ssh:plainhost", "someone", "1.2.3.4", "agent:x", default);
        await gate.Decide(id, "ok", "telegram:551");

        var meta = await ApprovedMeta(id);
        Assert.NotNull(meta);
        Assert.Contains("self_unknown", meta!);
    }

    [Fact]
    public async Task An_unlinked_approver_is_self_unknown()
    {
        // Subject is a known principal, but the approver's identity is not linked to any principal — we
        // cannot attribute the decision to a person, so it is unknown, not a clean four-eyes.
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("dee", "Dee", new[] { "os:contoso\\dee", "telegram:554" }, "google:admin", default);
        var gate = _f.Services.GetRequiredService<GateService>();
        var (_, id) = await gate.RaiseAction("ssh:deehost", "dee", "1.2.3.4", "agent:x", default,
            subjectIdentity: "os:contoso\\dee", subjectTrusted: true);

        await gate.Decide(id, "ok", "telegram:900000");   // an identity linked to nobody

        var meta = await ApprovedMeta(id);
        Assert.NotNull(meta);
        Assert.Contains("self_unknown", meta!);
    }
}
