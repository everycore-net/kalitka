using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Subject approval (0.30.1): the two boundaries of self before app-launch gives it teeth.
/// The subject identity that gates approval must be ASSERTED by a trusted agent (not a
/// requester string); `subject: required|forbidden` is explicit and composes with the
/// quorum; the subject must be the grant's beneficiary; and there is no admin fallback
/// under `required`. Distinctness is by operator principal, never channel.
/// </summary>
public class SubjectApprovalTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public SubjectApprovalTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    // An agent trusted to assert subjects (asserted) or not (claimed).
    private void Register(string id, string secret, string[] tags, bool canAssert)
    {
        var caps = canAssert ? new[] { "ssh", AgentCapabilities.AssertSubject } : new[] { "ssh" };
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "windows", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            caps, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null) { Tags = tags });
    }

    private Task Link(string id, params string[] identities) =>
        _f.Services.GetRequiredService<PrincipalService>().Save(id, id, identities, "google:admin", default);

    private Task Policy(string name, string[] tags, int required, SubjectApproval subject) =>
        _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy(name, "ssh:*", tags, required, 0) { Subject = subject }, "google:admin", default);

    private static HttpRequestMessage Req(string id, string secret, Dictionary<string, string> form)
    {
        var r = new HttpRequestMessage(HttpMethod.Post, "/agent/v1/requests") { Content = new FormUrlEncodedContent(form) };
        r.Headers.Add("X-Kalitka-Agent-Id", id); r.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return r;
    }

    private static string? Field(string j, string n)
    {
        using var d = JsonDocument.Parse(j);
        return d.RootElement.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
    }

    private async Task<(HttpStatusCode code, string? state, string? id)> Raise(string agentId, string secret, Dictionary<string, string> form)
    {
        var resp = await Client().SendAsync(Req(agentId, secret, form));
        var body = await resp.Content.ReadAsStringAsync();
        return (resp.StatusCode, Field(body, "state"), Field(body, "id"));
    }

    private GateService Gate => _f.Services.GetRequiredService<GateService>();

    // --- Boundaries refused up front (fail closed) -----------------------------

    [Fact]
    public async Task A_claimed_subject_cannot_satisfy_subject_required()
    {
        await Policy("cl", new[] { "env:cl" }, 1, SubjectApproval.Required);
        await Link("anna", "os:contoso\\anna", "google:sub-anna");
        Register("sa-claim", "s", new[] { "env:cl" }, canAssert: false);   // NOT trusted to assert
        var (code, state, _) = await Raise("sa-claim", "s",
            new() { ["host"] = "h", ["user"] = "anna", ["subject_identity"] = "os:contoso\\anna" });
        Assert.Equal(HttpStatusCode.Conflict, code);
        Assert.Equal("claimed-not-asserted", state);
    }

    [Fact]
    public async Task The_subject_must_be_the_beneficiary()
    {
        await Policy("bf", new[] { "env:bf" }, 1, SubjectApproval.Required);
        await Link("anna", "os:contoso\\anna", "google:sub-anna");
        Register("sa-bene", "s", new[] { "env:bf" }, canAssert: true);
        // Asking for Administrator while the subject is anna — self-confirmation is meaningless.
        var (code, state, _) = await Raise("sa-bene", "s",
            new() { ["host"] = "h", ["user"] = "Administrator", ["subject_identity"] = "os:contoso\\anna" });
        Assert.Equal(HttpStatusCode.Conflict, code);
        Assert.Equal("beneficiary-mismatch", state);
    }

    [Fact]
    public async Task An_unmapped_subject_under_required_is_unsatisfiable_not_a_fallback()
    {
        await Policy("um", new[] { "env:um" }, 1, SubjectApproval.Required);
        Register("sa-unmap", "s", new[] { "env:um" }, canAssert: true);   // zoe is linked to no operator
        var (code, state, _) = await Raise("sa-unmap", "s",
            new() { ["host"] = "h", ["user"] = "zoe", ["subject_identity"] = "os:contoso\\zoe" });
        Assert.Equal(HttpStatusCode.Conflict, code);
        Assert.Equal("subject-unmapped", state);
    }

    // --- Approval mechanics ----------------------------------------------------

    [Fact]
    public async Task Required_at_1_is_satisfied_only_by_the_subject()
    {
        await Policy("r1", new[] { "env:r1" }, 1, SubjectApproval.Required);
        await Link("anna", "os:contoso\\anna", "google:sub-anna");
        Register("sa-r1", "s", new[] { "env:r1" }, canAssert: true);
        var (_, _, id) = await Raise("sa-r1", "s", new() { ["host"] = "h", ["user"] = "anna", ["subject_identity"] = "os:contoso\\anna" });

        // Someone who is not the subject cannot satisfy it, even though required is 1.
        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id!, "ok", "google:sub-bob")).Outcome);
        Assert.Equal("waiting", Gate.StateOf(id!));
        // The subject (any linked channel) does.
        Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(id!, "ok", "google:sub-anna")).Outcome);
        Assert.Equal("approved", Gate.StateOf(id!));
    }

    [Fact]
    public async Task Required_at_2_needs_the_subject_and_one_other_distinct_principal()
    {
        await Policy("r2", new[] { "env:r2" }, 2, SubjectApproval.Required);
        await Link("anna", "os:contoso\\anna", "google:sub-anna", "telegram:9001");
        Register("sa-r2", "s", new[] { "env:r2" }, canAssert: true);
        var (_, _, id) = await Raise("sa-r2", "s", new() { ["host"] = "h", ["user"] = "anna", ["subject_identity"] = "os:contoso\\anna" });

        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id!, "ok", "google:sub-anna")).Outcome);   // subject, 1 of 2
        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id!, "ok", "telegram:9001")).Outcome);     // same person, still 1
        Assert.Equal("waiting", Gate.StateOf(id!));
        Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(id!, "ok", "google:sub-bob")).Outcome);    // a second person
        Assert.Equal("approved", Gate.StateOf(id!));
    }

    [Fact]
    public async Task Forbidden_refuses_the_subjects_own_approval()
    {
        await Policy("fb", new[] { "env:fb" }, 1, SubjectApproval.Forbidden);
        await Link("anna", "os:contoso\\anna", "google:sub-anna");
        Register("sa-fb", "s", new[] { "env:fb" }, canAssert: true);
        var (_, _, id) = await Raise("sa-fb", "s", new() { ["host"] = "h", ["user"] = "anna", ["subject_identity"] = "os:contoso\\anna" });

        // The subject cannot approve their own request.
        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id!, "ok", "google:sub-anna")).Outcome);
        Assert.Equal("waiting", Gate.StateOf(id!));
        // Another person can.
        Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(id!, "ok", "google:sub-bob")).Outcome);
        Assert.Equal("approved", Gate.StateOf(id!));
    }
}
