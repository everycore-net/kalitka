using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Per-request notification routing (0.30): a request's machine-readable subject is
/// resolved to an operator principal and asked directly; a `self` policy asks only the
/// person acting; an unmapped subject falls back to the admins and that fallback is
/// audited. The reverse of 0.27.0 (answer→person) — now request→person.
/// </summary>
public class NotificationRoutingTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public NotificationRoutingTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Register(string id, string secret, string[]? tags = null) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null) { Tags = tags ?? Array.Empty<string>() });

    private static HttpRequestMessage Agent(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = form is null ? null : new FormUrlEncodedContent(form) };
        req.Headers.Add("X-Kalitka-Agent-Id", id);
        req.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return req;
    }

    private async Task Raise(string agentId, string secret, Dictionary<string, string> form) =>
        await Client().SendAsync(Agent(HttpMethod.Post, "/agent/v1/requests", agentId, secret, form));

    private List<string> ChatIdsSince(int fromIndex) =>
        _f.Telegram.Messages.Select(m => m.ChatId).Skip(fromIndex).ToList();

    [Fact]
    public async Task A_mapped_subject_asks_the_operator_and_the_admins()
    {
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("anna", "Anna", new[] { "os:contoso\\anna", "telegram:555" }, "google:admin", default);
        Register("route-a", "s");
        var before = _f.Telegram.Messages.Count;

        await Raise("route-a", "s", new() { ["host"] = "h1", ["user"] = "anna", ["subject_identity"] = "os:CONTOSO\\anna" });

        var chats = ChatIdsSince(before);
        Assert.Contains("555", chats);   // the operator, resolved from the subject
        Assert.Contains("111", chats);   // and the admins (default fan-out for a normal request)
    }

    [Fact]
    public async Task Subject_required_at_quorum_1_asks_only_the_operator()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("selfp", "ssh:*", new[] { "env:self" }, 1, 0) { Subject = SubjectApproval.Required }, "google:admin", default);
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("bea", "Bea", new[] { "os:contoso\\bea", "telegram:777" }, "google:admin", default);
        // The agent must be trusted to ASSERT the subject; a bare CLI subject would be refused.
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            "route-self", "route-self", "windows", "h", AgentStatus.Active, AgentSecrets.Hash("s"),
            new[] { "ssh", AgentCapabilities.AssertSubject }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null)
        { Tags = new[] { "env:self" } });
        var before = _f.Telegram.Messages.Count;

        // beneficiary (user) matches the asserted subject account (bea).
        await Raise("route-self", "s", new() { ["host"] = "h2", ["user"] = "bea", ["subject_identity"] = "os:contoso\\bea" });

        var chats = ChatIdsSince(before);
        Assert.Contains("777", chats);        // only the person acting
        Assert.DoesNotContain("111", chats);  // the admins are NOT asked when the subject alone suffices
    }

    [Fact]
    public async Task An_unmapped_subject_falls_back_to_admins_and_is_audited()
    {
        Register("route-u", "s");
        var before = _f.Telegram.Messages.Count;

        await Raise("route-u", "s", new() { ["host"] = "h3", ["user"] = "carl", ["subject_identity"] = "os:contoso\\nobody" });

        Assert.Contains("111", ChatIdsSince(before));   // admins asked as fallback
        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(EventType: AuditEvents.NotifyFallback), default);
        Assert.Contains(events, e => e.Metadata.Contains("os:contoso\\nobody"));
    }

    [Fact]
    public async Task An_ordinary_request_without_a_subject_identity_asks_the_admins()
    {
        Register("route-plain", "s");
        var before = _f.Telegram.Messages.Count;
        await Raise("route-plain", "s", new() { ["host"] = "h4", ["user"] = "sergej" });
        Assert.Contains("111", ChatIdsSince(before));   // unchanged baseline
    }

    [Fact]
    public async Task The_notification_shows_the_asserted_account_and_sid()
    {
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("zed", "Zed", new[] { "os:contoso\\zed", "telegram:808" }, "google:admin", default);
        // subject.assert so the SID is honoured — the Windows-agent case the fix targets.
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            "route-sid", "route-sid", "windows", "h", AgentStatus.Active, AgentSecrets.Hash("s"),
            new[] { "ssh", AgentCapabilities.AssertSubject }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null));
        var before = _f.Telegram.Messages.Count;

        await Raise("route-sid", "s", new()
        {
            ["host"] = "h5", ["user"] = "zed",
            ["subject_identity"] = "os:contoso\\zed", ["subject_sid"] = "S-1-5-21-9-9-9-1104",
        });

        // The approver sees the qualified subject AND the SID — not the bare login it used to show.
        var msgs = _f.Telegram.Messages.Skip(before).Select(m => m.Html).ToList();
        Assert.Contains(msgs, h => h.Contains("Subject:") && h.Contains("S-1-5-21-9-9-9-1104"));
    }

    [Fact]
    public async Task A_bare_agent_cannot_inject_a_sid_into_the_notification()
    {
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("yan", "Yan", new[] { "os:contoso\\yan", "telegram:809" }, "google:admin", default);
        Register("route-nosid", "s");   // no subject.assert
        var before = _f.Telegram.Messages.Count;

        await Raise("route-nosid", "s", new()
        {
            ["host"] = "h6", ["user"] = "yan",
            ["subject_identity"] = "os:contoso\\yan", ["subject_sid"] = "S-1-5-21-6-6-6-1337",
        });

        // The subject identity still shows (it routes), but a SID from a non-asserting agent is dropped.
        var msgs = _f.Telegram.Messages.Skip(before).Select(m => m.Html).ToList();
        Assert.Contains(msgs, h => h.Contains("Subject:"));
        Assert.DoesNotContain(msgs, h => h.Contains("S-1-5-21-6-6-6-1337"));
    }

    [Fact]
    public async Task IdentitiesOf_is_the_reverse_of_Resolve()
    {
        var svc = _f.Services.GetRequiredService<PrincipalService>();
        await svc.Save("dora", "Dora", new[] { "google:sub-d", "telegram:900" }, "google:admin", default);
        Assert.Equal("dora", svc.Resolve("telegram:900"));
        Assert.Contains("telegram:900", svc.IdentitiesOf("dora"));
        Assert.Equal(new[] { "telegram:900" }, svc.IdentitiesOf("dora", "telegram:"));
    }
}
