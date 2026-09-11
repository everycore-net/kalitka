using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Policy enforcement on the approval quorum (0.19.3): a policy can require several
/// DISTINCT approvers, and only authenticated control-plane identities (google:&lt;sub&gt;)
/// count toward a quorum &gt; 1 — the same person, or an e-mail link, must not satisfy
/// four-eyes. A single approval still approves when no policy raises the bar.
/// </summary>
public class PolicyQuorumTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public PolicyQuorumTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Register(string id, string secret, string[] tags) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null) { Tags = tags });

    private static HttpRequestMessage Agent(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = form is null ? null : new FormUrlEncodedContent(form) };
        req.Headers.Add("X-Kalitka-Agent-Id", id);
        req.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return req;
    }

    private static string? Field(string json, string name)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
    }

    private async Task<string> Raise(string agentId, string secret, string host)
    {
        var raise = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request", agentId, secret,
            new() { ["host"] = host, ["user"] = "sergej", ["ip"] = "203.0.113.7" }));
        return Field(await raise.Content.ReadAsStringAsync(), "id")!;
    }

    // Approve as a specific control-plane admin (distinct Google sub per e-mail).
    private async Task ApproveAsAdmin(string id, string email)
    {
        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-" + email, email);
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(req);
    }

    private async Task<(string state, string? grant)> Poll(string agentId, string secret, string id)
    {
        var json = await (await Client().SendAsync(Agent(HttpMethod.Get, $"/agent/status?id={id}", agentId, secret))).Content.ReadAsStringAsync();
        return (Field(json, "state") ?? "gone", Field(json, "grant"));
    }

    [Fact]
    public async Task Quorum_of_two_needs_two_distinct_control_plane_approvers()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("q2", "ssh:*", new[] { "env:prod" }, 2, 0), "google:admin", default);
        Register("q-agent", "s", new[] { "env:prod" });

        var id = await Raise("q-agent", "s", "q-01");

        await ApproveAsAdmin(id, "admin@example.com");
        Assert.Equal("waiting", (await Poll("q-agent", "s", id)).state);      // one of two — not yet

        await ApproveAsAdmin(id, "approver@example.com");                     // a second, distinct person
        var (state, grant) = await Poll("q-agent", "s", id);
        Assert.Equal("approved", state);
        Assert.False(string.IsNullOrEmpty(grant));
    }

    [Fact]
    public async Task The_same_approver_twice_does_not_reach_a_quorum()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("q2b", "ssh:*", new[] { "role:db" }, 2, 0), "google:admin", default);
        Register("q-agent-2", "s", new[] { "role:db" });

        var id = await Raise("q-agent-2", "s", "q-02");
        await ApproveAsAdmin(id, "admin@example.com");
        await ApproveAsAdmin(id, "admin@example.com");   // same sub — counts once

        Assert.Equal("waiting", (await Poll("q-agent-2", "s", id)).state);
    }

    [Fact]
    public async Task Single_approval_still_approves_when_no_policy_raises_the_bar()
    {
        Register("q-agent-3", "s", new[] { "env:staging" });   // matches no quorum policy
        var id = await Raise("q-agent-3", "s", "q-03");
        await ApproveAsAdmin(id, "admin@example.com");
        Assert.Equal("approved", (await Poll("q-agent-3", "s", id)).state);
    }

    [Fact]
    public async Task An_email_link_does_not_count_toward_a_quorum()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("q2c", "ssh:*", new[] { "site:bonn" }, 2, 0), "google:admin", default);
        Register("q-agent-4", "s", new[] { "site:bonn" });
        var id = await Raise("q-agent-4", "s", "q-04");

        // An e-mail approve link (actor email:link) is not a control-plane principal.
        var token = _f.Services.GetRequiredService<OneTimeTokenService>().Mint("approve", "ssh:q-04", id, "a", 15);
        var page = await (await Client().PostAsync("/action", new FormUrlEncodedContent(new Dictionary<string, string> { ["t"] = token }))).Content.ReadAsStringAsync();

        Assert.Contains("does not count", page);                          // told it doesn't count
        Assert.Equal("waiting", (await Poll("q-agent-4", "s", id)).state); // and the request stands
    }
}
