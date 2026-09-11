using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Policy enforcement on the grant lifetime (0.19.2): a matching policy's
/// <c>grant_ttl</c> shortens the SSH grant; it can only ever restrict, never extend
/// past the global lifetime, and it applies only to agents whose tags match.
/// </summary>
public class PolicyEnforcementTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public PolicyEnforcementTests(GateFactory f) => _f = f;

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

    private async Task Approve(string id)
    {
        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);
    }

    private async Task<DateTimeOffset> GrantExpiryFor(string agentId, string secret, string host)
    {
        var raise = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request", agentId, secret,
            new() { ["host"] = host, ["user"] = "sergej", ["ip"] = "203.0.113.7" }));
        var id = Field(await raise.Content.ReadAsStringAsync(), "id")!;
        await Approve(id);
        var status = await (await Client().SendAsync(Agent(HttpMethod.Get, $"/agent/status?id={id}", agentId, secret))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var cap = _f.Services.GetRequiredService<OneTimeTokenService>().Read(grant)!;
        return cap.ExpiresAt;
    }

    [Fact]
    public async Task Matching_policy_shortens_the_grant_and_non_matching_agents_keep_the_default()
    {
        // Global OneTimeMinutes is 15; the policy shortens matching agents to 5.
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("prod-ssh", "ssh:*", new[] { "env:prod" }, 1, 5), "google:admin", default);

        Register("pol-prod", "s1", new[] { "env:prod" });   // matches the policy
        Register("pol-dev", "s2", new[] { "env:dev" });     // does not match

        var now = _f.Clock.GetUtcNow();
        Assert.Equal(now.AddMinutes(5).ToUnixTimeSeconds(),
            (await GrantExpiryFor("pol-prod", "s1", "prod-01")).ToUnixTimeSeconds());   // policy TTL
        Assert.Equal(now.AddMinutes(15).ToUnixTimeSeconds(),
            (await GrantExpiryFor("pol-dev", "s2", "dev-01")).ToUnixTimeSeconds());     // global default
    }

    [Fact]
    public async Task Policy_can_only_shorten_never_extend_past_the_global_lifetime()
    {
        // A policy TTL longer than the global (15) must not extend the grant.
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("long-ssh", "ssh:long-*", Array.Empty<string>(), 1, 999), "google:admin", default);
        Register("pol-long", "s3", Array.Empty<string>());

        var now = _f.Clock.GetUtcNow();
        Assert.Equal(now.AddMinutes(15).ToUnixTimeSeconds(),
            (await GrantExpiryFor("pol-long", "s3", "long-01")).ToUnixTimeSeconds());   // clamped to global
    }
}
