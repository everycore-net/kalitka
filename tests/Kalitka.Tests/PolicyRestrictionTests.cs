using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Restrict-only policy gates and cert-binding carried through the grant (0.26.1): a
/// source-address flows to redeem for an SSH cert to pin, a policy can require a source
/// binding, and a policy can allow-list which logins (principals) a request may ask for.
/// All refusals happen up front, before anyone is asked to approve.
/// </summary>
public class PolicyRestrictionTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public PolicyRestrictionTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Register(string id, string secret, string[]? tags = null) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null) { Tags = tags ?? Array.Empty<string>() });

    private static HttpRequestMessage Req(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
    {
        var r = new HttpRequestMessage(m, url) { Content = form is null ? null : new FormUrlEncodedContent(form) };
        r.Headers.Add("X-Kalitka-Agent-Id", id);
        r.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return r;
    }

    private static string? Field(string j, string n)
    {
        using var d = JsonDocument.Parse(j);
        return d.RootElement.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
    }

    private async Task Approve(string id)
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-admin", "admin@example.com");
        var d = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = id, ["verb"] = "ok", ["csrf"] = a.IssueCsrf(who.Sub) }) };
        d.Headers.Add("Cookie", $"{AdminAuth.CookieName}={a.IssueCookie(who)}");
        await Client().SendAsync(d);
    }

    [Fact]
    public async Task The_approved_source_address_is_returned_on_redeem()
    {
        Register("src-flow", "s");
        const string cidr = "10.0.0.0/24,192.168.1.5";
        var id = Field(await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "src-flow", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy", ["source_address"] = cidr }))).Content.ReadAsStringAsync(), "id")!;
        await Approve(id);
        var grant = Field(await (await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/requests/{id}", "src-flow", "s"))).Content.ReadAsStringAsync(), "grant")!;
        var redeem = await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/grants/redeem", "src-flow", "s",
            new() { ["grant"] = grant, ["agent"] = "bastion" }))).Content.ReadAsStringAsync();

        Assert.Equal(cidr, Field(redeem, "source_address"));
    }

    [Fact]
    public async Task A_policy_requiring_a_source_address_refuses_a_request_without_one()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("prod-pinned", "ssh:*", new[] { "env:src" }, 1, 0) { RequireSourceAddress = true },
                "google:admin", default);
        Register("src-req", "s", new[] { "env:src" });

        var bare = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "src-req", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy" }));
        Assert.Equal(HttpStatusCode.Conflict, bare.StatusCode);
        Assert.Equal("source-required", Field(await bare.Content.ReadAsStringAsync(), "state"));

        var pinned = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "src-req", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy", ["source_address"] = "10.0.0.0/24" }));
        Assert.Equal(HttpStatusCode.OK, pinned.StatusCode);
    }

    [Fact]
    public async Task A_principal_allow_list_permits_some_logins_and_refuses_others()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("prod-logins", "ssh:*", new[] { "env:pl" }, 1, 0)
            { AllowedPrincipals = new[] { "deploy", "readonly" } }, "google:admin", default);
        Register("pl-agent", "s", new[] { "env:pl" });

        var root = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "pl-agent", "s",
            new() { ["host"] = "prod-01", ["user"] = "root" }));
        Assert.Equal(HttpStatusCode.Conflict, root.StatusCode);
        Assert.Equal("principal-not-allowed", Field(await root.Content.ReadAsStringAsync(), "state"));

        var deploy = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "pl-agent", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy" }));
        Assert.Equal(HttpStatusCode.OK, deploy.StatusCode);
        Assert.Equal("waiting", Field(await deploy.Content.ReadAsStringAsync(), "state"));
    }

    [Fact]
    public async Task Overlapping_principal_allow_lists_intersect()
    {
        // Two policies match the same agent; a login must be permitted by BOTH.
        var svc = _f.Services.GetRequiredService<PolicyService>();
        await svc.Save(new AccessPolicy("pl-a", "ssh:*", new[] { "env:ix" }, 1, 0)
        { AllowedPrincipals = new[] { "deploy", "readonly" } }, "google:admin", default);
        await svc.Save(new AccessPolicy("pl-b", "ssh:*", new[] { "env:ix" }, 1, 0)
        { AllowedPrincipals = new[] { "deploy" } }, "google:admin", default);
        Register("ix-agent", "s", new[] { "env:ix" });

        // readonly is allowed by pl-a but not pl-b -> refused (intersection is {deploy}).
        var ro = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "ix-agent", "s",
            new() { ["host"] = "prod-01", ["user"] = "readonly" }));
        Assert.Equal(HttpStatusCode.Conflict, ro.StatusCode);

        var deploy = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "ix-agent", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy" }));
        Assert.Equal(HttpStatusCode.OK, deploy.StatusCode);
    }
}
