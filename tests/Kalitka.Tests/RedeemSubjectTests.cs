using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Redeem returns the Core-approved principal (the request's user) as <c>subject</c>
/// (0.25.1). This is the binding an SSH-cert signer relies on: the certificate principal
/// must come from what Core approved, never from an unvalidated caller argument, so an
/// approval for one login can never be turned into a certificate for another.
/// </summary>
public class RedeemSubjectTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public RedeemSubjectTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Register(string id, string secret) =>
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash(secret),
            new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null));

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

    [Fact]
    public async Task Redeem_returns_the_approved_user_as_subject()
    {
        Register("ssh-bind", "s");
        // The request is for login "deploy" — that, and only that, is what an approval binds.
        var id = Field(await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "ssh-bind", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy" }))).Content.ReadAsStringAsync(), "id")!;

        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-admin", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = id, ["verb"] = "ok", ["csrf"] = a.IssueCsrf(who.Sub) }) };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={a.IssueCookie(who)}");
        await Client().SendAsync(decide);

        var status = await (await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/requests/{id}", "ssh-bind", "s"))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var redeem = await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/grants/redeem", "ssh-bind", "s",
            new() { ["grant"] = grant, ["agent"] = "bastion" }))).Content.ReadAsStringAsync();

        Assert.Equal("deploy", Field(redeem, "subject"));   // the signer must use exactly this
    }
}
