using System.Net;
using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Command-aware approval (0.26): a request can carry the exact command to run; the
/// approved command is returned on redeem so an SSH-cert signer can force it, and a
/// policy can REQUIRE a command (forbid an open shell) for a resource. The SSH analogue
/// of 0.24's stored-procedure actions — one specific, approved operation, not a shell.
/// </summary>
public class CommandAwareTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public CommandAwareTests(GateFactory f) => _f = f;

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
    public async Task The_approved_command_is_returned_on_redeem()
    {
        Register("cmd-flow", "s");
        const string cmd = "systemctl restart nginx";
        var id = Field(await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "cmd-flow", "s",
            new() { ["host"] = "prod-01", ["user"] = "deploy", ["command"] = cmd }))).Content.ReadAsStringAsync(), "id")!;
        await Approve(id);
        var grant = Field(await (await Client().SendAsync(Req(HttpMethod.Get, $"/agent/v1/requests/{id}", "cmd-flow", "s"))).Content.ReadAsStringAsync(), "grant")!;
        var redeem = await (await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/grants/redeem", "cmd-flow", "s",
            new() { ["grant"] = grant, ["agent"] = "bastion" }))).Content.ReadAsStringAsync();

        Assert.Equal(cmd, Field(redeem, "command"));     // the signer forces exactly this
        Assert.Equal("deploy", Field(redeem, "subject"));
    }

    [Fact]
    public async Task A_policy_requiring_a_command_refuses_an_open_shell()
    {
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("prod-cmd-only", "ssh:*", new[] { "env:prod" }, 1, 0) { RequireCommand = true },
                "google:admin", default);
        Register("cmd-req", "s", new[] { "env:prod" });

        // No command → refused up front, before anyone is asked to approve.
        var open = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "cmd-req", "s",
            new() { ["host"] = "prod-01", ["user"] = "root" }));
        Assert.Equal(HttpStatusCode.Conflict, open.StatusCode);
        Assert.Equal("command-required", Field(await open.Content.ReadAsStringAsync(), "state"));

        // With a command → accepted (waiting for approval).
        var scoped = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "cmd-req", "s",
            new() { ["host"] = "prod-01", ["user"] = "root", ["command"] = "tail -n100 /var/log/app.log" }));
        Assert.Equal(HttpStatusCode.OK, scoped.StatusCode);
        Assert.Equal("waiting", Field(await scoped.Content.ReadAsStringAsync(), "state"));
    }

    [Fact]
    public async Task Without_a_requiring_policy_an_open_shell_is_still_fine()
    {
        Register("cmd-open", "s", new[] { "env:staging" });   // no matching require-command policy
        var resp = await Client().SendAsync(Req(HttpMethod.Post, "/agent/v1/requests", "cmd-open", "s",
            new() { ["host"] = "staging-01", ["user"] = "sergej" }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("waiting", Field(await resp.Content.ReadAsStringAsync(), "state"));
    }
}
