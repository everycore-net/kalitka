using System.Net.Http;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Operator principals (parallel track): a quorum counts DISTINCT people, not channels.
/// An identity linked to a principal (telegram:, later slack:/teams:/app:) counts as that
/// person; the same person on two channels counts once; an unlinked Google admin still
/// counts as itself; any other unlinked channel does not. This is what lets Telegram
/// approvals satisfy four-eyes without letting one human satisfy it alone.
/// </summary>
public class OperatorPrincipalTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public OperatorPrincipalTests(GateFactory f) => _f = f;

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

    private static string? Field(string j, string n)
    {
        using var d = JsonDocument.Parse(j);
        return d.RootElement.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
    }

    private async Task<string> Raise(string agentId, string secret, string host)
    {
        var r = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/v1/requests", agentId, secret,
            new() { ["host"] = host, ["user"] = "sergej" }));
        return Field(await r.Content.ReadAsStringAsync(), "id")!;
    }

    private GateService Gate => _f.Services.GetRequiredService<GateService>();

    private async Task Quorum(string name, string[] tags) =>
        await _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy(name, "ssh:*", tags, 2, 0), "google:admin", default);

    [Fact]
    public async Task A_linked_telegram_approval_counts_toward_a_quorum()
    {
        await Quorum("q-tg", new[] { "env:tg" });
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("alice", "Alice", new[] { "telegram:111" }, "google:admin", default);
        Register("op-a", "s", new[] { "env:tg" });
        var id = await Raise("op-a", "s", "h1");

        // One unlinked Google admin — counts as itself.
        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id, "ok", "google:sub-bob")).Outcome);
        Assert.Equal("waiting", Gate.StateOf(id));

        // A Telegram approval by a linked, distinct person — reaches the quorum.
        Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(id, "ok", "telegram:111")).Outcome);
        Assert.Equal("approved", Gate.StateOf(id));
    }

    [Fact]
    public async Task The_same_person_on_two_channels_counts_once()
    {
        await Quorum("q-dup", new[] { "env:dup" });
        await _f.Services.GetRequiredService<PrincipalService>()
            .Save("carol", "Carol", new[] { "google:sub-carol", "telegram:222" }, "google:admin", default);
        Register("op-c", "s", new[] { "env:dup" });
        var id = await Raise("op-c", "s", "h2");

        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id, "ok", "google:sub-carol")).Outcome);
        // Same operator via Telegram — dedupes to one vote, so still short of two.
        Assert.Equal(CallbackOutcome.Pending, (await Gate.Decide(id, "ok", "telegram:222")).Outcome);
        Assert.Equal("waiting", Gate.StateOf(id));
    }

    [Fact]
    public async Task An_unlinked_telegram_identity_does_not_count()
    {
        await Quorum("q-unl", new[] { "env:unl" });
        Register("op-u", "s", new[] { "env:unl" });
        var id = await Raise("op-u", "s", "h3");

        var r = await Gate.Decide(id, "ok", "telegram:999");   // not linked to anyone
        Assert.Equal(CallbackOutcome.Pending, r.Outcome);
        Assert.Contains("not linked", r.Text);
        Assert.Equal("waiting", Gate.StateOf(id));
    }

    [Fact]
    public async Task An_identity_cannot_be_linked_to_two_operators()
    {
        var svc = _f.Services.GetRequiredService<PrincipalService>();
        Assert.Null(await svc.Save("dave", "Dave", new[] { "telegram:555" }, "google:admin", default));
        var err = await svc.Save("evan", "Evan", new[] { "telegram:555" }, "google:admin", default);
        Assert.NotNull(err);                       // rejected: already linked to dave
        Assert.Equal("dave", svc.Resolve("telegram:555"));
    }
}
