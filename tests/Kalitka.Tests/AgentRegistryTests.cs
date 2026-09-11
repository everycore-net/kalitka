using System.Net;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The agent registry trust model: an agent is identified by its id, authenticated
/// by its own secret, and authorised only for its capabilities and resources — a
/// valid credential is never a licence for anything else. Covers the mandatory
/// isolation cases; enrollment-token cases come with that slice.
/// </summary>
public class AgentRegistryTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AgentRegistryTests(GateFactory f) => _f = f;

    // ---- Unit: identity, secrets, store -------------------------------------

    [Fact]
    public void Secret_hash_verifies_and_rejects_wrong()
    {
        var hash = AgentSecrets.Hash("s3cr3t");
        Assert.True(AgentSecrets.Verify("s3cr3t", hash));
        Assert.False(AgentSecrets.Verify("wrong", hash));
        Assert.NotEqual(hash, AgentSecrets.Hash("s3cr3t"));   // salted: two hashes differ
    }

    [Fact]
    public void MayRepresent_requires_both_capability_and_resource()
    {
        var a = new AgentIdentity("a", new[] { "ssh" }, new[] { "ssh:prod-01" }, IsLegacy: false);
        Assert.True(a.MayRepresent("ssh:prod-01"));
        Assert.False(a.MayRepresent("ssh:other"));       // resource not in scope
        Assert.False(a.MayRepresent("sudo:prod-01"));    // capability not held

        var w = new AgentIdentity("w", new[] { "ssh" }, new[] { "ssh:*" }, IsLegacy: false);
        Assert.True(w.MayRepresent("ssh:anything"));
        Assert.False(w.MayRepresent("rdp:anything"));    // wildcard never crosses capability

        var legacyAny = AgentIdentity.Legacy(Array.Empty<string>());
        Assert.True(legacyAny.MayRepresent("ssh:whatever"));   // legacy unbound = any
        var legacyBound = AgentIdentity.Legacy(new[] { "ssh:prod-01" });
        Assert.False(legacyBound.MayRepresent("ssh:other"));
    }

    [Fact]
    public void Credential_rotation_invalidates_the_old_secret()
    {
        var store = new InMemoryAgentStore();
        var a = Agent("rot", "old-secret", AgentStatus.Active, new[] { "ssh" }, new[] { "ssh:x" });
        store.Create(a);
        Assert.True(store.RotateSecret("rot", AgentSecrets.Hash("new-secret")));
        var after = store.GetById("rot")!;
        Assert.True(AgentSecrets.Verify("new-secret", after.SecretHash));
        Assert.False(AgentSecrets.Verify("old-secret", after.SecretHash));
    }

    [Fact]
    public void Revoked_state_is_visible_to_another_instance()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kalitka-agents-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var db = Path.Combine(dir, "state.db");
            new SqliteAgentStore(db).Create(Agent("n1", "s", AgentStatus.Active, new[] { "ssh" }, new[] { "ssh:x" }));
            Assert.True(new SqliteAgentStore(db).SetStatus("n1", AgentStatus.Revoked, DateTimeOffset.UtcNow));
            var seen = new SqliteAgentStore(db).GetById("n1")!;   // a second "node"
            Assert.Equal(AgentStatus.Revoked, seen.Status);
            Assert.NotNull(seen.RevokedAt);
        }
        finally { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); Directory.Delete(dir, true); }
    }

    // ---- HTTP: authentication + authorisation -------------------------------

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private static Agent Agent(string id, string secret, AgentStatus status, string[] caps, string[] resources) =>
        new(id, id, "linux", "host-" + id, status, AgentSecrets.Hash(secret), caps, resources, "",
            DateTimeOffset.UtcNow, null, "", null);

    private HttpRequestMessage Reg(HttpMethod m, string url, string id, string secret, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url);
        if (form is not null) req.Content = new FormUrlEncodedContent(form);
        req.Headers.Add("X-Kalitka-Agent-Id", id);
        req.Headers.Add("X-Kalitka-Agent-Secret", secret);
        return req;
    }

    private static string? Field(string j, string n)
    {
        using var doc = JsonDocument.Parse(j);
        return doc.RootElement.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
    }

    private async Task<int> RaiseStatus(string agentId, string secret, string host)
    {
        var r = await Client().SendAsync(Reg(HttpMethod.Post, "/agent/request", agentId, secret,
            new() { ["host"] = host, ["user"] = "sergej", ["ip"] = "203.0.113.9" }));
        return (int)r.StatusCode;
    }

    [Fact]
    public async Task Registered_agent_raises_only_its_own_resource()
    {
        var store = _f.Services.GetRequiredService<IAgentStore>();
        store.Create(Agent("reg-a", "sec-a", AgentStatus.Active, new[] { "ssh" }, new[] { "ssh:prod-a" }));

        Assert.Equal(200, await RaiseStatus("reg-a", "sec-a", "prod-a"));   // in scope
        Assert.Equal(403, await RaiseStatus("reg-a", "sec-a", "prod-b"));   // resource not in scope
    }

    [Fact]
    public async Task Agent_cannot_use_another_agents_credential()
    {
        var store = _f.Services.GetRequiredService<IAgentStore>();
        store.Create(Agent("x-a", "sec-x-a", AgentStatus.Active, new[] { "ssh" }, new[] { "ssh:*" }));
        store.Create(Agent("x-b", "sec-x-b", AgentStatus.Active, new[] { "ssh" }, new[] { "ssh:*" }));

        Assert.Equal(200, await RaiseStatus("x-a", "sec-x-a", "h"));    // own credential
        Assert.Equal(403, await RaiseStatus("x-a", "sec-x-b", "h"));    // A's id, B's secret
        Assert.Equal(403, await RaiseStatus("nope", "sec-x-a", "h"));   // unknown id
    }

    [Fact]
    public async Task Disabled_and_revoked_agents_are_rejected()
    {
        var store = _f.Services.GetRequiredService<IAgentStore>();
        store.Create(Agent("dis", "sec", AgentStatus.Disabled, new[] { "ssh" }, new[] { "ssh:*" }));
        store.Create(Agent("rev", "sec", AgentStatus.Revoked, new[] { "ssh" }, new[] { "ssh:*" }));
        Assert.Equal(403, await RaiseStatus("dis", "sec", "h"));
        Assert.Equal(403, await RaiseStatus("rev", "sec", "h"));
    }

    [Fact]
    public async Task Legacy_global_secret_still_works_during_migration()
    {
        // The GateFactory sets AgentSecret=agent-secret and no AgentResources (=> any).
        var req = new HttpRequestMessage(HttpMethod.Post, "/agent/request")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["host"] = "legacy-host", ["user"] = "u", ["ip"] = "203.0.113.9" }) };
        req.Headers.Add("X-Kalitka-Agent", "agent-secret");
        var r = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task Agent_id_survives_request_grant_session_audit()
    {
        var store = _f.Services.GetRequiredService<IAgentStore>();
        store.Create(Agent("chain", "sec-chain", AgentStatus.Active, new[] { "ssh" }, new[] { "ssh:chain-host" }));

        var raise = await Client().SendAsync(Reg(HttpMethod.Post, "/agent/request", "chain", "sec-chain",
            new() { ["host"] = "chain-host", ["user"] = "sergej", ["ip"] = "203.0.113.9" }));
        var id = Field(await raise.Content.ReadAsStringAsync(), "id")!;

        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);

        var status = await (await Client().SendAsync(Reg(HttpMethod.Get, $"/agent/status?id={id}", "chain", "sec-chain"))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var redeem = await Client().SendAsync(Reg(HttpMethod.Post, "/agent/redeem", "chain", "sec-chain",
            new() { ["grant"] = grant, ["agent"] = "reported-hostname" }));
        var sessionId = Field(await redeem.Content.ReadAsStringAsync(), "session_id")!;
        await Client().SendAsync(Reg(HttpMethod.Post, "/agent/session/end", "chain", "sec-chain",
            new() { ["session_id"] = sessionId, ["outcome"] = "ok" }));

        // Every step of the chain carries actor=agent:chain.
        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(Resource: "ssh:chain-host"), default);
        foreach (var type in new[] { AuditEvents.AccessRequested, AuditEvents.GrantCreated,
            AuditEvents.GrantRedeemed, AuditEvents.SessionStarted, AuditEvents.SessionEnded })
            Assert.Contains(events, e => e.EventType == type && e.RequestId == id && e.Actor == "agent:chain");

        // The session records the canonical id; the hostname is only metadata.
        var session = _f.Services.GetRequiredService<ISessionStore>().Get(sessionId)!;
        Assert.Equal("chain", session.AgentId);
        Assert.Equal("reported-hostname", session.Metadata);
    }
}
