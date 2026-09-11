using System.Net;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The Postgres backend — the multi-node step. Runs only when KALITKA_TEST_POSTGRES
/// is set (CI provides a Postgres service; a local run without it skips). Proves the
/// same guarantees as the SQLite backend against real Postgres: state written by one
/// "instance" is seen by another, resolve/redeem/close are atomic and once-only, and
/// a decision commits with its audit event (or rolls back with it).
/// </summary>
public sealed class PostgresStoreTests
{
    private readonly string? _cs = Environment.GetEnvironmentVariable("KALITKA_TEST_POSTGRES");

    public PostgresStoreTests()
    {
        if (string.IsNullOrEmpty(_cs)) return;
        // Ensure the schema exists, then start each test from a clean slate.
        _ = new PgRequestStore(_cs); _ = new PgReplayStore(_cs);
        _ = new PgSessionStore(_cs); _ = new PgAuditStore(_cs); _ = new PgConfigStore(_cs);
        _ = new PgAgentStore(_cs);
        using var conn = new NpgsqlConnection(_cs); conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "TRUNCATE requests, replay, sessions, audit, config, agents;";
        cmd.ExecuteNonQuery();
    }

    private bool Skip => string.IsNullOrEmpty(_cs);

    private PendingRequest Req(string id, DateTimeOffset raised, string state = "waiting") => new()
    {
        Id = id, Target = "prod-01", Input = "sergej", Ip = "203.0.113.5", Resource = "ssh:prod-01",
        Country = "Germany", CountryCode = "DE", City = "Berlin", Raised = raised, State = state
    };

    private static AuditEvent Ev(string id, string type, string requestId) => new(
        id, DateTimeOffset.UtcNow, type, "agent", "sergej", "ssh:prod-01", requestId, "g1", "ssh", "");

    private static SessionRecord Session(string id, DateTimeOffset at) =>
        new(id, "g1", "r1", "sergej", "ssh:prod-01", "linux-prod-03", at, null, "", "");

    // ---- Requests -----------------------------------------------------------

    [Fact]
    public void Request_is_visible_to_another_instance()
    {
        if (Skip) return;
        var raised = DateTimeOffset.UtcNow;
        new PgRequestStore(_cs!).Add(Req("r1", raised));
        var got = new PgRequestStore(_cs!).Get("r1");
        Assert.NotNull(got);
        Assert.Equal("ssh:prod-01", got!.Resource);
        Assert.Equal(raised.ToUnixTimeMilliseconds(), got.Raised.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void Resolves_once_across_instances()
    {
        if (Skip) return;
        var raised = DateTimeOffset.UtcNow;
        var ok = raised.AddMinutes(-5);
        new PgRequestStore(_cs!).Add(Req("r1", raised));
        Assert.True(new PgRequestStore(_cs!).TryResolve("r1", "approved", ok, out var r));
        Assert.Equal("approved", r!.State);
        Assert.False(new PgRequestStore(_cs!).TryResolve("r1", "denied", ok, out _));
        Assert.Equal("approved", new PgRequestStore(_cs!).Get("r1")!.State);
    }

    [Fact]
    public void Grant_is_set_once()
    {
        if (Skip) return;
        var store = new PgRequestStore(_cs!);
        store.Add(Req("r1", DateTimeOffset.UtcNow));
        Assert.True(store.TrySetGrant("r1", "grant-A", out var first));
        Assert.Equal("grant-A", first);
        Assert.False(new PgRequestStore(_cs!).TrySetGrant("r1", "grant-B", out var second));
        Assert.Equal("grant-A", second);
    }

    [Fact]
    public void Count_and_drop_respect_state_and_age()
    {
        if (Skip) return;
        var store = new PgRequestStore(_cs!);
        var now = DateTimeOffset.UtcNow;
        store.Add(Req("fresh", now));
        store.Add(Req("stale", now.AddMinutes(-30)));
        store.Add(Req("done", now, state: "approved"));
        Assert.Equal(1, store.CountWaiting(now.AddMinutes(-5)));
        store.DropOlderThan(now.AddMinutes(-10));
        Assert.Null(store.Get("stale"));
        Assert.NotNull(store.Get("fresh"));
    }

    [Fact]
    public void Concurrent_resolve_only_one_wins()
    {
        if (Skip) return;
        var raised = DateTimeOffset.UtcNow;
        var ok = raised.AddMinutes(-5);
        new PgRequestStore(_cs!).Add(Req("r1", raised));
        var wins = 0;
        Parallel.For(0, 20, i =>
        {
            var state = i % 2 == 0 ? "approved" : "denied";
            if (new PgRequestStore(_cs!).TryResolve("r1", state, ok, out _)) Interlocked.Increment(ref wins);
        });
        Assert.Equal(1, wins);
        Assert.NotEqual("waiting", new PgRequestStore(_cs!).Get("r1")!.State);
    }

    // ---- Replay -------------------------------------------------------------

    [Fact]
    public async Task Jti_is_consumable_once_across_instances()
    {
        if (Skip) return;
        var exp = DateTimeOffset.UtcNow.AddMinutes(15);
        Assert.True(await new PgReplayStore(_cs!).TryConsumeAsync("jti-1", exp, default));
        Assert.False(await new PgReplayStore(_cs!).TryConsumeAsync("jti-1", exp, default));
    }

    [Fact]
    public async Task Concurrent_consume_only_one_wins()
    {
        if (Skip) return;
        var store = new PgReplayStore(_cs!);
        var exp = DateTimeOffset.UtcNow.AddMinutes(15);
        var wins = 0;
        await Parallel.ForAsync(0, 20, async (_, ct) =>
        {
            if (await store.TryConsumeAsync("jti-hot", exp, ct)) Interlocked.Increment(ref wins);
        });
        Assert.Equal(1, wins);
    }

    // ---- Sessions -----------------------------------------------------------

    [Fact]
    public void Session_starts_persists_and_closes_once()
    {
        if (Skip) return;
        var start = DateTimeOffset.UtcNow;
        new PgSessionStore(_cs!).Start(Session("s1", start));
        Assert.NotNull(new PgSessionStore(_cs!).Get("s1"));
        Assert.True(new PgSessionStore(_cs!).End("s1", "ok", start.AddMinutes(3)));
        Assert.False(new PgSessionStore(_cs!).End("s1", "again", start.AddMinutes(4)));
        var closed = new PgSessionStore(_cs!).Get("s1");
        Assert.Equal("ok", closed!.Outcome);
        Assert.NotNull(closed.EndedAt);
    }

    // ---- Atomic unit of work (the load-bearing ones) ------------------------

    [Fact]
    public async Task Redeem_commits_all_four_effects_together()
    {
        if (Skip) return;
        var atomic = new PgAtomicWork(_cs!);
        var now = DateTimeOffset.UtcNow;
        var ok = await atomic.Do(scope =>
        {
            Assert.True(scope.TryConsumeReplay("jti-1", now.AddMinutes(15)));
            scope.StartSession(Session("s1", now));
            scope.AppendAudit(Ev("redeemed-1", AuditEvents.GrantRedeemed, "r1"));
            scope.AppendAudit(Ev("started-1", AuditEvents.SessionStarted, "r1"));
            return true;
        }, default);
        Assert.True(ok);
        Assert.NotNull(new PgSessionStore(_cs!).Get("s1"));
        Assert.False(await new PgReplayStore(_cs!).TryConsumeAsync("jti-1", now.AddMinutes(15), default));
        var events = await new PgAuditStore(_cs!).Query(new AuditQuery(), default);
        Assert.Contains(events, e => e.Id == "redeemed-1");
        Assert.Contains(events, e => e.Id == "started-1");
    }

    [Fact]
    public async Task Redeem_rolls_back_all_four_when_the_last_append_fails()
    {
        if (Skip) return;
        var atomic = new PgAtomicWork(_cs!);
        var now = DateTimeOffset.UtcNow;
        await new PgAuditStore(_cs!).Append(Ev("dup", AuditEvents.SessionStarted, "r0"), default);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await atomic.Do(scope =>
            {
                scope.TryConsumeReplay("jti-1", now.AddMinutes(15));
                scope.StartSession(Session("s1", now));
                scope.AppendAudit(Ev("redeemed-1", AuditEvents.GrantRedeemed, "r1"));
                scope.AppendAudit(Ev("dup", AuditEvents.SessionStarted, "r1"));   // duplicate id → violation
                return true;
            }, default));

        Assert.True(await new PgReplayStore(_cs!).TryConsumeAsync("jti-1", now.AddMinutes(15), default)); // marker rolled back
        Assert.Null(new PgSessionStore(_cs!).Get("s1"));                                                  // session rolled back
        var events = await new PgAuditStore(_cs!).Query(new AuditQuery(), default);
        Assert.DoesNotContain(events, e => e.Id == "redeemed-1");
    }

    [Fact]
    public async Task Close_leaves_the_session_open_when_the_append_fails()
    {
        if (Skip) return;
        var atomic = new PgAtomicWork(_cs!);
        var now = DateTimeOffset.UtcNow;
        new PgSessionStore(_cs!).Start(Session("s1", now));
        await new PgAuditStore(_cs!).Append(Ev("dup", AuditEvents.SessionEnded, "r1"), default);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await atomic.Do(scope =>
            {
                Assert.True(scope.EndSession("s1", "ok", now.AddMinutes(5)));
                scope.AppendAudit(Ev("dup", AuditEvents.SessionEnded, "r1"));
                return true;
            }, default));

        var s = new PgSessionStore(_cs!).Get("s1");
        Assert.NotNull(s);
        Assert.Null(s!.EndedAt);
    }

    // ---- Config -------------------------------------------------------------

    [Fact]
    public void Config_is_visible_to_another_instance()
    {
        if (Skip) return;
        new PgConfigStore(_cs!).Mutate("enforced", _ => "[\"sage.example.com\"]");
        Assert.Equal("[\"sage.example.com\"]", new PgConfigStore(_cs!).Get("enforced"));
    }

    [Fact]
    public void Config_concurrent_mutate_loses_nothing()
    {
        if (Skip) return;
        new PgConfigStore(_cs!);   // ensure table
        Parallel.For(0, 20, i =>
        {
            new PgConfigStore(_cs!).Mutate("k", cur =>
            {
                var list = string.IsNullOrEmpty(cur) ? new List<int>() : JsonSerializer.Deserialize<List<int>>(cur)!;
                list.Add(i);
                return JsonSerializer.Serialize(list);
            });
        });
        var final = JsonSerializer.Deserialize<List<int>>(new PgConfigStore(_cs!).Get("k")!)!;
        Assert.Equal(20, final.Count);   // advisory-locked RMW: no lost updates across writers
    }

    // ---- Agents -------------------------------------------------------------

    [Fact]
    public void Agent_persists_and_revoke_is_visible_to_another_instance()
    {
        if (Skip) return;
        var a = new Agent("pg-a", "pg-a", "linux", "h", AgentStatus.Active, AgentSecrets.Hash("s"),
            new[] { "ssh" }, new[] { "ssh:*" }, "", DateTimeOffset.UtcNow, null, "", null);
        new PgAgentStore(_cs!).Create(a);

        var got = new PgAgentStore(_cs!).GetById("pg-a")!;
        Assert.Equal(AgentStatus.Active, got.Status);
        Assert.True(AgentSecrets.Verify("s", got.SecretHash));
        Assert.Equal(new[] { "ssh:*" }, got.AllowedResources);

        Assert.True(new PgAgentStore(_cs!).SetStatus("pg-a", AgentStatus.Revoked, DateTimeOffset.UtcNow));
        var seen = new PgAgentStore(_cs!).GetById("pg-a")!;   // a second node
        Assert.Equal(AgentStatus.Revoked, seen.Status);
        Assert.NotNull(seen.RevokedAt);
    }

    // ---- Wired app on Postgres ----------------------------------------------

    private sealed class PgFactory : GateFactory
    {
        private readonly string _cs;
        public PgFactory(string cs) => _cs = cs;
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("Kalitka:PostgresConnectionString", _cs);
        }
    }

    [Fact]
    public async Task Wired_app_uses_the_postgres_backend_end_to_end()
    {
        if (Skip) return;
        using var f = new PgFactory(_cs!);
        Assert.IsType<PgRequestStore>(f.Services.GetRequiredService<IRequestStore>());
        Assert.IsType<PgAtomicWork>(f.Services.GetRequiredService<IAtomicWork>());

        HttpClient Client() => f.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        HttpRequestMessage Agent(HttpMethod m, string url, Dictionary<string, string>? form = null)
        {
            var req = new HttpRequestMessage(m, url);
            if (form is not null) req.Content = new FormUrlEncodedContent(form);
            req.Headers.Add("X-Kalitka-Agent", "agent-secret");
            return req;
        }
        static string? Field(string j, string n)
        {
            using var doc = JsonDocument.Parse(j);
            return doc.RootElement.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
        }

        var raise = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request",
            new() { ["host"] = "prod-01", ["user"] = "sergej", ["ip"] = "203.0.113.90" }));
        var id = Field(await raise.Content.ReadAsStringAsync(), "id")!;

        var auth = f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);

        var status = await (await Client().SendAsync(Agent(HttpMethod.Get, $"/agent/status?id={id}"))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant")!;
        var redeem = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.OK, redeem.StatusCode);
        var sessionId = Field(await redeem.Content.ReadAsStringAsync(), "session_id")!;
        var again = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        var end = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/session/end",
            new() { ["session_id"] = sessionId, ["outcome"] = "ok" }));
        Assert.Equal(HttpStatusCode.OK, end.StatusCode);

        var audit = f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(Resource: "ssh:prod-01"), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.GrantRedeemed && e.RequestId == id);
        Assert.Contains(events, e => e.EventType == AuditEvents.SessionStarted);
        Assert.Contains(events, e => e.EventType == AuditEvents.SessionEnded);
    }
}
