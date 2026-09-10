using System.Net;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The unit of work that makes a state change and its audit event commit together.
/// The load-bearing test is the rollback: when the audit append fails, the resolve
/// it was paired with must be undone — no access without its history.
/// </summary>
public sealed class AtomicWorkTests : IDisposable
{
    private readonly string _dir;
    private readonly string _db;
    private readonly SqliteRequestStore _requests;
    private readonly SqliteReplayStore _replay;
    private readonly SqliteSessionStore _sessions;
    private readonly SqliteAuditStore _audit;
    private readonly SqliteAtomicWork _atomic;

    public AtomicWorkTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "kalitka-atomic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "state.db");
        // One file for all of them — that is what lets them share a transaction.
        _requests = new SqliteRequestStore(_db);
        _replay = new SqliteReplayStore(_db);
        _sessions = new SqliteSessionStore(_db);
        _audit = new SqliteAuditStore(_db);
        _atomic = new SqliteAtomicWork(_db);
    }

    public void Dispose()
    {
        try { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); Directory.Delete(_dir, true); }
        catch { }
    }

    private void AddWaiting(string id, DateTimeOffset raised) => _requests.Add(new PendingRequest
    {
        Id = id, Target = "prod-01", Input = "sergej", Ip = "203.0.113.5", Resource = "ssh:prod-01",
        Country = "Germany", CountryCode = "DE", City = "Berlin", Raised = raised, State = "waiting"
    });

    private static AuditEvent Approved(string eventId, string requestId) => new(
        eventId, DateTimeOffset.UtcNow, AuditEvents.AccessApproved, "google:sub", "sergej",
        "ssh:prod-01", requestId, "-", "web", "ok");

    [Fact]
    public async Task Resolve_and_append_commit_together()
    {
        var raised = DateTimeOffset.UtcNow;
        AddWaiting("r1", raised);

        var resolved = await _atomic.Do(scope =>
        {
            Assert.True(scope.TryResolve("r1", "approved", raised.AddMinutes(-5), out var r));
            scope.AppendAudit(Approved("evt-1", "r1"));
            return r;
        }, default);

        Assert.NotNull(resolved);
        Assert.Equal("approved", _requests.Get("r1")!.State);

        var events = await _audit.Query(new AuditQuery(), default);
        Assert.Contains(events, e => e.Id == "evt-1" && e.EventType == AuditEvents.AccessApproved);
    }

    [Fact]
    public async Task Append_failure_rolls_back_the_resolve()
    {
        var raised = DateTimeOffset.UtcNow;
        AddWaiting("r1", raised);

        // Seed an event, then try to append another with the same primary key inside
        // the unit of work: the INSERT throws, so the whole transaction must roll back.
        await _audit.Append(Approved("dup", "r0"), default);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _atomic.Do(scope =>
            {
                scope.TryResolve("r1", "approved", raised.AddMinutes(-5), out _);
                scope.AppendAudit(Approved("dup", "r1"));   // duplicate id → constraint violation
                return true;
            }, default));

        // The resolve was rolled back with the failed append: the request is still waiting.
        Assert.Equal("waiting", _requests.Get("r1")!.State);

        // And no partial audit row landed — only the one we seeded.
        var events = await _audit.Query(new AuditQuery(), default);
        Assert.Single(events);
        Assert.Equal("dup", events[0].Id);
    }

    // ---- Redeem: consume + start + two appends, all four or nothing ------------

    private static AuditEvent Ev(string id, string type, string requestId) => new(
        id, DateTimeOffset.UtcNow, type, "agent", "sergej", "ssh:prod-01", requestId, "g1", "ssh", "");

    private static SessionRecord Session(string id, DateTimeOffset at) =>
        new(id, "g1", "r1", "sergej", "ssh:prod-01", "linux-prod-03", at, null, "", "");

    [Fact]
    public async Task Redeem_commits_all_four_effects_together()
    {
        var now = DateTimeOffset.UtcNow;
        var ok = await _atomic.Do(scope =>
        {
            Assert.True(scope.TryConsumeReplay("jti-1", now.AddMinutes(15)));
            scope.StartSession(Session("s1", now));
            scope.AppendAudit(Ev("redeemed-1", AuditEvents.GrantRedeemed, "r1"));
            scope.AppendAudit(Ev("started-1", AuditEvents.SessionStarted, "r1"));
            return true;
        }, default);

        Assert.True(ok);
        Assert.NotNull(_sessions.Get("s1"));
        Assert.False(await _replay.TryConsumeAsync("jti-1", now.AddMinutes(15), default));   // already consumed
        var events = await _audit.Query(new AuditQuery(), default);
        Assert.Contains(events, e => e.Id == "redeemed-1");
        Assert.Contains(events, e => e.Id == "started-1");
    }

    [Fact]
    public async Task Redeem_rolls_back_all_four_when_the_last_append_fails()
    {
        var now = DateTimeOffset.UtcNow;
        // Seed the id the fourth append will collide with, so session.started throws.
        await _audit.Append(Ev("dup", AuditEvents.SessionStarted, "r0"), default);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _atomic.Do(scope =>
            {
                scope.TryConsumeReplay("jti-1", now.AddMinutes(15));                 // ✓
                scope.StartSession(Session("s1", now));                             // ✓
                scope.AppendAudit(Ev("redeemed-1", AuditEvents.GrantRedeemed, "r1"));// ✓
                scope.AppendAudit(Ev("dup", AuditEvents.SessionStarted, "r1"));      // ✗ duplicate id
                return true;
            }, default));

        // The whole redeem is undone: replay marker absent, session absent, both
        // events absent. This is the invariant "consumed ⇒ session + both events".
        Assert.True(await _replay.TryConsumeAsync("jti-1", now.AddMinutes(15), default));   // consumable again → marker was rolled back
        Assert.Null(_sessions.Get("s1"));                                                   // session rolled back
        var events = await _audit.Query(new AuditQuery(), default);
        Assert.Single(events);                                                              // only the seeded "dup"
        Assert.DoesNotContain(events, e => e.Id == "redeemed-1");
    }

    [Fact]
    public async Task Close_leaves_the_session_open_when_the_append_fails()
    {
        var now = DateTimeOffset.UtcNow;
        _sessions.Start(Session("s1", now));
        await _audit.Append(Ev("dup", AuditEvents.SessionEnded, "r1"), default);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _atomic.Do(scope =>
            {
                Assert.True(scope.EndSession("s1", "ok", now.AddMinutes(5)));   // ✓
                scope.AppendAudit(Ev("dup", AuditEvents.SessionEnded, "r1"));   // ✗ duplicate id
                return true;
            }, default));

        var s = _sessions.Get("s1");
        Assert.NotNull(s);
        Assert.Null(s!.EndedAt);   // the close was rolled back — the session is still open
    }

    // ---- Wiring: the app turns on transactional mode when state == audit file ----

    public sealed class TransactionalFactory : GateFactory
    {
        public string Db { get; } =
            Path.Combine(Path.GetTempPath(), "kalitka-tx-" + Guid.NewGuid().ToString("N"), "state.db");

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            Directory.CreateDirectory(Path.GetDirectoryName(Db)!);
            builder.UseSetting("Kalitka:StateDbPath", Db);
            builder.UseSetting("Kalitka:AuditDbPath", Db);   // same file → transactional
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try
            {
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                Directory.Delete(Path.GetDirectoryName(Db)!, true);
            }
            catch { }
        }
    }

    [Fact]
    public async Task Wired_app_uses_a_transaction_for_state_and_audit()
    {
        using var f = new TransactionalFactory();

        // State and audit share a file, so the unit of work must be registered —
        // this is what routes Decide through the transactional branch.
        Assert.NotNull(f.Services.GetService<IAtomicWork>());

        HttpClient Client() => f.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

        HttpRequestMessage Agent(HttpMethod m, string url, Dictionary<string, string>? form = null)
        {
            var req = new HttpRequestMessage(m, url);
            if (form is not null) req.Content = new FormUrlEncodedContent(form);
            req.Headers.Add("X-Kalitka-Agent", "agent-secret");
            return req;
        }

        var raise = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request",
            new() { ["host"] = "prod-01", ["user"] = "sergej", ["ip"] = "203.0.113.90" }));
        using var doc = JsonDocument.Parse(await raise.Content.ReadAsStringAsync());
        var id = doc.RootElement.GetProperty("id").GetString()!;

        var auth = f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);   // Post-Redirect-Get: 302 back to the request view

        // The decision and its audit event committed together: state is approved
        // and the durable event is there, both in the one file.
        var audit = f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(Resource: "ssh:prod-01"), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.AccessApproved && e.RequestId == id);
    }

    [Fact]
    public async Task Wired_app_redeem_and_close_run_the_transactional_path()
    {
        using var f = new TransactionalFactory();
        Assert.NotNull(f.Services.GetService<IAtomicWork>());

        HttpClient Client() => f.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        HttpRequestMessage Agent(HttpMethod m, string url, Dictionary<string, string>? form = null)
        {
            var req = new HttpRequestMessage(m, url);
            if (form is not null) req.Content = new FormUrlEncodedContent(form);
            req.Headers.Add("X-Kalitka-Agent", "agent-secret");
            return req;
        }
        static string? Field(string json, string name)
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null
                ? v.GetString() : null;
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

        // Reuse still refused, now through the transactional consume.
        var again = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        var end = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/session/end",
            new() { ["session_id"] = sessionId, ["outcome"] = "ok" }));
        Assert.Equal(HttpStatusCode.OK, end.StatusCode);

        // The whole lifecycle committed to the one file: redeemed, started, ended.
        var audit = f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(Resource: "ssh:prod-01"), default);
        Assert.Contains(events, e => e.EventType == AuditEvents.GrantRedeemed && e.RequestId == id);
        Assert.Contains(events, e => e.EventType == AuditEvents.SessionStarted);
        Assert.Contains(events, e => e.EventType == AuditEvents.SessionEnded);
    }
}
