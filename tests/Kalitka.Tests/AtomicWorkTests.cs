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
    private readonly SqliteAuditStore _audit;
    private readonly SqliteAtomicWork _atomic;

    public AtomicWorkTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "kalitka-atomic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "state.db");
        // Same file for both — that is what lets them share a transaction.
        _requests = new SqliteRequestStore(_db);
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
}
