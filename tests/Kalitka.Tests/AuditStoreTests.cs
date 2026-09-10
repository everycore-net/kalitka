using Kalitka;
using Xunit;

namespace Kalitka.Tests;

public class AuditStoreTests
{
    private static AuditEvent Ev(string type, string actor, string resource, long ts) =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.FromUnixTimeSeconds(ts), type,
            actor, "subject", resource, "req-" + ts, "-", "web", "");

    private static async Task RoundTrips(IAuditStore store)
    {
        await store.Append(Ev(AuditEvents.AccessRequested, "-", "web:a.example.com", 1000), default);
        await store.Append(Ev(AuditEvents.AccessApproved, "google:sub-1", "web:a.example.com", 2000), default);
        await store.Append(Ev(AuditEvents.AccessDenied, "telegram:42", "web:b.example.com", 3000), default);

        var all = await store.Query(new AuditQuery(), default);
        Assert.Equal(3, all.Count);
        Assert.Equal(AuditEvents.AccessDenied, all[0].EventType);      // newest first

        Assert.Single(await store.Query(new AuditQuery(EventType: AuditEvents.AccessApproved), default));
        Assert.Single(await store.Query(new AuditQuery(Actor: "telegram"), default));
        Assert.Equal(2, (await store.Query(new AuditQuery(Resource: "a.example.com"), default)).Count);

        var page1 = await store.Query(new AuditQuery(Limit: 1), default);
        var page2 = await store.Query(new AuditQuery(Limit: 1, Offset: 1), default);
        Assert.Single(page1);
        Assert.Single(page2);
        Assert.NotEqual(page1[0].Id, page2[0].Id);
    }

    [Fact]
    public Task InMemory_store_appends_filters_and_pages() => RoundTrips(new InMemoryAuditStore());

    [Fact]
    public async Task Sqlite_store_appends_filters_and_pages()
    {
        var path = Path.Combine(Path.GetTempPath(), "kalitka-audit-" + Guid.NewGuid().ToString("N") + ".db");
        try { await RoundTrips(new SqliteAuditStore(path)); }
        finally { foreach (var f in Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + "*")) try { File.Delete(f); } catch { } }
    }

    [Fact]
    public async Task Sqlite_store_survives_reopen()
    {
        var path = Path.Combine(Path.GetTempPath(), "kalitka-audit-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            await new SqliteAuditStore(path).Append(Ev(AuditEvents.AccessApproved, "google:x", "web:a", 5000), default);
            // A fresh instance (as after a restart) still sees it — that is the point.
            var reopened = await new SqliteAuditStore(path).Query(new AuditQuery(), default);
            Assert.Single(reopened);
        }
        finally { foreach (var f in Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + "*")) try { File.Delete(f); } catch { } }
    }
}
