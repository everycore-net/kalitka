using System.Text.Json;
using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The config store behind the block/allow lists, armed hosts and settings. The
/// load-bearing property is that <c>Mutate</c> is an atomic read-modify-write, so
/// concurrent config edits don't lose each other, and that a change made through one
/// instance is visible to another sharing the backend.
/// </summary>
public sealed class ConfigStoreTests : IDisposable
{
    private readonly string _dir;

    public ConfigStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "kalitka-cfg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); Directory.Delete(_dir, true); }
        catch { }
    }

    [Fact]
    public void InMemory_round_trips_and_mutates()
    {
        var s = new InMemoryConfigStore();
        Assert.Null(s.Get("k"));
        s.Mutate("k", cur => (cur ?? "") + "a");
        s.Mutate("k", cur => (cur ?? "") + "b");
        Assert.Equal("ab", s.Get("k"));
    }

    [Fact]
    public void Sqlite_config_is_visible_to_another_instance()
    {
        var db = Path.Combine(_dir, "state.db");
        new SqliteConfigStore(db).Mutate("lists", _ => "[1,2,3]");
        Assert.Equal("[1,2,3]", new SqliteConfigStore(db).Get("lists"));
    }

    [Fact]
    public void Sqlite_concurrent_mutate_loses_nothing()
    {
        var db = Path.Combine(_dir, "state.db");
        new SqliteConfigStore(db);   // create the table
        Parallel.For(0, 20, i =>
        {
            new SqliteConfigStore(db).Mutate("k", cur =>
            {
                var list = string.IsNullOrEmpty(cur) ? new List<int>() : JsonSerializer.Deserialize<List<int>>(cur)!;
                list.Add(i);
                return JsonSerializer.Serialize(list);
            });
        });
        var final = JsonSerializer.Deserialize<List<int>>(new SqliteConfigStore(db).Get("k")!)!;
        Assert.Equal(20, final.Count);          // every append survived → the RMW is atomic
        Assert.Equal(Enumerable.Range(0, 20), final.OrderBy(x => x));
    }

    [Fact]
    public void JsonFile_backend_round_trips_via_the_configured_path()
    {
        var o = Options.Create(new GateOptions
        {
            ListsPath = Path.Combine(_dir, "lists.json"),
            EnforcedPath = Path.Combine(_dir, "enforced.json"),
            SettingsPath = Path.Combine(_dir, "settings.json"),
        });
        var a = new JsonFileConfigStore(o.Value, NullLogger<JsonFileConfigStore>.Instance);
        a.Mutate("enforced", _ => "[\"sage.example.com\"]");
        // A second instance on the same paths reads the same content.
        var b = new JsonFileConfigStore(o.Value, NullLogger<JsonFileConfigStore>.Instance);
        Assert.Equal("[\"sage.example.com\"]", b.Get("enforced"));
        Assert.Equal("[\"sage.example.com\"]", File.ReadAllText(Path.Combine(_dir, "enforced.json")));
    }

    [Fact]
    public void AccessLists_change_propagates_to_another_instance_within_the_ttl()
    {
        var store = new InMemoryConfigStore();   // shared "backend"
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var o = Options.Create(new GateOptions());

        var a = new AccessLists(o, NullLogger<AccessLists>.Instance, store, clock);
        var b = new AccessLists(o, NullLogger<AccessLists>.Instance, store, clock);

        a.Add("block", "web:*", "ip", "1.2.3.4", "now");

        // B still has its cached (empty) view within the TTL.
        Assert.False(b.IsBlocked("web:app", "1.2.3.4", "", ""));

        // Past the TTL, B reloads from the shared store and sees A's entry.
        clock.Advance(TimeSpan.FromSeconds(11));
        Assert.True(b.IsBlocked("web:app", "1.2.3.4", "", ""));
    }
}
