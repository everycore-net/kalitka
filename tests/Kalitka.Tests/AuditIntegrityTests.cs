using Kalitka;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Tamper-evidence for the audit log — the proof a compliance export rests on. The hash chain must
/// build gap-free, catch any in-place edit, chain legacy rows on migration, and a signed checkpoint
/// over the head must round-trip and never be issued over a broken chain.
/// </summary>
public class AuditIntegrityTests
{
    private static AuditEvent Ev(string type, string subject = "s") =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), type,
            "google:admin", subject, "ssh:h", "req", "grant", "web", "meta");

    // ---- in-memory + checkpoint ------------------------------------------------

    [Fact]
    public async Task In_memory_chain_builds_and_a_checkpoint_round_trips()
    {
        var store = new InMemoryAuditStore();
        for (var i = 0; i < 3; i++) await store.Append(Ev("access.approved"), default);

        var v = await store.VerifyChain(default);
        Assert.True(v.Intact);
        Assert.Equal(3, v.Checked);
        Assert.Equal(3, v.HeadSeq);

        var integ = new AuditIntegrity(store, new TokenSigner("unit-test-signing-key-0123456789"),
            new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero)));
        var cp = await integ.SignHead(default);
        Assert.NotNull(cp);
        Assert.Equal(v.HeadHash, cp!.Hash);
        Assert.True(integ.VerifyCheckpoint(cp));
        Assert.False(integ.VerifyCheckpoint(cp with { Hash = "DEADBEEF" }));   // tampered checkpoint
    }

    // ---- sqlite: chain, tamper, backfill --------------------------------------

    private static string TempDb() => Path.Combine(Path.GetTempPath(), "kalitka-audit-" + Guid.NewGuid().ToString("N") + ".db");

    [Fact]
    public async Task Sqlite_chain_builds_across_appends()
    {
        var path = TempDb();
        try
        {
            var store = new SqliteAuditStore(path);
            for (var i = 0; i < 5; i++) await store.Append(Ev("access.approved"), default);
            var v = await store.VerifyChain(default);
            Assert.True(v.Intact);
            Assert.Equal(5, v.Checked);
            Assert.Equal(5, v.HeadSeq);
        }
        finally { SqliteConnection.ClearAllPools(); File.Delete(path); }
    }

    [Fact]
    public async Task Sqlite_detects_an_in_place_edit()
    {
        var path = TempDb();
        try
        {
            var store = new SqliteAuditStore(path);
            for (var i = 0; i < 4; i++) await store.Append(Ev("access.approved"), default);

            // Tamper directly in the database — flip the metadata of the event at seq 2.
            await using (var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
            {
                await conn.OpenAsync();
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = "UPDATE audit SET metadata='forged' WHERE seq=2;";
                await cmd.ExecuteNonQueryAsync();
            }

            var v = await store.VerifyChain(default);
            Assert.False(v.Intact);
            Assert.Equal(2, v.FirstBadSeq);
        }
        finally { SqliteConnection.ClearAllPools(); File.Delete(path); }
    }

    [Fact]
    public async Task Sqlite_backfills_legacy_rows_on_migration()
    {
        var path = TempDb();
        try
        {
            // Simulate a pre-tamper-evidence DB: rows exist with empty hash columns.
            new SqliteAuditStore(path);   // creates the table (with chain columns)
            SqliteConnection.ClearAllPools();
            await using (var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
            {
                await conn.OpenAsync();
                for (var i = 0; i < 3; i++)
                {
                    await using var cmd = conn.CreateCommand();
                    cmd.CommandText = "INSERT INTO audit(id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata,seq,prev_hash,hash) "
                        + "VALUES($id,$ts,'access.approved','a','s','ssh:h','','','web','',0,'','');";
                    cmd.Parameters.AddWithValue("$id", "legacy-" + i);
                    cmd.Parameters.AddWithValue("$ts", 1_700_000_000 + i);
                    await cmd.ExecuteNonQueryAsync();
                }
            }
            SqliteConnection.ClearAllPools();

            // Re-open: the constructor backfills the chain over the legacy rows.
            var store = new SqliteAuditStore(path);
            var v = await store.VerifyChain(default);
            Assert.True(v.Intact);
            Assert.Equal(3, v.Checked);
        }
        finally { SqliteConnection.ClearAllPools(); File.Delete(path); }
    }

    [Fact]
    public async Task A_broken_chain_is_never_signed()
    {
        var path = TempDb();
        try
        {
            var store = new SqliteAuditStore(path);
            await store.Append(Ev("access.approved"), default);
            await using (var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
            {
                await conn.OpenAsync();
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = "UPDATE audit SET actor='forged' WHERE seq=1;";
                await cmd.ExecuteNonQueryAsync();
            }
            var integ = new AuditIntegrity(store, new TokenSigner("k0123456789-0123456789-0123456789"), TimeProvider.System);
            Assert.Null(await integ.SignHead(default));   // never sign over a tampered log
        }
        finally { SqliteConnection.ClearAllPools(); File.Delete(path); }
    }

    // ---- framing --------------------------------------------------------------

    [Fact]
    public void Length_prefixed_framing_resists_field_boundary_collisions()
    {
        // Two events whose (actor, subject) differ only by where a boundary falls must not collide.
        var a = Ev("t") with { Actor = "ab", Subject = "c" };
        var b = Ev("t") with { Actor = "a", Subject = "bc", Id = a.Id, Timestamp = a.Timestamp };
        Assert.NotEqual(AuditHash.Compute(a, ""), AuditHash.Compute(b, ""));
    }
}
