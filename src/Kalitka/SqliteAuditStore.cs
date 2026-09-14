using System.Text;
using Microsoft.Data.Sqlite;

namespace Kalitka;

/// <summary>
/// Durable audit in a single SQLite file — the self-hosted / single-node choice. Append-only, and
/// now <b>tamper-evident</b>: every event carries a sequence number and the hash of the one before
/// it (see <see cref="AuditHash"/>), so the history is a chain a customer can verify. The chain's
/// read-head-then-insert is serialized by SQLite's single writer (the async path opens an IMMEDIATE
/// transaction; the atomic path already holds the write lock from its state write), so there are no
/// gaps or forks.
/// </summary>
public sealed class SqliteAuditStore : IAuditStore
{
    private readonly string _cs;

    public SqliteAuditStore(string path)
    {
        _cs = new SqliteConnectionStringBuilder { DataSource = path }.ToString();

        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS audit(
              id TEXT PRIMARY KEY, ts INTEGER NOT NULL, event_type TEXT NOT NULL,
              actor TEXT, subject TEXT, resource TEXT, request_id TEXT,
              grant_id TEXT, channel TEXT, metadata TEXT);
            CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
            """;
        cmd.ExecuteNonQuery();

        // Tamper-evidence columns, added idempotently to an existing table.
        foreach (var (col, def) in new[] { ("seq", "INTEGER NOT NULL DEFAULT 0"), ("prev_hash", "TEXT NOT NULL DEFAULT ''"), ("hash", "TEXT NOT NULL DEFAULT ''") })
            if (!ColumnExists(conn, col))
            {
                using var alter = conn.CreateCommand();
                alter.CommandText = $"ALTER TABLE audit ADD COLUMN {col} {def};";
                alter.ExecuteNonQuery();
            }
        using var seqIx = conn.CreateCommand();
        seqIx.CommandText = "CREATE INDEX IF NOT EXISTS ix_audit_seq ON audit(seq);";
        seqIx.ExecuteNonQuery();

        Backfill(conn);
    }

    private static bool ColumnExists(SqliteConnection conn, string col)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name=$n;";
        cmd.Parameters.AddWithValue("$n", col);
        return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
    }

    // Establish the chain over any pre-existing rows (a DB that predates tamper-evidence), in
    // (ts, id) order. This does not retroactively prove old integrity — we compute it now — but it
    // sets a verifiable baseline, so any tampering from here on breaks the chain.
    private static void Backfill(SqliteConnection conn)
    {
        using (var check = conn.CreateCommand())
        {
            check.CommandText = "SELECT COUNT(*) FROM audit WHERE hash='';";
            if (Convert.ToInt64(check.ExecuteScalar()) == 0) return;   // already chained
        }

        using var tx = conn.BeginTransaction(deferred: false);
        var rows = new List<AuditEvent>();
        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = "SELECT id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata FROM audit ORDER BY ts ASC, id ASC;";
            using var r = sel.ExecuteReader();
            while (r.Read()) rows.Add(Read(r));
        }
        long seq = 0; var head = AuditHash.Genesis;
        foreach (var e in rows)
        {
            var linked = AuditHash.Link(e, seq, head);
            seq = linked.Seq; head = linked.Hash;
            using var upd = conn.CreateCommand();
            upd.Transaction = tx;
            upd.CommandText = "UPDATE audit SET seq=$seq, prev_hash=$prev, hash=$hash WHERE id=$id;";
            upd.Parameters.AddWithValue("$seq", linked.Seq);
            upd.Parameters.AddWithValue("$prev", linked.PrevHash);
            upd.Parameters.AddWithValue("$hash", linked.Hash);
            upd.Parameters.AddWithValue("$id", linked.Id);
            upd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_cs);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    private const string InsertSql = """
        INSERT INTO audit(id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata,seq,prev_hash,hash)
        VALUES($id,$ts,$et,$actor,$subject,$resource,$req,$grant,$channel,$meta,$seq,$prev,$hash);
        """;

    private static void Bind(SqliteCommand cmd, AuditEvent e)
    {
        cmd.Parameters.AddWithValue("$id", e.Id);
        cmd.Parameters.AddWithValue("$ts", e.Timestamp.ToUnixTimeSeconds());
        cmd.Parameters.AddWithValue("$et", e.EventType);
        cmd.Parameters.AddWithValue("$actor", e.Actor);
        cmd.Parameters.AddWithValue("$subject", e.Subject);
        cmd.Parameters.AddWithValue("$resource", e.Resource);
        cmd.Parameters.AddWithValue("$req", e.RequestId);
        cmd.Parameters.AddWithValue("$grant", e.GrantId);
        cmd.Parameters.AddWithValue("$channel", e.Channel);
        cmd.Parameters.AddWithValue("$meta", e.Metadata);
        cmd.Parameters.AddWithValue("$seq", e.Seq);
        cmd.Parameters.AddWithValue("$prev", e.PrevHash);
        cmd.Parameters.AddWithValue("$hash", e.Hash);
    }

    // (seq, hash) of the last event, or (0, genesis) when empty. Read under the caller's write lock.
    private static (long Seq, string Hash) Head(SqliteConnection conn, SqliteTransaction? tx)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1;";
        using var r = cmd.ExecuteReader();
        return r.Read() ? (r.GetInt64(0), r.GetString(1)) : (0L, AuditHash.Genesis);
    }

    public async Task Append(AuditEvent e, CancellationToken ct)
    {
        await using var conn = Open();
        // IMMEDIATE: take the write lock before reading the head, so two appends can't chain off the
        // same stale head (SQLite is single-writer, so this serializes with the atomic path too).
        await using var tx = conn.BeginTransaction(deferred: false);
        var head = Head(conn, tx);
        var linked = AuditHash.Link(e, head.Seq, head.Hash);
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
        Bind(cmd, linked);
        await cmd.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
    }

    // The append inside a caller's transaction (IAtomicWork): the head is read under the write lock
    // the caller's state write already holds, so the chain stays gap-free across both paths.
    internal static void AppendCore(SqliteConnection conn, SqliteTransaction tx, AuditEvent e)
    {
        var head = Head(conn, tx);
        var linked = AuditHash.Link(e, head.Seq, head.Hash);
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
        Bind(cmd, linked);
        cmd.ExecuteNonQuery();
    }

    public async Task<AuditVerification> VerifyChain(CancellationToken ct)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata,seq,prev_hash,hash FROM audit ORDER BY seq ASC;";
        var list = new List<AuditEvent>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadFull(r));
        return AuditChain.Verify(list);
    }

    public async Task<IReadOnlyList<AuditEvent>> Query(AuditQuery q, CancellationToken ct)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();

        var sql = new StringBuilder(
            "SELECT id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata,seq,prev_hash,hash FROM audit WHERE 1=1");

        if (!string.IsNullOrEmpty(q.Actor)) { sql.Append(" AND actor LIKE $actor"); cmd.Parameters.AddWithValue("$actor", "%" + q.Actor + "%"); }
        if (!string.IsNullOrEmpty(q.Resource)) { sql.Append(" AND resource LIKE $resource"); cmd.Parameters.AddWithValue("$resource", "%" + q.Resource + "%"); }
        if (!string.IsNullOrEmpty(q.EventType)) { sql.Append(" AND event_type = $et"); cmd.Parameters.AddWithValue("$et", q.EventType); }
        if (q.Since is { } s) { sql.Append(" AND ts >= $since"); cmd.Parameters.AddWithValue("$since", s.ToUnixTimeSeconds()); }
        if (q.Until is { } u) { sql.Append(" AND ts <= $until"); cmd.Parameters.AddWithValue("$until", u.ToUnixTimeSeconds()); }

        sql.Append(" ORDER BY ts DESC, id DESC LIMIT $limit OFFSET $offset");
        cmd.Parameters.AddWithValue("$limit", Math.Clamp(q.Limit, 1, 500));
        cmd.Parameters.AddWithValue("$offset", Math.Max(0, q.Offset));
        cmd.CommandText = sql.ToString();

        var list = new List<AuditEvent>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadFull(r));
        return list;
    }

    private static AuditEvent Read(SqliteDataReader r) => new(
        r.GetString(0), DateTimeOffset.FromUnixTimeSeconds(r.GetInt64(1)), r.GetString(2),
        r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7), r.GetString(8), r.GetString(9));

    private static AuditEvent ReadFull(SqliteDataReader r) => Read(r) with
    {
        Seq = r.GetInt64(10), PrevHash = r.GetString(11), Hash = r.GetString(12),
    };
}
