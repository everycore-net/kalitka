using System.Text;
using Microsoft.Data.Sqlite;

namespace Kalitka;

/// <summary>
/// Durable audit in a single SQLite file — the self-hosted / single-node choice.
/// Append-only: one INSERT per event, no updates or deletes. Queries are
/// parameterised and paged. Nothing fancier on purpose (no ORM, no migrations
/// framework); when a shared multi-instance store is needed, it is another
/// <see cref="IAuditStore"/>.
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

    public async Task Append(AuditEvent e, CancellationToken ct)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO audit(id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata)
            VALUES($id,$ts,$et,$actor,$subject,$resource,$req,$grant,$channel,$meta);
            """;
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
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<AuditEvent>> Query(AuditQuery q, CancellationToken ct)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();

        var sql = new StringBuilder(
            "SELECT id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata FROM audit WHERE 1=1");

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
        while (await r.ReadAsync(ct))
            list.Add(new AuditEvent(
                r.GetString(0), DateTimeOffset.FromUnixTimeSeconds(r.GetInt64(1)), r.GetString(2),
                r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7), r.GetString(8), r.GetString(9)));
        return list;
    }
}
