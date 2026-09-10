using Microsoft.Data.Sqlite;

namespace Kalitka;

/// <summary>
/// Shared plumbing for the durable state stores. One SQLite file holds three
/// tables — <c>requests</c>, <c>replay</c>, <c>sessions</c> — each owned by one
/// store below. WAL so a reader never blocks the single writer; that is what lets
/// several processes on the same host share one file. Nothing here is
/// SQLite-specific in spirit: every atomic transition is a single conditional
/// statement, so a Postgres backend is the same SQL against another connection.
/// </summary>
internal static class SqliteState
{
    public static SqliteConnection Open(string cs)
    {
        var conn = new SqliteConnection(cs);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    public static string ConnectionString(string path) =>
        new SqliteConnectionStringBuilder { DataSource = path }.ToString();
}

/// <summary>
/// Durable pending requests. The load-bearing methods are the two atomic ones:
/// <see cref="TryResolve"/> (waiting → terminal, once) and <see cref="TrySetGrant"/>
/// (attach the grant, once). Both are a single guarded <c>UPDATE</c> whose row
/// count says whether this caller won — so a decision racing across instances is
/// resolved by the database, exactly as the in-memory version is resolved by a
/// lock.
/// </summary>
public sealed class SqliteRequestStore : IRequestStore
{
    private readonly string _cs;

    public SqliteRequestStore(string path)
    {
        _cs = SqliteState.ConnectionString(path);
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS requests(
              id TEXT PRIMARY KEY, target TEXT NOT NULL, input TEXT NOT NULL,
              ip TEXT NOT NULL, resource TEXT NOT NULL, country TEXT, country_code TEXT,
              city TEXT, raised INTEGER NOT NULL, state TEXT NOT NULL, grant_tok TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS ix_requests_state ON requests(state, raised);
            """;
        cmd.ExecuteNonQuery();
    }

    public void Add(PendingRequest r)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO requests(id,target,input,ip,resource,country,country_code,city,raised,state,grant_tok)
            VALUES($id,$target,$input,$ip,$resource,$country,$cc,$city,$raised,$state,$grant)
            ON CONFLICT(id) DO UPDATE SET
              target=$target,input=$input,ip=$ip,resource=$resource,country=$country,
              country_code=$cc,city=$city,raised=$raised,state=$state,grant_tok=$grant;
            """;
        Bind(cmd, r);
        cmd.ExecuteNonQuery();
    }

    public PendingRequest? Get(string id)
    {
        using var conn = SqliteState.Open(_cs);
        return GetCore(conn, null, id);
    }

    // Bound to a caller's connection/transaction so a unit of work (IAtomicWork)
    // can read a request inside the same transaction as its state change.
    internal static PendingRequest? GetCore(SqliteConnection conn, SqliteTransaction? tx, string id)
    {
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = $"SELECT {Cols} FROM requests WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public void Remove(string id)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM requests WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<PendingRequest> Snapshot()
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM requests ORDER BY raised DESC;";
        var list = new List<PendingRequest>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Read(r));
        return list;
    }

    public int CountWaiting(DateTimeOffset since)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM requests WHERE state='waiting' AND raised>=$since;";
        cmd.Parameters.AddWithValue("$since", since.ToUnixTimeMilliseconds());
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    public void DropOlderThan(DateTimeOffset cutoff)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM requests WHERE raised<$cutoff;";
        cmd.Parameters.AddWithValue("$cutoff", cutoff.ToUnixTimeMilliseconds());
        cmd.ExecuteNonQuery();
    }

    public bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
    {
        using var conn = SqliteState.Open(_cs);
        return ResolveCore(conn, null, id, toState, notOlderThan, out request);
    }

    // The resolve as it runs inside a caller's transaction (null tx = its own
    // connection, the standalone path). Same guarantee either way: one conditional
    // UPDATE, only the row still waiting and still fresh moves, only one writer wins.
    internal static bool ResolveCore(SqliteConnection conn, SqliteTransaction? tx,
        string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
    {
        request = null;
        using (var cmd = conn.CreateCommand())
        {
            if (tx is not null) cmd.Transaction = tx;
            cmd.CommandText = "UPDATE requests SET state=$to WHERE id=$id AND state='waiting' AND raised>=$fresh;";
            cmd.Parameters.AddWithValue("$to", toState);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$fresh", notOlderThan.ToUnixTimeMilliseconds());
            if (cmd.ExecuteNonQuery() != 1) return false;   // gone, already resolved, or too old
        }
        request = GetCore(conn, tx, id);
        return request is not null;
    }

    public bool TrySetGrant(string id, string candidate, out string grant)
    {
        grant = "";
        using var conn = SqliteState.Open(_cs);
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "UPDATE requests SET grant_tok=$g WHERE id=$id AND grant_tok='';";
            cmd.Parameters.AddWithValue("$g", candidate);
            cmd.Parameters.AddWithValue("$id", id);
            if (cmd.ExecuteNonQuery() == 1) { grant = candidate; return true; }
        }
        // We did not set it: either no such request, or another caller already did.
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT grant_tok FROM requests WHERE id=$id;";
            read.Parameters.AddWithValue("$id", id);
            grant = read.ExecuteScalar() as string ?? "";
        }
        return false;
    }

    private const string Cols =
        "id,target,input,ip,resource,country,country_code,city,raised,state,grant_tok";

    private static void Bind(SqliteCommand cmd, PendingRequest r)
    {
        cmd.Parameters.AddWithValue("$id", r.Id);
        cmd.Parameters.AddWithValue("$target", r.Target);
        cmd.Parameters.AddWithValue("$input", r.Input);
        cmd.Parameters.AddWithValue("$ip", r.Ip);
        cmd.Parameters.AddWithValue("$resource", r.Resource);
        cmd.Parameters.AddWithValue("$country", r.Country);
        cmd.Parameters.AddWithValue("$cc", r.CountryCode);
        cmd.Parameters.AddWithValue("$city", r.City);
        cmd.Parameters.AddWithValue("$raised", r.Raised.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$state", r.State);
        cmd.Parameters.AddWithValue("$grant", r.Grant);
    }

    private static PendingRequest Read(SqliteDataReader r) => new()
    {
        Id = r.GetString(0), Target = r.GetString(1), Input = r.GetString(2), Ip = r.GetString(3),
        Resource = r.GetString(4), Country = r.GetString(5), CountryCode = r.GetString(6),
        City = r.GetString(7), Raised = DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(8)),
        State = r.GetString(9), Grant = r.GetString(10)
    };
}

/// <summary>
/// Durable single-use: a consumed <c>jti</c> is a primary key, so the first insert
/// wins and every replay hits the conflict. <c>ON CONFLICT DO NOTHING</c> makes
/// that a rows-affected check, no exception in the hot path. Expired rows are
/// pruned opportunistically — past its expiry a token fails signature anyway.
/// </summary>
public sealed class SqliteReplayStore : IReplayStore
{
    private readonly string _cs;
    private readonly TimeProvider _clock;

    public SqliteReplayStore(string path, TimeProvider? clock = null)
    {
        _cs = SqliteState.ConnectionString(path);
        _clock = clock ?? TimeProvider.System;
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS replay(jti TEXT PRIMARY KEY, expires INTEGER NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    public async Task<bool> TryConsumeAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(jti)) return false;

        await using var conn = SqliteState.Open(_cs);
        await using (var prune = conn.CreateCommand())
        {
            prune.CommandText = "DELETE FROM replay WHERE expires<$now;";
            prune.Parameters.AddWithValue("$now", _clock.GetUtcNow().ToUnixTimeSeconds());
            await prune.ExecuteNonQueryAsync(ct);
        }

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO replay(jti,expires) VALUES($j,$e) ON CONFLICT(jti) DO NOTHING;";
        cmd.Parameters.AddWithValue("$j", jti);
        cmd.Parameters.AddWithValue("$e", expiresAt.ToUnixTimeSeconds());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;   // 1 = first use, 0 = replay
    }
}

/// <summary>
/// Durable sessions. <see cref="End"/> is the atomic one — a guarded <c>UPDATE</c>
/// that only closes a still-open session — so a session ends exactly once even if
/// two logout hooks report it. Start and the reads are plain SQL.
/// </summary>
public sealed class SqliteSessionStore : ISessionStore
{
    private readonly string _cs;

    public SqliteSessionStore(string path)
    {
        _cs = SqliteState.ConnectionString(path);
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS sessions(
              session_id TEXT PRIMARY KEY, grant_id TEXT, request_id TEXT, subject TEXT,
              resource TEXT, agent_id TEXT, started INTEGER NOT NULL, ended INTEGER,
              outcome TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '');
            """;
        cmd.ExecuteNonQuery();
    }

    public void Start(SessionRecord s)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO sessions(session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata)
            VALUES($sid,$grant,$req,$subject,$resource,$agent,$started,$ended,$outcome,$meta)
            ON CONFLICT(session_id) DO UPDATE SET
              grant_id=$grant,request_id=$req,subject=$subject,resource=$resource,agent_id=$agent,
              started=$started,ended=$ended,outcome=$outcome,metadata=$meta;
            """;
        cmd.Parameters.AddWithValue("$sid", s.SessionId);
        cmd.Parameters.AddWithValue("$grant", s.GrantId);
        cmd.Parameters.AddWithValue("$req", s.RequestId);
        cmd.Parameters.AddWithValue("$subject", s.Subject);
        cmd.Parameters.AddWithValue("$resource", s.Resource);
        cmd.Parameters.AddWithValue("$agent", s.AgentId);
        cmd.Parameters.AddWithValue("$started", s.StartedAt.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$ended", (object?)s.EndedAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$outcome", s.Outcome);
        cmd.Parameters.AddWithValue("$meta", s.Metadata);
        cmd.ExecuteNonQuery();
    }

    public bool End(string sessionId, string outcome, DateTimeOffset at)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE sessions SET ended=$at, outcome=$o WHERE session_id=$id AND ended IS NULL;";
        cmd.Parameters.AddWithValue("$at", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$o", outcome);
        cmd.Parameters.AddWithValue("$id", sessionId);
        return cmd.ExecuteNonQuery() == 1;   // 1 = we closed it, 0 = unknown or already closed
    }

    public SessionRecord? Get(string sessionId)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM sessions WHERE session_id=$id;";
        cmd.Parameters.AddWithValue("$id", sessionId);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public IReadOnlyList<SessionRecord> Snapshot()
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM sessions ORDER BY started DESC;";
        var list = new List<SessionRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Read(r));
        return list;
    }

    private const string Cols =
        "session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata";

    private static SessionRecord Read(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5),
        DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)),
        r.IsDBNull(7) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(7)),
        r.GetString(8), r.GetString(9));
}
