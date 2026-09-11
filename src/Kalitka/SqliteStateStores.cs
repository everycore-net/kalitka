using System.Text.Json;
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

    private const string InsertSql =
        "INSERT INTO replay(jti,expires) VALUES($j,$e) ON CONFLICT(jti) DO NOTHING;";

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
        cmd.CommandText = InsertSql;
        cmd.Parameters.AddWithValue("$j", jti);
        cmd.Parameters.AddWithValue("$e", expiresAt.ToUnixTimeSeconds());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;   // 1 = first use, 0 = replay
    }

    // The consume as it runs inside a caller's transaction (see IAtomicWork), so a
    // grant's single use commits with the session it starts. No pruning here — that
    // is housekeeping for the standalone path, not part of a redeem's transaction.
    internal static bool ConsumeCore(SqliteConnection conn, SqliteTransaction? tx, string jti, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(jti)) return false;
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
        cmd.Parameters.AddWithValue("$j", jti);
        cmd.Parameters.AddWithValue("$e", expiresAt.ToUnixTimeSeconds());
        return cmd.ExecuteNonQuery() == 1;
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

    private const string InsertSql = """
        INSERT INTO sessions(session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata)
        VALUES($sid,$grant,$req,$subject,$resource,$agent,$started,$ended,$outcome,$meta)
        ON CONFLICT(session_id) DO UPDATE SET
          grant_id=$grant,request_id=$req,subject=$subject,resource=$resource,agent_id=$agent,
          started=$started,ended=$ended,outcome=$outcome,metadata=$meta;
        """;

    private const string CloseSql =
        "UPDATE sessions SET ended=$at, outcome=$o WHERE session_id=$id AND ended IS NULL;";

    public void Start(SessionRecord s)
    {
        using var conn = SqliteState.Open(_cs);
        StartCore(conn, null, s);
    }

    // Start as it runs inside a caller's transaction (see IAtomicWork).
    internal static void StartCore(SqliteConnection conn, SqliteTransaction? tx, SessionRecord s)
    {
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
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
        return EndCore(conn, null, sessionId, outcome, at);
    }

    // Close-if-open as it runs inside a caller's transaction (see IAtomicWork): a
    // guarded UPDATE, so a repeat close matches no row and returns false — harmless,
    // not a second successful transition.
    internal static bool EndCore(SqliteConnection conn, SqliteTransaction? tx,
        string sessionId, string outcome, DateTimeOffset at)
    {
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = CloseSql;
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

/// <summary>
/// Durable config (lists / enforced / settings) in SQLite — one <c>config(key,value)</c>
/// row per blob. <see cref="Mutate"/> runs in an IMMEDIATE transaction so the
/// read-modify-write is serialised against other writers on the file: no lost list
/// edits when two processes on the host change a list at once.
/// </summary>
public sealed class SqliteConfigStore : IConfigStore
{
    private readonly string _cs;

    public SqliteConfigStore(string path)
    {
        _cs = SqliteState.ConnectionString(path);
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    public string? Get(string key)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM config WHERE key=$k;";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void Mutate(string key, Func<string?, string> update)
    {
        using var conn = SqliteState.Open(_cs);
        using var tx = conn.BeginTransaction(deferred: false);   // IMMEDIATE: take the write lock up front
        string? cur;
        using (var read = conn.CreateCommand())
        {
            read.Transaction = tx;
            read.CommandText = "SELECT value FROM config WHERE key=$k;";
            read.Parameters.AddWithValue("$k", key);
            cur = read.ExecuteScalar() as string;
        }
        var next = update(cur);
        using (var up = conn.CreateCommand())
        {
            up.Transaction = tx;
            up.CommandText = "INSERT INTO config(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=$v;";
            up.Parameters.AddWithValue("$k", key);
            up.Parameters.AddWithValue("$v", next);
            up.ExecuteNonQuery();
        }
        tx.Commit();
    }
}

/// <summary>Durable agent registry in SQLite (see <see cref="IAgentStore"/>).</summary>
public sealed class SqliteAgentStore : IAgentStore
{
    private readonly string _cs;

    public SqliteAgentStore(string path)
    {
        _cs = SqliteState.ConnectionString(path);
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS agents(
              id TEXT PRIMARY KEY, display_name TEXT NOT NULL, platform TEXT NOT NULL,
              hostname TEXT NOT NULL, status TEXT NOT NULL, secret_hash TEXT NOT NULL,
              capabilities TEXT NOT NULL, allowed_resources TEXT NOT NULL, metadata TEXT NOT NULL,
              created_at INTEGER NOT NULL, last_seen_at INTEGER, last_ip TEXT NOT NULL DEFAULT '',
              revoked_at INTEGER, tags TEXT NOT NULL DEFAULT '[]');
            """;
        cmd.ExecuteNonQuery();
    }

    public Agent? GetById(string id)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM agents WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public void Create(Agent a)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO agents(id,display_name,platform,hostname,status,secret_hash,capabilities,allowed_resources,metadata,created_at,last_seen_at,last_ip,revoked_at,tags)
            VALUES($id,$dn,$pf,$hn,$st,$sh,$cap,$res,$md,$ca,$ls,$ip,$rv,$tags)
            ON CONFLICT(id) DO UPDATE SET
              display_name=$dn,platform=$pf,hostname=$hn,status=$st,secret_hash=$sh,
              capabilities=$cap,allowed_resources=$res,metadata=$md,created_at=$ca,
              last_seen_at=$ls,last_ip=$ip,revoked_at=$rv,tags=$tags;
            """;
        cmd.Parameters.AddWithValue("$id", a.Id);
        cmd.Parameters.AddWithValue("$dn", a.DisplayName);
        cmd.Parameters.AddWithValue("$pf", a.Platform);
        cmd.Parameters.AddWithValue("$hn", a.Hostname);
        cmd.Parameters.AddWithValue("$st", a.Status.ToString());
        cmd.Parameters.AddWithValue("$sh", a.SecretHash);
        cmd.Parameters.AddWithValue("$cap", JsonSerializer.Serialize(a.Capabilities));
        cmd.Parameters.AddWithValue("$res", JsonSerializer.Serialize(a.AllowedResources));
        cmd.Parameters.AddWithValue("$md", a.Metadata);
        cmd.Parameters.AddWithValue("$ca", a.CreatedAt.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$ls", (object?)a.LastSeenAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ip", a.LastIp);
        cmd.Parameters.AddWithValue("$rv", (object?)a.RevokedAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(a.Tags));
        cmd.ExecuteNonQuery();
    }

    public bool SetStatus(string id, AgentStatus status, DateTimeOffset at)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agents SET status=$st, revoked_at=CASE WHEN $st='Revoked' THEN $at ELSE revoked_at END WHERE id=$id;";
        cmd.Parameters.AddWithValue("$st", status.ToString());
        cmd.Parameters.AddWithValue("$at", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteNonQuery() == 1;
    }

    public bool RotateSecret(string id, string newHash)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agents SET secret_hash=$sh WHERE id=$id;";
        cmd.Parameters.AddWithValue("$sh", newHash);
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteNonQuery() == 1;
    }

    public void TouchLastSeen(string id, DateTimeOffset at, string ip)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agents SET last_seen_at=$ls, last_ip=$ip WHERE id=$id;";
        cmd.Parameters.AddWithValue("$ls", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$ip", ip);
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<Agent> Snapshot()
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM agents ORDER BY display_name;";
        var list = new List<Agent>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Read(r));
        return list;
    }

    private const string Cols =
        "id,display_name,platform,hostname,status,secret_hash,capabilities,allowed_resources,metadata,created_at,last_seen_at,last_ip,revoked_at,tags";

    private static Agent Read(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3),
        Enum.Parse<AgentStatus>(r.GetString(4)), r.GetString(5),
        JsonSerializer.Deserialize<string[]>(r.GetString(6)) ?? Array.Empty<string>(),
        JsonSerializer.Deserialize<string[]>(r.GetString(7)) ?? Array.Empty<string>(),
        r.GetString(8), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(9)),
        r.IsDBNull(10) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(10)),
        r.GetString(11), r.IsDBNull(12) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(12)))
    {
        Tags = JsonSerializer.Deserialize<string[]>(r.GetString(13)) ?? Array.Empty<string>()
    };
}
