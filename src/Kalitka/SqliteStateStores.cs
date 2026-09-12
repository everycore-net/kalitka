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
              city TEXT, raised INTEGER NOT NULL, state TEXT NOT NULL, grant_tok TEXT NOT NULL DEFAULT '',
              required_approvals INTEGER NOT NULL DEFAULT 1,
              profile TEXT NOT NULL DEFAULT '', max_uses INTEGER NOT NULL DEFAULT 0,
              command TEXT NOT NULL DEFAULT '', source_addr TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS ix_requests_state ON requests(state, raised);
            -- Distinct approvers per request (quorum): (request_id, principal) is unique,
            -- so an approval is idempotent and the count is a simple COUNT.
            CREATE TABLE IF NOT EXISTS request_approvals(
              request_id TEXT NOT NULL, principal TEXT NOT NULL,
              PRIMARY KEY(request_id, principal));
            """;
        cmd.ExecuteNonQuery();

        // Columns added after requests first shipped (required_approvals 0.19.3,
        // profile/max_uses 0.23) — add idempotently so an older DB does not break on SELECT.
        foreach (var (col, def) in new[] { ("required_approvals", "INTEGER NOT NULL DEFAULT 1"), ("profile", "TEXT NOT NULL DEFAULT ''"), ("max_uses", "INTEGER NOT NULL DEFAULT 0"), ("command", "TEXT NOT NULL DEFAULT ''"), ("source_addr", "TEXT NOT NULL DEFAULT ''") })
        {
            using var check = conn.CreateCommand();
            check.CommandText = "SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name=$n;";
            check.Parameters.AddWithValue("$n", col);
            if (Convert.ToInt64(check.ExecuteScalar()) > 0) continue;
            using var alter = conn.CreateCommand();
            alter.CommandText = $"ALTER TABLE requests ADD COLUMN {col} {def};";
            alter.ExecuteNonQuery();
        }
    }

    public void Add(PendingRequest r)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO requests(id,target,input,ip,resource,country,country_code,city,raised,state,grant_tok,required_approvals,profile,max_uses,command,source_addr)
            VALUES($id,$target,$input,$ip,$resource,$country,$cc,$city,$raised,$state,$grant,$req,$profile,$uses,$command,$srcaddr)
            ON CONFLICT(id) DO UPDATE SET
              target=$target,input=$input,ip=$ip,resource=$resource,country=$country,
              country_code=$cc,city=$city,raised=$raised,state=$state,grant_tok=$grant,required_approvals=$req,
              profile=$profile,max_uses=$uses,command=$command,source_addr=$srcaddr;
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
        cmd.CommandText = "DELETE FROM requests WHERE id=$id; DELETE FROM request_approvals WHERE request_id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public int AddApprovalAndCount(string id, string principal)
    {
        using var conn = SqliteState.Open(_cs);
        using (var ins = conn.CreateCommand())
        {
            ins.CommandText = "INSERT INTO request_approvals(request_id,principal) VALUES($id,$p) ON CONFLICT DO NOTHING;";
            ins.Parameters.AddWithValue("$id", id);
            ins.Parameters.AddWithValue("$p", principal);
            ins.ExecuteNonQuery();
        }
        return CountApprovals(conn, id);
    }

    public int ApprovalCount(string id)
    {
        using var conn = SqliteState.Open(_cs);
        return CountApprovals(conn, id);
    }

    private static int CountApprovals(SqliteConnection conn, string id)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM request_approvals WHERE request_id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        return Convert.ToInt32(cmd.ExecuteScalar());
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
        cmd.CommandText = """
            DELETE FROM request_approvals WHERE request_id IN (SELECT id FROM requests WHERE raised<$cutoff);
            DELETE FROM requests WHERE raised<$cutoff;
            """;
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
        "id,target,input,ip,resource,country,country_code,city,raised,state,grant_tok,required_approvals,profile,max_uses,command,source_addr";

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
        cmd.Parameters.AddWithValue("$req", r.RequiredApprovals);
        cmd.Parameters.AddWithValue("$profile", r.Profile);
        cmd.Parameters.AddWithValue("$uses", r.MaxUses);
        cmd.Parameters.AddWithValue("$command", r.Command);
        cmd.Parameters.AddWithValue("$srcaddr", r.SourceAddr);
    }

    private static PendingRequest Read(SqliteDataReader r) => new()
    {
        Id = r.GetString(0), Target = r.GetString(1), Input = r.GetString(2), Ip = r.GetString(3),
        Resource = r.GetString(4), Country = r.GetString(5), CountryCode = r.GetString(6),
        City = r.GetString(7), Raised = DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(8)),
        State = r.GetString(9), Grant = r.GetString(10), RequiredApprovals = r.GetInt32(11),
        Profile = r.GetString(12), MaxUses = r.GetInt32(13), Command = r.GetString(14), SourceAddr = r.GetString(15)
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
              outcome TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '',
              profile TEXT NOT NULL DEFAULT '', remaining_uses INTEGER NOT NULL DEFAULT -1,
              expires_at INTEGER);
            """;
        cmd.ExecuteNonQuery();

        // Bounded-grant columns added in 0.23; add idempotently for upgrades.
        foreach (var (col, def) in new[] { ("profile", "TEXT NOT NULL DEFAULT ''"), ("remaining_uses", "INTEGER NOT NULL DEFAULT -1"), ("expires_at", "INTEGER") })
        {
            using var chk = conn.CreateCommand();
            chk.CommandText = "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name=$n;";
            chk.Parameters.AddWithValue("$n", col);
            if (Convert.ToInt64(chk.ExecuteScalar()) > 0) continue;
            using var alt = conn.CreateCommand();
            alt.CommandText = $"ALTER TABLE sessions ADD COLUMN {col} {def};";
            alt.ExecuteNonQuery();
        }
    }

    private const string InsertSql = """
        INSERT INTO sessions(session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata,profile,remaining_uses,expires_at)
        VALUES($sid,$grant,$req,$subject,$resource,$agent,$started,$ended,$outcome,$meta,$profile,$uses,$exp)
        ON CONFLICT(session_id) DO UPDATE SET
          grant_id=$grant,request_id=$req,subject=$subject,resource=$resource,agent_id=$agent,
          started=$started,ended=$ended,outcome=$outcome,metadata=$meta,profile=$profile,remaining_uses=$uses,expires_at=$exp;
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
        cmd.Parameters.AddWithValue("$profile", s.Profile);
        cmd.Parameters.AddWithValue("$uses", s.RemainingUses);
        cmd.Parameters.AddWithValue("$exp", (object?)s.ExpiresAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
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

    public int? TrySpendUse(string sessionId)
    {
        using var conn = SqliteState.Open(_cs);
        // One guarded UPDATE: only an open session with uses left decrements, so a
        // concurrent spend cannot take the count below zero or spend a closed session.
        using (var upd = conn.CreateCommand())
        {
            upd.CommandText = "UPDATE sessions SET remaining_uses=remaining_uses-1 WHERE session_id=$id AND ended IS NULL AND remaining_uses>0;";
            upd.Parameters.AddWithValue("$id", sessionId);
            if (upd.ExecuteNonQuery() == 1)
            {
                using var read = conn.CreateCommand();
                read.CommandText = "SELECT remaining_uses FROM sessions WHERE session_id=$id;";
                read.Parameters.AddWithValue("$id", sessionId);
                return Convert.ToInt32(read.ExecuteScalar());
            }
        }
        // Nothing decremented: unlimited (-1) on an open session, else not spendable.
        using var q = conn.CreateCommand();
        q.CommandText = "SELECT remaining_uses FROM sessions WHERE session_id=$id AND ended IS NULL;";
        q.Parameters.AddWithValue("$id", sessionId);
        var v = q.ExecuteScalar();
        return v is not null && Convert.ToInt32(v) < 0 ? -1 : null;
    }

    private const string Cols =
        "session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata,profile,remaining_uses,expires_at";

    private static SessionRecord Read(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5),
        DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)),
        r.IsDBNull(7) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(7)),
        r.GetString(8), r.GetString(9))
    {
        Profile = r.GetString(10),
        RemainingUses = r.GetInt32(11),
        ExpiresAt = r.IsDBNull(12) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(12)),
    };
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
              revoked_at INTEGER, tags TEXT NOT NULL DEFAULT '[]',
              provenance TEXT NOT NULL DEFAULT '{}', keys TEXT NOT NULL DEFAULT '[]',
              last_auth_method TEXT NOT NULL DEFAULT '', last_key_id TEXT NOT NULL DEFAULT '',
              last_signed_at INTEGER);
            """;
        cmd.ExecuteNonQuery();

        // Columns added after the table first shipped (tags 0.16, provenance 0.17,
        // keys 0.20, auth observability 0.21.2). CREATE TABLE IF NOT EXISTS never adds
        // columns to a pre-existing table, so an older agents table would otherwise make
        // every SELECT throw "no such column". Add them idempotently.
        EnsureColumn(conn, "tags", "TEXT NOT NULL DEFAULT '[]'");
        EnsureColumn(conn, "provenance", "TEXT NOT NULL DEFAULT '{}'");
        EnsureColumn(conn, "keys", "TEXT NOT NULL DEFAULT '[]'");
        EnsureColumn(conn, "last_auth_method", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn(conn, "last_key_id", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn(conn, "last_signed_at", "INTEGER");
    }

    private static void EnsureColumn(Microsoft.Data.Sqlite.SqliteConnection conn, string column, string definition)
    {
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM pragma_table_info('agents') WHERE name=$n;";
        check.Parameters.AddWithValue("$n", column);
        if (Convert.ToInt64(check.ExecuteScalar()) > 0) return;

        using var alter = conn.CreateCommand();
        alter.CommandText = $"ALTER TABLE agents ADD COLUMN {column} {definition};";
        alter.ExecuteNonQuery();
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
            INSERT INTO agents(id,display_name,platform,hostname,status,secret_hash,capabilities,allowed_resources,metadata,created_at,last_seen_at,last_ip,revoked_at,tags,provenance,keys,last_auth_method,last_key_id,last_signed_at)
            VALUES($id,$dn,$pf,$hn,$st,$sh,$cap,$res,$md,$ca,$ls,$ip,$rv,$tags,$prov,$keys,$lam,$lki,$lsa)
            ON CONFLICT(id) DO UPDATE SET
              display_name=$dn,platform=$pf,hostname=$hn,status=$st,secret_hash=$sh,
              capabilities=$cap,allowed_resources=$res,metadata=$md,created_at=$ca,
              last_seen_at=$ls,last_ip=$ip,revoked_at=$rv,tags=$tags,provenance=$prov,keys=$keys,
              last_auth_method=$lam,last_key_id=$lki,last_signed_at=$lsa;
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
        cmd.Parameters.AddWithValue("$prov", JsonSerializer.Serialize(new AgentProvenance(a.ProfileId, a.ProfileHostname, a.AppliedProfileRevision)));
        cmd.Parameters.AddWithValue("$keys", JsonSerializer.Serialize(a.Keys));
        cmd.Parameters.AddWithValue("$lam", a.LastAuthMethod);
        cmd.Parameters.AddWithValue("$lki", a.LastKeyId);
        cmd.Parameters.AddWithValue("$lsa", (object?)a.LastSignedAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
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

    public void RecordAuth(string id, DateTimeOffset at, string ip, string method, string keyId)
    {
        using var conn = SqliteState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE agents SET last_seen_at=$ls, last_ip=$ip, last_auth_method=$m, last_key_id=$k,
              last_signed_at=CASE WHEN $m='signature' THEN $ls ELSE last_signed_at END
            WHERE id=$id;
            """;
        cmd.Parameters.AddWithValue("$ls", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$ip", ip);
        cmd.Parameters.AddWithValue("$m", method);
        cmd.Parameters.AddWithValue("$k", keyId);
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
        "id,display_name,platform,hostname,status,secret_hash,capabilities,allowed_resources,metadata,created_at,last_seen_at,last_ip,revoked_at,tags,provenance,keys,last_auth_method,last_key_id,last_signed_at";

    private static Agent Read(SqliteDataReader r)
    {
        var prov = JsonSerializer.Deserialize<AgentProvenance>(r.GetString(14)) ?? new("", "", 0);
        return new Agent(
            r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3),
            Enum.Parse<AgentStatus>(r.GetString(4)), r.GetString(5),
            JsonSerializer.Deserialize<string[]>(r.GetString(6)) ?? Array.Empty<string>(),
            JsonSerializer.Deserialize<string[]>(r.GetString(7)) ?? Array.Empty<string>(),
            r.GetString(8), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(9)),
            r.IsDBNull(10) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(10)),
            r.GetString(11), r.IsDBNull(12) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(12)))
        {
            Tags = JsonSerializer.Deserialize<string[]>(r.GetString(13)) ?? Array.Empty<string>(),
            ProfileId = prov.ProfileId,
            ProfileHostname = prov.ProfileHostname,
            AppliedProfileRevision = prov.AppliedProfileRevision,
            Keys = JsonSerializer.Deserialize<AgentKey[]>(r.GetString(15)) ?? Array.Empty<AgentKey>(),
            LastAuthMethod = r.GetString(16),
            LastKeyId = r.GetString(17),
            LastSignedAt = r.IsDBNull(18) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(18)),
        };
    }
}
