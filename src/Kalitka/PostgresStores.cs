using System.Text;
using System.Text.Json;
using Npgsql;

namespace Kalitka;

/// <summary>
/// Postgres backend for the durable stores — the true multi-<i>node</i> step. Same
/// seams and same atomic guarantees as the SQLite backend, expressed in Postgres
/// SQL: a guarded <c>UPDATE</c> whose row count decides the winner, and
/// <c>INSERT … ON CONFLICT DO NOTHING</c> for single-use. Connections are pooled by
/// Npgsql on the connection string, so open-per-operation is cheap. Selected when
/// <see cref="GateOptions.PostgresConnectionString"/> is set.
/// </summary>
internal static class PgState
{
    public static NpgsqlConnection Open(string cs)
    {
        var conn = new NpgsqlConnection(cs);
        conn.Open();
        return conn;
    }
}

public sealed class PgRequestStore : IRequestStore
{
    private readonly string _cs;

    public PgRequestStore(string cs)
    {
        _cs = cs;
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS requests(
              id TEXT PRIMARY KEY, target TEXT NOT NULL, input TEXT NOT NULL,
              ip TEXT NOT NULL, resource TEXT NOT NULL, country TEXT, country_code TEXT,
              city TEXT, raised BIGINT NOT NULL, state TEXT NOT NULL, grant_tok TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS ix_requests_state ON requests(state, raised);
            """;
        cmd.ExecuteNonQuery();
    }

    public void Add(PendingRequest r)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO requests(id,target,input,ip,resource,country,country_code,city,raised,state,grant_tok)
            VALUES(@id,@target,@input,@ip,@resource,@country,@cc,@city,@raised,@state,@grant)
            ON CONFLICT(id) DO UPDATE SET
              target=EXCLUDED.target,input=EXCLUDED.input,ip=EXCLUDED.ip,resource=EXCLUDED.resource,
              country=EXCLUDED.country,country_code=EXCLUDED.country_code,city=EXCLUDED.city,
              raised=EXCLUDED.raised,state=EXCLUDED.state,grant_tok=EXCLUDED.grant_tok;
            """;
        Bind(cmd, r);
        cmd.ExecuteNonQuery();
    }

    public PendingRequest? Get(string id)
    {
        using var conn = PgState.Open(_cs);
        return GetCore(conn, null, id);
    }

    internal static PendingRequest? GetCore(NpgsqlConnection conn, NpgsqlTransaction? tx, string id)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"SELECT {Cols} FROM requests WHERE id=@id;";
        cmd.Parameters.AddWithValue("id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public void Remove(string id)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM requests WHERE id=@id;";
        cmd.Parameters.AddWithValue("id", id);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<PendingRequest> Snapshot()
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM requests ORDER BY raised DESC;";
        var list = new List<PendingRequest>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Read(r));
        return list;
    }

    public int CountWaiting(DateTimeOffset since)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM requests WHERE state='waiting' AND raised>=@since;";
        cmd.Parameters.AddWithValue("since", since.ToUnixTimeMilliseconds());
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    public void DropOlderThan(DateTimeOffset cutoff)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM requests WHERE raised<@cutoff;";
        cmd.Parameters.AddWithValue("cutoff", cutoff.ToUnixTimeMilliseconds());
        cmd.ExecuteNonQuery();
    }

    public bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
    {
        using var conn = PgState.Open(_cs);
        return ResolveCore(conn, null, id, toState, notOlderThan, out request);
    }

    internal static bool ResolveCore(NpgsqlConnection conn, NpgsqlTransaction? tx,
        string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
    {
        request = null;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "UPDATE requests SET state=@to WHERE id=@id AND state='waiting' AND raised>=@fresh;";
            cmd.Parameters.AddWithValue("to", toState);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("fresh", notOlderThan.ToUnixTimeMilliseconds());
            if (cmd.ExecuteNonQuery() != 1) return false;
        }
        request = GetCore(conn, tx, id);
        return request is not null;
    }

    public bool TrySetGrant(string id, string candidate, out string grant)
    {
        grant = "";
        using var conn = PgState.Open(_cs);
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "UPDATE requests SET grant_tok=@g WHERE id=@id AND grant_tok='';";
            cmd.Parameters.AddWithValue("g", candidate);
            cmd.Parameters.AddWithValue("id", id);
            if (cmd.ExecuteNonQuery() == 1) { grant = candidate; return true; }
        }
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT grant_tok FROM requests WHERE id=@id;";
            read.Parameters.AddWithValue("id", id);
            grant = read.ExecuteScalar() as string ?? "";
        }
        return false;
    }

    private const string Cols =
        "id,target,input,ip,resource,country,country_code,city,raised,state,grant_tok";

    private static void Bind(NpgsqlCommand cmd, PendingRequest r)
    {
        cmd.Parameters.AddWithValue("id", r.Id);
        cmd.Parameters.AddWithValue("target", r.Target);
        cmd.Parameters.AddWithValue("input", r.Input);
        cmd.Parameters.AddWithValue("ip", r.Ip);
        cmd.Parameters.AddWithValue("resource", r.Resource);
        cmd.Parameters.AddWithValue("country", r.Country);
        cmd.Parameters.AddWithValue("cc", r.CountryCode);
        cmd.Parameters.AddWithValue("city", r.City);
        cmd.Parameters.AddWithValue("raised", r.Raised.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("state", r.State);
        cmd.Parameters.AddWithValue("grant", r.Grant);
    }

    private static PendingRequest Read(NpgsqlDataReader r) => new()
    {
        Id = r.GetString(0), Target = r.GetString(1), Input = r.GetString(2), Ip = r.GetString(3),
        Resource = r.GetString(4), Country = r.GetString(5), CountryCode = r.GetString(6),
        City = r.GetString(7), Raised = DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(8)),
        State = r.GetString(9), Grant = r.GetString(10)
    };
}

public sealed class PgReplayStore : IReplayStore
{
    private readonly string _cs;
    private readonly TimeProvider _clock;

    public PgReplayStore(string cs, TimeProvider? clock = null)
    {
        _cs = cs;
        _clock = clock ?? TimeProvider.System;
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS replay(jti TEXT PRIMARY KEY, expires BIGINT NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    private const string InsertSql =
        "INSERT INTO replay(jti,expires) VALUES(@j,@e) ON CONFLICT(jti) DO NOTHING;";

    public async Task<bool> TryConsumeAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(jti)) return false;

        await using var conn = PgState.Open(_cs);
        await using (var prune = conn.CreateCommand())
        {
            prune.CommandText = "DELETE FROM replay WHERE expires<@now;";
            prune.Parameters.AddWithValue("now", _clock.GetUtcNow().ToUnixTimeSeconds());
            await prune.ExecuteNonQueryAsync(ct);
        }

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = InsertSql;
        cmd.Parameters.AddWithValue("j", jti);
        cmd.Parameters.AddWithValue("e", expiresAt.ToUnixTimeSeconds());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    internal static bool ConsumeCore(NpgsqlConnection conn, NpgsqlTransaction? tx, string jti, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(jti)) return false;
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
        cmd.Parameters.AddWithValue("j", jti);
        cmd.Parameters.AddWithValue("e", expiresAt.ToUnixTimeSeconds());
        return cmd.ExecuteNonQuery() == 1;
    }
}

public sealed class PgSessionStore : ISessionStore
{
    private readonly string _cs;

    public PgSessionStore(string cs)
    {
        _cs = cs;
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS sessions(
              session_id TEXT PRIMARY KEY, grant_id TEXT, request_id TEXT, subject TEXT,
              resource TEXT, agent_id TEXT, started BIGINT NOT NULL, ended BIGINT,
              outcome TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '');
            """;
        cmd.ExecuteNonQuery();
    }

    private const string InsertSql = """
        INSERT INTO sessions(session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata)
        VALUES(@sid,@grant,@req,@subject,@resource,@agent,@started,@ended,@outcome,@meta)
        ON CONFLICT(session_id) DO UPDATE SET
          grant_id=EXCLUDED.grant_id,request_id=EXCLUDED.request_id,subject=EXCLUDED.subject,
          resource=EXCLUDED.resource,agent_id=EXCLUDED.agent_id,started=EXCLUDED.started,
          ended=EXCLUDED.ended,outcome=EXCLUDED.outcome,metadata=EXCLUDED.metadata;
        """;

    private const string CloseSql =
        "UPDATE sessions SET ended=@at, outcome=@o WHERE session_id=@id AND ended IS NULL;";

    public void Start(SessionRecord s)
    {
        using var conn = PgState.Open(_cs);
        StartCore(conn, null, s);
    }

    internal static void StartCore(NpgsqlConnection conn, NpgsqlTransaction? tx, SessionRecord s)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
        cmd.Parameters.AddWithValue("sid", s.SessionId);
        cmd.Parameters.AddWithValue("grant", s.GrantId);
        cmd.Parameters.AddWithValue("req", s.RequestId);
        cmd.Parameters.AddWithValue("subject", s.Subject);
        cmd.Parameters.AddWithValue("resource", s.Resource);
        cmd.Parameters.AddWithValue("agent", s.AgentId);
        cmd.Parameters.AddWithValue("started", s.StartedAt.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("ended", (object?)s.EndedAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("outcome", s.Outcome);
        cmd.Parameters.AddWithValue("meta", s.Metadata);
        cmd.ExecuteNonQuery();
    }

    public bool End(string sessionId, string outcome, DateTimeOffset at)
    {
        using var conn = PgState.Open(_cs);
        return EndCore(conn, null, sessionId, outcome, at);
    }

    internal static bool EndCore(NpgsqlConnection conn, NpgsqlTransaction? tx,
        string sessionId, string outcome, DateTimeOffset at)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = CloseSql;
        cmd.Parameters.AddWithValue("at", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("o", outcome);
        cmd.Parameters.AddWithValue("id", sessionId);
        return cmd.ExecuteNonQuery() == 1;
    }

    public SessionRecord? Get(string sessionId)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM sessions WHERE session_id=@id;";
        cmd.Parameters.AddWithValue("id", sessionId);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public IReadOnlyList<SessionRecord> Snapshot()
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM sessions ORDER BY started DESC;";
        var list = new List<SessionRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Read(r));
        return list;
    }

    private const string Cols =
        "session_id,grant_id,request_id,subject,resource,agent_id,started,ended,outcome,metadata";

    private static SessionRecord Read(NpgsqlDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5),
        DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)),
        r.IsDBNull(7) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(7)),
        r.GetString(8), r.GetString(9));
}

/// <summary>Durable append-only audit in Postgres — the multi-node history.</summary>
public sealed class PgAuditStore : IAuditStore
{
    private readonly string _cs;

    public PgAuditStore(string cs)
    {
        _cs = cs;
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS audit(
              id TEXT PRIMARY KEY, ts BIGINT NOT NULL, event_type TEXT NOT NULL,
              actor TEXT, subject TEXT, resource TEXT, request_id TEXT,
              grant_id TEXT, channel TEXT, metadata TEXT);
            CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
            """;
        cmd.ExecuteNonQuery();
    }

    private const string InsertSql = """
        INSERT INTO audit(id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata)
        VALUES(@id,@ts,@et,@actor,@subject,@resource,@req,@grant,@channel,@meta);
        """;

    private static void Bind(NpgsqlCommand cmd, AuditEvent e)
    {
        cmd.Parameters.AddWithValue("id", e.Id);
        cmd.Parameters.AddWithValue("ts", e.Timestamp.ToUnixTimeSeconds());
        cmd.Parameters.AddWithValue("et", e.EventType);
        cmd.Parameters.AddWithValue("actor", e.Actor);
        cmd.Parameters.AddWithValue("subject", e.Subject);
        cmd.Parameters.AddWithValue("resource", e.Resource);
        cmd.Parameters.AddWithValue("req", e.RequestId);
        cmd.Parameters.AddWithValue("grant", e.GrantId);
        cmd.Parameters.AddWithValue("channel", e.Channel);
        cmd.Parameters.AddWithValue("meta", e.Metadata);
    }

    public async Task Append(AuditEvent e, CancellationToken ct)
    {
        await using var conn = PgState.Open(_cs);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = InsertSql;
        Bind(cmd, e);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    internal static void AppendCore(NpgsqlConnection conn, NpgsqlTransaction tx, AuditEvent e)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = InsertSql;
        Bind(cmd, e);
        cmd.ExecuteNonQuery();
    }

    public async Task<IReadOnlyList<AuditEvent>> Query(AuditQuery q, CancellationToken ct)
    {
        await using var conn = PgState.Open(_cs);
        await using var cmd = conn.CreateCommand();

        var sql = new StringBuilder(
            "SELECT id,ts,event_type,actor,subject,resource,request_id,grant_id,channel,metadata FROM audit WHERE 1=1");

        // ILIKE for case-insensitive substring, matching SQLite's default LIKE.
        if (!string.IsNullOrEmpty(q.Actor)) { sql.Append(" AND actor ILIKE @actor"); cmd.Parameters.AddWithValue("actor", "%" + q.Actor + "%"); }
        if (!string.IsNullOrEmpty(q.Resource)) { sql.Append(" AND resource ILIKE @resource"); cmd.Parameters.AddWithValue("resource", "%" + q.Resource + "%"); }
        if (!string.IsNullOrEmpty(q.EventType)) { sql.Append(" AND event_type = @et"); cmd.Parameters.AddWithValue("et", q.EventType); }
        if (q.Since is { } s) { sql.Append(" AND ts >= @since"); cmd.Parameters.AddWithValue("since", s.ToUnixTimeSeconds()); }
        if (q.Until is { } u) { sql.Append(" AND ts <= @until"); cmd.Parameters.AddWithValue("until", u.ToUnixTimeSeconds()); }

        sql.Append(" ORDER BY ts DESC, id DESC LIMIT @limit OFFSET @offset");
        cmd.Parameters.AddWithValue("limit", Math.Clamp(q.Limit, 1, 500));
        cmd.Parameters.AddWithValue("offset", Math.Max(0, q.Offset));
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

/// <summary>
/// The Postgres unit of work: one connection, one transaction, the store cores run
/// against it, commit — or, if the work throws, dispose rolls it back. This is what
/// makes a state change and its audit event (and a redeem's four effects) atomic on
/// Postgres, exactly as <see cref="SqliteAtomicWork"/> does on SQLite.
/// </summary>
public sealed class PgAtomicWork : IAtomicWork
{
    private readonly string _cs;

    public PgAtomicWork(string cs) => _cs = cs;

    public async Task<T> Do<T>(Func<IWorkScope, T> work, CancellationToken ct)
    {
        await using var conn = PgState.Open(_cs);
        await using var tx = await conn.BeginTransactionAsync(ct);
        var result = work(new Scope(conn, tx));
        await tx.CommitAsync(ct);
        return result;
    }

    private sealed class Scope : IWorkScope
    {
        private readonly NpgsqlConnection _conn;
        private readonly NpgsqlTransaction _tx;

        public Scope(NpgsqlConnection conn, NpgsqlTransaction tx) { _conn = conn; _tx = tx; }

        public bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
            => PgRequestStore.ResolveCore(_conn, _tx, id, toState, notOlderThan, out request);

        public bool TryConsumeReplay(string jti, DateTimeOffset expiresAt)
            => PgReplayStore.ConsumeCore(_conn, _tx, jti, expiresAt);

        public void StartSession(SessionRecord session)
            => PgSessionStore.StartCore(_conn, _tx, session);

        public bool EndSession(string sessionId, string outcome, DateTimeOffset at)
            => PgSessionStore.EndCore(_conn, _tx, sessionId, outcome, at);

        public void AppendAudit(AuditEvent e) => PgAuditStore.AppendCore(_conn, _tx, e);
    }
}

/// <summary>
/// Durable config (lists / enforced / settings) in Postgres — one
/// <c>config(key,value)</c> row per blob, shared by every instance. <see cref="Mutate"/>
/// takes a transaction-scoped advisory lock on the key before its read-modify-write,
/// so concurrent edits from different nodes serialise instead of clobbering each
/// other. That is what makes config genuinely multi-node, not just shared storage.
/// </summary>
public sealed class PgConfigStore : IConfigStore
{
    private readonly string _cs;

    public PgConfigStore(string cs)
    {
        _cs = cs;
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    public string? Get(string key)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM config WHERE key=@k;";
        cmd.Parameters.AddWithValue("k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void Mutate(string key, Func<string?, string> update)
    {
        using var conn = PgState.Open(_cs);
        using var tx = conn.BeginTransaction();

        using (var lk = conn.CreateCommand())
        {
            lk.Transaction = tx;
            // Serialise all Mutate for this key across the cluster; released at commit.
            lk.CommandText = "SELECT pg_advisory_xact_lock(hashtext(@k));";
            lk.Parameters.AddWithValue("k", key);
            lk.ExecuteNonQuery();
        }

        string? cur;
        using (var read = conn.CreateCommand())
        {
            read.Transaction = tx;
            read.CommandText = "SELECT value FROM config WHERE key=@k;";
            read.Parameters.AddWithValue("k", key);
            cur = read.ExecuteScalar() as string;
        }

        var next = update(cur);
        using (var up = conn.CreateCommand())
        {
            up.Transaction = tx;
            up.CommandText = "INSERT INTO config(key,value) VALUES(@k,@v) ON CONFLICT(key) DO UPDATE SET value=@v;";
            up.Parameters.AddWithValue("k", key);
            up.Parameters.AddWithValue("v", next);
            up.ExecuteNonQuery();
        }
        tx.Commit();
    }
}

/// <summary>Durable agent registry in Postgres, shared across the cluster — a
/// revoked agent is revoked everywhere (see <see cref="IAgentStore"/>).</summary>
public sealed class PgAgentStore : IAgentStore
{
    private readonly string _cs;

    public PgAgentStore(string cs)
    {
        _cs = cs;
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS agents(
              id TEXT PRIMARY KEY, display_name TEXT NOT NULL, platform TEXT NOT NULL,
              hostname TEXT NOT NULL, status TEXT NOT NULL, secret_hash TEXT NOT NULL,
              capabilities TEXT NOT NULL, allowed_resources TEXT NOT NULL, metadata TEXT NOT NULL,
              created_at BIGINT NOT NULL, last_seen_at BIGINT, last_ip TEXT NOT NULL DEFAULT '',
              revoked_at BIGINT, tags TEXT NOT NULL DEFAULT '[]',
              provenance TEXT NOT NULL DEFAULT '{}');
            """;
        cmd.ExecuteNonQuery();
    }

    public Agent? GetById(string id)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM agents WHERE id=@id;";
        cmd.Parameters.AddWithValue("id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public void Create(Agent a)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO agents(id,display_name,platform,hostname,status,secret_hash,capabilities,allowed_resources,metadata,created_at,last_seen_at,last_ip,revoked_at,tags,provenance)
            VALUES(@id,@dn,@pf,@hn,@st,@sh,@cap,@res,@md,@ca,@ls,@ip,@rv,@tags,@prov)
            ON CONFLICT(id) DO UPDATE SET
              display_name=EXCLUDED.display_name,platform=EXCLUDED.platform,hostname=EXCLUDED.hostname,
              status=EXCLUDED.status,secret_hash=EXCLUDED.secret_hash,capabilities=EXCLUDED.capabilities,
              allowed_resources=EXCLUDED.allowed_resources,metadata=EXCLUDED.metadata,created_at=EXCLUDED.created_at,
              last_seen_at=EXCLUDED.last_seen_at,last_ip=EXCLUDED.last_ip,revoked_at=EXCLUDED.revoked_at,tags=EXCLUDED.tags,provenance=EXCLUDED.provenance;
            """;
        cmd.Parameters.AddWithValue("id", a.Id);
        cmd.Parameters.AddWithValue("dn", a.DisplayName);
        cmd.Parameters.AddWithValue("pf", a.Platform);
        cmd.Parameters.AddWithValue("hn", a.Hostname);
        cmd.Parameters.AddWithValue("st", a.Status.ToString());
        cmd.Parameters.AddWithValue("sh", a.SecretHash);
        cmd.Parameters.AddWithValue("cap", JsonSerializer.Serialize(a.Capabilities));
        cmd.Parameters.AddWithValue("res", JsonSerializer.Serialize(a.AllowedResources));
        cmd.Parameters.AddWithValue("md", a.Metadata);
        cmd.Parameters.AddWithValue("ca", a.CreatedAt.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("ls", (object?)a.LastSeenAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ip", a.LastIp);
        cmd.Parameters.AddWithValue("rv", (object?)a.RevokedAt?.ToUnixTimeMilliseconds() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tags", JsonSerializer.Serialize(a.Tags));
        cmd.Parameters.AddWithValue("prov", JsonSerializer.Serialize(new AgentProvenance(a.ProfileId, a.ProfileHostname, a.AppliedProfileRevision)));
        cmd.ExecuteNonQuery();
    }

    public bool SetStatus(string id, AgentStatus status, DateTimeOffset at)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agents SET status=@st, revoked_at=CASE WHEN @st='Revoked' THEN @at ELSE revoked_at END WHERE id=@id;";
        cmd.Parameters.AddWithValue("st", status.ToString());
        cmd.Parameters.AddWithValue("at", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("id", id);
        return cmd.ExecuteNonQuery() == 1;
    }

    public bool RotateSecret(string id, string newHash)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agents SET secret_hash=@sh WHERE id=@id;";
        cmd.Parameters.AddWithValue("sh", newHash);
        cmd.Parameters.AddWithValue("id", id);
        return cmd.ExecuteNonQuery() == 1;
    }

    public void TouchLastSeen(string id, DateTimeOffset at, string ip)
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agents SET last_seen_at=@ls, last_ip=@ip WHERE id=@id;";
        cmd.Parameters.AddWithValue("ls", at.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("ip", ip);
        cmd.Parameters.AddWithValue("id", id);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<Agent> Snapshot()
    {
        using var conn = PgState.Open(_cs);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Cols} FROM agents ORDER BY display_name;";
        var list = new List<Agent>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Read(r));
        return list;
    }

    private const string Cols =
        "id,display_name,platform,hostname,status,secret_hash,capabilities,allowed_resources,metadata,created_at,last_seen_at,last_ip,revoked_at,tags,provenance";

    private static Agent Read(NpgsqlDataReader r)
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
        };
    }
}
