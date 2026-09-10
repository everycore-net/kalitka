using Microsoft.Data.Sqlite;

namespace Kalitka;

/// <summary>
/// The store operations available inside a unit of work, all bound to its one
/// transaction. Deliberately small — it grows a method only when a new state/audit
/// pair needs to commit together (0.11 slices: resolve+append first, then
/// redeem+start and close+end).
/// </summary>
public interface IWorkScope
{
    /// <summary>Resolve-once, exactly as <see cref="IRequestStore.TryResolve"/>, but
    /// on this unit of work's transaction.</summary>
    bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request);

    /// <summary>Append an audit event on this unit of work's transaction, so it
    /// commits with the state change above — or not at all.</summary>
    void AppendAudit(AuditEvent e);
}

/// <summary>
/// Runs several store writes as one atomic unit, so a state transition and its
/// audit event commit together. It exists only when state and audit share one
/// transactional backend (the same SQLite file today, Postgres later); the engine
/// asks for it and, when it is absent — in-memory, or state and audit on separate
/// files — falls back to sequential best-effort writes. That fallback is honest:
/// in-memory loses state and audit together on a crash, so it has no gap to close;
/// separate files cannot span a transaction and keep today's behaviour.
/// </summary>
public interface IAtomicWork
{
    Task<T> Do<T>(Func<IWorkScope, T> work, CancellationToken ct);
}

/// <summary>
/// The SQLite unit of work: open one connection, begin one transaction, run the
/// work against it, commit. If <paramref name="work"/> throws (e.g. the audit
/// append fails) the transaction is disposed uncommitted and everything — the
/// state change included — rolls back. Both tables live in the one file, so this
/// is an ordinary local transaction, not a distributed one.
/// </summary>
public sealed class SqliteAtomicWork : IAtomicWork
{
    private readonly string _cs;

    public SqliteAtomicWork(string path) => _cs = SqliteState.ConnectionString(path);

    public async Task<T> Do<T>(Func<IWorkScope, T> work, CancellationToken ct)
    {
        await using var conn = SqliteState.Open(_cs);
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);
        var result = work(new Scope(conn, tx));
        await tx.CommitAsync(ct);
        return result;
    }

    private sealed class Scope : IWorkScope
    {
        private readonly SqliteConnection _conn;
        private readonly SqliteTransaction _tx;

        public Scope(SqliteConnection conn, SqliteTransaction tx) { _conn = conn; _tx = tx; }

        public bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request)
            => SqliteRequestStore.ResolveCore(_conn, _tx, id, toState, notOlderThan, out request);

        public void AppendAudit(AuditEvent e) => SqliteAuditStore.AppendCore(_conn, _tx, e);
    }
}
