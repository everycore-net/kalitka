using System.Collections.Concurrent;

namespace Kalitka;

/// <summary>
/// Enforces that a one-time token is used at most once. It stores replay state
/// (consumed <c>jti</c>s), not the tokens themselves — the token is self-
/// contained and signed. In-memory today; a shared backend (Redis <c>SET NX</c>,
/// a SQL unique key) is what makes single-use hold across instances.
/// </summary>
public interface IReplayStore
{
    /// <summary>
    /// Marks a jti consumed and returns true only for the first caller. Later
    /// calls with the same jti return false. The entry may be forgotten after
    /// <paramref name="expiresAt"/> — past it the token's signature fails anyway.
    /// </summary>
    Task<bool> TryConsumeAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct);
}

/// <summary>Single-process replay store: a concurrent set of consumed jtis.</summary>
public sealed class InMemoryReplayStore : IReplayStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumed = new();
    private readonly TimeProvider _clock;

    public InMemoryReplayStore(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    public Task<bool> TryConsumeAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(jti)) return Task.FromResult(false);

        Prune();
        // TryAdd is atomic: exactly one caller adds the jti, the rest see false.
        return Task.FromResult(_consumed.TryAdd(jti, expiresAt));
    }

    private void Prune()
    {
        if (_consumed.Count < 10_000) return;
        var now = _clock.GetUtcNow();
        foreach (var kv in _consumed)
            if (kv.Value < now) _consumed.TryRemove(kv.Key, out _);
    }
}
