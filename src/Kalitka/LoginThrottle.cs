using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Guards the primary-credential check on the RADIUS path against two abuses:
/// <list type="bullet">
///   <item><b>Account-lockout weaponisation.</b> A flood of bad passwords for a victim's username
///     would, one bind each, trip the domain lockout policy and lock the person out. So we count
///     failures per username and, past a threshold below the domain's, refuse further attempts
///     <b>without binding</b> — kalitka never forwards the attempts that would do the locking. A
///     successful login clears the count.</item>
///   <item><b>Bind avalanche.</b> A flood, or a hung DC, could spawn unbounded concurrent binds. A
///     semaphore caps how many are in flight; excess waits briefly, then is refused as busy.</item>
/// </list>
/// Not keyed on the peer: the RADIUS peer is the gateway, one address proxying every user, so a
/// per-peer cap would throttle everyone at once. The username is the right key.
/// </summary>
public sealed class LoginThrottle
{
    private readonly int _maxFailures;
    private readonly TimeSpan _window;
    private readonly TimeSpan _queueTimeout;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _slots;
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset Start)> _failures =
        new(StringComparer.OrdinalIgnoreCase);

    public LoginThrottle(IOptions<GateOptions> options, TimeProvider clock)
    {
        var o = options.Value;
        _maxFailures = Math.Max(1, o.RadiusMaxUsernameFailures);
        _window = TimeSpan.FromMinutes(Math.Max(1, o.RadiusFailureWindowMinutes));
        _queueTimeout = TimeSpan.FromSeconds(Math.Max(0, o.RadiusVerifyQueueTimeoutSeconds));
        _clock = clock;
        _slots = new SemaphoreSlim(Math.Max(1, o.RadiusMaxConcurrentVerifications));
    }

    /// <summary>Acquire the right to verify <paramref name="username"/>, or null if it is over its
    /// failure budget (refused without binding) or no slot came free in time (busy). Dispose the
    /// permit to release the slot; call <see cref="LoginPermit.Record"/> with the outcome first.</summary>
    public async Task<LoginPermit?> AcquireAsync(string username, CancellationToken ct)
    {
        if (Failures(username) >= _maxFailures) return null;   // do not feed the domain lockout
        if (!await _slots.WaitAsync(_queueTimeout, ct)) return null;
        return new LoginPermit(this, username);
    }

    internal void Record(string username, bool ok)
    {
        if (ok) { _failures.TryRemove(username, out _); return; }
        var now = _clock.GetUtcNow();
        _failures.AddOrUpdate(username,
            _ => (1, now),
            (_, cur) => now - cur.Start >= _window ? (1, now) : (cur.Count + 1, cur.Start));
    }

    internal void Release() => _slots.Release();

    private int Failures(string username)
    {
        if (!_failures.TryGetValue(username, out var w)) return 0;
        return _clock.GetUtcNow() - w.Start >= _window ? 0 : w.Count;   // a stale window counts as zero
    }
}

/// <summary>A held verification slot. Record the outcome, then dispose to release the slot.</summary>
public sealed class LoginPermit : IDisposable
{
    private readonly LoginThrottle _throttle;
    private readonly string _username;
    private int _released;

    internal LoginPermit(LoginThrottle throttle, string username)
    {
        _throttle = throttle;
        _username = username;
    }

    /// <summary>Record whether the credential check succeeded (clears the failure count) or failed
    /// (counts toward the per-username cap).</summary>
    public void Record(bool ok) => _throttle.Record(_username, ok);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _released, 1) == 0) _throttle.Release();
    }
}
