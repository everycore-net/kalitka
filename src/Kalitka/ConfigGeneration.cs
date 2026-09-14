namespace Kalitka;

/// <summary>
/// Closes the one place the config cache can be unsafe: the TTL that lets a change propagate with a
/// bounded lag is harmless when a rule is <i>relaxed</i> (the worst case is a few extra seconds of
/// asking), but on the decision path a snapshot that has not yet seen a <i>tightening</i> made on
/// another instance would wrongly grant authority — let traffic bypass an armed gate, or honour an
/// allow that was just revoked.
///
/// The guard is asymmetric on purpose. The deny / enforce direction never consults it, so a
/// loosening simply arrives at the slower cache TTL. Only the direction that <b>grants</b> authority
/// calls <see cref="Fresh"/> before deciding: if the reader's snapshot might be older than the
/// confirm window, it checks the store's monotonic <see cref="IConfigStore.Generation"/> — a cheap
/// counter, not a re-read of the whole blob — and reports whether the snapshot has been superseded.
/// A bump means the caller must reload and decide again on fresh config.
///
/// The window bounds how often the counter is read: within it the snapshot is trusted outright, so a
/// tightening is reflected on the grant path within one window, and a hot path pays at most one
/// counter read per window regardless of request rate. Not thread-safe; callers serialise it under
/// the same lock that guards their cached snapshot.
/// </summary>
public sealed class ConfigGeneration
{
    private readonly IConfigStore _store;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _window;
    private long _seen;
    private DateTimeOffset _confirmedAt = DateTimeOffset.MinValue;

    public ConfigGeneration(IConfigStore store, TimeProvider clock, TimeSpan window)
    {
        _store = store;
        _clock = clock;
        _window = window;
    }

    /// <summary>Record the generation the current snapshot reflects. Call right after a full reload
    /// of the cached config, so a later <see cref="Fresh"/> compares against what was actually read.</summary>
    public void Mark()
    {
        _seen = _store.Generation();
        _confirmedAt = _clock.GetUtcNow();
    }

    /// <summary>On the authority-granting path only. Returns <c>true</c> if the snapshot is current
    /// enough to grant — confirmed within the window, or the store's generation is unchanged since it
    /// was marked. Returns <c>false</c> if the config was superseded since the snapshot: the caller
    /// must reload and re-evaluate before granting, so a missed tightening cannot slip through.</summary>
    public bool Fresh()
    {
        if (_clock.GetUtcNow() - _confirmedAt < _window) return true;   // within the window: trust the snapshot
        if (_store.Generation() == _seen) { _confirmedAt = _clock.GetUtcNow(); return true; }  // unchanged: still current
        return false;   // superseded — caller reloads and decides again
    }
}
