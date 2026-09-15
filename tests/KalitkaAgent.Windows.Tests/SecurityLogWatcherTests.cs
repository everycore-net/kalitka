using KalitkaAgent;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The watcher's local fold: a 4625 storm for one person must not spin up a second poll loop while
/// the first is still in flight (Core dedups the request too, but we should not even ask twice).
/// Distinct subjects proceed independently, and a subject can be handled again once its activation
/// has finished. Driven through <c>HandleAsync</c> with a fake activator — no live event log.
/// </summary>
public class SecurityLogWatcherTests
{
    // An activator that blocks until released, counting concurrent and total activations.
    private sealed class GatedActivator : IRdpActivator
    {
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Started;
        public int Concurrent;
        public int MaxConcurrent;
        private readonly object _lock = new();

        public async Task ActivateAsync(RdpDenial denial, CancellationToken ct)
        {
            lock (_lock) { Started++; Concurrent++; MaxConcurrent = Math.Max(MaxConcurrent, Concurrent); }
            try { await _gate.Task.WaitAsync(ct); }
            finally { lock (_lock) { Concurrent--; } }
        }

        public void Release() => _gate.TrySetResult();
    }

    private static SecurityLogWatcher Watcher(IRdpActivator activator) =>
        new(new AgentIdentity(), activator, NullLogger<SecurityLogWatcher>.Instance);

    private static RdpDenial Denial(string sid) => new(sid, "CONTOSO\\anna", "anna", "10.0.0.9", "rdp:WIN-01");

    [Fact]
    public async Task Repeated_denials_for_one_subject_while_in_flight_fold_to_one_activation()
    {
        var act = new GatedActivator();
        var w = Watcher(act);
        var d = Denial("S-1-5-21-1-1");

        var first = w.HandleAsync(d, default);       // starts and blocks in the activator
        await w.HandleAsync(d, default);             // same subject in flight → returns at once
        await w.HandleAsync(d, default);

        Assert.Equal(1, act.Started);                // only one activation actually ran
        act.Release();
        await first;
    }

    [Fact]
    public async Task Distinct_subjects_activate_independently()
    {
        var act = new GatedActivator();
        var w = Watcher(act);

        var a = w.HandleAsync(Denial("S-1-5-21-1-1"), default);
        var b = w.HandleAsync(Denial("S-1-5-21-2-2"), default);

        // Both are in flight at once — the fold is per-subject, not global.
        Assert.Equal(2, act.MaxConcurrent);
        act.Release();
        await Task.WhenAll(a, b);
    }

    [Fact]
    public async Task A_subject_can_be_handled_again_after_its_activation_completes()
    {
        var act = new GatedActivator();
        var w = Watcher(act);
        var d = Denial("S-1-5-21-1-1");

        act.Release();                 // activations complete immediately
        await w.HandleAsync(d, default);
        await w.HandleAsync(d, default);

        Assert.Equal(2, act.Started);  // the in-flight guard cleared between the two
    }
}
