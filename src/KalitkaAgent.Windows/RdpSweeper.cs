using System.Runtime.Versioning;

namespace KalitkaAgent;

/// <summary>
/// Removes expired RDP leases on a steady cadence, independent of Core. Expiry is a locally
/// known time, so access ends on schedule even if Core is unreachable — a control-plane outage
/// must never extend access. The interval only bounds how long past expiry a lease may linger;
/// a minute is well within any RDP grant's lifetime.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpSweeper : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    private readonly RdpEnforcer _rdp;
    private readonly ILogger<RdpSweeper> _log;

    public RdpSweeper(RdpEnforcer rdp, ILogger<RdpSweeper> log)
    {
        _rdp = rdp;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { if (_rdp.Sweep() > 0) { /* logged per-lease inside Sweep */ } }
            catch (Exception ex) { _log.LogError(ex, "RDP sweep failed"); }
            try { await timer.WaitForNextTickAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
}
