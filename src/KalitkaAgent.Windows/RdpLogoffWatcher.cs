using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace KalitkaAgent;

/// <summary>
/// Watches the Windows Security log for RDP logoffs (event 4634, logon type 10) and ends the
/// matching Kalitka lease the moment its owner logs off — access is freed early instead of lingering
/// to the grant's TTL, and Core is told the session closed. The logoff is authoritative locally
/// (deny + dejournal happen whether or not Core is reachable); the report to Core is best-effort,
/// and a later reconcile closes anything a Core outage missed. Off by default, under the same
/// <c>Kalitka:RdpWatch</c> switch as the denied-logon watcher.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpLogoffWatcher : BackgroundService
{
    private readonly AgentIdentity _identity;
    private readonly RdpEnforcer _rdp;
    private readonly CoreClient _core;
    private readonly ILogger<RdpLogoffWatcher> _log;

    public RdpLogoffWatcher(AgentIdentity identity, RdpEnforcer rdp, CoreClient core, ILogger<RdpLogoffWatcher> log)
    {
        _identity = identity;
        _rdp = rdp;
        _core = core;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await _identity.WaitAsync(stoppingToken); }
        catch (OperationCanceledException) { return; }

        var query = new EventLogQuery("Security", PathType.LogName, "*[System/EventID=4634]");
        using var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += (_, e) => OnEvent(e.EventRecord, stoppingToken);
        try
        {
            watcher.Enabled = true;
        }
        catch (EventLogException ex)
        {
            _log.LogError(ex, "cannot subscribe to the Security log; RDP logoff accounting is off");
            return;
        }
        _log.LogInformation("Watching the Security log for RDP logoffs (4634, logon type 10)");

        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) { }
        watcher.Enabled = false;
    }

    private void OnEvent(EventRecord? record, CancellationToken ct)
    {
        if (record is null) return;
        RdpLogoff? logoff = null;
        try { logoff = RdpLogoff.TryParse(EventData.Parse(record.ToXml())); }
        catch (Exception ex) { _log.LogWarning(ex, "could not read a 4634 event"); }
        finally { record.Dispose(); }

        if (logoff is not null) _ = HandleAsync(logoff, ct);
    }

    /// <summary>End the lease for a logged-off subject, if Kalitka granted one. Public so tests can
    /// drive it directly.</summary>
    public async Task HandleAsync(RdpLogoff logoff, CancellationToken ct)
    {
        var lease = _rdp.LeaseForSid(logoff.Sid);
        if (lease is null) return;   // not a Kalitka-granted session; nothing to end

        _log.LogInformation("RDP logoff for {Account}; ending lease early", logoff.Account);
        _rdp.Revoke(lease.SessionId);   // authoritative: deny + dejournal (the session is already gone)

        var agentId = _identity.Current;
        if (agentId is null) return;
        try { await _core.EndSessionAsync(agentId, lease.SessionId, "ended", ct); }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogWarning(ex, "could not report session end to Core; a reconcile will"); }
    }
}
