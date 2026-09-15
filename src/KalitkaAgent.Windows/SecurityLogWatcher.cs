using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Xml.Linq;

namespace KalitkaAgent;

/// <summary>
/// Watches the Windows Security log for denied RDP logons (event 4625, logon-type-not-granted) and
/// raises an approval for the refused person — so with hard mode enabled they need no client at all:
/// they just try to connect, the OS refuses, this sees the refusal, and the approval fires. A 4625
/// storm for one person folds to a single request (Core dedups; we also guard locally so we do not
/// start a second poll loop for a subject already in flight). Reading the Security log needs
/// privilege; the agent runs as SYSTEM, which has it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecurityLogWatcher : BackgroundService
{
    private readonly AgentIdentity _identity;
    private readonly IRdpActivator _activator;
    private readonly ILogger<SecurityLogWatcher> _log;
    private readonly ConcurrentDictionary<string, byte> _inflight = new(StringComparer.OrdinalIgnoreCase);

    public SecurityLogWatcher(AgentIdentity identity, IRdpActivator activator, ILogger<SecurityLogWatcher> log)
    {
        _identity = identity;
        _activator = activator;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The watcher can only raise once enrolled; wait for the id rather than race Worker startup.
        try { await _identity.WaitAsync(stoppingToken); }
        catch (OperationCanceledException) { return; }

        var query = new EventLogQuery("Security", PathType.LogName, "*[System/EventID=4625]");
        using var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += (_, e) => OnEvent(e.EventRecord, stoppingToken);
        try
        {
            watcher.Enabled = true;
        }
        catch (EventLogException ex)
        {
            // Almost always "access denied": the service is not running with rights to read the
            // Security log. Fail loud but do not crash the host — the pipe path still works.
            _log.LogError(ex, "cannot subscribe to the Security log; RDP logon watching is off");
            return;
        }
        _log.LogInformation("Watching the Security log for denied RDP logons (4625, logon-type-not-granted)");

        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) { }
        watcher.Enabled = false;
    }

    private void OnEvent(EventRecord? record, CancellationToken ct)
    {
        if (record is null) return;
        RdpDenial? denial = null;
        try { denial = RdpDenial.TryParse(ParseEventData(record.ToXml()), Environment.MachineName); }
        catch (Exception ex) { _log.LogWarning(ex, "could not read a 4625 event"); }
        finally { record.Dispose(); }

        if (denial is not null) _ = HandleAsync(denial, ct);
    }

    /// <summary>Raise for one denial unless a raise for this subject is already in flight. Public so
    /// tests can drive it directly with a fake activator, no live log.</summary>
    public async Task HandleAsync(RdpDenial denial, CancellationToken ct)
    {
        if (!_inflight.TryAdd(denial.Sid, 0)) return;   // already activating this subject; fold
        try
        {
            _log.LogInformation("Denied RDP logon for {Account}{From}; raising approval",
                denial.Account, string.IsNullOrEmpty(denial.Ip) ? "" : $" from {denial.Ip}");
            await _activator.ActivateAsync(denial, ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "activation failed for {Account}", denial.Account); }
        finally { _inflight.TryRemove(denial.Sid, out _); }
    }

    /// <summary>Pull the named EventData fields out of a 4625's XML. Static and pure so it is tested
    /// against a real event shape without a live log.</summary>
    public static IReadOnlyDictionary<string, string> ParseEventData(string xml)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        var doc = XDocument.Parse(xml);
        var ns = doc.Root!.Name.Namespace;
        foreach (var data in doc.Descendants(ns + "Data"))
        {
            var name = data.Attribute("Name")?.Value;
            if (name is not null) dict[name] = data.Value;
        }
        return dict;
    }
}
