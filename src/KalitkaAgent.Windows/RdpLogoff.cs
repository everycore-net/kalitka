namespace KalitkaAgent;

/// <summary>
/// A finished RDP session, parsed from a Windows Security-log 4634 (logoff) event of logon type 10.
/// When the person who held a Kalitka grant logs off, the grant should end <b>now</b>, not linger to
/// its TTL: access is freed early and the session is reported closed to Core. Parsing is a pure
/// function so the trigger conditions are testable without a live event log. A 4634 fires on a real
/// logoff, not on a mere disconnect (4779) — a disconnected session can be reconnected, so the grant
/// rightly persists until reconnect-and-logoff or its TTL sweep.
/// </summary>
public sealed record RdpLogoff(string Sid, string Account)
{
    private const int LogonTypeRemoteInteractive = 10;

    public static RdpLogoff? TryParse(IReadOnlyDictionary<string, string> data)
    {
        if (!data.TryGetValue("LogonType", out var lt) || !int.TryParse(lt, out var type) || type != LogonTypeRemoteInteractive)
            return null;
        if (!data.TryGetValue("TargetUserSid", out var sid) || !Sids.IsAccount(sid)) return null;

        var user = data.GetValueOrDefault("TargetUserName", "");
        var domain = data.GetValueOrDefault("TargetDomainName", "");
        var account = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
        return new RdpLogoff(sid, account);
    }
}
