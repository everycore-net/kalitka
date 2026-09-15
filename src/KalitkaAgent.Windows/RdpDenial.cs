using System.Globalization;

namespace KalitkaAgent;

/// <summary>
/// A denied RDP logon, parsed from a Windows Security-log 4625 event: someone tried to sign in over
/// RDP and was refused because they lack the logon right (they are in the deny group, hard mode; or
/// simply not in Remote Desktop Users, soft mode). That refusal is the trigger for an approval —
/// the person just tries to connect, and the agent raises the request for them.
///
/// The identity comes from the event's <c>TargetUserSid</c>/<c>TargetUserName</c>, which LSA wrote
/// when it resolved and refused the account — so, like the pipe token, it is OS-asserted, not
/// anything the person typed. Parsing is a pure function so the trigger conditions are testable
/// without a live event log.
/// </summary>
public sealed record RdpDenial(string Sid, string Account, string User, string Ip, string Resource)
{
    // Logon type 10 is RemoteInteractive (RDP). 0xC000015B is STATUS_LOGON_TYPE_NOT_GRANTED — the
    // status when a deny-logon right (or a missing allow) refuses the session. Different Windows
    // builds put it in Status or SubStatus, so either counts.
    private const int LogonTypeRemoteInteractive = 10;
    private const long StatusLogonTypeNotGranted = 0xC000015B;

    /// <summary>The subject to raise the request for — OS-asserted, so <c>subject.assert</c> is honest.</summary>
    public CallerSubject ToSubject() => new(Sid, Account, User, "os:" + Account);

    /// <summary>Parse a 4625's EventData (name → value) into a denial worth acting on, or null when
    /// the event is not an RDP logon-type-not-granted for a real account.</summary>
    public static RdpDenial? TryParse(IReadOnlyDictionary<string, string> data, string machineName)
    {
        if (!data.TryGetValue("LogonType", out var lt) || !int.TryParse(lt, out var type) || type != LogonTypeRemoteInteractive)
            return null;
        if (!IsNotGranted(data)) return null;

        if (!data.TryGetValue("TargetUserSid", out var sid) || !IsAccountSid(sid)) return null;
        var user = data.GetValueOrDefault("TargetUserName", "");
        if (string.IsNullOrWhiteSpace(user)) return null;

        var domain = data.GetValueOrDefault("TargetDomainName", "");
        var account = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
        var ip = data.GetValueOrDefault("IpAddress", "");
        if (ip == "-") ip = "";   // 4625 writes "-" when the source address is unknown
        return new RdpDenial(sid, account, user, ip, "rdp:" + machineName);
    }

    private static bool IsNotGranted(IReadOnlyDictionary<string, string> data) =>
        Hex(data.GetValueOrDefault("SubStatus")) == StatusLogonTypeNotGranted ||
        Hex(data.GetValueOrDefault("Status")) == StatusLogonTypeNotGranted;

    private static long Hex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return 0;
        var v = value.Trim();
        if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) v = v[2..];
        return long.TryParse(v, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var n) ? n : 0;
    }

    // A real local or domain account SID (the S-1-5-21-<domain>-<rid> shape), not a null/anonymous
    // or service well-known SID — we only ever raise for a person who could actually be approved.
    private static bool IsAccountSid(string sid) =>
        !string.IsNullOrWhiteSpace(sid) && sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);
}
