using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace KalitkaAgent;

/// <summary>
/// Ends the interactive sessions belonging to an account. This exists because removing someone
/// from Remote Desktop Users (or, in hard mode, adding them back to a deny group) does <b>not</b>
/// eject a session that is already open: the access token was assembled at logon and outlives the
/// group change. So closing a lease means "remove the right <i>plus</i> terminate the session" —
/// this is the second half. Kept behind an interface so the enforcer stays testable off-box.
/// </summary>
public interface ISessionKiller
{
    /// <summary>Log off every session whose owner is <paramref name="sid"/>. Returns how many
    /// were ended. May throw on an OS-level failure; the caller treats that as best-effort and
    /// logs it, because the group change is the primary guarantee and journal cleanup must not be
    /// blocked by a lingering token.</summary>
    int LogoffBySid(SecurityIdentifier sid);
}

/// <summary>
/// The real thing, via <c>wtsapi32</c>. Enumerates the local terminal-services sessions, resolves
/// each session's owner SID from its user+domain name, and logs off the ones that match. Runs as
/// SYSTEM (the service account), which is what <c>WTSLogoffSession</c> requires. Session 0 is
/// skipped: it is the non-interactive services session, never a logon Kalitka grants.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WtsSessionKiller : ISessionKiller
{
    private static readonly IntPtr CurrentServer = IntPtr.Zero;   // WTS_CURRENT_SERVER_HANDLE

    // Populated by the marshaller from the WTS buffer, so the fields are never assigned in source;
    // the layout must still carry all three for the sequential marshalling to line up.
#pragma warning disable CS0649
    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPWStr)] public string pWinStationName;
        public int State;
    }
#pragma warning restore CS0649

    private enum WtsInfoClass { WTSUserName = 5, WTSDomainName = 7 }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern int WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr ppSessionInfo, out int pCount);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WtsInfoClass infoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSLogoffSession(IntPtr hServer, int sessionId, bool bWait);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    public int LogoffBySid(SecurityIdentifier sid)
    {
        if (WTSEnumerateSessions(CurrentServer, 0, 1, out var pInfo, out var count) == 0)
            throw new InvalidOperationException($"WTSEnumerateSessions failed (win32 {Marshal.GetLastWin32Error()})");

        var ended = 0;
        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(pInfo + i * size);
                if (info.SessionId == 0) continue;   // services session, never a granted logon
                if (OwnerOf(info.SessionId) is { } owner && owner == sid)
                {
                    if (!WTSLogoffSession(CurrentServer, info.SessionId, true))
                        throw new InvalidOperationException($"WTSLogoffSession({info.SessionId}) failed (win32 {Marshal.GetLastWin32Error()})");
                    ended++;
                }
            }
        }
        finally { WTSFreeMemory(pInfo); }
        return ended;
    }

    // The SID that owns a session, from its user + domain name — or null for a station with no
    // logged-on user (a listening/disconnected console), which owns nobody.
    private static SecurityIdentifier? OwnerOf(int sessionId)
    {
        var user = Query(sessionId, WtsInfoClass.WTSUserName);
        if (string.IsNullOrEmpty(user)) return null;
        var domain = Query(sessionId, WtsInfoClass.WTSDomainName);
        var account = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
        try { return (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier)); }
        catch (IdentityNotMappedException) { return null; }
    }

    private static string? Query(int sessionId, WtsInfoClass cls)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, cls, out var buf, out _)) return null;
        try { return Marshal.PtrToStringUni(buf); }
        finally { WTSFreeMemory(buf); }
    }
}
