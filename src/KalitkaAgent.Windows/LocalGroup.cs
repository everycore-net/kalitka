using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace KalitkaAgent;

/// <summary>
/// Membership of the local <b>Remote Desktop Users</b> group — the mechanism behind RDP JIT.
/// Kept behind an interface so the enforcement logic (add on redeem, remove on expiry, survive
/// a restart) is testable without touching the real machine, and the P/Invoke lives in one
/// place. Add/remove are idempotent: adding an existing member or removing an absent one is a
/// success, so a reconcile can re-assert freely.
/// </summary>
public interface ILocalGroup
{
    void Add(SecurityIdentifier member);
    void Remove(SecurityIdentifier member);
}

/// <summary>
/// The real thing, via <c>netapi32</c>. The group is addressed by its <b>well-known SID</b>
/// (<see cref="WellKnownSidType.BuiltinRemoteDesktopUsersSid"/>, S-1-5-32-555) and its localized
/// name resolved from that — never a hard-coded "Remote Desktop Users", which is wrong on a
/// non-English Windows. Members are added by SID, so a domain or local account both work and no
/// name lookup can be spoofed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsLocalGroup : ILocalGroup
{
    private const int NERR_Success = 0;
    private const int ERROR_MEMBER_IN_ALIAS = 1378;      // already a member — Add is idempotent
    private const int ERROR_MEMBER_NOT_IN_ALIAS = 1377;  // not a member — Remove is idempotent

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr lgrmi0_sid; }

    [DllImport("netapi32.dll")]
    private static extern int NetLocalGroupAddMembers(string? servername, string groupname, uint level, IntPtr buf, uint totalentries);

    [DllImport("netapi32.dll")]
    private static extern int NetLocalGroupDelMembers(string? servername, string groupname, uint level, IntPtr buf, uint totalentries);

    private readonly string _group = RemoteDesktopUsersGroupName();

    public void Add(SecurityIdentifier member) => Call(NetLocalGroupAddMembers, member, ERROR_MEMBER_IN_ALIAS);
    public void Remove(SecurityIdentifier member) => Call(NetLocalGroupDelMembers, member, ERROR_MEMBER_NOT_IN_ALIAS);

    private void Call(Func<string?, string, uint, IntPtr, uint, int> api, SecurityIdentifier member, int benignError)
    {
        var sidBytes = new byte[member.BinaryLength];
        member.GetBinaryForm(sidBytes, 0);
        var sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
        var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_0>());
        try
        {
            Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
            Marshal.StructureToPtr(new LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid = sidPtr }, infoPtr, false);
            var rc = api(null, _group, 0, infoPtr, 1);
            if (rc != NERR_Success && rc != benignError)
                throw new InvalidOperationException($"local-group membership change failed (rc={rc}) for {member}");
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(sidPtr);
        }
    }

    // The localized account name of the built-in Remote Desktop Users group, e.g.
    // "Remotedesktopbenutzer" on a German Windows — taken from the well-known SID, not assumed.
    private static string RemoteDesktopUsersGroupName()
    {
        var sid = new SecurityIdentifier(WellKnownSidType.BuiltinRemoteDesktopUsersSid, null);
        var name = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;   // e.g. BUILTIN\Remote Desktop Users
        var slash = name.IndexOf('\\');
        return slash >= 0 ? name[(slash + 1)..] : name;
    }
}
