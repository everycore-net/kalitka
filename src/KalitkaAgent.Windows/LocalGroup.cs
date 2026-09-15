using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace KalitkaAgent;

/// <summary>
/// A local group Kalitka manages: it can be created if missing, its SID resolved (to assign a
/// privilege to it), and members added/removed by SID. Two flavours are used — the built-in
/// <b>Remote Desktop Users</b> (soft mode: add on grant) and a Kalitka-owned deny group (hard
/// mode: remove on grant). Behind an interface so the enforcement logic is testable off-box, and
/// so the P/Invoke lives in one place. Add/remove are idempotent so a reconcile can re-assert.
/// </summary>
public interface ILocalGroup
{
    /// <summary>Create the group if it does not exist. A no-op for a built-in group.</summary>
    void EnsureExists();
    /// <summary>The group's SID — needed to assign it a privilege via LSA. Valid after
    /// <see cref="EnsureExists"/> for a group Kalitka creates.</summary>
    SecurityIdentifier GroupSid();
    void Add(SecurityIdentifier member);
    void Remove(SecurityIdentifier member);
}

/// <summary>
/// The real thing, via <c>netapi32</c>. A group is addressed by its <b>account name</b>; for the
/// built-in Remote Desktop Users that name is resolved from its well-known SID
/// (<see cref="WellKnownSidType.BuiltinRemoteDesktopUsersSid"/>), never hard-coded — the localized
/// name differs on a non-English Windows. Members are added by SID, so a domain or local account
/// both work and no name lookup can be spoofed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsLocalGroup : ILocalGroup
{
    private const int NERR_Success = 0;
    private const int ERROR_ALIAS_EXISTS = 1379;         // group already there — EnsureExists is idempotent
    private const int ERROR_MEMBER_IN_ALIAS = 1378;      // already a member — Add is idempotent
    private const int ERROR_MEMBER_NOT_IN_ALIAS = 1377;  // not a member — Remove is idempotent

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr lgrmi0_sid; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_INFO_1 { public string lgrpi1_name; public string? lgrpi1_comment; }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupAdd(string? servername, uint level, ref LOCALGROUP_INFO_1 buf, out uint parmErr);

    [DllImport("netapi32.dll")]
    private static extern int NetLocalGroupAddMembers(string? servername, string groupname, uint level, IntPtr buf, uint totalentries);

    [DllImport("netapi32.dll")]
    private static extern int NetLocalGroupDelMembers(string? servername, string groupname, uint level, IntPtr buf, uint totalentries);

    private readonly string _group;
    private readonly bool _create;
    private readonly string? _comment;

    private WindowsLocalGroup(string group, bool create, string? comment)
    {
        _group = group;
        _create = create;
        _comment = comment;
    }

    /// <summary>The built-in Remote Desktop Users group (soft mode). Always exists.</summary>
    public static WindowsLocalGroup RemoteDesktopUsers() =>
        new(BuiltinName(WellKnownSidType.BuiltinRemoteDesktopUsersSid), create: false, comment: null);

    /// <summary>A Kalitka-owned deny group (hard mode), created if missing.</summary>
    public static WindowsLocalGroup Named(string name, string comment) =>
        new(name, create: true, comment: comment);

    public void EnsureExists()
    {
        if (!_create) return;
        var info = new LOCALGROUP_INFO_1 { lgrpi1_name = _group, lgrpi1_comment = _comment };
        var rc = NetLocalGroupAdd(null, 1, ref info, out _);
        if (rc != NERR_Success && rc != ERROR_ALIAS_EXISTS)
            throw new InvalidOperationException($"could not create local group '{_group}' (rc={rc})");
    }

    public SecurityIdentifier GroupSid() =>
        (SecurityIdentifier)new NTAccount(_group).Translate(typeof(SecurityIdentifier));

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

    // The localized account name of a built-in group, e.g. "Remotedesktopbenutzer" on a German
    // Windows — taken from the well-known SID, not assumed.
    private static string BuiltinName(WellKnownSidType type)
    {
        var sid = new SecurityIdentifier(type, null);
        var name = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;   // e.g. BUILTIN\Remote Desktop Users
        var slash = name.IndexOf('\\');
        return slash >= 0 ? name[(slash + 1)..] : name;
    }
}
