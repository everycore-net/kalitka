using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace KalitkaAgent;

/// <summary>
/// Assigns a Windows account right (a "privilege" in LSA terms) to a SID. Hard mode uses this once
/// at startup to give the Kalitka-Gated group <c>SeDenyRemoteInteractiveLogonRight</c> — "Deny log
/// on through Remote Desktop Services" — so that membership of the group is what actually blocks a
/// logon. Behind an interface so the enforcement logic is testable without touching local policy.
/// </summary>
public interface ILsaPolicy
{
    /// <summary>Grant <paramref name="privilege"/> to <paramref name="sid"/>. Idempotent: LSA
    /// keeps a set, so re-adding an existing right is a success.</summary>
    void GrantPrivilege(SecurityIdentifier sid, string privilege);
}

/// <summary>The "Deny log on through Remote Desktop Services" right — the mechanism behind hard
/// mode's default-deny.</summary>
public static class LsaRights
{
    public const string DenyRemoteInteractiveLogon = "SeDenyRemoteInteractiveLogonRight";
}

/// <summary>
/// The real thing, via the LSA policy API in <c>advapi32</c>. Opens the local policy with just
/// <c>POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES</c> (enough to add a right), then
/// <c>LsaAddAccountRights</c>, which is additive and idempotent.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsLsaPolicy : ILsaPolicy
{
    private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
    private const uint POLICY_LOOKUP_NAMES = 0x00000800;

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint accessMask, out IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern uint LsaAddAccountRights(IntPtr policyHandle, byte[] accountSid, LSA_UNICODE_STRING[] userRights, uint countOfRights);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policyHandle);

    // Turns an NTSTATUS into a Win32 error code for a readable message.
    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(uint status);

    public void GrantPrivilege(SecurityIdentifier sid, string privilege)
    {
        var attrs = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        var status = LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, out var policy);
        if (status != 0) throw new InvalidOperationException($"LsaOpenPolicy failed (win32 {LsaNtStatusToWinError(status)})");

        var buffer = IntPtr.Zero;
        try
        {
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            buffer = Marshal.StringToHGlobalUni(privilege);
            var byteLen = (ushort)(privilege.Length * 2);   // UTF-16, excludes the terminating null
            var rights = new[]
            {
                new LSA_UNICODE_STRING { Buffer = buffer, Length = byteLen, MaximumLength = (ushort)(byteLen + 2) },
            };

            status = LsaAddAccountRights(policy, sidBytes, rights, 1);
            if (status != 0) throw new InvalidOperationException($"LsaAddAccountRights failed (win32 {LsaNtStatusToWinError(status)})");
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            LsaClose(policy);
        }
    }
}
