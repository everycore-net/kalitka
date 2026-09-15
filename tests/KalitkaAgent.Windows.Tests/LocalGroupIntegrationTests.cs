using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// Exercises <see cref="WindowsLocalGroup"/> against a REAL local group — the layer that applies OS
/// authority, which no other test touched, which is exactly why the netapi32 marshalling defect
/// (default ANSI on a Unicode-only API → every membership call returned NERR_GroupNotFound 2220)
/// reached a live host behind a green build. Creates a throwaway group, adds and removes the current
/// user's SID, and deletes the group. On the Windows CI runner (elevated) it runs; off Windows or
/// without the privilege to manage local groups it skips rather than fails.
/// </summary>
[SupportedOSPlatform("windows")]
public class LocalGroupIntegrationTests
{
    [Fact]
    public void Add_and_remove_a_member_round_trips_on_a_real_group()
    {
        if (!OperatingSystem.IsWindows()) return;   // netapi32 is Windows-only

        var name = "kalitka-test-" + Guid.NewGuid().ToString("N")[..8];
        var group = WindowsLocalGroup.Named(name, "kalitka marshalling test");

        try { group.EnsureExists(); }
        catch (InvalidOperationException) { return; }   // not elevated / can't manage groups: skip

        try
        {
            var me = WindowsIdentity.GetCurrent().User!;
            // The regression: before the CharSet fix each of these threw "rc=2220". All must succeed,
            // and add/remove must be idempotent (benign ERROR_MEMBER_IN_ALIAS / _NOT_IN_ALIAS).
            group.Add(me);
            group.Add(me);       // already a member — no throw
            group.Remove(me);
            group.Remove(me);    // no longer a member — no throw
        }
        finally
        {
            NetLocalGroupDel(null, name);
        }
    }

    // Test-only: delete the throwaway group. Unicode for the same reason the production imports are.
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupDel(string? servername, string groupname);
}
