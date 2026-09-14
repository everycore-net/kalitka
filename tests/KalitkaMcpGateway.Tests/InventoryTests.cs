using KalitkaMcpGateway;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The inventory makes drift safe and the fingerprint honest: a tool's contract id folds in the
/// snapshot epoch (a digest of the whole snapshot), so it is stable across restarts for the same
/// tools but shifts whenever the inventory changes — and the upstream is not trusted (duplicate
/// names and non-object schemas reject the whole snapshot).
/// </summary>
public class InventoryTests
{
    private static UpstreamTool T(string name, string schema = "{\"type\":\"object\"}") => new(name, schema);

    [Fact]
    public void Contract_id_is_stable_across_revision_counters_for_the_same_toolset()
    {
        // The security component is the snapshot epoch (a digest), not the local revision counter,
        // so the same tools give the same contract id even at a different revision — durable across
        // restarts once inventories persist.
        var r1 = ToolInventory.Build("azure", "uid", 1, new[] { T("restart_vm"), T("stop_vm") });
        var r2 = ToolInventory.Build("azure", "uid", 99, new[] { T("stop_vm"), T("restart_vm") });
        Assert.Equal(r1.Epoch, r2.Epoch);
        Assert.Equal(Convert.ToHexString(r1.ContractId("restart_vm")),
                     Convert.ToHexString(r2.ContractId("restart_vm")));
    }

    [Fact]
    public void Contract_id_changes_when_the_inventory_changes()
    {
        var a = ToolInventory.Build("azure", "uid", 1, new[] { T("restart_vm") });
        var b = ToolInventory.Build("azure", "uid", 1, new[] { T("restart_vm"), T("delete_vm") });
        Assert.NotEqual(a.Epoch, b.Epoch);
        // Even restart_vm — unchanged itself — gets a new contract id, so any inventory change
        // invalidates every in-flight grant on the upstream.
        Assert.NotEqual(Convert.ToHexString(a.ContractId("restart_vm")),
                        Convert.ToHexString(b.ContractId("restart_vm")));
    }

    [Fact]
    public void Contract_hash_is_revision_independent_identity()
    {
        var r1 = ToolInventory.Build("azure", "uid", 1, new[] { T("restart_vm") });
        var r2 = ToolInventory.Build("azure", "uid", 2, new[] { T("restart_vm") });
        r1.TryGet("restart_vm", out var a);
        r2.TryGet("restart_vm", out var b);
        Assert.Equal(a.ContractHashHex, b.ContractHashHex);
    }

    [Fact]
    public void Diff_reports_added_removed_and_retyped_tools()
    {
        var old = ToolInventory.Build("azure", "uid", 1, new[] { T("keep"), T("gone"), T("retype", "{\"type\":\"object\"}") });
        var @new = ToolInventory.Build("azure", "uid", 2, new[] { T("keep"), T("added"), T("retype", "{\"type\":\"string\"}") });
        var diff = ToolInventory.Diff(old, @new);
        Assert.Equal(new[] { "added" }, diff.Added);
        Assert.Equal(new[] { "gone" }, diff.Removed);
        Assert.Equal(new[] { "retype" }, diff.Changed);
        Assert.True(diff.Any);
    }

    [Fact]
    public void DiffersFrom_ignores_order_and_the_revision()
    {
        var inv = ToolInventory.Build("azure", "uid", 5, new[] { T("a"), T("b") });
        Assert.False(inv.DiffersFrom(new[] { T("b"), T("a") }));
        Assert.True(inv.DiffersFrom(new[] { T("a") }));
    }

    [Fact]
    public void A_retyped_schema_is_rejected_if_not_an_object()
    {
        Assert.Throws<JcsException>(() => ToolInventory.Build("azure", "uid", 1, new[] { T("bad", "\"a string schema\"") }));
        Assert.Throws<JcsException>(() => ToolInventory.Build("azure", "uid", 1, new[] { T("bad", "[1,2]") }));
    }

    [Fact]
    public void A_duplicate_tool_name_rejects_the_whole_snapshot()
    {
        Assert.Throws<JcsException>(() => ToolInventory.Build("azure", "uid", 1,
            new[] { T("restart_vm"), T("restart_vm", "{\"type\":\"object\",\"required\":[\"x\"]}") }));
    }
}
