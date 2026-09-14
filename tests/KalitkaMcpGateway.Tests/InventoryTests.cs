using KalitkaMcpGateway;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The inventory is what makes drift safe and the fingerprint honest: a tool's contract id folds
/// in the inventory revision (so bumping it invalidates old requests), and a snapshot diff surfaces
/// added / removed / retyped tools.
/// </summary>
public class InventoryTests
{
    private static UpstreamTool T(string name, string schema = "{\"type\":\"object\"}") => new(name, schema);

    [Fact]
    public void Contract_id_changes_with_the_revision()
    {
        var r1 = ToolInventory.Build("azure", "uid", 1, new[] { T("restart_vm") });
        var r2 = ToolInventory.Build("azure", "uid", 2, new[] { T("restart_vm") });
        Assert.NotEqual(Convert.ToHexString(r1.ContractId("restart_vm")),
                        Convert.ToHexString(r2.ContractId("restart_vm")));
    }

    [Fact]
    public void Contract_hash_is_revision_independent_identity()
    {
        var r1 = ToolInventory.Build("azure", "uid", 1, new[] { T("restart_vm") });
        var r2 = ToolInventory.Build("azure", "uid", 2, new[] { T("restart_vm") });
        r1.TryGet("restart_vm", out var a);
        r2.TryGet("restart_vm", out var b);
        Assert.Equal(a.ContractHashHex, b.ContractHashHex);   // same schema -> same identity across revisions
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
        Assert.False(inv.DiffersFrom(new[] { T("b"), T("a") }));   // same set, different order
        Assert.True(inv.DiffersFrom(new[] { T("a") }));            // b removed
    }
}
