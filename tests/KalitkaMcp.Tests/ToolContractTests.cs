using System.Reflection;
using KalitkaMcp;
using Xunit;

namespace KalitkaMcp.Tests;

/// <summary>
/// The control-plane server's defining constraint is a <b>structural absence</b>: there must be
/// no tool that approves a request. "No approve_request" is a design invariant, not a code
/// comment — a workload that could both ask and approve makes the human decoration — so it is
/// asserted here over the actual exported tool surface, discovered the way the MCP SDK does.
/// </summary>
public class ToolContractTests
{
    // Every [McpServerTool] method's tool name, discovered by reflection (attribute Name, or the
    // method name) across all [McpServerToolType] types in the server assembly.
    private static IReadOnlyList<string> ToolNames()
    {
        var asm = typeof(KalitkaTools).Assembly;
        var names = new List<string>();
        foreach (var type in asm.GetTypes()
                     .Where(t => t.GetCustomAttributes().Any(a => a.GetType().Name == "McpServerToolTypeAttribute")))
            foreach (var m in type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                var attr = m.GetCustomAttributes().FirstOrDefault(a => a.GetType().Name == "McpServerToolAttribute");
                if (attr is null) continue;
                var named = attr.GetType().GetProperty("Name")?.GetValue(attr) as string;
                names.Add(string.IsNullOrEmpty(named) ? m.Name : named);
            }
        return names;
    }

    [Fact]
    public void The_control_plane_exposes_exactly_the_intended_tools()
    {
        var names = ToolNames();
        Assert.Equal(
            new[] { "kalitka.end_session", "kalitka.get_request", "kalitka.request_access" },
            names.OrderBy(n => n).ToArray());
    }

    [Fact]
    public void There_is_no_approve_tool_by_construction()
    {
        Assert.DoesNotContain(ToolNames(), n => n.Contains("approve", StringComparison.OrdinalIgnoreCase));
    }
}
