using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The SafeText backport: the approver-facing rendering in main kalitka (not just the MCP gateway)
/// must neutralize a deceptive command/subject — a bidi override or invisible character can never
/// reach the human able to reorder what they read. One standard of rigour across the product.
/// </summary>
public class SafeRenderBackportTests
{
    private static readonly AdminIdentity Who = new("sub-test", "admin@example.com");

    private static PendingView View(string command = "", string input = "sergej", string target = "prod-01") =>
        new("req-1", target, input, "203.0.113.5", "Germany", "DE", "Berlin",
            DateTimeOffset.UnixEpoch, "waiting", Command: command);

    [Fact]
    public void A_bidi_override_in_the_command_is_shown_as_a_marker_not_raw()
    {
        var html = AdminPages.Detail(Who, View(command: "systemctl restart ‮gpj.service"), "csrf");
        Assert.Contains("[U+202E RLO]", html);
        Assert.DoesNotContain("‮", html, StringComparison.Ordinal);   // the raw override never survives
    }

    [Fact]
    public void A_control_character_in_the_subject_is_neutralized()
    {
        var html = AdminPages.Detail(Who, View(input: "anna"), "csrf");
        Assert.Contains("[U+0007 CTRL]", html);
        Assert.DoesNotContain("", html, StringComparison.Ordinal);
    }

    [Fact]
    public void A_plain_command_is_shown_unchanged()
    {
        var html = AdminPages.Detail(Who, View(command: "systemctl restart nginx"), "csrf");
        Assert.Contains("systemctl restart nginx", html);
    }
}
