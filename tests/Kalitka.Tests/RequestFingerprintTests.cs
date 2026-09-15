using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The dedup fingerprint distinguishes requests by the authority they ask for: the same authority
/// hashes the same (so a 4625 storm folds), and any difference — command, profile, source, uses,
/// signed, beneficiary — hashes differently (so distinct SSH/DB requests never collapse into one).
/// </summary>
public class RequestFingerprintTests
{
    private static string Of(string resource = "ssh:prod-01", string subjectId = "sid:S-1-5-21-1",
        string beneficiary = "sergej", string profile = "", string command = "", string source = "",
        int maxUses = 0, bool signed = false) =>
        RequestFingerprint.Of(resource, subjectId, beneficiary, profile, command, source, maxUses, signed);

    [Fact]
    public void The_same_authority_hashes_the_same()
    {
        Assert.Equal(Of(command: "ls"), Of(command: "ls"));
    }

    [Theory]
    [InlineData("resource")]
    [InlineData("subject")]
    [InlineData("beneficiary")]
    [InlineData("profile")]
    [InlineData("command")]
    [InlineData("source")]
    [InlineData("uses")]
    [InlineData("signed")]
    public void Any_authority_relevant_difference_changes_the_hash(string field)
    {
        var baseline = Of();
        var changed = field switch
        {
            "resource" => Of(resource: "ssh:prod-02"),
            "subject" => Of(subjectId: "sid:S-1-5-21-2"),
            "beneficiary" => Of(beneficiary: "anna"),
            "profile" => Of(profile: "sql-dba"),
            "command" => Of(command: "rm -rf"),
            "source" => Of(source: "10.0.0.0/24"),
            "uses" => Of(maxUses: 3),
            "signed" => Of(signed: true),
            _ => baseline,
        };
        Assert.NotEqual(baseline, changed);
    }

    [Fact]
    public void Framing_prevents_a_boundary_shift_collision()
    {
        // Without length-prefixing, moving a character across the resource/subject boundary would
        // collide; framed, it does not.
        Assert.NotEqual(Of(resource: "ssh:a", subjectId: "bc"), Of(resource: "ssh:ab", subjectId: "c"));
    }
}
