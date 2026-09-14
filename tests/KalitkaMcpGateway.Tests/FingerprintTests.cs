using System.Text;
using KalitkaMcpGateway;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The fingerprint binds a grant to one exact call. What matters: identical calls fingerprint
/// the same, and every dimension that changes authority (arguments, tool, contract, subject,
/// workload, upstream alias) changes the fingerprint — so an approved grant can never be
/// redeemed for a different call.
/// </summary>
public class FingerprintTests
{
    private static byte[] Contract(string schema = "{\"type\":\"object\"}", long rev = 1) =>
        CallFingerprint.ToolContractId("up-uuid", "restart_vm", Jcs.Canonicalize(schema), rev);

    private static byte[] Fp(
        string alias = "azure-prod", string tool = "restart_vm", byte[]? contract = null,
        string subject = "operator:sergej", string workload = "ai:claude:inst1", string args = "{\"vm\":\"dev-01\"}") =>
        CallFingerprint.Compute(alias, tool, contract ?? Contract(), subject, workload, Jcs.Canonicalize(args));

    [Fact]
    public void Identical_calls_fingerprint_identically()
    {
        // Argument key order does not matter (canonicalisation), everything else equal.
        var a = Fp(args: "{\"vm\":\"dev-01\",\"force\":true}");
        var b = Fp(args: "{\"force\":true,\"vm\":\"dev-01\"}");
        Assert.Equal(a, b);
    }

    [Fact]
    public void Changing_an_argument_changes_the_fingerprint()
    {
        Assert.NotEqual(Fp(args: "{\"vm\":\"dev-01\"}"), Fp(args: "{\"vm\":\"prod-web-01\"}"));
    }

    [Theory]
    [InlineData("alias")]
    [InlineData("tool")]
    [InlineData("subject")]
    [InlineData("workload")]
    public void Each_identity_dimension_changes_the_fingerprint(string dimension)
    {
        var baseline = Fp();
        var changed = dimension switch
        {
            "alias" => Fp(alias: "azure-dev"),
            "tool" => Fp(tool: "delete_vm"),
            "subject" => Fp(subject: "operator:anna"),
            "workload" => Fp(workload: "ai:claude:inst2"),
            _ => throw new ArgumentOutOfRangeException(nameof(dimension)),
        };
        Assert.NotEqual(baseline, changed);
    }

    [Fact]
    public void A_changed_tool_contract_changes_the_fingerprint()
    {
        Assert.NotEqual(Fp(contract: Contract(rev: 1)), Fp(contract: Contract(rev: 2)));
        Assert.NotEqual(
            Fp(contract: Contract(schema: "{\"type\":\"object\"}")),
            Fp(contract: Contract(schema: "{\"type\":\"object\",\"required\":[\"vm\"]}")));
    }

    [Fact]
    public void Call_id_is_three_groups_of_crockford_base32()
    {
        var id = CallFingerprint.CallId(Fp());
        Assert.Matches("^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$", id);
        Assert.DoesNotContain(id, c => c is 'I' or 'L' or 'O' or 'U');   // excluded, ambiguous
        Assert.Equal(CallFingerprint.CallId(Fp()), id);   // stable for the same fingerprint
    }

    [Fact]
    public void Base64url_has_no_padding_or_url_unsafe_characters()
    {
        var s = CallFingerprint.ToBase64Url(Fp());
        Assert.DoesNotContain('=', s);
        Assert.DoesNotContain('+', s);
        Assert.DoesNotContain('/', s);
    }
}
