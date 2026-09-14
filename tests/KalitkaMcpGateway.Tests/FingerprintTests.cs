using KalitkaMcpGateway;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The fingerprint binds a grant to one exact call. What matters: identical calls fingerprint the
/// same, and every dimension that changes authority (arguments, tool, contract, subject + whether
/// asserted, workload + its assurance, upstream alias) changes the fingerprint. Framing is
/// length-prefixed, so a value containing a delimiter cannot shift a boundary and collide.
/// </summary>
public class FingerprintTests
{
    private const string Epoch = "EPOCH-A";

    private static AuthenticatedCallContext Ctx(
        string subjectId = "operator:sergej", bool asserted = false,
        string workloadId = "ai:claude:i1", string assurance = "unverified") =>
        new(new WorkloadRef(workloadId, assurance), new SubjectRef(subjectId, asserted));

    private static byte[] Contract(string schema = "{\"type\":\"object\"}", string epoch = Epoch) =>
        CallFingerprint.ToolContractId("up-uuid", "restart_vm", epoch, Jcs.Canonicalize(schema));

    private static byte[] Fp(
        string alias = "azure-prod", string tool = "restart_vm", byte[]? contract = null,
        AuthenticatedCallContext? ctx = null, string args = "{\"vm\":\"dev-01\"}") =>
        CallFingerprint.Compute(alias, tool, contract ?? Contract(), ctx ?? Ctx(), Jcs.Canonicalize(args));

    [Fact]
    public void Identical_calls_fingerprint_identically()
    {
        var a = Fp(args: "{\"vm\":\"dev-01\",\"force\":true}");
        var b = Fp(args: "{\"force\":true,\"vm\":\"dev-01\"}");   // key order irrelevant (canonical)
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
    [InlineData("subject-asserted")]
    [InlineData("workload")]
    [InlineData("workload-assurance")]
    public void Each_identity_dimension_changes_the_fingerprint(string dimension)
    {
        var baseline = Fp();
        var changed = dimension switch
        {
            "alias" => Fp(alias: "azure-dev"),
            "tool" => Fp(tool: "delete_vm"),
            "subject" => Fp(ctx: Ctx(subjectId: "operator:anna")),
            "subject-asserted" => Fp(ctx: Ctx(asserted: true)),
            "workload" => Fp(ctx: Ctx(workloadId: "ai:claude:i2")),
            "workload-assurance" => Fp(ctx: Ctx(assurance: "attested-tpm")),
            _ => throw new ArgumentOutOfRangeException(nameof(dimension)),
        };
        Assert.NotEqual(baseline, changed);
    }

    [Fact]
    public void A_changed_tool_contract_changes_the_fingerprint()
    {
        Assert.NotEqual(Fp(contract: Contract(epoch: "EPOCH-A")), Fp(contract: Contract(epoch: "EPOCH-B")));
        Assert.NotEqual(
            Fp(contract: Contract(schema: "{\"type\":\"object\"}")),
            Fp(contract: Contract(schema: "{\"type\":\"object\",\"required\":[\"vm\"]}")));
    }

    [Fact]
    public void Length_prefixed_framing_has_no_boundary_collision()
    {
        // With a naive NUL/concat framing, moving a character across a field boundary could collide.
        // Length-prefixing makes ("azure","prod") and ("azure prod","") distinct tools/aliases.
        Assert.NotEqual(Fp(alias: "azure", tool: "prodtool"), Fp(alias: "azureprod", tool: "tool"));
    }

    [Fact]
    public void Call_id_is_three_groups_of_crockford_base32()
    {
        var id = CallFingerprint.CallId(Fp());
        Assert.Matches("^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$", id);
        Assert.DoesNotContain(id, c => c is 'I' or 'L' or 'O' or 'U');
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

    // End-to-end golden: fixed inputs -> canonical schema -> contract id -> canonical args ->
    // fingerprint -> Call ID. Pins the whole pipeline so a third-party implementation can match it.
    [Fact]
    public void End_to_end_pipeline_is_stable()
    {
        var inv = ToolInventory.Build("azure-prod", "up-uuid", 1,
            new[] { new UpstreamTool("restart_vm", "{\"type\":\"object\",\"properties\":{\"vm\":{\"type\":\"string\"}}}") });
        inv.TryGet("restart_vm", out var t);
        var fp = CallFingerprint.Compute("azure-prod", "restart_vm", inv.ContractId("restart_vm"),
            Ctx(), Jcs.Canonicalize("{\"vm\":\"dev-01\"}"));

        // Golden values from the reference implementation (v2). A change here is a scheme change.
        Assert.Equal("4E8C7F93D171B8A1ED2E2426635304A75B503618D688A82C2359F887643AD311", inv.Epoch);
        Assert.Equal("bat7uYiwwPh9EE45eb9Qw2AXUh686iz92QMq1HJC5MU", CallFingerprint.ToBase64Url(fp));
        Assert.Equal("DPNQ-QEC8-P30F", CallFingerprint.CallId(fp));
    }
}
