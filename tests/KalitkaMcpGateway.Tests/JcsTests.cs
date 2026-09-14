using System.Text;
using System.Text.Json;
using KalitkaMcpGateway;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The canonicalisation is the security boundary, so it is tested two ways: the published
/// conformance vectors (which a third-party gateway must also pass), and the properties that
/// make the fingerprint safe — same-meaning inputs collapse, different calls do not, and
/// anything that cannot be reduced to one form is rejected.
/// </summary>
public class JcsTests
{
    private static string Canon(string json) => Encoding.UTF8.GetString(Jcs.Canonicalize(json));

    // ---- published conformance vectors ----------------------------------------

    public sealed record Vectors(VecCase[] Canonicalization, VecCase[] Numbers, VecCase[] Reject);
    public sealed record VecCase(string? Name, string Input, string? Canonical);

    private static Vectors Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "kalitka-mcp-call-v1.json");
        return JsonSerializer.Deserialize<Vectors>(File.ReadAllText(path),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    }

    public static IEnumerable<object[]> CanonicalCases() =>
        Load().Canonicalization.Concat(Load().Numbers).Select(c => new object[] { c.Input, c.Canonical! });

    [Theory]
    [MemberData(nameof(CanonicalCases))]
    public void Vector_canonicalizes_exactly(string input, string canonical) =>
        Assert.Equal(canonical, Canon(input));

    public static IEnumerable<object[]> RejectCases() =>
        Load().Reject.Select(c => new object[] { c.Input });

    [Theory]
    [MemberData(nameof(RejectCases))]
    public void Vector_is_rejected(string input) =>
        Assert.Throws<JcsException>(() => Jcs.Canonicalize(input));

    // ---- number formatting: V8-derived boundary vectors -----------------------

    [Theory]
    [InlineData(0.0, "0")]
    [InlineData(1.0, "1")]
    [InlineData(-1.5, "-1.5")]
    [InlineData(100.0, "100")]
    [InlineData(0.1, "0.1")]
    [InlineData(1e20, "100000000000000000000")]
    [InlineData(1e21, "1e+21")]
    [InlineData(1e-6, "0.000001")]
    [InlineData(1e-7, "1e-7")]
    [InlineData(9007199254740992.0, "9007199254740992")]
    [InlineData(5e-324, "5e-324")]                       // smallest denormal
    [InlineData(1.7976931348623157e308, "1.7976931348623157e+308")]  // max double
    public void Number_matches_es6_tostring(double value, string expected) =>
        Assert.Equal(expected, Jcs.NumberToJson(value));

    // ---- fingerprint-safety properties ----------------------------------------

    [Fact]
    public void Reordering_object_keys_yields_identical_bytes()
    {
        Assert.Equal(Canon("{\"a\":1,\"b\":2}"), Canon("{\"b\":2,\"a\":1}"));
    }

    [Fact]
    public void One_and_one_point_zero_are_the_same_call()
    {
        Assert.Equal(Canon("{\"n\":1}"), Canon("{\"n\":1.0}"));
    }

    [Fact]
    public void Missing_and_null_are_different_calls()
    {
        // No schema defaults are applied, so an absent key and an explicit null are distinct.
        Assert.NotEqual(Canon("{\"a\":1}"), Canon("{\"a\":1,\"b\":null}"));
    }

    [Fact]
    public void Nfc_and_nfd_are_different_calls_at_the_byte_level()
    {
        var nfc = "{\"s\":\"é\"}";           // é as one code point (U+00E9)
        var nfd = "{\"s\":\"é\"}";          // e + combining acute (U+0065 U+0301)
        Assert.NotEqual(Canon(nfc), Canon(nfd));   // Unicode is deliberately NOT normalized
    }

    [Fact]
    public void Array_order_is_significant()
    {
        Assert.NotEqual(Canon("[1,2]"), Canon("[2,1]"));
    }

    [Fact]
    public void Duplicate_keys_are_rejected()
    {
        Assert.Throws<JcsException>(() => Jcs.Canonicalize("{\"a\":1,\"a\":2}"));
    }

    [Fact]
    public void Control_characters_use_short_escapes_and_lowercase_hex()
    {
        // Input carries the escapes (raw control chars are invalid JSON); canonical output keeps
        // the short escape for tab and \u00xx (lowercase hex) for U+0001.
        Assert.Equal("{\"s\":\"\\t\\u0001\"}", Canon("{\"s\":\"\\t\\u0001\"}"));
    }

    [Fact]
    public void Negative_zero_formats_as_zero()
    {
        Assert.Equal("0", Jcs.NumberToJson(-0.0));
    }
}
