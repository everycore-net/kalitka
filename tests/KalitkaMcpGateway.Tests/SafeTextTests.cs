using Kalitka.Text;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// The human-safe renderer: the approval UI must never show a value less safely than the gateway
/// reads it. Dangerous characters become labelled tokens (never raw), mixed scripts warn and mixed +
/// confusable is high-risk, a single national script is not itself a warning, and the weakest channel
/// (plain text) still surfaces every dangerous character.
/// </summary>
public class SafeTextTests
{
    private const string Rlo = "‮";     // right-to-left override
    private const string CyrO = "о";    // Cyrillic 'о' (confusable with ASCII 'o')
    private const string CyrA = "а";    // Cyrillic 'а'

    [Fact]
    public void A_plain_ascii_identifier_is_not_risky()
    {
        var r = SafeText.Render("prod-web-01", FieldKind.SecurityIdentifier);
        Assert.Equal(RiskLevel.None, r.Risk);
        Assert.False(r.ShowTriple);
        Assert.All(r.Tokens, t => Assert.Equal(TokenClass.Ascii, t.Class));
    }

    [Fact]
    public void A_single_national_script_is_not_a_warning_but_shows_the_triple()
    {
        var r = SafeText.Render("Сергей", FieldKind.SecurityIdentifier);
        Assert.Equal(RiskLevel.None, r.Risk);           // one script is legitimate, not a warning
        Assert.True(r.ShowTriple);                       // still surfaced: skeleton differs from displayed
        Assert.Equal(new[] { "Cyrillic" }, r.Scripts);
    }

    [Fact]
    public void Mixed_script_with_a_confusable_is_high_risk()
    {
        // "prod-web-01" but the 'o' is Cyrillic — Latin + Cyrillic, and the char is a confusable.
        var spoof = "pr" + CyrO + "d-web-01";
        var r = SafeText.Render(spoof, FieldKind.SecurityIdentifier);
        Assert.Equal(RiskLevel.HighRisk, r.Risk);
        Assert.Contains("Cyrillic", r.Scripts);
        Assert.Contains("Latin", r.Scripts);
        Assert.Equal("prod-web-01", r.Skeleton);        // folds back to the impersonated identifier
    }

    [Fact]
    public void Mixed_script_without_a_confusable_is_a_warning()
    {
        var r = SafeText.Render("web中", FieldKind.SecurityIdentifier);   // Latin + Han
        Assert.Equal(RiskLevel.Warning, r.Risk);
    }

    [Fact]
    public void A_bidi_override_is_high_risk_and_never_emitted_raw()
    {
        var r = SafeText.Render("file" + Rlo + "gpj.exe", FieldKind.SecurityIdentifier);
        Assert.Equal(RiskLevel.HighRisk, r.Risk);
        var danger = Assert.Single(r.Tokens, t => t.Class == TokenClass.Dangerous);
        Assert.Equal("[U+202E RLO]", danger.Label);

        var text = SafeText.ToTextMarkers(r);
        Assert.Contains("[U+202E RLO]", text);
        // Ordinal: the override is an ignorable char, so a culture-sensitive search would false-match.
        Assert.DoesNotContain(Rlo, text, StringComparison.Ordinal);   // the raw override never survives
        Assert.StartsWith("[!]", text);                  // high-risk tag on the weakest channel
    }

    [Fact]
    public void Free_text_flags_only_dangerous_characters_no_over_colouring()
    {
        // Cyrillic in a reason string is not flagged; a control char still is.
        var mixedReason = SafeText.Render("нужно перезапустить web", FieldKind.FreeText);
        Assert.Equal(RiskLevel.None, mixedReason.Risk);
        Assert.False(mixedReason.ShowTriple);
        Assert.DoesNotContain(mixedReason.Tokens, t => t.Class == TokenClass.Script);

        var withControl = SafeText.Render("oknow", FieldKind.FreeText);
        Assert.Equal(RiskLevel.HighRisk, withControl.Risk);
        Assert.Contains(withControl.Tokens, t => t.Class == TokenClass.Dangerous);
    }

    [Fact]
    public void Skeleton_folds_confusables_and_raw_escapes_non_ascii()
    {
        var r = SafeText.Render(CyrA + "dmin", FieldKind.SecurityIdentifier);   // Cyrillic 'а' + "dmin"
        Assert.Equal("admin", r.Skeleton);
        Assert.Equal("\\u0430dmin", r.Raw);
    }

    // ---- published renderer vectors -------------------------------------------

    public sealed record RVectors(RCase[] Cases);
    public sealed record RCase(string Name, string Input, string Kind, string Risk, string? Skeleton, string? Text_Markers);

    public static IEnumerable<object[]> RendererVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "renderer-vectors.json");
        var v = System.Text.Json.JsonSerializer.Deserialize<RVectors>(File.ReadAllText(path),
            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        return v.Cases.Select(c => new object[] { c });
    }

    [Theory]
    [MemberData(nameof(RendererVectors))]
    public void Renderer_vector(RCase c)
    {
        var kind = c.Kind == "free" ? FieldKind.FreeText : FieldKind.SecurityIdentifier;
        var r = SafeText.Render(c.Input, kind);
        Assert.Equal(Enum.Parse<RiskLevel>(c.Risk), r.Risk);
        if (c.Skeleton is not null) Assert.Equal(c.Skeleton, r.Skeleton);
        if (c.Text_Markers is not null) Assert.Equal(c.Text_Markers, SafeText.ToTextMarkers(r));
    }
}
