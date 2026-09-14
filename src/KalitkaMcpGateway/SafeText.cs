using System.Text;

namespace KalitkaMcpGateway;

/// <summary>How risky a rendered value looks to a human. Colour is never the only signal — the
/// class travels in the model so any channel can show it (underline, icon, prefix, tooltip).</summary>
public enum RiskLevel { None, Warning, HighRisk }

/// <summary>The kind of a token in a rendering — so a rich channel can style it and a weak channel
/// can still make the dangerous ones unmissable.</summary>
public enum TokenClass { Ascii, Script, Dangerous }

/// <summary>One run of a rendered value. A <see cref="TokenClass.Dangerous"/> token carries a
/// <see cref="Label"/> like <c>[U+202E RLO]</c> and its <see cref="Text"/> is never emitted raw.</summary>
public sealed record RenderToken(string Text, TokenClass Class, string? Script = null, string? Label = null);

/// <summary>Whether a value is a security identifier (strict analysis) or free-form reason text
/// (only dangerous characters are flagged — no over-colouring).</summary>
public enum FieldKind { SecurityIdentifier, FreeText }

/// <summary>A safe rendering of one value: styled tokens, an overall risk, and — for a suspicious
/// identifier — the Displayed / Skeleton / Raw triple so a human can see what it really is.</summary>
public sealed record SafeRendering(
    string Displayed,
    RenderToken[] Tokens,
    RiskLevel Risk,
    bool ShowTriple,
    string Skeleton,
    string Raw,
    string[] Scripts);

/// <summary>
/// Renders an argument value for a human approver so that the approval UI never shows a request
/// <b>less safely than the gateway interprets it</b>. Control / bidi / invisible characters become
/// explicit <c>[U+XXXX NAME]</c> tokens (never executed); mixed scripts are a warning and mixed +
/// confusable is high-risk; a whole word in one national script (e.g. «Сергей») is not itself a
/// warning. The model is channel-agnostic; <see cref="ToTextMarkers"/> is the weakest-channel form
/// (Telegram / e-mail: text only), and the invariant is enforced there — no raw dangerous character
/// ever passes through.
/// </summary>
public static class SafeText
{
    public static SafeRendering Render(string value, FieldKind kind)
    {
        var tokens = Tokenize(value, kind);
        var hasDangerous = tokens.Any(t => t.Class == TokenClass.Dangerous);
        var national = kind == FieldKind.SecurityIdentifier ? Unicode.NationalScripts(value) : new SortedSet<string>();
        var mixed = national.Count > 1;
        var confusable = kind == FieldKind.SecurityIdentifier && Unicode.EnumerateRunes(value).Any(Unicode.IsConfusable);

        var risk = hasDangerous ? RiskLevel.HighRisk
            : kind == FieldKind.FreeText ? RiskLevel.None
            : mixed && confusable ? RiskLevel.HighRisk
            : mixed ? RiskLevel.Warning
            : RiskLevel.None;

        var skeleton = Unicode.Skeleton(value);
        var showTriple = risk != RiskLevel.None || (kind == FieldKind.SecurityIdentifier && skeleton != value);

        return new SafeRendering(value, tokens, risk, showTriple, skeleton, Escape(value), national.ToArray());
    }

    /// <summary>The weakest-channel rendering (plain text): dangerous characters become their
    /// labels, and a risk tag is prefixed. The security invariant lives here — this string can be
    /// shown in Telegram or e-mail with no dangerous character surviving.</summary>
    public static string ToTextMarkers(SafeRendering r)
    {
        var sb = new StringBuilder();
        if (r.Risk == RiskLevel.HighRisk) sb.Append("[!] ");
        else if (r.Risk == RiskLevel.Warning) sb.Append("[?] ");
        foreach (var t in r.Tokens) sb.Append(t.Class == TokenClass.Dangerous ? t.Label : t.Text);
        return sb.ToString();
    }

    private static RenderToken[] Tokenize(string value, FieldKind kind)
    {
        var tokens = new List<RenderToken>();
        var run = new StringBuilder();
        TokenClass runClass = TokenClass.Ascii;
        string? runScript = null;

        void Flush()
        {
            if (run.Length == 0) return;
            tokens.Add(new RenderToken(run.ToString(), runClass, runScript));
            run.Clear();
        }

        foreach (var cp in Unicode.EnumerateRunes(value))
        {
            if (Unicode.IsDangerous(cp))
            {
                Flush();
                tokens.Add(new RenderToken(char.ConvertFromUtf32(cp), TokenClass.Dangerous,
                    Label: $"[{Unicode.CodePoint(cp)} {Unicode.DangerName(cp)}]"));
                continue;
            }

            // Free text: everything non-dangerous is plain text, no per-script colouring.
            if (kind == FieldKind.FreeText)
            {
                if (runClass != TokenClass.Ascii) { Flush(); runClass = TokenClass.Ascii; runScript = null; }
                run.Append(char.ConvertFromUtf32(cp));
                continue;
            }

            // Security identifier: split runs by ASCII vs national script.
            var (cls, script) = cp < 0x80 ? (TokenClass.Ascii, (string?)null) : (TokenClass.Script, Unicode.ScriptOf(cp));
            if (cls != runClass || script != runScript) { Flush(); runClass = cls; runScript = script; }
            run.Append(char.ConvertFromUtf32(cp));
        }
        Flush();
        return tokens.ToArray();
    }

    // A fully unambiguous form: ASCII printable as-is, everything else as \uXXXX / \UXXXXXXXX.
    private static string Escape(string value)
    {
        var sb = new StringBuilder();
        foreach (var cp in Unicode.EnumerateRunes(value))
        {
            if (cp is >= 0x20 and < 0x7F) sb.Append((char)cp);
            else if (cp <= 0xFFFF) sb.Append("\\u").Append(cp.ToString("X4"));
            else sb.Append("\\U").Append(cp.ToString("X8"));
        }
        return sb.ToString();
    }
}
