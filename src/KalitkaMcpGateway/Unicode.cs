using System.Globalization;

namespace KalitkaMcpGateway;

/// <summary>
/// The small, <b>pinned</b> Unicode facts the safe renderer needs — script of a code point, whether
/// it is a dangerous (control / bidi / invisible) character, and a confusable skeleton. Deliberately
/// self-contained (no ICU / no runtime Unicode dependency): the confusable table is a curated,
/// version-pinned subset, and the intent is to <i>generate</i> the full table from the official
/// <c>confusables.txt</c> at build for a pinned Unicode version — so a Unicode update is an explicit,
/// reviewed security change, never a surprise shift in behaviour. <see cref="UnicodeVersion"/> records
/// the pin; the published renderer vectors are the conformance contract.
/// </summary>
public static class Unicode
{
    /// <summary>The Unicode version the confusable data is pinned to. Bumping it is a security change.</summary>
    public const string UnicodeVersion = "15.1";

    /// <summary>A code point that must never reach a human as itself — it can reorder, hide, or
    /// impersonate text. Rendered as an explicit labelled token instead.</summary>
    public static bool IsDangerous(int cp) =>
        cp <= 0x1F || cp == 0x7F || (cp is >= 0x80 and <= 0x9F)       // C0 / DEL / C1 controls
        || cp is 0x00AD or 0x061C or 0x034F                          // soft hyphen, Arabic letter mark, CGJ
        || cp is >= 0x200B and <= 0x200F                             // ZWSP, ZWNJ, ZWJ, LRM, RLM
        || cp is >= 0x202A and <= 0x202E                             // LRE RLE PDF LRO RLO
        || cp is >= 0x2060 and <= 0x2064                             // WJ, invisible operators
        || cp is >= 0x2066 and <= 0x2069                             // LRI RLI FSI PDI
        || cp is 0x2028 or 0x2029                                    // line / paragraph separator
        || cp == 0xFEFF                                              // BOM / ZWNBSP
        || cp is >= 0xFFF9 and <= 0xFFFB;                            // interlinear annotation

    /// <summary>A short name for a dangerous code point, for the <c>[U+XXXX NAME]</c> token.</summary>
    public static string DangerName(int cp) => cp switch
    {
        0x09 => "TAB", 0x0A => "LF", 0x0D => "CR", 0x00 => "NUL",
        0x00AD => "SHY", 0x061C => "ALM", 0x034F => "CGJ",
        0x200B => "ZWSP", 0x200C => "ZWNJ", 0x200D => "ZWJ", 0x200E => "LRM", 0x200F => "RLM",
        0x202A => "LRE", 0x202B => "RLE", 0x202C => "PDF", 0x202D => "LRO", 0x202E => "RLO",
        0x2060 => "WJ", 0x2066 => "LRI", 0x2067 => "RLI", 0x2068 => "FSI", 0x2069 => "PDI",
        0x2028 => "LS", 0x2029 => "PS", 0xFEFF => "BOM",
        _ when cp <= 0x1F || cp == 0x7F || (cp is >= 0x80 and <= 0x9F) => "CTRL",
        _ => "?",
    };

    /// <summary>The (coarse) script of a code point — enough to detect script mixing. Digits,
    /// punctuation, spaces and symbols are <c>Common</c> and never count as a national script.</summary>
    public static string ScriptOf(int cp)
    {
        if (cp is (>= 0x41 and <= 0x5A) or (>= 0x61 and <= 0x7A)          // ASCII letters
            or (>= 0xC0 and <= 0x24F) or (>= 0x1E00 and <= 0x1EFF)) return "Latin";
        if (cp is >= 0x370 and <= 0x3FF or (>= 0x1F00 and <= 0x1FFF)) return "Greek";
        if (cp is >= 0x400 and <= 0x52F) return "Cyrillic";
        if (cp is >= 0x590 and <= 0x5FF) return "Hebrew";
        if (cp is >= 0x600 and <= 0x6FF or (>= 0x750 and <= 0x77F)) return "Arabic";
        if (cp is >= 0x4E00 and <= 0x9FFF or (>= 0x3400 and <= 0x4DBF)) return "Han";
        if (cp is >= 0x3040 and <= 0x309F) return "Hiragana";
        if (cp is >= 0x30A0 and <= 0x30FF) return "Katakana";
        if (cp is >= 0xAC00 and <= 0xD7A3 or (>= 0x1100 and <= 0x11FF)) return "Hangul";
        return "Common";
    }

    // A curated, pinned confusable folding to a Latin/ASCII prototype. NOT the full UTS #39 table —
    // it covers the high-value Cyrillic/Greek homoglyphs of ASCII identifiers; the full table is to
    // be generated from confusables.txt at build. Folding only maps non-ASCII to ASCII, never the
    // reverse, so an all-ASCII string is its own skeleton.
    private static readonly Dictionary<int, char> Fold = new()
    {
        // Cyrillic lower
        [0x0430] = 'a', [0x0435] = 'e', [0x043E] = 'o', [0x0440] = 'p', [0x0441] = 'c',
        [0x0443] = 'y', [0x0445] = 'x', [0x0455] = 's', [0x0456] = 'i', [0x0458] = 'j',
        [0x04CF] = 'l', [0x0491] = 'r', [0x043D] = 'h', [0x043C] = 'm', [0x0442] = 't',
        // Cyrillic upper
        [0x0410] = 'A', [0x0412] = 'B', [0x0415] = 'E', [0x041A] = 'K', [0x041C] = 'M',
        [0x041D] = 'H', [0x041E] = 'O', [0x0420] = 'P', [0x0421] = 'C', [0x0422] = 'T',
        [0x0423] = 'Y', [0x0425] = 'X',
        // Greek lower
        [0x03B1] = 'a', [0x03B5] = 'e', [0x03B9] = 'i', [0x03BA] = 'k', [0x03BD] = 'v',
        [0x03BF] = 'o', [0x03C1] = 'p', [0x03C4] = 't', [0x03C7] = 'x', [0x03C5] = 'u',
        // Greek upper
        [0x0391] = 'A', [0x0392] = 'B', [0x0395] = 'E', [0x0396] = 'Z', [0x0397] = 'H',
        [0x0399] = 'I', [0x039A] = 'K', [0x039C] = 'M', [0x039D] = 'N', [0x039F] = 'O',
        [0x03A1] = 'P', [0x03A4] = 'T', [0x03A5] = 'Y', [0x03A7] = 'X',
    };

    /// <summary>True if the code point is a known confusable of an ASCII character.</summary>
    public static bool IsConfusable(int cp) => Fold.ContainsKey(cp);

    /// <summary>The confusable skeleton: each known confusable folded to its ASCII prototype, other
    /// characters left as-is. Two strings with the same skeleton look alike. (A pinned subset — see
    /// the class remarks.)</summary>
    public static string Skeleton(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var r in EnumerateRunes(s))
            sb.Append(Fold.TryGetValue(r, out var c) ? c : char.ConvertFromUtf32(r));
        return sb.ToString();
    }

    /// <summary>The set of national scripts present (excludes Common). Empty or one ⇒ not mixed.</summary>
    public static SortedSet<string> NationalScripts(string s)
    {
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var r in EnumerateRunes(s))
        {
            if (IsDangerous(r)) continue;
            var sc = ScriptOf(r);
            if (sc != "Common") set.Add(sc);
        }
        return set;
    }

    internal static IEnumerable<int> EnumerateRunes(string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                yield return char.ConvertToUtf32(s[i], s[i + 1]);
                i++;
            }
            else yield return s[i];
        }
    }

    internal static string CodePoint(int cp) => "U+" + cp.ToString(cp > 0xFFFF ? "X6" : "X4", CultureInfo.InvariantCulture);
}
