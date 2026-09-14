using System.Globalization;
using System.Text;
using System.Text.Json;

namespace KalitkaMcpGateway;

/// <summary>Raised when input cannot be canonicalised (duplicate object keys, a non-finite
/// number, or malformed JSON). Canonicalisation fails closed: an input that cannot be reduced
/// to one exact form is rejected, never guessed.</summary>
public sealed class JcsException(string message) : Exception(message);

/// <summary>
/// RFC 8785 (JSON Canonicalicalization Scheme) — the security boundary of the MCP gateway. The
/// grant is bound to the SHA-256 of the canonical bytes, so two inputs a human would read as the
/// same call must produce the same bytes, and two different calls must not collide. Objects are
/// sorted by key over UTF-16 code units, strings use the minimal JSON escaping, and numbers use
/// the ECMAScript <c>Number::toString</c> production (not any platform's <c>ToString</c>).
///
/// Two deliberate v1 rules from the design: <b>no schema defaults are applied</b> (the envelope
/// is exactly what the gateway received), and <b>Unicode is NOT normalised</b> — so <c>NFC</c>
/// and <c>NFD</c> forms are different calls at the byte level (the human-facing renderer, a
/// later slice, is what flags confusables). Duplicate keys are rejected.
/// </summary>
public static class Jcs
{
    public static byte[] Canonicalize(string rawJson) => Canonicalize(Encoding.UTF8.GetBytes(rawJson));

    public static byte[] Canonicalize(ReadOnlySpan<byte> rawUtf8Json)
    {
        var reader = new Utf8JsonReader(rawUtf8Json,
            new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 128 });
        if (!reader.Read()) throw new JcsException("empty input");
        var sb = new StringBuilder();
        try { Write(ref reader, sb); }
        catch (JsonException e) { throw new JcsException("malformed JSON: " + e.Message); }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // Canonicalise the value the reader is positioned on, leaving the reader on that value's
    // last token. Objects buffer their members so they can be emitted in sorted key order.
    private static void Write(ref Utf8JsonReader r, StringBuilder sb)
    {
        switch (r.TokenType)
        {
            case JsonTokenType.StartObject:
                var members = new List<(string Key, string Value)>();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                while (r.Read() && r.TokenType != JsonTokenType.EndObject)
                {
                    var key = r.GetString()!;                 // TokenType == PropertyName
                    if (!seen.Add(key)) throw new JcsException($"duplicate object key: {key}");
                    r.Read();                                  // move to the value
                    var child = new StringBuilder();
                    Write(ref r, child);
                    members.Add((key, child.ToString()));
                }
                // RFC 8785: sort by the UTF-16 code units of the key. Ordinal compares char (a
                // UTF-16 code unit) values, which is exactly that.
                members.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));
                sb.Append('{');
                for (var i = 0; i < members.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    EscapeString(members[i].Key, sb);
                    sb.Append(':').Append(members[i].Value);
                }
                sb.Append('}');
                break;

            case JsonTokenType.StartArray:
                sb.Append('[');
                var first = true;
                while (r.Read() && r.TokenType != JsonTokenType.EndArray)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Write(ref r, sb);
                }
                sb.Append(']');
                break;

            case JsonTokenType.String:
                EscapeString(r.GetString()!, sb);
                break;

            case JsonTokenType.Number:
                if (!r.TryGetDouble(out var d) || !double.IsFinite(d))
                    throw new JcsException("number is not a finite IEEE-754 double");
                sb.Append(NumberToJson(d));
                break;

            case JsonTokenType.True: sb.Append("true"); break;
            case JsonTokenType.False: sb.Append("false"); break;
            case JsonTokenType.Null: sb.Append("null"); break;

            default:
                throw new JcsException($"unexpected token {r.TokenType}");
        }
    }

    // RFC 8785 string escaping: only ", \ and the C0 controls are escaped (short escapes where
    // ES defines them, else \u00xx with lowercase hex). Everything else — including all non-ASCII
    // — is emitted literally as UTF-8. No Unicode normalisation.
    private static void EscapeString(string s, StringBuilder sb)
    {
        sb.Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (ch < 0x20) sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>
    /// The ECMAScript <c>Number::toString</c> (base 10) production, per RFC 8785 §3.2.2.3. The
    /// shortest round-tripping digits come from the runtime (identical to V8's, both minimal),
    /// but the <b>formatting</b> — when to use a decimal point, leading zeros, or an exponent —
    /// is applied here exactly per the spec steps, never delegated to a platform
    /// <c>ToString</c>. Conformance is pinned by V8-derived boundary vectors.
    /// </summary>
    public static string NumberToJson(double value)
    {
        if (!double.IsFinite(value)) throw new JcsException("non-finite number");
        if (value == 0.0) return "0";   // also collapses -0 to 0

        var sign = value < 0 ? "-" : "";
        var m = Math.Abs(value);

        // Shortest round-trippable digits from the runtime (Ryū/Grisu — minimal, == V8's).
        var (s, n) = ShortestDigits(m);
        var k = s.Length;

        string body;
        if (k <= n && n <= 21)
            body = s + new string('0', n - k);                        // integer, trailing zeros
        else if (0 < n && n <= 21)
            body = s[..n] + "." + s[n..];                             // decimal point inside digits
        else if (-6 < n && n <= 0)
            body = "0." + new string('0', -n) + s;                    // small: 0.000…digits
        else
        {
            // Exponential: one digit, optional fraction, 'e', signed exponent.
            var mantissa = k == 1 ? s : s[..1] + "." + s[1..];
            var e = n - 1;
            body = mantissa + "e" + (e >= 0 ? "+" : "-") + Math.Abs(e).ToString(CultureInfo.InvariantCulture);
        }
        return sign + body;
    }

    // Decompose |value| into (significant digits s, n) with value = s × 10^(n-k), s having no
    // leading or trailing zeros. The digit sequence is taken from the runtime's shortest
    // round-trip form ("R" is shortest on .NET Core 3+), then re-based; only the formatting
    // above is ours, so the digits match any conforming shortest implementation.
    private static (string s, int n) ShortestDigits(double m)
    {
        var r = m.ToString("R", CultureInfo.InvariantCulture);   // e.g. "1", "1.5", "1E-07", "1.234E+21"
        var exp = 0;
        var ei = r.IndexOf('E');
        if (ei >= 0)
        {
            exp = int.Parse(r[(ei + 1)..], CultureInfo.InvariantCulture);
            r = r[..ei];
        }
        var dot = r.IndexOf('.');
        string intPart, fracPart;
        if (dot >= 0) { intPart = r[..dot]; fracPart = r[(dot + 1)..]; }
        else { intPart = r; fracPart = ""; }

        var digits = intPart + fracPart;
        var point = intPart.Length + exp;   // decimal point sits after this many digits of `digits`

        // Strip leading zeros (each shifts the point left).
        var start = 0;
        while (start < digits.Length - 1 && digits[start] == '0') { start++; point--; }
        digits = digits[start..];
        // Strip trailing zeros (do not move the point).
        var end = digits.Length;
        while (end > 1 && digits[end - 1] == '0') end--;
        digits = digits[..end];

        return (digits, point);
    }
}
