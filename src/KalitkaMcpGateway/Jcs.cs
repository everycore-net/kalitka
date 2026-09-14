using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace KalitkaMcpGateway;

/// <summary>Raised when input cannot be canonicalised — duplicate keys, a non-finite or unsafe
/// number, a lone surrogate, a size/complexity limit, or malformed JSON. Canonicalisation fails
/// closed: an input that cannot be reduced to one exact, faithfully-representable form is rejected.</summary>
public sealed class JcsException(string message) : Exception(message);

/// <summary>
/// RFC 8785 (JSON Canonicalicalization Scheme) — the security boundary of the MCP gateway, hardened
/// against hostile input. The grant binds to the SHA-256 of the canonical bytes, and the gateway
/// forwards <b>those same bytes</b> to the upstream, so what a human approved is exactly what runs.
///
/// Objects are sorted by UTF-16 code units, strings use minimal JSON escaping, and numbers use the
/// ECMAScript <c>Number::toString</c> production (not any platform <c>ToString</c>). Two v1 rules,
/// both fail-safe: no schema defaults (absent ≠ null) and no Unicode normalisation (NFC ≠ NFD).
/// Rejected: duplicate object keys, non-finite numbers, <b>unsafe integers</b> (beyond ±(2^53−1) —
/// these must travel as strings, per I-JSON), lone UTF-16 surrogates, and anything over the input /
/// node / string / depth limits.
/// </summary>
public static class Jcs
{
    public const int MaxInputBytes = 256 * 1024;
    public const int MaxNodes = 10_000;
    public const int MaxStringChars = 64 * 1024;
    public const int MaxDepth = 32;
    private const long MaxSafeInteger = 9_007_199_254_740_991;   // 2^53 - 1 (I-JSON)

    public static byte[] Canonicalize(string rawJson) => Canonicalize(Encoding.UTF8.GetBytes(rawJson));

    public static byte[] Canonicalize(ReadOnlySpan<byte> rawUtf8Json)
    {
        if (rawUtf8Json.Length > MaxInputBytes) throw new JcsException($"input exceeds {MaxInputBytes} bytes");
        var reader = new Utf8JsonReader(rawUtf8Json,
            new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = MaxDepth });
        if (!reader.Read()) throw new JcsException("empty input");
        var sb = new StringBuilder();
        var budget = new Budget();
        try
        {
            Write(ref reader, sb, budget);
            if (reader.Read()) throw new JcsException("trailing content after the JSON value");
        }
        catch (JsonException e) { throw new JcsException("malformed JSON: " + e.Message); }
        catch (InvalidOperationException e) { throw new JcsException("invalid JSON value: " + e.Message); }   // e.g. lone surrogate transcoding
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private sealed class Budget { public int Nodes; }

    private static void Write(ref Utf8JsonReader r, StringBuilder sb, Budget budget)
    {
        if (++budget.Nodes > MaxNodes) throw new JcsException($"input exceeds {MaxNodes} nodes");
        switch (r.TokenType)
        {
            case JsonTokenType.StartObject:
                var members = new List<(string Key, string Value)>();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                while (r.Read() && r.TokenType != JsonTokenType.EndObject)
                {
                    var key = r.GetString()!;
                    RejectLoneSurrogates(key);
                    if (!seen.Add(key)) throw new JcsException($"duplicate object key: {key}");
                    r.Read();
                    var child = new StringBuilder();
                    Write(ref r, child, budget);
                    members.Add((key, child.ToString()));
                }
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
                    Write(ref r, sb, budget);
                }
                sb.Append(']');
                break;

            case JsonTokenType.String:
                var s = r.GetString()!;
                if (s.Length > MaxStringChars) throw new JcsException($"string exceeds {MaxStringChars} chars");
                RejectLoneSurrogates(s);
                EscapeString(s, sb);
                break;

            case JsonTokenType.Number:
                sb.Append(NumberToJson(SafeNumber(ref r)));
                break;

            case JsonTokenType.True: sb.Append("true"); break;
            case JsonTokenType.False: sb.Append("false"); break;
            case JsonTokenType.Null: sb.Append("null"); break;

            default:
                throw new JcsException($"unexpected token {r.TokenType}");
        }
    }

    // A number the gateway will faithfully carry: a finite double, and — if written as an integer —
    // within the I-JSON safe range. An unsafe integer must travel as a string, so that an upstream
    // reading Int64/BigInteger can never see a value different from what was fingerprinted.
    private static double SafeNumber(ref Utf8JsonReader r)
    {
        if (!r.TryGetDouble(out var d) || !double.IsFinite(d))
            throw new JcsException("number is not a finite IEEE-754 double");
        var raw = Encoding.UTF8.GetString(r.HasValueSequence ? r.ValueSequence.ToArray() : r.ValueSpan.ToArray());
        var isInteger = raw.AsSpan().IndexOfAny('.', 'e', 'E') < 0;
        if (isInteger && BigInteger.Abs(BigInteger.Parse(raw, CultureInfo.InvariantCulture)) > MaxSafeInteger)
            throw new JcsException("unsafe integer (beyond 2^53-1); send it as a string");
        return d;
    }

    private static void RejectLoneSurrogates(string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])) throw new JcsException("lone high surrogate");
                i++;   // valid pair
            }
            else if (char.IsLowSurrogate(s[i])) throw new JcsException("lone low surrogate");
        }
    }

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
    /// shortest round-tripping digits come from the runtime (identical to V8's, both minimal), but
    /// the <b>formatting</b> is applied here exactly per the spec steps, never delegated to a platform
    /// <c>ToString</c>. Conformance is pinned by V8-derived boundary vectors.
    /// </summary>
    public static string NumberToJson(double value)
    {
        if (!double.IsFinite(value)) throw new JcsException("non-finite number");
        if (value == 0.0) return "0";   // also collapses -0 to 0

        var sign = value < 0 ? "-" : "";
        var (s, n) = ShortestDigits(Math.Abs(value));
        var k = s.Length;

        string body;
        if (k <= n && n <= 21) body = s + new string('0', n - k);
        else if (0 < n && n <= 21) body = s[..n] + "." + s[n..];
        else if (-6 < n && n <= 0) body = "0." + new string('0', -n) + s;
        else
        {
            var mantissa = k == 1 ? s : s[..1] + "." + s[1..];
            var e = n - 1;
            body = mantissa + "e" + (e >= 0 ? "+" : "-") + Math.Abs(e).ToString(CultureInfo.InvariantCulture);
        }
        return sign + body;
    }

    private static (string s, int n) ShortestDigits(double m)
    {
        var r = m.ToString("R", CultureInfo.InvariantCulture);
        var exp = 0;
        var ei = r.IndexOf('E');
        if (ei >= 0) { exp = int.Parse(r[(ei + 1)..], CultureInfo.InvariantCulture); r = r[..ei]; }
        var dot = r.IndexOf('.');
        string intPart, fracPart;
        if (dot >= 0) { intPart = r[..dot]; fracPart = r[(dot + 1)..]; }
        else { intPart = r; fracPart = ""; }

        var digits = intPart + fracPart;
        var point = intPart.Length + exp;
        var start = 0;
        while (start < digits.Length - 1 && digits[start] == '0') { start++; point--; }
        digits = digits[start..];
        var end = digits.Length;
        while (end > 1 && digits[end - 1] == '0') end--;
        digits = digits[..end];
        return (digits, point);
    }
}
