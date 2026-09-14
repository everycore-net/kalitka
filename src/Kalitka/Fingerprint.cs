using System.Security.Cryptography;
using System.Text;

namespace Kalitka;

/// <summary>
/// A short, human-quotable fingerprint of a key, in the same Crockford base32 alphabet (no I/L/O/U)
/// and dashed shape as the MCP gateway's Call ID — so a person reading one aloud recognises the
/// format, and a device is named the same wherever it appears. Derived from the credential, never a
/// separate counter: two people comparing the fingerprint are comparing the actual key.
/// </summary>
public static class Fingerprint
{
    // Crockford base32, excluding I, L, O, U — unambiguous read aloud. Matches the gateway Call ID.
    private const string Crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>An 8-symbol fingerprint, grouped <c>XXXX-XXXX</c>, of the SHA-256 of the input.</summary>
    public static string Of(ReadOnlySpan<byte> data)
    {
        var hash = SHA256.HashData(data);
        var s = Base32(hash, 8);
        return $"{s[..4]}-{s[4..8]}";
    }

    /// <summary>Fingerprint of a base64-encoded key (e.g. a WebAuthn credential's SPKI).</summary>
    public static string OfBase64(string base64)
    {
        try { return Of(Convert.FromBase64String(base64)); }
        catch { return Of(Encoding.UTF8.GetBytes(base64)); }
    }

    private static string Base32(ReadOnlySpan<byte> data, int symbols)
    {
        var sb = new StringBuilder(symbols);
        int buffer = 0, bits = 0, i = 0;
        while (sb.Length < symbols)
        {
            if (bits < 5) { buffer = (buffer << 8) | (i < data.Length ? data[i++] : 0); bits += 8; }
            bits -= 5;
            sb.Append(Crockford[(buffer >> bits) & 0x1F]);
        }
        return sb.ToString();
    }
}
