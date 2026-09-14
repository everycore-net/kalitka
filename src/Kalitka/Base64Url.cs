namespace Kalitka;

/// <summary>
/// Base64url without padding — the encoding WebAuthn uses on the wire for the challenge, credential
/// id and raw fields (clientDataJSON carries the challenge this way). One implementation so encode
/// and decode cannot drift.
/// </summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
    }

    /// <summary>Decode, or an empty array if the input is not valid base64url — for parsing
    /// attacker-supplied fields where a throw would just be a 500.</summary>
    public static bool TryDecode(string s, out byte[] bytes)
    {
        try { bytes = Decode(s); return true; }
        catch { bytes = Array.Empty<byte>(); return false; }
    }
}
