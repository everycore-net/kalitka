using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Kalitka;

/// <summary>
/// One signer for every signed token in kalitka, keyed by a purpose id. The key
/// for each purpose is derived from the master <c>HmacSecret</c> with HKDF, so a
/// token minted for one purpose can never verify under another — even on a
/// parsing bug, an admin session is not a visitor session is not a one-time
/// capability.
///
/// The API takes the key id as a parameter on purpose:
/// <code>Sign(payload, "admin:v1")</code> / <code>Verify(token, "admin:v1", out …)</code>.
/// Moving another consumer onto its own derived key later is a one-line change at
/// the call site, no new type. Current ids: <c>admin:v1</c>, <c>admin-state:v1</c>
/// (session cookie and one-time capabilities migrate here later).
/// </summary>
public sealed class TokenSigner
{
    private readonly byte[] _master;
    private readonly ConcurrentDictionary<string, byte[]> _derived = new();

    public TokenSigner(string masterSecret) => _master = Encoding.UTF8.GetBytes(masterSecret);

    private byte[] KeyFor(string keyId) => _derived.GetOrAdd(keyId, id =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, _master, outputLength: 32,
            info: Encoding.UTF8.GetBytes("kalitka:" + id)));

    /// <summary>Signs a payload for a purpose, returning <c>{base64url(payload)}.{sig}</c>.</summary>
    public string Sign(string payload, string keyId)
    {
        var body = Base64Url(Encoding.UTF8.GetBytes(payload));
        return $"{body}.{Signature(body, keyId)}";
    }

    /// <summary>Verifies a token for a purpose and returns its payload. Constant-time.</summary>
    public bool Verify(string token, string keyId, out string payload)
    {
        payload = "";
        if (string.IsNullOrEmpty(token)) return false;

        var dot = token.IndexOf('.');
        if (dot <= 0 || dot == token.Length - 1) return false;

        var body = token[..dot];
        var sig = token[(dot + 1)..];

        var expected = Signature(body, keyId);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(sig)))
            return false;

        try { payload = Encoding.UTF8.GetString(Base64UrlDecode(body)); }
        catch { return false; }

        return true;
    }

    private string Signature(string value, string keyId)
    {
        using var hmac = new HMACSHA256(KeyFor(keyId));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
    }
}
