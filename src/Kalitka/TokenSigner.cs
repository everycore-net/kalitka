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
    private readonly byte[]? _prev;   // previous master, accepted on VERIFY only, during a rotation window
    private readonly ConcurrentDictionary<string, byte[]> _derived = new();
    private readonly ConcurrentDictionary<string, byte[]> _derivedPrev = new();

    /// <summary>The current master signs and verifies. An optional <paramref name="previousMaster"/>
    /// is accepted on verification only — so rotating the master (set previous = old, master = new)
    /// keeps existing tokens valid through an overlap window instead of logging everyone out at once.
    /// New tokens are always signed with the current master; drop the previous once the window passes.</summary>
    public TokenSigner(string masterSecret, string? previousMaster = null)
    {
        _master = Encoding.UTF8.GetBytes(masterSecret);
        _prev = string.IsNullOrEmpty(previousMaster) ? null : Encoding.UTF8.GetBytes(previousMaster);
    }

    private static byte[] Key(ConcurrentDictionary<string, byte[]> cache, byte[] master, string keyId) =>
        cache.GetOrAdd(keyId, id => HKDF.DeriveKey(HashAlgorithmName.SHA256, master, outputLength: 32,
            info: Encoding.UTF8.GetBytes("kalitka:" + id)));

    /// <summary>Signs a payload for a purpose, returning <c>{base64url(payload)}.{sig}</c>.</summary>
    public string Sign(string payload, string keyId)
    {
        var body = Base64Url(Encoding.UTF8.GetBytes(payload));
        return $"{body}.{Signature(body, keyId, _master, _derived)}";
    }

    /// <summary>Verifies a token for a purpose and returns its payload. Constant-time; accepts the
    /// previous master during a rotation window.</summary>
    public bool Verify(string token, string keyId, out string payload)
    {
        payload = "";
        if (string.IsNullOrEmpty(token)) return false;

        var dot = token.IndexOf('.');
        if (dot <= 0 || dot == token.Length - 1) return false;

        var body = token[..dot];
        var sig = Encoding.UTF8.GetBytes(token[(dot + 1)..]);

        var ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Signature(body, keyId, _master, _derived)), sig);
        if (!ok && _prev is not null)
            ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Signature(body, keyId, _prev, _derivedPrev)), sig);
        if (!ok) return false;

        try { payload = Encoding.UTF8.GetString(Base64UrlDecode(body)); }
        catch { return false; }

        return true;
    }

    private static string Signature(string value, string keyId, byte[] master, ConcurrentDictionary<string, byte[]> cache)
    {
        using var hmac = new HMACSHA256(Key(cache, master, keyId));
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
