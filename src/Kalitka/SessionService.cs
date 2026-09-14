using System.Security.Cryptography;
using System.Text;

namespace Kalitka;

/// <summary>
/// Every signed token kalitka issues — the session cookie and the OAuth state —
/// in one small, pure place. It holds the HMAC key and the clock and nothing
/// else, so the crypto (sign, verify, expiry, scope) can be tested on its own,
/// away from the HTTP pipeline.
///
/// A session token is <c>{exp}:{scope}:{sig}</c>, where <c>scope</c> is a host
/// name or <c>*</c> for every host. The signature covers <c>{exp}:{scope}</c>,
/// so neither the expiry nor the scope can be changed without the key.
/// </summary>
public sealed class SessionService
{
    private readonly byte[] _key;
    private readonly byte[]? _prevKey;   // accepted on verify only, during a rotation window
    private readonly TimeProvider _clock;

    public SessionService(string hmacSecret, TimeProvider clock, string? previousSecret = null)
    {
        _key = Encoding.UTF8.GetBytes(hmacSecret);
        _prevKey = string.IsNullOrEmpty(previousSecret) ? null : Encoding.UTF8.GetBytes(previousSecret);
        _clock = clock;
    }

    /// <summary>A session for one host only.</summary>
    public string BuildHost(string host, int minutes) => Sign($"{Expiry(minutes)}:{host}");

    /// <summary>A session for every host ("*").</summary>
    public string BuildDomain(int minutes) => Sign($"{Expiry(minutes)}:*");

    public bool IsValid(string? token, string host)
    {
        if (string.IsNullOrEmpty(token)) return false;

        var parts = token.Split(':');
        if (parts.Length != 3) return false;
        if (!long.TryParse(parts[0], out var expiry)) return false;
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > expiry) return false;

        if (parts[1] != "*" && !string.Equals(parts[1], host, StringComparison.OrdinalIgnoreCase))
            return false;

        return Matches($"{parts[0]}:{parts[1]}", parts[2]);
    }

    // ---- OAuth state: carries the target + a browser-bound nonce, signed -----
    // The nonce is echoed in a cookie set at login start; the callback requires the
    // two to match, so a state minted for one browser cannot be replayed to force a
    // login in another (login-CSRF). Signed, no server-side storage.

    public string BuildState(string target, string nonce, int minutes = 10)
    {
        var body = $"{_clock.GetUtcNow().AddMinutes(minutes).ToUnixTimeSeconds()}|{nonce}|{target}";
        return $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(body))}.{Signature(body, _key)}";
    }

    public bool TryReadState(string state, string nonce, out string target)
    {
        target = "";
        if (string.IsNullOrEmpty(state)) return false;

        var parts = state.Split('.');
        if (parts.Length != 2) return false;

        string body;
        try { body = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])); }
        catch { return false; }

        if (!Matches(body, parts[1])) return false;

        var fields = body.Split('|', 3);
        if (fields.Length != 3 || !long.TryParse(fields[0], out var expiry)) return false;
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > expiry) return false;
        if (!NonceMatches(fields[1], nonce)) return false;

        target = fields[2];
        return true;
    }

    /// <summary>Constant-time nonce check; an empty cookie nonce never matches.</summary>
    internal static bool NonceMatches(string stateNonce, string cookieNonce) =>
        !string.IsNullOrEmpty(cookieNonce) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(stateNonce), Encoding.UTF8.GetBytes(cookieNonce));

    private long Expiry(int minutes) => _clock.GetUtcNow().AddMinutes(minutes).ToUnixTimeSeconds();

    private string Sign(string body) => $"{body}:{Signature(body, _key)}";

    // Verify against the current key, then the previous one during a rotation window. Constant-time.
    private bool Matches(string value, string providedHex)
    {
        var provided = Encoding.UTF8.GetBytes(providedHex);
        if (CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Signature(value, _key)), provided)) return true;
        return _prevKey is not null
            && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Signature(value, _prevKey)), provided);
    }

    private static string Signature(string value, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }
}
