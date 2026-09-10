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
    private readonly TimeProvider _clock;

    public SessionService(string hmacSecret, TimeProvider clock)
    {
        _key = Encoding.UTF8.GetBytes(hmacSecret);
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

        var expected = Signature($"{parts[0]}:{parts[1]}");
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(parts[2]));
    }

    // ---- OAuth state: carries the target, signed, no storage ----------------

    public string BuildState(string target, int minutes = 10)
    {
        var body = $"{_clock.GetUtcNow().AddMinutes(minutes).ToUnixTimeSeconds()}|{target}";
        return $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(body))}.{Signature(body)}";
    }

    public bool TryReadState(string state, out string target)
    {
        target = "";
        if (string.IsNullOrEmpty(state)) return false;

        var parts = state.Split('.');
        if (parts.Length != 2) return false;

        string body;
        try { body = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])); }
        catch { return false; }

        var expected = Signature(body);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(parts[1])))
            return false;

        var fields = body.Split('|', 2);
        if (fields.Length != 2 || !long.TryParse(fields[0], out var expiry)) return false;
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > expiry) return false;

        target = fields[1];
        return true;
    }

    private long Expiry(int minutes) => _clock.GetUtcNow().AddMinutes(minutes).ToUnixTimeSeconds();

    private string Sign(string body) => $"{body}:{Signature(body)}";

    private string Signature(string value)
    {
        using var hmac = new HMACSHA256(_key);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }
}
