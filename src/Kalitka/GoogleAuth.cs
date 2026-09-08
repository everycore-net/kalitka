using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Google sign-in as the second way in: the people who belong here get through
/// in one click, everyone else still rings the doorbell and waits.
///
/// OAuth 2.0 authorization code flow with a confidential client. The code is
/// exchanged server-side and the identity read from the userinfo endpoint —
/// deliberately no home-grown JWT parsing or JWKS handling: the answer comes
/// straight from Google over TLS in a server-to-server call, so issuer and
/// audience are implied. What is checked is the e-mail, that Google says it is
/// verified, and that it is on the allow list.
/// </summary>
public sealed class GoogleAuth
{
    private readonly HttpClient _http;
    private readonly GateOptions _options;
    private readonly ILogger<GoogleAuth> _log;

    public GoogleAuth(HttpClient http, IOptions<GateOptions> options, ILogger<GoogleAuth> log)
    {
        _http = http;
        _options = options.Value;
        _log = log;
        _http.Timeout = TimeSpan.FromSeconds(10);
    }

    /// <summary>Without a client id and secret the button is not shown at all.</summary>
    public bool Enabled =>
        !string.IsNullOrEmpty(_options.GoogleClientId) &&
        !string.IsNullOrEmpty(_options.GoogleClientSecret);

    private string RedirectUri => $"https://{_options.GateHost}/oauth2/callback";

    public string AuthorizationUrl(string state)
    {
        var query = new Dictionary<string, string>
        {
            ["client_id"]     = _options.GoogleClientId,
            ["redirect_uri"]  = RedirectUri,
            ["response_type"] = "code",
            ["scope"]         = "openid email",
            ["state"]         = state,
            ["prompt"]        = "select_account",
        };

        var qs = string.Join("&", query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

        return "https://accounts.google.com/o/oauth2/v2/auth?" + qs;
    }

    /// <summary>Exchanges the code and returns the verified e-mail, or null.</summary>
    public async Task<string?> ResolveEmail(string code, CancellationToken ct)
    {
        try
        {
            using var tokenResponse = await _http.PostAsync("https://oauth2.googleapis.com/token",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["code"]          = code,
                    ["client_id"]     = _options.GoogleClientId,
                    ["client_secret"] = _options.GoogleClientSecret,
                    ["redirect_uri"]  = RedirectUri,
                    ["grant_type"]    = "authorization_code",
                }), ct);

            if (!tokenResponse.IsSuccessStatusCode)
            {
                _log.LogWarning("Google token endpoint: {Status}", tokenResponse.StatusCode);
                return null;
            }

            using var tokenDoc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync(ct));
            var accessToken = tokenDoc.RootElement.TryGetProperty("access_token", out var at)
                ? at.GetString() : null;
            if (string.IsNullOrEmpty(accessToken)) return null;

            using var request = new HttpRequestMessage(HttpMethod.Get,
                "https://openidconnect.googleapis.com/v1/userinfo");
            request.Headers.Authorization = new("Bearer", accessToken);

            using var userResponse = await _http.SendAsync(request, ct);
            if (!userResponse.IsSuccessStatusCode)
            {
                _log.LogWarning("Google userinfo endpoint: {Status}", userResponse.StatusCode);
                return null;
            }

            using var userDoc = JsonDocument.Parse(await userResponse.Content.ReadAsStringAsync(ct));
            var root = userDoc.RootElement;

            var email = root.TryGetProperty("email", out var e) ? e.GetString() : null;
            var verified = root.TryGetProperty("email_verified", out var v)
                && (v.ValueKind == JsonValueKind.True
                    || (v.ValueKind == JsonValueKind.String && v.GetString() == "true"));

            if (string.IsNullOrEmpty(email) || !verified) return null;
            return email;
        }
        catch (Exception ex)
        {
            _log.LogWarning("Google exchange failed: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>Single addresses first, then whole domains.</summary>
    public bool IsPermitted(string email)
    {
        email = email.Trim().ToLowerInvariant();

        if (_options.GoogleEmails.Any(x => string.Equals(x.Trim(), email, StringComparison.OrdinalIgnoreCase)))
            return true;

        var at = email.LastIndexOf('@');
        if (at < 0) return false;

        var domain = email[(at + 1)..];
        return _options.GoogleDomains.Any(d => string.Equals(d.Trim(), domain, StringComparison.OrdinalIgnoreCase));
    }
}
