using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Microsoft / Entra sign-in — the second control-plane provider, for the many organisations (the
/// German mid-market especially) that live on Microsoft 365 and have no Google. OIDC authorization
/// code flow; the code is exchanged server-side and the identity read from the <c>id_token</c> the
/// token endpoint returns over TLS (no JWKS handling, same trust model as the Google path: the answer
/// comes straight from the provider in a server-to-server call).
///
/// Three Entra facts drive the design (owner review):
/// <list type="bullet">
/// <item>The stable identity is <c>tid+oid</c>, not the e-mail/UPN (which change) — so the actor is
/// <c>ms:&lt;tid&gt;:&lt;oid&gt;</c> and the e-mail is only for display and allowlist matching.</item>
/// <item>Multi-tenant is dangerous: with an <c>organizations</c>/<c>common</c> authority any Microsoft
/// account can complete the flow, so <see cref="GateOptions.MicrosoftAllowedTenants"/> gates the
/// tenant here; a single-tenant authority (a tid) is the safe default.</item>
/// <item>Each installer registers their own app and consents — nothing shared.</item>
/// </list>
/// </summary>
public class MicrosoftAuth : IIdentityProvider
{
    private readonly HttpClient _http;
    private readonly GateOptions _options;
    private readonly ILogger<MicrosoftAuth> _log;

    public MicrosoftAuth(HttpClient http, IOptions<GateOptions> options, ILogger<MicrosoftAuth> log)
    {
        _http = http;
        _options = options.Value;
        _log = log;
        _http.Timeout = TimeSpan.FromSeconds(10);
    }

    public string Scheme => "ms";
    public string DisplayName => "Microsoft";

    public bool Enabled =>
        !string.IsNullOrEmpty(_options.MicrosoftClientId) &&
        !string.IsNullOrEmpty(_options.MicrosoftClientSecret);

    private string Tenant => string.IsNullOrWhiteSpace(_options.MicrosoftTenant) ? "organizations" : _options.MicrosoftTenant.Trim();
    private string Authority => $"https://login.microsoftonline.com/{Tenant}";

    public string AuthorizationUrl(string state, string redirectUri)
    {
        var query = new Dictionary<string, string>
        {
            ["client_id"]     = _options.MicrosoftClientId,
            ["redirect_uri"]  = redirectUri,
            ["response_type"] = "code",
            ["response_mode"] = "query",
            ["scope"]         = "openid email profile",
            ["state"]         = state,
            ["prompt"]        = "select_account",
        };
        var qs = string.Join("&", query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return $"{Authority}/oauth2/v2.0/authorize?" + qs;
    }

    public virtual async Task<ProvenIdentity?> Resolve(string code, string redirectUri, CancellationToken ct)
    {
        try
        {
            using var tokenResponse = await _http.PostAsync($"{Authority}/oauth2/v2.0/token",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["code"]          = code,
                    ["client_id"]     = _options.MicrosoftClientId,
                    ["client_secret"] = _options.MicrosoftClientSecret,
                    ["redirect_uri"]  = redirectUri,
                    ["grant_type"]    = "authorization_code",
                    ["scope"]         = "openid email profile",
                }), ct);

            if (!tokenResponse.IsSuccessStatusCode)
            {
                _log.LogWarning("Microsoft token endpoint: {Status}", tokenResponse.StatusCode);
                return null;
            }

            using var tokenDoc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync(ct));
            var idToken = tokenDoc.RootElement.TryGetProperty("id_token", out var it) ? it.GetString() : null;
            if (string.IsNullOrEmpty(idToken)) return null;

            return FromIdToken(idToken);
        }
        catch (Exception ex)
        {
            _log.LogWarning("Microsoft exchange failed: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>Read tid/oid/e-mail from the id_token's claims (its payload segment), then gate the
    /// tenant. The token came directly from the token endpoint over TLS, so the payload is trusted
    /// without signature verification — the same server-to-server trust the Google path relies on.
    /// Split out so tenant gating is unit-testable without a live Entra.</summary>
    public ProvenIdentity? FromIdToken(string idToken)
    {
        var parts = idToken.Split('.');
        if (parts.Length < 2) return null;
        JsonElement claims;
        try { claims = JsonDocument.Parse(Base64Url.Decode(parts[1])).RootElement; }
        catch { return null; }

        var tid = Str(claims, "tid");
        var oid = Str(claims, "oid");
        if (string.IsNullOrEmpty(tid) || string.IsNullOrEmpty(oid)) return null;

        // Tenant gate: with a multi-tenant authority this is what stops any Microsoft account.
        if (_options.MicrosoftAllowedTenants.Length > 0 &&
            !_options.MicrosoftAllowedTenants.Any(t => string.Equals(t.Trim(), tid, StringComparison.OrdinalIgnoreCase)))
        {
            _log.LogWarning("Microsoft sign-in from disallowed tenant {Tid}", tid);
            return null;
        }
        if (_options.MicrosoftAllowedTenants.Length == 0 && Tenant is "common" or "organizations" or "consumers")
            _log.LogWarning("Microsoft authority is multi-tenant and MicrosoftAllowedTenants is empty — "
                + "any tenant can authenticate; only the admin allowlist gates access.");

        // Display e-mail: email claim, else UPN / preferred_username. Never keys identity.
        var email = Str(claims, "email");
        if (string.IsNullOrEmpty(email)) email = Str(claims, "preferred_username");
        if (string.IsNullOrEmpty(email)) email = Str(claims, "upn");

        return new ProvenIdentity(Scheme, $"{tid}:{oid}", email ?? "");
    }

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
