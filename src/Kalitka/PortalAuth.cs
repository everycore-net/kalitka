using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>The signed-in portal user: the operator principal they resolve to, plus the e-mail for
/// display. A principal with no console permission is simply an employee — this session lets them see
/// and ask for their own access, nothing on the control plane.</summary>
public sealed record PortalSession(OperatorPrincipal Principal, string Email, string Actor);

/// <summary>
/// Authentication for the self-service portal (<c>/portal</c>) — a <b>separate</b> population from the
/// admin control plane. It reuses the provider seam (Google/Microsoft/passkey) to prove who you are,
/// then resolves that identity to an <see cref="OperatorPrincipal"/> — and, deliberately, applies no
/// admin allowlist: a portal user is any signed-in person linked to a principal, whether or not they
/// hold any console permission.
///
/// Kept apart from <see cref="AdminAuth"/> on purpose: its own signing purpose (<c>portal:v1</c>) and
/// its own cookie, so a stolen portal cookie is cryptographically useless at <c>/admin</c>, and no
/// control-plane permission check ever has to remember "…but not for portal sessions".
/// </summary>
public sealed class PortalAuth
{
    public const string CookieName = "kalitka_portal";

    private const string SessionKey = "portal:v1";
    private const string StateKey = "portal-state:v1";
    private const string CsrfKey = "portal-csrf:v1";
    private const int StateMinutes = 10;

    private readonly GateOptions _options;
    private readonly IdentityProviders _providers;
    private readonly PrincipalService _principals;
    private readonly TokenSigner _signer;
    private readonly TimeProvider _clock;

    public PortalAuth(IdentityProviders providers, PrincipalService principals, TokenSigner signer,
        IOptions<GateOptions> options, TimeProvider? clock = null)
    {
        _providers = providers;
        _principals = principals;
        _signer = signer;
        _options = options.Value;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>The portal is available if any sign-in provider is configured. No allowlist — access is
    /// decided by whether the person resolves to a principal, not by a list.</summary>
    public bool Enabled => _providers.Any;

    public IReadOnlyList<(string Scheme, string Name)> Providers =>
        _providers.Enabled.Select(p => (p.Scheme, p.DisplayName)).ToList();

    public string RedirectUri => $"https://{_options.GateHost}/portal/oauth2/callback";

    public string LoginUrl(string scheme, string returnPath, string nonce)
    {
        var provider = _providers.ByScheme(scheme);
        if (provider is null) return "/portal/login";
        var exp = _clock.GetUtcNow().AddMinutes(StateMinutes).ToUnixTimeSeconds();
        var state = _signer.Sign($"{exp}|{nonce}|{scheme}|{SafeReturn(returnPath)}", StateKey);
        return provider.AuthorizationUrl(state, RedirectUri);
    }

    /// <summary>The outcome of a callback. <see cref="Authenticated"/> says the provider verified the
    /// person; <see cref="PrincipalId"/> is null when that verified person is not linked to any
    /// principal — the "signed in but no access yet" case the portal refuses by default.</summary>
    public sealed record LoginResult(bool Authenticated, string Scheme = "", string Sub = "", string Email = "",
        string? PrincipalId = null, string ReturnPath = "/portal");

    public async Task<LoginResult> CompleteLogin(string code, string state, string nonce, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(code) || !_signer.Verify(state, StateKey, out var payload)) return new LoginResult(false);
        var parts = payload.Split('|', 4);
        if (parts.Length != 4 || !long.TryParse(parts[0], out var exp)) return new LoginResult(false);
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return new LoginResult(false);
        if (!SessionService.NonceMatches(parts[1], nonce)) return new LoginResult(false);
        var provider = _providers.ByScheme(parts[2]);
        if (provider is null) return new LoginResult(false);
        var returnPath = SafeReturn(parts[3]);

        var identity = await provider.Resolve(code, RedirectUri, ct);
        if (identity is null) return new LoginResult(false);

        var actor = $"{identity.Scheme}:{identity.Subject}";
        var principalId = _principals.Resolve(actor);   // null = authenticated, but no principal
        return new LoginResult(true, identity.Scheme, identity.Subject, identity.Email, principalId, returnPath);
    }

    // ---- Session cookie -----------------------------------------------------

    /// <summary>Mint the portal cookie for a verified identity. It carries the actor
    /// (<c>scheme:sub</c>), never the principal id — the principal is resolved fresh on every read, so
    /// re-linking or removing an identity takes effect at once.</summary>
    public string IssueCookie(string scheme, string sub, string email)
    {
        var expUnix = _clock.GetUtcNow().AddMinutes(_options.AdminSessionMinutes).ToUnixTimeSeconds();
        return _signer.Sign($"{expUnix}|{scheme}|{sub}|{email}", SessionKey);
    }

    public PortalSession? ReadCookie(string? cookie)
    {
        if (string.IsNullOrEmpty(cookie) || !_signer.Verify(cookie, SessionKey, out var payload)) return null;
        var parts = payload.Split('|', 4);
        if (parts.Length != 4 || !long.TryParse(parts[0], out var exp)) return null;
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return null;

        var actor = $"{parts[1]}:{parts[2]}";
        // Resolve the principal fresh: if the identity is no longer linked to anyone, the session is
        // over now — not whenever the cookie happens to expire.
        var principalId = _principals.Resolve(actor);
        if (principalId is null) return null;
        var principal = _principals.Get(principalId);
        if (principal is null) return null;
        return new PortalSession(principal, parts[3], actor);
    }

    public string IssueCsrf(string sub)
    {
        var exp = _clock.GetUtcNow().AddMinutes(_options.AdminSessionMinutes).ToUnixTimeSeconds();
        return _signer.Sign($"{exp}|{sub}", CsrfKey);
    }

    public bool ValidateCsrf(string? token, string sub)
    {
        if (string.IsNullOrEmpty(token) || !_signer.Verify(token, CsrfKey, out var payload)) return false;
        var parts = payload.Split('|', 2);
        if (parts.Length != 2 || !long.TryParse(parts[0], out var exp)) return false;
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return false;
        return parts[1] == sub;
    }

    private static string SafeReturn(string path) =>
        !string.IsNullOrEmpty(path) && path.StartsWith('/') && !path.StartsWith("//") && path.StartsWith("/portal")
            ? path : "/portal";
}
