using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>The verified operator behind an admin session.</summary>
public sealed record AdminIdentity(string Sub, string Email, string Scheme = "google")
{
    /// <summary>
    /// Typed audit actor keyed on the provider's stable subject (Google's <c>sub</c>, Microsoft's
    /// <c>tid:oid</c>) — <c>scheme:sub</c>, e.g. <c>google:11476…</c> or <c>ms:&lt;tid&gt;:&lt;oid&gt;</c>.
    /// Never the e-mail, which is display/audit identity and can change. Scheme defaults to
    /// <c>google</c> so pre-provider-seam callers and sessions are unchanged.
    /// </summary>
    public string Actor => $"{Scheme}:{Sub}";

    /// <summary>Effective permissions for <b>this request</b>, resolved from the
    /// current config at guard time — never frozen into the cookie, so removing an
    /// address from an allowlist takes effect at once. Empty until the guard fills it.</summary>
    public IReadOnlySet<string> Permissions { get; init; } = new HashSet<string>();

    public bool Can(string permission) => Permissions.Contains(permission);
}

/// <summary>
/// Authentication for the web control plane (<c>/admin</c>). Google OIDC proves
/// who you are; an explicit allowlist decides whether you may operate kalitka;
/// a separate signed cookie carries the admin session. This is deliberately
/// distinct from the visitor Google flow: different allowlist, different signing
/// key (<c>admin:v1</c>), stricter cookie.
///
/// It is not a fallback for Telegram — Telegram approval remains an independent
/// channel. This is the door to the control plane, nothing else.
/// </summary>
public sealed class AdminAuth
{
    public const string CookieName = "kalitka_admin";

    private const string SessionKey = "admin:v1";
    private const string StateKey = "admin-state:v1";
    private const string CsrfKey = "admin-csrf:v1";
    private const int StateMinutes = 10;

    private readonly GateOptions _options;
    private readonly IdentityProviders _providers;
    private readonly TokenSigner _signer;
    private readonly TimeProvider _clock;
    private readonly OperatorApprovers? _approvers;

    public AdminAuth(IdentityProviders providers, TokenSigner signer, IOptions<GateOptions> options,
        TimeProvider? clock = null, OperatorApprovers? approvers = null)
    {
        _providers = providers;
        _signer = signer;
        _options = options.Value;
        _clock = clock ?? TimeProvider.System;
        _approvers = approvers;
    }

    /// <summary>Where a provider sends the admin back — the same URI for every provider (each must
    /// register it), distinguished by the scheme carried in the signed state.</summary>
    public string AdminRedirectUri => $"https://{_options.GateHost}/admin/oauth2/callback";

    /// <summary>The enabled providers, for the login page's buttons.</summary>
    public IReadOnlyList<(string Scheme, string Name)> Providers =>
        _providers.Enabled.Select(p => (p.Scheme, p.DisplayName)).ToList();

    /// <summary>
    /// The plane can log in only if some provider is configured and at least one allowlist is
    /// populated. Neither means fail closed — no admin login.
    /// </summary>
    public bool Enabled =>
        _providers.Any && (_options.AdminEmails.Length > 0 || _options.AdminDomains.Length > 0
            || _options.ApproverEmails.Length > 0 || _options.AgentAdminEmails.Length > 0);

    /// <summary>Permitted to reach the control plane at all — i.e. holds at least one
    /// permission. Kept for the callback/cookie allowlist re-check.</summary>
    public bool IsPermitted(string email) => ResolvePermissions(email).Count > 0;

    /// <summary>
    /// The effective permissions for an address, resolved from the current config.
    /// Full admin (<see cref="GateOptions.AdminEmails"/>/<see cref="GateOptions.AdminDomains"/>)
    /// gets everything; the narrow lists add their bundles; membership is additive
    /// (the union across every list the address matches). Nobody listed → empty.
    /// </summary>
    public IReadOnlySet<string> ResolvePermissions(string email)
    {
        email = email.Trim().ToLowerInvariant();
        if (email.Length == 0) return EmptyPerms;

        if (MatchesFullAdmin(email)) return Perm.All;

        var perms = new HashSet<string>();
        // Static env list, plus operators granted approve rights at runtime (device enrolment).
        if (InList(_options.ApproverEmails, email) || (_approvers?.Contains(email) ?? false))
            perms.UnionWith(Perm.Approver);
        if (InList(_options.AgentAdminEmails, email)) perms.UnionWith(Perm.AgentAdmin);
        return perms;
    }

    private static readonly IReadOnlySet<string> EmptyPerms = new HashSet<string>();

    // Full admin: exact e-mail, or (broader, explicit) whole domain. Fail closed if
    // no full-admin list is configured — but the narrow lists can still grant access.
    private bool MatchesFullAdmin(string email)
    {
        if (InList(_options.AdminEmails, email)) return true;
        if (_options.AdminDomains.Length > 0)
        {
            var at = email.LastIndexOf('@');
            if (at < 0) return false;
            var domain = email[(at + 1)..];
            if (_options.AdminDomains.Any(d => string.Equals(d.Trim(), domain, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    private static bool InList(string[] list, string email) =>
        list.Any(x => string.Equals(x.Trim(), email, StringComparison.OrdinalIgnoreCase));

    // ---- Login --------------------------------------------------------------

    /// <summary>Google authorization URL for admin login, carrying a signed state
    /// with a short life, a browser-bound nonce (echoed in a login cookie), and the
    /// page to return to.</summary>
    public string LoginUrl(string scheme, string returnPath, string nonce)
    {
        var provider = _providers.ByScheme(scheme);
        if (provider is null) return "/admin/login";   // unknown/disabled provider → back to the picker
        var exp = _clock.GetUtcNow().AddMinutes(StateMinutes).ToUnixTimeSeconds();
        var state = _signer.Sign($"{exp}|{nonce}|{scheme}|{SafeReturn(returnPath)}", StateKey);
        return provider.AuthorizationUrl(state, AdminRedirectUri);
    }

    public sealed record LoginResult(bool Ok, AdminIdentity? Identity = null, string ReturnPath = "/admin/dashboard");

    /// <summary>
    /// Completes the callback: state must be intact and unexpired, its nonce must
    /// match the one from the login cookie (so a state cannot be replayed into
    /// another browser — login-CSRF), Google must return a verified identity, and
    /// the e-mail must be on the allowlist.
    /// </summary>
    public async Task<LoginResult> CompleteLogin(string code, string state, string nonce, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(code) || !_signer.Verify(state, StateKey, out var payload))
            return new LoginResult(false);

        var parts = payload.Split('|', 4);
        if (parts.Length != 4 || !long.TryParse(parts[0], out var exp)) return new LoginResult(false);
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return new LoginResult(false);
        if (!SessionService.NonceMatches(parts[1], nonce)) return new LoginResult(false);
        var provider = _providers.ByScheme(parts[2]);
        if (provider is null) return new LoginResult(false);
        var returnPath = SafeReturn(parts[3]);

        var identity = await provider.Resolve(code, AdminRedirectUri, ct);
        if (identity is null || !IsPermitted(identity.Email)) return new LoginResult(false);

        return new LoginResult(true, new AdminIdentity(identity.Subject, identity.Email, identity.Scheme), returnPath);
    }

    // ---- CSRF (stateless, bound to the session subject, with an expiry) ------
    // Bound to the subject and given the same lifetime as the admin session, so a
    // leaked token is not valid forever — it dies with (or before) the session
    // rather than only when HmacSecret is rotated.

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

    // ---- Session cookie -----------------------------------------------------

    public string IssueCookie(AdminIdentity who)
    {
        var exp = _clock.GetUtcNow().AddMinutes(_options.AdminSessionMinutes).ToUnixTimeSeconds();
        // exp|scheme|sub|email — email/sub/scheme carry no '|', and email is last (greedy) so a stray
        // separator cannot shift the earlier fields.
        return _signer.Sign($"{exp}|{who.Scheme}|{who.Sub}|{who.Email}", SessionKey);
    }

    public AdminIdentity? ReadCookie(string? cookie)
    {
        if (string.IsNullOrEmpty(cookie) || !_signer.Verify(cookie, SessionKey, out var payload))
            return null;

        // 4 parts (exp|scheme|sub|email) going forward; 3 parts (exp|sub|email) is a pre-seam Google
        // session, still honoured.
        var parts = payload.Split('|', 4);
        string scheme, sub, email;
        long exp;
        if (parts.Length == 4)
        {
            if (!long.TryParse(parts[0], out exp)) return null;
            scheme = parts[1]; sub = parts[2]; email = parts[3];
        }
        else if (parts.Length == 3)
        {
            if (!long.TryParse(parts[0], out exp)) return null;
            scheme = "google"; sub = parts[1]; email = parts[2];
        }
        else return null;

        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return null;

        // Re-check the allowlist on every read, not just at login: removing someone from the lists
        // revokes their session now, not whenever the cookie happens to expire.
        if (!IsPermitted(email)) return null;

        return new AdminIdentity(sub, email, scheme);
    }

    // Only same-site absolute paths are valid return targets — never an open
    // redirect to another host.
    private static string SafeReturn(string path) =>
        !string.IsNullOrEmpty(path) && path.StartsWith('/') && !path.StartsWith("//")
            ? path : "/admin/dashboard";
}
