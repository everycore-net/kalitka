using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>The verified operator behind an admin session.</summary>
public sealed record AdminIdentity(string Sub, string Email)
{
    /// <summary>Typed audit actor, e.g. <c>google:sergej@example.com</c>.</summary>
    public string Actor => $"google:{Email}";
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
    private readonly GoogleAuth _google;
    private readonly TokenSigner _signer;
    private readonly TimeProvider _clock;

    public AdminAuth(GoogleAuth google, TokenSigner signer, IOptions<GateOptions> options, TimeProvider? clock = null)
    {
        _google = google;
        _signer = signer;
        _options = options.Value;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>
    /// The plane can log in only if Google is configured and at least one
    /// allowlist is populated. Neither list means fail closed — no admin login.
    /// </summary>
    public bool Enabled =>
        _google.Enabled && (_options.AdminEmails.Length > 0 || _options.AdminDomains.Length > 0);

    /// <summary>
    /// Emails are the primary mechanism (exact match); domains are the broader,
    /// explicit mode. With neither populated nobody is permitted.
    /// </summary>
    public bool IsPermitted(string email)
    {
        email = email.Trim().ToLowerInvariant();
        if (email.Length == 0) return false;

        var hasEmails = _options.AdminEmails.Length > 0;
        var hasDomains = _options.AdminDomains.Length > 0;
        if (!hasEmails && !hasDomains) return false;   // fail closed

        if (hasEmails && _options.AdminEmails.Any(x =>
                string.Equals(x.Trim(), email, StringComparison.OrdinalIgnoreCase)))
            return true;

        if (hasDomains)
        {
            var at = email.LastIndexOf('@');
            if (at < 0) return false;
            var domain = email[(at + 1)..];
            if (_options.AdminDomains.Any(d =>
                    string.Equals(d.Trim(), domain, StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        return false;
    }

    // ---- Login --------------------------------------------------------------

    /// <summary>Google authorization URL for admin login, carrying a signed state
    /// with a short life and the page to return to.</summary>
    public string LoginUrl(string returnPath)
    {
        var exp = _clock.GetUtcNow().AddMinutes(StateMinutes).ToUnixTimeSeconds();
        var state = _signer.Sign($"{exp}|{SafeReturn(returnPath)}", StateKey);
        return _google.AuthorizationUrl(state, _google.AdminRedirectUri);
    }

    public sealed record LoginResult(bool Ok, AdminIdentity? Identity = null, string ReturnPath = "/admin/dashboard");

    /// <summary>
    /// Completes the callback: state must be intact and unexpired, Google must
    /// return a verified identity, and the e-mail must be on the allowlist.
    /// </summary>
    public async Task<LoginResult> CompleteLogin(string code, string state, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(code) || !_signer.Verify(state, StateKey, out var payload))
            return new LoginResult(false);

        var parts = payload.Split('|', 2);
        if (parts.Length != 2 || !long.TryParse(parts[0], out var exp)) return new LoginResult(false);
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return new LoginResult(false);
        var returnPath = SafeReturn(parts[1]);

        var identity = await _google.ResolveIdentity(code, _google.AdminRedirectUri, ct);
        if (identity is null || !IsPermitted(identity.Value.Email)) return new LoginResult(false);

        return new LoginResult(true, new AdminIdentity(identity.Value.Sub, identity.Value.Email), returnPath);
    }

    // ---- CSRF (stateless, bound to the session subject) ---------------------

    public string IssueCsrf(string sub) => _signer.Sign(sub, CsrfKey);

    public bool ValidateCsrf(string? token, string sub) =>
        !string.IsNullOrEmpty(token) && _signer.Verify(token, CsrfKey, out var s) && s == sub;

    // ---- Session cookie -----------------------------------------------------

    public string IssueCookie(AdminIdentity who)
    {
        var exp = _clock.GetUtcNow().AddMinutes(_options.AdminSessionMinutes).ToUnixTimeSeconds();
        // Email carries a '|'? It cannot — addresses have no pipe; still, sub is
        // first and email last so a stray separator cannot shift the subject.
        return _signer.Sign($"{exp}|{who.Sub}|{who.Email}", SessionKey);
    }

    public AdminIdentity? ReadCookie(string? cookie)
    {
        if (string.IsNullOrEmpty(cookie) || !_signer.Verify(cookie, SessionKey, out var payload))
            return null;

        var parts = payload.Split('|', 3);
        if (parts.Length != 3 || !long.TryParse(parts[0], out var exp)) return null;
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > exp) return null;

        return new AdminIdentity(parts[1], parts[2]);
    }

    // Only same-site absolute paths are valid return targets — never an open
    // redirect to another host.
    private static string SafeReturn(string path) =>
        !string.IsNullOrEmpty(path) && path.StartsWith('/') && !path.StartsWith("//")
            ? path : "/admin/dashboard";
}
