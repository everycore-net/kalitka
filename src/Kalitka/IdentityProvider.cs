namespace Kalitka;

/// <summary>
/// An identity proven by a provider's OIDC round-trip: the stable subject key, the display e-mail,
/// and which provider vouched for it. The <see cref="Actor"/> — <c>scheme:subject</c> — is what the
/// audit log, the operator principals and the quorum key on. Provider-neutral by construction: a new
/// provider is a new <see cref="Scheme"/>, nothing downstream changes.
///
/// The subject is the provider's <b>stable</b> id, not the e-mail (which can change): Google's
/// <c>sub</c>, Microsoft's <c>tid:oid</c>. The e-mail is for display and for matching the admin
/// allowlist, never for keying identity.
/// </summary>
public sealed record ProvenIdentity(string Scheme, string Subject, string Email)
{
    public string Actor => $"{Scheme}:{Subject}";
}

/// <summary>
/// One sign-in provider behind the control plane (Google, Microsoft/Entra, later Okta/Keycloak). The
/// seam is deliberately thin: build an authorization URL, and exchange the returned code for a proven
/// identity. Provider-specific safety (which tenants/domains may even authenticate) lives inside the
/// provider's <see cref="Resolve"/>, so the layers above stay provider-agnostic.
/// </summary>
public interface IIdentityProvider
{
    /// <summary>Stable scheme prefix used in the actor string: <c>google</c>, <c>ms</c>, …</summary>
    string Scheme { get; }

    /// <summary>Human label for the sign-in button.</summary>
    string DisplayName { get; }

    /// <summary>Configured enough to be offered (client id + secret present).</summary>
    bool Enabled { get; }

    string AuthorizationUrl(string state, string redirectUri);

    /// <summary>Exchange the authorization code for a proven identity, or null if the exchange fails
    /// or the caller is not allowed to authenticate here (e.g. an untrusted Entra tenant).</summary>
    Task<ProvenIdentity?> Resolve(string code, string redirectUri, CancellationToken ct);
}

/// <summary>The enabled providers, resolvable by scheme — the registry the admin plane dispatches
/// through. Also the single source for "is any sign-in configured".</summary>
public sealed class IdentityProviders
{
    private readonly IReadOnlyList<IIdentityProvider> _all;

    public IdentityProviders(IEnumerable<IIdentityProvider> providers) => _all = providers.ToList();

    /// <summary>The providers currently offerable, in registration order.</summary>
    public IReadOnlyList<IIdentityProvider> Enabled => _all.Where(p => p.Enabled).ToList();

    public bool Any => _all.Any(p => p.Enabled);

    /// <summary>The enabled provider for a scheme, or null.</summary>
    public IIdentityProvider? ByScheme(string scheme) =>
        _all.FirstOrDefault(p => p.Enabled && string.Equals(p.Scheme, scheme, StringComparison.Ordinal));
}
