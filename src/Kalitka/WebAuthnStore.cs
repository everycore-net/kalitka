using System.Text.Json;

namespace Kalitka;

/// <summary>
/// One registered passkey/security key: what we need to verify a future assertion and to reason
/// about its assurance. The public key is stored as base64 SPKI so the same
/// <see cref="IAgentSignatureSuite"/> that verifies agents verifies passkeys. <see
/// cref="BackupEligible"/> records the WebAuthn BE flag — a cloud-synced credential is not
/// device-bound, which policy may refuse for high-assurance approvals.
/// </summary>
public sealed record WebAuthnCredential(
    string CredentialId,     // base64url, as the browser reports it
    string PublicKeySpki,    // base64 (standard) SubjectPublicKeyInfo
    int Alg,                 // COSE algorithm id: -7 ES256, -8 EdDSA
    long SignCount,
    string PrincipalId,      // the operator principal this device belongs to
    string DisplayName,
    bool BackupEligible,
    string CreatedAt,
    string LastUsedAt)
{
    /// <summary>The channel identity a decision from this device carries, so the quorum counts it
    /// as its owner (linked to the principal at registration).</summary>
    public string Identity => "app:" + CredentialId;

    /// <summary>A short human-quotable fingerprint of the device's key (gateway Call-ID alphabet), so
    /// the person can verify the right device bound and it is named the same everywhere.</summary>
    public string Fingerprint => Kalitka.Fingerprint.OfBase64(PublicKeySpki);
}

/// <summary>
/// Where registered credentials live — one JSON blob in the shared <see cref="IConfigStore"/>, the
/// same durable, cluster-wide home as operator principals. Mirrors <see cref="PrincipalService"/>:
/// a small, rarely-written set behind an atomic read-modify-write.
/// </summary>
public sealed class WebAuthnStore
{
    private const string Key = "webauthn-credentials";
    private readonly IConfigStore _config;

    public WebAuthnStore(IConfigStore config) => _config = config;

    public IReadOnlyList<WebAuthnCredential> All() => Parse(_config.Get(Key));

    public WebAuthnCredential? ByCredentialId(string credentialId) =>
        All().FirstOrDefault(c => string.Equals(c.CredentialId, credentialId, StringComparison.Ordinal));

    public IReadOnlyList<WebAuthnCredential> ForPrincipal(string principalId) =>
        All().Where(c => string.Equals(c.PrincipalId, principalId, StringComparison.OrdinalIgnoreCase)).ToList();

    public void Add(WebAuthnCredential cred)
    {
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur).Where(c => c.CredentialId != cred.CredentialId).ToList();
            list.Add(cred);
            return JsonSerializer.Serialize(list);
        });
    }

    /// <summary>Advance the stored signature counter after a verified assertion (clone detection is
    /// done by the caller before calling this).</summary>
    public void RecordUse(string credentialId, long newSignCount, string usedAt)
    {
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            for (var i = 0; i < list.Count; i++)
                if (list[i].CredentialId == credentialId)
                    list[i] = list[i] with { SignCount = newSignCount, LastUsedAt = usedAt };
            return JsonSerializer.Serialize(list);
        });
    }

    public bool Remove(string credentialId)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            removed = list.RemoveAll(c => c.CredentialId == credentialId) > 0;
            return JsonSerializer.Serialize(list);
        });
        return removed;
    }

    private static List<WebAuthnCredential> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<WebAuthnCredential>>(blob) ?? new());
}
