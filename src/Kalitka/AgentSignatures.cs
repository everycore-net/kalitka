using System.Security.Cryptography;
using System.Text;

namespace Kalitka;

/// <summary>
/// A registered public key for an agent. The stronger successor to the shared per-agent
/// secret: the agent keeps the private key and signs each request, so no reusable secret
/// is ever sent or stored. A key is add-only here; rotation and revocation manage the set.
///
/// <see cref="PublicKey"/> is base64 of the key's <b>SubjectPublicKeyInfo</b> (SPKI), which
/// is self-describing — the algorithm (Ed25519, ECDSA-P256, …) is derived from the key, not
/// declared beside it. Keys registered before SPKI storage are raw 32-byte Ed25519 and are
/// normalised to SPKI on read (see <see cref="AgentSignatures.NormalizeToSpki"/>).
/// </summary>
public sealed record AgentKey(string KeyId, string PublicKey, DateTimeOffset AddedAt)
{
    /// <summary>What the agent observed locally about where the key lives — a claim, NOT a
    /// verified fact: <c>software</c> | <c>windows-platform</c> | <c>apple-secure-enclave</c>
    /// | <c>unknown</c>. Policy must not read this; it is UI context only.</summary>
    public string ProviderHint { get; init; } = "unknown";

    /// <summary>What Core has actually verified about the key: <c>unverified</c> (default,
    /// and the only value until attestation exists) | <c>attested-tpm</c> |
    /// <c>attested-secure-enclave</c>. This is the field a policy may trust.</summary>
    public string Assurance { get; init; } = "unverified";
}

/// <summary>
/// Verification of application-level signed requests — chosen over mTLS because a
/// signed request reaches the app unchanged whatever the reverse proxy does with TLS.
/// The signature covers a canonical string binding the method, path, body hash,
/// timestamp and a nonce, so it cannot be replayed against a different request; a
/// short timestamp window plus a single-use nonce stop replay of the same one.
/// Scheme is versioned (<c>kalitka-agent-sig-v1</c>) so it can evolve.
/// </summary>
public static class AgentSignatures
{
    public const string Scheme = "kalitka-agent-sig-v1";
    public const int MaxSkewSeconds = 300;   // reject timestamps more than 5 min off

    // Ed25519 SPKI = fixed 12-byte prefix + the 32 raw public-key bytes. Used to normalise
    // keys registered before SPKI storage (raw 32 bytes) into the canonical form on read.
    private static readonly byte[] Ed25519SpkiPrefix = Convert.FromHexString("302a300506032b6570032100");

    public static string Sha256Hex(ReadOnlySpan<byte> body) => Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    /// <summary>The key id for a new key: a fingerprint of the key itself,
    /// <c>base64url(SHA-256(SPKI))</c>. Idempotent re-registration of the SAME public key —
    /// and nothing more: it is not a fingerprint of the machine or the TPM (a reinstall makes
    /// a new key, hence a new id). Legacy random ids are left as they are.</summary>
    public static string FingerprintKeyId(ReadOnlySpan<byte> spki) =>
        Convert.ToBase64String(SHA256.HashData(spki)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Normalise a stored public key to canonical SPKI bytes, modern form first:
    /// a strict SPKI parse if any suite recognises it, otherwise a legacy raw 32-byte
    /// Ed25519 key wrapped into SPKI. Null if it is neither. After this, nothing in Core
    /// needs to know a key was ever stored raw.</summary>
    public static byte[]? NormalizeToSpki(string publicKeyBase64)
    {
        byte[] raw;
        try { raw = Convert.FromBase64String(publicKeyBase64); } catch { return null; }
        if (AgentSignatureSuites.For(raw) is not null) return raw;                 // already SPKI
        if (raw.Length == 32) return Ed25519SpkiPrefix.Concat(raw).ToArray();      // legacy raw Ed25519
        return null;
    }

    /// <summary>Strict SPKI validation for NEW enrolment: the key must be SPKI of a known
    /// suite. The raw legacy form is read-compatibility only — never accepted on registration.</summary>
    public static bool IsValidSpki(string publicKeyBase64)
    {
        byte[] spki;
        try { spki = Convert.FromBase64String(publicKeyBase64); } catch { return false; }
        return AgentSignatureSuites.For(spki)?.ValidatePublicKey(spki) == true;
    }

    /// <summary>The fingerprint key id for a stored/registered key (SPKI or legacy raw),
    /// or null if the key is unusable.</summary>
    public static string? KeyIdFor(string publicKeyBase64) =>
        NormalizeToSpki(publicKeyBase64) is { } spki ? FingerprintKeyId(spki) : null;

    /// <summary>The exact bytes a client must sign. Newline-joined, version first, so
    /// there is no ambiguity and no field can be smuggled into another.</summary>
    public static byte[] CanonicalString(string method, string pathAndQuery, string bodyHashHex, string timestamp, string nonce) =>
        Encoding.UTF8.GetBytes(string.Join('\n', Scheme, method.ToUpperInvariant(), pathAndQuery, bodyHashHex, timestamp, nonce));

    /// <summary>True if the key is usable for verification — SPKI of a known suite, or the
    /// legacy raw Ed25519 form. Read-compatibility check; new enrolment uses the stricter
    /// <see cref="IsValidSpki"/>.</summary>
    public static bool IsValidPublicKey(string publicKeyBase64) => NormalizeToSpki(publicKeyBase64) is not null;

    /// <summary>Verify a signature (base64) over <paramref name="message"/> with a stored
    /// public key (SPKI or legacy raw). The suite is chosen from the key's own SPKI, never
    /// the request. False on any malformed input — never throws.</summary>
    public static bool Verify(string publicKeyBase64, byte[] message, string signatureBase64)
    {
        try
        {
            var spki = NormalizeToSpki(publicKeyBase64);
            if (spki is null) return false;
            var sig = Convert.FromBase64String(signatureBase64);
            var suite = AgentSignatureSuites.For(spki);
            return suite is not null && suite.Verify(spki, message, sig);
        }
        catch { return false; }
    }
}
