using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Kalitka;

/// <summary>
/// One public-key signature algorithm, behind a single seam so a second algorithm lands
/// here instead of spreading through the code. Everything works on <b>SubjectPublicKeyInfo</b>
/// (SPKI): the algorithm is <i>derived from the credential</i> (the OID is inside the SPKI),
/// never declared next to it or chosen by the caller — otherwise a caller could pick the
/// suite and turn algorithm confusion into a downgrade. The canonical signed string does not
/// change, so the wire scheme stays <c>kalitka-agent-sig-v1</c>; this is additive.
/// </summary>
public interface IAgentSignatureSuite
{
    /// <summary>A stable label for the suite (diagnostics only; never taken from the wire).</summary>
    string Name { get; }

    /// <summary>True if this suite recognises the SPKI as its own key type.</summary>
    bool CanHandle(ReadOnlySpan<byte> spki);

    /// <summary>True if the SPKI is a well-formed key of this suite's exact type/curve.</summary>
    bool ValidatePublicKey(ReadOnlySpan<byte> spki);

    /// <summary>Verify a signature over <paramref name="message"/>. The suite owns the
    /// semantic difference (Ed25519 signs the message; ECDSA-P256 signs its SHA-256), so
    /// the canonical-request layer above stays identical. Never throws.</summary>
    bool Verify(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
}

/// <summary>Ed25519, the original suite. .NET has no Ed25519, so verification stays on
/// BouncyCastle (server-side only — the Windows agent uses native CNG for its own suite).</summary>
public sealed class Ed25519SignatureSuite : IAgentSignatureSuite
{
    public string Name => "ed25519";
    public bool CanHandle(ReadOnlySpan<byte> spki) => TryKey(spki, out _);
    public bool ValidatePublicKey(ReadOnlySpan<byte> spki) => TryKey(spki, out _);

    public bool Verify(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != 64 || !TryKey(spki, out var key)) return false;
        try
        {
            var v = new Ed25519Signer();
            v.Init(false, key);
            var msg = message.ToArray();
            v.BlockUpdate(msg, 0, msg.Length);
            return v.VerifySignature(signature.ToArray());
        }
        catch { return false; }
    }

    private static bool TryKey(ReadOnlySpan<byte> spki, out Ed25519PublicKeyParameters key)
    {
        key = null!;
        try { if (PublicKeyFactory.CreateKey(spki.ToArray()) is Ed25519PublicKeyParameters e) { key = e; return true; } }
        catch { }
        return false;
    }
}

/// <summary>ECDSA on NIST P-256 with SHA-256. On the wire the signature is IEEE P1363
/// (r‖s), exactly 64 bytes — one representation, never DER: P1363 is 64 opaque bytes so a
/// leading <c>0x30</c> is a plausible value, not a discriminator, and sniffing DER vs P1363
/// is a latent interop bug. CNG produces P1363 natively; the bash client converts OpenSSL's
/// DER to P1363 before sending.</summary>
public sealed class EcdsaP256SignatureSuite : IAgentSignatureSuite
{
    private const string P256Oid = "1.2.840.10045.3.1.7";   // nistP256 / prime256v1

    public string Name => "ecdsa-p256";
    public bool CanHandle(ReadOnlySpan<byte> spki) => Import(spki) is not null;
    public bool ValidatePublicKey(ReadOnlySpan<byte> spki) => Import(spki) is not null;

    public bool Verify(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != 64) return false;   // P-256 P1363 is exactly 64 bytes
        using var ec = Import(spki);
        if (ec is null) return false;
        try { return ec.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch { return false; }
    }

    private static ECDsa? Import(ReadOnlySpan<byte> spki)
    {
        var ec = ECDsa.Create();
        try
        {
            ec.ImportSubjectPublicKeyInfo(spki, out _);   // imports AND validates it is EC
            if (ec.ExportParameters(false).Curve.Oid.Value == P256Oid) return ec;
        }
        catch { }
        ec.Dispose();
        return null;
    }
}

/// <summary>The registered suites, tried in order. The suite for a key is chosen from the
/// key's own SPKI — never from the request — so the algorithm cannot be downgraded by a
/// caller. Add a suite here; nothing else in Core changes.</summary>
public static class AgentSignatureSuites
{
    public static readonly IReadOnlyList<IAgentSignatureSuite> All =
        new IAgentSignatureSuite[] { new Ed25519SignatureSuite(), new EcdsaP256SignatureSuite() };

    public static IAgentSignatureSuite? For(ReadOnlySpan<byte> spki)
    {
        foreach (var s in All) if (s.CanHandle(spki)) return s;
        return null;
    }
}
