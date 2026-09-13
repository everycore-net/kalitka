using System.Security.Cryptography;
using Kalitka;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The pluggable signature-suite seam (0.29.0): keys are stored as SPKI, the algorithm is
/// derived from the credential (never the request), a second suite (ECDSA-P256) verifies
/// through the same entry point, legacy raw Ed25519 keys still verify, and the key id is a
/// fingerprint of the key. New enrolment is SPKI-only.
/// </summary>
public class AgentSuiteTests
{
    private static readonly byte[] Msg = AgentSignatures.CanonicalString(
        "POST", "/agent/v1/requests", AgentSignatures.Sha256Hex(new byte[0]), "1700000000", "nonce123");

    // --- Ed25519 ---------------------------------------------------------------
    private static (byte[] rawPub, string spkiB64, Ed25519PrivateKeyParameters priv) NewEd25519()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        var pub = (Ed25519PublicKeyParameters)pair.Public;
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub).GetDerEncoded();
        return (pub.GetEncoded(), Convert.ToBase64String(spki), (Ed25519PrivateKeyParameters)pair.Private);
    }

    private static string SignEd(Ed25519PrivateKeyParameters priv, byte[] msg)
    {
        var s = new Ed25519Signer(); s.Init(true, priv); s.BlockUpdate(msg, 0, msg.Length);
        return Convert.ToBase64String(s.GenerateSignature());
    }

    [Fact]
    public void Ed25519_spki_verifies_and_legacy_raw_still_verifies()
    {
        var (raw, spki, priv) = NewEd25519();
        var sig = SignEd(priv, Msg);
        Assert.True(AgentSignatures.Verify(spki, Msg, sig));                          // modern SPKI
        Assert.True(AgentSignatures.Verify(Convert.ToBase64String(raw), Msg, sig));   // legacy raw 32 bytes
        Assert.False(AgentSignatures.Verify(spki, Msg, Convert.ToBase64String(new byte[64])));
    }

    [Fact]
    public void Same_key_raw_and_spki_share_one_fingerprint_key_id()
    {
        var (raw, spki, _) = NewEd25519();
        Assert.Equal(AgentSignatures.KeyIdFor(Convert.ToBase64String(raw)), AgentSignatures.KeyIdFor(spki));
    }

    [Fact]
    public void Key_id_is_base64url()
    {
        var (_, spki, _) = NewEd25519();
        var id = AgentSignatures.KeyIdFor(spki)!;
        Assert.DoesNotContain('+', id);
        Assert.DoesNotContain('/', id);
        Assert.DoesNotContain('=', id);
    }

    [Fact]
    public void New_enrolment_is_spki_only_but_verify_still_reads_raw()
    {
        var (raw, spki, _) = NewEd25519();
        Assert.True(AgentSignatures.IsValidSpki(spki));                               // SPKI accepted
        Assert.False(AgentSignatures.IsValidSpki(Convert.ToBase64String(raw)));       // raw rejected on enrolment
        Assert.True(AgentSignatures.IsValidPublicKey(Convert.ToBase64String(raw)));   // but still usable (read-compat)
    }

    // --- ECDSA P-256 -----------------------------------------------------------
    [Fact]
    public void Ecdsa_p256_spki_with_p1363_signature_verifies()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo());
        var sig = ec.SignData(Msg, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.Equal(64, sig.Length);                                                 // one representation
        Assert.True(AgentSignatures.Verify(spki, Msg, Convert.ToBase64String(sig)));
        Assert.True(AgentSignatures.IsValidSpki(spki));                               // ECDSA enrols too
    }

    [Fact]
    public void Ecdsa_der_signature_is_rejected_not_sniffed()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo());
        // A DER-encoded signature of the same key/message must NOT verify — only P1363.
        var der = ec.SignData(Msg, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(AgentSignatures.Verify(spki, Msg, Convert.ToBase64String(der)));
    }

    [Fact]
    public void The_suite_is_chosen_from_the_key_not_the_signature()
    {
        // An Ed25519 signature presented against an ECDSA key does not verify: the suite
        // comes from the stored SPKI, so there is no algorithm-confusion downgrade.
        var (_, edSpki, edPriv) = NewEd25519();
        var edSig = SignEd(edPriv, Msg);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSpki = Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo());
        Assert.False(AgentSignatures.Verify(ecSpki, Msg, edSig));
    }
}
