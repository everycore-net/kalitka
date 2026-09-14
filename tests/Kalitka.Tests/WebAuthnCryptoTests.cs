using System.Security.Cryptography;
using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The WebAuthn wire parsing and COSE→SPKI conversion, checked against keys and signatures produced
/// by a real P-256 authenticator — the conversions must land a passkey on the same signature suites
/// that verify agents.
/// </summary>
public class WebAuthnCryptoTests
{
    [Fact]
    public void A_cose_ec2_key_converts_to_an_spki_the_p256_suite_accepts()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var auth = new SoftAuthenticator();   // holds its own key; register to get an attestation
        var (att, _) = auth.Register("gate.example.com", "https://gate.example.com", SoftAuthenticator.B64u(new byte[32]));
        var ad = WebAuthn.ParseAttestationObject(Base64Url.Decode(att));
        var (spki, alg) = WebAuthn.CoseKeyToSpki(ad.CosePublicKey!);

        Assert.Equal(-7, alg);
        var suite = AgentSignatureSuites.For(Convert.FromBase64String(spki));
        Assert.NotNull(suite);
        Assert.Equal("ecdsa-p256", suite!.Name);
        Assert.True(suite.ValidatePublicKey(Convert.FromBase64String(spki)));
    }

    [Fact]
    public void A_der_signature_converts_to_p1363_and_verifies_through_the_suite()
    {
        var auth = new SoftAuthenticator();
        var challenge = SoftAuthenticator.B64u(RandomNumberGenerator.GetBytes(32));
        // Register to capture this authenticator's SPKI, then sign an assertion.
        var (att, _) = auth.Register("gate.example.com", "https://gate.example.com", challenge);
        var spki = Convert.FromBase64String(WebAuthn.CoseKeyToSpki(
            WebAuthn.ParseAttestationObject(Base64Url.Decode(att)).CosePublicKey!).SpkiBase64);

        var (_, adB64, cdjB64, sigDerB64) = auth.Sign("gate.example.com", "https://gate.example.com", challenge, 1);
        var message = WebAuthn.SignedMessage(Base64Url.Decode(adB64), Base64Url.Decode(cdjB64));
        var p1363 = WebAuthn.DerToP1363(Base64Url.Decode(sigDerB64));

        var suite = AgentSignatureSuites.For(spki)!;
        Assert.True(suite.Verify(spki, message, p1363));
        // A flipped bit must not verify.
        p1363[0] ^= 0xFF;
        Assert.False(suite.Verify(spki, message, p1363));
    }

    [Fact]
    public void Authenticator_data_flags_and_counter_parse()
    {
        var auth = new SoftAuthenticator { BackupEligible = true };
        var (_, adB64, _, _) = auth.Sign("gate.example.com", "https://gate.example.com",
            SoftAuthenticator.B64u(new byte[32]), signCount: 42);
        var ad = WebAuthn.ParseAuthData(Base64Url.Decode(adB64));

        Assert.True(ad.UserPresent);
        Assert.True(ad.UserVerified);
        Assert.True(ad.BackupEligible);
        Assert.Equal(42u, ad.SignCount);
        Assert.False(ad.AttestedData);   // an assertion carries no attested credential data
    }

    [Fact]
    public void Client_data_parses_type_challenge_origin()
    {
        var auth = new SoftAuthenticator();
        var (_, _, cdjB64, _) = auth.Sign("gate.example.com", "https://gate.example.com", "Q0hBTExFTkdF", 1);
        var cd = WebAuthn.ParseClientData(Base64Url.Decode(cdjB64));
        Assert.Equal("webauthn.get", cd.Type);
        Assert.Equal("Q0hBTExFTkdF", cd.Challenge);
        Assert.Equal("https://gate.example.com", cd.Origin);
    }

    [Fact]
    public void A_truncated_authenticator_data_is_rejected_not_crashed()
    {
        Assert.Throws<WebAuthnException>(() => WebAuthn.ParseAuthData(new byte[10]));
    }
}
