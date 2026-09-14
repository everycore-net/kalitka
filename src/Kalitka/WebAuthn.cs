using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kalitka;

/// <summary>Anything malformed in an attacker-supplied WebAuthn payload throws this; the endpoint
/// turns it into a 4xx, never a 500.</summary>
public sealed class WebAuthnException(string message) : Exception(message);

/// <summary>Parsed authenticator data (RFC WebAuthn §6.1): the RP-ID hash, the flags, the signature
/// counter, and — on a registration — the newly created credential id and its COSE public key.</summary>
public sealed record AuthData(
    byte[] RpIdHash, byte Flags, uint SignCount, byte[]? CredentialId, byte[]? CosePublicKey)
{
    public bool UserPresent   => (Flags & 0x01) != 0;
    public bool UserVerified  => (Flags & 0x04) != 0;
    public bool BackupEligible => (Flags & 0x08) != 0;   // BE: the credential MAY be synced across devices
    public bool BackedUp       => (Flags & 0x10) != 0;   // BS: it currently is
    public bool AttestedData  => (Flags & 0x40) != 0;
}

/// <summary>The relevant fields of clientDataJSON (RFC WebAuthn §5.8.1).</summary>
public sealed record ClientData(string Type, string Challenge, string Origin);

/// <summary>
/// WebAuthn wire parsing and COSE→SPKI conversion, dependency-light: CBOR via the first-party
/// <c>System.Formats.Cbor</c> and signature verification through the very same
/// <see cref="IAgentSignatureSuite"/> that verifies agent keys — so the algorithm set and the
/// provider/assurance vocabulary have one home, and passkeys inherit both. Attestation is
/// <c>none</c>: we take the self-reported public key, we do not verify a hardware attestation chain.
/// </summary>
public static class WebAuthn
{
    public static ClientData ParseClientData(byte[] clientDataJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(clientDataJson);
            var root = doc.RootElement;
            return new ClientData(
                root.GetProperty("type").GetString() ?? "",
                root.GetProperty("challenge").GetString() ?? "",
                root.GetProperty("origin").GetString() ?? "");
        }
        catch (Exception e) { throw new WebAuthnException("clientDataJSON is not valid: " + e.Message); }
    }

    /// <summary>The attestationObject of a registration is CBOR { fmt, attStmt, authData }.</summary>
    public static AuthData ParseAttestationObject(byte[] attestationObject)
    {
        try
        {
            var reader = new CborReader(attestationObject);
            var n = reader.ReadStartMap() ?? throw new WebAuthnException("attestationObject: not a definite map");
            byte[]? authData = null;
            for (var i = 0; i < n; i++)
            {
                var key = reader.ReadTextString();
                if (key == "authData") authData = reader.ReadByteString();
                else reader.SkipValue();
            }
            reader.ReadEndMap();
            if (authData is null) throw new WebAuthnException("attestationObject: no authData");
            return ParseAuthData(authData);
        }
        catch (WebAuthnException) { throw; }
        catch (Exception e) { throw new WebAuthnException("attestationObject is not valid CBOR: " + e.Message); }
    }

    public static AuthData ParseAuthData(byte[] authData)
    {
        if (authData.Length < 37) throw new WebAuthnException("authenticatorData too short");
        var rpIdHash = authData[..32];
        var flags = authData[32];
        var signCount = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);

        byte[]? credId = null, cose = null;
        if ((flags & 0x40) != 0)   // AT: attested credential data present (registration)
        {
            if (authData.Length < 55) throw new WebAuthnException("attested credential data truncated");
            var credIdLen = (authData[53] << 8) | authData[54];
            var start = 55;
            if (authData.Length < start + credIdLen) throw new WebAuthnException("credential id truncated");
            credId = authData[start..(start + credIdLen)];
            // The COSE public key is the remaining CBOR; read exactly one item so trailing
            // extensions (ED flag) do not corrupt it.
            var rest = authData[(start + credIdLen)..];
            var reader = new CborReader(rest);
            var keyBytes = reader.ReadEncodedValue().ToArray();
            cose = keyBytes;
        }
        return new AuthData(rpIdHash, flags, signCount, credId, cose);
    }

    /// <summary>Convert a COSE_Key (EC2/P-256 or OKP/Ed25519) to a base64 SPKI the signature suites
    /// accept, and report the COSE algorithm id (-7 ES256, -8 EdDSA).</summary>
    public static (string SpkiBase64, int Alg) CoseKeyToSpki(byte[] coseKey)
    {
        try
        {
            var reader = new CborReader(coseKey);
            var n = reader.ReadStartMap() ?? throw new WebAuthnException("COSE key: not a definite map");
            int kty = 0, alg = 0, crv = 0;
            byte[]? x = null, y = null;
            for (var i = 0; i < n; i++)
            {
                var label = reader.ReadInt32();
                switch (label)
                {
                    case 1: kty = reader.ReadInt32(); break;   // kty
                    case 3: alg = reader.ReadInt32(); break;   // alg
                    case -1:                                    // crv
                        crv = reader.ReadInt32(); break;
                    case -2: x = reader.ReadByteString(); break;
                    case -3: y = reader.ReadByteString(); break;
                    default: reader.SkipValue(); break;
                }
            }
            reader.ReadEndMap();

            if (kty == 2)   // EC2
            {
                if (crv != 1) throw new WebAuthnException("unsupported EC curve (only P-256)");
                if (x is not { Length: 32 } || y is not { Length: 32 }) throw new WebAuthnException("bad EC point");
                using var ec = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = x, Y = y },
                });
                return (Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()), alg == 0 ? -7 : alg);
            }
            if (kty == 1)   // OKP (Ed25519)
            {
                if (crv != 6) throw new WebAuthnException("unsupported OKP curve (only Ed25519)");
                if (x is not { Length: 32 }) throw new WebAuthnException("bad Ed25519 key");
                // SPKI = SEQUENCE { AlgorithmIdentifier { 1.3.101.112 }, BIT STRING(0x00 || pubkey) }
                var spki = new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 }
                    .Concat(x).ToArray();
                return (Convert.ToBase64String(spki), alg == 0 ? -8 : alg);
            }
            throw new WebAuthnException("unsupported COSE key type");
        }
        catch (WebAuthnException) { throw; }
        catch (Exception e) { throw new WebAuthnException("COSE key is not valid: " + e.Message); }
    }

    /// <summary>The bytes an authenticator signs: authenticatorData ‖ SHA-256(clientDataJSON).</summary>
    public static byte[] SignedMessage(byte[] authenticatorData, byte[] clientDataJson) =>
        authenticatorData.Concat(SHA256.HashData(clientDataJson)).ToArray();

    /// <summary>WebAuthn ES256 signatures are ASN.1 DER (SEQUENCE { INTEGER r, INTEGER s }); the
    /// P-256 suite expects fixed IEEE-P1363 (r‖s, 32 bytes each). Convert; leave EdDSA (raw) alone.
    /// Hand-parsed (short-form lengths, which is all a P-256 signature needs) to add no ASN.1
    /// dependency.</summary>
    public static byte[] DerToP1363(byte[] der)
    {
        try
        {
            var i = 0;
            if (der[i++] != 0x30) throw new WebAuthnException("not a DER sequence");
            var seqLen = der[i++];                       // short form (a P-256 sig is well under 128)
            if (seqLen > 0x80 || i + seqLen != der.Length) throw new WebAuthnException("bad sequence length");
            var r = ReadDerInteger(der, ref i);
            var s = ReadDerInteger(der, ref i);
            if (i != der.Length) throw new WebAuthnException("trailing bytes after signature");
            return ToFixed(r, 32).Concat(ToFixed(s, 32)).ToArray();
        }
        catch (WebAuthnException) { throw; }
        catch (Exception e) { throw new WebAuthnException("bad ECDSA signature encoding: " + e.Message); }
    }

    private static byte[] ReadDerInteger(byte[] der, ref int i)
    {
        if (der[i++] != 0x02) throw new WebAuthnException("expected DER integer");
        int len = der[i++];
        if (len > 0x80) throw new WebAuthnException("unsupported long-form integer length");
        var v = der[i..(i + len)];
        i += len;
        return v;
    }

    private static byte[] ToFixed(byte[] be, int size)
    {
        // Strip a DER sign-padding leading zero, then left-pad (or reject if too long) to `size`.
        var start = 0;
        while (start < be.Length - 1 && be[start] == 0x00) start++;
        var trimmed = be[start..];
        if (trimmed.Length > size) throw new WebAuthnException("signature integer too large");
        var padded = new byte[size];
        Array.Copy(trimmed, 0, padded, size - trimmed.Length, trimmed.Length);
        return padded;
    }
}
