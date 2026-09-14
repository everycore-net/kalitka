using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kalitka.Tests;

/// <summary>
/// A software WebAuthn authenticator for tests: it holds a real P-256 key and produces genuine
/// attestation objects and assertions (DER ES256 signatures, exactly as a browser authenticator
/// would), so the whole verification path is exercised end to end without external vectors.
/// </summary>
public sealed class SoftAuthenticator
{
    public readonly ECDsa Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] CredId { get; } = RandomNumberGenerator.GetBytes(16);
    public bool BackupEligible { get; set; }

    public string CredentialIdB64u => B64u(CredId);

    private byte[] CoseKey()
    {
        var p = Key.ExportParameters(false);
        var w = new CborWriter();
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(2);    // kty EC2
        w.WriteInt32(3); w.WriteInt32(-7);   // alg ES256
        w.WriteInt32(-1); w.WriteInt32(1);   // crv P-256
        w.WriteInt32(-2); w.WriteByteString(Pad32(p.Q.X!));
        w.WriteInt32(-3); w.WriteByteString(Pad32(p.Q.Y!));
        w.WriteEndMap();
        return w.Encode();
    }

    private byte[] AuthData(string rpId, uint signCount, bool attested)
    {
        var ms = new MemoryStream();
        ms.Write(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));
        byte flags = 0x01 | 0x04;                       // UP | UV
        if (BackupEligible) flags |= 0x08 | 0x10;       // BE | BS
        if (attested) flags |= 0x40;                    // AT
        ms.WriteByte(flags);
        ms.Write(new[] { (byte)(signCount >> 24), (byte)(signCount >> 16), (byte)(signCount >> 8), (byte)signCount });
        if (attested)
        {
            ms.Write(new byte[16]);                      // aaguid
            ms.Write(new[] { (byte)(CredId.Length >> 8), (byte)CredId.Length });
            ms.Write(CredId);
            ms.Write(CoseKey());
        }
        return ms.ToArray();
    }

    private static string ClientData(string type, string challengeB64u, string origin) =>
        $"{{\"type\":\"{type}\",\"challenge\":\"{challengeB64u}\",\"origin\":\"{origin}\"}}";

    public (string AttestationObject, string ClientDataJson) Register(string rpId, string origin, string challengeB64u)
    {
        var authData = AuthData(rpId, 0, attested: true);
        var w = new CborWriter();
        w.WriteStartMap(3);
        w.WriteTextString("fmt"); w.WriteTextString("none");
        w.WriteTextString("attStmt"); w.WriteStartMap(0); w.WriteEndMap();
        w.WriteTextString("authData"); w.WriteByteString(authData);
        w.WriteEndMap();
        return (B64u(w.Encode()), B64u(Encoding.UTF8.GetBytes(ClientData("webauthn.create", challengeB64u, origin))));
    }

    public (string CredentialId, string AuthenticatorData, string ClientDataJson, string Signature)
        Sign(string rpId, string origin, string challengeB64u, uint signCount, string type = "webauthn.get")
    {
        var authData = AuthData(rpId, signCount, attested: false);
        var cdj = Encoding.UTF8.GetBytes(ClientData(type, challengeB64u, origin));
        var message = authData.Concat(SHA256.HashData(cdj)).ToArray();
        // WebAuthn ES256 signatures are DER — this is what DerToP1363 must handle.
        var der = Key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return (CredentialIdB64u, B64u(authData), B64u(cdj), B64u(der));
    }

    /// <summary>Pull the challenge (base64url) out of a "begin" options JSON.</summary>
    public static string ChallengeOf(string optionsJson) =>
        JsonDocument.Parse(optionsJson).RootElement.GetProperty("challenge").GetString()!;

    private static byte[] Pad32(byte[] b)
    {
        if (b.Length == 32) return b;
        var r = new byte[32];
        Array.Copy(b, 0, r, 32 - b.Length, b.Length);
        return r;
    }

    public static string B64u(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
