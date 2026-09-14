using System.Security.Cryptography;

namespace KalitkaMcp;

/// <summary>
/// The MCP server's signing key: ECDSA P-256, portable (plain <see cref="ECDsa"/>, no platform
/// crypto), persisted as PKCS#8 next to the server. A desktop MCP host is impersonable by
/// anything running as that user, so this key is honestly <c>software</c> / <c>assurance:
/// unverified</c> — never a trusted subject asserter. It only proves "the same workload that
/// enrolled is the one calling". Signatures are IEEE P1363 (64 bytes), what Core's
/// <c>ecdsa-p256</c> suite verifies.
/// </summary>
public sealed class SigningKey : IDisposable
{
    private readonly ECDsa _ecdsa;

    public string ProviderHint => "software";

    private SigningKey(ECDsa ecdsa) => _ecdsa = ecdsa;

    /// <summary>Load the PKCS#8 key at <paramref name="path"/>, creating and persisting a new
    /// P-256 key on first run. The file is the credential — protect it with filesystem ACLs.</summary>
    public static SigningKey LoadOrCreate(string path)
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            ec.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _);
            return new SigningKey(ec);
        }
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllBytes(path, ec.ExportPkcs8PrivateKey());
        return new SigningKey(ec);
    }

    /// <summary>base64 of the key's SPKI — the exact form Core stores and fingerprints.</summary>
    public string PublicKeySpkiBase64() => Convert.ToBase64String(_ecdsa.ExportSubjectPublicKeyInfo());

    /// <summary>The key id as Core computes it: <c>base64url(SHA-256(SPKI))</c>.</summary>
    public string KeyId()
    {
        var spki = _ecdsa.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(SHA256.HashData(spki)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Sign the canonical bytes: SHA-256 + P1363 (r‖s, 64 bytes).</summary>
    public string SignBase64(ReadOnlySpan<byte> message) =>
        Convert.ToBase64String(_ecdsa.SignData(message.ToArray(), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    public void Dispose() => _ecdsa.Dispose();
}
