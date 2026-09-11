using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Kalitka;

/// <summary>
/// A registered Ed25519 public key for an agent. The stronger successor to the shared
/// per-agent secret: the agent keeps the private key and signs each request, so no
/// reusable secret is ever sent or stored. A key is add-only here; rotation and
/// revocation manage the set (0.20.2). <see cref="PublicKey"/> is base64 of the 32
/// raw Ed25519 public-key bytes.
/// </summary>
public sealed record AgentKey(string KeyId, string PublicKey, DateTimeOffset AddedAt);

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

    public static string NewKeyId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();

    public static string Sha256Hex(ReadOnlySpan<byte> body) => Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    /// <summary>The exact bytes a client must sign. Newline-joined, version first, so
    /// there is no ambiguity and no field can be smuggled into another.</summary>
    public static byte[] CanonicalString(string method, string pathAndQuery, string bodyHashHex, string timestamp, string nonce) =>
        Encoding.UTF8.GetBytes(string.Join('\n', Scheme, method.ToUpperInvariant(), pathAndQuery, bodyHashHex, timestamp, nonce));

    /// <summary>True if <paramref name="publicKeyBase64"/> is a well-formed Ed25519 key
    /// (32 bytes). Used when a key is registered, so bad keys never reach verification.</summary>
    public static bool IsValidPublicKey(string publicKeyBase64)
    {
        try { return Convert.FromBase64String(publicKeyBase64).Length == 32; }
        catch { return false; }
    }

    /// <summary>Verify an Ed25519 signature (base64, 64 bytes) over <paramref name="message"/>
    /// with a base64 public key. False on any malformed input — never throws.</summary>
    public static bool Verify(string publicKeyBase64, byte[] message, string signatureBase64)
    {
        try
        {
            var pub = Convert.FromBase64String(publicKeyBase64);
            var sig = Convert.FromBase64String(signatureBase64);
            if (pub.Length != 32 || sig.Length != 64) return false;

            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(pub, 0));
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(sig);
        }
        catch { return false; }
    }
}
