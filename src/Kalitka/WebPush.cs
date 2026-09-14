using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kalitka;

/// <summary>An application-server (VAPID) key pair: the P-256 key that identifies this sender to a
/// push service. Public key is the uncompressed point (base64url) the browser passes as
/// <c>applicationServerKey</c>; private is the raw scalar d (base64url).</summary>
public sealed record VapidKeys(string PublicKey, string PrivateKey)
{
    public static VapidKeys Generate()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(true);
        return new VapidKeys(Base64Url.Encode(Point(p)), Base64Url.Encode(p.D!));
    }

    internal static byte[] Point(ECParameters p) =>
        new byte[] { 0x04 }.Concat(Pad32(p.Q.X!)).Concat(Pad32(p.Q.Y!)).ToArray();

    internal static byte[] Pad32(byte[] b)
    {
        if (b.Length == 32) return b;
        var r = new byte[32];
        Array.Copy(b, 0, r, 32 - b.Length, b.Length);
        return r;
    }
}

/// <summary>
/// VAPID (RFC 8292): a short-lived ES256 JWT that identifies this server to the push service, so a
/// stolen subscription cannot be spammed by a third party. Built on the BCL — no library.
/// </summary>
public static class Vapid
{
    /// <summary>The <c>Authorization</c> header value for a push to <paramref name="endpoint"/>:
    /// <c>vapid t=&lt;jwt&gt;,k=&lt;public key&gt;</c>.</summary>
    public static string Authorization(string endpoint, string subject, VapidKeys keys, DateTimeOffset now)
    {
        var origin = new Uri(endpoint).GetLeftPart(UriPartial.Authority);
        var header = Base64Url.Encode(Encoding.UTF8.GetBytes("{\"typ\":\"JWT\",\"alg\":\"ES256\"}"));
        var claims = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["aud"] = origin,
            ["exp"] = now.AddHours(12).ToUnixTimeSeconds(),
            ["sub"] = subject,
        });
        var body = header + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(claims));

        using var ec = LoadPrivate(keys);
        var sig = ec.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);   // JWS wants raw r‖s
        var jwt = body + "." + Base64Url.Encode(sig);
        return $"vapid t={jwt},k={keys.PublicKey}";
    }

    internal static ECDsa LoadPrivate(VapidKeys keys)
    {
        var pub = Base64Url.Decode(keys.PublicKey);   // 0x04 || X || Y
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Base64Url.Decode(keys.PrivateKey),
            Q = new ECPoint { X = pub[1..33], Y = pub[33..65] },
        });
    }
}

/// <summary>
/// Message encryption for Web Push: RFC 8291 (the key schedule off the ECDH secret + auth secret)
/// over RFC 8188's <c>aes128gcm</c> content coding. Built entirely on the BCL — ECDH, HKDF and
/// AES-GCM are all in the framework, so a whole push library is not needed. The ephemeral key and
/// salt are injectable so the RFC 8291 §5 vector can be reproduced exactly in tests.
/// </summary>
public static class WebPushCrypto
{
    private const int RecordSize = 4096;

    /// <summary>Encrypt <paramref name="plaintext"/> for a subscription's <paramref name="p256dh"/>
    /// (the UA public key) and <paramref name="auth"/> secret. Returns the full aes128gcm body.</summary>
    public static byte[] Encrypt(string p256dh, string auth, byte[] plaintext,
        ECDiffieHellman? asKey = null, byte[]? salt = null)
    {
        var uaPublicBytes = Base64Url.Decode(p256dh);          // 0x04 || X || Y (65)
        var authSecret = Base64Url.Decode(auth);               // 16
        salt ??= RandomNumberGenerator.GetBytes(16);

        var owned = asKey is null;
        asKey ??= ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var asParams = asKey.ExportParameters(false);
            var asPublic = VapidKeys.Point(asParams);          // 65

            using var uaKey = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = uaPublicBytes[1..33], Y = uaPublicBytes[33..65] },
            });
            var ecdhSecret = asKey.DeriveRawSecretAgreement(uaKey.PublicKey);   // 32 (the shared X)

            // RFC 8291 §3.4: IKM from the ECDH secret keyed by the auth secret.
            var keyInfo = Concat(Encoding.ASCII.GetBytes("WebPush: info\0"), uaPublicBytes, asPublic);
            var ikm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ecdhSecret, 32, authSecret, keyInfo);

            // RFC 8188: CEK and nonce from the IKM keyed by the record salt.
            var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, salt, Encoding.ASCII.GetBytes("Content-Encoding: aes128gcm\0"));
            var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 12, salt, Encoding.ASCII.GetBytes("Content-Encoding: nonce\0"));

            // Single record: data || 0x02 (last-record delimiter), then AES-128-GCM.
            var padded = new byte[plaintext.Length + 1];
            Array.Copy(plaintext, padded, plaintext.Length);
            padded[^1] = 0x02;
            var ciphertext = new byte[padded.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(cek, 16))
                gcm.Encrypt(nonce, padded, ciphertext, tag);

            // aes128gcm header: salt(16) || rs(4 BE) || idlen(1) || keyid(as public) || ciphertext||tag
            var header = new byte[16 + 4 + 1 + asPublic.Length];
            Array.Copy(salt, 0, header, 0, 16);
            header[16] = (byte)((RecordSize >> 24) & 0xFF); header[17] = (byte)((RecordSize >> 16) & 0xFF);
            header[18] = (byte)((RecordSize >> 8) & 0xFF); header[19] = (byte)(RecordSize & 0xFF);
            header[20] = (byte)asPublic.Length;
            Array.Copy(asPublic, 0, header, 21, asPublic.Length);
            return Concat(header, ciphertext, tag);
        }
        finally { if (owned) asKey.Dispose(); }
    }

    /// <summary>Build an <see cref="ECDiffieHellman"/> from a raw private scalar and its public point
    /// (both base64url) — for reproducing the RFC vector's fixed application-server key in tests.</summary>
    public static ECDiffieHellman KeyFrom(string publicKey, string privateKey)
    {
        var pub = Base64Url.Decode(publicKey);
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Base64Url.Decode(privateKey),
            Q = new ECPoint { X = pub[1..33], Y = pub[33..65] },
        });
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var len = parts.Sum(p => p.Length);
        var r = new byte[len];
        var o = 0;
        foreach (var p in parts) { Array.Copy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }
}
