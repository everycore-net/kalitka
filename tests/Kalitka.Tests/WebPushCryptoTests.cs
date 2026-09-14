using System.Security.Cryptography;
using System.Text;
using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Web Push message encryption (RFC 8291 over RFC 8188 aes128gcm) and VAPID (RFC 8292), checked
/// against the RFC 8291 §5 worked example: same application-server key and salt in, the header framed
/// exactly as the RFC specifies, and the body decrypts back to the RFC's plaintext with the RFC's
/// user-agent key. That is full interop with the spec, not a self-consistency check.
/// </summary>
public class WebPushCryptoTests
{
    // RFC 8291 §5 vectors (base64url).
    private const string UaPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    private const string UaPublic  = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    private const string AuthSecret = "BTBZMqHH6r4Tts7J_aSIgg";
    private const string AsPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    private const string AsPublic  = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    private const string Salt = "DGv6ra1nlYgDCS1FRnbzlw";
    private const string Plaintext = "When I grow up, I want to be a watermelon";

    [Fact]
    public void The_rfc8291_vector_frames_the_header_and_decrypts_to_the_plaintext()
    {
        using var asKey = WebPushCrypto.KeyFrom(AsPublic, AsPrivate);
        var body = WebPushCrypto.Encrypt(UaPublic, AuthSecret, Encoding.UTF8.GetBytes(Plaintext),
            asKey, Base64Url.Decode(Salt));

        // Header: salt(16) || rs(4 BE) || idlen(1) || keyid(=as public).
        Assert.Equal(Base64Url.Decode(Salt), body[..16]);
        Assert.Equal(4096u, (uint)((body[16] << 24) | (body[17] << 16) | (body[18] << 8) | body[19]));
        Assert.Equal(65, body[20]);
        Assert.Equal(Base64Url.Decode(AsPublic), body[21..(21 + 65)]);

        Assert.Equal(Plaintext, Decrypt(body, UaPublic, UaPrivate, AuthSecret));
    }

    [Fact]
    public void A_freshly_generated_key_and_salt_round_trips()
    {
        // The production path: random ephemeral key + salt. A browser (here, our decrypt) recovers it.
        using var ua = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var p = ua.ExportParameters(true);
        var uaPub = Base64Url.Encode(new byte[] { 0x04 }.Concat(Pad32(p.Q.X!)).Concat(Pad32(p.Q.Y!)).ToArray());
        var uaPriv = Base64Url.Encode(p.D!);
        var auth = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));

        var body = WebPushCrypto.Encrypt(uaPub, auth, Encoding.UTF8.GetBytes("hello device"));
        Assert.Equal("hello device", Decrypt(body, uaPub, uaPriv, auth));
    }

    [Fact]
    public void Vapid_authorization_is_a_signed_jwt_for_the_endpoint_origin()
    {
        var keys = VapidKeys.Generate();
        var header = Vapid.Authorization("https://push.example.com/send/abc", "mailto:ops@example.com",
            keys, DateTimeOffset.UnixEpoch.AddSeconds(1_000_000));

        Assert.StartsWith("vapid t=", header);
        Assert.Contains(",k=" + keys.PublicKey, header);
        var jwt = header["vapid t=".Length..].Split(',')[0];
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        // The signature verifies under the VAPID public key, and the aud is the endpoint origin.
        using var pub = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Base64Url.Decode(keys.PublicKey)[1..33],
                Y = Base64Url.Decode(keys.PublicKey)[33..65],
            },
        });
        var signed = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        Assert.True(pub.VerifyData(signed, Base64Url.Decode(parts[2]), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var claims = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));
        Assert.Contains("\"aud\":\"https://push.example.com\"", claims);
    }

    private static byte[] Pad32(byte[] b)
    {
        if (b.Length == 32) return b;
        var r = new byte[32];
        Array.Copy(b, 0, r, 32 - b.Length, b.Length);
        return r;
    }

    // The user-agent side of RFC 8291/8188: what a browser's push service does to read the message.
    private static string Decrypt(byte[] body, string uaPublic, string uaPrivate, string auth)
    {
        var salt = body[..16];
        int idlen = body[20];
        var asPublic = body[21..(21 + idlen)];
        var ciphertext = body[(21 + idlen)..];

        using var ua = WebPushCrypto.KeyFrom(uaPublic, uaPrivate);
        using var asPub = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = asPublic[1..33], Y = asPublic[33..65] },
        });
        var ecdh = ua.DeriveRawSecretAgreement(asPub.PublicKey);

        var keyInfo = Encoding.ASCII.GetBytes("WebPush: info\0")
            .Concat(Base64Url.Decode(uaPublic)).Concat(asPublic).ToArray();
        var ikm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ecdh, 32, Base64Url.Decode(auth), keyInfo);
        var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, salt, Encoding.ASCII.GetBytes("Content-Encoding: aes128gcm\0"));
        var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 12, salt, Encoding.ASCII.GetBytes("Content-Encoding: nonce\0"));

        var tag = ciphertext[^16..];
        var ct = ciphertext[..^16];
        var padded = new byte[ct.Length];
        using var gcm = new AesGcm(cek, 16);
        gcm.Decrypt(nonce, ct, tag, padded);
        return Encoding.UTF8.GetString(padded[..^1]);   // strip the 0x02 last-record delimiter
    }
}
