using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Ed25519 signed-request agent auth (0.20): the agent proves possession of a private
/// key whose public half is registered, over a canonical string binding method/path/
/// body/timestamp/nonce — so nothing reusable is sent, a signature cannot be replayed
/// against another request, and a stale or replayed one is rejected.
/// </summary>
public class AgentSigningTests
{
    private static (string pubB64, Ed25519PrivateKeyParameters priv) NewKeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        var pub = (Ed25519PublicKeyParameters)pair.Public;
        return (Convert.ToBase64String(pub.GetEncoded()), (Ed25519PrivateKeyParameters)pair.Private);
    }

    private static string Sign(Ed25519PrivateKeyParameters priv, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, priv);
        signer.BlockUpdate(message, 0, message.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    [Fact]
    public void Verify_accepts_a_good_signature_and_rejects_tampering()
    {
        var (pub, priv) = NewKeyPair();
        var msg = Encoding.UTF8.GetBytes("hello");
        var sig = Sign(priv, msg);

        Assert.True(AgentSignatures.Verify(pub, msg, sig));
        Assert.False(AgentSignatures.Verify(pub, Encoding.UTF8.GetBytes("hell0"), sig));   // message changed
        Assert.False(AgentSignatures.Verify(NewKeyPair().pubB64, msg, sig));               // wrong key
        Assert.False(AgentSignatures.Verify(pub, msg, Convert.ToBase64String(new byte[64]))); // zero sig
        Assert.False(AgentSignatures.Verify("not-base64!!", msg, sig));                    // malformed key
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IsValidPublicKey_checks_length(bool valid) =>
        Assert.Equal(valid, AgentSignatures.IsValidPublicKey(
            valid ? NewKeyPair().pubB64 : Convert.ToBase64String(new byte[16])));

    // ---- End to end over the wire -------------------------------------------

    public class Http : IClassFixture<GateFactory>
    {
        private readonly GateFactory _f;
        public Http(GateFactory f) => _f = f;

        private HttpClient Client() =>
            _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

        private string RegisterWithKey(string id, string pubB64)
        {
            _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
                id, id, "linux", "h", AgentStatus.Active, AgentSecrets.Hash("unused-secret"),
                new[] { "ssh" }, new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null)
            { Keys = new[] { new AgentKey("k1", pubB64, _f.Clock.GetUtcNow()) } });
            return id;
        }

        private HttpRequestMessage Signed(string id, Ed25519PrivateKeyParameters priv, string body,
            long? tsOverride = null, string? nonce = null, string? bodyToHash = null)
        {
            var ts = (tsOverride ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();
            nonce ??= Guid.NewGuid().ToString("N");
            var hash = AgentSignatures.Sha256Hex(Encoding.UTF8.GetBytes(bodyToHash ?? body));
            var msg = AgentSignatures.CanonicalString("POST", "/agent/request", hash, ts, nonce);
            var req = new HttpRequestMessage(HttpMethod.Post, "/agent/request")
            { Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded") };
            req.Headers.Add("X-Kalitka-Agent-Id", id);
            req.Headers.Add("X-Kalitka-Signature", AgentSigningTests.Sign(priv, msg));
            req.Headers.Add("X-Kalitka-Timestamp", ts);
            req.Headers.Add("X-Kalitka-Nonce", nonce);
            return req;
        }

        private static string Body(string host) => $"host={host}&user=sergej&ip=203.0.113.7";

        [Fact]
        public async Task A_valid_signed_request_authenticates()
        {
            var (pub, priv) = NewKeyPair();
            var id = RegisterWithKey("sig-ok", pub);
            var res = await Client().SendAsync(Signed(id, priv, Body("s-ok")));
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
            Assert.True(doc.RootElement.TryGetProperty("id", out _));
        }

        [Fact]
        public async Task A_tampered_body_is_rejected()
        {
            var (pub, priv) = NewKeyPair();
            var id = RegisterWithKey("sig-tamper", pub);
            // Sign the hash of one body but send another.
            var req = Signed(id, priv, Body("evil"), bodyToHash: Body("innocent"));
            Assert.Equal(HttpStatusCode.Forbidden, (await Client().SendAsync(req)).StatusCode);
        }

        [Fact]
        public async Task A_stale_timestamp_is_rejected()
        {
            var (pub, priv) = NewKeyPair();
            var id = RegisterWithKey("sig-stale", pub);
            var old = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 400;   // beyond the 300s window
            Assert.Equal(HttpStatusCode.Forbidden, (await Client().SendAsync(Signed(id, priv, Body("s"), tsOverride: old))).StatusCode);
        }

        [Fact]
        public async Task A_replayed_nonce_is_rejected()
        {
            var (pub, priv) = NewKeyPair();
            var id = RegisterWithKey("sig-replay", pub);
            var nonce = Guid.NewGuid().ToString("N");
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Two identical signed requests (same ts+nonce+body → same signature).
            Assert.Equal(HttpStatusCode.OK, (await Client().SendAsync(Signed(id, priv, Body("s"), ts, nonce))).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await Client().SendAsync(Signed(id, priv, Body("s"), ts, nonce))).StatusCode);
        }

        [Fact]
        public async Task A_signature_from_an_unregistered_key_is_rejected()
        {
            var (pub, _) = NewKeyPair();
            var id = RegisterWithKey("sig-wrongkey", pub);
            var other = NewKeyPair().priv;   // not the agent's key
            Assert.Equal(HttpStatusCode.Forbidden, (await Client().SendAsync(Signed(id, other, Body("s")))).StatusCode);
        }
    }
}
