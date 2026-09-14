using Kalitka;
using KalitkaMcp;
using Xunit;

namespace KalitkaMcp.Tests;

/// <summary>
/// The MCP server is just another signed <c>/agent/*</c> client, so the one thing that must be
/// exactly right is that a signature from its portable P-256 key verifies under Core's own
/// <c>AgentSignatures</c>, byte for byte, over the same canonical string.
/// </summary>
public class WireParityTests
{
    private static SigningKey FreshKey(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), "kalitka-mcp-test-" + Guid.NewGuid().ToString("N") + ".p8");
        return SigningKey.LoadOrCreate(path);
    }

    [Fact]
    public void Signature_verifies_under_core_suite()
    {
        var path = "";
        try
        {
            using var key = FreshKey(out path);
            var msg = Wire.CanonicalString("POST", "/agent/v1/requests", Wire.Sha256Hex("body=1"u8), "1700000000", "abcd");
            Assert.True(AgentSignatures.Verify(key.PublicKeySpkiBase64(), msg, key.SignBase64(msg)));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Exported_key_is_accepted_for_enrollment_and_key_id_matches()
    {
        var path = "";
        try
        {
            using var key = FreshKey(out path);
            Assert.True(AgentSignatures.IsValidSpki(key.PublicKeySpkiBase64()));
            Assert.Equal(AgentSignatures.KeyIdFor(key.PublicKeySpkiBase64()), key.KeyId());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_persisted_key_is_stable_across_reloads()
    {
        var path = "";
        try
        {
            string spki;
            using (var key = FreshKey(out path)) spki = key.PublicKeySpkiBase64();
            using var reloaded = SigningKey.LoadOrCreate(path);   // same file -> same key
            Assert.Equal(spki, reloaded.PublicKeySpkiBase64());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_tampered_message_does_not_verify()
    {
        var path = "";
        try
        {
            using var key = FreshKey(out path);
            var signed = Wire.CanonicalString("POST", "/agent/v1/requests", Wire.Sha256Hex("body=1"u8), "1700000000", "abcd");
            var sig = key.SignBase64(signed);
            var tampered = Wire.CanonicalString("POST", "/agent/v1/requests", Wire.Sha256Hex("body=2"u8), "1700000000", "abcd");
            Assert.False(AgentSignatures.Verify(key.PublicKeySpkiBase64(), tampered, sig));
        }
        finally { File.Delete(path); }
    }
}
