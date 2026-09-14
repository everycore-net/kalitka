using System.Text;
using Kalitka;
using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The one thing that must be exactly right before anything else: a signature the Windows
/// agent's CNG platform key produces has to verify under Core's <c>ecdsa-p256</c> suite,
/// byte for byte, over the same canonical string. If this holds, the rest of the agent is
/// plumbing; if it does not, nothing the agent sends is accepted. These tests use the
/// software KSP (no TPM needed in CI) — the wire format is identical either way — and clean
/// up the persisted key after themselves.
/// </summary>
public class WireParityTests
{
    // Per-user software key: a machine key would need admin rights to create, which CI/test
    // runs do not have. The wire format is identical regardless of scope or provider.
    private static PlatformKey FreshKey(out string keyName)
    {
        keyName = "kalitka-test-" + Guid.NewGuid().ToString("N");
        return PlatformKey.OpenOrCreate(keyName, preferSoftware: true, machineKey: false);
    }

    [Fact]
    public void Cng_signature_verifies_under_core_suite()
    {
        var name = "";
        try
        {
            using var key = FreshKey(out name);
            var spki = key.PublicKeySpkiBase64();

            var msg = Wire.CanonicalString("POST", "/agent/v1/requests", Wire.Sha256Hex("body=1"u8), "1700000000", "abcd");
            var sig = key.SignBase64(msg);

            Assert.True(AgentSignatures.Verify(spki, msg, sig));
        }
        finally { PlatformKey.Delete(name, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public void Exported_key_is_accepted_for_enrollment()
    {
        var name = "";
        try
        {
            using var key = FreshKey(out name);
            Assert.True(AgentSignatures.IsValidSpki(key.PublicKeySpkiBase64()));
        }
        finally { PlatformKey.Delete(name, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public void Key_id_matches_core_fingerprint()
    {
        var name = "";
        try
        {
            using var key = FreshKey(out name);
            Assert.Equal(AgentSignatures.KeyIdFor(key.PublicKeySpkiBase64()), key.KeyId());
        }
        finally { PlatformKey.Delete(name, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public void A_tampered_message_does_not_verify()
    {
        var name = "";
        try
        {
            using var key = FreshKey(out name);
            var spki = key.PublicKeySpkiBase64();
            var signed = Wire.CanonicalString("POST", "/agent/v1/requests", Wire.Sha256Hex("body=1"u8), "1700000000", "abcd");
            var sig = key.SignBase64(signed);

            var tampered = Wire.CanonicalString("POST", "/agent/v1/requests", Wire.Sha256Hex("body=2"u8), "1700000000", "abcd");
            Assert.False(AgentSignatures.Verify(spki, tampered, sig));
        }
        finally { PlatformKey.Delete(name, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public void Canonical_string_is_byte_identical_to_core()
    {
        var mine = Wire.CanonicalString("post", "/agent/v1/requests?x=1", "deadbeef", "1700000000", "nonce123");
        var theirs = AgentSignatures.CanonicalString("post", "/agent/v1/requests?x=1", "deadbeef", "1700000000", "nonce123");
        Assert.Equal(theirs, mine);
        Assert.Equal("kalitka-agent-sig-v1\nPOST\n/agent/v1/requests?x=1\ndeadbeef\n1700000000\nnonce123",
            Encoding.UTF8.GetString(mine));
    }
}
