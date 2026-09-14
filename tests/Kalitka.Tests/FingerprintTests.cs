using System.Text;
using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The device fingerprint: deterministic, in the gateway Call-ID alphabet, so a person can
/// read it aloud to confirm the right device bound.</summary>
public class FingerprintTests
{
    [Fact]
    public void It_is_deterministic_and_shaped_like_a_call_id()
    {
        var a = Fingerprint.Of(Encoding.UTF8.GetBytes("device-key"));
        var b = Fingerprint.Of(Encoding.UTF8.GetBytes("device-key"));
        Assert.Equal(a, b);
        Assert.Matches("^[0-9A-Z]{4}-[0-9A-Z]{4}$", a);
    }

    [Fact]
    public void It_uses_the_crockford_alphabet_without_ambiguous_letters()
    {
        // Sample many inputs; no I, L, O or U ever appears (unambiguous read aloud).
        for (var i = 0; i < 500; i++)
        {
            var f = Fingerprint.Of(Encoding.UTF8.GetBytes("k" + i));
            Assert.DoesNotContain('I', f);
            Assert.DoesNotContain('L', f);
            Assert.DoesNotContain('O', f);
            Assert.DoesNotContain('U', f);
        }
    }

    [Fact]
    public void Different_keys_give_different_fingerprints()
    {
        Assert.NotEqual(Fingerprint.Of(Encoding.UTF8.GetBytes("a")), Fingerprint.Of(Encoding.UTF8.GetBytes("b")));
    }
}
