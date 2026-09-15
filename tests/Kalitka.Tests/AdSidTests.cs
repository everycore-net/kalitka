using System.Buffers.Binary;
using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Formatting an AD objectSid (LDAP's raw bytes) to the canonical string, cross-platform — this is
/// what lets RADIUS assert the same <c>sid:</c> a Windows host agent does, so one person is one
/// subject across both entrances. Plus the CredentialResult "established" rule.
/// </summary>
public class AdSidTests
{
    // Build an objectSid binary: revision 1, a 6-byte big-endian authority, then little-endian subs.
    private static byte[] Binary(long authority, params uint[] subs)
    {
        var b = new byte[8 + subs.Length * 4];
        b[0] = 1;
        b[1] = (byte)subs.Length;
        for (var i = 0; i < 6; i++) b[2 + i] = (byte)(authority >> (8 * (5 - i)));
        for (var i = 0; i < subs.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8 + i * 4, 4), subs[i]);
        return b;
    }

    [Fact]
    public void Formats_a_domain_account_sid()
    {
        var bytes = Binary(5, 21, 1004336348, 1177238915, 682003330, 1114);
        Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-1114", AdSid.FromBinary(bytes));
    }

    [Fact]
    public void Formats_a_well_known_sid()
    {
        Assert.Equal("S-1-5-18", AdSid.FromBinary(Binary(5, 18)));   // LocalSystem
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(7)]   // header says 5 subs but the buffer is short
    public void Rejects_a_truncated_buffer(int length)
    {
        var full = Binary(5, 21, 1);
        full[1] = 5;   // claim more subs than present
        Assert.Null(AdSid.FromBinary(full.AsSpan(0, Math.Min(length, full.Length)).ToArray()));
    }

    [Fact]
    public void CredentialResult_is_established_only_when_verified_with_a_sid()
    {
        Assert.True(new CredentialResult(true, "S-1-5-21-1").Established);
        Assert.False(new CredentialResult(true).Established);   // bind ok, no sid resolved
        Assert.False(CredentialResult.Fail.Established);
        Assert.False(CredentialResult.Fail.Ok);
    }
}
