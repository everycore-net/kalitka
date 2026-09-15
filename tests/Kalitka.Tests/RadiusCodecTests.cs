using System.Security.Cryptography;
using System.Text;
using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The RADIUS packet codec: parse/build, the RFC 2865 User-Password cipher, the Response
/// Authenticator, and the RFC 2869 Message-Authenticator (verified by round-trip, since the shared
/// secret binds both ends).</summary>
public class RadiusCodecTests
{
    private const string Secret = "s3cr3t-shared";

    private static byte[] Attr(byte type, string val) => Encoding.UTF8.GetBytes(val);

    private static byte[] Request(string user, string password, byte[] auth, bool withMac = false)
    {
        var enc = RadiusPacket.EncryptPassword(password, Secret, auth);
        return RadiusPacket.BuildAccessRequest(7, auth, new[]
        {
            new RadiusAttribute(RadiusAttr.UserName, Encoding.UTF8.GetBytes(user)),
            new RadiusAttribute(RadiusAttr.UserPassword, enc),
        }, Secret, withMac);
    }

    [Theory]
    [InlineData("pw")]
    [InlineData("exactly-16-chars")]                        // one block, full
    [InlineData("a-much-longer-password-over-two-blocks")]  // multi-block
    [InlineData("")]                                        // empty
    public void User_password_round_trips(string password)
    {
        var auth = RadiusPacket.NewAuthenticator();
        var packet = RadiusPacket.Parse(Request("anna", password, auth))!;
        Assert.Equal("anna", packet.GetString(RadiusAttr.UserName));
        Assert.Equal(password, packet.DecryptPassword(Secret));
    }

    [Fact]
    public void Parse_reads_code_id_and_attributes()
    {
        var packet = RadiusPacket.Parse(Request("bob", "x", RadiusPacket.NewAuthenticator()))!;
        Assert.Equal(RadiusCode.AccessRequest, packet.Code);
        Assert.Equal(7, packet.Identifier);
        Assert.Equal("bob", packet.GetString(RadiusAttr.UserName));
    }

    [Fact]
    public void Malformed_packets_are_rejected_not_crashed()
    {
        Assert.Null(RadiusPacket.Parse(new byte[5]));            // too short
        var p = Request("x", "y", RadiusPacket.NewAuthenticator());
        p[3] = 255;                                              // length beyond the datagram
        Assert.Null(RadiusPacket.Parse(p));
    }

    [Fact]
    public void The_response_authenticator_is_valid()
    {
        var reqAuth = RadiusPacket.NewAuthenticator();
        var resp = RadiusPacket.BuildResponse(RadiusCode.AccessAccept, 7, reqAuth,
            new[] { new RadiusAttribute(RadiusAttr.ReplyMessage, Encoding.UTF8.GetBytes("ok")) }, Secret, withMessageAuthenticator: false);

        // Recompute: MD5(code|id|len|reqAuth|attrs|secret) with the request authenticator in the field.
        var check = (byte[])resp.Clone();
        Array.Copy(reqAuth, 0, check, 4, 16);
        var expected = MD5.HashData(check.Concat(Encoding.UTF8.GetBytes(Secret)).ToArray());
        Assert.Equal(expected, resp[4..20]);
    }

    [Fact]
    public void A_message_authenticator_on_the_request_verifies_and_detects_tampering()
    {
        var auth = RadiusPacket.NewAuthenticator();
        var raw = Request("anna", "pw", auth, withMac: true);
        var packet = RadiusPacket.Parse(raw)!;
        Assert.True(packet.VerifyMessageAuthenticator(raw, Secret));
        Assert.False(packet.VerifyMessageAuthenticator(raw, "wrong-secret"));

        raw[^1] ^= 0xFF;   // flip a byte in the last attribute value
        var tampered = RadiusPacket.Parse(raw)!;
        Assert.False(tampered.VerifyMessageAuthenticator(raw, Secret));
    }

    [Fact]
    public void A_response_message_authenticator_is_included_when_requested()
    {
        var reqAuth = RadiusPacket.NewAuthenticator();
        var resp = RadiusPacket.BuildResponse(RadiusCode.AccessChallenge, 3, reqAuth,
            new[] { new RadiusAttribute(RadiusAttr.State, new byte[] { 1, 2, 3 }) }, Secret, withMessageAuthenticator: true);
        Assert.NotNull(RadiusPacket.Parse(resp)!.Get(RadiusAttr.MessageAuthenticator));
    }
}
