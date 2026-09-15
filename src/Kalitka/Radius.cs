using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Kalitka;

/// <summary>RADIUS packet codes (RFC 2865) we speak. We are the auth server for a gateway (RD
/// Gateway via NPS, a VPN, Citrix, Wi-Fi 802.1X): the gateway sends Access-Request, we answer.</summary>
public enum RadiusCode : byte
{
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccessChallenge = 11,
}

/// <summary>RADIUS attribute type numbers we touch.</summary>
public static class RadiusAttr
{
    public const byte UserName = 1;
    public const byte UserPassword = 2;
    public const byte NasIpAddress = 4;
    public const byte ReplyMessage = 18;
    public const byte State = 24;
    public const byte CallingStationId = 31;   // the client's address, as the gateway sees it
    public const byte NasIdentifier = 32;
    public const byte MessageAuthenticator = 80;
}

public sealed record RadiusAttribute(byte Type, byte[] Value);

/// <summary>
/// A parsed RADIUS packet and the codec for it (RFC 2865 / 2869). Deliberately hand-rolled on the
/// BCL (MD5/HMAC-MD5 are all RADIUS needs) — the protocol is small and we only implement the
/// Access-* exchange. The transport secret and MD5 are RADIUS legacy; the docs tell operators to run
/// it in a protected segment or over RADIUS/TLS where the gateway supports it.
/// </summary>
public sealed class RadiusPacket
{
    public RadiusCode Code { get; init; }
    public byte Identifier { get; init; }
    public byte[] Authenticator { get; init; } = new byte[16];
    public IReadOnlyList<RadiusAttribute> Attributes { get; init; } = Array.Empty<RadiusAttribute>();

    public byte[]? Get(byte type) => Attributes.FirstOrDefault(a => a.Type == type)?.Value;
    public string? GetString(byte type) => Get(type) is { } v ? Encoding.UTF8.GetString(v) : null;

    /// <summary>Parse a datagram, or null if it is not a well-formed RADIUS packet.</summary>
    public static RadiusPacket? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 20) return null;
        int length = BinaryPrimitives.ReadUInt16BigEndian(data[2..4]);
        if (length < 20 || length > data.Length) return null;

        var attrs = new List<RadiusAttribute>();
        var i = 20;
        while (i < length)
        {
            if (i + 2 > length) return null;
            int type = data[i];
            int alen = data[i + 1];
            if (alen < 2 || i + alen > length) return null;
            attrs.Add(new RadiusAttribute((byte)type, data.Slice(i + 2, alen - 2).ToArray()));
            i += alen;
        }
        return new RadiusPacket
        {
            Code = (RadiusCode)data[0],
            Identifier = data[1],
            Authenticator = data[4..20].ToArray(),
            Attributes = attrs,
        };
    }

    /// <summary>Decrypt the User-Password attribute (RFC 2865 §5.2), given the shared secret and this
    /// request's authenticator. Null if there is no password.</summary>
    public string? DecryptPassword(string sharedSecret)
    {
        var enc = Get(RadiusAttr.UserPassword);
        if (enc is null || enc.Length == 0 || enc.Length % 16 != 0) return null;
        var secret = Encoding.UTF8.GetBytes(sharedSecret);
        var plain = new byte[enc.Length];
        // b_n = MD5(secret + c_{n-1}); c_0 = the request authenticator (RFC 2865 §5.2).
        for (var block = 0; block < enc.Length; block += 16)
        {
            var b = MD5.HashData(Concat(secret, block == 0 ? Authenticator : enc[(block - 16)..block]));
            for (var k = 0; k < 16; k++) plain[block + k] = (byte)(enc[block + k] ^ b[k]);
        }
        // Trim trailing NUL padding.
        var end = plain.Length;
        while (end > 0 && plain[end - 1] == 0) end--;
        return Encoding.UTF8.GetString(plain, 0, end);
    }

    /// <summary>Encrypt a password into a User-Password value (the NAS side — used by tests to build a
    /// request, and symmetric to <see cref="DecryptPassword"/>).</summary>
    public static byte[] EncryptPassword(string password, string sharedSecret, byte[] requestAuthenticator)
    {
        var secret = Encoding.UTF8.GetBytes(sharedSecret);
        var p = Encoding.UTF8.GetBytes(password);
        var padded = new byte[((p.Length + 15) / 16 + (p.Length == 0 ? 1 : 0)) * 16];
        if (padded.Length == 0) padded = new byte[16];
        Array.Copy(p, padded, p.Length);
        var enc = new byte[padded.Length];
        for (var block = 0; block < padded.Length; block += 16)
        {
            var b = MD5.HashData(Concat(secret, block == 0 ? requestAuthenticator : enc[(block - 16)..block]));
            for (var k = 0; k < 16; k++) enc[block + k] = (byte)(padded[block + k] ^ b[k]);
        }
        return enc;
    }

    /// <summary>Build a response datagram (Access-Accept/Reject/Challenge) with the Response
    /// Authenticator computed over the request authenticator + secret (RFC 2865 §3). If
    /// <paramref name="withMessageAuthenticator"/>, an RFC 2869 Message-Authenticator is added first
    /// (HMAC-MD5, keyed by the secret, over the packet with that attribute and the auth field set as
    /// the RADIUS rules require).</summary>
    public static byte[] BuildResponse(RadiusCode code, byte identifier, byte[] requestAuthenticator,
        IEnumerable<RadiusAttribute> attributes, string sharedSecret, bool withMessageAuthenticator)
    {
        var secret = Encoding.UTF8.GetBytes(sharedSecret);
        var attrs = attributes.ToList();
        if (withMessageAuthenticator)
            attrs.Add(new RadiusAttribute(RadiusAttr.MessageAuthenticator, new byte[16]));  // placeholder, filled below

        var packet = Assemble(code, identifier, requestAuthenticator, attrs);

        if (withMessageAuthenticator)
        {
            // Message-Authenticator = HMAC-MD5(secret) over the whole packet with its own value zeroed
            // and the authenticator field = the request authenticator.
            var maOffset = FindAttrOffset(packet, RadiusAttr.MessageAuthenticator);
            using var hmac = new HMACMD5(secret);
            var mac = hmac.ComputeHash(packet);
            Array.Copy(mac, 0, packet, maOffset + 2, 16);
        }

        // Response Authenticator = MD5(packet-with-request-auth + secret), written into the auth field.
        var digest = MD5.HashData(Concat(packet, secret));
        Array.Copy(digest, 0, packet, 4, 16);
        return packet;
    }

    /// <summary>Verify an incoming Access-Request's Message-Authenticator, if present. Absent → true
    /// (the attribute is optional in RADIUS, though a hardened gateway should send it).</summary>
    public bool VerifyMessageAuthenticator(ReadOnlySpan<byte> rawPacket, string sharedSecret)
    {
        var ma = Get(RadiusAttr.MessageAuthenticator);
        if (ma is null) return true;
        if (ma.Length != 16) return false;

        var copy = rawPacket.ToArray();
        var offset = FindAttrOffset(copy, RadiusAttr.MessageAuthenticator);
        if (offset < 0) return false;
        var received = copy[(offset + 2)..(offset + 18)];
        Array.Clear(copy, offset + 2, 16);             // zero the field for the HMAC (auth field stays the request's)
        using var hmac = new HMACMD5(Encoding.UTF8.GetBytes(sharedSecret));
        var expected = hmac.ComputeHash(copy);
        return CryptographicOperations.FixedTimeEquals(received, expected);
    }

    /// <summary>Build an Access-Request datagram (the NAS side). The authenticator is random (the
    /// Request Authenticator); a Message-Authenticator is added when asked (HMAC-MD5 over the packet
    /// with that field zeroed). Used by tests and symmetric to <see cref="BuildResponse"/>.</summary>
    public static byte[] BuildAccessRequest(byte identifier, byte[] authenticator,
        IEnumerable<RadiusAttribute> attributes, string sharedSecret, bool withMessageAuthenticator)
    {
        var attrs = attributes.ToList();
        if (withMessageAuthenticator)
            attrs.Add(new RadiusAttribute(RadiusAttr.MessageAuthenticator, new byte[16]));
        var packet = Assemble(RadiusCode.AccessRequest, identifier, authenticator, attrs);
        if (withMessageAuthenticator)
        {
            var maOffset = FindAttrOffset(packet, RadiusAttr.MessageAuthenticator);
            using var hmac = new HMACMD5(Encoding.UTF8.GetBytes(sharedSecret));
            Array.Copy(hmac.ComputeHash(packet), 0, packet, maOffset + 2, 16);
        }
        return packet;
    }

    private static byte[] Assemble(RadiusCode code, byte identifier, byte[] authenticator, List<RadiusAttribute> attrs)
    {
        var attrBytes = new List<byte>();
        foreach (var a in attrs)
        {
            attrBytes.Add(a.Type);
            attrBytes.Add((byte)(a.Value.Length + 2));
            attrBytes.AddRange(a.Value);
        }
        var length = 20 + attrBytes.Count;
        var packet = new byte[length];
        packet[0] = (byte)code;
        packet[1] = identifier;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)length);
        Array.Copy(authenticator, 0, packet, 4, 16);
        attrBytes.CopyTo(packet, 20);
        return packet;
    }

    private static int FindAttrOffset(byte[] packet, byte type)
    {
        var i = 20;
        while (i + 2 <= packet.Length)
        {
            int t = packet[i], len = packet[i + 1];
            if (len < 2) return -1;
            if (t == type) return i;
            i += len;
        }
        return -1;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r);
        b.CopyTo(r.AsSpan(a.Length));
        return r;
    }

    /// <summary>A random 16-byte request authenticator (the NAS side; tests use it).</summary>
    public static byte[] NewAuthenticator() => RandomNumberGenerator.GetBytes(16);
}
