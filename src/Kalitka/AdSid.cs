using System.Buffers.Binary;
using System.Text;

namespace Kalitka;

/// <summary>
/// Formats an Active Directory <c>objectSid</c> (returned by LDAP as raw bytes) into the canonical
/// <c>S-1-5-21-…</c> string — cross-platform, so Core can do it on Linux where
/// <c>System.Security.Principal.SecurityIdentifier</c> is not available. The binary layout is
/// revision, sub-authority count, a 6-byte big-endian identifier authority, then that many 4-byte
/// little-endian sub-authorities (the same shape a Windows agent's SID has, so the two entrances
/// resolve to the same string).
/// </summary>
public static class AdSid
{
    public static string? FromBinary(ReadOnlySpan<byte> b)
    {
        if (b.Length < 8) return null;
        int revision = b[0];
        int count = b[1];
        if (b.Length < 8 + 4 * count) return null;

        long authority = 0;
        for (var i = 2; i < 8; i++) authority = (authority << 8) | b[i];

        var sb = new StringBuilder("S-").Append(revision).Append('-').Append(authority);
        for (var i = 0; i < count; i++)
            sb.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(b.Slice(8 + i * 4, 4)));
        return sb.ToString();
    }
}
