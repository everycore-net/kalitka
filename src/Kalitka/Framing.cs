using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Kalitka;

/// <summary>
/// Length-prefixed framing: each field is written as a 4-byte big-endian length followed by its
/// bytes, so no field value can shift a boundary and let two different field-sets collide on the same
/// concatenation. This is the one discipline behind every canonical byte-string kalitka signs or
/// hashes — the audit hash chain (<see cref="AuditHash"/>) and the approval envelope
/// (<see cref="ApprovalEnvelope"/>) — so it lives in one place.
/// </summary>
public static class Framing
{
    /// <summary>Append one length-prefixed field (raw bytes) to <paramref name="buf"/>.</summary>
    public static void Field(ArrayBufferWriter<byte> buf, ReadOnlySpan<byte> bytes)
    {
        var header = buf.GetSpan(4);
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
        buf.Advance(4);
        buf.Write(bytes);
    }

    /// <summary>Append one length-prefixed field, the UTF-8 bytes of <paramref name="s"/>.</summary>
    public static void Field(ArrayBufferWriter<byte> buf, string s) => Field(buf, Encoding.UTF8.GetBytes(s));

    /// <summary>Frame a fixed set of string fields into one canonical byte-string.</summary>
    public static byte[] Encode(params string[] fields)
    {
        var buf = new ArrayBufferWriter<byte>();
        foreach (var f in fields) Field(buf, f);
        return buf.WrittenSpan.ToArray();
    }
}
