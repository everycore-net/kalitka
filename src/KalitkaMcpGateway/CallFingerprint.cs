using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace KalitkaMcpGateway;

/// <summary>
/// The identity of one MCP tool call — what a grant is bound to, so between approval and execution
/// neither the tool, its contract, the subject, the workload (nor its assurance), nor the arguments
/// can change without invalidating the grant. Fields are joined with <b>unambiguous length-prefixed
/// framing</b> (4-byte big-endian length ‖ bytes), so no field value — even one containing a NUL —
/// can shift the boundary and collide with a different call. The version prefix
/// <c>kalitka-mcp-call-v2</c> covers the framing and the canonicalisation together.
/// </summary>
public static class CallFingerprint
{
    public const string Scheme = "kalitka-mcp-call-v2";

    // Crockford base32, excluding I, L, O, U (unambiguous for humans reading a Call ID aloud).
    private const string Crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>
    /// The contract the gateway <i>observed</i> for a tool, bound to an <paramref name="inventoryEpoch"/>
    /// (a digest of the whole inventory snapshot — see <see cref="ToolInventory"/>). Because the epoch
    /// covers the entire snapshot, any inventory change (a tool added, removed, or retyped anywhere)
    /// changes every tool's contract id and so invalidates all not-yet-redeemed grants on that upstream.
    /// A digest is durable and restart-stable, unlike a local counter.
    /// </summary>
    public static byte[] ToolContractId(string upstreamId, string tool, string inventoryEpoch, ReadOnlySpan<byte> canonicalInputSchema)
    {
        var buf = new ArrayBufferWriter<byte>();
        Field(buf, upstreamId);
        Field(buf, tool);
        Field(buf, inventoryEpoch);
        Field(buf, canonicalInputSchema);
        return SHA256.HashData(buf.WrittenSpan);
    }

    /// <summary>
    /// The call fingerprint: SHA-256 over the scheme, the upstream alias, the tool name, the
    /// tool-contract id, the subject (id + asserted/claimed), the workload (id + assurance), and the
    /// canonical arguments — each length-prefixed. The upstream <b>alias</b> (admin-assigned, stable)
    /// is bound in, so a caller cannot aim the same call at a softer policy space by renaming.
    /// </summary>
    public static byte[] Compute(
        string upstreamAlias, string tool, ReadOnlySpan<byte> toolContractId,
        AuthenticatedCallContext ctx, ReadOnlySpan<byte> canonicalArguments)
    {
        var buf = new ArrayBufferWriter<byte>();
        Field(buf, Scheme);
        Field(buf, upstreamAlias);
        Field(buf, tool);
        Field(buf, toolContractId);
        Field(buf, ctx.Subject.Id);
        Field(buf, ctx.Subject.Asserted ? "asserted" : "claimed");
        Field(buf, ctx.Workload.Id);
        Field(buf, ctx.Workload.Assurance);
        Field(buf, canonicalArguments);
        return SHA256.HashData(buf.WrittenSpan);
    }

    /// <summary>base64url (no padding) of a fingerprint — the wire/storage form.</summary>
    public static string ToBase64Url(ReadOnlySpan<byte> fingerprint) =>
        Convert.ToBase64String(fingerprint).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// A short, human-quotable prefix of the fingerprint — <c>7DM4-R9KT-2F81</c> — shown identically
    /// in the approval UI, the audit log and the gateway's own logs, so a human can confirm they
    /// approved the call that executed. A truncation of the same fingerprint, never a separate counter.
    /// </summary>
    public static string CallId(ReadOnlySpan<byte> fingerprint)
    {
        var chars = Base32(fingerprint, 12);
        return $"{chars[..4]}-{chars[4..8]}-{chars[8..12]}";
    }

    private static void Field(ArrayBufferWriter<byte> buf, string s) => Field(buf, Encoding.UTF8.GetBytes(s));

    private static void Field(ArrayBufferWriter<byte> buf, ReadOnlySpan<byte> bytes)
    {
        var header = buf.GetSpan(4);
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
        buf.Advance(4);
        buf.Write(bytes);
    }

    private static string Base32(ReadOnlySpan<byte> data, int symbols)
    {
        var sb = new StringBuilder(symbols);
        int buffer = 0, bits = 0, i = 0;
        while (sb.Length < symbols)
        {
            if (bits < 5) { buffer = (buffer << 8) | (i < data.Length ? data[i++] : 0); bits += 8; }
            bits -= 5;
            sb.Append(Crockford[(buffer >> bits) & 0x1F]);
        }
        return sb.ToString();
    }
}
