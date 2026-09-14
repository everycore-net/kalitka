using System.Security.Cryptography;
using System.Text;

namespace KalitkaMcpGateway;

/// <summary>
/// The identity of one MCP tool call — what a grant is bound to, so between approval and
/// execution neither the tool, its contract, the subject, nor the arguments can change without
/// invalidating the grant. Everything hashed is either a fixed field or canonical bytes; the
/// version prefix <c>kalitka-mcp-call-v1</c> covers both the envelope and the canonicalisation,
/// so a scheme change is a new prefix.
/// </summary>
public static class CallFingerprint
{
    public const string Scheme = "kalitka-mcp-call-v1";

    // Crockford base32, excluding I, L, O, U (unambiguous for humans reading a Call ID aloud).
    private const string Crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>
    /// The contract the gateway <i>observed</i> for a tool: the upstream, the tool name, the
    /// canonical input schema, and the inventory revision. Bound into the fingerprint so a
    /// changed contract (a new/renamed argument, a retyped field) makes an old grant
    /// un-redeemable. Description/title/icons are deliberately excluded — a typo fix must not
    /// invalidate live grants; <c>outputSchema</c> is out in v1 (the authority is over the input
    /// operation).
    /// </summary>
    public static byte[] ToolContractId(string upstreamId, string toolName, ReadOnlySpan<byte> canonicalInputSchema, long inventoryRevision)
    {
        using var sha = SHA256.Create();
        var buf = new List<byte>();
        AppendField(buf, upstreamId);
        AppendField(buf, toolName);
        AppendField(buf, inventoryRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        buf.AddRange(canonicalInputSchema.ToArray());
        return sha.ComputeHash(buf.ToArray());
    }

    /// <summary>
    /// The call fingerprint: SHA-256 over the scheme, the upstream alias, the tool name, the
    /// tool-contract id, the subject and workload identities, and the canonical arguments. The
    /// upstream <b>alias</b> (admin-assigned, stable) is part of it, so a caller cannot aim the
    /// same call at a softer policy space by renaming.
    /// </summary>
    public static byte[] Compute(
        string upstreamAlias, string toolName, ReadOnlySpan<byte> toolContractId,
        string subject, string workload, ReadOnlySpan<byte> canonicalArguments)
    {
        using var sha = SHA256.Create();
        var buf = new List<byte>();
        AppendField(buf, Scheme);
        AppendField(buf, upstreamAlias);
        AppendField(buf, toolName);
        AppendField(buf, Convert.ToHexString(toolContractId));
        AppendField(buf, subject);
        AppendField(buf, workload);
        buf.AddRange(canonicalArguments.ToArray());
        return sha.ComputeHash(buf.ToArray());
    }

    /// <summary>base64url (no padding) of a fingerprint — the wire/storage form.</summary>
    public static string ToBase64Url(ReadOnlySpan<byte> fingerprint) =>
        Convert.ToBase64String(fingerprint).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// A short, human-quotable prefix of the fingerprint — <c>7DM4-R9KT-2F81</c> — shown
    /// identically in the approval UI, the audit log and the gateway's own logs, so a human can
    /// confirm they approved the call that executed. It is a truncation of the same fingerprint
    /// (Crockford base32), never a separate counter.
    /// </summary>
    public static string CallId(ReadOnlySpan<byte> fingerprint)
    {
        var chars = Base32(fingerprint, 12);   // 12 symbols = 3 groups of 4
        return $"{chars[..4]}-{chars[4..8]}-{chars[8..12]}";
    }

    // A NUL-delimited length-independent field: the fields are text without NUL, so the
    // delimiter is unambiguous and no field can bleed into the next.
    private static void AppendField(List<byte> buf, string field)
    {
        buf.AddRange(Encoding.UTF8.GetBytes(field));
        buf.Add(0);
    }

    private static string Base32(ReadOnlySpan<byte> data, int symbols)
    {
        var sb = new StringBuilder(symbols);
        int buffer = 0, bits = 0, i = 0;
        while (sb.Length < symbols)
        {
            if (bits < 5)
            {
                buffer = (buffer << 8) | (i < data.Length ? data[i++] : 0);
                bits += 8;
            }
            bits -= 5;
            sb.Append(Crockford[(buffer >> bits) & 0x1F]);
        }
        return sb.ToString();
    }
}
