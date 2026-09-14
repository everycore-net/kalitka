using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Kalitka;

/// <summary>
/// Tamper-evidence for the audit log: each event carries the hash of the one before it, so the
/// whole history is a chain that cannot be altered or reordered without breaking. This is what turns
/// "we logged the approval" into "here is a log a customer can verify" — the core claim of a
/// human-approval gate. Fields are joined with <b>length-prefixed framing</b> (the same discipline
/// as the MCP gateway's call fingerprint), so no field value can shift a boundary and forge a
/// matching hash. Versioned so the scheme can evolve.
/// </summary>
public static class AuditHash
{
    public const string Scheme = "kalitka-audit-v1";

    /// <summary>The genesis link — the previous hash for the first event.</summary>
    public const string Genesis = "";

    /// <summary>Hash of an event chained to <paramref name="prevHash"/>: SHA-256 over the scheme,
    /// the previous hash, the sequence number, and every content field, each length-prefixed.</summary>
    public static string Compute(AuditEvent e, string prevHash)
    {
        var buf = new ArrayBufferWriter<byte>();
        Framing.Field(buf, Scheme);
        Framing.Field(buf, prevHash);
        Framing.Field(buf, e.Seq.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Framing.Field(buf, e.Id);
        Framing.Field(buf, e.Timestamp.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));
        Framing.Field(buf, e.EventType);
        Framing.Field(buf, e.Actor);
        Framing.Field(buf, e.Subject);
        Framing.Field(buf, e.Resource);
        Framing.Field(buf, e.RequestId);
        Framing.Field(buf, e.GrantId);
        Framing.Field(buf, e.Channel);
        Framing.Field(buf, e.Metadata);
        // NB: AuditEvent.Proof is deliberately NOT in the chain hash — it rides on the event through
        // the same atomic append, and its integrity is bound by a short commitment folded into the
        // hashed Metadata (see DecisionEvent). Adding a field here would rewrite every existing hash.
        return Convert.ToHexString(SHA256.HashData(buf.WrittenSpan));
    }

    /// <summary>The next event, linked to the current head: assigns <c>Seq</c>, <c>PrevHash</c> and
    /// <c>Hash</c>. Stores call this under their own serialization so the chain has no gaps or forks.</summary>
    public static AuditEvent Link(AuditEvent e, long headSeq, string headHash)
    {
        var linked = e with { Seq = headSeq + 1, PrevHash = headHash };
        return linked with { Hash = Compute(linked, headHash) };
    }
}

/// <summary>Verifies a hash chain read back from a store.</summary>
public static class AuditChain
{
    /// <summary>Verify events in ascending sequence order. Each event's stored hash must recompute
    /// from its own content + prev-hash, and (except the first in the window) must link to the prior
    /// event's hash. The first event's prev may point at an event already dropped from a bounded
    /// store, so only its self-hash is checked there.</summary>
    public static AuditVerification Verify(IReadOnlyList<AuditEvent> orderedOldestFirst)
    {
        if (orderedOldestFirst.Count == 0) return AuditVerification.Empty;
        var head = "";
        long headSeq = 0;
        for (var i = 0; i < orderedOldestFirst.Count; i++)
        {
            var e = orderedOldestFirst[i];
            if (i > 0 && e.PrevHash != orderedOldestFirst[i - 1].Hash)
                return new AuditVerification(false, i, e.Seq, head, headSeq);
            if (AuditHash.Compute(e, e.PrevHash) != e.Hash)
                return new AuditVerification(false, i, e.Seq, head, headSeq);
            head = e.Hash;
            headSeq = e.Seq;
        }
        return new AuditVerification(true, orderedOldestFirst.Count, null, head, headSeq);
    }
}
