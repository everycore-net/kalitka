using System.Buffers;
using System.Security.Cryptography;

namespace Kalitka;

/// <summary>
/// What a device actually signs when it approves. The WebAuthn challenge <b>is</b> this envelope, so
/// the authenticator's signature (over <c>authenticatorData ‖ sha256(clientDataJSON)</c>, and
/// clientDataJSON carries the challenge) is a signature over <i>this</i> decision — not "a session
/// pressed approve". The fields are length-prefixed (<see cref="Framing"/>) so no value can shift a
/// boundary.
///
/// The envelope is the reusable core of device-signed approval: the future native app and the iOS
/// shield's <c>defer</c> path sign the same shape, so the audit proof is one format across channels.
///
/// Fields, in order: scheme, request id, decision (the granular verb), timestamp (unix ms), a hash
/// of the policy context being approved, and a server nonce (unpredictability + single-use).
/// </summary>
public static class ApprovalEnvelope
{
    public const string Scheme = "kalitka-approval-v1";

    /// <summary>The canonical bytes that become the WebAuthn challenge.</summary>
    public static byte[] Build(string requestId, string verb, long timestampMs, string policyContextHash, string nonce)
    {
        var buf = new ArrayBufferWriter<byte>();
        Framing.Field(buf, Scheme);
        Framing.Field(buf, requestId);
        Framing.Field(buf, verb);
        Framing.Field(buf, timestampMs.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Framing.Field(buf, policyContextHash);
        Framing.Field(buf, nonce);
        return buf.WrittenSpan.ToArray();
    }

    /// <summary>A hash over the approval-defining terms of a request, so a policy change between
    /// "begin" and "finish" (different quorum, subject rule, command, source) invalidates a signature
    /// gathered against the old terms. Snapshotted fields, matching what was shown to the approver.</summary>
    public static string PolicyContextHash(ApprovalContext c)
    {
        var bytes = Framing.Encode(
            c.Resource,
            c.RequiredApprovals.ToString(System.Globalization.CultureInfo.InvariantCulture),
            c.Subject,
            c.Command,
            c.SourceAddr,
            c.Profile);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }
}

/// <summary>The approval-defining terms of a waiting request, as an immutable snapshot the signing
/// layer can read without touching engine state — the fields that define <i>what</i> is being
/// approved (and so must not shift between issuing a challenge and verifying the signature).</summary>
public sealed record ApprovalContext(
    string Id, string Resource, int RequiredApprovals, string Subject, string Command, string SourceAddr, string Profile);

/// <summary>
/// The stored proof of a device-signed decision: everything an auditor needs to re-verify the
/// signature offline against the registered credential — the credential id, the authenticator data,
/// the clientDataJSON, and the signature. Serialized length-prefixed and tagged <c>wa1:</c>.
/// </summary>
public sealed record WebAuthnProof(byte[] CredentialId, byte[] AuthenticatorData, byte[] ClientDataJson, byte[] Signature)
{
    public const string Tag = "wa1:";

    public string Encode()
    {
        var buf = new ArrayBufferWriter<byte>();
        Framing.Field(buf, CredentialId);
        Framing.Field(buf, AuthenticatorData);
        Framing.Field(buf, ClientDataJson);
        Framing.Field(buf, Signature);
        return Tag + Base64Url.Encode(buf.WrittenSpan);
    }

    /// <summary>A short commitment to this proof, folded into the hashed audit Metadata so the proof
    /// (which is not itself in the chain hash) cannot be altered or stripped without detection.</summary>
    public static string Commitment(string encodedProof) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(encodedProof)))[..16];
}
