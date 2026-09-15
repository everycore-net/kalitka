namespace Kalitka;

/// <summary>
/// The dedup fingerprint of a request: a hash over every field that shapes the <b>authority</b> being
/// asked for, length-prefixed so no field value can shift a boundary (the same framing discipline as
/// the audit hash). Two raises fold onto one pending request only when they are asking for exactly
/// the same thing — a repeated logon-denied for one person and host folds, but two SSH requests that
/// differ in command, profile, source or use budget do not. Only ever computed when a machine-
/// readable subject identity is present; a web visitor's request never folds.
/// </summary>
public static class RequestFingerprint
{
    public static string Of(string resource, string subjectIdentity, string beneficiary, string profile,
        string command, string sourceAddr, int maxUses, bool requireSigned) =>
        AgentSignatures.Sha256Hex(Framing.Encode(
            "dedup-v1", resource, subjectIdentity, beneficiary, profile, command, sourceAddr,
            maxUses.ToString(), requireSigned ? "1" : "0"));
}
