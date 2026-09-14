namespace KalitkaMcpGateway;

/// <summary>The human a call acts for. <see cref="Asserted"/> distinguishes a subject an executor
/// vouched for from one the workload merely claimed — the same asserted-vs-claimed rule as the rest
/// of Kalitka. It is part of the fingerprint binding, so a claimed subject and an asserted one are
/// different calls and an approval for one is never reusable for the other.</summary>
public sealed record SubjectRef(string Id, bool Asserted);

/// <summary>The AI workload making the call: its identity and how much that identity is trusted
/// (<see cref="Assurance"/>, e.g. <c>unverified</c> until attestation). Assurance is bound into the
/// fingerprint so the same identifier at a different assurance level is a different call.</summary>
public sealed record WorkloadRef(string Id, string Assurance = "unverified");

/// <summary>
/// The authenticated context of a tool call — never bare strings. Every security-relevant property
/// that could change a policy outcome (who the subject is and whether it was asserted; the workload
/// and its assurance) is carried typed and folded into the call fingerprint, so one identity string
/// cannot silently stand for two different trust levels.
/// </summary>
public sealed record AuthenticatedCallContext(WorkloadRef Workload, SubjectRef Subject);
