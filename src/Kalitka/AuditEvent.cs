namespace Kalitka;

/// <summary>
/// One audit event. The envelope is deliberately fixed and resource-centric, so
/// SSH/DB/RDP events later fit the same shape without a schema change. Free-form
/// detail goes in <see cref="Metadata"/> — a short note, not a JSON dumping
/// ground; anything worth querying earns a first-class field.
/// </summary>
public sealed record AuditEvent(
    string Id,
    DateTimeOffset Timestamp,
    string EventType,
    string Actor,        // who acted: telegram:<id>, google:<sub>, email:link, or "-"
    string Subject,      // who/what it is about (the visitor's input, an e-mail)
    string Resource,     // web:<host>, later ssh:<host>, db:<host>/<db>, ...
    string RequestId,
    string GrantId,
    string Channel,      // gate | telegram | web | email | ssh | ...
    string Metadata)
{
    // ---- Tamper-evidence (hash chain) ---------------------------------------
    // Assigned by the store at append time, under its own serialization: a monotonic sequence
    // number and the hash of this event chained to the previous one. Default (0 / empty) on an
    // event that has not been appended yet. See AuditHash.
    public long Seq { get; init; }
    public string PrevHash { get; init; } = "";
    public string Hash { get; init; } = "";

    // ---- Device-signed decision proof (WebAuthn) ----------------------------
    // A compact, self-describing token ("wa1:<base64url>") carrying the assertion that signed THIS
    // decision — credential id, authenticator data, clientDataJSON, signature — so an auditor can
    // re-verify the signature offline against the registered credential. Empty on every event that
    // was not device-signed. Deliberately NOT part of the chain hash (that would rewrite existing
    // hashes); its integrity is bound instead by a short commitment folded into the hashed Metadata
    // (see ApprovalEngine.DecisionEvent). It rides on the event through the same atomic append, so a
    // decision and its proof still commit together.
    public string Proof { get; init; } = "";
}

/// <summary>The result of verifying the audit hash chain: whether it is intact, how many events
/// were checked, and — if broken — the sequence number of the first bad link.</summary>
public sealed record AuditVerification(bool Intact, long Checked, long? FirstBadSeq, string HeadHash, long HeadSeq = 0)
{
    public static readonly AuditVerification Empty = new(true, 0, null, "", 0);
}

/// <summary>Event types. Resource-centric; grant/session reserved for PAM axes.</summary>
public static class AuditEvents
{
    public const string AccessRequested    = "access.requested";
    public const string AccessApproved     = "access.approved";
    public const string AccessApprovalNoted = "access.approval_noted";   // quorum: one approver, not yet enough
    public const string AccessDenied       = "access.denied";
    public const string NotifyFallback     = "notify.fallback";   // subject did not resolve to an operator; asked the admins
    public const string GrantCreated     = "grant.created";
    public const string GrantRedeemed    = "grant.redeemed";
    public const string GrantExpired     = "grant.expired";
    public const string SessionStarted   = "session.started";
    public const string SessionProvisioned = "session.provisioned";   // DB-agent applied the grant's profile
    public const string SessionReconciled = "session.reconciled";     // crash-recovery cleanup (reason: core-confirmed | local-expiry | orphan-max-age)
    public const string SessionEnded     = "session.ended";
    public const string AdminLogin       = "admin.login";
    public const string AdminLoginDenied = "admin.login_denied";

    public const string AgentEnrollmentCreated = "agent.enrollment_created";
    public const string AgentEnrolled          = "agent.enrolled";
    public const string AgentAuthFailed        = "agent.auth_failed";
    public const string AgentDisabled          = "agent.disabled";
    public const string AgentEnabled           = "agent.enabled";
    public const string AgentCredentialRotated = "agent.credential_rotated";
    public const string AgentRevoked           = "agent.revoked";
    public const string AgentResourceDenied    = "agent.resource_denied";
    public const string AgentKeyAdded          = "agent.key_added";
    public const string AgentKeyRemoved        = "agent.key_removed";
    public const string AgentProfileCreated    = "agent.profile_created";
    public const string AgentProfileUpdated    = "agent.profile_updated";
    public const string AgentProfileDeleted    = "agent.profile_deleted";
    public const string AgentProfileApplied    = "agent.profile_applied";
    public const string AgentPrivilegedCapability = "agent.privileged_capability";   // sudo-grade cap granted/revoked

    public const string PolicyCreated = "policy.created";
    public const string PolicyUpdated = "policy.updated";
    public const string PolicyDeleted = "policy.deleted";

    public const string PrincipalCreated = "principal.created";
    public const string PrincipalUpdated = "principal.updated";
    public const string PrincipalDeleted = "principal.deleted";

    public const string CatalogItemCreated = "catalog.created";
    public const string CatalogItemUpdated = "catalog.updated";
    public const string CatalogItemDeleted = "catalog.deleted";

    public const string IntegrationCreated = "integration.created";
    public const string IntegrationUpdated = "integration.updated";
    public const string IntegrationRotated = "integration.rotated";
    public const string IntegrationDeleted = "integration.deleted";

    // Device vocabulary mirrors agent.* so history filters line up (device.enrolled ~ agent.enrolled).
    public const string WebAuthnRegistered = "device.enrolled";         // a passkey/device was registered to an operator
    public const string WebAuthnRemoved    = "device.revoked";          // a device was revoked
    public const string WebAuthnCloneAlarm = "device.clone_alarm";      // signature counter went backwards — possible cloned key

    public const string PasskeyRemembered = "passkey.remembered";   // a visitor bound a passkey after approval
    public const string PasskeyUsed       = "passkey.used";         // a visitor passed the gate with a passkey
    public const string PasskeyRevoked    = "passkey.revoked";      // a remembered visitor passkey was revoked (= blocked)

    public const string EnrollInvited   = "enroll.invited";     // an admin issued a one-time enrolment invite
    public const string EnrollCompleted = "enroll.completed";   // an invitee signed in via the IdP and enrolled
    public const string ApproverGranted = "approver.granted";   // an operator was granted approve rights at runtime
    public const string ApproverRevoked = "approver.revoked";   // ...and revoked
}

/// <summary>A narrow query over the audit log: a few filters and a page.</summary>
public sealed record AuditQuery(
    string? Actor = null,
    string? Resource = null,
    string? EventType = null,
    DateTimeOffset? Since = null,
    DateTimeOffset? Until = null,
    int Limit = 50,
    int Offset = 0);
