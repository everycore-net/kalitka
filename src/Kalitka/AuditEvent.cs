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
    string Metadata);

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
