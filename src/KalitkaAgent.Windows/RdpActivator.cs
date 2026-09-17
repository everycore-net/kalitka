using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace KalitkaAgent;

/// <summary>What became of a redeem+grant attempt. The pipe path maps these to reply codes.</summary>
public enum GrantOutcome { Granted, Forbidden, RedeemFailed, SubjectIdentityMissing, ProvisionFailed }

public sealed record GrantResult(GrantOutcome Outcome, DateTimeOffset? ExpiresAt = null, int Status = 200);

/// <summary>
/// The one place a Core grant turns into local RDP access, for the pipe request flow (a local process
/// asks via <c>rdp_activate</c>). It owns the security-critical steps: redeem the one-time grant, confirm
/// the Core-approved subject is the very account we are about to enable (never grant to someone else),
/// then hand the lease to the enforcer.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpActivator
{
    private readonly CoreClient _core;
    private readonly RdpEnforcer _rdp;
    private readonly ILogger<RdpActivator> _log;

    public RdpActivator(CoreClient core, RdpEnforcer rdp, ILogger<RdpActivator> log)
    {
        _core = core;
        _rdp = rdp;
        _log = log;
    }

    /// <summary>Redeem a grant and, if it is for the expected caller, enable RDP for them. Shared by
    /// the pipe path so the beneficiary check lives in exactly one place.</summary>
    public async Task<GrantResult> RedeemAndGrantAsync(string agentId, CallerSubject caller, string grant, CancellationToken ct)
    {
        var redeemed = await _core.RedeemAsync(agentId, grant, ct);
        if (redeemed.SessionId is null || redeemed.ExpiresAt is null)
            return new GrantResult(GrantOutcome.RedeemFailed, Status: redeemed.Status);

        // Only ever enable RDP for the very person Core approved, matched on the full stable subject
        // identity (os:DOMAIN\user, sid:…) — never a bare login name, which collides across domains
        // and machines (CONTOSO\anna vs SRV01\anna). This is what stops a caller redeeming a grant
        // approved for someone else and having it enabled for themselves.
        if (BeneficiaryDenial(redeemed.SubjectIdentity, caller) is { } denial)
        {
            if (denial == GrantOutcome.SubjectIdentityMissing)
                // Core returned no subject_identity. That redeem field arrived in #114; a Core too old to
                // send it leaves us unable to verify the beneficiary, so we fail closed — but this is a
                // version skew (upgrade Core), NOT a beneficiary mismatch, and must not read as one.
                _log.LogError("RDP activate refused: Core returned no subject_identity — Core is too old "
                    + "(the redeem field arrived in #114). Upgrade Core; this is a version skew, not a beneficiary mismatch.");
            else
                _log.LogWarning("RDP activate refused: grant subject {Subject} is not {Identity}", redeemed.SubjectIdentity, caller.SubjectIdentity);
            return new GrantResult(denial);
        }

        try
        {
            _rdp.Grant(new RdpLease(redeemed.SessionId, caller.Sid, caller.Account, redeemed.ExpiresAt.Value));
        }
        catch (Exception ex)
        {
            // Enforce failed after Core minted the session. RdpEnforcer.Grant has already rolled back its
            // write-ahead lease (no lease survives a grant that never took, so reconcile won't re-assert
            // it). Tell Core the session was NOT provisioned, so a failed grant is not left looking like
            // live access in the audit and an orphaned "open" session does not linger.
            _log.LogError(ex, "RDP enforce failed for {Account}; reporting provision-failed to Core", caller.Account);
            try { await _core.ReportProvisionFailedAsync(agentId, redeemed.SessionId, ex.Message, ct); }
            catch (Exception report) { _log.LogError(report, "could not report provision-failed for session {Session}", redeemed.SessionId); }
            return new GrantResult(GrantOutcome.ProvisionFailed, Status: 500);
        }
        return new GrantResult(GrantOutcome.Granted, redeemed.ExpiresAt.Value);
    }

    /// <summary>The Core-approved subject identity must be the caller's full, stable identity — the
    /// whole <c>os:DOMAIN\user</c> / <c>sid:…</c> string, compared case-insensitively (Core stores it
    /// lower-cased), never a bare login-name tail. An empty approved identity never matches (fail
    /// closed).</summary>
    public static bool BeneficiaryMatches(string? approvedSubjectIdentity, CallerSubject caller)
    {
        if (string.IsNullOrEmpty(approvedSubjectIdentity)) return false;
        return string.Equals(approvedSubjectIdentity, caller.SubjectIdentity, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The refusal outcome for a redeemed grant's approved subject, or null if it may proceed.
    /// Splits the two fail-closed cases the operator must act on differently: an <b>absent</b> approved
    /// identity means Core is too old to send <c>subject_identity</c> (a version skew — upgrade Core),
    /// while a <b>present but different</b> identity is a genuine beneficiary mismatch (a grant for
    /// someone else). Both refuse; only the reason and the fix differ.</summary>
    public static GrantOutcome? BeneficiaryDenial(string? approvedSubjectIdentity, CallerSubject caller)
    {
        if (string.IsNullOrEmpty(approvedSubjectIdentity)) return GrantOutcome.SubjectIdentityMissing;
        return BeneficiaryMatches(approvedSubjectIdentity, caller) ? null : GrantOutcome.Forbidden;
    }
}
