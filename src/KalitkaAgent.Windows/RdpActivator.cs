using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace KalitkaAgent;

/// <summary>Raises and drives an RDP request to a grant on the subject's behalf — used by the
/// security-log watcher, which has no interactive client to poll for it.</summary>
public interface IRdpActivator
{
    Task ActivateAsync(RdpDenial denial, CancellationToken ct);
}

/// <summary>What became of a redeem+grant attempt. The pipe path maps these to reply codes; the
/// watcher just logs.</summary>
public enum GrantOutcome { Granted, Forbidden, RedeemFailed, SubjectIdentityMissing }

public sealed record GrantResult(GrantOutcome Outcome, DateTimeOffset? ExpiresAt = null, int Status = 200);

/// <summary>
/// The one place a Core grant turns into local RDP access. It owns the security-critical steps so
/// both callers (the interactive pipe flow and the log watcher) share exactly one implementation:
/// redeem the one-time grant, confirm the Core-approved subject is the very account we are about to
/// enable (never grant to someone else), then hand the lease to the enforcer. It also drives the
/// full raise→poll→grant loop for the watcher, which has nobody to poll on its behalf.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpActivator : IRdpActivator
{
    // Poll a raised request until the human decides. The window matches Core's pending lifetime; a
    // few seconds between polls is well within human-paced approval and the request dedups anyway.
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan PollTimeout = TimeSpan.FromMinutes(5);

    private readonly CoreClient _core;
    private readonly RdpEnforcer _rdp;
    private readonly AgentIdentity _identity;
    private readonly TimeProvider _clock;
    private readonly ILogger<RdpActivator> _log;

    public RdpActivator(CoreClient core, RdpEnforcer rdp, AgentIdentity identity, TimeProvider clock, ILogger<RdpActivator> log)
    {
        _core = core;
        _rdp = rdp;
        _identity = identity;
        _clock = clock;
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

        _rdp.Grant(new RdpLease(redeemed.SessionId, caller.Sid, caller.Account, redeemed.ExpiresAt.Value));
        return new GrantResult(GrantOutcome.Granted, redeemed.ExpiresAt.Value);
    }

    /// <summary>The watcher's autonomous path: raise the request for the denied subject, poll until
    /// the human decides, and enable RDP on approval. No-op if the id is not published yet.</summary>
    public async Task ActivateAsync(RdpDenial denial, CancellationToken ct)
    {
        var agentId = _identity.Current;
        if (agentId is null) return;

        var caller = denial.ToSubject();
        var raise = await _core.RaiseAsync(agentId, caller, denial.Resource, command: null, ct);
        if (raise.State == "allowed") return;                    // already permitted; nothing to enable
        if (raise.State != "waiting" || string.IsNullOrEmpty(raise.Id))
        {
            _log.LogInformation("RDP request for {Account} not pending ({State}); nothing to do", caller.Account, raise.State);
            return;
        }

        var deadline = _clock.GetUtcNow() + PollTimeout;
        while (!ct.IsCancellationRequested && _clock.GetUtcNow() < deadline)
        {
            await Task.Delay(PollInterval, _clock, ct);
            var poll = await _core.PollAsync(agentId, raise.Id!, ct);
            if (poll.State == "approved" && !string.IsNullOrEmpty(poll.Grant))
            {
                var result = await RedeemAndGrantAsync(agentId, caller, poll.Grant!, ct);
                if (result.Outcome == GrantOutcome.Granted)
                    _log.LogInformation("RDP enabled for {Account} until {Expiry:u}", caller.Account, result.ExpiresAt);
                return;
            }
            if (poll.State is "denied" or "expired" || poll.State is null) return;   // terminal
        }
    }

    /// <summary>The Core-approved subject identity must be the caller's full, stable identity — the
    /// whole <c>os:DOMAIN\user</c> / <c>sid:…</c> string, compared case-insensitively (Core stores it
    /// lower-cased), never a bare login-name tail. An empty approved identity never matches (fail
    /// closed). Shared by both activation paths.</summary>
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
