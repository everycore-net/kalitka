namespace Kalitka;

/// <summary>
/// Where pending access requests live. Today an in-memory dictionary; the point
/// of the seam is that a durable/shared backend (SQL, Redis) can replace it
/// without the engine changing — the step toward multi-instance.
///
/// The load-bearing method is <see cref="TryResolve"/>: it is the one atomic
/// "resolve exactly once" transition. Without it, two channels (Telegram and the
/// web plane, or two admins) racing an Approve and a Deny on the same request
/// could both succeed, leaving it both approved and denied. A one-time token's
/// single-use guarantee is the same shape and gets its own store later.
/// </summary>
public interface IRequestStore
{
    void Add(PendingRequest request);
    PendingRequest? Get(string id);
    void Remove(string id);

    /// <summary>All current requests (waiting and recently resolved).</summary>
    IReadOnlyList<PendingRequest> Snapshot();

    /// <summary>Waiting requests raised at or after <paramref name="since"/>.</summary>
    int CountWaiting(DateTimeOffset since);

    /// <summary>Forget requests older than the cutoff, whatever their state.</summary>
    void DropOlderThan(DateTimeOffset cutoff);

    /// <summary>
    /// Atomically move a request from waiting to a terminal state, but only if it
    /// is still waiting and was raised at or after <paramref name="notOlderThan"/>.
    /// Returns true and the request when THIS call made the transition; false if
    /// it was gone, already resolved, or too old (no change made).
    /// </summary>
    bool TryResolve(string id, string toState, DateTimeOffset notOlderThan, out PendingRequest? request);

    /// <summary>
    /// Atomically attach the one-time grant to the request, but only if it has none
    /// yet. Returns the effective grant (existing or the candidate just stored) and,
    /// via the return value, whether THIS call stored it. The atomicity belongs in
    /// the store, not the engine: with a durable backend <see cref="Get"/> hands back
    /// a copy, so mutating that copy would be lost — and two status polls landing on
    /// two instances must not mint two redeemable grants for one approval.
    /// </summary>
    bool TrySetGrant(string id, string candidate, out string grant);

    /// <summary>
    /// Record a distinct approver for a request and return how many distinct approvers
    /// it now has. Idempotent per principal (approving twice counts once) and atomic,
    /// so concurrent approvals on different nodes accumulate a correct quorum count.
    /// The caller decides eligibility (which principals count) and, once the count
    /// reaches the request's <see cref="PendingRequest.RequiredApprovals"/>, makes the
    /// single <see cref="TryResolve"/> transition to approved.
    /// </summary>
    int AddApprovalAndCount(string id, string principal);

    /// <summary>How many distinct approvers a request has so far (for display).</summary>
    int ApprovalCount(string id);
}
