namespace Kalitka;

/// <summary>
/// Who to ask for a request, resolved once per request (0.30). A request's machine-readable
/// subject is resolved to an operator principal, then to that operator's channel identities;
/// each notifier picks out the identities of its own scheme (<c>telegram:</c>, <c>email:</c>,
/// …). <see cref="IncludeAdmins"/> says whether the global admins are asked too — false for a
/// <c>self</c> approval (only the person acting), true otherwise, and true on the fallback
/// path when a subject did not resolve (that fallback is audited, never silent).
/// </summary>
public sealed record NotifyRouting(IReadOnlyList<string> OperatorIdentities, bool IncludeAdmins)
{
    /// <summary>The baseline: ask the global admins (an ordinary request with no routable
    /// subject, or the audited fallback when a subject did not resolve).</summary>
    public static readonly NotifyRouting Admins = new(Array.Empty<string>(), true);
}

/// <summary>
/// A channel that asks a human to decide a pending request. The engine (or a
/// frontend on top of it) hands a request here; the notifier delivers it and,
/// out of band, feeds the human's answer back by calling
/// <see cref="ApprovalEngine.Decide"/>. Telegram is the first implementation; a
/// push app would be a second, with no change to the engine.
/// </summary>
public interface INotifier
{
    bool Ready { get; }

    /// <summary>Tell the resolved operator (and/or the admins) a request is waiting. The
    /// <paramref name="routing"/> says whose identities to target for this channel's scheme
    /// and whether to include the global admins.</summary>
    Task Announce(PendingRequest request, NotifyRouting routing, CancellationToken ct);
}
