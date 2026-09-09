namespace Kalitka;

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

    /// <summary>Tell the operator a request is waiting for a decision.</summary>
    Task Announce(PendingRequest request, CancellationToken ct);
}
