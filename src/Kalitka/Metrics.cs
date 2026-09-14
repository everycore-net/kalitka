using System.Globalization;
using System.Text;

namespace Kalitka;

/// <summary>
/// The four operational signals the audit asked for, in Prometheus text format and nothing more:
/// how long approvals take, how deep the pending queue is, how often notification fell back to the
/// admins, and how decisions break down by outcome and reason. Self-contained on purpose — no
/// metrics SDK, no exporter dependency — the same choice the rest of the product makes for its
/// formalism (JCS, the audit chain): a handful of counters, a fixed-bucket histogram, and a text
/// renderer are small enough to own and test outright.
///
/// A process-wide singleton behind one lock. Recording is not on a hot enough path (a decision, an
/// approval, a fallback) to need lock-free counters, and a single lock keeps the render a consistent
/// snapshot. The pending-queue depth is not stored here — it is a live gauge read from the request
/// store at scrape time and passed to <see cref="Render"/>.
/// </summary>
public sealed class Metrics
{
    private readonly object _lock = new();

    // decision outcome + reason → count (e.g. denied/block-list, approved/-, asked/-).
    private readonly Dictionary<(string Decision, string Reason), long> _decisions = new();
    // notify fallback reason → count (subject-unmapped, operator-unreachable).
    private readonly Dictionary<string, long> _notifyFallback = new();

    // Time-to-approval histogram. Human-in-the-loop approval spans seconds to the better part of an
    // hour, so the buckets are coarse and wide. Non-cumulative counts; the render accumulates them.
    private static readonly double[] Buckets = { 5, 10, 30, 60, 120, 300, 600, 1800, 3600 };
    private readonly long[] _ttaCounts = new long[Buckets.Length + 1];   // +1 for the +Inf overflow
    private long _ttaCount;
    private long _ttaSumMillis;   // kept in ms so the sum stays an integer under Interlocked-free lock

    public void RecordDecision(string decision, string? reason)
    {
        var key = (decision ?? "-", string.IsNullOrEmpty(reason) ? "-" : reason);
        lock (_lock) _decisions[key] = _decisions.TryGetValue(key, out var n) ? n + 1 : 1;
    }

    public void RecordNotifyFallback(string reason)
    {
        var r = string.IsNullOrEmpty(reason) ? "-" : reason;
        lock (_lock) _notifyFallback[r] = _notifyFallback.TryGetValue(r, out var n) ? n + 1 : 1;
    }

    public void RecordTimeToApproval(double seconds)
    {
        if (double.IsNaN(seconds) || seconds < 0) return;
        var i = 0;
        while (i < Buckets.Length && seconds > Buckets[i]) i++;   // first bucket whose bound the value fits
        lock (_lock)
        {
            _ttaCounts[i]++;
            _ttaCount++;
            _ttaSumMillis += (long)(seconds * 1000);
        }
    }

    /// <summary>Render the current values in Prometheus text exposition format. <paramref
    /// name="pendingDepth"/> is the live queue depth, read from the request store at scrape time.</summary>
    public string Render(int pendingDepth)
    {
        var sb = new StringBuilder();
        lock (_lock)
        {
            sb.Append("# HELP kalitka_decisions_total Access decisions by outcome and reason.\n");
            sb.Append("# TYPE kalitka_decisions_total counter\n");
            foreach (var ((decision, reason), n) in _decisions)
                sb.Append("kalitka_decisions_total{decision=\"").Append(Escape(decision))
                  .Append("\",reason=\"").Append(Escape(reason)).Append("\"} ").Append(n).Append('\n');

            sb.Append("# HELP kalitka_notify_fallback_total Approval notifications that fell back to the admins, by reason.\n");
            sb.Append("# TYPE kalitka_notify_fallback_total counter\n");
            foreach (var (reason, n) in _notifyFallback)
                sb.Append("kalitka_notify_fallback_total{reason=\"").Append(Escape(reason)).Append("\"} ").Append(n).Append('\n');

            sb.Append("# HELP kalitka_pending_requests Requests currently waiting for a decision.\n");
            sb.Append("# TYPE kalitka_pending_requests gauge\n");
            sb.Append("kalitka_pending_requests ").Append(pendingDepth).Append('\n');

            sb.Append("# HELP kalitka_time_to_approval_seconds Time from a request being raised to its approval.\n");
            sb.Append("# TYPE kalitka_time_to_approval_seconds histogram\n");
            long cumulative = 0;
            for (var i = 0; i < Buckets.Length; i++)
            {
                cumulative += _ttaCounts[i];
                sb.Append("kalitka_time_to_approval_seconds_bucket{le=\"")
                  .Append(Buckets[i].ToString(CultureInfo.InvariantCulture)).Append("\"} ").Append(cumulative).Append('\n');
            }
            cumulative += _ttaCounts[Buckets.Length];   // the +Inf overflow bucket
            sb.Append("kalitka_time_to_approval_seconds_bucket{le=\"+Inf\"} ").Append(cumulative).Append('\n');
            sb.Append("kalitka_time_to_approval_seconds_sum ")
              .Append((_ttaSumMillis / 1000.0).ToString(CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("kalitka_time_to_approval_seconds_count ").Append(_ttaCount).Append('\n');
        }
        return sb.ToString();
    }

    // Prometheus label values escape backslash, double-quote and newline. Reasons are known
    // kebab-case tokens, but escape defensively so an unexpected value can never break the format.
    private static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
}
