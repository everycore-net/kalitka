using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The self-contained metrics registry: the Prometheus text it renders for each of the four signals
/// the audit asked for, the histogram bucketing, and label escaping.
/// </summary>
public class MetricsTests
{
    [Fact]
    public void An_empty_registry_still_renders_every_family_and_the_gauge()
    {
        var text = new Metrics().Render(pendingDepth: 0);
        Assert.Contains("# TYPE kalitka_decisions_total counter", text);
        Assert.Contains("# TYPE kalitka_notify_fallback_total counter", text);
        Assert.Contains("# TYPE kalitka_pending_requests gauge", text);
        Assert.Contains("kalitka_pending_requests 0", text);
        Assert.Contains("# TYPE kalitka_time_to_approval_seconds histogram", text);
        Assert.Contains("kalitka_time_to_approval_seconds_count 0", text);
    }

    [Fact]
    public void Decisions_are_counted_per_outcome_and_reason()
    {
        var m = new Metrics();
        m.RecordDecision("denied", "block-list");
        m.RecordDecision("denied", "block-list");
        m.RecordDecision("approved", null);

        var text = m.Render(0);
        Assert.Contains("kalitka_decisions_total{decision=\"denied\",reason=\"block-list\"} 2", text);
        Assert.Contains("kalitka_decisions_total{decision=\"approved\",reason=\"-\"} 1", text);
    }

    [Fact]
    public void Notify_fallbacks_are_counted_per_reason()
    {
        var m = new Metrics();
        m.RecordNotifyFallback("subject-unmapped");
        m.RecordNotifyFallback("operator-unreachable");
        m.RecordNotifyFallback("subject-unmapped");

        var text = m.Render(0);
        Assert.Contains("kalitka_notify_fallback_total{reason=\"subject-unmapped\"} 2", text);
        Assert.Contains("kalitka_notify_fallback_total{reason=\"operator-unreachable\"} 1", text);
    }

    [Fact]
    public void The_pending_gauge_reflects_the_live_depth_passed_in()
    {
        Assert.Contains("kalitka_pending_requests 7", new Metrics().Render(7));
    }

    [Fact]
    public void Time_to_approval_lands_in_the_right_buckets_and_sums()
    {
        var m = new Metrics();
        m.RecordTimeToApproval(3);      // ≤ 5
        m.RecordTimeToApproval(45);     // ≤ 60, > 30
        m.RecordTimeToApproval(5000);   // overflow (+Inf only)

        var text = m.Render(0);
        // Cumulative buckets: 3 is in le=5; 3 and 45 are ≤ 60; all three are ≤ +Inf.
        Assert.Contains("kalitka_time_to_approval_seconds_bucket{le=\"5\"} 1", text);
        Assert.Contains("kalitka_time_to_approval_seconds_bucket{le=\"30\"} 1", text);
        Assert.Contains("kalitka_time_to_approval_seconds_bucket{le=\"60\"} 2", text);
        Assert.Contains("kalitka_time_to_approval_seconds_bucket{le=\"+Inf\"} 3", text);
        Assert.Contains("kalitka_time_to_approval_seconds_sum 5048", text);
        Assert.Contains("kalitka_time_to_approval_seconds_count 3", text);
    }

    [Fact]
    public void A_negative_or_nan_observation_is_ignored()
    {
        var m = new Metrics();
        m.RecordTimeToApproval(-1);
        m.RecordTimeToApproval(double.NaN);
        Assert.Contains("kalitka_time_to_approval_seconds_count 0", m.Render(0));
    }

    [Fact]
    public void Label_values_are_escaped()
    {
        var m = new Metrics();
        m.RecordDecision("denied", "we\"ird\\reason");
        Assert.Contains("reason=\"we\\\"ird\\\\reason\"", m.Render(0));
    }
}
