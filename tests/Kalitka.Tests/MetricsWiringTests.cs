using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The engine records into the metrics registry on the real decision paths — every decision goes
/// through the same seam as the audit log, and an approval records how long it took.
/// </summary>
public class MetricsWiringTests
{
    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));

    private static ApprovalEngine Engine(TimeProvider clock, Metrics metrics)
    {
        var o = new GateOptions();
        var store = new InMemoryConfigStore();
        var lists = new AccessLists(Options.Create(o), NullLogger<AccessLists>.Instance, store, clock);
        return new ApprovalEngine(new NullGeoLookup(), lists, o, NullLogger<ApprovalEngine>.Instance,
            clock, new InMemoryRequestStore(), new InMemoryAuditStore(), config: store, metrics: metrics);
    }

    [Fact]
    public async Task A_rejected_request_is_counted_with_its_reason()
    {
        var metrics = new Metrics();
        var engine = Engine(ClockAt(), metrics);

        // No host is armed, so the target is not guarded → rejected.
        await engine.Request("host.example.com", "sergej", "203.0.113.5", default);

        Assert.Contains("kalitka_decisions_total{decision=\"rejected\",reason=\"target-not-guarded\"} 1",
            metrics.Render(0));
    }

    [Fact]
    public async Task An_approval_is_counted_and_its_time_recorded()
    {
        var metrics = new Metrics();
        var clock = ClockAt();
        var engine = Engine(clock, metrics);

        engine.SetEnforced("host.example.com", true);   // arm it so a request is raised, not rejected
        var (state, id, _) = await engine.Request("host.example.com", "sergej", "203.0.113.5", default);
        Assert.Equal("waiting", state);
        Assert.Equal(1, engine.PendingCount());          // the pending gauge source reflects the queue

        clock.Advance(TimeSpan.FromSeconds(20));          // the human takes 20s to decide
        var result = await engine.Decide(id, "ok", "telegram:1");
        Assert.Equal(CallbackOutcome.Decided, result.Outcome);

        var text = metrics.Render(engine.PendingCount());
        Assert.Contains("kalitka_decisions_total{decision=\"approved\",reason=\"ok\"} 1", text);
        Assert.Contains("kalitka_time_to_approval_seconds_count 1", text);
        Assert.Contains("kalitka_time_to_approval_seconds_bucket{le=\"30\"} 1", text);   // 20s ≤ 30
        Assert.Contains("kalitka_pending_requests 0", text);                              // decided → queue empty
    }
}
