using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The RADIUS credential-check guard: a per-username failure cap (so a bad-password flood cannot
/// lock the victim out at the DC — kalitka simply stops forwarding the attempts) and bounded
/// concurrency (so a flood or a hung DC cannot avalanche binds).
/// </summary>
public class LoginThrottleTests
{
    private static (LoginThrottle throttle, FakeTimeProvider clock) Build(
        int maxFailures = 3, int windowMinutes = 15, int maxConcurrent = 8, int queueTimeoutSeconds = 0)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var opts = Options.Create(new GateOptions
        {
            RadiusMaxUsernameFailures = maxFailures,
            RadiusFailureWindowMinutes = windowMinutes,
            RadiusMaxConcurrentVerifications = maxConcurrent,
            RadiusVerifyQueueTimeoutSeconds = queueTimeoutSeconds,
        });
        return (new LoginThrottle(opts, clock), clock);
    }

    private static async Task FailOnce(LoginThrottle t, string user)
    {
        var permit = await t.AcquireAsync(user, default);
        Assert.NotNull(permit);
        permit!.Record(false);
        permit.Dispose();
    }

    [Fact]
    public async Task Refuses_a_username_past_its_failure_budget_without_binding()
    {
        var (t, _) = Build(maxFailures: 3);
        for (var i = 0; i < 3; i++) await FailOnce(t, "anna");

        // The 4th attempt never gets a permit — so no bind, so the DC's lockout counter is untouched.
        Assert.Null(await t.AcquireAsync("anna", default));
        // A different user is unaffected.
        Assert.NotNull(await t.AcquireAsync("bob", default));
    }

    [Fact]
    public async Task A_successful_login_clears_the_failure_count()
    {
        var (t, _) = Build(maxFailures: 3);
        await FailOnce(t, "anna");
        await FailOnce(t, "anna");

        var ok = await t.AcquireAsync("anna", default);
        Assert.NotNull(ok);
        ok!.Record(true);              // success resets
        ok.Dispose();

        // Back to a full budget of three.
        for (var i = 0; i < 3; i++) await FailOnce(t, "anna");
        Assert.Null(await t.AcquireAsync("anna", default));
    }

    [Fact]
    public async Task Failures_age_out_after_the_window()
    {
        var (t, clock) = Build(maxFailures: 3, windowMinutes: 15);
        for (var i = 0; i < 3; i++) await FailOnce(t, "anna");
        Assert.Null(await t.AcquireAsync("anna", default));

        clock.Advance(TimeSpan.FromMinutes(16));           // the window has passed
        Assert.NotNull(await t.AcquireAsync("anna", default));
    }

    [Fact]
    public async Task Bounded_concurrency_refuses_when_no_slot_is_free()
    {
        var (t, _) = Build(maxConcurrent: 1, queueTimeoutSeconds: 0);
        var held = await t.AcquireAsync("anna", default);
        Assert.NotNull(held);

        Assert.Null(await t.AcquireAsync("bob", default));  // no slot, times out immediately

        held!.Dispose();                                    // release
        Assert.NotNull(await t.AcquireAsync("bob", default));
    }
}
