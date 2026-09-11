using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Enrollment: a one-time token activates a pending agent, is single-use, and
/// expires. Service-level with a dedicated clock so advancing time here cannot
/// disturb the shared web fixture.
/// </summary>
public class AgentEnrollmentTests
{
    private static (AgentService svc, InMemoryAgentStore store, FakeTimeProvider clock) Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var store = new InMemoryAgentStore();
        var tokens = new OneTimeTokenService(new TokenSigner("unit-test-signing-key-0123456789"), clock);
        var svc = new AgentService(store, tokens, new InMemoryReplayStore(clock), new InMemoryAuditStore(),
            Options.Create(new GateOptions { EnrollmentTokenMinutes = 60 }), clock);
        return (svc, store, clock);
    }

    private const string Secret = "enroll-secret-abcdef123456";   // >= 16 chars

    [Fact]
    public async Task Enrollment_token_activates_a_pending_agent()
    {
        var (svc, store, _) = Fresh();
        var token = await svc.CreateEnrollmentToken("prod-01", "linux", new[] { "ssh" }, new[] { "ssh:prod-01" }, "google:admin", default);

        var r = await svc.Enroll(token, Secret, "prod-01.local", "os=debian", default);
        Assert.True(r.Ok);

        var agent = store.GetById(r.AgentId!)!;
        Assert.Equal(AgentStatus.Active, agent.Status);
        Assert.True(AgentSecrets.Verify(Secret, agent.SecretHash));
        Assert.Equal("prod-01.local", agent.Hostname);
        Assert.Equal("os=debian", agent.Metadata);
        Assert.Equal(new[] { "ssh:prod-01" }, agent.AllowedResources);
    }

    [Fact]
    public async Task Enrollment_token_is_single_use()
    {
        var (svc, _, _) = Fresh();
        var token = await svc.CreateEnrollmentToken("a", "linux", new[] { "ssh" }, new[] { "ssh:*" }, "google:admin", default);

        Assert.True((await svc.Enroll(token, Secret, "h", "", default)).Ok);
        // The token cannot enrol again: the agent is no longer pending, and the jti
        // is consumed — a replay is caught by whichever guard it hits first.
        var again = await svc.Enroll(token, Secret, "h", "", default);
        Assert.False(again.Ok);
        Assert.Contains(again.Error, new[] { "used", "not-pending" });
    }

    [Fact]
    public async Task Expired_enrollment_token_is_rejected()
    {
        var (svc, _, clock) = Fresh();
        var token = await svc.CreateEnrollmentToken("a", "linux", new[] { "ssh" }, new[] { "ssh:*" }, "google:admin", default);

        clock.Advance(TimeSpan.FromMinutes(61));   // past EnrollmentTokenMinutes
        var r = await svc.Enroll(token, Secret, "h", "", default);
        Assert.False(r.Ok);
        Assert.Equal("invalid", r.Error);
    }

    [Fact]
    public async Task A_weak_secret_is_rejected()
    {
        var (svc, _, _) = Fresh();
        var token = await svc.CreateEnrollmentToken("a", "linux", new[] { "ssh" }, new[] { "ssh:*" }, "google:admin", default);
        var r = await svc.Enroll(token, "short", "h", "", default);
        Assert.False(r.Ok);
        Assert.Equal("weak-secret", r.Error);
    }

    [Fact]
    public async Task Rotation_returns_a_new_secret_and_invalidates_the_old()
    {
        var (svc, store, _) = Fresh();
        var created = await svc.Create("a", "linux", new[] { "ssh" }, new[] { "ssh:*" }, "google:admin", default);
        var old = created.Secret;

        var fresh = await svc.Rotate(created.Agent.Id, "google:admin", default);
        Assert.NotNull(fresh);
        Assert.NotEqual(old, fresh);
        var after = store.GetById(created.Agent.Id)!;
        Assert.True(AgentSecrets.Verify(fresh!, after.SecretHash));
        Assert.False(AgentSecrets.Verify(old, after.SecretHash));
    }
}
