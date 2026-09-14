using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>Subscription storage, VAPID key persistence, and the push notifier's targeting — who a
/// new request reaches, and that a dropped subscription is pruned.</summary>
public class WebPushTests
{
    private sealed class FakeSender : IWebPushSender
    {
        public readonly List<PushSubscription> Sent = new();
        public PushResult Result = PushResult.Ok;
        public Task<PushResult> Send(PushSubscription sub, byte[] payload, CancellationToken ct)
        { Sent.Add(sub); return Task.FromResult(Result); }
    }

    private static PendingRequest Req() => new()
    {
        Id = "r1", Target = "prod-01", Input = "sergej", Resource = "ssh:prod-01",
        Raised = DateTimeOffset.UnixEpoch, State = "waiting",
    };

    [Fact]
    public void Subscriptions_dedupe_by_endpoint_and_filter_by_principal()
    {
        var store = new PushSubscriptionStore(new InMemoryConfigStore());
        store.Add(new PushSubscription("https://push/1", "p", "a", "op-1", "now"));
        store.Add(new PushSubscription("https://push/1", "p2", "a2", "op-1", "later"));   // same endpoint replaces
        store.Add(new PushSubscription("https://push/2", "p", "a", "op-2", "now"));

        Assert.Equal(2, store.All().Count);
        Assert.Equal("p2", store.ForPrincipal("op-1").Single().P256dh);
        Assert.True(store.RemoveByEndpoint("https://push/2"));
        Assert.Single(store.All());
    }

    [Fact]
    public void Vapid_keys_are_generated_once_and_stable_across_instances()
    {
        var config = new InMemoryConfigStore();
        var a = new VapidKeyProvider(config).PublicKey;
        var b = new VapidKeyProvider(config).PublicKey;   // a second instance on the same store
        Assert.False(string.IsNullOrEmpty(a));
        Assert.Equal(a, b);
    }

    private static (PushNotifier n, PushSubscriptionStore subs, FakeSender fake) Notifier()
    {
        var clock = new FakeTimeProvider();
        var config = new InMemoryConfigStore();
        var prin = new PrincipalService(config, new InMemoryAuditStore(), clock);
        prin.Save("op-1", "A", new[] { "app:cred1", "google:sub1" }, "sys", default).Wait();
        var subs = new PushSubscriptionStore(config);
        subs.Add(new PushSubscription("https://push/1", "p", "a", "op-1", "now"));
        subs.Add(new PushSubscription("https://push/2", "p", "a", "op-2", "now"));
        var fake = new FakeSender();
        return (new PushNotifier(subs, prin, fake, NullLogger<PushNotifier>.Instance), subs, fake);
    }

    [Fact]
    public async Task Ask_the_admins_pushes_to_every_registered_device()
    {
        var (n, _, fake) = Notifier();
        await n.Announce(Req(), NotifyRouting.Admins, default);
        Assert.Equal(2, fake.Sent.Count);
    }

    [Fact]
    public async Task A_routed_request_pushes_only_to_the_resolved_operator()
    {
        var (n, _, fake) = Notifier();
        await n.Announce(Req(), new NotifyRouting(new[] { "app:cred1" }, IncludeAdmins: false), default);
        Assert.Single(fake.Sent);
        Assert.Equal("https://push/1", fake.Sent[0].Endpoint);
    }

    [Fact]
    public async Task A_subscription_the_push_service_reports_gone_is_pruned()
    {
        var (n, subs, fake) = Notifier();
        fake.Result = PushResult.Gone;
        await n.Announce(Req(), NotifyRouting.Admins, default);
        Assert.Empty(subs.All());
    }
}
