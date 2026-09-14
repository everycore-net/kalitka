using System.Security.Cryptography;
using Kalitka;
using KalitkaMcpGateway;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaMcpGateway.Tests;

/// <summary>
/// Core as the authority, end to end against the real Core pipeline: the gateway raises an
/// <c>mcp:&lt;alias&gt;/&lt;tool&gt;</c> request, a human (a direct <c>GateService.Decide</c>, never
/// the AI) approves it in Core, and only then is the exact call forwarded — once. The at-most-once
/// claim is Core's redeem-once grant, so a second attempt cannot re-dispatch.
/// </summary>
public class CoreAuthorityTests : IClassFixture<CoreAuthorityTests.Factory>
{
    private readonly Factory _f;
    public CoreAuthorityTests(Factory f) => _f = f;

    private const string Alias = "azure-prod";
    private const string UpstreamId = "uid-1";
    private static readonly AuthenticatedCallContext Ctx =
        new(new WorkloadRef("ai:claude:i1"), new SubjectRef("operator:sergej", false));

    private GateService Gate => _f.Services.GetRequiredService<GateService>();

    // A gateway agent enrolled in Core (access.request + grant.redeem on mcp:*), a CoreAuthority
    // signing with its key, and a proxy over a fake upstream classifying merge as needing approval.
    private (GatewayProxy proxy, FakeUpstream upstream, CoreAuthority authority, string agentId) Build()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        var agentId = Guid.NewGuid().ToString("N")[..16];
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            agentId, agentId, "generic", "h", AgentStatus.Active, "",
            new[] { AgentCapabilities.Request, AgentCapabilities.Redeem }, new[] { "mcp:*" }, "",
            _f.Clock.GetUtcNow(), null, "", null)
        { Keys = new[] { new AgentKey(AgentSignatures.KeyIdFor(spki)!, spki, _f.Clock.GetUtcNow()) } });

        var http = _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var authority = new CoreAuthority(http, key, agentId);

        var upstream = new FakeUpstream();
        upstream.Tools.Add(new UpstreamTool("merge_pull_request", "{\"type\":\"object\"}"));
        var classifier = new DictionaryToolClassifier();
        var proxy = new GatewayProxy(upstream, classifier, authority, Alias, UpstreamId);
        proxy.RefreshInventoryAsync(default).GetAwaiter().GetResult();
        proxy.Inventory.TryGet("merge_pull_request", out var t);
        classifier.Set(Alias, "merge_pull_request", t.ContractHashHex, ToolClass.Approval(1));
        return (proxy, upstream, authority, agentId);
    }

    private string Fingerprint(GatewayProxy proxy, string args)
    {
        proxy.Inventory.TryGet("merge_pull_request", out var t);
        var fp = CallFingerprint.Compute(Alias, "merge_pull_request", proxy.Inventory.ContractId("merge_pull_request"),
            Ctx, Jcs.Canonicalize(args));
        return CallFingerprint.ToBase64Url(fp);
    }

    [Fact]
    public async Task A_call_is_raised_in_core_and_forwarded_only_after_a_human_approves()
    {
        var (proxy, upstream, authority, _) = Build();

        // First issue: the gateway raises an mcp: request in Core and waits — nothing forwarded.
        var pending = await proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);
        Assert.Equal(HandleKind.Pending, pending.Kind);
        Assert.Equal(0, upstream.CallCount);

        // Re-issue before approval: still pending.
        Assert.Equal(HandleKind.Pending, (await proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default)).Kind);
        Assert.Equal(0, upstream.CallCount);

        // A human approves in Core (out of band).
        Assert.True(authority.TryPendingRequest(Fingerprint(proxy, "{\"pr\":42}"), out var reqId));
        Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(reqId, "ok", "google:admin")).Outcome);

        // The re-issued call is now claimed (grant redeemed) and forwarded exactly once.
        var done = await proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);
        Assert.Equal(HandleKind.Result, done.Kind);
        Assert.Equal(CallState.Executed, done.State);
        Assert.Equal(1, upstream.CallCount);

        // A further re-issue cannot re-dispatch: the Core grant is spent (durable at-most-once).
        var again = await proxy.HandleAsync("merge_pull_request", "{\"pr\":42}", Ctx, default);
        Assert.NotEqual(HandleKind.Result, again.Kind);
        Assert.Equal(1, upstream.CallCount);
    }

    [Fact]
    public async Task A_denied_request_is_refused_and_not_forwarded()
    {
        var (proxy, upstream, authority, _) = Build();
        await proxy.HandleAsync("merge_pull_request", "{\"pr\":7}", Ctx, default);   // raises in Core
        Assert.True(authority.TryPendingRequest(Fingerprint(proxy, "{\"pr\":7}"), out var reqId));

        Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(reqId, "no", "google:admin")).Outcome);
        var r = await proxy.HandleAsync("merge_pull_request", "{\"pr\":7}", Ctx, default);
        Assert.Equal(HandleKind.Denied, r.Kind);
        Assert.Equal(0, upstream.CallCount);
    }

    public sealed class Factory : WebApplicationFactory<Program>
    {
        public FakeTelegram Telegram { get; } = new();
        public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        private readonly string _stateDir = Path.Combine(Path.GetTempPath(), "kalitka-gw-rt-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            Directory.CreateDirectory(_stateDir);
            builder.UseSetting("Kalitka:BotToken", "test-token");
            builder.UseSetting("Kalitka:WebhookPath", "/tg/secret-path");
            builder.UseSetting("Kalitka:WebhookSecret", "webhook-secret");
            builder.UseSetting("Kalitka:HmacSecret", "unit-test-signing-key-0123456789");
            builder.UseSetting("Kalitka:GateHost", "gate.example.com");
            builder.UseSetting("Kalitka:GeoUrl", "");
            builder.UseSetting("Kalitka:AdminIds:0", "111");
            builder.UseSetting("Kalitka:ListsPath", Path.Combine(_stateDir, "lists.json"));
            builder.UseSetting("Kalitka:EnforcedPath", Path.Combine(_stateDir, "enforced.json"));
            builder.UseSetting("Kalitka:SettingsPath", Path.Combine(_stateDir, "settings.json"));
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<ITelegramClient>(Telegram);
                services.AddSingleton<TimeProvider>(Clock);
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { if (Directory.Exists(_stateDir)) Directory.Delete(_stateDir, true); } catch { }
        }
    }
}
