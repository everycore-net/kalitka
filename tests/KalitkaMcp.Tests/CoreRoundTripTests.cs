using Kalitka;
using KalitkaMcp;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaMcp.Tests;

/// <summary>
/// The whole point end to end: the MCP server enrolls, raises a request through its own
/// <see cref="CoreClient"/> against the real Core pipeline, and can only ever get it to
/// <c>waiting</c> — a human (here, a direct <c>GateService.Decide</c>, never the AI) is what
/// turns it into <c>approved</c> with a grant. Nothing is stubbed but the clock and Telegram.
/// </summary>
public class CoreRoundTripTests : IClassFixture<CoreRoundTripTests.Factory>
{
    private readonly Factory _f;
    public CoreRoundTripTests(Factory f) => _f = f;

    private GateService Gate => _f.Services.GetRequiredService<GateService>();

    // A CoreClient wired to the test server, enrolled via a freshly minted one-time token for an
    // agent scoped to access.request on ssh:* — exactly how the server bootstraps in the field.
    private async Task<(CoreClient client, string keyPath, string statePath)> Enrolled()
    {
        var keyPath = Path.Combine(Path.GetTempPath(), "kalitka-mcp-rt-" + Guid.NewGuid().ToString("N") + ".p8");
        var statePath = Path.Combine(Path.GetTempPath(), "kalitka-mcp-rt-" + Guid.NewGuid().ToString("N") + ".json");
        var token = await _f.Services.GetRequiredService<AgentService>().CreateEnrollmentToken(
            "mcp", "generic", new[] { AgentCapabilities.Request, AgentCapabilities.Redeem },
            new[] { "ssh:*" }, "google:admin", default);

        var http = _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var key = SigningKey.LoadOrCreate(keyPath);
        var cfg = Options.Create(new McpConfig { KeyPath = keyPath, StatePath = statePath, EnrollmentToken = token });
        var client = new CoreClient(http, key, cfg);
        await client.EnsureEnrolledAsync(default);
        return (client, keyPath, statePath);
    }

    [Fact]
    public async Task Request_access_raises_a_real_request_that_only_a_human_can_approve()
    {
        var (client, keyPath, statePath) = await Enrolled();
        try
        {
            var raised = await client.RequestAccessAsync("ssh:box-01", profile: null, subjectIdentity: null, default);
            Assert.Equal(200, raised.Status);
            Assert.False(string.IsNullOrEmpty(raised.Id));
            Assert.Equal("waiting", raised.State);

            // Polling before a human decides stays waiting — the AI cannot advance it.
            var polled = await client.GetRequestAsync(raised.Id!, default);
            Assert.Equal("waiting", polled.State);
            Assert.Null(polled.Grant);

            // A human approves out-of-band; now the poll yields the one-time grant.
            Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(raised.Id!, "ok", "google:admin")).Outcome);
            var approved = await client.GetRequestAsync(raised.Id!, default);
            Assert.Equal("approved", approved.State);
            Assert.False(string.IsNullOrEmpty(approved.Grant));
        }
        finally { File.Delete(keyPath); File.Delete(statePath); }
    }

    [Fact]
    public async Task A_request_for_an_out_of_scope_resource_is_forbidden()
    {
        var (client, keyPath, statePath) = await Enrolled();
        try
        {
            // The agent is scoped to ssh:* only; a db: resource is not its to raise.
            var raised = await client.RequestAccessAsync("db:sql01/orders", profile: null, subjectIdentity: null, default);
            Assert.Equal(403, raised.Status);
        }
        finally { File.Delete(keyPath); File.Delete(statePath); }
    }

    public sealed class Factory : WebApplicationFactory<Program>
    {
        public FakeTelegram Telegram { get; } = new();
        public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        private readonly string _stateDir = Path.Combine(Path.GetTempPath(), "kalitka-mcp-rt-" + Guid.NewGuid().ToString("N"));

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
