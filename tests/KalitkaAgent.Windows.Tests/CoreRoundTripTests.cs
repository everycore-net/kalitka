using Kalitka;
using KalitkaAgent;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The whole point of the Windows agent, end to end against the real Core pipeline: a request
/// signed by the CNG platform key and assembled by the agent's own <see cref="CoreClient"/> is
/// accepted, and the OS-asserted subject is <b>trusted</b> for subject-approval only because
/// the agent holds <c>subject.assert</c>. The same request from an agent without that
/// capability is refused as <c>claimed-not-asserted</c>. This exercises the agent's HTTP
/// assembly (headers, body-hash-over-the-exact-bytes, signature) against Core's real
/// verification — nothing is stubbed but the clock and Telegram.
/// </summary>
public class CoreRoundTripTests : IClassFixture<CoreRoundTripTests.Factory>
{
    private readonly Factory _f;
    public CoreRoundTripTests(Factory f) => _f = f;

    // A P-256 CNG key, a matching registered agent, and a CoreClient wired to the test server.
    private (CoreClient client, string agentId, PlatformKey key, string keyName) Seed(string[] caps, string[]? resources = null)
    {
        var keyName = "kalitka-rt-" + Guid.NewGuid().ToString("N");
        var key = PlatformKey.OpenOrCreate(keyName, preferSoftware: true, machineKey: false);
        var agentId = Guid.NewGuid().ToString("N")[..16];
        var spki = key.PublicKeySpkiBase64();
        _f.Services.GetRequiredService<IAgentStore>().Create(new Agent(
            agentId, agentId, "windows", "h", AgentStatus.Active, "",
            caps, resources ?? new[] { "ssh:*" }, "", _f.Clock.GetUtcNow(), null, "", null)
        {
            Tags = new[] { "env:rt" },
            Keys = new[] { new AgentKey(AgentSignatures.KeyIdFor(spki)!, spki, _f.Clock.GetUtcNow()) },
        });
        var http = _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        return (new CoreClient(http, key), agentId, key, keyName);
    }

    private Task Policy(SubjectApproval subject) =>
        _f.Services.GetRequiredService<PolicyService>()
            .Save(new AccessPolicy("rt", "ssh:*", new[] { "env:rt" }, 1, 0) { Subject = subject }, "google:admin", default);

    private Task Link(string id, params string[] identities) =>
        _f.Services.GetRequiredService<PrincipalService>().Save(id, id, identities, "google:admin", default);

    private GateService Gate => _f.Services.GetRequiredService<GateService>();

    private static CallerSubject Anna =>
        new("S-1-5-21-1-2-3-1001", "CONTOSO\\anna", "anna", "os:CONTOSO\\anna");

    [Fact]
    public async Task A_trusted_agents_signed_request_is_accepted_and_the_subject_is_asserted()
    {
        await Policy(SubjectApproval.Required);
        await Link("anna", "os:CONTOSO\\anna", "google:sub-anna");
        var (client, agentId, key, keyName) = Seed(new[] { "ssh", AgentCapabilities.AssertSubject });
        try
        {
            var r = await client.RaiseAsync(agentId, Anna, "ssh:h", command: null, default);
            Assert.Equal(200, r.Status);      // not a 409 refusal
            Assert.Equal("waiting", r.State); // subject asserted, mapped, is the beneficiary
        }
        finally { key.Dispose(); PlatformKey.Delete(keyName, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public async Task Rdp_request_is_raised_approved_and_redeemed_with_the_subject_and_expiry()
    {
        // The RDP JIT path the Windows agent drives: raise rdp:<host> for the caller, a human
        // approves, poll yields the grant, redeem returns the Core-approved subject + exact expiry
        // that the local enforcer then trusts to add the member until.
        var (client, agentId, key, keyName) = Seed(
            new[] { AgentCapabilities.Request, AgentCapabilities.Redeem, AgentCapabilities.AssertSubject },
            new[] { "rdp:*" });
        try
        {
            var raised = await client.RaiseAsync(agentId, Anna, "rdp:hostA", command: null, default);
            Assert.Equal(200, raised.Status);
            Assert.Equal("waiting", raised.State);

            // Before approval, polling stays waiting with no grant.
            var pending = await client.PollAsync(agentId, raised.Id!, default);
            Assert.Equal("waiting", pending.State);
            Assert.Null(pending.Grant);

            Assert.Equal(CallbackOutcome.Decided, (await Gate.Decide(raised.Id!, "ok", "google:admin")).Outcome);
            var approved = await client.PollAsync(agentId, raised.Id!, default);
            Assert.Equal("approved", approved.State);
            Assert.False(string.IsNullOrEmpty(approved.Grant));

            var redeemed = await client.RedeemAsync(agentId, approved.Grant!, default);
            Assert.Equal(200, redeemed.Status);
            Assert.False(string.IsNullOrEmpty(redeemed.SessionId));
            Assert.Equal("anna", redeemed.Subject);      // Core-approved beneficiary
            Assert.NotNull(redeemed.ExpiresAt);           // exact expiry the enforcer removes at
        }
        finally { key.Dispose(); PlatformKey.Delete(keyName, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public async Task An_untrusted_agents_claimed_subject_is_refused_under_required()
    {
        await Policy(SubjectApproval.Required);
        await Link("anna", "os:CONTOSO\\anna", "google:sub-anna");
        var (client, agentId, key, keyName) = Seed(new[] { "ssh" });   // no subject.assert
        try
        {
            var r = await client.RaiseAsync(agentId, Anna, "ssh:h", command: null, default);
            Assert.Equal(409, r.Status);
            Assert.Equal("claimed-not-asserted", r.State);
        }
        finally { key.Dispose(); PlatformKey.Delete(keyName, preferSoftware: true, machineKey: false); }
    }

    [Fact]
    public async Task A_bad_signature_is_rejected_at_authentication()
    {
        var (_, agentId, key, keyName) = Seed(new[] { "ssh", AgentCapabilities.AssertSubject });
        try
        {
            // A CoreClient holding a DIFFERENT key than the one registered for the agent.
            var otherName = "kalitka-rt-" + Guid.NewGuid().ToString("N");
            using var other = PlatformKey.OpenOrCreate(otherName, preferSoftware: true, machineKey: false);
            var http = _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var rogue = new CoreClient(http, other);
            try
            {
                var r = await rogue.RaiseAsync(agentId, Anna, "ssh:h", command: null, default);
                Assert.Equal(403, r.Status);
            }
            finally { PlatformKey.Delete(otherName, preferSoftware: true, machineKey: false); }
        }
        finally { key.Dispose(); PlatformKey.Delete(keyName, preferSoftware: true, machineKey: false); }
    }

    public sealed class Factory : WebApplicationFactory<Program>
    {
        public FakeTelegram Telegram { get; } = new();
        public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        private readonly string _stateDir = Path.Combine(Path.GetTempPath(), "kalitka-rt-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
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
