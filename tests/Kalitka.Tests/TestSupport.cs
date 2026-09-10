using System.Collections.Concurrent;
using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;

namespace Kalitka.Tests;

/// <summary>Records what would have gone to Telegram, so nothing hits the network.</summary>
public sealed class FakeTelegram : ITelegramClient
{
    public readonly record struct Sent(string ChatId, string Html);
    public readonly record struct Callback(string Id, string? Text);

    public ConcurrentQueue<Sent> Messages { get; } = new();
    public ConcurrentQueue<Sent> Edits { get; } = new();
    public ConcurrentQueue<Callback> Callbacks { get; } = new();

    public bool Ready => true;

    public Task<bool> SendMessage(string chatId, string html, object? keyboard, CancellationToken ct)
    { Messages.Enqueue(new(chatId, html)); return Task.FromResult(true); }

    public Task<bool> EditMessage(string chatId, long messageId, string html, object? keyboard, CancellationToken ct)
    { Edits.Enqueue(new(chatId, html)); return Task.FromResult(true); }

    public Task<bool> AnswerCallback(string callbackId, string? text, CancellationToken ct)
    { Callbacks.Enqueue(new(callbackId, text)); return Task.FromResult(true); }
}

/// <summary>
/// Lets a test set the connection's remote address from the "X-Test-Peer"
/// header. The real client IP cannot be set through TestServer otherwise, and
/// the trusted-proxy logic hinges on it. Test-only, wired via an IStartupFilter
/// so it sits at the very front of the pipeline.
/// </summary>
public sealed class TestPeerStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (ctx, nextMw) =>
        {
            var peer = ctx.Request.Headers["X-Test-Peer"].ToString();
            if (!string.IsNullOrEmpty(peer) && IPAddress.TryParse(peer, out var ip))
                ctx.Connection.RemoteIpAddress = ip;
            await nextMw();
        });
        next(app);
    };
}

public sealed class GateFactory : WebApplicationFactory<Program>
{
    public FakeTelegram Telegram { get; } = new();
    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly string _stateDir = Path.Combine(Path.GetTempPath(), "kalitka-tests-" + Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_stateDir);

        builder.UseSetting("Kalitka:BotToken", "test-token");
        builder.UseSetting("Kalitka:WebhookPath", "/tg/secret-path");
        builder.UseSetting("Kalitka:WebhookSecret", "webhook-secret");
        builder.UseSetting("Kalitka:HmacSecret", "unit-test-signing-key-0123456789");
        builder.UseSetting("Kalitka:GateHost", "gate.example.com");
        builder.UseSetting("Kalitka:CookieDomain", ".example.com");
        builder.UseSetting("Kalitka:GeoUrl", "");                      // no network in tests
        builder.UseSetting("Kalitka:TrustedProxies:0", "10.0.0.0/8");
        builder.UseSetting("Kalitka:BypassNetworks:0", "192.168.0.0/16");
        builder.UseSetting("Kalitka:EnforcedHosts:0", "app.example.com");
        builder.UseSetting("Kalitka:AdminIds:0", "111");
        builder.UseSetting("Kalitka:MaxRequestsPerIp", "5");
        builder.UseSetting("Kalitka:RateWindowMinutes", "10");
        builder.UseSetting("Kalitka:MaxPending", "50");
        builder.UseSetting("Kalitka:ListsPath", Path.Combine(_stateDir, "lists.json"));
        builder.UseSetting("Kalitka:EnforcedPath", Path.Combine(_stateDir, "enforced.json"));
        builder.UseSetting("Kalitka:SettingsPath", Path.Combine(_stateDir, "settings.json"));
        // Enough for the web control plane to be "enabled": Google configured and
        // an admin allowlist present. No network is hit unless a real OIDC code is
        // exchanged, which the tests never do — they mint the admin cookie directly.
        builder.UseSetting("Kalitka:GoogleClientId", "test-client");
        builder.UseSetting("Kalitka:GoogleClientSecret", "test-secret");
        builder.UseSetting("Kalitka:AdminEmails:0", "admin@example.com");
        builder.UseSetting("Kalitka:InternalSecret", "internal-secret");   // /internal/*
        builder.UseSetting("Kalitka:AgentSecret", "agent-secret");         // /agent/*

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<ITelegramClient>(Telegram);
            services.AddSingleton<TimeProvider>(Clock);
            services.AddTransient<IStartupFilter, TestPeerStartupFilter>();
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { if (Directory.Exists(_stateDir)) Directory.Delete(_stateDir, true); } catch { }
    }
}
