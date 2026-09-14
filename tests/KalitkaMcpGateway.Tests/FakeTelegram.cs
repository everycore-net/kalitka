using Kalitka;

namespace KalitkaMcpGateway.Tests;

/// <summary>A no-op Telegram client so the Core-as-authority integration test hits no network.</summary>
public sealed class FakeTelegram : ITelegramClient
{
    public bool Ready => true;
    public Task<bool> SendMessage(string chatId, string html, object? keyboard, CancellationToken ct) => Task.FromResult(true);
    public Task<bool> EditMessage(string chatId, long messageId, string html, object? keyboard, CancellationToken ct) => Task.FromResult(true);
    public Task<bool> AnswerCallback(string callbackId, string? text, CancellationToken ct) => Task.FromResult(true);
}
