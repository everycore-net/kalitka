namespace Kalitka;

/// <summary>
/// The Telegram operations the gate uses. Behind an interface so tests can put
/// a fake in its place and assert what was sent, without a network call — and
/// so the webhook and callback paths are exercisable end to end.
/// </summary>
public interface ITelegramClient
{
    bool Ready { get; }
    Task<bool> SendMessage(string chatId, string html, object? keyboard, CancellationToken ct);
    Task<bool> EditMessage(string chatId, long messageId, string html, object? keyboard, CancellationToken ct);
    Task<bool> AnswerCallback(string callbackId, string? text, CancellationToken ct);
}
