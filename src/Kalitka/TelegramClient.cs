using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Thin wrapper over the Telegram Bot API — only the four calls kalitka needs.
///
/// Two details here were paid for in debugging time:
///
/// 1. The URL is always built absolute. The token contains a colon, so a
///    relative path like <c>bot123:ABC/sendMessage</c> is parsed by .NET as an
///    absolute URI with scheme "bot123", <c>BaseAddress</c> is dropped and the
///    call fails with "The URI scheme is not supported".
///
/// 2. Null fields are never serialised. Sending <c>reply_markup: null</c> makes
///    Telegram answer <c>400 object expected as reply markup</c>, which breaks
///    every plain message if one model is reused for both cases.
///
/// Note also that the token sits in the URL path, so the default HttpClient
/// logger would write it to the log in clear text — see appsettings.json.
/// </summary>
public sealed class TelegramClient : ITelegramClient
{
    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly GateOptions _options;
    private readonly ILogger<TelegramClient> _log;

    public TelegramClient(HttpClient http, IOptions<GateOptions> options, ILogger<TelegramClient> log)
    {
        _http = http;
        _options = options.Value;
        _log = log;
        _http.Timeout = TimeSpan.FromSeconds(15);
    }

    public bool Ready => !string.IsNullOrWhiteSpace(_options.BotToken);

    private async Task<bool> Call(string method, object payload, CancellationToken ct)
    {
        if (!Ready) return false;
        try
        {
            var url = $"https://api.telegram.org/bot{_options.BotToken}/{method}";
            var body = new StringContent(JsonSerializer.Serialize(payload, Json), Encoding.UTF8, "application/json");

            using var response = await _http.PostAsync(url, body, ct);
            if (response.IsSuccessStatusCode) return true;

            // The response body explains the mistake; the status alone does not.
            var text = await response.Content.ReadAsStringAsync(ct);
            _log.LogWarning("Telegram {Method} failed: {Status} {Body}", method, (int)response.StatusCode, text);
            return false;
        }
        catch (Exception e)
        {
            _log.LogWarning("Telegram {Method} failed: {Message}", method, e.Message);
            return false;
        }
    }

    public Task<bool> SendMessage(string chatId, string html, object? keyboard, CancellationToken ct) =>
        Call("sendMessage", new
        {
            chat_id = chatId,
            text = html,
            parse_mode = "HTML",
            disable_web_page_preview = true,
            reply_markup = keyboard
        }, ct);

    public Task<bool> EditMessage(string chatId, long messageId, string html, object? keyboard, CancellationToken ct) =>
        Call("editMessageText", new
        {
            chat_id = chatId,
            message_id = messageId,
            text = html,
            parse_mode = "HTML",
            disable_web_page_preview = true,
            reply_markup = keyboard
        }, ct);

    /// <summary>
    /// Answers a button press. Telegram keeps showing a spinner on the button
    /// until this is called, so it is not optional.
    /// </summary>
    public Task<bool> AnswerCallback(string callbackId, string? text, CancellationToken ct) =>
        Call("answerCallbackQuery", new { callback_query_id = callbackId, text }, ct);
}
