using System.Net;
using System.Text;

namespace Kalitka;

/// <summary>
/// The Telegram face of the gate: it turns a pending request into a message with
/// buttons, feeds button presses and slash-commands back into the
/// <see cref="ApprovalEngine"/>, and renders the results. All Telegram-specific
/// shape (message text, inline keyboards, the <c>callback_data</c> verbs, the
/// command replies) lives here and nowhere else — the engine knows none of it.
/// </summary>
public sealed class TelegramNotifier : INotifier
{
    private readonly ITelegramClient _telegram;
    private readonly ApprovalEngine _engine;
    private readonly GateOptions _options;

    public TelegramNotifier(ITelegramClient telegram, ApprovalEngine engine, GateOptions options)
    {
        _telegram = telegram;
        _engine = engine;
        _options = options;
    }

    public bool Ready => _telegram.Ready;

    // ---- Announce a new request --------------------------------------------

    public async Task Announce(PendingRequest request, CancellationToken ct)
    {
        // Notify only now, after the visitor typed something. Otherwise every
        // passing scanner would ring the bell.
        foreach (var chatId in NotificationTargets())
            await _telegram.SendMessage(chatId, Describe(request), Buttons(request), ct);
    }

    private IEnumerable<string> NotificationTargets()
    {
        if (_options.AdminIds.Length > 0)
            return _options.AdminIds.Select(id => id.ToString());

        return string.IsNullOrWhiteSpace(_options.ChatId)
            ? Array.Empty<string>()
            : new[] { _options.ChatId };
    }

    private static string H(string s) => WebUtility.HtmlEncode(s);

    private static string Describe(PendingRequest r)
    {
        var place = string.IsNullOrEmpty(r.CountryCode)
            ? "(private/unknown)"
            : $"{H(r.City)}, {H(r.Country)} [{H(r.CountryCode)}]";

        return "\U0001F514 <b>Someone is at the door</b>\n"
             + $"Target: <code>{H(r.Target)}</code>\n"
             + $"Says: <b>{H(r.Input)}</b>\n"
             // The command is the crux of what is being approved — show it prominently.
             + (string.IsNullOrEmpty(r.Command) ? "" : $"Command: <code>{H(r.Command)}</code>\n")
             + (string.IsNullOrEmpty(r.SourceAddr) ? "" : $"From-addr: <code>{H(r.SourceAddr)}</code>\n")
             + $"IP: <code>{H(r.Ip)}</code>\n"
             + $"From: {place}\n"
             + $"<i>{r.Raised:yyyy-MM-dd HH:mm:ss zzz}</i>";
    }

    private static object Buttons(PendingRequest r) => new
    {
        inline_keyboard = new object[]
        {
            new object[]
            {
                new { text = "✅ Let in",  callback_data = $"ok|{r.Id}" },
                new { text = "✖ Reject",  callback_data = $"no|{r.Id}" }
            },
            new object[]
            {
                new { text = "⭐ Always this IP",   callback_data = $"aip|{r.Id}" },
                new { text = "⭐ Always this name", callback_data = $"ain|{r.Id}" }
            },
            new object[]
            {
                new { text = "⛔ IP",      callback_data = $"bip|{r.Id}" },
                new { text = "⛔ Name",    callback_data = $"bin|{r.Id}" },
                new { text = "⛔ Country", callback_data = $"bco|{r.Id}" }
            }
        }
    };

    // ---- The operator presses a button -------------------------------------

    public async Task HandleCallback(string data, long fromId, string callbackId,
        string chatId, long messageId, CancellationToken ct)
    {
        if (!_engine.IsAdmin(fromId))
        {
            await _telegram.AnswerCallback(callbackId, "Not permitted", ct);
            return;
        }

        var parts = data.Split('|', 2);
        var verb = parts[0];
        var argument = parts.Length > 1 ? parts[1] : "";

        // Removing an entry from a list works on an index, not on a request.
        if (verb is "rmb" or "rma")
        {
            var list = verb == "rmb" ? "block" : "allow";
            var removed = int.TryParse(argument, out var index) && _engine.RemoveListEntry(list, index);
            await _telegram.AnswerCallback(callbackId, removed ? "removed" : "-", ct);
            if (removed) await _telegram.EditMessage(chatId, messageId, "Entry removed.", null, ct);
            return;
        }

        var result = await _engine.Decide(argument, verb, $"telegram:{fromId}");

        switch (result.Outcome)
        {
            case CallbackOutcome.Expired:
                await _telegram.AnswerCallback(callbackId, "expired", ct);
                await _telegram.EditMessage(chatId, messageId, "That request has expired.", null, ct);
                break;

            case CallbackOutcome.AlreadyHandled:
                await _telegram.AnswerCallback(callbackId, "already handled", ct);
                break;

            case CallbackOutcome.Decided:
                await _telegram.AnswerCallback(callbackId, null, ct);
                await _telegram.EditMessage(chatId, messageId,
                    $"{Describe(result.Request!)}\n\n<b>{result.Text}</b>", null, ct);
                break;

            case CallbackOutcome.Pending:
                // Recorded, but a policy needs more distinct approvers (and a Telegram
                // tap does not count toward a quorum > 1). Acknowledge, keep the buttons.
                await _telegram.AnswerCallback(callbackId, result.Text ?? "recorded", ct);
                break;

            case CallbackOutcome.Ignored:
            default:
                await _telegram.AnswerCallback(callbackId, null, ct);
                break;
        }
    }

    // ---- Slash-commands -----------------------------------------------------

    public Task ShowBlockList(string chatId, CancellationToken ct) =>
        ShowList(chatId, "block", "Block list", "rmb", ct);

    public Task ShowAllowList(string chatId, CancellationToken ct) =>
        ShowList(chatId, "allow", "Allow list", "rma", ct);

    private async Task ShowList(string chatId, string list, string title, string removePrefix, CancellationToken ct)
    {
        var entries = _engine.ListEntries(list);
        if (entries.Count == 0)
        {
            await _telegram.SendMessage(chatId, $"{title} is empty.", null, ct);
            return;
        }

        var text = new StringBuilder($"<b>{title}</b>\n");
        var rows = new List<object[]>();

        for (var i = 0; i < entries.Count; i++)
        {
            text.Append($"{i + 1}. [{H(entries[i].Resource)} · {H(entries[i].Type)}] <code>{H(entries[i].Value)}</code>\n");
            rows.Add(new object[] { new { text = $"remove {i + 1}", callback_data = $"{removePrefix}|{i}" } });
        }

        await _telegram.SendMessage(chatId, text.ToString(), new { inline_keyboard = rows.ToArray() }, ct);
    }

    /// <summary>
    /// Adds an entry by hand, without waiting for someone to ring first.
    /// Until this existed the lists could only grow as a reaction: you could
    /// not wave a colleague through before their first visit, nor turn away an
    /// address you already knew was trouble.
    /// </summary>
    public string ListAddCommand(string list, string argument)
    {
        var usage = list == "allow"
            ? "Usage: <code>/allow ip 203.0.113.5</code> or <code>/allow name anna@example.com</code>"
            : "Usage: <code>/block ip 203.0.113.5</code>, <code>/block name mallory</code> or <code>/block country CN</code>";

        var parts = (argument ?? "").Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return usage;

        var type = parts[0].ToLowerInvariant() switch
        {
            "ip"                 => "ip",
            "name" or "subject"  => "subject",
            "country"            => "country",
            _                    => ""
        };
        if (type.Length == 0) return usage;

        // Country on the allow list would mean "everyone from there walks in".
        if (list == "allow" && type == "country")
            return "Country works on the block list only — as a way in it is far too coarse.";

        var value = parts[1].Trim();
        if (value.Length is 0 or > 120) return usage;

        if (type == "ip" && !IPAddress.TryParse(value, out _))
            return "That does not look like an IP address.";

        if (type == "country" && value.Length != 2)
            return "Country must be a two-letter code, e.g. <code>CN</code>.";

        _engine.AddListEntry(list, type, value);

        var where = list == "allow" ? "allow list" : "block list";
        var effect = list == "allow"
            ? "They will be let through without asking."
            : "They will be turned away silently, with no notification.";

        return $"Added to the {where}: [{H(type)}] <code>{H(value)}</code>\n{effect}";
    }

    public string MuteCommand(string argument)
    {
        if (argument.Trim() is "off" or "0")
        {
            _engine.ClearMute();
            return "Mute off.";
        }

        var minutes = int.TryParse(argument.Trim(), out var m) && m > 0 ? m : 60;
        var until = _engine.SetMute(minutes);

        return $"Muted for {minutes} min (until {until:HH:mm}). "
             + "Everyone who rings is silently added to the block list by IP.";
    }

    public string SessionCommand(string argument)
    {
        argument = (argument ?? "").Trim();

        if (argument.Length == 0)
            return $"Session length: <b>{_engine.SessionMinutes} min</b>.\n<code>/session 720</code> to change.";

        if (!int.TryParse(argument, out var minutes) || minutes < 1 || minutes > 60 * 24 * 90)
            return "Give minutes, e.g. <code>/session 720</code> (1..129600).";

        _engine.SetSessionMinutes(minutes);
        return $"Session length set to <b>{minutes} min</b>. Applies to new approvals.";
    }

    public string HostsCommand()
    {
        var hosts = _engine.EnforcedHosts();
        return hosts.Count == 0
            ? "No host is currently guarded."
            : "<b>Guarded hosts</b>\n" + string.Join("\n", hosts.Select(h => $"• <code>{H(h)}</code>"));
    }

    public Task Reply(string chatId, string html, CancellationToken ct) =>
        _telegram.SendMessage(chatId, html, null, ct);
}
