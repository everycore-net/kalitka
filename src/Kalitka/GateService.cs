using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The gate itself. It sits in front of the real login, not instead of it:
/// a visitor states who they are, the operator decides, and only then does the
/// request reach the application — which still asks for its own password.
///
/// Deliberate design choices, each of which cost something to learn:
///
/// * Sessions are a signed cookie, not server state. Nothing to persist, and
///   rotating <see cref="GateOptions.HmacSecret"/> logs everyone out at once.
/// * A blocked visitor is rejected silently and never produces a notification
///   again. That is the whole point of the block list: not to filter traffic,
///   but to stop your phone from buzzing.
/// * Pending requests live in memory and expire. A door nobody answers should
///   close by itself.
/// </summary>
public sealed class GateService
{
    public sealed class PendingRequest
    {
        public string Id = "", Target = "", Input = "", Ip = "";
        public string Country = "", CountryCode = "", City = "";
        public DateTimeOffset Raised;
        public string State = "waiting";   // waiting | approved | denied
    }

    private readonly TelegramClient _telegram;
    private readonly GeoLookup _geo;
    private readonly AccessLists _lists;
    private readonly GateOptions _options;
    private readonly ILogger<GateService> _log;

    private readonly ConcurrentDictionary<string, PendingRequest> _pending = new();
    private readonly HashSet<string> _enforced = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _enforcedLock = new();
    private readonly byte[] _key;

    private int _sessionMinutes;
    private DateTimeOffset _mutedUntil = DateTimeOffset.MinValue;

    public GateService(TelegramClient telegram, GeoLookup geo, AccessLists lists,
        IOptions<GateOptions> options, ILogger<GateService> log)
    {
        _telegram = telegram;
        _geo = geo;
        _lists = lists;
        _options = options.Value;
        _log = log;

        _key = Encoding.UTF8.GetBytes(_options.HmacSecret);
        _sessionMinutes = _options.SessionMinutes;

        LoadEnforced();
        LoadSettings();
    }

    public string InternalSecret => _options.InternalSecret;
    public string CookieName => _options.CookieName;
    public string CookieDomain => _options.CookieDomain;
    public int SessionMinutes => _sessionMinutes;
    public string GateHost => _options.GateHost;

    // ---- Which hosts are armed ---------------------------------------------

    private void LoadEnforced()
    {
        try
        {
            if (File.Exists(_options.EnforcedPath))
            {
                foreach (var h in JsonSerializer.Deserialize<List<string>>(File.ReadAllText(_options.EnforcedPath)) ?? new())
                    _enforced.Add(h);
            }
            else
            {
                foreach (var h in _options.EnforcedHosts) _enforced.Add(h);
            }
        }
        catch (Exception e) { _log.LogWarning("Could not read enforced hosts: {Message}", e.Message); }
    }

    private void SaveEnforced()
    {
        try
        {
            var dir = Path.GetDirectoryName(_options.EnforcedPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_options.EnforcedPath, JsonSerializer.Serialize(_enforced.ToList()));
        }
        catch (Exception e) { _log.LogWarning("Could not write enforced hosts: {Message}", e.Message); }
    }

    public bool IsEnforced(string host) { lock (_enforcedLock) return _enforced.Contains(host); }

    public void SetEnforced(string host, bool on)
    {
        lock (_enforcedLock)
        {
            if (on) _enforced.Add(host); else _enforced.Remove(host);
            SaveEnforced();
        }
    }

    public IReadOnlyList<string> EnforcedHosts() { lock (_enforcedLock) return _enforced.ToList(); }

    // ---- Runtime settings ---------------------------------------------------

    private void LoadSettings()
    {
        try
        {
            if (!File.Exists(_options.SettingsPath)) return;
            using var doc = JsonDocument.Parse(File.ReadAllText(_options.SettingsPath));
            if (doc.RootElement.TryGetProperty("sessionMinutes", out var s) && s.TryGetInt32(out var m) && m > 0)
                _sessionMinutes = m;
        }
        catch (Exception e) { _log.LogWarning("Could not read settings: {Message}", e.Message); }
    }

    private void SaveSettings()
    {
        try
        {
            var dir = Path.GetDirectoryName(_options.SettingsPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_options.SettingsPath, JsonSerializer.Serialize(new { sessionMinutes = _sessionMinutes }));
        }
        catch (Exception e) { _log.LogWarning("Could not write settings: {Message}", e.Message); }
    }

    // ---- Sessions: signed cookie, no storage --------------------------------

    /// <summary>Session valid for one host only — the manual approval path.</summary>
    public string BuildCookie(string host) => Sign($"{Expiry()}:{host}");

    /// <summary>
    /// Session valid for every host ("*"). Used after a Google sign-in: someone
    /// who proved who they are should not have to prove it again per host.
    /// </summary>
    public string BuildGlobalCookie() => Sign($"{Expiry()}:*");

    private long Expiry() => DateTimeOffset.UtcNow.AddMinutes(_sessionMinutes).ToUnixTimeSeconds();

    private string Sign(string body) => $"{body}:{Signature(body)}";

    public bool IsCookieValid(string? cookie, string host)
    {
        if (string.IsNullOrEmpty(cookie)) return false;

        var parts = cookie.Split(':');
        if (parts.Length != 3) return false;
        if (!long.TryParse(parts[0], out var expiry)) return false;
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiry) return false;

        if (parts[1] != "*" && !string.Equals(parts[1], host, StringComparison.OrdinalIgnoreCase))
            return false;

        var expected = Signature($"{parts[0]}:{parts[1]}");
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(parts[2]));
    }

    private string Signature(string value)
    {
        using var hmac = new HMACSHA256(_key);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    // ---- OAuth state: carries the target, signed, no storage ----------------

    public string BuildState(string target)
    {
        var body = $"{DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds()}|{target}";
        return $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(body))}.{Signature(body)}";
    }

    public bool TryReadState(string state, out string target)
    {
        target = "";
        if (string.IsNullOrEmpty(state)) return false;

        var parts = state.Split('.');
        if (parts.Length != 2) return false;

        string body;
        try { body = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])); }
        catch { return false; }

        var expected = Signature(body);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(parts[1])))
            return false;

        var fields = body.Split('|', 2);
        if (fields.Length != 2 || !long.TryParse(fields[0], out var expiry)) return false;
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiry) return false;

        target = fields[1];
        return true;
    }

    /// <summary>
    /// Only our own hosts may be redirect targets, or the gate becomes an open
    /// redirect. The parent domain is derived from <see cref="GateOptions.GateHost"/>:
    /// gate.example.com allows example.com and anything below it.
    /// </summary>
    public bool IsOurHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        var dot = _options.GateHost.IndexOf('.');
        if (dot < 0) return false;

        var parent = _options.GateHost[(dot + 1)..];
        return host.Equals(parent, StringComparison.OrdinalIgnoreCase)
            || host.EndsWith("." + parent, StringComparison.OrdinalIgnoreCase);
    }

    // ---- The way back in ----------------------------------------------------

    /// <summary>
    /// The forwardAuth is fail-closed: if the gate is down, nothing gets in.
    /// These networks are the tested way back — usually the LAN you are sitting
    /// on when you have to fix the gate itself.
    /// </summary>
    public bool IsBypassed(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;

        foreach (var network in _options.BypassNetworks)
        {
            try { if (IPNetwork.Parse(network.Trim()).Contains(address)) return true; }
            catch { /* a malformed entry must not break the check */ }
        }
        return false;
    }

    public bool IsAllowedIp(string ip) => _lists.IsAllowed(ip, "");

    // ---- Mute ---------------------------------------------------------------

    /// <summary>
    /// While muted, every new caller goes silently onto the block list by IP.
    /// For the night someone decides to hammer the door.
    /// </summary>
    public bool IsMuted => DateTimeOffset.Now < _mutedUntil;
    public DateTimeOffset MutedUntil => _mutedUntil;

    public bool IsAdmin(long telegramUserId) => _options.AdminIds.Contains(telegramUserId);

    // ---- A visitor rings ----------------------------------------------------

    public async Task<(string state, string id)> Request(string target, string input, string ip, CancellationToken ct)
    {
        input = (input ?? "").Trim();
        if (input.Length is 0 or > 120) return ("invalid", "");
        if (!IsOurHost(target)) return ("invalid", "");

        var place = await _geo.Locate(ip, ct);

        // Allow list: straight through, no question asked.
        if (_lists.IsAllowed(ip, input)) return ("allowed", "");

        // Block list: silent rejection, and above all no notification.
        if (_lists.IsBlocked(ip, input, place.CountryCode))
        {
            _log.LogInformation("Blocked caller turned away: ip={Ip} input={Input} country={Country}",
                ip, input, place.CountryCode);
            return ("blocked", "");
        }

        if (IsMuted)
        {
            _lists.Add("block", "ip", ip, Now());
            _log.LogInformation("Muted — silently blocked {Ip}", ip);
            return ("blocked", "");
        }

        DropExpired();

        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var request = new PendingRequest
        {
            Id = id, Target = target, Input = input, Ip = ip,
            Country = place.Country, CountryCode = place.CountryCode, City = place.City,
            Raised = DateTimeOffset.Now, State = "waiting"
        };
        _pending[id] = request;

        // Notify only now, after the visitor typed something. Otherwise every
        // passing scanner would ring the bell.
        foreach (var chatId in NotificationTargets())
            await _telegram.SendMessage(chatId, Describe(request), Buttons(request), ct);

        return ("waiting", id);
    }

    private IEnumerable<string> NotificationTargets()
    {
        if (_options.AdminIds.Length > 0)
            return _options.AdminIds.Select(id => id.ToString());

        return string.IsNullOrWhiteSpace(_options.ChatId)
            ? Array.Empty<string>()
            : new[] { _options.ChatId };
    }

    public string? StateOf(string id) => _pending.TryGetValue(id, out var r) ? r.State : null;
    public string? TargetOf(string id) => _pending.TryGetValue(id, out var r) ? r.Target : null;

    private void DropExpired()
    {
        var cutoff = DateTimeOffset.Now.AddMinutes(-_options.PendingMinutes);
        foreach (var kv in _pending)
            if (kv.Value.Raised < cutoff) _pending.TryRemove(kv.Key, out _);
    }

    private static string Now() => DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm");
    private static string H(string s) => WebUtility.HtmlEncode(s);

    private string Describe(PendingRequest r)
    {
        var place = string.IsNullOrEmpty(r.CountryCode)
            ? "(private/unknown)"
            : $"{H(r.City)}, {H(r.Country)} [{H(r.CountryCode)}]";

        return "\U0001F514 <b>Someone is at the door</b>\n"
             + $"Target: <code>{H(r.Target)}</code>\n"
             + $"Says: <b>{H(r.Input)}</b>\n"
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

    // ---- The operator decides ----------------------------------------------

    public async Task HandleCallback(string data, long fromId, string callbackId,
        string chatId, long messageId, CancellationToken ct)
    {
        if (!IsAdmin(fromId))
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
            var removed = int.TryParse(argument, out var index) && _lists.RemoveAt(list, index);
            await _telegram.AnswerCallback(callbackId, removed ? "removed" : "-", ct);
            if (removed) await _telegram.EditMessage(chatId, messageId, "Entry removed.", null, ct);
            return;
        }

        if (!_pending.TryGetValue(argument, out var request))
        {
            await _telegram.AnswerCallback(callbackId, "expired", ct);
            await _telegram.EditMessage(chatId, messageId, "That request has expired.", null, ct);
            return;
        }

        // With several admins the same request is on several phones. Only the
        // first press counts, otherwise the lists collect duplicates.
        if (request.State != "waiting")
        {
            await _telegram.AnswerCallback(callbackId, "already handled", ct);
            return;
        }

        var stamp = Now();
        string outcome;

        switch (verb)
        {
            case "ok":
                request.State = "approved";
                outcome = "✅ let in";
                break;

            case "no":
                request.State = "denied";
                outcome = "✖ rejected";
                break;

            case "aip":
                request.State = "approved";
                _lists.Add("allow", "ip", request.Ip, stamp);
                outcome = $"✅⭐ let in, IP remembered: {H(request.Ip)}";
                break;

            case "ain":
                request.State = "approved";
                _lists.Add("allow", "input", request.Input, stamp);
                outcome = $"✅⭐ let in, name remembered: {H(request.Input)}";
                break;

            case "bip":
                request.State = "denied";
                _lists.Add("block", "ip", request.Ip, stamp);
                outcome = $"⛔ IP blocked: {H(request.Ip)}";
                break;

            case "bin":
                request.State = "denied";
                _lists.Add("block", "input", request.Input, stamp);
                outcome = $"⛔ name blocked: {H(request.Input)}";
                break;

            case "bco":
                request.State = "denied";
                _lists.Add("block", "country", request.CountryCode, stamp);
                outcome = $"⛔ country blocked: {H(request.CountryCode)}";
                break;

            default:
                await _telegram.AnswerCallback(callbackId, null, ct);
                return;
        }

        await _telegram.AnswerCallback(callbackId, null, ct);
        await _telegram.EditMessage(chatId, messageId, $"{Describe(request)}\n\n<b>{outcome}</b>", null, ct);
    }

    // ---- Bot commands -------------------------------------------------------

    public Task ShowBlockList(string chatId, CancellationToken ct) =>
        ShowList(chatId, "block", "Block list", "rmb", ct);

    public Task ShowAllowList(string chatId, CancellationToken ct) =>
        ShowList(chatId, "allow", "Allow list", "rma", ct);

    private async Task ShowList(string chatId, string list, string title, string removePrefix, CancellationToken ct)
    {
        var entries = _lists.All(list);
        if (entries.Count == 0)
        {
            await _telegram.SendMessage(chatId, $"{title} is empty.", null, ct);
            return;
        }

        var text = new StringBuilder($"<b>{title}</b>\n");
        var rows = new List<object[]>();

        for (var i = 0; i < entries.Count; i++)
        {
            text.Append($"{i + 1}. [{H(entries[i].Type)}] <code>{H(entries[i].Value)}</code>\n");
            rows.Add(new object[] { new { text = $"remove {i + 1}", callback_data = $"{removePrefix}|{i}" } });
        }

        await _telegram.SendMessage(chatId, text.ToString(), new { inline_keyboard = rows.ToArray() }, ct);
    }

    public string MuteCommand(string argument)
    {
        if (argument.Trim() is "off" or "0")
        {
            _mutedUntil = DateTimeOffset.MinValue;
            return "Mute off.";
        }

        var minutes = int.TryParse(argument.Trim(), out var m) && m > 0 ? m : 60;
        _mutedUntil = DateTimeOffset.Now.AddMinutes(minutes);

        return $"Muted for {minutes} min (until {_mutedUntil:HH:mm}). "
             + "Everyone who rings is silently added to the block list by IP.";
    }

    public string SessionCommand(string argument)
    {
        argument = (argument ?? "").Trim();

        if (argument.Length == 0)
            return $"Session length: <b>{_sessionMinutes} min</b>.\n<code>/session 720</code> to change.";

        if (!int.TryParse(argument, out var minutes) || minutes < 1 || minutes > 60 * 24 * 90)
            return "Give minutes, e.g. <code>/session 720</code> (1..129600).";

        _sessionMinutes = minutes;
        SaveSettings();
        return $"Session length set to <b>{minutes} min</b>. Applies to new approvals.";
    }

    public string HostsCommand()
    {
        var hosts = EnforcedHosts();
        return hosts.Count == 0
            ? "No host is currently guarded."
            : "<b>Guarded hosts</b>\n" + string.Join("\n", hosts.Select(h => $"• <code>{H(h)}</code>"));
    }

    public Task Reply(string chatId, string html, CancellationToken ct) =>
        _telegram.SendMessage(chatId, html, null, ct);
}
