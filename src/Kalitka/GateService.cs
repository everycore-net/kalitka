using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The gate, as one object for the HTTP frontend and the tests to hold. It is a
/// thin facade over two collaborators it builds itself:
///
/// * <see cref="ApprovalEngine"/> — the decision core (pending requests,
///   policies, signed sessions), which knows nothing about HTTP or Telegram.
/// * <see cref="TelegramNotifier"/> — the Telegram face (messages, buttons,
///   commands), the first <see cref="INotifier"/>.
///
/// Keeping the split behind this facade means the frontend and the test surface
/// did not have to change when the one class became three. A second notifier (a
/// push app) or a second frontend (Envoy ext_authz, PAM) plugs into the engine
/// without touching this seam.
/// </summary>
public sealed class GateService
{
    private readonly ApprovalEngine _engine;
    private readonly TelegramNotifier _notifier;
    private readonly IReadOnlyList<INotifier> _extra;

    public GateService(ITelegramClient telegram, GeoLookup geo, AccessLists lists,
        IOptions<GateOptions> options, ILogger<GateService> log, TimeProvider? clock = null,
        IEnumerable<INotifier>? extraNotifiers = null)
    {
        // In-memory store today; the IRequestStore seam is where a durable/shared
        // backend plugs in for multi-instance (see the roadmap). Swapping it is a
        // one-line change here.
        _engine = new ApprovalEngine(geo, lists, options.Value, log,
            clock ?? TimeProvider.System, new InMemoryRequestStore());
        _notifier = new TelegramNotifier(telegram, _engine, options.Value);
        // Telegram is always a channel; DI supplies any others (e.g. e-mail).
        _extra = extraNotifiers?.ToList() ?? new List<INotifier>();
    }

    // ---- Configuration and sessions (engine) --------------------------------

    public IReadOnlyList<IPNetwork> TrustedProxies => _engine.TrustedProxies;
    public string InternalSecret => _engine.InternalSecret;
    public string CookieName => _engine.CookieName;
    public string CookieDomain => _engine.CookieDomain;
    public int SessionMinutes => _engine.SessionMinutes;
    public string GateHost => _engine.GateHost;

    public string BuildCookie(string host) => _engine.BuildCookie(host);
    public string BuildGlobalCookie() => _engine.BuildGlobalCookie();
    public string BuildIdentitySession(string target) => _engine.BuildIdentitySession(target);
    public bool IsCookieValid(string? cookie, string host) => _engine.IsCookieValid(cookie, host);

    public string BuildState(string target) => _engine.BuildState(target);
    public bool TryReadState(string state, out string target) => _engine.TryReadState(state, out target);

    // ---- Hosts and policies (engine) ----------------------------------------

    public bool IsEnforced(string host) => _engine.IsEnforced(host);
    public void SetEnforced(string host, bool on) => _engine.SetEnforced(host, on);
    public IReadOnlyList<string> EnforcedHosts() => _engine.EnforcedHosts();

    public bool IsGuardedHost(string host) => _engine.IsGuardedHost(host);
    public bool IsBypassed(string ip) => _engine.IsBypassed(ip);
    public bool IsAllowedIp(string ip) => _engine.IsAllowedIp(ip);
    public bool IsAdmin(long telegramUserId) => _engine.IsAdmin(telegramUserId);

    // ---- A visitor rings: judge, then let the notifiers ask -----------------

    public async Task<(string state, string id)> Request(string target, string input, string ip, CancellationToken ct)
    {
        var (state, id, request) = await _engine.Request(target, input, ip, ct);
        if (request is not null)
        {
            await _notifier.Announce(request, ct);
            foreach (var n in _extra)
                await n.Announce(request, ct);
        }
        return (state, id);
    }

    public string? StateOf(string id) => _engine.StateOf(id);
    public string? TargetOf(string id) => _engine.TargetOf(id);

    public IReadOnlyList<PendingView> PendingSnapshot() => _engine.PendingSnapshot();
    public PendingView? RequestView(string id) => _engine.RequestView(id);

    /// <summary>Apply a decision from a non-Telegram channel (the web plane). The
    /// actor is typed, e.g. <c>google:sergej@example.com</c>.</summary>
    public CallbackResult Decide(string id, string verb, string actor) => _engine.Decide(id, verb, actor);

    // ---- Telegram frontend (notifier) ---------------------------------------

    public Task HandleCallback(string data, long fromId, string callbackId,
        string chatId, long messageId, CancellationToken ct) =>
        _notifier.HandleCallback(data, fromId, callbackId, chatId, messageId, ct);

    public Task ShowBlockList(string chatId, CancellationToken ct) => _notifier.ShowBlockList(chatId, ct);
    public Task ShowAllowList(string chatId, CancellationToken ct) => _notifier.ShowAllowList(chatId, ct);

    public string ListAddCommand(string list, string argument) => _notifier.ListAddCommand(list, argument);
    public string MuteCommand(string argument) => _notifier.MuteCommand(argument);
    public string SessionCommand(string argument) => _notifier.SessionCommand(argument);
    public string HostsCommand() => _notifier.HostsCommand();

    public Task Reply(string chatId, string html, CancellationToken ct) => _notifier.Reply(chatId, html, ct);
}
