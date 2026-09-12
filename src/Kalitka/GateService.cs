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

    public GateService(ITelegramClient telegram, IGeoLookup geo, AccessLists lists,
        IOptions<GateOptions> options, ILogger<GateService> log, TimeProvider? clock = null,
        IEnumerable<INotifier>? extraNotifiers = null, IAuditStore? audit = null,
        IRequestStore? requestStore = null, IAtomicWork? atomic = null, IConfigStore? config = null,
        PolicyService? policies = null)
    {
        // DI supplies the request and audit stores (in-memory by default, SQLite
        // when a path is configured), so pending state and history survive a
        // restart and their atomic transitions hold across every process on the
        // same file. When state and audit share one transactional backend, DI also
        // supplies the unit of work that commits a decision and its audit event
        // together; absent it, the engine keeps the sequential best-effort path.
        // The config store (enforced hosts / settings) is the same one AccessLists
        // uses, so all shared config sits in one backend.
        _engine = new ApprovalEngine(geo, lists, options.Value, log,
            clock ?? TimeProvider.System, requestStore ?? new InMemoryRequestStore(),
            audit ?? new InMemoryAuditStore(), atomic, config, policies);
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

    public string BuildState(string target, string nonce) => _engine.BuildState(target, nonce);
    public bool TryReadState(string state, string nonce, out string target) => _engine.TryReadState(state, nonce, out target);

    // ---- Hosts and policies (engine) ----------------------------------------

    public bool IsEnforced(string host) => _engine.IsEnforced(host);
    public void SetEnforced(string host, bool on) => _engine.SetEnforced(host, on);
    public IReadOnlyList<string> EnforcedHosts() => _engine.EnforcedHosts();

    public string AgentSecret => _engine.AgentSecret;
    public string[] AgentResources => _engine.AgentResources;
    public bool AgentMayRaise(string resource) => _engine.AgentMayRaise(resource);

    public bool IsGuardedHost(string host) => _engine.IsGuardedHost(host);
    public bool IsBypassed(string ip) => _engine.IsBypassed(ip);
    public bool IsAllowedIp(string host, string ip) => _engine.IsAllowedIp(host, ip);
    public bool IsAdmin(long telegramUserId) => _engine.IsAdmin(telegramUserId);

    // ---- A visitor rings: judge, then let the notifiers ask -----------------

    public async Task<(string state, string id)> Request(string target, string input, string ip, CancellationToken ct)
    {
        var (state, id, request) = await _engine.Request(target, input, ip, ct);
        await AnnounceAll(request, ct);
        return (state, id);
    }

    /// <summary>
    /// A non-HTTP frontend (the SSH agent) asks for a decision on a resource such
    /// as <c>ssh:prod-01</c>. Same judging and channels as a visitor request; the
    /// agent then polls <see cref="StateOf"/>.
    /// </summary>
    public async Task<(string state, string id)> RaiseAction(string resource, string subject, string ip, string actor, CancellationToken ct,
        IReadOnlyList<string>? agentTags = null, string profile = "", int maxUses = 0, string command = "")
    {
        var (state, id, request) = await _engine.RaiseAction(resource, subject, ip, actor, ct, agentTags, profile, maxUses, command);
        await AnnounceAll(request, ct);
        return (state, id);
    }

    private async Task AnnounceAll(PendingRequest? request, CancellationToken ct)
    {
        if (request is null) return;
        await _notifier.Announce(request, ct);
        foreach (var n in _extra)
            await n.Announce(request, ct);
    }

    public string? StateOf(string id) => _engine.StateOf(id);
    public string? TargetOf(string id) => _engine.TargetOf(id);
    public string? ResourceOf(string id) => _engine.ResourceOf(id);
    public string? SubjectOf(string id) => _engine.SubjectOf(id);
    public string ProfileOf(string id) => _engine.ProfileOf(id);
    public int MaxUsesOf(string id) => _engine.MaxUsesOf(id);
    public string CommandOf(string id) => _engine.CommandOf(id);
    public (string grant, bool created) EnsureGrant(string id, string candidate) => _engine.EnsureGrant(id, candidate);

    public IReadOnlyList<PendingView> PendingSnapshot() => _engine.PendingSnapshot();
    public PendingView? RequestView(string id) => _engine.RequestView(id);

    /// <summary>Apply a decision from a non-Telegram channel (the web plane). The
    /// actor is typed, e.g. <c>google:sergej@example.com</c>.</summary>
    public Task<CallbackResult> Decide(string id, string verb, string actor) => _engine.Decide(id, verb, actor);

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
