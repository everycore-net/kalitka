using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Kalitka;

/// <summary>A request waiting for a human decision. Lives in memory and expires.</summary>
public sealed class PendingRequest
{
    public string Id = "", Target = "", Input = "", Ip = "";
    public string Resource = "";       // web:<host> | ssh:<host> | ...
    public string Country = "", CountryCode = "", City = "";
    public DateTimeOffset Raised;
    public string State = "waiting";   // waiting | approved | denied
    public string Grant = "";          // the one-time grant token, issued once on approval
}

/// <summary>What a callback decision came to — enough for a notifier to render it.</summary>
public enum CallbackOutcome { Expired, AlreadyHandled, Ignored, Decided }

/// <summary>The result of <see cref="ApprovalEngine.Decide"/>: outcome plus, when
/// a decision was actually taken, the request and a one-line description of it.</summary>
public sealed record CallbackResult(CallbackOutcome Outcome, PendingRequest? Request = null, string? Text = null);

/// <summary>A read-only view of a request, for a frontend that lists them (the
/// web control plane). A snapshot copy, so callers cannot mutate engine state.</summary>
public sealed record PendingView(
    string Id, string Target, string Input, string Ip,
    string Country, string CountryCode, string City, DateTimeOffset Raised, string State);

/// <summary>
/// The decision core, with no idea how it is asked or answered. It owns the
/// pending requests, the policies (allow/block/bypass/rate-limit/mute), the
/// signed session and OAuth-state tokens, and the audit trail. It does not know
/// about HTTP or Telegram — those are frontends and notifiers around it.
///
/// Deliberate design choices, each of which cost something to learn:
///
/// * Sessions are a signed token, not server state. Nothing to persist, and
///   rotating <see cref="GateOptions.HmacSecret"/> logs everyone out at once.
/// * A blocked visitor is rejected silently and never produces a notification
///   again. That is the whole point of the block list: not to filter traffic,
///   but to stop your phone from buzzing.
/// * Pending requests live in memory and expire. A door nobody answers should
///   close by itself.
/// </summary>
public sealed class ApprovalEngine
{
    private readonly TimeProvider _clock;
    private readonly IGeoLookup _geo;
    private readonly AccessLists _lists;
    private readonly GateOptions _options;
    private readonly ILogger _log;

    private readonly IRequestStore _store;
    private readonly IAuditStore _audit;
    private readonly IAtomicWork? _atomic;   // present only when state + audit share a transactional backend
    private readonly HashSet<string> _enforced = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _enforcedLock = new();
    private readonly SessionService _sessions;

    private readonly List<IPNetwork> _trustedProxies;
    private readonly List<IPNetwork> _bypassNetworks;

    // Sliding window per address, kept in memory: a restart forgetting who rang
    // twice is not a problem worth a database.
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _recentByIp = new();

    private int _sessionMinutes;
    private DateTimeOffset _mutedUntil = DateTimeOffset.MinValue;

    public ApprovalEngine(IGeoLookup geo, AccessLists lists, GateOptions options,
        ILogger log, TimeProvider clock, IRequestStore store, IAuditStore audit,
        IAtomicWork? atomic = null)
    {
        _geo = geo;
        _lists = lists;
        _options = options;
        _log = log;
        _clock = clock;
        _store = store;
        _audit = audit;
        _atomic = atomic;

        _sessions = new SessionService(_options.HmacSecret, clock);
        _sessionMinutes = _options.SessionMinutes;

        _trustedProxies = ClientIp.ParseNetworks(_options.TrustedProxies,
            bad => _log.LogWarning("Ignoring malformed TrustedProxies entry {Entry}", bad));
        _bypassNetworks = ClientIp.ParseNetworks(_options.BypassNetworks,
            bad => _log.LogWarning("Ignoring malformed BypassNetworks entry {Entry}", bad));

        LoadEnforced();
        LoadSettings();
    }

    public IReadOnlyList<IPNetwork> TrustedProxies => _trustedProxies;

    public string InternalSecret => _options.InternalSecret;
    public string AgentSecret => _options.AgentSecret;

    /// <summary>May an agent (holding the agent secret) raise this resource? True
    /// when no resource binding is configured, else exact or scheme-wildcard.</summary>
    public bool AgentMayRaise(string resource)
    {
        if (_options.AgentResources.Length == 0) return true;
        foreach (var r in _options.AgentResources)
        {
            if (string.Equals(r, resource, StringComparison.OrdinalIgnoreCase)) return true;
            if (r.EndsWith(":*", StringComparison.Ordinal) &&
                resource.StartsWith(r[..^1], StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

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

    // ---- Sessions: the signed tokens themselves live in SessionService -----

    /// <summary>Session valid for one host only — the manual approval path.</summary>
    public string BuildCookie(string host) => _sessions.BuildHost(host, _sessionMinutes);

    /// <summary>Session valid for every host ("*").</summary>
    public string BuildGlobalCookie() => _sessions.BuildDomain(_sessionMinutes);

    /// <summary>
    /// The session to grant after a Google sign-in for <paramref name="target"/>.
    /// <c>Application</c> scope (default) binds it to that one host, exactly like
    /// a manual approval; <c>Domain</c> scope opens every guarded sibling. See
    /// <see cref="GateOptions.SessionScope"/>.
    /// </summary>
    public string BuildIdentitySession(string target) =>
        _options.SessionScope == SessionScope.Domain
            ? _sessions.BuildDomain(_sessionMinutes)
            : _sessions.BuildHost(target, _sessionMinutes);

    public bool IsCookieValid(string? cookie, string host) => _sessions.IsValid(cookie, host);

    public string BuildState(string target) => _sessions.BuildState(target);
    public bool TryReadState(string state, out string target) => _sessions.TryReadState(state, out target);

    /// <summary>
    /// A redirect target must be a host kalitka is actually guarding — nothing
    /// wider. Matching on "anything under our domain" was not enough: it let a
    /// forged Host header steer visitors to a name we never guarded, and turned
    /// the gate into an open redirect for the whole domain.
    ///
    /// Since an unguarded host never redirects here in the first place, the
    /// armed set is the complete and correct list of valid targets.
    /// </summary>
    public bool IsGuardedHost(string host) =>
        !string.IsNullOrWhiteSpace(host) && IsEnforced(host);

    // ---- The way back in ----------------------------------------------------

    /// <summary>
    /// The forwardAuth is fail-closed: if the gate is down, nothing gets in.
    /// These networks are the tested way back — usually the LAN you are sitting
    /// on when you have to fix the gate itself.
    /// </summary>
    public bool IsBypassed(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        foreach (var network in _bypassNetworks)
        {
            if (network.BaseAddress.AddressFamily != address.AddressFamily) continue;
            if (network.Contains(address)) return true;
        }
        return false;
    }

    /// <summary>
    /// Has this address rung too often lately? Over the limit the door stays
    /// shut and silent — no page, no notification, nothing to learn from.
    /// </summary>
    public bool IsRateLimited(string ip)
    {
        if (_options.MaxRequestsPerIp <= 0 || string.IsNullOrEmpty(ip)) return false;

        var now = _clock.GetUtcNow();
        var window = now.AddMinutes(-_options.RateWindowMinutes);

        var times = _recentByIp.GetOrAdd(ip, _ => new List<DateTimeOffset>());
        lock (times)
        {
            times.RemoveAll(t => t < window);
            if (times.Count >= _options.MaxRequestsPerIp) return true;
            times.Add(now);
        }

        // Keep the dictionary from growing without bound on a scan.
        if (_recentByIp.Count > 10_000)
        {
            foreach (var kv in _recentByIp)
            {
                lock (kv.Value) { if (kv.Value.All(t => t < window)) _recentByIp.TryRemove(kv.Key, out _); }
            }
        }

        return false;
    }

    private int PendingCount() =>
        _store.CountWaiting(_clock.GetUtcNow().AddMinutes(-_options.PendingMinutes));

    public bool IsAllowedIp(string host, string ip) => _lists.IsAllowed("web:" + host, ip, "");

    // ---- Mute ---------------------------------------------------------------

    /// <summary>
    /// While muted, every new caller goes silently onto the block list by IP.
    /// For the night someone decides to hammer the door.
    /// </summary>
    public bool IsMuted => _clock.GetUtcNow() < _mutedUntil;
    public DateTimeOffset MutedUntil => _mutedUntil;

    public DateTimeOffset SetMute(int minutes)
    {
        _mutedUntil = _clock.GetUtcNow().AddMinutes(minutes);
        return _mutedUntil;
    }

    public void ClearMute() => _mutedUntil = DateTimeOffset.MinValue;

    public bool IsAdmin(long telegramUserId) => _options.AdminIds.Contains(telegramUserId);

    // ---- A visitor rings ----------------------------------------------------

    /// <summary>
    /// A visitor rings at a guarded HTTP host. The target must be armed; the
    /// resource is <c>web:&lt;host&gt;</c>.
    /// </summary>
    public async Task<(string state, string id, PendingRequest? request)> Request(
        string target, string input, string ip, CancellationToken ct)
    {
        input = (input ?? "").Trim();
        if (input.Length is 0 or > 120) return ("invalid", "", null);

        if (!IsGuardedHost(target))
        {
            Audit.Decision(_log, "rejected", target, ip, reason: "target-not-guarded");
            return ("invalid", "", null);
        }

        return await Raise("web:" + target, target, input, ip, ct);
    }

    /// <summary>
    /// A non-HTTP frontend (an SSH agent, later DB/RDP) asks for a decision on an
    /// arbitrary resource, e.g. <c>ssh:prod-01</c>. No armed-host check — the
    /// resource is the target — but the same allow/block/mute/rate protections,
    /// and callers must be trusted (the /agent endpoints require the internal
    /// secret). It does not broker any credentials: it only says yes or no.
    /// </summary>
    public async Task<(string state, string id, PendingRequest? request)> RaiseAction(
        string resource, string subject, string ip, CancellationToken ct)
    {
        subject = (subject ?? "").Trim();
        if (subject.Length is 0 or > 120 || string.IsNullOrWhiteSpace(resource)) return ("invalid", "", null);
        return await Raise(resource, resource, subject, ip, ct);
    }

    /// <summary>
    /// The shared core: judge and, if it needs a human, create the pending request.
    /// The engine does not notify — that is a notifier's job. <paramref name="target"/>
    /// is what the operator sees; <paramref name="resource"/> is the audit identity.
    /// </summary>
    private async Task<(string state, string id, PendingRequest? request)> Raise(
        string resource, string target, string subject, string ip, CancellationToken ct)
    {
        var place = await _geo.Locate(ip, ct);

        // Allow list: straight through, no question asked. Scoped to the resource.
        if (_lists.IsAllowed(resource, ip, subject))
        {
            Audit.Decision(_log, "allowed", target, ip, identity: subject, reason: "allow-list");
            return ("allowed", "", null);
        }

        // Block list: silent rejection, and above all no notification.
        if (_lists.IsBlocked(resource, ip, subject, place.CountryCode))
        {
            Audit.Decision(_log, "denied", target, ip, identity: subject, reason: "block-list");
            return ("blocked", "", null);
        }

        if (IsMuted)
        {
            _lists.Add("block", resource, "ip", ip, Now());
            Audit.Decision(_log, "denied", target, ip, identity: subject, reason: "muted");
            return ("blocked", "", null);
        }

        // Over the limit the caller gets the same silent refusal as a blocked
        // one: telling them they were throttled only tells them when to retry.
        if (IsRateLimited(ip))
        {
            Audit.Decision(_log, "denied", target, ip, identity: subject, reason: "rate-limited");
            return ("blocked", "", null);
        }

        DropExpired();

        if (_options.MaxPending > 0 && PendingCount() >= _options.MaxPending)
        {
            Audit.Decision(_log, "denied", target, ip, identity: subject, reason: "pending-limit");
            return ("blocked", "", null);
        }

        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var request = new PendingRequest
        {
            Id = id, Target = target, Resource = resource, Input = subject, Ip = ip,
            Country = place.Country, CountryCode = place.CountryCode, City = place.City,
            Raised = _clock.GetUtcNow(), State = "waiting"
        };
        _store.Add(request);

        Audit.Decision(_log, "asked", target, ip, requestId: id, identity: subject);
        await _audit.Append(Event(AuditEvents.AccessRequested,
            actor: "-", subject: subject, resource: resource, requestId: id,
            channel: resource.StartsWith("web:", StringComparison.Ordinal) ? "gate" : "agent"), ct);

        return ("waiting", id, request);
    }

    private AuditEvent Event(string type, string actor, string subject, string resource,
        string requestId, string channel, string metadata = "") =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type,
            actor, subject, resource, requestId, "-", channel, metadata);

    private static string ChannelOf(string actor) =>
        actor.StartsWith("telegram:", StringComparison.Ordinal) ? "telegram"
        : actor.StartsWith("google:", StringComparison.Ordinal) ? "web"
        : actor.StartsWith("email:", StringComparison.Ordinal) ? "email"
        : "other";

    public string? StateOf(string id) => _store.Get(id)?.State;
    public string? TargetOf(string id) => _store.Get(id)?.Target;
    public string? ResourceOf(string id) => _store.Get(id)?.Resource;
    public string? SubjectOf(string id) => _store.Get(id)?.Input;

    /// <summary>
    /// Issue the request's one-time grant exactly once (on first approval read),
    /// so repeated status polls return the same grant, not a new redeemable one.
    /// Returns the effective grant and whether this call created it.
    /// </summary>
    public (string grant, bool created) EnsureGrant(string id, string candidate)
    {
        // The atomic issue-once lives in the store: with a durable/shared backend
        // Get returns a copy, so mutating it here would be lost and two instances
        // could each mint a grant for one approval.
        var created = _store.TrySetGrant(id, candidate, out var grant);
        return (grant, created);
    }

    /// <summary>
    /// A snapshot of the requests currently in memory, newest first — for the web
    /// control plane to list. Includes resolved ones until they age out, so it
    /// backs both the pending view and a short-lived history; durable history is
    /// the audit log (a later, store-backed item).
    /// </summary>
    public IReadOnlyList<PendingView> PendingSnapshot() =>
        _store.Snapshot()
            .OrderByDescending(r => r.Raised)
            .Select(r => new PendingView(
                r.Id, r.Target, r.Input, r.Ip, r.Country, r.CountryCode, r.City, r.Raised, r.State))
            .ToList();

    public PendingView? RequestView(string id) =>
        _store.Get(id) is { } r
            ? new PendingView(r.Id, r.Target, r.Input, r.Ip, r.Country, r.CountryCode, r.City, r.Raised, r.State)
            : null;

    private void DropExpired() =>
        _store.DropOlderThan(_clock.GetUtcNow().AddMinutes(-_options.PendingMinutes));

    private string Now() => _clock.GetUtcNow().ToString("yyyy-MM-dd HH:mm");
    private static string H(string s) => WebUtility.HtmlEncode(s);

    // ---- The operator decides ----------------------------------------------

    /// <summary>
    /// Applies a decision verb to a pending request. Does the terminal-state and
    /// expiry checks, the state transition, the list side-effects and the audit
    /// line — but nothing about how the decision arrived or is acknowledged.
    ///
    /// The first press wins: the state is terminal afterwards, so a second press
    /// (several admins, or a stale button days later) cannot resurrect it. An
    /// approval nobody is waiting for any more is not an approval — hence the
    /// lifetime check as well.
    /// </summary>
    public async Task<CallbackResult> Decide(string id, string verb, string actor)
    {
        var request = _store.Get(id);
        if (request is null) return new CallbackResult(CallbackOutcome.Expired);
        if (request.State != "waiting") return new CallbackResult(CallbackOutcome.AlreadyHandled);

        var cutoff = _clock.GetUtcNow().AddMinutes(-_options.PendingMinutes);
        if (request.Raised < cutoff)
        {
            _store.Remove(request.Id);
            Audit.Decision(_log, "ignored", request.Target, request.Ip,
                requestId: request.Id, identity: request.Input, actor: actor, reason: "callback-too-late");
            return new CallbackResult(CallbackOutcome.Expired);
        }

        var toState = verb switch
        {
            "ok" or "aip" or "ain"          => "approved",
            "no" or "bip" or "bin" or "bco" => "denied",
            _                               => null
        };
        if (toState is null) return new CallbackResult(CallbackOutcome.Ignored);

        // The one atomic step: only the first caller flips waiting → terminal, so
        // an Approve and a Deny racing the same request cannot both win. The list
        // side-effect below therefore also happens at most once.
        //
        // When state and audit share a transactional backend, the durable event is
        // written *inside* that same transition, so a decision and its history
        // commit together — the access-integrity guarantee. Otherwise the append is
        // a best-effort second step (below), and the decision stands even if it
        // fails. The list side-effects are file-backed, not part of the DB
        // transaction, so they stay outside it either way.
        if (_atomic is not null)
        {
            var resolved = await _atomic.Do(scope =>
            {
                if (!scope.TryResolve(id, toState, cutoff, out var req) || req is null) return (PendingRequest?)null;
                scope.AppendAudit(DecisionEvent(toState, actor, req, verb));
                return req;
            }, CancellationToken.None);
            if (resolved is null) return new CallbackResult(CallbackOutcome.AlreadyHandled);
            request = resolved;
        }
        else
        {
            if (!_store.TryResolve(id, toState, cutoff, out request) || request is null)
                return new CallbackResult(CallbackOutcome.AlreadyHandled);
        }

        var stamp = Now();
        switch (verb)
        {
            case "aip": _lists.Add("allow", request.Resource, "ip", request.Ip, stamp); break;
            case "ain": _lists.Add("allow", request.Resource, "subject", request.Input, stamp); break;
            case "bip": _lists.Add("block", request.Resource, "ip", request.Ip, stamp); break;
            case "bin": _lists.Add("block", request.Resource, "subject", request.Input, stamp); break;
            case "bco": _lists.Add("block", request.Resource, "country", request.CountryCode, stamp); break;
        }

        var outcome = verb switch
        {
            "ok"  => "✅ let in",
            "no"  => "✖ rejected",
            "aip" => $"✅⭐ let in, IP remembered: {H(request.Ip)}",
            "ain" => $"✅⭐ let in, name remembered: {H(request.Input)}",
            "bip" => $"⛔ IP blocked: {H(request.Ip)}",
            "bin" => $"⛔ name blocked: {H(request.Input)}",
            "bco" => $"⛔ country blocked: {H(request.CountryCode)}",
            _     => ""
        };

        Audit.Decision(_log, toState == "approved" ? "approved" : "denied",
            request.Target, request.Ip, requestId: request.Id, identity: request.Input,
            actor: actor, reason: verb);
        // Non-transactional path only: the durable event is a best-effort second
        // step here, so if it fails (disk/IO) the decision stands without it. The
        // transactional path already appended the event inside the resolve above.
        if (_atomic is null)
            await _audit.Append(DecisionEvent(toState, actor, request, verb), CancellationToken.None);

        return new CallbackResult(CallbackOutcome.Decided, request, outcome);
    }

    /// <summary>The audit event for a resolved decision — built the same way whether
    /// it is appended inside the transaction or as the best-effort second step.</summary>
    private AuditEvent DecisionEvent(string toState, string actor, PendingRequest request, string verb) =>
        Event(toState == "approved" ? AuditEvents.AccessApproved : AuditEvents.AccessDenied,
            actor: actor, subject: request.Input, resource: request.Resource,
            requestId: request.Id, channel: ChannelOf(actor), metadata: verb);

    // ---- Lists: read and mutate (formatting lives in the notifier) ----------

    public IReadOnlyList<AccessLists.Entry> ListEntries(string list) => _lists.All(list);

    public bool RemoveListEntry(string list, int index) => _lists.RemoveAt(list, index);

    // Manual /allow /block default to web:* — the historical meaning of these
    // commands. Resource-specific entries come from the buttons on a request,
    // which carry that request's resource.
    public void AddListEntry(string list, string type, string value) => _lists.Add(list, "web:*", type, value, Now());

    public void SetSessionMinutes(int minutes)
    {
        _sessionMinutes = minutes;
        SaveSettings();
    }
}
