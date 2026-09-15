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
    public int RequiredApprovals = 1;  // quorum from policy at raise time; 1 = single approval
    // Bounded-grant shape (0.23): the server-side profile the DB-agent (or other
    // connector) applies, and an optional use cap. The grant ends on the first of its
    // TTL, its uses being spent, or an explicit revoke.
    public string Profile = "";        // e.g. sql-readonly | sql-writer | ssh (opaque to Core)
    public int MaxUses = 0;            // 0 = unlimited (session + TTL bounded only)
    // Command-aware approval (0.26): the exact command the operator asked to run. When
    // set, the human approves THIS command, and an SSH-cert signer must issue a cert with
    // force-command = this — the session can run nothing else. Empty = interactive/open.
    public string Command = "";
    // Source-address binding (0.26.1): the approved source CIDR(s). When set, an SSH-cert
    // signer must issue a cert with source-address = this — the cert is usable only from
    // there, so a stolen cert is worthless elsewhere. Empty = no source restriction.
    public string SourceAddr = "";
    // Notification routing (0.30): a machine-readable subject identity (e.g. os:CONTOSO\anna,
    // sid:S-1-5-21-…) the agent knows, resolvable to an operator principal so THIS person is
    // asked — not the global admins. Empty = ordinary request (ask admins). Distinct from the
    // free-text Input, which is what a visitor typed and cannot be matched to a principal.
    public string SubjectIdentity = "";
    // Subject-approval (0.30.1), snapshotted at raise (like RequiredApprovals): Required =
    // the subject's operator principal must be among the distinct approvers (and the count
    // must still reach RequiredApprovals); Forbidden = the subject's principal may NOT
    // approve (four-eyes by others); Optional = no special rule. For Required/Forbidden the
    // subject was trusted-asserted by a capable agent and resolves to a known principal.
    public SubjectApproval Subject = SubjectApproval.Optional;
    // Out-of-band proof of intent (the iOS-shield "defer" case): when set, this request can be
    // APPROVED only by a device signature (WebAuthn), never a chat tap or a session click — a denial
    // stays unsigned (fail-safe). Snapshotted at raise, like the other approval terms.
    public bool RequireSignedApproval = false;
    // Dedup fingerprint (0.46.1): a hash of the authority-relevant fields (resource, subject,
    // beneficiary, profile, command, source, uses, signed). Repeated identical raises (a 4625 storm)
    // fold onto the one still-waiting request with the same key; requests that differ in any of those
    // fields do not fold. Empty = never folds (a web visitor, or any raise without a subject identity).
    public string DedupKey = "";
    // Covering scope (0.47): a resource glob this approval is explicitly for, so a perimeter approval
    // can cover a family of hosts behind it (see docs/design/covering-grant.md). Set ONLY by a trusted
    // channel from its own config (e.g. a RADIUS client's GrantScope) — never from the agent API, so a
    // requester cannot ask to cover more than the channel is configured for. Empty = covers nothing
    // beyond the exact resource (today's behaviour). Carried onto the session at redeem.
    public string Scope = "";
}

/// <summary>What a callback decision came to — enough for a notifier to render it.
/// <see cref="Pending"/> means the approval was recorded but the request still needs
/// more distinct approvers (a policy quorum) before it becomes approved.</summary>
public enum CallbackOutcome { Expired, AlreadyHandled, Ignored, Decided, Pending }

/// <summary>The result of <see cref="ApprovalEngine.Decide"/>: outcome plus, when
/// a decision was actually taken, the request and a one-line description of it.</summary>
public sealed record CallbackResult(CallbackOutcome Outcome, PendingRequest? Request = null, string? Text = null);

/// <summary>A read-only view of a request, for a frontend that lists them (the
/// web control plane). A snapshot copy, so callers cannot mutate engine state.</summary>
public sealed record PendingView(
    string Id, string Target, string Input, string Ip,
    string Country, string CountryCode, string City, DateTimeOffset Raised, string State,
    int RequiredApprovals = 1, int ApprovalCount = 0, string Command = "", string SourceAddr = "",
    bool RequireSignedApproval = false);

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
    private readonly IConfigStore _config;   // enforced hosts + runtime settings (shared across instances)
    private readonly HashSet<string> _enforced = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _enforcedLock = new();   // also guards the config cache
    private static readonly TimeSpan ConfigTtl = TimeSpan.FromSeconds(10);
    // A tightening (a newly armed host) must reach the bypass path faster than the TTL; disarming
    // (a loosening) tolerates the full TTL. This bounds how fresh the snapshot must be to permit.
    private static readonly TimeSpan ConfigGenWindow = TimeSpan.FromSeconds(1);
    private DateTimeOffset _configLoadedAt = DateTimeOffset.MinValue;
    private ConfigGeneration _configGen = null!;   // set in the ctor once _config is known
    private readonly SessionService _sessions;

    private readonly List<IPNetwork> _trustedProxies;
    private readonly List<IPNetwork> _bypassNetworks;

    // Sliding window per address, kept in memory: a restart forgetting who rang
    // twice is not a problem worth a database.
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _recentByIp = new();
    // Same window keyed on the machine-readable subject — for agent requests (e.g. RDP), where every
    // user behind one agent shares that agent's IP, so a per-IP limit cannot throttle one stuck user.
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _recentBySubject = new();

    private int _sessionMinutes;
    private DateTimeOffset _mutedUntil = DateTimeOffset.MinValue;

    private readonly PolicyService? _policies;
    private readonly PrincipalService? _principals;
    private readonly Metrics? _metrics;

    public ApprovalEngine(IGeoLookup geo, AccessLists lists, GateOptions options,
        ILogger log, TimeProvider clock, IRequestStore store, IAuditStore audit,
        IAtomicWork? atomic = null, IConfigStore? config = null, PolicyService? policies = null,
        PrincipalService? principals = null, Metrics? metrics = null)
    {
        _geo = geo;
        _lists = lists;
        _options = options;
        _log = log;
        _clock = clock;
        _store = store;
        _audit = audit;
        _atomic = atomic;
        _config = config ?? new JsonFileConfigStore(options, log);
        _configGen = new ConfigGeneration(_config, clock, ConfigGenWindow);
        _policies = policies;
        _principals = principals;
        _metrics = metrics;

        _sessions = new SessionService(_options.HmacSecret, clock, _options.HmacSecretPrevious);
        _sessionMinutes = _options.SessionMinutes;

        _trustedProxies = ClientIp.ParseNetworks(_options.TrustedProxies,
            bad => _log.LogWarning("Ignoring malformed TrustedProxies entry {Entry}", bad));
        _bypassNetworks = ClientIp.ParseNetworks(_options.BypassNetworks,
            bad => _log.LogWarning("Ignoring malformed BypassNetworks entry {Entry}", bad));

        lock (_enforcedLock) RefreshConfig();
    }

    public IReadOnlyList<IPNetwork> TrustedProxies => _trustedProxies;

    public string InternalSecret => _options.InternalSecret;
    public string AgentSecret => _options.AgentSecret;
    public string[] AgentResources => _options.AgentResources;   // legacy global-secret binding

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
    public int SessionMinutes { get { lock (_enforcedLock) { RefreshConfig(); return _sessionMinutes; } } }
    public string GateHost => _options.GateHost;

    // ---- Which hosts are armed ---------------------------------------------

    // Reload enforced hosts and settings from the shared config store if the cache
    // has aged out, so a change on another instance shows up within the TTL. Caller
    // holds _enforcedLock.
    private void RefreshConfig()
    {
        if (_clock.GetUtcNow() - _configLoadedAt < ConfigTtl) return;
        _enforced.Clear();
        foreach (var h in LoadEnforcedSet()) _enforced.Add(h);
        _sessionMinutes = LoadSessionMinutes();
        _configLoadedAt = _clock.GetUtcNow();
        _configGen.Mark();   // this snapshot reflects the store's current generation
    }

    private IEnumerable<string> LoadEnforcedSet()
    {
        try
        {
            var blob = _config.Get("enforced");
            if (blob is not null) return JsonSerializer.Deserialize<List<string>>(blob) ?? new();
        }
        catch (Exception e) { _log.LogWarning("Could not read enforced hosts: {Message}", e.Message); }
        return _options.EnforcedHosts;   // the configured default until the operator changes it
    }

    public bool IsEnforced(string host)
    {
        lock (_enforcedLock)
        {
            RefreshConfig();
            if (_enforced.Contains(host)) return true;   // armed: the safe direction, decide now

            // Not armed → traffic would bypass the gate with no approval. A snapshot that missed an
            // arming on another instance would wrongly permit, so confirm the generation before
            // granting the bypass; a bump means reload and re-decide on fresh config.
            if (_configGen.Fresh()) return false;
            _configLoadedAt = DateTimeOffset.MinValue;
            RefreshConfig();
            return _enforced.Contains(host);
        }
    }

    public void SetEnforced(string host, bool on)
    {
        lock (_enforcedLock)
        {
            // Atomic read-modify-write on the shared store: base on the persisted set
            // if any, else the configured default (so disarming a default host sticks).
            _config.Mutate("enforced", cur =>
            {
                var set = cur is not null
                    ? new HashSet<string>(JsonSerializer.Deserialize<List<string>>(cur) ?? new(), StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(_options.EnforcedHosts, StringComparer.OrdinalIgnoreCase);
                if (on) set.Add(host); else set.Remove(host);
                return JsonSerializer.Serialize(set.ToList());
            });
            _configLoadedAt = DateTimeOffset.MinValue;   // force the local cache to reload now
            RefreshConfig();
        }
    }

    public IReadOnlyList<string> EnforcedHosts() { lock (_enforcedLock) { RefreshConfig(); return _enforced.ToList(); } }

    // ---- Runtime settings ---------------------------------------------------

    private int LoadSessionMinutes()
    {
        try
        {
            var blob = _config.Get("settings");
            if (blob is not null)
            {
                using var doc = JsonDocument.Parse(blob);
                if (doc.RootElement.TryGetProperty("sessionMinutes", out var s) && s.TryGetInt32(out var m) && m > 0)
                    return m;
            }
        }
        catch (Exception e) { _log.LogWarning("Could not read settings: {Message}", e.Message); }
        return _options.SessionMinutes;
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

    public string BuildState(string target, string nonce, string scheme = "google") => _sessions.BuildState(target, nonce, scheme);
    public bool TryReadState(string state, string nonce, out string target, out string scheme) => _sessions.TryReadState(state, nonce, out target, out scheme);

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
    public bool IsRateLimited(string ip) => RateLimited(_recentByIp, ip);

    // The sliding-window check, over any keying (IP or subject). Caller holds no lock.
    private bool RateLimited(ConcurrentDictionary<string, List<DateTimeOffset>> map, string key)
    {
        if (_options.MaxRequestsPerIp <= 0 || string.IsNullOrEmpty(key)) return false;

        var now = _clock.GetUtcNow();
        var window = now.AddMinutes(-_options.RateWindowMinutes);

        var times = map.GetOrAdd(key, _ => new List<DateTimeOffset>());
        lock (times)
        {
            times.RemoveAll(t => t < window);
            if (times.Count >= _options.MaxRequestsPerIp) return true;
            times.Add(now);
        }

        // Keep the dictionary from growing without bound on a scan.
        if (map.Count > 10_000)
        {
            foreach (var kv in map)
            {
                lock (kv.Value) { if (kv.Value.All(t => t < window)) map.TryRemove(kv.Key, out _); }
            }
        }

        return false;
    }

    // Requests still waiting for a decision (not yet expired) — the pending-queue depth.
    public int PendingCount() =>
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
            MeteredDecision("rejected", target, ip, reason: "target-not-guarded");
            return ("invalid", "", null);
        }

        return await Raise("web:" + target, target, input, ip, "-", ct, Array.Empty<string>(), "", 0);
    }

    /// <summary>
    /// A non-HTTP frontend (an SSH agent, later DB/RDP) asks for a decision on an
    /// arbitrary resource, e.g. <c>ssh:prod-01</c>. No armed-host check — the
    /// resource is the target — but the same allow/block/mute/rate protections,
    /// and callers must be trusted (the /agent endpoints require the internal
    /// secret). It does not broker any credentials: it only says yes or no.
    /// </summary>
    public async Task<(string state, string id, PendingRequest? request)> RaiseAction(
        string resource, string subject, string ip, string actor, CancellationToken ct,
        IReadOnlyList<string>? agentTags = null, string profile = "", int maxUses = 0, string command = "",
        string sourceAddr = "", string subjectIdentity = "", bool subjectTrusted = false, bool requireSigned = false,
        string scope = "")
    {
        subject = (subject ?? "").Trim();
        if (subject.Length is 0 or > 120 || string.IsNullOrWhiteSpace(resource)) return ("invalid", "", null);
        return await Raise(resource, resource, subject, ip, actor, ct, agentTags ?? Array.Empty<string>(), profile, maxUses, command, sourceAddr, subjectIdentity, subjectTrusted, requireSigned, scope);
    }

    /// <summary>
    /// The shared core: judge and, if it needs a human, create the pending request.
    /// The engine does not notify — that is a notifier's job. <paramref name="target"/>
    /// is what the operator sees; <paramref name="resource"/> is the audit identity.
    /// </summary>
    private async Task<(string state, string id, PendingRequest? request)> Raise(
        string resource, string target, string subject, string ip, string actor, CancellationToken ct,
        IReadOnlyList<string> agentTags, string profile, int maxUses, string command = "", string sourceAddr = "",
        string subjectIdentity = "", bool subjectTrusted = false, bool requireSigned = false, string scope = "")
    {
        command = (command ?? "").Trim();
        sourceAddr = (sourceAddr ?? "").Trim();
        subjectIdentity = OperatorPrincipal.Normalize(subjectIdentity ?? "");
        var place = await _geo.Locate(ip, ct);

        // Allow list: straight through, no question asked. Scoped to the resource.
        if (_lists.IsAllowed(resource, ip, subject))
        {
            MeteredDecision("allowed", target, ip, identity: subject, reason: "allow-list");
            return ("allowed", "", null);
        }

        // Block list: silent rejection, and above all no notification.
        if (_lists.IsBlocked(resource, ip, subject, place.CountryCode))
        {
            MeteredDecision("denied", target, ip, identity: subject, reason: "block-list");
            return ("blocked", "", null);
        }

        if (IsMuted)
        {
            _lists.Add("block", resource, "ip", ip, Now());
            MeteredDecision("denied", target, ip, identity: subject, reason: "muted");
            return ("blocked", "", null);
        }

        DropExpired();

        // The dedup fingerprint of this raise: a hash of every field that shapes the authority asked
        // for, so repeated identical raises fold but two requests that differ in any of them do not.
        // Only requests carrying a machine-readable subject fold (a web visitor never does).
        var dedupKey = subjectIdentity.Length > 0
            ? RequestFingerprint.Of(resource, subjectIdentity, subject, profile ?? "", command, sourceAddr, Math.Max(0, maxUses), requireSigned)
            : "";
        var freshCutoff = _clock.GetUtcNow().AddMinutes(-_options.PendingMinutes);

        // Reuse a still-waiting identical request instead of raising a duplicate — an agent
        // re-triggered by repeated logon-denied (4625) events for the same person and host must fold
        // onto the one pending request, not flood the approver. Checked BEFORE the rate limit, so a
        // stuck client folding onto its own request is never throttled. Null request → the caller
        // does not re-notify. (The atomic backstop against an exact race is TryCreateOrGetPending.)
        if (dedupKey.Length > 0)
        {
            var existing = _store.Snapshot().FirstOrDefault(r =>
                r.State == "waiting" && r.Raised > freshCutoff &&
                string.Equals(r.DedupKey, dedupKey, StringComparison.Ordinal));
            if (existing is not null)
            {
                MeteredDecision("asked", target, ip, requestId: existing.Id, identity: subject, reason: "deduped");
                return ("waiting", existing.Id, null);
            }
        }

        // Over the limit the caller gets the same silent refusal as a blocked one: telling them they
        // were throttled only tells them when to retry. Per-IP, plus per-subject for agent requests
        // (every user behind one agent shares its IP, so only a subject key throttles one stuck user).
        if (IsRateLimited(ip) || (subjectIdentity.Length > 0 && RateLimited(_recentBySubject, subjectIdentity)))
        {
            MeteredDecision("denied", target, ip, identity: subject, reason: "rate-limited");
            return ("blocked", "", null);
        }

        if (_options.MaxPending > 0 && PendingCount() >= _options.MaxPending)
        {
            MeteredDecision("denied", target, ip, identity: subject, reason: "pending-limit");
            return ("blocked", "", null);
        }

        // A tag-driven policy may require more than one approval for this resource, and may
        // forbid an open shell (require a command). Policy only restricts, so the floor is 1.
        var decision = _policies?.Effective(resource, agentTags, profile ?? "") ?? PolicyDecision.None;
        var required = decision.RequiredApprovals;

        // Restrict-only policy gates, all refused before anyone is asked to approve:
        //   command-required     — no open-shell access to this resource
        //   source-required      — access must be pinned to a source address
        //   principal-not-allowed — the requested login is not on the policy allow-list
        if (decision.RequireCommand && command.Length == 0)
        {
            MeteredDecision("denied", target, ip, identity: subject, reason: "command-required");
            return ("command-required", "", null);
        }
        if (decision.RequireSourceAddress && sourceAddr.Length == 0)
        {
            MeteredDecision("denied", target, ip, identity: subject, reason: "source-required");
            return ("source-required", "", null);
        }
        if (!decision.PrincipalAllowed(subject))
        {
            MeteredDecision("denied", target, ip, identity: subject, reason: "principal-not-allowed");
            return ("principal-not-allowed", "", null);
        }

        // Subject-approval (Required or Forbidden) is only safe when a TRUSTED agent asserted
        // the subject — else a caller could name someone else's identity and approve their own
        // privileged action (Required), or lie about who the subject is to sidestep exclusion
        // (Forbidden). It also needs the subject to resolve to a known operator principal, and
        // — for Required — that subject to be the grant's beneficiary and be reachable. Any of
        // these missing is refused up front, never silently downgraded to a normal quorum.
        if (decision.Subject != SubjectApproval.Optional)
        {
            if (subjectIdentity.Length == 0)
            { MeteredDecision("denied", target, ip, identity: subject, reason: "subject-required"); return ("subject-required", "", null); }
            if (!subjectTrusted)
            { MeteredDecision("denied", target, ip, identity: subject, reason: "claimed-not-asserted"); return ("claimed-not-asserted", "", null); }
            var sp = _principals?.Resolve(subjectIdentity);
            if (sp is null)
            { MeteredDecision("denied", target, ip, identity: subject, reason: "subject-unmapped"); return ("subject-unmapped", "", null); }
            if (decision.Subject == SubjectApproval.Required)
            {
                if (!BeneficiaryMatches(subject, subjectIdentity))
                { MeteredDecision("denied", target, ip, identity: subject, reason: "beneficiary-mismatch"); return ("beneficiary-mismatch", "", null); }
                if (_principals!.IdentitiesOf(sp).Count == 0)
                { MeteredDecision("denied", target, ip, identity: subject, reason: "subject-unreachable"); return ("subject-unreachable", "", null); }
            }
        }

        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var request = new PendingRequest
        {
            Id = id, Target = target, Resource = resource, Input = subject, Ip = ip,
            Country = place.Country, CountryCode = place.CountryCode, City = place.City,
            Raised = _clock.GetUtcNow(), State = "waiting", RequiredApprovals = required,
            Profile = profile ?? "", MaxUses = Math.Max(0, maxUses), Command = command, SourceAddr = sourceAddr,
            SubjectIdentity = subjectIdentity, Subject = decision.Subject, RequireSignedApproval = requireSigned,
            DedupKey = dedupKey, Scope = scope ?? ""
        };

        // Atomic create-or-fold: if an identical raise won a concurrent race (two 4625s, or two
        // cluster nodes), fold onto its request instead of creating a duplicate — no second notify.
        if (!_store.TryCreateOrGetPending(request, freshCutoff, out var effective))
        {
            MeteredDecision("asked", target, ip, requestId: effective.Id, identity: subject, reason: "deduped");
            return ("waiting", effective.Id, null);
        }

        MeteredDecision("asked", target, ip, requestId: id, identity: subject);
        await _audit.Append(Event(AuditEvents.AccessRequested,
            actor: actor, subject: subject, resource: resource, requestId: id,
            channel: resource.StartsWith("web:", StringComparison.Ordinal) ? "gate" : "agent",
            metadata: command.Length > 0 ? "command: " + command : ""), ct);

        return ("waiting", id, request);
    }

    private AuditEvent Event(string type, string actor, string subject, string resource,
        string requestId, string channel, string metadata = "") =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type,
            actor, subject, resource, requestId, "-", channel, metadata);

    // A control-plane (console) sign-in — any OIDC provider. An unlinked such identity counts as
    // itself in a quorum; the check is provider-neutral, so adding Microsoft/Okta needs no change
    // beyond this list.
    private static readonly string[] ConsoleSchemes = { "google:", "ms:" };
    private static bool IsConsoleActor(string actor) =>
        ConsoleSchemes.Any(s => actor.StartsWith(s, StringComparison.Ordinal));

    /// <summary>The distinct-approver key for a quorum, channel-agnostic. An identity linked
    /// to an operator principal collapses to <c>principal:&lt;id&gt;</c> (so the same human on
    /// Telegram and the web counts once); an unlinked <b>console</b> identity (any OIDC provider)
    /// counts as itself; anything else unlinked is not eligible (cannot be attributed to a distinct
    /// human). This is the one place the quorum learns about channels — Slack/Teams/app are
    /// just more identity schemes to link, no change here.</summary>
    private (bool eligible, string key) QuorumKey(string actor)
    {
        var principalId = _principals?.Resolve(actor);
        if (principalId is not null) return (true, "principal:" + principalId);
        if (IsConsoleActor(actor)) return (true, actor);
        return (false, "");
    }

    private static string ChannelOf(string actor) =>
        actor.StartsWith("telegram:", StringComparison.Ordinal) ? "telegram"
        : IsConsoleActor(actor) ? "web"
        : actor.StartsWith("email:", StringComparison.Ordinal) ? "email"
        : actor.StartsWith("app:", StringComparison.Ordinal) ? "app"
        : "other";

    public string? StateOf(string id) => _store.Get(id)?.State;
    public string? TargetOf(string id) => _store.Get(id)?.Target;
    public string? ResourceOf(string id) => _store.Get(id)?.Resource;
    public string? SubjectOf(string id) => _store.Get(id)?.Input;
    public string ProfileOf(string id) => _store.Get(id)?.Profile ?? "";
    public int MaxUsesOf(string id) => _store.Get(id)?.MaxUses ?? 0;
    public string CommandOf(string id) => _store.Get(id)?.Command ?? "";
    public string SourceAddrOf(string id) => _store.Get(id)?.SourceAddr ?? "";
    public string ScopeOf(string id) => _store.Get(id)?.Scope ?? "";

    /// <summary>The approval-defining terms of a waiting request, as an immutable snapshot — for the
    /// signing layer, which must bind a signature to exactly what is being approved.</summary>
    public ApprovalContext? ApprovalContextOf(string id)
    {
        var r = _store.Get(id);
        return r is null ? null
            : new ApprovalContext(r.Id, r.Resource, r.RequiredApprovals, r.Subject.ToString(), r.Command, r.SourceAddr, r.Profile);
    }

    /// <summary>Who to ask for this request (0.30): the request's machine-readable subject
    /// resolved to an operator's channel identities, plus whether the admins are asked too.
    /// A subject that does not resolve to an operator falls back to the admins — and that
    /// fallback is audited, never silent, so a misconfigured deployment does not quietly
    /// become ask-the-owner-about-everything. An ordinary request (no subject identity) goes
    /// to the admins as it always has.</summary>
    public async Task<NotifyRouting> ResolveRouting(PendingRequest r, CancellationToken ct)
    {
        var subj = r.SubjectIdentity ?? "";
        if (subj.Length == 0 || _principals is null) return NotifyRouting.Admins;   // no routing intent

        var principalId = _principals.Resolve(subj);
        if (principalId is null)
        {
            await AuditNotifyFallback(r, "subject-unmapped", ct);
            return NotifyRouting.Admins;
        }
        // Forbidden: the subject may not approve, so never route the request to them — ask
        // the admins (other principals) instead.
        if (r.Subject == SubjectApproval.Forbidden) return NotifyRouting.Admins;

        var identities = _principals.IdentitiesOf(principalId);
        if (identities.Count == 0)
        {
            await AuditNotifyFallback(r, "operator-unreachable", ct);
            return NotifyRouting.Admins;
        }
        // Subject Required: ask the subject; add the admins only when more approvers are
        // still needed (RequiredApprovals > 1). Otherwise (Optional): operator AND admins.
        var includeAdmins = r.Subject == SubjectApproval.Required ? r.RequiredApprovals > 1 : true;
        return new NotifyRouting(identities, includeAdmins);
    }

    /// <summary>Does the asserted subject identity denote the same account as the grant's
    /// beneficiary (the requested user)? Self-confirmation is only meaningful when the person
    /// confirming is the one receiving the authority — a request for <c>--user Administrator</c>
    /// by an ordinary subject can never be self-approved. The account is the tail of the
    /// identity (after the last <c>\</c> or <c>:</c>), compared case-insensitively; a subject
    /// with no comparable account (e.g. a bare <c>sid:</c>) does not match, so it fails closed.</summary>
    private static bool BeneficiaryMatches(string user, string subjectIdentity)
    {
        var acct = subjectIdentity;
        var bs = acct.LastIndexOf('\\');
        if (bs >= 0) acct = acct[(bs + 1)..];
        else { var c = acct.LastIndexOf(':'); if (c >= 0) acct = acct[(c + 1)..]; }
        return acct.Length > 0 && string.Equals(acct, user, StringComparison.OrdinalIgnoreCase);
    }

    private Task AuditNotifyFallback(PendingRequest r, string reason, CancellationToken ct)
    {
        _metrics?.RecordNotifyFallback(reason);
        return _audit.Append(Event(AuditEvents.NotifyFallback, "system", r.Input, r.Resource, r.Id,
            r.Resource.StartsWith("web:", StringComparison.Ordinal) ? "gate" : "agent",
            $"{reason}: {r.SubjectIdentity}"), ct);
    }

    // Audit the decision (one grep-able line) and count it (outcome + reason distribution). Every
    // decision in the engine goes through here, so the metric cannot drift from the audit log.
    private void MeteredDecision(string decision, string host, string clientIp,
        string? requestId = null, string? identity = null, string? actor = null, string? reason = null)
    {
        Audit.Decision(_log, decision, host, clientIp, requestId, identity, actor, reason);
        _metrics?.RecordDecision(decision, reason);
    }

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
            .Select(View)
            .ToList();

    public PendingView? RequestView(string id) =>
        _store.Get(id) is { } r ? View(r) : null;

    private PendingView View(PendingRequest r) =>
        new(r.Id, r.Target, r.Input, r.Ip, r.Country, r.CountryCode, r.City, r.Raised, r.State,
            r.RequiredApprovals, r.RequiredApprovals > 1 ? _store.ApprovalCount(r.Id) : 0, r.Command, r.SourceAddr,
            r.RequireSignedApproval);

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
    public async Task<CallbackResult> Decide(string id, string verb, string actor, string proof = "")
    {
        var request = _store.Get(id);
        if (request is null) return new CallbackResult(CallbackOutcome.Expired);
        if (request.State != "waiting") return new CallbackResult(CallbackOutcome.AlreadyHandled);

        var cutoff = _clock.GetUtcNow().AddMinutes(-_options.PendingMinutes);
        if (request.Raised < cutoff)
        {
            _store.Remove(request.Id);
            MeteredDecision("ignored", request.Target, request.Ip,
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

        // Out-of-band proof of intent (defer): an approval must carry a device signature; a chat tap
        // or session click cannot satisfy it. A denial stays unsigned (one "no" is enough, fail-safe).
        if (request.RequireSignedApproval && toState == "approved" && string.IsNullOrEmpty(proof))
            return new CallbackResult(CallbackOutcome.Pending, request,
                "This request can only be approved with a registered device — open it in the app and approve with your device.");

        // Quorum: a tag-driven policy may require several DISTINCT approvers. A denial
        // from any channel still denies at once (one "no" is enough). An approval, when
        // the quorum is > 1, counts per DISTINCT OPERATOR PRINCIPAL — the human, not the
        // channel: an identity linked to a principal (telegram:, slack:, teams:, app:, a
        // linked google:) counts as that person, and the same person via two channels
        // dedupes to one. An unlinked google admin counts as itself (its sub); any other
        // unlinked channel identity cannot be attributed to a distinct human and does not
        // count. When enough distinct principals have signed off, we fall through.
        if (toState == "approved" && (request.RequiredApprovals > 1 || request.Subject != SubjectApproval.Optional))
        {
            var (eligible, principalKey) = QuorumKey(actor);
            if (!eligible)
            {
                await _audit.Append(Event(AuditEvents.AccessApprovalNoted, actor, request.Input, request.Resource,
                    id, ChannelOf(actor), "not counted (identity not linked to an operator principal)"), CancellationToken.None);
                return new CallbackResult(CallbackOutcome.Pending, request,
                    "Approval noted — this identity is not linked to an operator, so it does not count toward the quorum.");
            }

            var subjectPrincipal = request.Subject == SubjectApproval.Optional ? null : _principals?.Resolve(request.SubjectIdentity);

            // Forbidden: the request's own subject may not approve it — a clean four-eyes by
            // others. Their tap is refused outright and never counted.
            if (request.Subject == SubjectApproval.Forbidden && subjectPrincipal is not null
                && principalKey == "principal:" + subjectPrincipal)
            {
                await _audit.Append(Event(AuditEvents.AccessApprovalNoted, actor, request.Input, request.Resource,
                    id, ChannelOf(actor), "refused (subject may not approve own request)"), CancellationToken.None);
                return new CallbackResult(CallbackOutcome.Pending, request,
                    "You cannot approve your own request — this resource requires another person.");
            }

            var count = _store.AddApprovalAndCount(id, principalKey);

            // Required: the subject's operator principal must be among the approvers. Any of
            // that person's linked channels satisfies it — the same person via two channels
            // is still one.
            var subjectPending = request.Subject == SubjectApproval.Required
                && (subjectPrincipal is null || !_store.HasApproval(id, "principal:" + subjectPrincipal));

            if (count < request.RequiredApprovals || subjectPending)
            {
                await _audit.Append(Event(AuditEvents.AccessApprovalNoted, actor, request.Input, request.Resource,
                    id, "web", subjectPending ? $"{count} of {request.RequiredApprovals}, awaiting the subject" : $"{count} of {request.RequiredApprovals}"), CancellationToken.None);
                return new CallbackResult(CallbackOutcome.Pending, request,
                    subjectPending
                        ? $"Approved by {count} of {request.RequiredApprovals} — still waiting for the subject to confirm."
                        : $"Approved by {count} of {request.RequiredApprovals} — waiting for more approvers.");
            }
            // Quorum reached (and the subject has confirmed, if required) — fall through.
        }

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
                scope.AppendAudit(DecisionEvent(toState, actor, req, verb, proof));
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

        MeteredDecision(toState == "approved" ? "approved" : "denied",
            request.Target, request.Ip, requestId: request.Id, identity: request.Input,
            actor: actor, reason: verb);
        if (toState == "approved")
            _metrics?.RecordTimeToApproval((_clock.GetUtcNow() - request.Raised).TotalSeconds);
        // Non-transactional path only: the durable event is a best-effort second
        // step here, so if it fails (disk/IO) the decision stands without it. The
        // transactional path already appended the event inside the resolve above.
        if (_atomic is null)
            await _audit.Append(DecisionEvent(toState, actor, request, verb, proof), CancellationToken.None);

        return new CallbackResult(CallbackOutcome.Decided, request, outcome);
    }

    /// <summary>The audit event for a resolved decision — built the same way whether
    /// it is appended inside the transaction or as the best-effort second step.</summary>
    private AuditEvent DecisionEvent(string toState, string actor, PendingRequest request, string verb, string proof = "") =>
        Event(toState == "approved" ? AuditEvents.AccessApproved : AuditEvents.AccessDenied,
            actor: actor, subject: request.Input, resource: request.Resource,
            requestId: request.Id, channel: ChannelOf(actor),
            // A device-signed decision folds a short commitment to its proof into the hashed Metadata
            // (the proof itself rides on AuditEvent.Proof, outside the chain hash), so the proof is
            // tamper-evident without rewriting the chain's field set.
            metadata: proof.Length == 0 ? verb : $"{verb} p={WebAuthnProof.Commitment(proof)}")
        with { Proof = proof };

    // ---- Lists: read and mutate (formatting lives in the notifier) ----------

    public IReadOnlyList<AccessLists.Entry> ListEntries(string list) => _lists.All(list);

    public bool RemoveListEntry(string list, int index) => _lists.RemoveAt(list, index);

    // Manual /allow /block default to web:* — the historical meaning of these
    // commands. Resource-specific entries come from the buttons on a request,
    // which carry that request's resource.
    public void AddListEntry(string list, string type, string value) => _lists.Add(list, "web:*", type, value, Now());

    public void SetSessionMinutes(int minutes)
    {
        lock (_enforcedLock)
        {
            // Read-modify-write the settings blob rather than overwrite it, so a
            // future second setting is not silently dropped when session length changes.
            _config.Mutate("settings", cur =>
            {
                var obj = ParseSettingsObject(cur);
                obj["sessionMinutes"] = minutes;
                return obj.ToJsonString();
            });
            _sessionMinutes = minutes;
            _configLoadedAt = _clock.GetUtcNow();
        }
    }

    private static System.Text.Json.Nodes.JsonObject ParseSettingsObject(string? blob)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(blob))
                return System.Text.Json.Nodes.JsonNode.Parse(blob)?.AsObject() ?? new();
        }
        catch { /* malformed → start fresh, same as LoadSessionMinutes' fallback */ }
        return new();
    }
}
