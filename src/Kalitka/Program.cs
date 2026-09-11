using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kalitka;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<GateOptions>(builder.Configuration.GetSection("Kalitka"));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpClient<ITelegramClient, TelegramClient>();
builder.Services.AddHttpClient<HttpGeoLookup>();
// Geolocation provider (notification only, never blocks a request): a local
// MaxMind database when GeoDbPath is set (no visitor IP leaves the box), else the
// HTTP provider when GeoUrl is set, else disabled. A configured-but-missing .mmdb
// falls back rather than downing the gate.
builder.Services.AddSingleton<IGeoLookup>(sp =>
{
    var o = sp.GetRequiredService<IOptions<GateOptions>>().Value;
    if (!string.IsNullOrWhiteSpace(o.GeoDbPath))
    {
        if (File.Exists(o.GeoDbPath))
            return new MaxMindGeoLookup(o.GeoDbPath, sp.GetRequiredService<ILogger<MaxMindGeoLookup>>());
        sp.GetRequiredService<ILogger<Program>>().LogWarning(
            "Kalitka__GeoDbPath is set but {Path} does not exist; falling back.", o.GeoDbPath);
    }
    if (!string.IsNullOrWhiteSpace(o.GeoUrl)) return sp.GetRequiredService<HttpGeoLookup>();
    return new NullGeoLookup();
});
builder.Services.AddHttpClient<GoogleAuth>();
builder.Services.AddSingleton<AccessLists>();
builder.Services.AddSingleton<GateService>();
builder.Services.AddSingleton<TokenSigner>(sp =>
    new TokenSigner(sp.GetRequiredService<IOptions<GateOptions>>().Value.HmacSecret));
builder.Services.AddTransient<AdminAuth>();
builder.Services.AddSingleton<OneTimeTokenService>();
// Backend precedence for the durable stores: Postgres (multi-node) when a
// connection string is set, else SQLite when a path is set, else in-memory. The
// seams and atomic guarantees are identical across all three — only the wiring
// differs. With Postgres, all four stores share the one database, so state and
// audit commit in one transaction.
static string? Pg(IServiceProvider sp) =>
    sp.GetRequiredService<IOptions<GateOptions>>().Value.PostgresConnectionString is { Length: > 0 } cs ? cs : null;

builder.Services.AddSingleton<IAuditStore>(sp =>
{
    if (Pg(sp) is { } cs) return new PgAuditStore(cs);
    var path = sp.GetRequiredService<IOptions<GateOptions>>().Value.AuditDbPath;
    return string.IsNullOrWhiteSpace(path) ? new InMemoryAuditStore() : new SqliteAuditStore(path);
});
builder.Services.AddSingleton<IRequestStore>(sp =>
{
    if (Pg(sp) is { } cs) return new PgRequestStore(cs);
    var path = sp.GetRequiredService<IOptions<GateOptions>>().Value.StateDbPath;
    return string.IsNullOrWhiteSpace(path) ? new InMemoryRequestStore() : new SqliteRequestStore(path);
});
builder.Services.AddSingleton<IReplayStore>(sp =>
{
    var clock = sp.GetRequiredService<TimeProvider>();
    if (Pg(sp) is { } cs) return new PgReplayStore(cs, clock);
    var path = sp.GetRequiredService<IOptions<GateOptions>>().Value.StateDbPath;
    return string.IsNullOrWhiteSpace(path) ? new InMemoryReplayStore(clock) : new SqliteReplayStore(path, clock);
});
builder.Services.AddSingleton<ISessionStore>(sp =>
{
    if (Pg(sp) is { } cs) return new PgSessionStore(cs);
    var path = sp.GetRequiredService<IOptions<GateOptions>>().Value.StateDbPath;
    return string.IsNullOrWhiteSpace(path) ? new InMemorySessionStore() : new SqliteSessionStore(path);
});
// The unit of work that commits a state change and its audit event in one
// transaction. Always present with Postgres (one database). With SQLite only when
// state and audit are the *same* file. Absent otherwise — in-memory, or state and
// audit on separate files — and the engine keeps the sequential best-effort append.
var pgConn = builder.Configuration["Kalitka:PostgresConnectionString"];
var stateDbPath = builder.Configuration["Kalitka:StateDbPath"];
var auditDbPath = builder.Configuration["Kalitka:AuditDbPath"];
if (!string.IsNullOrWhiteSpace(pgConn))
{
    builder.Services.AddSingleton<IAtomicWork>(_ => new PgAtomicWork(pgConn));
}
else if (!string.IsNullOrWhiteSpace(stateDbPath) &&
    string.Equals(stateDbPath, auditDbPath, StringComparison.Ordinal))
{
    builder.Services.AddSingleton<IAtomicWork>(_ => new SqliteAtomicWork(stateDbPath));
}
// Shared config (block/allow lists, armed hosts, runtime settings). Same backend
// precedence as the stores; the file backend is the single-instance default and
// keeps existing lists.json / enforced.json / settings.json working.
builder.Services.AddSingleton<IConfigStore>(sp =>
{
    var o = sp.GetRequiredService<IOptions<GateOptions>>().Value;
    if (!string.IsNullOrWhiteSpace(o.PostgresConnectionString)) return new PgConfigStore(o.PostgresConnectionString);
    if (!string.IsNullOrWhiteSpace(o.StateDbPath)) return new SqliteConfigStore(o.StateDbPath);
    return new JsonFileConfigStore(o, sp.GetRequiredService<ILogger<JsonFileConfigStore>>());
});
// Agent registry: the durable identity/trust model for /agent/* callers. Same
// backend precedence; in-memory default. Empty until agents are enrolled — the
// legacy global AgentSecret keeps working alongside during migration.
builder.Services.AddSingleton<IAgentStore>(sp =>
{
    var o = sp.GetRequiredService<IOptions<GateOptions>>().Value;
    if (!string.IsNullOrWhiteSpace(o.PostgresConnectionString)) return new PgAgentStore(o.PostgresConnectionString);
    if (!string.IsNullOrWhiteSpace(o.StateDbPath)) return new SqliteAgentStore(o.StateDbPath);
    return new InMemoryAgentStore();
});
builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
// A second approval channel beside Telegram. GateService picks up every INotifier.
builder.Services.AddSingleton<INotifier, EmailNotifier>();
builder.Services.AddSingleton<GrantService>();
builder.Services.AddSingleton<AgentService>();
builder.Services.AddSingleton<ProfileService>();
builder.Services.AddSingleton<ReconcileService>();

var app = builder.Build();
var options = app.Services.GetRequiredService<IOptions<GateOptions>>().Value;

// Refuse to start half-configured. An open webhook or an unsigned cookie is
// worse than a gate that does not come up: the first fails silently, the
// second is noticed immediately.
foreach (var (value, name) in new[]
{
    (options.BotToken,      nameof(options.BotToken)),
    (options.WebhookPath,   nameof(options.WebhookPath)),
    (options.WebhookSecret, nameof(options.WebhookSecret)),
    (options.HmacSecret,    nameof(options.HmacSecret)),
    (options.GateHost,      nameof(options.GateHost)),
})
{
    if (string.IsNullOrWhiteSpace(value))
        throw new InvalidOperationException($"Kalitka__{name} must be set.");
}

if (!options.WebhookPath.StartsWith('/'))
    throw new InvalidOperationException("Kalitka__WebhookPath must start with '/'.");

// Behind a proxy with no trusted proxies configured, every visitor looks like
// the proxy itself. If that address happens to fall inside a bypass network —
// and a proxy on a Docker network usually does — the gate would wave everyone
// through while looking perfectly configured. Refuse rather than pretend.
if (options.BypassNetworks.Length > 0 && options.TrustedProxies.Length == 0)
{
    throw new InvalidOperationException(
        "Kalitka__BypassNetworks is set but Kalitka__TrustedProxies is empty. "
        + "Without trusted proxies every request appears to come from the proxy, "
        + "which would put all visitors inside the bypass network. "
        + "Set TrustedProxies to the address range your reverse proxy connects from.");
}

if (options.TrustedProxies.Length == 0)
{
    app.Logger.LogWarning(
        "No trusted proxies configured: forwarded headers are ignored and every "
        + "decision uses the address the connection came from. Behind a reverse "
        + "proxy that means all visitors share one address.");
}

app.MapGet("/health", () => Results.Text("ok"));

// ---------------------------------------------------------------------------
// The forwardAuth endpoint. Your reverse proxy asks this before every request
// to a guarded host: 200 means let it through, 302 sends the visitor here.
// ---------------------------------------------------------------------------
var authCheck = (HttpContext ctx, GateService gate, ILogger<Program> log) =>
{
    if (IsAllowed(ctx, gate, log, out var host)) return Results.Ok();

    // A redirect is only meaningful to a top-level navigation. A WebSocket
    // handshake, an XHR/fetch or a sub-resource cannot follow a 302 to the
    // gate's HTML page: the handshake fails, the fetch reads HTML as its data,
    // and a single-page app behind the gate hangs on a blank screen. Answer
    // those with 401 instead, so the app fails cleanly and its own login flow
    // (or a full reload) can take over.
    if (!IsTopLevelNavigation(ctx.Request))
        return Results.Unauthorized();

    return Results.Redirect(
        $"https://{gate.GateHost}/request?target={Uri.EscapeDataString(host)}", false);
};

// The same verdict, mapped for a proxy whose auth check acts on the status code
// and does the redirect itself — nginx `auth_request`, which turns a 401 into a
// redirect via `error_page`. Allow → 200, otherwise → 401, never a redirect (a
// 3xx would confuse those proxies). The Location header carries where the gate
// is, for a proxy that can use it.
var authzCheck = (HttpContext ctx, GateService gate, ILogger<Program> log) =>
{
    if (IsAllowed(ctx, gate, log, out var host)) return Results.Ok();

    ctx.Response.Headers.Location = $"https://{gate.GateHost}/request?target={Uri.EscapeDataString(host)}";
    return Results.Unauthorized();
};

// Both exact and catch-all: Traefik/Caddy call `/auth` verbatim, while Envoy
// `ext_authz` prepends its `path_prefix` to the *original* request path, so the
// check arrives as `/auth/<whatever>`. The verdict never depends on the path, so
// the trailing segments are simply ignored — and the prefix keeps these checks
// clear of kalitka's own routes (/request, /wait, ...).
app.MapMethods("/auth", new[] { "GET", "HEAD" }, authCheck);
app.MapMethods("/auth/{*rest}", new[] { "GET", "HEAD" }, authCheck);
app.MapMethods("/authz", new[] { "GET", "HEAD" }, authzCheck);
app.MapMethods("/authz/{*rest}", new[] { "GET", "HEAD" }, authzCheck);

// ---------------------------------------------------------------------------
// What the visitor sees
// ---------------------------------------------------------------------------
app.MapGet("/request", (HttpContext ctx, GoogleAuth google) =>
    Results.Content(Pages.Form(VisitorLang(ctx), ctx.Request.Query["target"].ToString(), false, google.Enabled),
        "text/html; charset=utf-8"));

app.MapPost("/request", async (HttpContext ctx, GateService gate, GoogleAuth google) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var target = form["target"].ToString();
    var input = form["input"].ToString();
    var lang = VisitorLang(ctx);
    var s = L10n.For(lang);

    var ip = ResolveIp(ctx, gate);

    var (state, id) = await gate.Request(target, input, ip, ctx.RequestAborted);

    if (state == "allowed")
    {
        SetSessionCookie(ctx, gate, gate.BuildCookie(target));
        return Results.Redirect($"https://{target}", false);
    }

    return state switch
    {
        // Refused and blocked look the same on purpose: a blocked caller should
        // not learn that they are blocked.
        "blocked" => Results.Content(Pages.Message(lang, s.RefusedTitle, s.AccessDenied), "text/html; charset=utf-8"),
        "invalid" => Results.Content(Pages.Form(lang, target, error: true, google.Enabled), "text/html; charset=utf-8"),
        _         => Results.Content(Pages.Waiting(lang, id, target), "text/html; charset=utf-8")
    };
});

app.MapGet("/wait/status", (HttpContext ctx, GateService gate) =>
{
    var id = ctx.Request.Query["id"].ToString();
    var state = gate.StateOf(id);

    if (state is null) return Results.Json(new { state = "gone" });

    if (state == "approved")
    {
        var target = gate.TargetOf(id) ?? "";
        SetSessionCookie(ctx, gate, gate.BuildCookie(target));
        return Results.Json(new { state = "approved", target });
    }

    return Results.Json(new { state = state == "denied" ? "denied" : "waiting" });
});

// ---------------------------------------------------------------------------
// Google sign-in: the second way in, for people who should not have to wait
// ---------------------------------------------------------------------------
app.MapGet("/google/login", (HttpContext ctx, GateService gate, GoogleAuth google) =>
{
    if (!google.Enabled) return Results.NotFound();

    var target = ctx.Request.Query["target"].ToString();
    if (!gate.IsGuardedHost(target)) return Results.BadRequest();

    var nonce = NewStateNonce();
    SetStateCookie(ctx, "kalitka_oauth_state", "/", nonce);
    return Results.Redirect(google.AuthorizationUrl(gate.BuildState(target, nonce)), false);
});

app.MapGet("/oauth2/callback", async (HttpContext ctx, GateService gate, GoogleAuth google) =>
{
    var code = ctx.Request.Query["code"].ToString();
    var state = ctx.Request.Query["state"].ToString();
    var nonce = ctx.Request.Cookies["kalitka_oauth_state"] ?? "";
    ClearStateCookie(ctx, "kalitka_oauth_state", "/");

    var s = L10n.For(VisitorLang(ctx));
    if (string.IsNullOrEmpty(code) || !gate.TryReadState(state, nonce, out var target) || !gate.IsGuardedHost(target))
        return Results.Content(Pages.Message(VisitorLang(ctx), s.ErrorTitle, s.SigninInvalid),
            "text/html; charset=utf-8");

    var email = await google.ResolveEmail(code, ctx.RequestAborted);
    if (email is null || !google.IsPermitted(email))
        return Results.Content(Pages.Message(VisitorLang(ctx), s.RefusedTitle, s.GoogleNotPermitted),
            "text/html; charset=utf-8");

    Audit.Decision(app.Logger, "approved", target, ResolveIp(ctx, gate), identity: email, reason: "google");

    // A proven identity earns a session scoped by SessionScope: the one host it
    // signed in for (Application, the default), or every guarded host under the
    // cookie domain (Domain). Manual approvals are always per-host.
    SetSessionCookie(ctx, gate, gate.BuildIdentitySession(target));
    return Results.Redirect($"https://{target}", false);
});

// ---------------------------------------------------------------------------
// Arm or disarm a host from another service on the same network
// ---------------------------------------------------------------------------
app.MapGet("/internal/hosts", (HttpContext ctx, GateService gate) =>
    InternalGuard(ctx, gate) ?? Results.Json(gate.EnforcedHosts()));

app.MapPost("/internal/toggle", (HttpContext ctx, GateService gate) =>
{
    var denied = InternalGuard(ctx, gate);
    if (denied is not null) return denied;

    var host = ctx.Request.Query["host"].ToString();
    if (string.IsNullOrWhiteSpace(host)) return Results.BadRequest();

    var on = ctx.Request.Query["on"].ToString() == "1";
    gate.SetEnforced(host, on);
    return Results.Json(new { host, on });
});

// ---------------------------------------------------------------------------
// Non-HTTP agents (SSH, later DB/RDP), guarded by the agent registry. An agent on
// another host — e.g. an sshd PAM hook — raises an access request for a resource
// like ssh:<host> and polls its state. Kalitka only decides yes/no; it brokers no
// credentials and proxies nothing. The human approves through any channel.
//
// The canonical namespace is /agent/v1/* (protocol versioning from the start); the
// unprefixed /agent/* paths remain as deprecated aliases so already-deployed PAM
// hooks keep working. Both map to the same handlers; legacy calls get a
// `Deprecation` response header.
// ---------------------------------------------------------------------------
app.MapPost("/agent/v1/requests", AgentRequest);
app.MapPost("/agent/request", AgentRequest);
app.MapGet("/agent/v1/requests/{id}", AgentPoll);
app.MapGet("/agent/status", AgentPoll);
app.MapPost("/agent/v1/grants/redeem", AgentRedeem);
app.MapPost("/agent/redeem", AgentRedeem);
app.MapPost("/agent/v1/sessions/end", AgentSessionEnd);
app.MapPost("/agent/session/end", AgentSessionEnd);
app.MapPost("/agent/v1/enroll", AgentEnroll);
app.MapPost("/agent/enroll", AgentEnroll);
app.MapPost("/agent/v1/heartbeat", AgentHeartbeat);
app.MapPost("/agent/heartbeat", AgentHeartbeat);

static async Task<IResult> AgentRequest(HttpContext ctx, GateService gate, IAgentStore agents)
{
    MarkAgentVersion(ctx);
    var identity = AuthenticateAgent(ctx, gate, agents);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    var host = form["host"].ToString().Trim();
    var user = form["user"].ToString().Trim();
    var ip = form["ip"].ToString().Trim();
    if (string.IsNullOrEmpty(ip)) ip = ResolveIp(ctx, gate);

    // The host names a resource; keep it a sane label (it lands in audit/notify).
    if (host.Length is 0 or > 100 || host.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '-' or '_')))
        return Results.BadRequest();

    // The authenticated agent may only raise resources it is scoped to (capability
    // + allowed resource) — a valid credential is not a licence for any resource.
    var resource = "ssh:" + host;
    if (!identity.MayRepresent(resource, AgentCapabilities.Request)) return Results.StatusCode(403);

    var (state, id) = await gate.RaiseAction(resource, user, ip, identity.Actor, ctx.RequestAborted);
    return Results.Json(new { id, state });
}

static async Task<IResult> AgentPoll(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents)
{
    MarkAgentVersion(ctx);
    var identity = AuthenticateAgent(ctx, gate, agents);
    if (identity is null) return Results.StatusCode(403);

    // v1: /agent/v1/requests/{id}; legacy: /agent/status?id=…
    var id = ctx.Request.RouteValues.TryGetValue("id", out var rv) && rv is string s && s.Length > 0
        ? s : ctx.Request.Query["id"].ToString();
    var state = gate.StateOf(id) ?? "gone";
    // On approval the agent gets a one-time grant to redeem — approval alone no
    // longer means "in". Issued once; repeated polls return the same grant.
    var grant = state == "approved" ? await grants.IssueGrant(id, identity, ctx.RequestAborted) : null;
    return Results.Json(new { state, grant });
}

// Redeem the grant exactly once and start a session (grant.redeemed + session.started).
static async Task<IResult> AgentRedeem(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents)
{
    MarkAgentVersion(ctx);
    var identity = AuthenticateAgent(ctx, gate, agents);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    // "agent" is the self-reported hostname (metadata); identity is the canonical one.
    var result = await grants.Redeem(form["grant"].ToString(), identity, form["agent"].ToString(), ctx.RequestAborted);
    if (result.Ok) return Results.Json(new { session_id = result.SessionId });
    return Results.Json(new { error = result.Error }, statusCode: result.Error == "used" ? 409 : 403);
}

// The agent reports the session ended (session.ended).
static async Task<IResult> AgentSessionEnd(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents)
{
    MarkAgentVersion(ctx);
    var identity = AuthenticateAgent(ctx, gate, agents);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    var ok = await grants.EndSession(form["session_id"].ToString(), form["outcome"].ToString(), ctx.RequestAborted);
    return ok ? Results.Ok() : Results.StatusCode(404);
}

// Self-enrolment: an agent presents a one-time enrollment token and its own
// generated secret to become active. The token itself is the authorization here.
static async Task<IResult> AgentEnroll(HttpContext ctx, AgentService agentsSvc)
{
    MarkAgentVersion(ctx);
    var form = await ctx.Request.ReadFormAsync();
    var result = await agentsSvc.Enroll(
        form["token"].ToString(), form["secret"].ToString(),
        form["hostname"].ToString(), form["metadata"].ToString(), ctx.RequestAborted);
    return result.Ok
        ? Results.Json(new { agent_id = result.AgentId })
        : Results.Json(new { error = result.Error }, statusCode: result.Error == "used" ? 409 : 400);
}

// A liveness ping. last_seen is also updated on any authenticated agent call.
static IResult AgentHeartbeat(HttpContext ctx, GateService gate, IAgentStore agents)
{
    MarkAgentVersion(ctx);
    return AuthenticateAgent(ctx, gate, agents) is null ? Results.StatusCode(403) : Results.Ok();
}

// Flag the deprecated unprefixed /agent/* aliases so callers can migrate to /agent/v1.
static void MarkAgentVersion(HttpContext ctx)
{
    if (!ctx.Request.Path.StartsWithSegments("/agent/v1"))
        ctx.Response.Headers["Deprecation"] = "true";
}

// ---------------------------------------------------------------------------
// Telegram webhook: secret path plus secret header
// ---------------------------------------------------------------------------
app.MapPost(options.WebhookPath, async (HttpContext ctx, GateService gate, ILogger<Program> log) =>
{
    if (!SecretEquals(ctx.Request.Headers["X-Telegram-Bot-Api-Secret-Token"].ToString(), options.WebhookSecret))
        return Results.StatusCode(403);

    try
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
        var update = doc.RootElement;

        if (update.TryGetProperty("callback_query", out var callback))
        {
            var callbackId = callback.GetProperty("id").GetString() ?? "";
            var from = callback.GetProperty("from").GetProperty("id").GetInt64();
            var data = callback.TryGetProperty("data", out var d) ? d.GetString() ?? "" : "";

            var chatId = ""; long messageId = 0;
            if (callback.TryGetProperty("message", out var message))
            {
                chatId = message.GetProperty("chat").GetProperty("id").GetInt64().ToString();
                messageId = message.GetProperty("message_id").GetInt64();
            }

            await gate.HandleCallback(data, from, callbackId, chatId, messageId, ctx.RequestAborted);
        }
        else if (update.TryGetProperty("message", out var message))
        {
            var from = message.GetProperty("from").GetProperty("id").GetInt64();
            var chatId = message.GetProperty("chat").GetProperty("id").GetInt64().ToString();
            var text = message.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "";

            if (gate.IsAdmin(from))
            {
                var pieces = text.Trim().Split(' ', 2);
                var command = pieces[0].Split('@')[0].ToLowerInvariant();
                var argument = pieces.Length > 1 ? pieces[1] : "";

                switch (command)
                {
                    case "/blocked": await gate.ShowBlockList(chatId, ctx.RequestAborted); break;
                    case "/allowed": await gate.ShowAllowList(chatId, ctx.RequestAborted); break;
                    case "/allow":   await gate.Reply(chatId, gate.ListAddCommand("allow", argument), ctx.RequestAborted); break;
                    case "/block":   await gate.Reply(chatId, gate.ListAddCommand("block", argument), ctx.RequestAborted); break;
                    case "/hosts":   await gate.Reply(chatId, gate.HostsCommand(), ctx.RequestAborted); break;
                    case "/mute":    await gate.Reply(chatId, gate.MuteCommand(argument), ctx.RequestAborted); break;
                    case "/unmute":  await gate.Reply(chatId, gate.MuteCommand("off"), ctx.RequestAborted); break;
                    case "/session": await gate.Reply(chatId, gate.SessionCommand(argument), ctx.RequestAborted); break;
                    default:
                        await gate.Reply(chatId,
                            "kalitka:\n"
                            + "/allowed, /blocked — show the lists\n"
                            + "/allow ip|name &lt;value&gt; — let someone in before they ask\n"
                            + "/block ip|name|country &lt;value&gt; — turn someone away in advance\n"
                            + "/hosts — which hosts are guarded\n"
                            + "/mute [min], /unmute\n"
                            + "/session [min] — how long an approval lasts",
                            ctx.RequestAborted);
                        break;
                }
            }
        }
    }
    catch (Exception e)
    {
        // Never answer Telegram with 500: it would retry the same update
        // forever. Log it and move on.
        log.LogWarning("Could not handle update: {Message}", e.Message);
    }

    return Results.Ok();
});

// ---------------------------------------------------------------------------
// One-time approval links (the e-mail channel). The GET shows a confirmation
// page and consumes nothing — a mail scanner pre-fetching the link is harmless.
// Only the POST consumes the one-time token and resolves the request.
// ---------------------------------------------------------------------------
app.MapGet("/action", (HttpContext ctx, OneTimeTokenService tokens, GateService gate) =>
{
    var lang = VisitorLang(ctx);
    var s = L10n.For(lang);
    var token = ctx.Request.Query["t"].ToString();
    var cap = tokens.Read(token);
    var verb = cap is null ? null : OneTimeTokenService.VerbFor(cap.Purpose, cap.Action);
    if (cap is null || verb is null)
        return Results.Content(Pages.Message(lang, s.LinkInvalidTitle, s.LinkInvalidText),
            "text/html; charset=utf-8");

    var view = gate.RequestView(cap.RequestId);
    if (view is null || view.State != "waiting")
        return Results.Content(Pages.Message(lang, s.NothingToDoTitle, s.NothingToDoText),
            "text/html; charset=utf-8");

    return Results.Content(
        Pages.ActionConfirm(lang, verb == "ok", cap.Resource, view.Input, token),
        "text/html; charset=utf-8");
});

app.MapPost("/action", async (HttpContext ctx, OneTimeTokenService tokens, IReplayStore replay, GateService gate) =>
{
    var lang = VisitorLang(ctx);
    var s = L10n.For(lang);
    var form = await ctx.Request.ReadFormAsync();
    var cap = tokens.Read(form["t"].ToString());
    var verb = cap is null ? null : OneTimeTokenService.VerbFor(cap.Purpose, cap.Action);
    if (cap is null || verb is null)
        return Results.Content(Pages.Message(lang, s.LinkInvalidTitle, s.LinkInvalidText),
            "text/html; charset=utf-8");

    // Consume first (single-use), then resolve. A spent link cannot act again,
    // and the resolve-once guarantee handles a request already decided elsewhere.
    if (!await replay.TryConsumeAsync(cap.Jti, cap.ExpiresAt, ctx.RequestAborted))
        return Results.Content(Pages.Message(lang, s.AlreadyUsedTitle, s.AlreadyUsedText),
            "text/html; charset=utf-8");

    var result = await gate.Decide(cap.RequestId, verb, "email:link");
    var message = result.Outcome switch
    {
        CallbackOutcome.Decided        => verb == "ok" ? s.ActionApproved : s.ActionDenied,
        CallbackOutcome.AlreadyHandled => s.ActionAlreadyDecided,
        _                              => s.ActionNoLongerWaiting
    };
    return Results.Content(Pages.Message(lang, s.DoneTitle, message), "text/html; charset=utf-8");
});

// ---------------------------------------------------------------------------
// Web control plane (/admin): a second, authenticated channel over the same
// engine. Google OIDC + an explicit admin allowlist + a separate admin session
// (admin:v1 key). Telegram approval stays independently available.
// ---------------------------------------------------------------------------
var adminGroup = app.MapGroup("/admin");

adminGroup.MapGet("", () => Results.Redirect("/admin/dashboard", false));

adminGroup.MapGet("/login", (HttpContext ctx, AdminAuth auth) =>
{
    if (auth.ReadCookie(ctx.Request.Cookies[AdminAuth.CookieName]) is not null)
        return Results.Redirect("/admin/dashboard", false);
    var error = ctx.Request.Query["error"].ToString();
    return Results.Content(AdminPages.Login(auth.Enabled, string.IsNullOrEmpty(error) ? null : error),
        "text/html; charset=utf-8");
});

adminGroup.MapGet("/login/google", (HttpContext ctx, AdminAuth auth) =>
{
    if (!auth.Enabled) return Results.NotFound();
    var nonce = NewStateNonce();
    SetStateCookie(ctx, "kalitka_admin_state", "/admin", nonce);
    return Results.Redirect(auth.LoginUrl(ctx.Request.Query["return"].ToString(), nonce), false);
});

adminGroup.MapGet("/oauth2/callback", async (HttpContext ctx, AdminAuth auth, GateService gate, IAuditStore audit, ILogger<Program> log) =>
{
    if (!auth.Enabled) return Results.NotFound();

    var nonce = ctx.Request.Cookies["kalitka_admin_state"] ?? "";
    ClearStateCookie(ctx, "kalitka_admin_state", "/admin");
    var result = await auth.CompleteLogin(
        ctx.Request.Query["code"].ToString(), ctx.Request.Query["state"].ToString(), nonce, ctx.RequestAborted);

    if (!result.Ok || result.Identity is null)
    {
        Audit.Decision(log, "admin-login-denied", "-", ResolveIp(ctx, gate), reason: "google");
        await audit.Append(AdminEvent(AuditEvents.AdminLoginDenied, "-", "-"), ctx.RequestAborted);
        return Results.Redirect("/admin/login?error=" + Uri.EscapeDataString("Sign-in was not accepted."), false);
    }

    SetAdminCookie(ctx, auth.IssueCookie(result.Identity));
    Audit.Decision(log, "admin-login", "-", ResolveIp(ctx, gate),
        identity: result.Identity.Email, actor: result.Identity.Actor, reason: "google");
    await audit.Append(AdminEvent(AuditEvents.AdminLogin, result.Identity.Actor, result.Identity.Email), ctx.RequestAborted);
    return Results.Redirect(result.ReturnPath, false);
});

adminGroup.MapPost("/logout", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete(AdminAuth.CookieName, new CookieOptions { Path = "/admin", Secure = true });
    return Results.Redirect("/admin/login", false);
});

// One guard for everything below: a valid admin session, re-checked against the
// allowlist on every request (removing someone from AdminEmails revokes their
// session now, not at expiry). A protected endpoint added to this group cannot
// forget the check. The verified identity is put on HttpContext.Items.
var guarded = adminGroup.MapGroup("");
guarded.AddEndpointFilter(async (ctx, next) =>
{
    var http = ctx.HttpContext;
    var adminAuth = http.RequestServices.GetRequiredService<AdminAuth>();
    var who = adminAuth.ReadCookie(http.Request.Cookies[AdminAuth.CookieName]);
    if (who is null)
        return Results.Redirect("/admin/login?return=" + Uri.EscapeDataString(http.Request.Path), false);
    // Resolve permissions from the current config for this request (not frozen in the
    // cookie), so an allowlist change takes effect at once. Per-endpoint filters and
    // the nav both read who.Permissions.
    http.Items["admin"] = who with { Permissions = adminAuth.ResolvePermissions(who.Email) };
    return await next(ctx);
});

guarded.MapGet("/dashboard", (HttpContext ctx, GateService gate) =>
{
    var pending = gate.PendingSnapshot();
    return Results.Content(
        AdminPages.Dashboard(Admin(ctx), pending.Count(r => r.State == "waiting"), gate.EnforcedHosts().Count),
        "text/html; charset=utf-8");
});

guarded.MapGet("/requests", (HttpContext ctx, GateService gate) =>
    Results.Content(AdminPages.Requests(Admin(ctx), gate.PendingSnapshot()), "text/html; charset=utf-8"))
    .RequirePermission(Perm.RequestsRead);

guarded.MapGet("/requests/{id}", (HttpContext ctx, string id, AdminAuth auth, GateService gate) =>
{
    var who = Admin(ctx);
    var view = gate.RequestView(id);
    return view is null
        ? Results.Content(AdminPages.Requests(who, gate.PendingSnapshot()), "text/html; charset=utf-8")
        : Results.Content(AdminPages.Detail(who, view, auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.RequestsRead);

guarded.MapPost("/requests/decide", async (HttpContext ctx, AdminAuth auth, GateService gate) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await gate.Decide(form["id"].ToString(), form["verb"].ToString(), who.Actor);
    return Results.Redirect("/admin/requests", false);
}).RequirePermission(Perm.RequestsDecide);

guarded.MapGet("/history", async (HttpContext ctx, IAuditStore audit) =>
{
    var q = ctx.Request.Query;
    var actor = q["actor"].ToString();
    var resource = q["resource"].ToString();
    var eventType = q["event"].ToString();
    int.TryParse(q["offset"].ToString(), out var offset);
    const int limit = 50;

    var events = await audit.Query(new AuditQuery(
        Actor: string.IsNullOrEmpty(actor) ? null : actor,
        Resource: string.IsNullOrEmpty(resource) ? null : resource,
        EventType: string.IsNullOrEmpty(eventType) ? null : eventType,
        Limit: limit, Offset: Math.Max(0, offset)), ctx.RequestAborted);

    return Results.Content(
        AdminPages.History(Admin(ctx), events, actor, resource, eventType, Math.Max(0, offset), limit),
        "text/html; charset=utf-8");
}).RequirePermission(Perm.HistoryRead);

// ---- Agents (control plane) ------------------------------------------------

guarded.MapGet("/agents", (HttpContext ctx, AdminAuth auth, AgentService agentsSvc, ProfileService profiles) =>
{
    var who = Admin(ctx);
    var tag = ctx.Request.Query["tag"].ToString().Trim();
    var agents = agentsSvc.All();
    if (tag.Length > 0)
        agents = agents.Where(a => a.Tags.Any(t => t.Contains(tag, StringComparison.OrdinalIgnoreCase))).ToList();
    return Results.Content(AdminPages.Agents(who, agents, profiles.All(), auth.IssueCsrf(who.Sub), tag), "text/html; charset=utf-8");
}).RequirePermission(Perm.AgentsRead);

guarded.MapGet("/agents/{id}", (HttpContext ctx, string id, AdminAuth auth, AgentService agentsSvc, ReconcileService reconcile) =>
{
    var who = Admin(ctx);
    var agent = agentsSvc.Get(id);
    return agent is null
        ? Results.Redirect("/admin/agents", false)
        : Results.Content(AdminPages.AgentDetail(who, agent, auth.IssueCsrf(who.Sub), reconcile.Preview(id)), "text/html; charset=utf-8");
}).RequirePermission(Perm.AgentsRead);

guarded.MapPost("/agents/create", async (HttpContext ctx, AdminAuth auth, AgentService agentsSvc, ProfileService profiles) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);

    var wantToken = form["mode"].ToString() == "token";
    var profileName = form["profile"].ToString().Trim();
    var hostname = form["hostname"].ToString().Trim();

    // From a profile: expand its templates against the hostname and snapshot onto
    // the agent. Otherwise free-form from the fields.
    if (profileName.Length > 0)
    {
        var profile = profiles.Get(profileName);
        if (profile is null) return Results.BadRequest();
        if (hostname.Length == 0) return Results.BadRequest();

        if (wantToken)
        {
            var t = await agentsSvc.CreateEnrollmentTokenFromProfile(profile, hostname, who.Actor, ctx.RequestAborted);
            return Results.Content(AdminPages.SecretShown(who, "Enrollment token",
                "Give this to the agent once — it is single-use and expires.", t,
                "Enrol with: kalitka-agent enroll --token <token>. It is not shown again."), "text/html; charset=utf-8");
        }
        var c = await agentsSvc.CreateFromProfile(profile, hostname, form["display_name"].ToString(), who.Actor, ctx.RequestAborted);
        return Results.Content(AdminPages.SecretShown(who, "Agent created",
            $"Agent id {c.Agent.Id} — its secret, shown once:", c.Secret,
            "Store it on the host as KALITKA_AGENT_SECRET (with the id as KALITKA_AGENT_ID). If lost, rotate."),
            "text/html; charset=utf-8");
    }

    var name = form["display_name"].ToString();
    var platform = form["platform"].ToString();
    var caps = Words(form["capabilities"].ToString());
    var resources = Words(form["allowed_resources"].ToString());
    var tags = Words(form["tags"].ToString());

    if (wantToken)
    {
        var token = await agentsSvc.CreateEnrollmentToken(name, platform, caps, resources, who.Actor, ctx.RequestAborted, tags);
        return Results.Content(AdminPages.SecretShown(who, "Enrollment token", "Give this to the agent once — it is single-use and expires.",
            token, "Enrol with: kalitka-agent enroll --token <token>. It is not shown again."), "text/html; charset=utf-8");
    }

    var created = await agentsSvc.Create(name, platform, caps, resources, who.Actor, ctx.RequestAborted, tags);
    return Results.Content(AdminPages.SecretShown(who, "Agent created",
        $"Agent id {created.Agent.Id} — its secret, shown once:", created.Secret,
        "Store it on the host as KALITKA_AGENT_SECRET (with the id as KALITKA_AGENT_ID). If lost, rotate."),
        "text/html; charset=utf-8");
}).RequirePermission(Perm.AgentsManage);

// ---- Agent profiles (templates) --------------------------------------------

guarded.MapGet("/profiles", (HttpContext ctx, AdminAuth auth, ProfileService profiles) =>
{
    var who = Admin(ctx);
    return Results.Content(AdminPages.Profiles(who, profiles.All(), auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.AgentsRead);

guarded.MapPost("/profiles/create", async (HttpContext ctx, AdminAuth auth, ProfileService profiles) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var name = form["name"].ToString().Trim();
    if (name.Length == 0) return Results.BadRequest();
    var profile = new AgentProfile(name, form["platform"].ToString().Trim(),
        Words(form["capabilities"].ToString()), Words(form["resource_templates"].ToString()), Words(form["tags"].ToString()));
    await profiles.Save(profile, who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/profiles", false);
}).RequirePermission(Perm.ProfilesManage);

guarded.MapPost("/profiles/delete", async (HttpContext ctx, AdminAuth auth, ProfileService profiles) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await profiles.Delete(form["name"].ToString().Trim(), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/profiles", false);
}).RequirePermission(Perm.ProfilesManage);

// ---- Reconcile: deliberate, audited apply of profile changes to agents -----

guarded.MapGet("/reconcile", (HttpContext ctx, AdminAuth auth, ReconcileService reconcile) =>
{
    var who = Admin(ctx);
    return Results.Content(AdminPages.Reconcile(who, reconcile.PreviewAll(), auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.AgentsRead);

guarded.MapPost("/reconcile/apply", async (HttpContext ctx, AdminAuth auth, ReconcileService reconcile) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var confirm = form["confirm"].ToString() == "1";
    await reconcile.Apply(form["agent"].ToString().Trim(), confirm, who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/reconcile", false);
}).RequirePermission(Perm.AgentsManage);

// Bulk apply — only the plans that grant nothing new. Expansions are never applied
// here; they need per-agent confirmation.
guarded.MapPost("/reconcile/apply-safe", async (HttpContext ctx, AdminAuth auth, ReconcileService reconcile) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    foreach (var p in reconcile.PreviewAll().Where(p => !p.IsExpansion))
        await reconcile.Apply(p.AgentId, confirmExpansion: false, who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/reconcile", false);
}).RequirePermission(Perm.AgentsManage);

guarded.MapPost("/agents/{id}/action", async (HttpContext ctx, string id, AdminAuth auth, AgentService agentsSvc) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);

    switch (form["verb"].ToString())
    {
        case "disable": await agentsSvc.Disable(id, who.Actor, ctx.RequestAborted); break;
        case "enable":  await agentsSvc.Enable(id, who.Actor, ctx.RequestAborted); break;
        case "revoke":  await agentsSvc.Revoke(id, who.Actor, ctx.RequestAborted); break;
        case "rotate":
            var secret = await agentsSvc.Rotate(id, who.Actor, ctx.RequestAborted);
            if (secret is null) break;
            return Results.Content(AdminPages.SecretShown(who, "Secret rotated",
                $"New secret for agent {id}, shown once:", secret,
                "The old secret no longer works. Update the host now."), "text/html; charset=utf-8");
    }
    return Results.Redirect("/admin/agents/" + id, false);
}).RequirePermission(Perm.AgentsManage);

// An empty response makes some browsers download the reply as a 0-byte file
// instead of showing anything. Always answer with something typed.
app.MapFallback((HttpContext ctx) =>
{
    var s = L10n.For(VisitorLang(ctx));
    return Results.Content(Pages.Message(VisitorLang(ctx), s.NotFoundTitle, s.NotFoundText),
        "text/html; charset=utf-8", statusCode: 404);
});

app.Run();
return;

/// <summary>The visitor's language, negotiated from the browser's Accept-Language
/// header (no cookie, no state). Falls back to English.</summary>
static Lang VisitorLang(HttpContext ctx) => L10n.Negotiate(ctx.Request.Headers.AcceptLanguage.ToString());

/// <summary>Constant-time equality for the plaintext shared secrets (Telegram
/// webhook, internal switch, legacy global agent), so a wrong value cannot be
/// recovered byte by byte from response timing. Registered-agent secrets and signed
/// tokens already use PBKDF2 / HMAC with fixed-time compares; these were the gaps.</summary>
static bool SecretEquals(string a, string b) =>
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

/// <summary>
/// The client address, honouring forwarded headers only when the request came
/// from a proxy we trust. See <see cref="ClientIp"/> for why the leftmost
/// X-Forwarded-For entry is the wrong one to read.
/// </summary>
static string ResolveIp(HttpContext ctx, GateService gate) =>
    ClientIp.Resolve(
        ctx.Connection.RemoteIpAddress?.ToString(),
        ctx.Request.Headers["X-Forwarded-For"].ToString(),
        ctx.Request.Headers["X-Real-Ip"].ToString(),
        gate.TrustedProxies).Ip;

/// <summary>
/// The host being asked for. X-Forwarded-Host is only believed when it came
/// from a trusted proxy; otherwise the Host header is all we have, and either
/// way the name still has to be one kalitka actually guards.
/// </summary>
static string ClientHost(HttpContext ctx, GateService gate)
{
    var trusted = ClientIp.Resolve(
        ctx.Connection.RemoteIpAddress?.ToString(),
        ctx.Request.Headers["X-Forwarded-For"].ToString(),
        ctx.Request.Headers["X-Real-Ip"].ToString(),
        gate.TrustedProxies).ForwardedHonoured;

    var forwarded = ctx.Request.Headers["X-Forwarded-Host"].ToString();
    if (trusted && !string.IsNullOrEmpty(forwarded))
        return forwarded.Split(',')[0].Trim();

    return ctx.Request.Host.Host;
}

/// <summary>
/// The verdict every HTTP frontend shares: may this request through, or must it
/// ring the gate? Unarmed hosts, the LAN bypass, the allow list and a valid
/// session all pass; everything else is a challenge. How a challenge is
/// expressed — a 302 for Traefik/Caddy/Envoy, a 401 for nginx auth_request — is
/// the frontend's business, not this method's. <paramref name="host"/> is the
/// guarded name, needed to build the gate URL.
/// </summary>
static bool IsAllowed(HttpContext ctx, GateService gate, ILogger log, out string host)
{
    host = ClientHost(ctx, gate);

    // Not armed for this host? Straight through — even though the middleware is
    // attached. This is what lets you roll the middleware out first and arm
    // hosts one at a time.
    if (!gate.IsEnforced(host)) return true;

    var ip = ResolveIp(ctx, gate);

    if (gate.IsBypassed(ip)) { Audit.Decision(log, "allowed", host, ip, reason: "bypass-network"); return true; }
    if (gate.IsAllowedIp(host, ip)) { Audit.Decision(log, "allowed", host, ip, reason: "allow-list"); return true; }
    if (gate.IsCookieValid(ctx.Request.Cookies[gate.CookieName], host)) return true;

    return false;
}

/// <summary>
/// Whether this request is a top-level navigation — the only kind that can act
/// on a 302 to the gate. The reverse proxy forwards the original request's
/// headers here, so the browser's Fetch Metadata tells us: only
/// <c>Sec-Fetch-Mode: navigate</c> is a document navigation; a WebSocket
/// handshake, an XHR/fetch or a sub-resource is anything else. Older clients
/// send no Fetch Metadata, so fall back to <c>Accept</c>: a document navigation
/// asks for text/html, a fetch or asset does not. (Note: <c>Upgrade</c> and
/// <c>Connection</c> are hop-by-hop and do not survive the proxy hop, so a
/// WebSocket cannot be recognised by those — Sec-Fetch/Accept is what remains.)
/// </summary>
static bool IsTopLevelNavigation(HttpRequest req)
{
    var mode = req.Headers["Sec-Fetch-Mode"].ToString();
    if (!string.IsNullOrEmpty(mode))
        return string.Equals(mode, "navigate", StringComparison.OrdinalIgnoreCase);

    return req.Headers["Accept"].ToString()
        .Contains("text/html", StringComparison.OrdinalIgnoreCase);
}

static void SetSessionCookie(HttpContext ctx, GateService gate, string value)
{
    var cookie = new CookieOptions
    {
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Expires = DateTimeOffset.UtcNow.AddMinutes(gate.SessionMinutes),
        Path = "/"
    };

    // Set on the parent domain so the browser carries it to every guarded host; the
    // scope inside the token, not the cookie's reach, is what limits access. Both a
    // manual approval and (since 0.16, SessionScope=Application by default) a Google
    // session are bound to the one host they were granted for; SessionScope=Domain is
    // the explicit opt-in for a session that spans every guarded host.
    if (!string.IsNullOrWhiteSpace(gate.CookieDomain)) cookie.Domain = gate.CookieDomain;

    ctx.Response.Cookies.Append(gate.CookieName, value, cookie);
}

// ---- OAuth state nonce cookie -----------------------------------------------
// A short-lived, browser-bound nonce set when a login starts and required to match
// the nonce inside the signed OAuth state at the callback (defeats login-CSRF). Lax,
// like the session cookies, so it survives the cross-site redirect back from Google.
static string NewStateNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

static void SetStateCookie(HttpContext ctx, string name, string path, string nonce) =>
    ctx.Response.Cookies.Append(name, nonce, new CookieOptions
    {
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Path = path,
        MaxAge = TimeSpan.FromMinutes(10),
    });

static void ClearStateCookie(HttpContext ctx, string name, string path) =>
    ctx.Response.Cookies.Delete(name, new CookieOptions { Secure = true, Path = path });

/// <summary>
/// The admin session cookie: scoped to /admin, no Expires (the absolute lifetime is
/// the signed token's own, not the browser's). SameSite=Lax, not Strict: the console
/// is entered through the Google OIDC callback, which is a cross-site redirect chain
/// (accounts.google.com → /admin/oauth2/callback → 302 /admin/dashboard). With Strict
/// the browser withholds the just-set cookie on that first navigation, the guard sees
/// nothing and bounces back to login — an endless login loop. Lax sends the cookie on
/// top-level GET navigations (this case) while still withholding it on cross-site
/// POSTs; state-changing POSTs are separately CSRF-protected, so this does not weaken
/// the control plane.
/// </summary>
static void SetAdminCookie(HttpContext ctx, string value)
{
    ctx.Response.Cookies.Append(AdminAuth.CookieName, value, new CookieOptions
    {
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Path = "/admin",
    });
}

// The admin identity the guard filter verified and stashed for the handler.
static AdminIdentity Admin(HttpContext ctx) => (AdminIdentity)ctx.Items["admin"]!;

// Split a free-text list (capabilities, resources) on spaces/commas.
static string[] Words(string s) =>
    s.Split(new[] { ' ', ',', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

static AuditEvent AdminEvent(string type, string actor, string email) =>
    new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, type, actor, email, "-", "-", "-", "web", "");

static IResult? InternalGuard(HttpContext ctx, GateService gate) =>
    string.IsNullOrEmpty(gate.InternalSecret)
    || !SecretEquals(ctx.Request.Headers["X-Kalitka-Internal"].ToString(), gate.InternalSecret)
        ? Results.StatusCode(403)
        : null;

// Authenticate an /agent/* caller into an AgentIdentity, or null (→ 403). A
// registered agent (X-Kalitka-Agent-Id + X-Kalitka-Agent-Secret) must be Active and
// its secret must verify; otherwise the legacy global secret (X-Kalitka-Agent) is
// accepted for migration. Authorization (capability + resource) is the identity's
// job, done at each endpoint — never a self-reported value.
static AgentIdentity? AuthenticateAgent(HttpContext ctx, GateService gate, IAgentStore agents)
{
    var id = ctx.Request.Headers["X-Kalitka-Agent-Id"].ToString();
    var secret = ctx.Request.Headers["X-Kalitka-Agent-Secret"].ToString();
    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(secret))
    {
        var agent = agents.GetById(id);
        if (agent is null || agent.Status != AgentStatus.Active) return null;   // unknown/disabled/revoked/pending
        if (!AgentSecrets.Verify(secret, agent.SecretHash)) return null;
        agents.TouchLastSeen(id, DateTimeOffset.UtcNow, ResolveIp(ctx, gate));
        return AgentIdentity.FromAgent(agent);
    }

    // Legacy global secret — deprecated, kept for one migration window.
    var legacy = ctx.Request.Headers["X-Kalitka-Agent"].ToString();
    if (!string.IsNullOrEmpty(gate.AgentSecret) && SecretEquals(legacy, gate.AgentSecret))
        return AgentIdentity.Legacy(gate.AgentResources);

    return null;
}

// Exposed so integration tests can host the real pipeline via WebApplicationFactory.
public partial class Program;
