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
// The control-plane sign-in providers behind one seam (Google, Microsoft/Entra). AdminAuth
// dispatches through the registry; a new provider is one more registration here.
builder.Services.AddHttpClient<MicrosoftAuth>();
builder.Services.AddTransient<IIdentityProvider>(sp => sp.GetRequiredService<GoogleAuth>());
builder.Services.AddTransient<IIdentityProvider>(sp => sp.GetRequiredService<MicrosoftAuth>());
builder.Services.AddTransient<IdentityProviders>();
builder.Services.AddSingleton<AccessLists>();
builder.Services.AddSingleton<Metrics>();
builder.Services.AddSingleton<WebAuthnStore>(sp => new WebAuthnStore(sp.GetRequiredService<IConfigStore>()));
builder.Services.AddSingleton<WebAuthnService>();
// Web Push (the installable PWA channel): VAPID identity + subscriptions + a push INotifier that
// GateService picks up alongside Telegram and e-mail.
builder.Services.AddHttpClient("webpush");
builder.Services.AddSingleton<VapidKeyProvider>(sp => new VapidKeyProvider(sp.GetRequiredService<IConfigStore>()));
builder.Services.AddSingleton<PushSubscriptionStore>(sp => new PushSubscriptionStore(sp.GetRequiredService<IConfigStore>()));
builder.Services.AddSingleton<IWebPushSender, WebPushSender>();
builder.Services.AddSingleton<INotifier, PushNotifier>();
// Device enrolment: runtime-granted approve rights + the invite → IdP → device flow.
builder.Services.AddSingleton<OperatorApprovers>(sp => new OperatorApprovers(
    sp.GetRequiredService<IConfigStore>(), sp.GetRequiredService<IAuditStore>(), sp.GetRequiredService<TimeProvider>()));
builder.Services.AddTransient<EnrollService>();
// Visitor passkeys (fido2 slice 1): the cryptographic "remember this device", a separate population
// from operator passkeys and agents — a visitor credential only lets its holder in.
builder.Services.AddSingleton<VisitorPasskeyStore>(sp => new VisitorPasskeyStore(sp.GetRequiredService<IConfigStore>()));
builder.Services.AddSingleton<VisitorPasskeyService>();
// RADIUS channel (confirm before login, no browser). The verifier is chosen from config: the dev
// accept-any switch, else an LDAP bind, else fail-closed. The listener runs only when configured.
builder.Services.AddSingleton<ICredentialVerifier>(sp =>
{
    var o = sp.GetRequiredService<IOptions<GateOptions>>().Value;
    if (o.RadiusAcceptAnyCredentials) return new AcceptAnyCredentialVerifier();
    if (!string.IsNullOrEmpty(o.LdapUrl))
        return new LdapCredentialVerifier(sp.GetRequiredService<IOptions<GateOptions>>(),
            sp.GetRequiredService<ILogger<LdapCredentialVerifier>>());
    return new DenyAllCredentialVerifier();
});
builder.Services.AddSingleton<RadiusApproval>();
builder.Services.AddHostedService<RadiusServer>();
builder.Services.AddSingleton<GateService>();
builder.Services.AddSingleton<TokenSigner>(sp =>
{
    var o = sp.GetRequiredService<IOptions<GateOptions>>().Value;
    return new TokenSigner(o.HmacSecret, o.HmacSecretPrevious);
});
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
builder.Services.AddSingleton(sp => new AuditIntegrity(
    sp.GetRequiredService<IAuditStore>(), sp.GetRequiredService<TokenSigner>(), sp.GetRequiredService<TimeProvider>()));
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
builder.Services.AddSingleton<PolicyService>();
builder.Services.AddSingleton<PolicyCopilot>();
builder.Services.AddSingleton<PrincipalService>();

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
// PWA assets — public (no secrets): the manifest, the service worker (root scope,
// so it can receive push and control /app), and the icon. Self-contained, no wwwroot.
// ---------------------------------------------------------------------------
app.MapGet("/manifest.webmanifest", () => Results.Content(
    "{\"name\":\"kalitka\",\"short_name\":\"kalitka\",\"start_url\":\"/admin/app\",\"scope\":\"/\","
    + "\"display\":\"standalone\",\"background_color\":\"#0f1117\",\"theme_color\":\"#0f1117\","
    + "\"icons\":[{\"src\":\"/icon.png\",\"sizes\":\"any\",\"type\":\"image/png\",\"purpose\":\"any\"}]}",
    "application/manifest+json"));

app.MapGet("/sw.js", () =>
{
    const string sw = """
        self.addEventListener('push', function(e){
          var d = {}; try { d = e.data ? e.data.json() : {}; } catch (x) {}
          e.waitUntil(self.registration.showNotification(d.title || 'kalitka', {
            body: d.body || 'An access request is waiting.',
            data: { url: d.url || '/admin/app' }, icon: '/icon.png', badge: '/icon.png', tag: d.id, renotify: true
          }));
        });
        self.addEventListener('notificationclick', function(e){
          e.notification.close();
          e.waitUntil(clients.matchAll({type:'window'}).then(function(cs){
            for (var i=0;i<cs.length;i++){ if (cs[i].url.indexOf(e.notification.data.url) >= 0 && 'focus' in cs[i]) return cs[i].focus(); }
            return clients.openWindow(e.notification.data.url);
          }));
        });
        """;
    // Served at the root, so its scope is already "/" — no Service-Worker-Allowed header needed.
    return Results.Text(sw, "text/javascript", System.Text.Encoding.UTF8);
});

app.MapGet("/icon.png", () =>
{
    var b64 = Brand.IconDataUri["data:image/png;base64,".Length..];
    return Results.Bytes(Convert.FromBase64String(b64), "image/png");
});

// ---------------------------------------------------------------------------
// Device enrolment: a one-time invite that must end in an IdP sign-in as the
// invited account (so an intercepted invite cannot enrol a stranger). On success
// the person is granted approve rights and a session, then lands in the app.
// ---------------------------------------------------------------------------
app.MapGet("/enroll", (HttpContext ctx, EnrollService enroll) =>
{
    var t = ctx.Request.Query["t"].ToString();
    var idp = ctx.Request.Query["idp"].ToString();
    var choices = enroll.ProviderChoices;

    // Which provider to sign in with: an explicit ?idp, else the only one, else show a picker.
    if (string.IsNullOrEmpty(idp))
    {
        if (choices.Count == 1) idp = choices[0].Scheme;
        else if (choices.Count == 0)
            return Results.Content(AppPages.Notice("Enrolment", "No sign-in provider is configured."), "text/html; charset=utf-8");
        else
            return Results.Content(AppPages.EnrollPicker(t, choices), "text/html; charset=utf-8");
    }

    var nonce = NewStateNonce();
    var url = enroll.StartUrl(idp, t, nonce);
    if (url is null)
        return Results.Content(AppPages.Notice("Enrolment", "This enrolment link is invalid or has expired."), "text/html; charset=utf-8");
    SetStateCookie(ctx, "kalitka_enroll_state", "/enroll", nonce);
    return Results.Redirect(url, false);
});

app.MapGet("/enroll/callback", async (HttpContext ctx, EnrollService enroll) =>
{
    var nonce = ctx.Request.Cookies["kalitka_enroll_state"] ?? "";
    ClearStateCookie(ctx, "kalitka_enroll_state", "/enroll");
    var result = await enroll.Complete(
        ctx.Request.Query["code"].ToString(), ctx.Request.Query["state"].ToString(), nonce, ctx.RequestAborted);
    if (!result.Ok || result.Identity is null)
        return Results.Content(AppPages.Notice("Enrolment", result.Error ?? "Enrolment was not accepted."), "text/html; charset=utf-8");

    // A normal operator session: they are now an approver, so /admin/app and /admin/devices work.
    SetAdminCookie(ctx, ctx.RequestServices.GetRequiredService<AdminAuth>().IssueCookie(result.Identity));
    return Results.Redirect("/admin/app", false);
});

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
app.MapGet("/request", (HttpContext ctx, IdentityProviders providers) =>
    Results.Content(Pages.Form(VisitorLang(ctx), ctx.Request.Query["target"].ToString(), false, VisitorProviders(providers)),
        "text/html; charset=utf-8"));

app.MapPost("/request", async (HttpContext ctx, GateService gate, IdentityProviders providers) =>
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
        "invalid" => Results.Content(Pages.Form(lang, target, error: true, VisitorProviders(providers)), "text/html; charset=utf-8"),
        // Pass the visitor's name as the label so a remembered device (passkey) is recognisable later.
        _         => Results.Content(Pages.Waiting(lang, id, target, input), "text/html; charset=utf-8")
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
// Passkey as a way past the gate (fido2 slice 1). A visitor cannot self-register:
// registration requires the session a just-completed approval minted (so it is
// "remember this device", not an identity provider). Login proves a remembered
// credential and mints the same session a manual approval would.
// ---------------------------------------------------------------------------
app.MapPost("/passkey/login/begin", (HttpContext ctx, GateService gate, VisitorPasskeyService passkeys) =>
{
    var target = ctx.Request.Query["target"].ToString();
    if (!gate.IsGuardedHost(target)) return Results.BadRequest();
    return WebAuthnJson(passkeys.LoginBegin(target));
});

app.MapPost("/passkey/login/finish", async (HttpContext ctx, GateService gate, VisitorPasskeyService passkeys) =>
{
    var dto = await ctx.Request.ReadFromJsonAsync<PasskeyLoginDto>();
    if (dto is null || !gate.IsGuardedHost(dto.Target)) return Results.BadRequest();
    var res = await passkeys.LoginFinish(dto.Target, dto.State, dto.CredentialId, dto.AuthenticatorData,
        dto.ClientDataJson, dto.Signature, ctx.RequestAborted);
    if (!res.Ok) return Results.Json(new { error = res.Error }, statusCode: 400);
    // Mint the same session a manual approval would — per-host, or domain-wide if remembered so.
    SetSessionCookie(ctx, gate, res.DomainScope ? gate.BuildGlobalCookie() : gate.BuildCookie(dto.Target));
    return Results.Json(new { ok = true, target = dto.Target });
});

app.MapPost("/passkey/register/begin", (HttpContext ctx, GateService gate, VisitorPasskeyService passkeys) =>
{
    var target = ctx.Request.Query["target"].ToString();
    // Only a visitor already approved for this host (holds a valid session) may remember a device.
    if (!gate.IsGuardedHost(target) || !gate.IsCookieValid(ctx.Request.Cookies[gate.CookieName], target))
        return Results.StatusCode(403);
    return WebAuthnJson(passkeys.RegisterBegin(target, ctx.Request.Query["label"].ToString()));
});

app.MapPost("/passkey/register/finish", async (HttpContext ctx, GateService gate, VisitorPasskeyService passkeys) =>
{
    var dto = await ctx.Request.ReadFromJsonAsync<PasskeyRegisterDto>();
    if (dto is null) return Results.BadRequest();
    if (!gate.IsGuardedHost(dto.Target) || !gate.IsCookieValid(ctx.Request.Cookies[gate.CookieName], dto.Target))
        return Results.StatusCode(403);
    var error = await passkeys.RegisterFinish(dto.Target, dto.State, dto.AttestationObject, dto.ClientDataJson, ctx.RequestAborted);
    return error is null ? Results.Json(new { ok = true }) : Results.Json(new { error }, statusCode: 400);
});

// ---------------------------------------------------------------------------
// Google sign-in: the second way in, for people who should not have to wait
// ---------------------------------------------------------------------------
app.MapGet("/login/{scheme}", (HttpContext ctx, GateService gate, IdentityProviders providers, string scheme) =>
{
    var provider = providers.ByScheme(scheme);
    if (provider is null) return Results.NotFound();

    var target = ctx.Request.Query["target"].ToString();
    if (!gate.IsGuardedHost(target)) return Results.BadRequest();

    var nonce = NewStateNonce();
    SetStateCookie(ctx, "kalitka_oauth_state", "/", nonce);
    // The scheme rides in the signed state; the callback (one shared route) finishes with it.
    return Results.Redirect(provider.AuthorizationUrl(gate.BuildState(target, nonce, scheme),
        $"https://{gate.GateHost}/oauth2/callback"), false);
});

app.MapGet("/oauth2/callback", async (HttpContext ctx, GateService gate, IdentityProviders providers) =>
{
    var code = ctx.Request.Query["code"].ToString();
    var state = ctx.Request.Query["state"].ToString();
    var nonce = ctx.Request.Cookies["kalitka_oauth_state"] ?? "";
    ClearStateCookie(ctx, "kalitka_oauth_state", "/");

    var s = L10n.For(VisitorLang(ctx));
    if (string.IsNullOrEmpty(code) || !gate.TryReadState(state, nonce, out var target, out var scheme) || !gate.IsGuardedHost(target))
        return Results.Content(Pages.Message(VisitorLang(ctx), s.ErrorTitle, s.SigninInvalid),
            "text/html; charset=utf-8");

    var provider = providers.ByScheme(scheme);
    var identity = provider is null ? null : await provider.Resolve(code, $"https://{gate.GateHost}/oauth2/callback", ctx.RequestAborted);
    // The provider's own visitor allowlist is the fast-path gate (Google domains/addresses, Entra
    // tenant/domain). Identity keyed on scheme:subject, never the e-mail.
    if (identity is null || !provider!.IsPermitted(identity.Email))
        return Results.Content(Pages.Message(VisitorLang(ctx), s.RefusedTitle, s.GoogleNotPermitted),
            "text/html; charset=utf-8");

    Audit.Decision(app.Logger, "approved", target, ResolveIp(ctx, gate), identity: identity.Email, reason: scheme);

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

// Prometheus scrape target. Guarded like the other /internal endpoints (Traefik routes the whole
// host, so an unguarded /metrics would be public); the scraper sends X-Kalitka-Internal, or an
// Authorization: Bearer with the same secret so a stock Prometheus can use credentials_file.
app.MapGet("/metrics", (HttpContext ctx, GateService gate, Metrics metrics) =>
    MetricsGuard(ctx, gate) ?? Results.Text(metrics.Render(gate.PendingCount()), "text/plain; version=0.0.4"));

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
app.MapPost("/agent/v1/sessions/use", AgentSessionUse);
app.MapPost("/agent/v1/sessions/provisioned", AgentSessionProvisioned);
app.MapGet("/agent/v1/sessions/{id}", AgentSessionLiveness);
app.MapPost("/agent/v1/sessions/reconciled", AgentSessionReconciled);
app.MapPost("/agent/v1/enroll", AgentEnroll);
app.MapPost("/agent/enroll", AgentEnroll);
app.MapPost("/agent/v1/heartbeat", AgentHeartbeat);
app.MapPost("/agent/heartbeat", AgentHeartbeat);

static async Task<IResult> AgentRequest(HttpContext ctx, GateService gate, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    var host = form["host"].ToString().Trim();
    var user = form["user"].ToString().Trim();
    var ip = form["ip"].ToString().Trim();
    if (string.IsNullOrEmpty(ip)) ip = ResolveIp(ctx, gate);

    // The resource is either given directly (e.g. db:sql01/orders, any scheme) or, for
    // the SSH hooks, built from the host. Either way it is a label that lands in
    // audit/notify, so keep it to a sane charset.
    var resource = form["resource"].ToString().Trim();
    if (resource.Length == 0)
    {
        if (host.Length is 0 or > 100 || host.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '-' or '_')))
            return Results.BadRequest();
        resource = "ssh:" + host;
    }
    else if (resource.Length > 160 || !resource.Contains(':') ||
             resource.Any(c => !(char.IsLetterOrDigit(c) || c is ':' or '.' or '-' or '_' or '/')))
    {
        return Results.BadRequest();
    }

    // The authenticated agent may only raise resources it is scoped to (capability
    // + allowed resource) — a valid credential is not a licence for any resource.
    if (!identity.MayRepresent(resource, AgentCapabilities.Request)) return Results.StatusCode(403);

    // Optional command (0.26): the exact command the operator asks to run. When set, the
    // human approves this command and an SSH-cert signer forces it (force-command). Kept to
    // a sane length; its characters are opaque (it becomes a cert value, never local shell).
    var command = form["command"].ToString().Trim();
    if (command.Length > 4000) return Results.BadRequest();

    // Optional source-address (0.26.1): an approved CIDR list the SSH cert is pinned to.
    // Kept to IP/CIDR-list characters (it becomes a cert value, never local shell).
    var sourceAddr = form["source_address"].ToString().Trim();
    if (sourceAddr.Length > 400 || sourceAddr.Any(c => !(char.IsAsciiHexDigit(c) || c is '.' or ':' or '/' or ',' or ' ')))
        return Results.BadRequest();

    // Optional machine-readable subject identity (0.30): e.g. os:CONTOSO\anna, sid:S-1-5-…
    // — used to route the request to the person acting. Opaque (matched against operator
    // identities, never shell); kept to a sane length.
    var subjectIdentity = form["subject_identity"].ToString().Trim();
    if (subjectIdentity.Length > 200) return Results.BadRequest();

    // Defer semantics (the iOS-shield case): require the approval to be a device signature, not a
    // chat tap — out-of-band proof of intent, for a caller that has already gated locally.
    var requireSigned = form["require_signed"].ToString() == "1";

    var (state, id) = await gate.RaiseAction(resource, user, ip, identity.Actor, ctx.RequestAborted, identity.Tags,
        form["profile"].ToString().Trim(), int.TryParse(form["max_uses"].ToString(), out var mu) ? mu : 0, command, sourceAddr,
        // A subject is trusted to gate subject-approval only when THIS agent may assert it
        // (e.g. the Windows agent, from the OS security context) — never a requester-typed
        // string, which could otherwise self-approve someone else's action.
        subjectIdentity, identity.CanAssertSubject, requireSigned);
    // A policy can restrict access up front — forbid an open shell, require a source
    // binding, disallow the requested login, or require the trusted subject to approve.
    // All are refused (409) before anyone is asked to approve access policy disallows.
    if (state is "command-required" or "source-required" or "principal-not-allowed"
        or "subject-required" or "claimed-not-asserted" or "subject-unmapped"
        or "subject-unreachable" or "beneficiary-mismatch")
        return Results.Json(new { id, state }, statusCode: 409);
    return Results.Json(new { id, state });
}

static async Task<IResult> AgentPoll(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
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
static async Task<IResult> AgentRedeem(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    // "agent" is the self-reported hostname (metadata); identity is the canonical one.
    var result = await grants.Redeem(form["grant"].ToString(), identity, form["agent"].ToString(), ctx.RequestAborted);
    // `subject` is the Core-approved principal (the request's user); an SSH-cert signer
    // derives the certificate principal from this, never from an unvalidated caller
    // argument, so the approved identity and the cert principal stay cryptographically bound.
    if (result.Ok) return Results.Json(new { session_id = result.SessionId, profile = result.Profile,
        expires_at = result.ExpiresAt?.ToUnixTimeSeconds(), subject = result.Subject, command = result.Command,
        source_address = result.SourceAddress });
    return Results.Json(new { error = result.Error }, statusCode: result.Error == "used" ? 409 : 403);
}

// The connector reports one use of a granted operation (bounded-grant max_uses). When
// the budget hits zero the session is closed ("spent") and the connector revokes.
static async Task<IResult> AgentSessionUse(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    var remaining = await grants.ReportUse(form["session_id"].ToString(), identity.Actor, ctx.RequestAborted);
    if (remaining is null) return Results.Json(new { error = "not-open" }, statusCode: 409);
    return Results.Json(new { remaining_uses = remaining, spent = remaining == 0 });
}

// The connector reports the provisioning outcome: applied, or failed (which closes the
// session, since access was never really granted).
static async Task<IResult> AgentSessionProvisioned(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    var ok = await grants.ReportProvisioned(form["session_id"].ToString(), form["error"].ToString(), identity.Actor, ctx.RequestAborted);
    return Results.Json(new { provisioned = ok });
}

// Session liveness for a connector's crash-recovery pass: {state, expires_at}. The
// connector journals expires_at so it can revoke on a locally-known expiry even while
// Core is unreachable — a Core outage must never extend access past a time already known.
static async Task<IResult> AgentSessionLiveness(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
    if (identity is null) return Results.StatusCode(403);

    var id = ctx.Request.RouteValues.TryGetValue("id", out var rv) && rv is string s && s.Length > 0 ? s : "";
    var rec = grants.Session(id);
    if (rec is null) return Results.Json(new { state = "unknown", expires_at = (long?)null });
    // A valid credential is not a licence to probe a session outside the agent's scope.
    if (!identity.MayRepresent(rec.Resource, AgentCapabilities.SessionEnd)) return Results.StatusCode(403);
    var (state, exp) = grants.Liveness(id);
    return Results.Json(new { state, expires_at = exp?.ToUnixTimeSeconds() });
}

// A connector reports a crash-recovery decision: it revoked provisioned access out of
// band. Always audited (session.reconciled) with the reason — so a cleanup made WITHOUT
// Core confirmation (orphan-max-age) is visible — and closes the session if still open.
static async Task<IResult> AgentSessionReconciled(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
    if (identity is null) return Results.StatusCode(403);

    var form = await ctx.Request.ReadFormAsync();
    var id = form["session_id"].ToString();
    var reason = form["reason"].ToString();
    if (reason is not ("core-confirmed" or "local-expiry" or "orphan-max-age")) return Results.BadRequest();
    // If Core still knows the session, the agent must be scoped to its resource. If Core
    // has forgotten it (orphan cleanup of a session Core already closed), there is no
    // resource to bind to — record the decision anyway; the principal name carries the
    // provenance that justified it.
    var rec = grants.Session(id);
    if (rec is not null && !identity.MayRepresent(rec.Resource, AgentCapabilities.SessionEnd)) return Results.StatusCode(403);
    await grants.ReconcileSession(id, reason, form["principal"].ToString(), identity.Actor, ctx.RequestAborted);
    return Results.Ok();
}

// The agent reports the session ended (session.ended).
static async Task<IResult> AgentSessionEnd(HttpContext ctx, GateService gate, GrantService grants, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    var identity = await AuthenticateAgent(ctx, gate, agents, replay);
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
        form["hostname"].ToString(), form["metadata"].ToString(), ctx.RequestAborted,
        form["public_key"].ToString(), form["provider_hint"].ToString());
    return result.Ok
        ? Results.Json(new { agent_id = result.AgentId })
        : Results.Json(new { error = result.Error }, statusCode: result.Error == "used" ? 409 : 400);
}

// A liveness ping. last_seen is also updated on any authenticated agent call.
static async Task<IResult> AgentHeartbeat(HttpContext ctx, GateService gate, IAgentStore agents, IReplayStore replay)
{
    MarkAgentVersion(ctx);
    return await AuthenticateAgent(ctx, gate, agents, replay) is null ? Results.StatusCode(403) : Results.Ok();
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
        // Quorum: recorded but not enough approvers yet. The engine's text carries the count.
        CallbackOutcome.Pending        => result.Text ?? s.ActionAlreadyDecided,
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
    return Results.Content(AdminPages.Login(auth.Enabled ? auth.Providers : Array.Empty<(string, string)>(),
        string.IsNullOrEmpty(error) ? null : error), "text/html; charset=utf-8");
});

adminGroup.MapGet("/login/{scheme}", (HttpContext ctx, AdminAuth auth, string scheme) =>
{
    if (!auth.Enabled) return Results.NotFound();
    var nonce = NewStateNonce();
    SetStateCookie(ctx, "kalitka_admin_state", "/admin", nonce);
    return Results.Redirect(auth.LoginUrl(scheme, ctx.Request.Query["return"].ToString(), nonce), false);
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

// ---- WebAuthn: registered devices (fido2 slice 1) -----------------------
// Self-service — any authenticated admin manages their own devices.
guarded.MapGet("/devices", (HttpContext ctx, AdminAuth auth, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    var all = who.Can(Perm.PrincipalsManage) ? webauthn.AllDevices() : null;
    return Results.Content(AdminPages.Devices(who, webauthn.DevicesFor(who), auth.IssueCsrf(who.Sub), all), "text/html; charset=utf-8");
});

guarded.MapPost("/devices/remove-any", async (HttpContext ctx, AdminAuth auth, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await webauthn.AdminRemove(form["credentialId"].ToString(), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/devices", false);
}).RequirePermission(Perm.PrincipalsManage);

// ---- Device enrolment (admin issues invites; runtime approvers) ---------
guarded.MapGet("/enroll", (HttpContext ctx, AdminAuth auth, OperatorApprovers approvers) =>
    Results.Content(AdminPages.EnrollPage(Admin(ctx), approvers.All(), auth.IssueCsrf(Admin(ctx).Sub)), "text/html; charset=utf-8"))
    .RequirePermission(Perm.PrincipalsManage);

guarded.MapPost("/enroll/invite", async (HttpContext ctx, AdminAuth auth, EnrollService enroll, OperatorApprovers approvers) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var email = form["email"].ToString();
    if (string.IsNullOrWhiteSpace(email)) return Results.Redirect("/admin/enroll", false);
    var link = await enroll.Invite(email, form["displayName"].ToString(), who.Actor, ctx.RequestAborted);
    return Results.Content(AdminPages.EnrollPage(who, approvers.All(), auth.IssueCsrf(who.Sub), link), "text/html; charset=utf-8");
}).RequirePermission(Perm.PrincipalsManage);

guarded.MapPost("/approvers/revoke", async (HttpContext ctx, AdminAuth auth, OperatorApprovers approvers) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await approvers.Revoke(form["email"].ToString(), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/enroll", false);
}).RequirePermission(Perm.PrincipalsManage);

// ---- Remembered visitor devices (passkeys) — the cryptographic allow list ----
guarded.MapGet("/passkeys", (HttpContext ctx, AdminAuth auth, VisitorPasskeyStore store) =>
    Results.Content(AdminPages.VisitorPasskeys(Admin(ctx), store.All(), auth.IssueCsrf(Admin(ctx).Sub)), "text/html; charset=utf-8"))
    .RequirePermission(Perm.RequestsDecide);

guarded.MapPost("/passkeys/revoke", async (HttpContext ctx, AdminAuth auth, VisitorPasskeyStore store, IAuditStore audit) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var credId = form["credentialId"].ToString();
    if (store.Revoke(credId))
        await audit.Append(new AuditEvent(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, AuditEvents.PasskeyRevoked,
            who.Actor, form["label"].ToString(), "", "", "", "admin", credId), ctx.RequestAborted);
    return Results.Redirect("/admin/passkeys", false);
}).RequirePermission(Perm.RequestsDecide);

guarded.MapPost("/devices/register/begin", (HttpContext ctx, AdminAuth auth, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    if (!auth.ValidateCsrf(ctx.Request.Headers["X-Csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var begin = webauthn.RegisterBegin(who);
    return WebAuthnJson(begin);
});

guarded.MapPost("/devices/register/finish", async (HttpContext ctx, AdminAuth auth, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    var dto = await ctx.Request.ReadFromJsonAsync<RegisterFinishDto>();
    if (dto is null || !auth.ValidateCsrf(dto.Csrf, who.Sub)) return Results.StatusCode(403);
    var error = await webauthn.RegisterFinish(who, dto.State, dto.CredentialId, dto.AttestationObject,
        dto.ClientDataJson, dto.DisplayName, ctx.RequestAborted);
    return error is null ? Results.Json(new { ok = true }) : Results.Json(new { error }, statusCode: 400);
});

guarded.MapPost("/devices/remove", async (HttpContext ctx, AdminAuth auth, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await webauthn.RemoveDevice(who, form["credentialId"].ToString(), ctx.RequestAborted);
    return Results.Redirect("/admin/devices", false);
});

// ---- WebAuthn: device-signed decision (fido2 slice 2) -------------------
guarded.MapPost("/requests/{id}/approve/begin", (HttpContext ctx, string id, AdminAuth auth, GateService gate, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    if (!auth.ValidateCsrf(ctx.Request.Headers["X-Csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var verb = ctx.Request.Query["verb"].ToString();
    var actx = gate.ApprovalContextOf(id);
    if (actx is null) return Results.Json(new { error = "request not found or already decided" }, statusCode: 404);
    return WebAuthnJson(webauthn.ApproveBegin(who, actx, verb));
}).RequirePermission(Perm.RequestsDecide);

guarded.MapPost("/requests/decide-signed", async (HttpContext ctx, AdminAuth auth, GateService gate, WebAuthnService webauthn) =>
{
    var who = Admin(ctx);
    var dto = await ctx.Request.ReadFromJsonAsync<DecideSignedDto>();
    if (dto is null || !auth.ValidateCsrf(dto.Csrf, who.Sub)) return Results.StatusCode(403);
    var actx = gate.ApprovalContextOf(dto.Id);
    if (actx is null) return Results.Json(new { error = "request not found or already decided" }, statusCode: 404);
    var result = await webauthn.ApproveVerify(who, actx, dto.Verb,
        new SignedDecisionInput(dto.State, dto.CredentialId, dto.AuthenticatorData, dto.ClientDataJson, dto.Signature),
        ctx.RequestAborted);
    if (!result.Ok) return Results.Json(new { error = result.Error }, statusCode: 400);
    await gate.Decide(dto.Id, dto.Verb, result.Actor, result.Proof);
    return Results.Json(new { ok = true });
}).RequirePermission(Perm.RequestsDecide);

// ---- The installable PWA (Web Push channel) ----------------------------
guarded.MapGet("/app", (HttpContext ctx, AdminAuth auth, GateService gate, VapidKeyProvider vapid) =>
{
    var who = Admin(ctx);
    return Results.Content(AppPages.Shell(who, gate.PendingSnapshot(), vapid.PublicKey, auth.IssueCsrf(who.Sub)),
        "text/html; charset=utf-8");
});

guarded.MapPost("/app/subscribe", async (HttpContext ctx, AdminAuth auth, PrincipalService principals, PushSubscriptionStore subs) =>
{
    var who = Admin(ctx);
    var dto = await ctx.Request.ReadFromJsonAsync<PushSubscribeDto>();
    if (dto is null || !auth.ValidateCsrf(dto.Csrf, who.Sub)) return Results.StatusCode(403);
    if (string.IsNullOrWhiteSpace(dto.Endpoint) || string.IsNullOrWhiteSpace(dto.P256dh) || string.IsNullOrWhiteSpace(dto.Auth))
        return Results.Json(new { error = "incomplete subscription" }, statusCode: 400);
    // Bind the device to the operator (create the principal if this is their first). Push then
    // reaches the person, not a global list — the same resolution as every other channel.
    var pid = principals.Resolve(who.Actor);
    if (pid is null) { pid = "op-" + who.Sub; await principals.Save(pid, who.Email, new[] { who.Actor }, who.Actor, ctx.RequestAborted); }
    subs.Add(new PushSubscription(dto.Endpoint, dto.P256dh, dto.Auth, pid, DateTimeOffset.UtcNow.ToString("O")));
    return Results.Json(new { ok = true });
});

guarded.MapPost("/app/unsubscribe", async (HttpContext ctx, AdminAuth auth, PushSubscriptionStore subs) =>
{
    var who = Admin(ctx);
    var dto = await ctx.Request.ReadFromJsonAsync<PushSubscribeDto>();
    if (dto is null || !auth.ValidateCsrf(dto.Csrf, who.Sub)) return Results.StatusCode(403);
    subs.RemoveByEndpoint(dto.Endpoint);
    return Results.Json(new { ok = true });
});

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

// Audit integrity: verify the hash chain and (if intact) sign the head — the exportable proof
// that the log has not been altered, reordered or truncated.
guarded.MapGet("/audit/verify", async (HttpContext ctx, AuditIntegrity integrity) =>
{
    var verification = await integrity.Verify(ctx.RequestAborted);
    var checkpoint = await integrity.SignHead(ctx.RequestAborted);
    return Results.Content(AdminPages.AuditIntegrity(Admin(ctx), verification, checkpoint), "text/html; charset=utf-8");
}).RequirePermission(Perm.HistoryRead);

// ---- Sessions (live view of used grants) -----------------------------------

guarded.MapGet("/sessions", async (HttpContext ctx, AdminAuth auth, GrantService grants, IOptions<GateOptions> opt) =>
{
    var who = Admin(ctx);
    // Auto-close anything left open past its max lifetime before listing.
    await grants.ExpireStaleSessions(TimeSpan.FromHours(opt.Value.SessionMaxHours), ctx.RequestAborted);
    return Results.Content(AdminPages.Sessions(who, grants.Sessions(), auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.RequestsRead);

guarded.MapPost("/sessions/revoke", async (HttpContext ctx, AdminAuth auth, GrantService grants) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await grants.RevokeSession(form["id"].ToString(), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/sessions", false);
}).RequirePermission(Perm.RequestsDecide);

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

// ---- Access policies (tag-driven, restrict-only) ---------------------------

guarded.MapGet("/policies", (HttpContext ctx, AdminAuth auth, PolicyService policies) =>
{
    var who = Admin(ctx);
    return Results.Content(AdminPages.Policies(who, policies.All(), auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.PoliciesRead);

// Read-only policy explain: a deterministic trace of the effective decision for a concrete
// request context (resource + agent tags + optional profile). No AI — the same composition
// the request engine uses, so a trace can never disagree with what would actually happen.
guarded.MapGet("/policies/explain", (HttpContext ctx, PolicyService policies) =>
{
    var who = Admin(ctx);
    var resource = ctx.Request.Query["resource"].ToString().Trim();
    var tags = ctx.Request.Query["tags"].ToString().Trim();
    var profile = ctx.Request.Query["profile"].ToString().Trim();
    PolicyExplanation? ex = resource.Length == 0 ? null : policies.Explain(resource, Words(tags), profile);
    return Results.Content(AdminPages.Explain(who, resource, tags, profile, ex), "text/html; charset=utf-8");
}).RequirePermission(Perm.PoliciesRead);

// Policy copilot: draft a change, preview its deterministic impact across the fleet (simulate),
// and apply it — with an explicit confirmation whenever it expands effective authority. The
// natural-language drafter plugs in on top of this; the authority stays deterministic here.
guarded.MapGet("/policies/copilot", (HttpContext ctx, AdminAuth auth, PolicyCopilot copilot) =>
{
    var who = Admin(ctx);
    var q = ctx.Request.Query;
    var draft = new AdminPages.CopilotDraft(
        Mode: q["mode"].ToString() == "remove" ? "remove" : "upsert",
        Name: q["name"].ToString().Trim(),
        Resource: q["match_resource"].ToString().Trim(),
        Tags: q["match_tags"].ToString().Trim(),
        Required: q["required"].ToString().Trim(),
        Ttl: q["grant_ttl"].ToString().Trim(),
        Subject: q["subject"].ToString().Trim());
    var change = CopilotChange(draft);
    var preview = change is null ? null : copilot.Preview(change);
    return Results.Content(AdminPages.Copilot(who, draft, preview, auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.PoliciesManage);

guarded.MapPost("/policies/copilot/apply", async (HttpContext ctx, AdminAuth auth, PolicyCopilot copilot) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var draft = new AdminPages.CopilotDraft(
        Mode: form["mode"].ToString() == "remove" ? "remove" : "upsert",
        Name: form["name"].ToString().Trim(),
        Resource: form["match_resource"].ToString().Trim(),
        Tags: form["match_tags"].ToString().Trim(),
        Required: form["required"].ToString().Trim(),
        Ttl: form["grant_ttl"].ToString().Trim(),
        Subject: form["subject"].ToString().Trim());
    var change = CopilotChange(draft);
    if (change is null) return Results.BadRequest();
    var confirm = form["confirm_expansion"].ToString() is "on" or "true" or "1";
    var result = await copilot.Apply(change, confirm, who.Actor, ctx.RequestAborted);
    // If it needed confirmation and none was given, send the operator back to the preview.
    if (result.NeedsConfirmation)
        return Results.Redirect("/admin/policies/copilot?" + CopilotQuery(draft), false);
    return Results.Redirect("/admin/policies", false);
}).RequirePermission(Perm.PoliciesManage);

guarded.MapPost("/policies/create", async (HttpContext ctx, AdminAuth auth, PolicyService policies) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    var name = form["name"].ToString().Trim();
    var resource = form["match_resource"].ToString().Trim();
    if (name.Length == 0 || resource.Length == 0) return Results.BadRequest();
    int.TryParse(form["required"].ToString(), out var required);
    int.TryParse(form["grant_ttl"].ToString(), out var ttl);
    var policy = new AccessPolicy(name, resource, Words(form["match_tags"].ToString()),
        Math.Max(1, required), Math.Max(0, ttl))
    {
        MatchProfile = form["match_profile"].ToString().Trim(),
        RequireCommand = form["require_command"].ToString() is "on" or "true" or "1",
        RequireSourceAddress = form["require_source"].ToString() is "on" or "true" or "1",
        AllowedPrincipals = Words(form["allowed_principals"].ToString()),
        Subject = form["subject"].ToString().Trim().ToLowerInvariant() switch
        {
            "required" => SubjectApproval.Required,
            "forbidden" => SubjectApproval.Forbidden,
            _ => SubjectApproval.Optional,
        },
    };
    await policies.Save(policy, who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/policies", false);
}).RequirePermission(Perm.PoliciesManage);

guarded.MapPost("/policies/delete", async (HttpContext ctx, AdminAuth auth, PolicyService policies) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await policies.Delete(form["name"].ToString().Trim(), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/policies", false);
}).RequirePermission(Perm.PoliciesManage);

// ---- Operator principals: who counts as a distinct approver in a quorum ----

guarded.MapGet("/principals", (HttpContext ctx, AdminAuth auth, PrincipalService principals) =>
{
    var who = Admin(ctx);
    return Results.Content(AdminPages.Principals(who, principals.All(), auth.IssueCsrf(who.Sub)), "text/html; charset=utf-8");
}).RequirePermission(Perm.PrincipalsRead);

guarded.MapPost("/principals/create", async (HttpContext ctx, AdminAuth auth, PrincipalService principals) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    if (form["id"].ToString().Trim().Length == 0) return Results.BadRequest();
    await principals.Save(form["id"].ToString(), form["display"].ToString(),
        Words(form["identities"].ToString()), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/principals", false);
}).RequirePermission(Perm.PrincipalsManage);

guarded.MapPost("/principals/delete", async (HttpContext ctx, AdminAuth auth, PrincipalService principals) =>
{
    var who = Admin(ctx);
    var form = await ctx.Request.ReadFormAsync();
    if (!auth.ValidateCsrf(form["csrf"].ToString(), who.Sub)) return Results.StatusCode(403);
    await principals.Delete(form["id"].ToString().Trim(), who.Actor, ctx.RequestAborted);
    return Results.Redirect("/admin/principals", false);
}).RequirePermission(Perm.PrincipalsManage);

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
        case "addkey": await agentsSvc.AddKey(id, form["public_key"].ToString().Trim(), who.Actor, ctx.RequestAborted, form["provider_hint"].ToString().Trim()); break;
        case "removekey": await agentsSvc.RemoveKey(id, form["key_id"].ToString().Trim(), who.Actor, ctx.RequestAborted); break;
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

// Build a PolicyChange from the copilot's draft fields, or null when there is nothing to preview.
static PolicyChange? CopilotChange(AdminPages.CopilotDraft d)
{
    if (d.Name.Length == 0) return null;
    if (d.Mode == "remove") return new PolicyChange.Remove(d.Name);
    if (d.Resource.Length == 0) return null;
    int.TryParse(d.Required, out var required);
    int.TryParse(d.Ttl, out var ttl);
    var subject = d.Subject.ToLowerInvariant() switch
    {
        "required" => SubjectApproval.Required,
        "forbidden" => SubjectApproval.Forbidden,
        _ => SubjectApproval.Optional,
    };
    return new PolicyChange.Upsert(
        new AccessPolicy(d.Name, d.Resource, Words(d.Tags), Math.Max(1, required), Math.Max(0, ttl)) { Subject = subject });
}

static string CopilotQuery(AdminPages.CopilotDraft d) =>
    $"mode={Uri.EscapeDataString(d.Mode)}&name={Uri.EscapeDataString(d.Name)}" +
    $"&match_resource={Uri.EscapeDataString(d.Resource)}&match_tags={Uri.EscapeDataString(d.Tags)}" +
    $"&required={Uri.EscapeDataString(d.Required)}&grant_ttl={Uri.EscapeDataString(d.Ttl)}&subject={Uri.EscapeDataString(d.Subject)}";

static AuditEvent AdminEvent(string type, string actor, string email) =>
    new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, type, actor, email, "-", "-", "-", "web", "");

static IResult? InternalGuard(HttpContext ctx, GateService gate) =>
    string.IsNullOrEmpty(gate.InternalSecret)
    || !SecretEquals(ctx.Request.Headers["X-Kalitka-Internal"].ToString(), gate.InternalSecret)
        ? Results.StatusCode(403)
        : null;

// The enabled sign-in providers as (scheme, name) for the visitor form's buttons.
static IReadOnlyList<(string Scheme, string Name)> VisitorProviders(IdentityProviders providers) =>
    providers.Enabled.Select(p => (p.Scheme, p.DisplayName)).ToList();

// A WebAuthn "begin" response: the ceremony options (already JSON) plus the stateless state token.
// The options are embedded raw so they are not double-encoded as a string.
static IResult WebAuthnJson(WebAuthnBegin b) =>
    Results.Content("{\"options\":" + b.OptionsJson + ",\"state\":" + System.Text.Json.JsonSerializer.Serialize(b.State) + "}",
        "application/json");

// Like InternalGuard, but also accepts the secret as "Authorization: Bearer <secret>" so a stock
// Prometheus can scrape with authorization.credentials_file — no secret in the scrape config.
static IResult? MetricsGuard(HttpContext ctx, GateService gate)
{
    if (string.IsNullOrEmpty(gate.InternalSecret)) return Results.StatusCode(403);
    if (SecretEquals(ctx.Request.Headers["X-Kalitka-Internal"].ToString(), gate.InternalSecret)) return null;
    var auth = ctx.Request.Headers.Authorization.ToString();
    const string bearer = "Bearer ";
    if (auth.StartsWith(bearer, StringComparison.Ordinal) && SecretEquals(auth[bearer.Length..], gate.InternalSecret))
        return null;
    return Results.StatusCode(403);
}

// Authenticate an /agent/* caller into an AgentIdentity, or null (→ 403). Three paths,
// most-preferred first: an Ed25519-signed request (no reusable secret in flight), the
// registry shared secret (migration window), then the legacy global secret. In every
// case the caller must be an Active registered agent (or the legacy global caller).
// Authorization (capability + resource) is the identity's job, done at each endpoint.
static async Task<AgentIdentity?> AuthenticateAgent(HttpContext ctx, GateService gate, IAgentStore agents, IReplayStore replay)
{
    var id = ctx.Request.Headers["X-Kalitka-Agent-Id"].ToString();

    // Preferred: a signed request. The agent proves possession of a private key whose
    // public half is registered; nothing reusable is sent.
    var sig = ctx.Request.Headers["X-Kalitka-Signature"].ToString();
    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(sig))
        return await AuthenticateSigned(ctx, gate, agents, replay, id, sig);

    var secret = ctx.Request.Headers["X-Kalitka-Agent-Secret"].ToString();
    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(secret))
    {
        var agent = agents.GetById(id);
        if (agent is null || agent.Status != AgentStatus.Active) return null;   // unknown/disabled/revoked/pending
        if (!AgentSecrets.Verify(secret, agent.SecretHash)) return null;
        agents.RecordAuth(id, DateTimeOffset.UtcNow, ResolveIp(ctx, gate), "secret", "");
        return AgentIdentity.FromAgent(agent);
    }

    // Legacy global secret — deprecated, kept for one migration window.
    var legacy = ctx.Request.Headers["X-Kalitka-Agent"].ToString();
    if (!string.IsNullOrEmpty(gate.AgentSecret) && SecretEquals(legacy, gate.AgentSecret))
        return AgentIdentity.Legacy(gate.AgentResources);

    return null;
}

// Verify an Ed25519-signed request against the agent's registered keys, with a
// timestamp window and a single-use nonce so it cannot be replayed.
static async Task<AgentIdentity?> AuthenticateSigned(HttpContext ctx, GateService gate, IAgentStore agents,
    IReplayStore replay, string id, string sig)
{
    var agent = agents.GetById(id);
    if (agent is null || agent.Status != AgentStatus.Active || agent.Keys.Count == 0) return null;

    var tsRaw = ctx.Request.Headers["X-Kalitka-Timestamp"].ToString();
    var nonce = ctx.Request.Headers["X-Kalitka-Nonce"].ToString();
    var keyId = ctx.Request.Headers["X-Kalitka-Key-Id"].ToString();
    if (!long.TryParse(tsRaw, out var ts) || string.IsNullOrEmpty(nonce)) return null;
    if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts) > AgentSignatures.MaxSkewSeconds) return null;

    var bodyHash = await BodyHash(ctx.Request);
    var message = AgentSignatures.CanonicalString(
        ctx.Request.Method, ctx.Request.Path + ctx.Request.QueryString, bodyHash, tsRaw, nonce);

    // The named key if given, otherwise any of the agent's keys.
    var matched = agent.Keys.Where(k => keyId.Length == 0 || k.KeyId == keyId)
        .FirstOrDefault(k => AgentSignatures.Verify(k.PublicKey, message, sig));
    if (matched is null) return null;

    // Valid signature — burn the nonce (only now, so a bad signature cannot exhaust
    // the nonce space) so this exact request cannot be replayed inside the window.
    var expiry = DateTimeOffset.FromUnixTimeSeconds(ts).AddSeconds(AgentSignatures.MaxSkewSeconds);
    if (!await replay.TryConsumeAsync($"agentsig:{id}:{nonce}", expiry, ctx.RequestAborted)) return null;

    agents.RecordAuth(id, DateTimeOffset.UtcNow, ResolveIp(ctx, gate), "signature", matched.KeyId);
    return AgentIdentity.FromAgent(agent);
}

// The sha256 of the request body, leaving the body re-readable for form parsing.
static async Task<string> BodyHash(HttpRequest req)
{
    req.EnableBuffering();
    req.Body.Position = 0;
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    req.Body.Position = 0;
    return AgentSignatures.Sha256Hex(ms.ToArray());
}

// WebAuthn ceremony payloads posted by the admin JS (case-insensitive JSON: camelCase on the wire).
internal sealed record RegisterFinishDto(string State, string CredentialId, string AttestationObject,
    string ClientDataJson, string DisplayName, string Csrf);
internal sealed record DecideSignedDto(string Id, string Verb, string State, string CredentialId,
    string AuthenticatorData, string ClientDataJson, string Signature, string Csrf);
internal sealed record PushSubscribeDto(string Endpoint, string P256dh, string Auth, string Csrf);
internal sealed record PasskeyLoginDto(string Target, string State, string CredentialId,
    string AuthenticatorData, string ClientDataJson, string Signature);
internal sealed record PasskeyRegisterDto(string Target, string State, string CredentialId,
    string AttestationObject, string ClientDataJson);

// Exposed so integration tests can host the real pipeline via WebApplicationFactory.
public partial class Program;
