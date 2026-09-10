using System.Text.Json;
using Kalitka;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<GateOptions>(builder.Configuration.GetSection("Kalitka"));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpClient<ITelegramClient, TelegramClient>();
builder.Services.AddHttpClient<GeoLookup>();
builder.Services.AddHttpClient<GoogleAuth>();
builder.Services.AddSingleton<AccessLists>();
builder.Services.AddSingleton<GateService>();

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
    Results.Content(Pages.Form(ctx.Request.Query["target"].ToString(), null, google.Enabled),
        "text/html; charset=utf-8"));

app.MapPost("/request", async (HttpContext ctx, GateService gate, GoogleAuth google) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var target = form["target"].ToString();
    var input = form["input"].ToString();

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
        "blocked" => Results.Content(Pages.Message("Refused", "Access denied."), "text/html; charset=utf-8"),
        "invalid" => Results.Content(Pages.Form(target, "Please enter something valid.", google.Enabled), "text/html; charset=utf-8"),
        _         => Results.Content(Pages.Waiting(id, target), "text/html; charset=utf-8")
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

    return Results.Redirect(google.AuthorizationUrl(gate.BuildState(target)), false);
});

app.MapGet("/oauth2/callback", async (HttpContext ctx, GateService gate, GoogleAuth google) =>
{
    var code = ctx.Request.Query["code"].ToString();
    var state = ctx.Request.Query["state"].ToString();

    if (string.IsNullOrEmpty(code) || !gate.TryReadState(state, out var target) || !gate.IsGuardedHost(target))
        return Results.Content(Pages.Message("Error", "Sign-in was not valid. Please try again."),
            "text/html; charset=utf-8");

    var email = await google.ResolveEmail(code, ctx.RequestAborted);
    if (email is null || !google.IsPermitted(email))
        return Results.Content(Pages.Message("Refused", "This Google account is not permitted."),
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
// Telegram webhook: secret path plus secret header
// ---------------------------------------------------------------------------
app.MapPost(options.WebhookPath, async (HttpContext ctx, GateService gate, ILogger<Program> log) =>
{
    if (ctx.Request.Headers["X-Telegram-Bot-Api-Secret-Token"].ToString() != options.WebhookSecret)
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

// An empty response makes some browsers download the reply as a 0-byte file
// instead of showing anything. Always answer with something typed.
app.MapFallback(() => Results.Content(Pages.Message("404", "Nothing here."),
    "text/html; charset=utf-8", statusCode: 404));

app.Run();
return;

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
    if (gate.IsAllowedIp(ip)) { Audit.Decision(log, "allowed", host, ip, reason: "allow-list"); return true; }
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

    // Set on the parent domain so the browser carries it to every guarded host.
    // A manual approval is still bound to one host inside the cookie; a Google
    // session is not — see the tracked issue on per-host isolation.
    if (!string.IsNullOrWhiteSpace(gate.CookieDomain)) cookie.Domain = gate.CookieDomain;

    ctx.Response.Cookies.Append(gate.CookieName, value, cookie);
}

static IResult? InternalGuard(HttpContext ctx, GateService gate) =>
    string.IsNullOrEmpty(gate.InternalSecret)
    || ctx.Request.Headers["X-Kalitka-Internal"].ToString() != gate.InternalSecret
        ? Results.StatusCode(403)
        : null;

// Exposed so integration tests can host the real pipeline via WebApplicationFactory.
public partial class Program;
