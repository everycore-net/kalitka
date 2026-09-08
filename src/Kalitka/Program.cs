using System.Text.Json;
using Kalitka;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<GateOptions>(builder.Configuration.GetSection("Kalitka"));
builder.Services.AddHttpClient<TelegramClient>();
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

app.MapGet("/health", () => Results.Text("ok"));

// ---------------------------------------------------------------------------
// The forwardAuth endpoint. Your reverse proxy asks this before every request
// to a guarded host: 200 means let it through, 302 sends the visitor here.
// ---------------------------------------------------------------------------
app.MapMethods("/auth", new[] { "GET", "HEAD" }, (HttpContext ctx, GateService gate) =>
{
    var host = ctx.Request.Headers["X-Forwarded-Host"].ToString();
    if (string.IsNullOrEmpty(host)) host = ctx.Request.Host.Host;

    // Not armed for this host? Straight through — even though the middleware is
    // attached. This is what lets you roll the middleware out first and arm
    // hosts one at a time.
    if (!gate.IsEnforced(host)) return Results.Ok();

    var ip = FirstIp(ctx.Request.Headers["X-Forwarded-For"].ToString());
    if (string.IsNullOrEmpty(ip)) ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "";

    if (gate.IsBypassed(ip) || gate.IsAllowedIp(ip)) return Results.Ok();
    if (gate.IsCookieValid(ctx.Request.Cookies[gate.CookieName], host)) return Results.Ok();

    return Results.Redirect(
        $"https://{gate.GateHost}/request?target={Uri.EscapeDataString(host)}", false);
});

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

    var ip = FirstIp(ctx.Request.Headers["X-Forwarded-For"].ToString());
    if (string.IsNullOrEmpty(ip)) ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "";

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
    if (!gate.IsOurHost(target)) return Results.BadRequest();

    return Results.Redirect(google.AuthorizationUrl(gate.BuildState(target)), false);
});

app.MapGet("/oauth2/callback", async (HttpContext ctx, GateService gate, GoogleAuth google) =>
{
    var code = ctx.Request.Query["code"].ToString();
    var state = ctx.Request.Query["state"].ToString();

    if (string.IsNullOrEmpty(code) || !gate.TryReadState(state, out var target) || !gate.IsOurHost(target))
        return Results.Content(Pages.Message("Error", "Sign-in was not valid. Please try again."),
            "text/html; charset=utf-8");

    var email = await google.ResolveEmail(code, ctx.RequestAborted);
    if (email is null || !google.IsPermitted(email))
        return Results.Content(Pages.Message("Refused", "This Google account is not permitted."),
            "text/html; charset=utf-8");

    // Proven identity earns a session for every guarded host, not just this one.
    SetSessionCookie(ctx, gate, gate.BuildGlobalCookie());
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

static string FirstIp(string forwardedFor) =>
    forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";

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

    // Set on the parent domain so one approval covers every guarded host.
    if (!string.IsNullOrWhiteSpace(gate.CookieDomain)) cookie.Domain = gate.CookieDomain;

    ctx.Response.Cookies.Append(gate.CookieName, value, cookie);
}

static IResult? InternalGuard(HttpContext ctx, GateService gate) =>
    string.IsNullOrEmpty(gate.InternalSecret)
    || ctx.Request.Headers["X-Kalitka-Internal"].ToString() != gate.InternalSecret
        ? Results.StatusCode(403)
        : null;
