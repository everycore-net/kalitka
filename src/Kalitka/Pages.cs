using System.Net;
using System.Text.Json;

namespace Kalitka;

/// <summary>
/// The pages a visitor (or an e-mail approver) ever sees. Deliberately plain HTML
/// with inline styles and no assets: the gate must work when everything behind it
/// does not, and a single self-contained response has nothing left to fail. The
/// look follows the kalitka.app brand — near-black, one cyan accent, a square mark
/// beside the wordmark. Every string is localised (see <see cref="L10n"/>).
/// </summary>
public static class Pages
{
    private const string Repo = "https://github.com/everycore-net/kalitka";
    private static readonly string Version = typeof(Pages).Assembly.GetName().Version?.ToString(3) ?? "";

    private static string Head(Strings s) =>
        $"<!doctype html><html lang=\"{s.Code}\"><head><meta charset=\"utf-8\">"
      + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      + "<meta name=\"robots\" content=\"noindex,nofollow\">"
      + $"<link rel=\"icon\" type=\"image/png\" href=\"{Brand.IconDataUri}\">"
      + $"<title>{H(s.DocTitle)}</title><style>"
      + $":root{{--bg:#0a0b0d;--card:#14161a;--line:#23262d;--fg:#f5f5f7;--mut:#9aa4b2;--accent:{Brand.Cyan}}}"
      + "*{box-sizing:border-box}"
      + "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);"
      + "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px}"
      + ".card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:26px 24px;max-width:370px;width:100%}"
      + ".brand{display:flex;align-items:center;gap:9px;margin-bottom:18px}"
      + ".mark{width:26px;height:26px;display:block;flex:0 0 auto}"
      + ".brand b{font-size:1.05rem;font-weight:700;letter-spacing:-.01em}"
      + "h1{font-size:1.25rem;margin:0 0 6px;font-weight:650}"
      + "p{color:var(--mut);font-size:.9rem;margin:.35rem 0;line-height:1.5}"
      + ".tag{color:var(--accent);font-size:.8rem;margin:-2px 0 2px;letter-spacing:.01em}"
      + "input{width:100%;padding:11px;margin:14px 0;border-radius:10px;border:1px solid #2a2e37;"
      + "background:var(--bg);color:var(--fg);font-size:1rem}input:focus{outline:0;border-color:var(--accent)}"
      + "button{width:100%;padding:11px;border:0;border-radius:10px;background:var(--accent);color:#05161a;"
      + "font-size:1rem;font-weight:600;cursor:pointer}button:hover{filter:brightness(1.08)}"
      + "code{color:var(--accent);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}"
      + ".sso{display:block;text-align:center;text-decoration:none;padding:11px;border-radius:10px;"
      + "background:#fff;color:#111;font-weight:600;margin:14px 0}"
      + ".or{color:var(--mut);font-size:.8rem;text-align:center;margin:6px 0}"
      + ".foot{margin-top:20px;padding-top:12px;border-top:1px solid var(--line)}"
      + ".foot a{color:#6b7280;font-size:.72rem;text-decoration:none}.foot a:hover{color:var(--mut)}"
      + "</style></head><body><div class=\"card\">"
      + $"<div class=\"brand\"><img class=\"mark\" src=\"{Brand.IconDataUri}\" alt=\"\" width=\"26\" height=\"26\"><b>kalitka</b></div>";

    // AGPL §13: the operator of a network service must offer its users the source.
    // A quiet footer link makes that automatic for an unmodified deployment.
    private static string Foot(Strings s) =>
        $"<div class=\"foot\"><a href=\"{Repo}\" target=\"_blank\" rel=\"noopener\">"
      + $"kalitka {H(Version)} · {H(s.SourceLabel)}</a></div></div></body></html>";

    private static string H(string s) => WebUtility.HtmlEncode(s);

    public static string Form(Lang lang, string target, bool error = false, bool googleEnabled = false)
    {
        var s = L10n.For(lang);
        return Head(s)
            + $"<h1>{H(s.DocTitle)}</h1>"
            + $"<p class=\"tag\">{H(s.Tagline)}</p>"
            + $"<p>{H(s.TargetLabel)}: <code>{H(target)}</code></p>"
            + (error ? $"<p style=\"color:#ff6b6b\">{H(s.InvalidInput)}</p>" : "")
            + (googleEnabled
                ? $"<a class=\"sso\" href=\"/google/login?target={Uri.EscapeDataString(target)}\">{H(s.SignInGoogle)}</a>"
                  + $"<div class=\"or\">{H(s.OrAsk)}</div>"
                : "")
            + "<form method=\"post\" action=\"/request\">"
            + $"<input type=\"hidden\" name=\"target\" value=\"{H(target)}\">"
            + $"<input name=\"input\" placeholder=\"{H(s.NamePlaceholder)}\" maxlength=\"120\" required autofocus>"
            + $"<button>{H(s.Ask)}</button></form>"
            + $"<p>{H(s.ByHand)}</p>"
            + Foot(s);
    }

    /// <summary>
    /// Waiting page. It polls, because a human has to press a button somewhere
    /// and no callback can reach this browser. Keep the interval modest: this
    /// is exactly the traffic that gets a visitor banned by a behavioural WAF —
    /// exempt this path there.
    /// </summary>
    public static string Waiting(Lang lang, string id, string target)
    {
        var s = L10n.For(lang);
        return Head(s)
            + $"<h1>{H(s.Asked)}</h1>"
            + $"<p id=\"m\">{H(s.WaitingMsg)}</p>"
            + "<script>"
            + $"var id={JsonSerializer.Serialize(id)},target={JsonSerializer.Serialize(target)};"
            + $"var T={JsonSerializer.Serialize(new { ok = s.ApprovedContinuing, no = s.RefusedShort, gone = s.ExpiredReload })};"
            + "function poll(){fetch('/wait/status?id='+encodeURIComponent(id)).then(r=>r.json()).then(d=>{"
            + "if(d.state=='approved'){document.getElementById('m').textContent=T.ok;location.href='https://'+target;}"
            + "else if(d.state=='denied'){document.getElementById('m').textContent=T.no;}"
            + "else if(d.state=='gone'){document.getElementById('m').textContent=T.gone;}"
            + "else{setTimeout(poll,3000);}});}"
            + "setTimeout(poll,3000);"
            + "</script>" + Foot(s);
    }

    public static string Message(Lang lang, string title, string text)
    {
        var s = L10n.For(lang);
        return Head(s) + $"<h1>{H(title)}</h1><p>{H(text)}</p>" + Foot(s);
    }

    /// <summary>
    /// The confirmation page for a one-time approval link. The GET that shows this
    /// never changes anything — a security scanner pre-fetching the link is
    /// harmless; only the POST from here consumes the link and decides.
    /// </summary>
    public static string ActionConfirm(Lang lang, bool approve, string resource, string says, string token)
    {
        var s = L10n.For(lang);
        return Head(s)
            + $"<h1>{H(approve ? s.ApproveAccessTitle : s.DenyAccessTitle)}</h1>"
            + $"<p>{H(s.ResourceLabel)}: <code>{H(resource)}</code></p>"
            + $"<p>{H(s.SaysLabel)}: <b>{H(says)}</b></p>"
            + "<form method=\"post\" action=\"/action\">"
            + $"<input type=\"hidden\" name=\"t\" value=\"{H(token)}\">"
            + $"<button>{H(approve ? s.ConfirmApprove : s.ConfirmDeny)}</button></form>"
            + $"<p>{H(s.OnceExpires)}</p>"
            + Foot(s);
    }
}
