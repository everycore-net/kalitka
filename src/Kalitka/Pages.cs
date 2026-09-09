using System.Net;
using System.Text.Json;

namespace Kalitka;

/// <summary>
/// The three pages a visitor ever sees. Deliberately plain HTML with inline
/// styles and no assets: the gate must work when everything behind it does not,
/// and a single self-contained response has nothing left to fail.
/// </summary>
public static class Pages
{
    private const string Head =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      + "<title>Access</title><style>"
      + "body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;display:flex;"
      + "min-height:100vh;align-items:center;justify-content:center;margin:0}"
      + ".card{background:#171a22;border:1px solid #262b36;border-radius:16px;padding:28px 26px;max-width:360px;width:90%}"
      + "h1{font-size:1.25rem;margin:0 0 6px}p{color:#9aa4b2;font-size:.9rem;margin:.3rem 0}"
      + "input{width:100%;box-sizing:border-box;padding:11px;margin:14px 0;border-radius:10px;"
      + "border:1px solid #333a47;background:#0f1117;color:#e6e6e6;font-size:1rem}"
      + "button{width:100%;padding:11px;border:0;border-radius:10px;background:#2456A6;color:#fff;"
      + "font-size:1rem;cursor:pointer}code{color:#7FB2FF}"
      + ".sso{display:block;box-sizing:border-box;text-align:center;text-decoration:none;padding:11px;"
      + "border-radius:10px;background:#fff;color:#111;font-weight:600;margin:14px 0}"
      + ".or{color:#6b7280;font-size:.8rem;text-align:center;margin:4px 0}"
      + "</style></head><body><div class=\"card\">";

    private const string Foot = "</div></body></html>";

    private static string H(string s) => WebUtility.HtmlEncode(s);

    public static string Form(string target, string? error = null, bool googleEnabled = false) =>
        Head
        + "<h1>Access</h1>"
        + $"<p>Target: <code>{H(target)}</code></p>"
        + (error is null ? "" : $"<p style=\"color:#ff6b6b\">{H(error)}</p>")
        + (googleEnabled
            ? $"<a class=\"sso\" href=\"/google/login?target={Uri.EscapeDataString(target)}\">Sign in with Google</a>"
              + "<div class=\"or\">or ask to be let in</div>"
            : "")
        + "<form method=\"post\" action=\"/request\">"
        + $"<input type=\"hidden\" name=\"target\" value=\"{H(target)}\">"
        + "<input name=\"input\" placeholder=\"Name or e-mail\" maxlength=\"120\" required autofocus>"
        + "<button>Ask</button></form>"
        + "<p>Someone has to let you in by hand. After that you continue to the login.</p>"
        + Foot;

    /// <summary>
    /// Waiting page. It polls, because a human has to press a button somewhere
    /// and no callback can reach this browser. Keep the interval modest: this
    /// is exactly the traffic that gets a visitor banned by a behavioural WAF —
    /// exempt this path there.
    /// </summary>
    public static string Waiting(string id, string target) =>
        Head
        + "<h1>Asked</h1>"
        + "<p id=\"m\">Waiting to be let in…</p>"
        + "<script>"
        + $"var id={JsonSerializer.Serialize(id)},target={JsonSerializer.Serialize(target)};"
        + "function poll(){fetch('/wait/status?id='+encodeURIComponent(id)).then(r=>r.json()).then(d=>{"
        + "if(d.state=='approved'){document.getElementById('m').textContent='Approved, continuing…';location.href='https://'+target;}"
        + "else if(d.state=='denied'){document.getElementById('m').textContent='Refused.';}"
        + "else if(d.state=='gone'){document.getElementById('m').textContent='Expired. Reload to ask again.';}"
        + "else{setTimeout(poll,3000);}});}"
        + "setTimeout(poll,3000);"
        + "</script>" + Foot;

    public static string Message(string title, string text) =>
        Head + $"<h1>{H(title)}</h1><p>{H(text)}</p>" + Foot;
}
