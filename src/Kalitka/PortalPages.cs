using System.Net;
using System.Text;

namespace Kalitka;

/// <summary>
/// The self-service portal: server-rendered, self-contained HTML, no assets or build step (the same
/// principle as the admin and visitor pages). Read surfaces in this slice — sign in, "my access", and
/// the visible catalogue; the request action and explain follow. Everything interpolated is
/// HTML-encoded.
/// </summary>
public static class PortalPages
{
    private static string H(string s) => WebUtility.HtmlEncode(s ?? "");

    private const string Head =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      + "<meta name=\"robots\" content=\"noindex,nofollow\">"
      + "<title>kalitka · my access</title><style>"
      + "body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;margin:0}"
      + ".top{display:flex;align-items:center;gap:14px;padding:12px 20px;background:#141821;border-bottom:1px solid #262b36}"
      + ".top b{color:#fff}.spacer{flex:1}.who{color:#6b7280;font-size:.82rem}"
      + ".top a{color:#9aa4b2;text-decoration:none;font-size:.9rem}.top a:hover{color:#fff}"
      + ".wrap{max-width:880px;margin:0 auto;padding:22px 20px}"
      + "h1{font-size:1.2rem;margin:0 0 6px}h2{font-size:1rem;margin:24px 0 10px}"
      + ".muted{color:#6b7280;font-size:.9rem}"
      + "table{width:100%;border-collapse:collapse;font-size:.9rem;margin-top:6px}"
      + "th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #222833}"
      + "th{color:#6b7280;font-weight:600}code{color:#7FB2FF}"
      + ".tag{display:inline-block;background:#171a22;border:1px solid #262b36;border-radius:20px;padding:2px 10px;margin:2px 4px 2px 0;font-size:.8rem}"
      + ".btn{display:inline-block;padding:9px 14px;border-radius:9px;background:#2456A6;color:#fff;text-decoration:none;font-size:.9rem}"
      + ".card{background:#141821;border:1px solid #262b36;border-radius:12px;padding:14px 16px;margin:10px 0}"
      + "button{padding:7px 12px;border:0;border-radius:8px;background:#2456A6;color:#fff;cursor:pointer;font-size:.85rem}"
      + "button:hover{background:#2b63bd}"
      + "</style></head><body>";
    private const string Foot = "</body></html>";

    /// <summary>Sign-in: one button per configured provider, or a note when none is.</summary>
    public static string Login(IReadOnlyList<(string Scheme, string Name)> providers, string? error = null)
    {
        var sb = new StringBuilder(Head);
        sb.Append("<div class=\"wrap\"><h1>kalitka</h1><p class=\"muted\">Sign in to see and request your access.</p>");
        if (!string.IsNullOrEmpty(error)) sb.Append("<p class=\"card\">").Append(H(error)).Append("</p>");
        if (providers.Count == 0)
            sb.Append("<p class=\"muted\">No sign-in provider is configured.</p>");
        else
            foreach (var (scheme, name) in providers)
                sb.Append("<p><a class=\"btn\" href=\"/portal/login/").Append(H(scheme)).Append("\">Sign in with ")
                  .Append(H(name)).Append("</a></p>");
        return sb.Append("</div>").Append(Foot).ToString();
    }

    /// <summary>Signed in, but not linked to any principal — refused by default, with who to ask.</summary>
    public static string NoAccess(string email)
    {
        var sb = new StringBuilder(Head);
        sb.Append("<div class=\"wrap\"><h1>No access yet</h1>")
          .Append("<p class=\"muted\">You are signed in as <b>").Append(H(email)).Append("</b>, but this account is not set up in kalitka yet.</p>")
          .Append("<p class=\"muted\">Ask an administrator to add you, then sign in again.</p>")
          .Append("<p><a class=\"btn\" href=\"/portal/logout\">Sign out</a></p>")
          .Append("</div>");
        return sb.Append(Foot).ToString();
    }

    /// <summary>How much approval a requestable unit needs, for the inline "why two approvals" note.</summary>
    public sealed record Requestable(CatalogItem Item, int RequiredApprovals, bool SubjectRequired);

    /// <summary>"My access": what the person holds, what they have in flight, and — as far as their
    /// visibility mode allows — what they may ask for (with a Request button and the approval it needs).</summary>
    public static string Home(PortalSession who, MyAccess mine, CatalogView catalog,
        IReadOnlyList<Requestable> requestables, string csrf, string? message = null)
    {
        var sb = new StringBuilder(Head);
        sb.Append("<div class=\"top\"><b>kalitka</b><span class=\"spacer\"></span>")
          .Append("<span class=\"who\">").Append(H(who.Principal.DisplayName)).Append(" · ").Append(H(who.Email)).Append("</span>")
          .Append("<a href=\"/portal/logout\">Sign out</a></div><div class=\"wrap\">");

        if (!string.IsNullOrEmpty(message)) sb.Append("<p class=\"card\">").Append(H(message)).Append("</p>");

        sb.Append("<h1>My access</h1>");

        sb.Append("<h2>Currently held</h2>");
        if (mine.Held.Count == 0)
            sb.Append("<p class=\"muted\">Nothing active.</p>");
        else
        {
            sb.Append("<table><tr><th>Resource</th><th>Until</th><th>Profile</th><th>Uses left</th></tr>");
            foreach (var h in mine.Held)
                sb.Append("<tr><td><code>").Append(H(h.Resource)).Append("</code></td><td>")
                  .Append(H(h.ExpiresAt is { } e ? e.UtcDateTime.ToString("u") : "—")).Append("</td><td>")
                  .Append(H(h.Profile.Length == 0 ? "—" : h.Profile)).Append("</td><td>")
                  .Append(h.RemainingUses < 0 ? "∞" : h.RemainingUses.ToString()).Append("</td></tr>");
            sb.Append("</table>");
        }

        if (mine.Pending.Count > 0)
        {
            sb.Append("<h2>Waiting on approval</h2><table><tr><th>Resource</th><th>Asked</th></tr>");
            foreach (var p in mine.Pending)
                sb.Append("<tr><td><code>").Append(H(p.Resource)).Append("</code></td><td>")
                  .Append(H(p.Raised.UtcDateTime.ToString("u"))).Append("</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("<h2>Available to request</h2>");
        if (catalog.Mode == CatalogVisibility.Full && requestables.Count > 0)
        {
            sb.Append("<table><tr><th>What</th><th>Category</th><th>Needs</th><th></th></tr>");
            foreach (var q in requestables)
            {
                var needs = q.RequiredApprovals == 1 ? "1 approval" : $"{q.RequiredApprovals} approvals";
                if (q.SubjectRequired) needs += " · your confirmation";
                sb.Append("<tr><td>").Append(H(q.Item.DisplayName)).Append(" <code>").Append(H(q.Item.Resource))
                  .Append("</code></td><td>").Append(H(q.Item.Category)).Append("</td><td class=\"muted\">").Append(H(needs))
                  .Append("</td><td><form method=\"post\" action=\"/portal/request\" style=\"margin:0\">")
                  .Append("<input type=\"hidden\" name=\"csrf\" value=\"").Append(H(csrf)).Append("\">")
                  .Append("<input type=\"hidden\" name=\"item\" value=\"").Append(H(q.Item.Id)).Append("\">")
                  .Append("<button type=\"submit\">Request</button></form></td></tr>");
            }
            sb.Append("</table>");
        }
        else if (catalog.Mode == CatalogVisibility.Categories && catalog.Categories.Count > 0)
        {
            sb.Append("<p>");
            foreach (var c in catalog.Categories) sb.Append("<span class=\"tag\">").Append(H(c)).Append("</span>");
            sb.Append("</p><p class=\"muted\">Ask an administrator for the specific resource you need.</p>");
        }
        else
        {
            sb.Append("<p class=\"muted\">Nothing is listed for self-service. Access is requested through your administrator.</p>");
        }

        return sb.Append("</div>").Append(Foot).ToString();
    }
}
