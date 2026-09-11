using System.Net;
using System.Text;

namespace Kalitka;

/// <summary>
/// The web control plane: server-rendered, self-contained HTML, no assets and no
/// build step — the same principle as the visitor pages. Small vanilla behaviour
/// only; every state change is a POST with a CSRF token.
/// </summary>
public static class AdminPages
{
    private const string Head =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      + "<meta name=\"robots\" content=\"noindex,nofollow\">"
      + "<title>kalitka · control plane</title><style>"
      + "body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;margin:0}"
      + ".top{display:flex;align-items:center;gap:18px;padding:12px 20px;background:#141821;border-bottom:1px solid #262b36}"
      + ".top b{color:#fff}.top a{color:#9aa4b2;text-decoration:none;font-size:.9rem}.top a:hover{color:#fff}"
      + ".spacer{flex:1}.who{color:#6b7280;font-size:.8rem}"
      + ".wrap{max-width:920px;margin:0 auto;padding:22px 20px}"
      + "h1{font-size:1.2rem;margin:0 0 14px}h2{font-size:1rem;margin:22px 0 10px}"
      + "table{width:100%;border-collapse:collapse;font-size:.9rem}"
      + "th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #222833}"
      + "th{color:#6b7280;font-weight:600}tr:hover td{background:#141821}"
      + "a.row{color:#7FB2FF;text-decoration:none}code{color:#7FB2FF}"
      + ".pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.75rem}"
      + ".waiting{background:#3a2f10;color:#f0c674}.approved{background:#12331c;color:#7ad08a}"
      + ".denied{background:#3a1414;color:#ff8a8a}"
      + ".tile{display:inline-block;background:#171a22;border:1px solid #262b36;border-radius:12px;"
      + "padding:16px 20px;margin:0 12px 12px 0}.tile b{font-size:1.6rem;display:block}"
      + ".btns{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}"
      + "button{padding:9px 14px;border:0;border-radius:9px;font-size:.9rem;cursor:pointer;color:#fff;background:#2456A6}"
      + "button.ok{background:#1f7a3d}button.no{background:#8a2323}button.mut{background:#2a3140;color:#cbd3df}"
      + ".card{background:#171a22;border:1px solid #262b36;border-radius:14px;padding:20px;max-width:380px}"
      + ".sso{display:block;text-align:center;text-decoration:none;padding:11px;border-radius:10px;background:#fff;color:#111;font-weight:600;margin:16px 0}"
      + "form.inline{display:inline}.muted{color:#6b7280;font-size:.85rem}"
      + "</style></head><body>";

    private const string Foot = "</body></html>";

    private static string H(string s) => WebUtility.HtmlEncode(s);

    private static string Shell(AdminIdentity who, string body) =>
        Head
        + "<div class=\"top\"><b>kalitka</b>"
        + "<a href=\"/admin/dashboard\">Dashboard</a>"
        + "<a href=\"/admin/requests\">Requests</a>"
        + "<a href=\"/admin/agents\">Agents</a>"
        + "<a href=\"/admin/history\">History</a>"
        + "<span class=\"spacer\"></span>"
        + $"<span class=\"who\">{H(who.Email)}</span>"
        + "<form class=\"inline\" method=\"post\" action=\"/admin/logout\"><button class=\"mut\">Sign out</button></form>"
        + "</div><div class=\"wrap\">" + body + "</div>" + Foot;

    // ---- Login (unauthenticated) -------------------------------------------

    public static string Login(bool enabled, string? error = null) =>
        Head + "<div class=\"wrap\"><div class=\"card\">"
        + "<h1>kalitka · control plane</h1>"
        + (error is null ? "" : $"<p style=\"color:#ff6b6b\">{H(error)}</p>")
        + (enabled
            ? "<a class=\"sso\" href=\"/admin/login/google\">Sign in with Google</a>"
              + "<p class=\"muted\">Only listed administrators may sign in.</p>"
            : "<p class=\"muted\">The web control plane is not configured. Set "
              + "<code>AdminEmails</code> (and Google sign-in). Telegram approval works regardless.</p>")
        + "</div></div>" + Foot;

    // ---- Dashboard ----------------------------------------------------------

    public static string Dashboard(AdminIdentity who, int waiting, int hosts) =>
        Shell(who,
            "<h1>Overview</h1>"
            + $"<a class=\"row\" href=\"/admin/requests\"><span class=\"tile\"><b>{waiting}</b>waiting</span></a>"
            + $"<span class=\"tile\"><b>{hosts}</b>guarded hosts</span>"
            + "<p class=\"muted\">Requests waiting for a decision appear under "
            + "<a class=\"row\" href=\"/admin/requests\">Requests</a>. This is a second channel; "
            + "Telegram still works.</p>");

    // ---- Requests list ------------------------------------------------------

    public static string Requests(AdminIdentity who, IReadOnlyList<PendingView> all)
    {
        var waiting = all.Where(r => r.State == "waiting").ToList();
        var sb = new StringBuilder("<h1>Requests</h1>");

        if (waiting.Count == 0)
            sb.Append("<p class=\"muted\">Nothing waiting.</p>");
        else
        {
            sb.Append("<table><tr><th>Target</th><th>Says</th><th>From</th><th>When</th><th></th></tr>");
            foreach (var r in waiting)
                sb.Append("<tr>")
                  .Append($"<td><code>{H(r.Target)}</code></td>")
                  .Append($"<td>{H(r.Input)}</td>")
                  .Append($"<td>{H(Place(r))}<br><span class=\"muted\">{H(r.Ip)}</span></td>")
                  .Append($"<td class=\"muted\">{r.Raised:HH:mm:ss}</td>")
                  .Append($"<td><a class=\"row\" href=\"/admin/requests/{H(r.Id)}\">open →</a></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        return Shell(who, sb.ToString());
    }

    // ---- One request --------------------------------------------------------

    public static string Detail(AdminIdentity who, PendingView r, string csrf)
    {
        var sb = new StringBuilder($"<h1>Request <code>{H(r.Id)}</code></h1>");
        sb.Append("<table>")
          .Append($"<tr><th>Target</th><td><code>{H(r.Target)}</code></td></tr>")
          .Append($"<tr><th>Says</th><td>{H(r.Input)}</td></tr>")
          .Append($"<tr><th>IP</th><td><code>{H(r.Ip)}</code></td></tr>")
          .Append($"<tr><th>From</th><td>{H(Place(r))}</td></tr>")
          .Append($"<tr><th>Raised</th><td>{r.Raised:yyyy-MM-dd HH:mm:ss}</td></tr>")
          .Append($"<tr><th>State</th><td>{Pill(r.State)}</td></tr>")
          .Append("</table>");

        if (r.State == "waiting")
        {
            sb.Append("<div class=\"btns\">")
              .Append(Btn(r.Id, csrf, "ok", "Approve", "ok"))
              .Append(Btn(r.Id, csrf, "aip", "Approve + remember IP", ""))
              .Append(Btn(r.Id, csrf, "ain", "Approve + remember name", ""))
              .Append(Btn(r.Id, csrf, "no", "Deny", "no"))
              .Append(Btn(r.Id, csrf, "bip", "Block IP", "mut"))
              .Append(Btn(r.Id, csrf, "bin", "Block name", "mut"))
              .Append(Btn(r.Id, csrf, "bco", "Block country", "mut"))
              .Append("</div>");
        }
        else
        {
            sb.Append("<p class=\"muted\">Already decided.</p>");
        }

        sb.Append("<p style=\"margin-top:18px\"><a class=\"row\" href=\"/admin/requests\">← back</a></p>");
        return Shell(who, sb.ToString());
    }

    private static string Btn(string id, string csrf, string verb, string label, string cls) =>
        "<form class=\"inline\" method=\"post\" action=\"/admin/requests/decide\">"
        + $"<input type=\"hidden\" name=\"id\" value=\"{H(id)}\">"
        + $"<input type=\"hidden\" name=\"verb\" value=\"{H(verb)}\">"
        + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
        + $"<button class=\"{cls}\">{H(label)}</button></form>";

    // ---- History ------------------------------------------------------------

    public static string History(AdminIdentity who, IReadOnlyList<AuditEvent> events,
        string actor, string resource, string eventType, int offset, int limit)
    {
        var sb = new StringBuilder("<h1>History</h1>");

        // Filter form (GET, so filters live in the URL and survive paging).
        sb.Append("<form method=\"get\" action=\"/admin/history\" style=\"margin-bottom:14px\">")
          .Append(Field("actor", actor)).Append(Field("resource", resource)).Append(Field("event", eventType))
          .Append("<button style=\"width:auto\">Filter</button></form>");

        if (events.Count == 0)
            sb.Append("<p class=\"muted\">No events.</p>");
        else
        {
            sb.Append("<table><tr><th>When (UTC)</th><th>Event</th><th>Actor</th>"
                + "<th>Resource</th><th>Subject</th><th>Req</th><th>Note</th></tr>");
            foreach (var e in events)
                sb.Append("<tr>")
                  .Append($"<td class=\"muted\">{e.Timestamp:yyyy-MM-dd HH:mm:ss}</td>")
                  .Append($"<td><code>{H(e.EventType)}</code></td>")
                  .Append($"<td>{H(e.Actor)}</td>")
                  .Append($"<td>{H(e.Resource)}</td>")
                  .Append($"<td>{H(e.Subject)}</td>")
                  .Append($"<td class=\"muted\"><code>{H(Short(e.RequestId))}</code></td>")
                  .Append($"<td class=\"muted\">{H(e.Metadata)}</td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        // Paging, filters carried along.
        sb.Append("<p style=\"margin-top:14px\">");
        if (offset > 0)
            sb.Append($"<a class=\"row\" href=\"{PageUrl(actor, resource, eventType, Math.Max(0, offset - limit))}\">← newer</a> ");
        if (events.Count == limit)
            sb.Append($"<a class=\"row\" href=\"{PageUrl(actor, resource, eventType, offset + limit)}\">older →</a>");
        sb.Append("</p>");

        return Shell(who, sb.ToString());
    }

    private static string Field(string name, string value) =>
        $"<input name=\"{name}\" value=\"{H(value)}\" placeholder=\"{name}\" "
        + "style=\"width:auto;display:inline-block;margin-right:8px\">";

    private static string PageUrl(string actor, string resource, string eventType, int offset)
    {
        var q = new List<string> { $"offset={offset}" };
        if (!string.IsNullOrEmpty(actor)) q.Add("actor=" + Uri.EscapeDataString(actor));
        if (!string.IsNullOrEmpty(resource)) q.Add("resource=" + Uri.EscapeDataString(resource));
        if (!string.IsNullOrEmpty(eventType)) q.Add("event=" + Uri.EscapeDataString(eventType));
        return "/admin/history?" + string.Join("&", q);
    }

    private static string Short(string s) => s.Length > 10 ? s[..10] : s;

    // ---- Agents -------------------------------------------------------------

    public static string Agents(AdminIdentity who, IReadOnlyList<Agent> agents, string csrf)
    {
        var sb = new StringBuilder("<h1>Agents</h1>");

        // Create form: one profile, two ways to provision — a secret shown once, or
        // a single-use enrollment token the machine redeems itself.
        sb.Append("<h2>New agent</h2>")
          .Append("<form method=\"post\" action=\"/admin/agents/create\">")
          .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
          .Append(In("display_name", "name (e.g. prod-linux-01)"))
          .Append(In("platform", "platform (linux, windows, …)"))
          .Append(In("capabilities", "capabilities (ssh sudo …)"))
          .Append(In("allowed_resources", "allowed resources (ssh:prod-01 ssh:*)"))
          .Append("<div class=\"btns\">")
          .Append("<button name=\"mode\" value=\"create\">Create (show secret once)</button>")
          .Append("<button class=\"mut\" name=\"mode\" value=\"token\">Enrollment token</button>")
          .Append("</div></form>");

        sb.Append("<h2>Registered</h2>");
        if (agents.Count == 0)
            sb.Append("<p class=\"muted\">No agents yet.</p>");
        else
        {
            sb.Append("<table><tr><th>Name</th><th>Platform</th><th>Capabilities</th>"
                + "<th>Resources</th><th>Status</th><th>Last seen</th><th></th></tr>");
            foreach (var a in agents)
                sb.Append("<tr>")
                  .Append($"<td>{H(a.DisplayName)}<br><span class=\"muted\">{H(a.Hostname)}</span></td>")
                  .Append($"<td>{H(a.Platform)}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", a.Capabilities))}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", a.AllowedResources))}</td>")
                  .Append($"<td>{StatusPill(a.Status)}</td>")
                  .Append($"<td class=\"muted\">{Seen(a.LastSeenAt)}</td>")
                  .Append($"<td><a class=\"row\" href=\"/admin/agents/{H(a.Id)}\">open →</a></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        return Shell(who, sb.ToString());
    }

    public static string AgentDetail(AdminIdentity who, Agent a, string csrf)
    {
        var sb = new StringBuilder($"<h1>Agent <code>{H(a.DisplayName)}</code></h1>");
        sb.Append("<table>")
          .Append($"<tr><th>Id</th><td><code>{H(a.Id)}</code></td></tr>")
          .Append($"<tr><th>Status</th><td>{StatusPill(a.Status)}</td></tr>")
          .Append($"<tr><th>Platform</th><td>{H(a.Platform)}</td></tr>")
          .Append($"<tr><th>Hostname</th><td>{H(a.Hostname)}</td></tr>")
          .Append($"<tr><th>Capabilities</th><td><code>{H(string.Join(" ", a.Capabilities))}</code></td></tr>")
          .Append($"<tr><th>Resources</th><td><code>{H(string.Join(" ", a.AllowedResources))}</code></td></tr>")
          .Append($"<tr><th>Created</th><td class=\"muted\">{a.CreatedAt:yyyy-MM-dd HH:mm} UTC</td></tr>")
          .Append($"<tr><th>Last seen</th><td class=\"muted\">{Seen(a.LastSeenAt)}{(string.IsNullOrEmpty(a.LastIp) ? "" : " · " + H(a.LastIp))}</td></tr>")
          .Append(string.IsNullOrEmpty(a.Metadata) ? "" : $"<tr><th>Reported</th><td class=\"muted\">{H(a.Metadata)}</td></tr>")
          .Append("</table>");

        sb.Append("<div class=\"btns\">");
        if (a.Status != AgentStatus.Revoked)
        {
            if (a.Status == AgentStatus.Disabled) sb.Append(Act(a.Id, csrf, "enable", "Enable", "ok"));
            else if (a.Status == AgentStatus.Active) sb.Append(Act(a.Id, csrf, "disable", "Disable", "mut"));
            sb.Append(Act(a.Id, csrf, "rotate", "Rotate secret", ""));
            sb.Append(Act(a.Id, csrf, "revoke", "Revoke", "no"));
        }
        else sb.Append("<span class=\"muted\">Revoked — re-enrol to return.</span>");
        sb.Append("</div>");

        sb.Append("<p style=\"margin-top:18px\"><a class=\"row\" href=\"/admin/agents\">← back</a></p>");
        return Shell(who, sb.ToString());
    }

    /// <summary>Show a secret or enrollment token exactly once — it is never stored
    /// in a form we can render again.</summary>
    public static string SecretShown(AdminIdentity who, string title, string label, string value, string note) =>
        Shell(who,
            $"<h1>{H(title)}</h1>"
            + "<div class=\"card\" style=\"max-width:640px\">"
            + $"<p class=\"muted\">{H(label)}</p>"
            + $"<p><code style=\"font-size:1rem;word-break:break-all\">{H(value)}</code></p>"
            + $"<p class=\"muted\">{H(note)}</p></div>"
            + "<p style=\"margin-top:18px\"><a class=\"row\" href=\"/admin/agents\">← back to agents</a></p>");

    private static string In(string name, string placeholder) =>
        $"<input name=\"{name}\" placeholder=\"{H(placeholder)}\" "
        + "style=\"display:block;width:100%;max-width:420px;margin:6px 0;padding:8px;border-radius:8px;"
        + "border:1px solid #2a3140;background:#0f1117;color:#e6e6e6\">";

    private static string Act(string id, string csrf, string verb, string label, string cls) =>
        $"<form class=\"inline\" method=\"post\" action=\"/admin/agents/{H(id)}/action\">"
        + $"<input type=\"hidden\" name=\"verb\" value=\"{H(verb)}\">"
        + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
        + $"<button class=\"{cls}\">{H(label)}</button></form>";

    private static string StatusPill(AgentStatus s) => s switch
    {
        AgentStatus.Active => "<span class=\"pill approved\">active</span>",
        AgentStatus.Pending => "<span class=\"pill waiting\">pending</span>",
        AgentStatus.Disabled => "<span class=\"pill waiting\">disabled</span>",
        _ => "<span class=\"pill denied\">revoked</span>",
    };

    private static string Seen(DateTimeOffset? at) => at is null ? "never" : $"{at:yyyy-MM-dd HH:mm} UTC";

    // ---- bits ---------------------------------------------------------------

    private static string Place(PendingView r) =>
        string.IsNullOrEmpty(r.CountryCode) ? "(private/unknown)"
        : $"{r.City}, {r.Country} [{r.CountryCode}]";

    private static string Pill(string state) =>
        $"<span class=\"pill {state}\">{H(state)}</span>";
}
