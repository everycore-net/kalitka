using System.Net;
using System.Text;
using Kalitka.Text;

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
      + "<link rel=\"icon\" type=\"image/png\" href=\"" + Brand.IconDataUri + "\">"
      + "<title>kalitka · control plane</title><style>"
      + "body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;margin:0}"
      + ".top{display:flex;align-items:center;gap:18px;padding:12px 20px;background:#141821;border-bottom:1px solid #262b36}"
      + ".top b{color:#fff}.top a{color:#9aa4b2;text-decoration:none;font-size:.9rem}.top a:hover{color:#fff}"
      + ".brand{display:flex;align-items:center;gap:8px}.brand .mark{width:22px;height:22px;display:block}"
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
      + ".priv{background:#3a2140;color:#e0a3ff;border:1px solid #6d3f7a}"
      + ".add{color:#7ad08a}.rem{color:#ff8a8a}.add.priv,.rem.priv{background:none;border:0}"
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

    // Approver-facing fields (command, target, subject, source) rendered so a bidi override,
    // invisible character or confusable cannot deceive the human deciding — dangerous characters
    // become explicit [U+XXXX NAME] markers, mixed/confusable scripts are flagged. Same SafeText
    // the MCP gateway uses; HtmlEncode then only guards the surrounding markup.
    private static string Safe(string s, FieldKind kind) => H(SafeText.ToTextMarkers(SafeText.Render(s, kind)));

    // Render a capability list, giving any sudo-grade capability (subject.assert) a
    // distinct badge so it never blends into an ordinary <code> run. A privileged grant
    // over the approval decision should be impossible to miss at a glance.
    private static string Caps(IEnumerable<string> caps)
    {
        var xs = caps.ToArray();
        if (xs.Length == 0) return "<span class=\"muted\">none</span>";
        var sb = new StringBuilder();
        foreach (var c in xs)
            sb.Append(AgentCapabilities.IsPrivileged(c)
                ? $"<span class=\"pill priv\" title=\"sudo-grade capability\">{H(c)}</span> "
                : $"<code>{H(c)}</code> ");
        return sb.ToString().TrimEnd();
    }

    // Honest wording: a provider hint is a local CLAIM, not a verified fact. Until
    // attestation validates it (assurance != unverified), never say "TPM protected".
    private static string ProviderLabel(AgentKey k) => k.Assurance switch
    {
        "attested-tpm" => "TPM-attested",
        "attested-secure-enclave" => "Secure Enclave-attested",
        _ => k.ProviderHint switch
        {
            "windows-platform" => "Platform Crypto Provider — not remotely attested",
            "apple-secure-enclave" => "Secure Enclave — not remotely attested",
            "software" => "software",
            _ => "unknown",
        },
    };

    private static string Shell(AdminIdentity who, string body) =>
        Head
        + $"<div class=\"top\"><span class=\"brand\"><img class=\"mark\" src=\"{Brand.IconDataUri}\" alt=\"\" width=\"22\" height=\"22\"><b>kalitka</b></span>"
        + "<a href=\"/admin/dashboard\">Dashboard</a>"
        // Nav mirrors permissions — purely UX; the endpoint guards are the boundary.
        + Nav(who, Perm.RequestsRead, "/admin/requests", "Requests")
        + Nav(who, Perm.RequestsRead, "/admin/sessions", "Sessions")
        + Nav(who, Perm.AgentsRead, "/admin/agents", "Agents")
        + Nav(who, Perm.ProfilesManage, "/admin/profiles", "Profiles")
        + Nav(who, Perm.AgentsRead, "/admin/reconcile", "Reconcile")
        + Nav(who, Perm.PoliciesRead, "/admin/policies", "Policies")
        + Nav(who, Perm.PoliciesRead, "/admin/policies/explain", "Explain")
        + Nav(who, Perm.PoliciesManage, "/admin/policies/copilot", "Copilot")
        + Nav(who, Perm.PrincipalsRead, "/admin/principals", "Operators")
        + Nav(who, Perm.HistoryRead, "/admin/history", "History")
        + Nav(who, Perm.HistoryRead, "/admin/audit/verify", "Integrity")
        // Self-service for every admin — you register and revoke your own devices.
        + "<a href=\"/admin/devices\">Devices</a>"
        // The installable operator app (Web Push + device-signed approval).
        + "<a href=\"/admin/app\">App</a>"
        + "<span class=\"spacer\"></span>"
        + $"<span class=\"who\">{H(who.Email)}</span>"
        + "<form class=\"inline\" method=\"post\" action=\"/admin/logout\"><button class=\"mut\">Sign out</button></form>"
        + "</div><div class=\"wrap\">" + body + "</div>" + Foot;

    private static string Nav(AdminIdentity who, string permission, string href, string label) =>
        who.Can(permission) ? $"<a href=\"{href}\">{H(label)}</a>" : "";

    // ---- Login (unauthenticated) -------------------------------------------

    public static string Login(bool enabled, string? error = null) =>
        Head + "<div class=\"wrap\"><div class=\"card\">"
        + $"<div class=\"brand\" style=\"margin-bottom:12px\"><img class=\"mark\" src=\"{Brand.IconDataUri}\" alt=\"\" width=\"28\" height=\"28\" style=\"width:28px;height:28px\"><b style=\"color:#fff;font-size:1.1rem\">kalitka</b></div>"
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
            // Only surface what this operator may act on.
            + (who.Can(Perm.RequestsRead)
                ? $"<a class=\"row\" href=\"/admin/requests\"><span class=\"tile\"><b>{waiting}</b>waiting</span></a>"
                  + $"<span class=\"tile\"><b>{hosts}</b>guarded hosts</span>"
                  + "<p class=\"muted\">Requests waiting for a decision appear under "
                  + "<a class=\"row\" href=\"/admin/requests\">Requests</a>. This is a second channel; "
                  + "Telegram still works.</p>"
                : who.Can(Perm.AgentsRead)
                    ? "<p class=\"muted\">Manage agents and profiles under "
                      + "<a class=\"row\" href=\"/admin/agents\">Agents</a>.</p>"
                    : "<p class=\"muted\">No sections are available to your account.</p>"));

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
                  .Append($"<td><code>{Safe(r.Target, FieldKind.SecurityIdentifier)}</code></td>")
                  .Append($"<td>{Safe(r.Input, FieldKind.FreeText)}</td>")
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
          .Append($"<tr><th>Target</th><td><code>{Safe(r.Target, FieldKind.SecurityIdentifier)}</code></td></tr>")
          .Append($"<tr><th>Says</th><td>{Safe(r.Input, FieldKind.FreeText)}</td></tr>")
          // The exact command being approved (0.26); its presence means access is limited
          // to this one command (an SSH cert force-command), not an open shell. Rendered safely.
          .Append(string.IsNullOrEmpty(r.Command) ? ""
              : $"<tr><th>Command</th><td><code>{Safe(r.Command, FieldKind.FreeText)}</code> <span class=\"muted\">(force-command — no open shell)</span></td></tr>")
          .Append(string.IsNullOrEmpty(r.SourceAddr) ? ""
              : $"<tr><th>From address</th><td><code>{Safe(r.SourceAddr, FieldKind.SecurityIdentifier)}</code> <span class=\"muted\">(cert usable only from here)</span></td></tr>")
          .Append($"<tr><th>IP</th><td><code>{H(r.Ip)}</code></td></tr>")
          .Append($"<tr><th>From</th><td>{H(Place(r))}</td></tr>")
          .Append($"<tr><th>Raised</th><td>{r.Raised:yyyy-MM-dd HH:mm:ss}</td></tr>")
          .Append($"<tr><th>State</th><td>{Pill(r.State)}</td></tr>")
          .Append(r.RequiredApprovals > 1
              ? $"<tr><th>Approvals</th><td>{r.ApprovalCount} / {r.RequiredApprovals} <span class=\"muted\">(policy quorum; distinct control-plane approvers)</span></td></tr>"
              : "")
          .Append("</table>");

        if (r.State == "waiting")
        {
            if (r.RequiredApprovals > 1)
                sb.Append($"<p class=\"muted\">This resource needs {r.RequiredApprovals} distinct approvers. "
                    + "Your approval counts once; a second person must also approve here.</p>");

            // Device-signed decision (fido2 slice 2): the assertion signs THIS request id + decision,
            // so history holds a signature bound to a named credential, not "a session pressed approve".
            sb.Append("<h2>Sign this decision with a device</h2>")
              .Append("<p class=\"muted\">Uses a registered passkey / security key. "
                  + "<a class=\"row\" href=\"/admin/devices\">Manage devices →</a></p>")
              .Append("<div class=\"btns\">")
              .Append($"<button class=\"ok\" onclick=\"kalitkaApprove('{H(r.Id)}','ok','{H(csrf)}')\">🔑 Approve with device</button>")
              .Append($"<button class=\"no\" onclick=\"kalitkaApprove('{H(r.Id)}','no','{H(csrf)}')\">🔑 Deny with device</button>")
              .Append("</div>");

            sb.Append("<h2>Or decide from this session</h2>")
              .Append("<div class=\"btns\">")
              .Append(Btn(r.Id, csrf, "ok", "Approve", "ok"))
              .Append(Btn(r.Id, csrf, "aip", "Approve + remember IP", ""))
              .Append(Btn(r.Id, csrf, "ain", "Approve + remember name", ""))
              .Append(Btn(r.Id, csrf, "no", "Deny", "no"))
              .Append(Btn(r.Id, csrf, "bip", "Block IP", "mut"))
              .Append(Btn(r.Id, csrf, "bin", "Block name", "mut"))
              .Append(Btn(r.Id, csrf, "bco", "Block country", "mut"))
              .Append("</div>")
              .Append(WebAuthnJs);
        }
        else
        {
            sb.Append("<p class=\"muted\">Already decided.</p>");
        }

        sb.Append("<p style=\"margin-top:18px\"><a class=\"row\" href=\"/admin/requests\">← back</a></p>");
        return Shell(who, sb.ToString());
    }

    // ---- Registered devices (WebAuthn) -------------------------------------

    public static string Devices(AdminIdentity who, IReadOnlyList<WebAuthnCredential> creds, string csrf)
    {
        var sb = new StringBuilder("<h1>Your devices</h1>");
        sb.Append("<p class=\"muted\">A registered device signs your approvals with a key in its secure hardware — "
            + "a decision bound to a credential we can name, not just a button press. Passkeys and platform "
            + "authenticators work; on a phone, add kalitka to the home screen first.</p>");

        if (creds.Count == 0)
            sb.Append("<p class=\"muted\">No devices registered yet.</p>");
        else
        {
            sb.Append("<table><tr><th>Device</th><th>Kind</th><th>Added</th><th>Last used</th><th></th></tr>");
            foreach (var c in creds)
                sb.Append("<tr>")
                  .Append($"<td>{H(c.DisplayName)}</td>")
                  // Honest: a cloud-synced passkey (BE flag) is not bound to one device.
                  .Append(c.BackupEligible
                      ? "<td><span class=\"pill waiting\" title=\"synced across the owner's devices\">cloud-synced</span></td>"
                      : "<td><span class=\"pill approved\" title=\"non-syncable, bound to this device\">device-bound</span></td>")
                  .Append($"<td class=\"muted\">{H(ShortWhen(c.CreatedAt))}</td>")
                  .Append($"<td class=\"muted\">{H(ShortWhen(c.LastUsedAt))}</td>")
                  .Append("<td><form class=\"inline\" method=\"post\" action=\"/admin/devices/remove\" "
                      + "onsubmit=\"return confirm('Revoke this device?')\">"
                      + $"<input type=\"hidden\" name=\"credentialId\" value=\"{H(c.CredentialId)}\">"
                      + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
                      + "<button class=\"no\">Revoke</button></form></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        sb.Append("<div class=\"btns\">")
          .Append($"<button class=\"ok\" onclick=\"kalitkaRegister('{H(csrf)}')\">🔑 Register this device</button>")
          .Append("</div>")
          .Append(WebAuthnJs);
        return Shell(who, sb.ToString());
    }

    private static string ShortWhen(string iso) =>
        DateTimeOffset.TryParse(iso, out var d) ? d.ToString("yyyy-MM-dd HH:mm") : iso;

    // Self-contained WebAuthn client: no bundler, no external asset, in keeping with the rest of the
    // control plane. Base64url <-> ArrayBuffer, then the two ceremonies (register, sign a decision).
    internal const string WebAuthnJs = @"<script>
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var p=s.length%4;if(p)s+='='.repeat(4-p);var bin=atob(s);var b=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i);return b.buffer;}
function bufToB64u(buf){var b=new Uint8Array(buf);var s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function kalitkaRegister(csrf){
 try{
  var r=await fetch('/admin/devices/register/begin',{method:'POST',headers:{'X-Csrf':csrf}});
  if(!r.ok){alert('Could not start registration ('+r.status+')');return;}
  var d=await r.json();var o=d.options;
  o.challenge=b64uToBuf(o.challenge);o.user.id=b64uToBuf(o.user.id);
  if(o.excludeCredentials)o.excludeCredentials=o.excludeCredentials.map(function(c){return{type:c.type,id:b64uToBuf(c.id)};});
  var cred=await navigator.credentials.create({publicKey:o});
  var name=prompt('Name this device','my phone')||'device';
  var body={state:d.state,credentialId:bufToB64u(cred.rawId),attestationObject:bufToB64u(cred.response.attestationObject),clientDataJson:bufToB64u(cred.response.clientDataJSON),displayName:name,csrf:csrf};
  var f=await fetch('/admin/devices/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  var j=await f.json();if(j.ok)location.reload();else alert('Registration failed: '+(j.error||''));
 }catch(e){alert('Registration cancelled: '+e);}
}
async function kalitkaApprove(id,verb,csrf){
 try{
  var r=await fetch('/admin/requests/'+encodeURIComponent(id)+'/approve/begin?verb='+encodeURIComponent(verb),{method:'POST',headers:{'X-Csrf':csrf}});
  if(!r.ok){var je=await r.json().catch(function(){return{};});alert('Could not start: '+(je.error||r.status));return;}
  var d=await r.json();var o=d.options;
  o.challenge=b64uToBuf(o.challenge);
  if(o.allowCredentials)o.allowCredentials=o.allowCredentials.map(function(c){return{type:c.type,id:b64uToBuf(c.id)};});
  var asr=await navigator.credentials.get({publicKey:o});
  var body={id:id,verb:verb,state:d.state,credentialId:bufToB64u(asr.rawId),authenticatorData:bufToB64u(asr.response.authenticatorData),clientDataJson:bufToB64u(asr.response.clientDataJSON),signature:bufToB64u(asr.response.signature),csrf:csrf};
  var f=await fetch('/admin/requests/decide-signed',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  var j=await f.json();if(j.ok)location.href='/admin/requests';else alert('Signature failed: '+(j.error||''));
 }catch(e){alert('Approval cancelled: '+e);}
}
</script>";

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

    public static string Agents(AdminIdentity who, IReadOnlyList<Agent> agents,
        IReadOnlyList<AgentProfile> profiles, string csrf, string tagFilter)
    {
        var sb = new StringBuilder("<h1>Agents</h1>");

        // Create form. From a profile (pick one + a hostname; its templates expand
        // and are snapshotted onto the agent), or free-form. Two ways to provision:
        // a secret shown once, or a single-use enrollment token.
        sb.Append("<h2>New agent</h2>")
          .Append("<form method=\"post\" action=\"/admin/agents/create\">")
          .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
          .Append("<select name=\"profile\" style=\"display:block;width:100%;max-width:420px;margin:6px 0;padding:8px;"
              + "border-radius:8px;border:1px solid #2a3140;background:#0f1117;color:#e6e6e6\">")
          .Append("<option value=\"\">— no profile (free-form below) —</option>");
        foreach (var p in profiles) sb.Append($"<option value=\"{H(p.Name)}\">{H(p.Name)}</option>");
        sb.Append("</select>")
          .Append(In("hostname", "hostname — fills {hostname} in profile templates"))
          .Append(In("display_name", "name (free-form; defaults to hostname)"))
          .Append(In("platform", "platform (free-form only: linux, windows, …)"))
          .Append(In("capabilities", "capabilities (free-form only: access.request grant.redeem …)"))
          .Append(In("allowed_resources", "allowed resources (free-form only: ssh:prod-01 ssh:*)"))
          .Append(In("tags", "tags (free-form only: env:prod role:web)"))
          .Append("<div class=\"btns\">")
          .Append("<button name=\"mode\" value=\"create\">Create (show secret once)</button>")
          .Append("<button class=\"mut\" name=\"mode\" value=\"token\">Enrollment token</button>")
          .Append("</div></form>");

        sb.Append("<h2>Registered</h2>");
        sb.Append("<form method=\"get\" action=\"/admin/agents\" style=\"margin-bottom:12px\">")
          .Append($"<input name=\"tag\" value=\"{H(tagFilter)}\" placeholder=\"filter by tag (e.g. env:prod)\" "
              + "style=\"width:auto;display:inline-block;margin-right:8px;padding:8px;border-radius:8px;"
              + "border:1px solid #2a3140;background:#0f1117;color:#e6e6e6\">")
          .Append("<button style=\"width:auto\">Filter</button></form>");

        if (agents.Count == 0)
            sb.Append("<p class=\"muted\">No agents.</p>");
        else
        {
            sb.Append("<table><tr><th>Name</th><th>Platform</th><th>Resources</th>"
                + "<th>Tags</th><th>Auth</th><th>Status</th><th>Last seen</th><th></th></tr>");
            foreach (var a in agents)
                sb.Append("<tr>")
                  .Append($"<td>{H(a.DisplayName)}<br><span class=\"muted\">{H(a.Hostname)}</span></td>")
                  .Append($"<td>{H(a.Platform)}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", a.AllowedResources))}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", a.Tags))}</td>")
                  .Append($"<td>{AuthBadge(a)}</td>")
                  .Append($"<td>{StatusPill(a.Status)}</td>")
                  .Append($"<td class=\"muted\">{Seen(a.LastSeenAt)}</td>")
                  .Append($"<td><a class=\"row\" href=\"/admin/agents/{H(a.Id)}\">open →</a></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        return Shell(who, sb.ToString());
    }

    public static string Profiles(AdminIdentity who, IReadOnlyList<AgentProfile> profiles, string csrf)
    {
        var sb = new StringBuilder("<h1>Profiles</h1>")
          .Append("<p class=\"muted\">A profile is a template + classification. Its resource templates "
              + "(<code>ssh:{hostname}</code>) are expanded and <b>snapshotted onto the agent</b> at create/enroll; "
              + "editing a profile does not change agents already created from it.</p>");

        sb.Append("<h2>New profile</h2>")
          .Append("<form method=\"post\" action=\"/admin/profiles/create\">")
          .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
          .Append(In("name", "name (e.g. linux-server)"))
          .Append(In("platform", "platform (linux, windows, …)"))
          .Append(In("capabilities", "capabilities (access.request grant.redeem session.end)"))
          .Append(In("resource_templates", "resource templates (ssh:{hostname} sudo:{hostname})"))
          .Append(In("tags", "tags (env:prod role:web)"))
          .Append("<div class=\"btns\"><button>Save profile</button></div></form>");

        sb.Append("<h2>Profiles</h2>");
        if (profiles.Count == 0)
            sb.Append("<p class=\"muted\">No profiles yet.</p>");
        else
        {
            sb.Append("<table><tr><th>Name</th><th>Platform</th><th>Capabilities</th>"
                + "<th>Resource templates</th><th>Tags</th><th></th></tr>");
            foreach (var p in profiles)
                sb.Append("<tr>")
                  .Append($"<td><code>{H(p.Name)}</code></td>")
                  .Append($"<td>{H(p.Platform)}</td>")
                  .Append($"<td>{Caps(p.Capabilities)}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", p.ResourceTemplates))}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", p.Tags))}</td>")
                  .Append("<td><form class=\"inline\" method=\"post\" action=\"/admin/profiles/delete\">"
                      + $"<input type=\"hidden\" name=\"name\" value=\"{H(p.Name)}\">"
                      + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
                      + "<button class=\"no\">Delete</button></form></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        return Shell(who, sb.ToString());
    }

    // ---- Sessions -----------------------------------------------------------

    public static string Sessions(AdminIdentity who, IReadOnlyList<SessionRecord> sessions, string csrf)
    {
        var sb = new StringBuilder("<h1>Sessions</h1>")
          .Append("<p class=\"muted\">Redeemed grants that became real sessions — the proof access happened, "
              + "not just that it was approved. Open sessions can be revoked; a session left open past its max "
              + "lifetime is auto-closed as <code>expired</code>.</p>");

        if (sessions.Count == 0)
            return Shell(who, sb.Append("<p class=\"muted\">No sessions.</p>").ToString());

        sb.Append("<table><tr><th>Subject</th><th>Resource</th><th>Profile</th><th>Agent</th><th>Started (UTC)</th>"
            + "<th>State</th><th>Request</th><th></th></tr>");
        foreach (var s in sessions)
        {
            var open = s.EndedAt is null;
            var state = open ? "<span class=\"pill approved\">open</span>"
                : $"<span class=\"pill denied\">{H(s.Outcome.Length == 0 ? "closed" : s.Outcome)}</span>";
            var profile = s.Profile.Length == 0 ? "<span class=\"muted\">—</span>"
                : $"<code>{H(s.Profile)}</code>" + (s.RemainingUses >= 0 ? $" <span class=\"muted\">{s.RemainingUses} left</span>" : "");
            sb.Append("<tr>")
              .Append($"<td>{H(s.Subject)}</td>")
              .Append($"<td><code>{H(s.Resource)}</code></td>")
              .Append($"<td>{profile}</td>")
              .Append($"<td class=\"muted\">{H(s.AgentId)}</td>")
              .Append($"<td class=\"muted\">{s.StartedAt:yyyy-MM-dd HH:mm:ss}</td>")
              .Append($"<td>{state}</td>")
              .Append($"<td class=\"muted\"><code>{H(Short(s.RequestId))}</code></td>")
              .Append(open
                  ? "<td><form class=\"inline\" method=\"post\" action=\"/admin/sessions/revoke\">"
                    + $"<input type=\"hidden\" name=\"id\" value=\"{H(s.SessionId)}\">"
                    + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
                    + "<button class=\"no\">Revoke</button></form></td>"
                  : "<td></td>")
              .Append("</tr>");
        }
        sb.Append("</table>");
        return Shell(who, sb.ToString());
    }

    // ---- Access policies ----------------------------------------------------

    public static string Policies(AdminIdentity who, IReadOnlyList<AccessPolicy> policies, string csrf)
    {
        var sb = new StringBuilder("<h1>Policies</h1>")
          .Append("<p class=\"muted\">A policy only <b>restricts</b> — it can require more approvals "
              + "or shorten the grant, never grant new access. It matches a request by resource "
              + "(<code>ssh:*</code>) and tags that must all be on the requesting agent "
              + "(<code>env:prod</code>). Several matching policies combine the strictest way "
              + "(most approvals, shortest grant).</p>");

        sb.Append("<h2>New policy</h2>")
          .Append("<form method=\"post\" action=\"/admin/policies/create\">")
          .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
          .Append(In("name", "name (e.g. prod-ssh)"))
          .Append(In("match_resource", "match resource (ssh:*  |  db:sql01/*  |  *)"))
          .Append(In("match_tags", "match tags — all required (env:prod role:web)"))
          .Append(In("match_profile", "match grant profile (e.g. sql-dba, sql-*; blank = any)"))
          .Append(In("required", "required approvals (e.g. 2)"))
          .Append(In("grant_ttl", "grant TTL minutes (0 = no override)"))
          .Append(In("allowed_principals", "allowed principals — logins this policy permits (deploy readonly); blank = any"))
          .Append("<label class=\"muted\" style=\"display:block;margin:6px 0\">"
              + "<input type=\"checkbox\" name=\"require_command\"> require a command (no open shell — SSH cert force-command only)</label>")
          .Append("<label class=\"muted\" style=\"display:block;margin:6px 0\">"
              + "<input type=\"checkbox\" name=\"require_source\"> require a source address (pin the SSH cert to an approved CIDR)</label>")
          .Append("<label class=\"muted\" style=\"display:block;margin:6px 0\">subject approval "
              + "<select name=\"subject\">"
              + "<option value=\"optional\">optional — may approve, counts as one</option>"
              + "<option value=\"required\">required — the subject must approve (trusted assertion)</option>"
              + "<option value=\"forbidden\">forbidden — the requester may not approve (four-eyes)</option>"
              + "</select></label>")
          .Append("<div class=\"btns\"><button>Save policy</button></div></form>");

        sb.Append("<h2>Policies</h2>");
        if (policies.Count == 0)
            sb.Append("<p class=\"muted\">No policies yet — every request needs one approval and the default grant lifetime.</p>");
        else
        {
            sb.Append("<table><tr><th>Name</th><th>Resource</th><th>Tags</th><th>Profile</th>"
                + "<th>Approvals</th><th>Grant TTL</th><th>Command</th><th>Source</th><th>Principals</th><th>Subject</th><th></th></tr>");
            foreach (var p in policies)
                sb.Append("<tr>")
                  .Append($"<td><code>{H(p.Name)}</code></td>")
                  .Append($"<td><code>{H(p.MatchResource)}</code></td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", p.MatchTags))}</td>")
                  .Append($"<td class=\"muted\">{(p.MatchProfile.Length == 0 ? "—" : H(p.MatchProfile))}</td>")
                  .Append($"<td>{p.RequiredApprovals}</td>")
                  .Append($"<td class=\"muted\">{(p.GrantTtlMinutes > 0 ? p.GrantTtlMinutes + " min" : "—")}</td>")
                  .Append($"<td class=\"muted\">{(p.RequireCommand ? "required" : "—")}</td>")
                  .Append($"<td class=\"muted\">{(p.RequireSourceAddress ? "required" : "—")}</td>")
                  .Append($"<td class=\"muted\">{(p.AllowedPrincipals.Length == 0 ? "—" : H(string.Join(" ", p.AllowedPrincipals)))}</td>")
                  .Append($"<td class=\"muted\">{(p.Subject == SubjectApproval.Optional ? "—" : H(p.Subject.ToString().ToLowerInvariant()))}</td>")
                  .Append("<td><form class=\"inline\" method=\"post\" action=\"/admin/policies/delete\">"
                      + $"<input type=\"hidden\" name=\"name\" value=\"{H(p.Name)}\">"
                      + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
                      + "<button class=\"no\">Delete</button></form></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }

        return Shell(who, sb.ToString());
    }

    /// <summary>Read-only "why would this be decided this way" — the deterministic trace for a
    /// concrete request context. No AI: it renders <see cref="PolicyService.Explain"/> straight,
    /// which is the same composition the request engine uses.</summary>
    public static string Explain(AdminIdentity who, string resource, string tags, string profile, PolicyExplanation? ex)
    {
        var sb = new StringBuilder("<h1>Policy explain</h1>")
          .Append("<p class=\"muted\">Enter a request context — the resource, the requesting agent's "
              + "tags, and (optionally) the grant profile — to see exactly which policies match and "
              + "the effective decision, attributed to the policy that set each value. This is the "
              + "same composition the engine uses to decide a real request.</p>");

        // GET form so the trace is a shareable URL; values persist across submits.
        sb.Append("<form method=\"get\" action=\"/admin/policies/explain\">")
          .Append(InVal("resource", "resource (ssh:prod-01  |  db:sql01/orders  |  mcp:github/merge_pull_request)", resource))
          .Append(InVal("tags", "agent tags — space separated (env:prod role:web)", tags))
          .Append(InVal("profile", "grant profile (optional, e.g. sql-dba)", profile))
          .Append("<div class=\"btns\"><button>Explain</button></div></form>");

        if (ex is not null)
        {
            var d = ex.Effective;
            sb.Append("<h2>Effective decision</h2>");
            if (ex.Considered.All(c => !c.Matched))
                sb.Append("<p class=\"muted\">No policy matches this context — the request would need "
                    + "one approval and the default grant lifetime.</p>");
            else
            {
                sb.Append("<table><tr><th>Value</th><th>Effective</th><th>From</th></tr>");
                foreach (var s in ex.Sources)
                    sb.Append("<tr>")
                      .Append($"<td class=\"muted\">{H(s.Field)}</td>")
                      .Append($"<td><code>{H(s.Value)}</code></td>")
                      .Append($"<td>{string.Join(" ", s.FromPolicies.Select(n => $"<code>{H(n)}</code>"))}</td>")
                      .Append("</tr>");
                sb.Append("</table>");
            }

            sb.Append("<h2>Policies considered</h2>")
              .Append("<table><tr><th>Name</th><th>Rev</th><th>Matched</th><th>Reason</th></tr>");
            foreach (var c in ex.Considered)
                sb.Append("<tr>")
                  .Append($"<td><code>{H(c.Name)}</code></td>")
                  .Append($"<td class=\"muted\">{c.Revision}</td>")
                  .Append($"<td>{(c.Matched ? "<span class=\"pill approved\">match</span>" : "<span class=\"pill\" style=\"background:#222833;color:#6b7280\">no</span>")}</td>")
                  .Append($"<td class=\"muted\">{H(c.Reason)}</td>")
                  .Append("</tr>");
            sb.Append("</table>");
            if (ex.Considered.Length == 0)
                sb.Append("<p class=\"muted\">No policies defined.</p>");
        }

        return Shell(who, sb.ToString());
    }

    // Like In(), but pre-filled — GET forms keep what the operator typed.
    private static string InVal(string name, string placeholder, string value) =>
        $"<input name=\"{name}\" placeholder=\"{H(placeholder)}\" value=\"{H(value)}\" "
        + "style=\"display:block;width:100%;max-width:520px;margin:6px 0;padding:8px;border-radius:8px;"
        + "border:1px solid #2a3140;background:#0f1117;color:#e6e6e6\">";

    /// <summary>The raw draft fields, echoed back to refill the form and carried into the apply POST.</summary>
    public sealed record CopilotDraft(string Mode, string Name, string Resource, string Tags, string Required, string Ttl, string Subject);

    /// <summary>The policy copilot's Draft/Change surface: propose a change, see its deterministic
    /// impact across the fleet (via simulate), and apply it — with an explicit confirmation whenever
    /// it expands effective authority. No AI here yet: this is the "kalitka produces authority" half
    /// that any intent-producer (a human now, an LLM later) feeds into.</summary>
    public static string Copilot(AdminIdentity who, CopilotDraft d, CopilotPreview? preview, string csrf)
    {
        var sb = new StringBuilder("<h1>Policy copilot</h1>")
          .Append("<p class=\"muted\">Propose a change and see exactly what it does to every agent "
              + "before it happens — the same deterministic simulate the engine uses. A change that "
              + "<b>expands</b> anyone's effective authority (fewer approvers, longer grant, a dropped "
              + "constraint) requires an explicit confirmation. <i>AI produces intent, kalitka produces "
              + "authority</i> — a natural-language drafter plugs in on top of this later.</p>");

        var isRemove = d.Mode == "remove";
        sb.Append("<h2>Draft a change</h2>")
          .Append("<form method=\"get\" action=\"/admin/policies/copilot\">")
          .Append("<label class=\"muted\" style=\"display:block;margin:6px 0\">change "
              + "<select name=\"mode\">"
              + $"<option value=\"upsert\"{(isRemove ? "" : " selected")}>create or update a policy</option>"
              + $"<option value=\"remove\"{(isRemove ? " selected" : "")}>delete a policy</option>"
              + "</select></label>")
          .Append(InVal("name", "policy name", d.Name));
        if (!isRemove)
            sb.Append(InVal("match_resource", "match resource (ssh:*  |  db:sql01/*  |  *)", d.Resource))
              .Append(InVal("match_tags", "match tags — all required (env:prod role:web)", d.Tags))
              .Append(InVal("required", "required approvals (e.g. 2)", d.Required))
              .Append(InVal("grant_ttl", "grant TTL minutes (0 = no override)", d.Ttl))
              .Append("<label class=\"muted\" style=\"display:block;margin:6px 0\">subject approval "
                  + "<select name=\"subject\">"
                  + Opt("optional", d.Subject) + Opt("required", d.Subject) + Opt("forbidden", d.Subject)
                  + "</select></label>");
        sb.Append("<div class=\"btns\"><button>Preview impact</button></div></form>");

        if (preview is not null)
        {
            sb.Append("<h2>Impact</h2>")
              .Append($"<p>{ImpactPill(preview.Overall)} "
                  + $"<span class=\"muted\">across {preview.Affected.Length} affected agent(s)</span></p>");

            if (preview.Affected.Length > 0)
            {
                sb.Append("<table><tr><th>Agent</th><th>Tags</th><th>Change</th></tr>");
                foreach (var a in preview.Affected)
                    sb.Append("<tr>")
                      .Append($"<td><code>{H(a.DisplayName)}</code></td>")
                      .Append($"<td class=\"muted\">{H(string.Join(" ", a.Tags))}</td>")
                      .Append($"<td>{Deltas(a.Impact.Deltas)}</td>")
                      .Append("</tr>");
                sb.Append("</table>");
            }

            // Apply form carries the draft forward; expansion requires the confirm checkbox.
            sb.Append("<form method=\"post\" action=\"/admin/policies/copilot/apply\">")
              .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
              .Append(Hidden("mode", d.Mode)).Append(Hidden("name", d.Name)).Append(Hidden("match_resource", d.Resource))
              .Append(Hidden("match_tags", d.Tags)).Append(Hidden("required", d.Required)).Append(Hidden("grant_ttl", d.Ttl))
              .Append(Hidden("subject", d.Subject));
            if (preview.RequiresApproval)
                sb.Append("<label style=\"display:block;margin:10px 0;color:#ff8a8a\">"
                    + "<input type=\"checkbox\" name=\"confirm_expansion\" value=\"true\"> "
                    + "I confirm this <b>expands effective authority</b> and should still be applied.</label>");
            sb.Append($"<div class=\"btns\"><button class=\"{(preview.RequiresApproval ? "no" : "ok")}\">Apply change</button></div></form>");
        }

        return Shell(who, sb.ToString());

        static string Opt(string v, string sel) => $"<option value=\"{v}\"{(v == sel ? " selected" : "")}>{v}</option>";
        static string Hidden(string n, string v) => $"<input type=\"hidden\" name=\"{n}\" value=\"{H(v)}\">";
    }

    private static string ImpactPill(PolicyImpactClass c) => c switch
    {
        PolicyImpactClass.NoChange => "<span class=\"pill\" style=\"background:#222833;color:#6b7280\">no effective change</span>",
        PolicyImpactClass.Restriction => "<span class=\"pill approved\">restriction</span>",
        PolicyImpactClass.AuthorityExpansion => "<span class=\"pill denied\">authority expansion</span>",
        _ => "<span class=\"pill priv\">mixed change</span>",
    };

    private static string Deltas(FieldDelta[] deltas)
    {
        if (deltas.Length == 0) return "<span class=\"muted\">—</span>";
        var sb = new StringBuilder();
        foreach (var d in deltas)
            sb.Append($"<span class=\"muted\">{H(d.Field)}:</span> <code>{H(d.Before)}</code> → <code>{H(d.After)}</code> ")
              .Append(d.Class == PolicyImpactClass.AuthorityExpansion ? "<span class=\"pill denied\">expand</span> "
                  : d.Class == PolicyImpactClass.Restriction ? "<span class=\"pill approved\">restrict</span> "
                  : d.Class == PolicyImpactClass.MixedChange ? "<span class=\"pill priv\">mixed</span> " : "")
              .Append("<br>");
        return sb.ToString();
    }

    /// <summary>Audit integrity: the hash-chain verification result and a signed checkpoint over the
    /// head — the exportable proof that the log has not been altered, reordered or truncated.</summary>
    public static string AuditIntegrity(AdminIdentity who, AuditVerification v, Kalitka.AuditIntegrity.Checkpoint? checkpoint)
    {
        var sb = new StringBuilder("<h1>Audit integrity</h1>")
          .Append("<p class=\"muted\">Every audit event is chained to the one before it by hash, so the "
              + "history cannot be altered or reordered without breaking the chain. A signed checkpoint over "
              + "the head also catches truncation. This is what a compliance export rests on.</p>");

        sb.Append("<h2>Chain</h2><table>")
          .Append($"<tr><th>Status</th><td>{(v.Intact ? "<span class=\"pill approved\">intact</span>" : "<span class=\"pill denied\">TAMPERED</span>")}</td></tr>")
          .Append($"<tr><th>Events checked</th><td>{v.Checked}</td></tr>")
          .Append($"<tr><th>Head seq</th><td>{v.HeadSeq}</td></tr>")
          .Append($"<tr><th>Head hash</th><td><code>{H(v.HeadHash)}</code></td></tr>");
        if (!v.Intact && v.FirstBadSeq is { } bad)
            sb.Append($"<tr><th>First bad link</th><td><span class=\"pill denied\">seq {bad}</span></td></tr>");
        sb.Append("</table>");

        if (checkpoint is not null)
            sb.Append("<h2>Signed checkpoint</h2>")
              .Append("<p class=\"muted\">Signed by the server key now; keep it to prove later that the log "
                  + "up to this point existed and has not been truncated.</p>")
              .Append("<table>")
              .Append($"<tr><th>Seq</th><td>{checkpoint.Seq}</td></tr>")
              .Append($"<tr><th>Hash</th><td><code>{H(checkpoint.Hash)}</code></td></tr>")
              .Append($"<tr><th>Signed at</th><td class=\"muted\">{checkpoint.SignedAt:yyyy-MM-dd HH:mm} UTC</td></tr>")
              .Append($"<tr><th>Token</th><td><code style=\"word-break:break-all\">{H(checkpoint.Token)}</code></td></tr>")
              .Append("</table>");
        else if (v.Intact)
            sb.Append("<p class=\"muted\">No events yet — nothing to checkpoint.</p>");

        return Shell(who, sb.ToString());
    }

    // ---- Operator principals (who counts as a distinct approver) -------------

    public static string Principals(AdminIdentity who, IReadOnlyList<OperatorPrincipal> principals, string csrf)
    {
        var sb = new StringBuilder("<h1>Operators</h1>");
        sb.Append("<p class=\"muted\">An operator is one person across channels. Linking their "
            + "identities lets a Telegram (later Slack/Teams/app) approval count in a quorum, and the "
            + "same person on two channels count once. Identities are <code>scheme:value</code> — "
            + "<code>google:&lt;sub&gt;</code>, <code>telegram:&lt;user_id&gt;</code>, "
            + "<code>slack:&lt;team&gt;:&lt;user&gt;</code>, <code>app:&lt;id&gt;</code>. "
            + "An unlinked Google admin still counts as itself; other unlinked channels do not.</p>");

        sb.Append("<h2>New / update operator</h2>")
          .Append("<form method=\"post\" action=\"/admin/principals/create\">")
          .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
          .Append(In("id", "id (stable slug, e.g. sergej)"))
          .Append(In("display", "display name (e.g. Sergej D.)"))
          .Append(In("identities", "identities — space-separated (google:1234 telegram:98765)"))
          .Append("<div class=\"btns\"><button>Save operator</button></div></form>");

        sb.Append("<h2>Operators</h2>");
        if (principals.Count == 0)
            sb.Append("<p class=\"muted\">No operators yet — a quorum currently counts only Google admins (each as itself).</p>");
        else
        {
            sb.Append("<table><tr><th>Id</th><th>Name</th><th>Identities</th><th></th></tr>");
            foreach (var p in principals)
                sb.Append("<tr>")
                  .Append($"<td><code>{H(p.Id)}</code></td>")
                  .Append($"<td>{H(p.DisplayName)}</td>")
                  .Append($"<td class=\"muted\">{H(string.Join(" ", p.Identities))}</td>")
                  .Append("<td><form class=\"inline\" method=\"post\" action=\"/admin/principals/delete\">"
                      + $"<input type=\"hidden\" name=\"id\" value=\"{H(p.Id)}\">"
                      + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">"
                      + "<button class=\"no\">Delete</button></form></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }
        return Shell(who, sb.ToString());
    }

    public static string AgentDetail(AdminIdentity who, Agent a, string csrf, ReconcileService.Plan? drift = null)
    {
        var sb = new StringBuilder($"<h1>Agent <code>{H(a.DisplayName)}</code></h1>");
        sb.Append("<table>")
          .Append($"<tr><th>Id</th><td><code>{H(a.Id)}</code></td></tr>")
          .Append($"<tr><th>Status</th><td>{StatusPill(a.Status)}</td></tr>")
          .Append($"<tr><th>Platform</th><td>{H(a.Platform)}</td></tr>")
          .Append($"<tr><th>Hostname</th><td>{H(a.Hostname)}</td></tr>")
          .Append($"<tr><th>Capabilities</th><td>{Caps(a.Capabilities)}</td></tr>")
          .Append($"<tr><th>Resources</th><td><code>{H(string.Join(" ", a.AllowedResources))}</code></td></tr>")
          .Append($"<tr><th>Tags</th><td class=\"muted\">{H(string.Join(" ", a.Tags))}</td></tr>")
          .Append(string.IsNullOrEmpty(a.ProfileId) ? ""
              : $"<tr><th>Profile</th><td><code>{H(a.ProfileId)}</code> <span class=\"muted\">@ {H(a.ProfileHostname)}, rev {a.AppliedProfileRevision}</span></td></tr>")
          .Append($"<tr><th>Created</th><td class=\"muted\">{a.CreatedAt:yyyy-MM-dd HH:mm} UTC</td></tr>")
          .Append($"<tr><th>Auth</th><td>{AuthBadge(a)}{(a.LastSignedAt is { } ls ? $" <span class=\"muted\">· last signed {ls:yyyy-MM-dd HH:mm} UTC</span>" : "")}</td></tr>")
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

        if (drift is not null && drift.HasChanges)
        {
            sb.Append("<h2>Profile drift</h2>")
              .Append($"<p class=\"muted\">Profile <code>{H(drift.ProfileId)}</code> changed (rev {drift.FromRevision}→{drift.ToRevision}). "
                  + "Applying updates this agent; any local overrides are kept"
                  + (drift.IsExpansion ? ", and this <b>grants new access</b> — confirm to apply." : ".") + "</p>")
              .Append($"<p>{Changes(drift)}</p>")
              .Append(ApplyForm(drift, csrf));
        }

        // Signing keys (0.20): an agent with a registered key signs its requests
        // instead of sending the shared secret.
        sb.Append("<h2>Signing keys</h2>");
        if (string.IsNullOrEmpty(a.SecretHash))
            sb.Append("<p class=\"muted\">Secretless — this agent has no usable shared secret and can authenticate only by signature.</p>");
        if (a.Keys.Count == 0)
            sb.Append("<p class=\"muted\">None — this agent still authenticates with its shared secret.</p>");
        else
        {
            sb.Append("<table><tr><th>Key id</th><th>Public key (SPKI)</th><th>Provider</th><th>Assurance</th><th>Added</th><th></th></tr>");
            foreach (var k in a.Keys)
                sb.Append("<tr>")
                  .Append($"<td><code>{H(k.KeyId)}</code></td>")
                  .Append($"<td class=\"muted\"><code>{H(k.PublicKey)}</code></td>")
                  .Append($"<td class=\"muted\">{H(ProviderLabel(k))}</td>")
                  .Append($"<td class=\"muted\">{H(k.Assurance)}</td>")
                  .Append($"<td class=\"muted\">{k.AddedAt:yyyy-MM-dd HH:mm} UTC</td>")
                  .Append(a.Status == AgentStatus.Revoked ? "<td></td>"
                      : "<td><form class=\"inline\" method=\"post\" action=\"" + $"/admin/agents/{H(a.Id)}/action" + "\">"
                        + $"<input type=\"hidden\" name=\"verb\" value=\"removekey\"><input type=\"hidden\" name=\"key_id\" value=\"{H(k.KeyId)}\">"
                        + $"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\"><button class=\"no\">Remove</button></form></td>")
                  .Append("</tr>");
            sb.Append("</table>");
        }
        if (a.Status != AgentStatus.Revoked)
            sb.Append("<form method=\"post\" action=\"" + $"/admin/agents/{H(a.Id)}/action" + "\" style=\"margin-top:10px\">")
              .Append($"<input type=\"hidden\" name=\"verb\" value=\"addkey\"><input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
              .Append(In("public_key", "public key — SPKI (base64)"))
              .Append("<div class=\"btns\"><button>Add key</button></div></form>");

        sb.Append("<p style=\"margin-top:18px\"><a class=\"row\" href=\"/admin/agents\">← back</a></p>");
        return Shell(who, sb.ToString());
    }

    // ---- Reconcile ----------------------------------------------------------

    public static string Reconcile(AdminIdentity who, IReadOnlyList<ReconcileService.Plan> plans, string csrf)
    {
        var sb = new StringBuilder("<h1>Reconcile</h1>")
          .Append("<p class=\"muted\">Profile changes reach already-enrolled agents only here, deliberately. "
              + "A change that <b>grants</b> a new capability or resource (an expansion) must be confirmed; "
              + "removals and tag changes apply directly. Local overrides on an agent are preserved.</p>");

        if (plans.Count == 0)
            return Shell(who, sb.Append("<p class=\"muted\">All profile-managed agents are in sync.</p>").ToString());

        var safe = plans.Count(p => !p.IsExpansion);
        if (safe > 0)
            sb.Append("<form method=\"post\" action=\"/admin/reconcile/apply-safe\">")
              .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">")
              .Append($"<div class=\"btns\"><button class=\"ok\">Apply all {safe} safe change(s)</button></div>")
              .Append("<p class=\"muted\">Safe = removals, tag changes and revision bumps only. Expansions are applied per agent below.</p></form>");

        sb.Append("<table><tr><th>Agent</th><th>Profile</th><th>Change</th><th></th></tr>");
        foreach (var p in plans)
            sb.Append("<tr>")
              .Append($"<td><a class=\"row\" href=\"/admin/agents/{H(p.AgentId)}\">{H(p.AgentId)}</a><br><span class=\"muted\">{H(p.Hostname)}</span></td>")
              .Append($"<td><code>{H(p.ProfileId)}</code><br><span class=\"muted\">rev {p.FromRevision}→{p.ToRevision}</span></td>")
              .Append($"<td>{Changes(p)}{(p.IsExpansion ? " <span class=\"pill denied\">expansion</span>" : "")}"
                    + $"{(p.TouchesPrivileged ? " <span class=\"pill priv\" title=\"sudo-grade capability granted/revoked\">privileged</span>" : "")}</td>")
              .Append($"<td>{ApplyForm(p, csrf)}</td>")
              .Append("</tr>");
        sb.Append("</table>");
        return Shell(who, sb.ToString());
    }

    /// <summary>The +added / -removed tokens for one plan, grouped by kind.</summary>
    private static string Changes(ReconcileService.Plan p)
    {
        var sb = new StringBuilder();
        Group(sb, "caps", p.AddedCapabilities, p.RemovedCapabilities);
        Group(sb, "res", p.AddedResources, p.RemovedResources);
        Group(sb, "tags", p.AddedTags, p.RemovedTags);
        if (sb.Length == 0) sb.Append("<span class=\"muted\">revision only</span>");
        return sb.ToString();

        static void Group(StringBuilder sb, string label, string[] added, string[] removed)
        {
            if (added.Length == 0 && removed.Length == 0) return;
            sb.Append($"<span class=\"muted\">{label}:</span> ");
            // A '!' marks a sudo-grade capability so it reads distinctly even inline.
            foreach (var a in added)
                sb.Append(AgentCapabilities.IsPrivileged(a)
                    ? $"<code class=\"add priv\">+!{H(a)}</code> " : $"<code class=\"add\">+{H(a)}</code> ");
            foreach (var r in removed)
                sb.Append(AgentCapabilities.IsPrivileged(r)
                    ? $"<code class=\"rem priv\">-!{H(r)}</code> " : $"<code class=\"rem\">-{H(r)}</code> ");
        }
    }

    /// <summary>Apply button for one plan. An expansion carries a required confirm
    /// checkbox (the server enforces it regardless).</summary>
    private static string ApplyForm(ReconcileService.Plan p, string csrf)
    {
        var sb = new StringBuilder("<form class=\"inline\" method=\"post\" action=\"/admin/reconcile/apply\">")
          .Append($"<input type=\"hidden\" name=\"agent\" value=\"{H(p.AgentId)}\">")
          .Append($"<input type=\"hidden\" name=\"csrf\" value=\"{H(csrf)}\">");
        if (p.IsExpansion)
            sb.Append("<label class=\"muted\" style=\"margin-right:6px\"><input type=\"checkbox\" name=\"confirm\" value=\"1\" required> confirm</label>")
              .Append("<button class=\"no\">Apply</button>");
        else
            sb.Append("<button class=\"ok\">Apply</button>");
        return sb.Append("</form>").ToString();
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

    // How the agent last authenticated — signature (green, migrated) vs secret (amber,
    // still on the fallback), so an operator can see who is left before dropping secrets.
    private static string AuthBadge(Agent a) => a.LastAuthMethod switch
    {
        "signature" => "<span class=\"pill approved\">signature</span>"
            + (string.IsNullOrEmpty(a.LastKeyId) ? "" : $" <span class=\"muted\">{H(a.LastKeyId)}</span>"),
        "secret" => "<span class=\"pill waiting\">secret</span>",
        _ => "<span class=\"muted\">—</span>",
    };

    private static string Seen(DateTimeOffset? at) => at is null ? "never" : $"{at:yyyy-MM-dd HH:mm} UTC";

    // ---- bits ---------------------------------------------------------------

    private static string Place(PendingView r) =>
        string.IsNullOrEmpty(r.CountryCode) ? "(private/unknown)"
        : $"{r.City}, {r.Country} [{r.CountryCode}]";

    private static string Pill(string state) =>
        $"<span class=\"pill {state}\">{H(state)}</span>";
}
