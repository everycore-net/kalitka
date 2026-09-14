using System.Net;
using System.Text;
using Kalitka.Text;

namespace Kalitka;

/// <summary>
/// The installable PWA: a focused operator surface — the requests waiting for you, approved by
/// touching a registered device, with Web Push so the phone rings without Telegram or an app store.
/// Server-rendered and self-contained like the rest of the control plane; the only client behaviour
/// is the WebAuthn ceremony (shared with the admin pages) and the push subscription.
/// </summary>
public static class AppPages
{
    private static string H(string s) => WebUtility.HtmlEncode(s);
    private static string Safe(string s, FieldKind kind) => H(SafeText.ToTextMarkers(SafeText.Render(s, kind)));

    private const string Head =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">"
      + "<meta name=\"robots\" content=\"noindex,nofollow\">"
      + "<meta name=\"theme-color\" content=\"#0f1117\">"
      + "<link rel=\"manifest\" href=\"/manifest.webmanifest\">"
      + "<link rel=\"icon\" type=\"image/png\" href=\"/icon.png\">"
      + "<link rel=\"apple-touch-icon\" href=\"/icon.png\">"
      + "<meta name=\"apple-mobile-web-app-capable\" content=\"yes\">"
      + "<meta name=\"apple-mobile-web-app-title\" content=\"kalitka\">"
      + "<title>kalitka</title><style>"
      + "body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:env(safe-area-inset-top) 0 0}"
      + ".top{display:flex;align-items:center;gap:10px;padding:14px 18px;background:#141821;border-bottom:1px solid #262b36}"
      + ".top b{color:#fff}.top .spacer{flex:1}.top .who{color:#6b7280;font-size:.8rem}"
      + ".wrap{max-width:640px;margin:0 auto;padding:18px}"
      + "h1{font-size:1.15rem;margin:0 0 14px}"
      + ".req{background:#171a22;border:1px solid #262b36;border-radius:14px;padding:16px;margin:0 0 14px}"
      + ".req .t{font-size:1.05rem;color:#fff}.req .m{color:#9aa4b2;font-size:.85rem;margin-top:4px}"
      + ".btns{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}"
      + "button{padding:11px 16px;border:0;border-radius:10px;font-size:.95rem;cursor:pointer;color:#fff;background:#2456A6}"
      + "button.ok{background:#1f7a3d}button.no{background:#8a2323}button.mut{background:#2a3140;color:#cbd3df}"
      + ".muted{color:#6b7280;font-size:.85rem}code{color:#7FB2FF}a{color:#7FB2FF}"
      + "</style></head><body>";

    private const string Foot = "</body></html>";

    public static string Shell(AdminIdentity who, IReadOnlyList<PendingView> pending, string vapidPublicKey, string csrf)
    {
        var waiting = pending.Where(r => r.State == "waiting").ToList();
        var sb = new StringBuilder(Head);
        sb.Append($"<div class=\"top\"><img src=\"/icon.png\" alt=\"\" width=\"24\" height=\"24\"><b>kalitka</b>"
            + "<span class=\"spacer\"></span>"
            + $"<span class=\"who\">{H(who.Email)}</span></div>");
        sb.Append("<div class=\"wrap\">");

        sb.Append("<div class=\"btns\" style=\"margin-bottom:18px\">")
          .Append($"<button class=\"mut\" onclick=\"kalitkaEnablePush('{H(vapidPublicKey)}','{H(csrf)}')\">🔔 Enable notifications on this device</button>")
          .Append("</div>");

        sb.Append("<h1>Waiting for you</h1>");
        if (waiting.Count == 0)
            sb.Append("<p class=\"muted\">Nothing waiting. You can close this — a notification will bring you back.</p>");
        else
            foreach (var r in waiting)
            {
                sb.Append("<div class=\"req\">")
                  .Append($"<div class=\"t\">{Safe(r.Input, FieldKind.FreeText)} <span class=\"muted\">→</span> <code>{Safe(r.Target, FieldKind.SecurityIdentifier)}</code></div>");
                if (!string.IsNullOrEmpty(r.Command))
                    sb.Append($"<div class=\"m\">command: <code>{Safe(r.Command, FieldKind.FreeText)}</code></div>");
                sb.Append($"<div class=\"m\">{H(r.Ip)} · {r.Raised:HH:mm:ss}</div>")
                  .Append("<div class=\"btns\">")
                  .Append($"<button class=\"ok\" onclick=\"kalitkaApprove('{H(r.Id)}','ok','{H(csrf)}')\">🔑 Approve</button>")
                  .Append($"<button class=\"no\" onclick=\"kalitkaApprove('{H(r.Id)}','no','{H(csrf)}')\">🔑 Deny</button>")
                  .Append("</div></div>");
            }

        sb.Append("</div>");
        sb.Append(AdminPages.WebAuthnJs);   // b64u helpers + kalitkaApprove, shared with the admin plane
        sb.Append(PushJs);
        return sb.ToString() + Foot;
    }

    // Register the service worker and subscribe to Web Push. On success the endpoint + keys go to the
    // server, bound to this operator. Reuses b64uToBuf from the shared WebAuthn script.
    private const string PushJs = @"<script>
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(function(){});}
async function kalitkaEnablePush(vapidKey,csrf){
 try{
  if(!('serviceWorker' in navigator)||!('PushManager' in window)){alert('Push is not supported on this browser. On iOS, add kalitka to the Home Screen first.');return;}
  var reg=await navigator.serviceWorker.register('/sw.js');
  var perm=await Notification.requestPermission();
  if(perm!=='granted'){alert('Notifications were not allowed.');return;}
  var sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:b64uToBuf(vapidKey)});
  var j=sub.toJSON();
  var body={endpoint:j.endpoint,p256dh:j.keys.p256dh,auth:j.keys.auth,csrf:csrf};
  var f=await fetch('/admin/app/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  alert(f.ok?'Notifications enabled on this device.':'Could not save the subscription.');
 }catch(e){alert('Could not enable notifications: '+e);}
}
</script>";
}
