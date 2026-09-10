namespace Kalitka;

/// <summary>
/// One line per decision, in a shape you can grep and ship somewhere.
///
/// What goes in: what was decided, about which host, about which client, on
/// whose authority, and why. What never goes in: the HMAC secret, the bot
/// token, cookie values, OAuth codes. An audit log that leaks the keys to the
/// thing it audits is worse than no audit log.
///
/// Identity is recorded because it is the point of the whole exercise — but it
/// is what the visitor *typed*, or the e-mail Google confirmed. Treat it as
/// personal data and keep the retention short.
/// </summary>
public static class Audit
{
    public const string Category = "Kalitka.Audit";

    public static void Decision(ILogger log, string decision, string host, string clientIp,
        string? requestId = null, string? identity = null, string? actor = null, string? reason = null)
    {
        // Structured properties, not string concatenation: this is meant to be
        // read by a machine first and a human second. The actor is typed by
        // channel — telegram:123456789, google:<sub> — so approvers stay
        // distinguishable as more channels appear.
        log.LogInformation(
            "audit decision={Decision} host={Host} clientIp={ClientIp} requestId={RequestId} identity={Identity} actor={Actor} reason={Reason}",
            decision, host, clientIp, requestId ?? "-", identity ?? "-", actor ?? "-", reason ?? "-");
    }
}
