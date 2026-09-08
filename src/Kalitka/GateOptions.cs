namespace Kalitka;

/// <summary>
/// Everything kalitka needs, bound from configuration (environment variables
/// prefixed <c>Kalitka__</c>). Nothing here has a sensible secret default on
/// purpose — the app refuses to start without the mandatory ones.
/// </summary>
public sealed class GateOptions
{
    // ---- Telegram -----------------------------------------------------------

    /// <summary>Bot token from BotFather.</summary>
    public string BotToken { get; set; } = "";

    /// <summary>
    /// Secret URL path the Telegram webhook posts to, e.g. <c>/tg/9f3c...</c>.
    /// A guessable path is the difference between "only Telegram calls this"
    /// and "anyone does".
    /// </summary>
    public string WebhookPath { get; set; } = "";

    /// <summary>
    /// Value Telegram sends in <c>X-Telegram-Bot-Api-Secret-Token</c>. Checked
    /// on every webhook call, so guessing the path alone is not enough.
    /// </summary>
    public string WebhookSecret { get; set; } = "";

    /// <summary>Telegram user IDs allowed to approve, reject and edit lists.</summary>
    public long[] AdminIds { get; set; } = Array.Empty<long>();

    /// <summary>
    /// Fallback chat for notifications. Normally leave empty: requests are sent
    /// to every admin directly, which also works if you add a second operator.
    /// </summary>
    public string ChatId { get; set; } = "";

    // ---- Sessions -----------------------------------------------------------

    /// <summary>
    /// Key the session cookie is signed with. Any long random string. Changing
    /// it invalidates all sessions, which is the emergency "log everyone out".
    /// </summary>
    public string HmacSecret { get; set; } = "";

    public string CookieName { get; set; } = "kalitka";

    /// <summary>
    /// Cookie domain. Use the parent domain (<c>.example.com</c>) so one
    /// approval covers every protected host under it.
    /// </summary>
    public string CookieDomain { get; set; } = "";

    /// <summary>How long an approval lasts. Changeable at runtime via the bot.</summary>
    public int SessionMinutes { get; set; } = 720;

    /// <summary>Lifetime of a pending request. Nobody waits an hour at a door.</summary>
    public int PendingMinutes { get; set; } = 5;

    // ---- Placement ----------------------------------------------------------

    /// <summary>
    /// Public host of kalitka itself, e.g. <c>gate.example.com</c>. Used to
    /// build redirects and the OAuth callback, and to decide which targets are
    /// ours (no open redirect).
    /// </summary>
    public string GateHost { get; set; } = "";

    /// <summary>
    /// Networks that skip the gate entirely, in CIDR form. The forwardAuth is
    /// fail-closed, so this is the tested way back in when something breaks.
    /// Leave empty if the gate has no trusted network.
    /// </summary>
    public string[] BypassNetworks { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Hosts the gate is actually enforced for. Hosts not listed pass straight
    /// through even if the middleware is attached — that is what lets you roll
    /// the middleware out everywhere first and arm it per host later.
    /// </summary>
    public string[] EnforcedHosts { get; set; } = Array.Empty<string>();

    // ---- Storage ------------------------------------------------------------

    public string ListsPath { get; set; } = "/data/lists.json";
    public string EnforcedPath { get; set; } = "/data/enforced.json";
    public string SettingsPath { get; set; } = "/data/settings.json";

    /// <summary>
    /// Secret for the <c>/internal/*</c> endpoints used to arm or disarm hosts
    /// from another service on the same network. Empty disables them.
    /// </summary>
    public string InternalSecret { get; set; } = "";

    // ---- Optional extras ----------------------------------------------------

    /// <summary>
    /// IP geolocation for the notification, <c>{ip}</c> is substituted. Purely
    /// informational: approving blind is worse than approving slowly. Empty
    /// disables the lookup.
    /// </summary>
    public string GeoUrl { get; set; } = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city";

    /// <summary>
    /// Google sign-in as a second way in. Empty client id hides the button and
    /// leaves only the ask-and-wait flow.
    /// Authorised redirect URI at Google: <c>https://{GateHost}/oauth2/callback</c>.
    /// </summary>
    public string GoogleClientId { get; set; } = "";
    public string GoogleClientSecret { get; set; } = "";

    /// <summary>Who may enter via Google: whole domains and/or single addresses.</summary>
    public string[] GoogleDomains { get; set; } = Array.Empty<string>();
    public string[] GoogleEmails { get; set; } = Array.Empty<string>();
}
