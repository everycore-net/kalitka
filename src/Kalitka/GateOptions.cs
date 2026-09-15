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

    /// <summary>
    /// The <b>previous</b> signing secret, accepted on verification only, for a graceful key
    /// rotation. To rotate without logging everyone out: set this to the old <see cref="HmacSecret"/>
    /// and <see cref="HmacSecret"/> to a new value — existing admin/visitor sessions and OAuth state
    /// stay valid through the overlap; new tokens use the new key. Clear it once the window (a session
    /// lifetime) has passed. Empty = no overlap.
    /// </summary>
    public string HmacSecretPrevious { get; set; } = "";

    public string CookieName { get; set; } = "kalitka";

    /// <summary>
    /// Cookie domain, e.g. <c>.example.com</c>. The cookie is set on the parent
    /// domain so the browser carries it to every guarded host under it.
    ///
    /// The cookie is always set on this parent domain so the browser carries it
    /// to the guarded hosts; what a session actually opens is decided by the
    /// host signed into it, not by the cookie's domain — see
    /// <see cref="SessionScope"/>.
    /// </summary>
    public string CookieDomain { get; set; } = "";

    /// <summary>
    /// What a Google sign-in grants. A <b>manual</b> approval is always bound to
    /// the one host it was granted for. This decides the Google path:
    /// <list type="bullet">
    /// <item><c>Application</c> (default) — a session for the one host the sign-in
    /// was for. A sibling host asks again (one click, Google remembers the
    /// account). No host opens another.</item>
    /// <item><c>Domain</c> — one sign-in grants every guarded host under
    /// <see cref="CookieDomain"/>. Convenient when the hosts are equally
    /// sensitive; weigh it when they are not.</item>
    /// </list>
    /// </summary>
    public SessionScope SessionScope { get; set; } = SessionScope.Application;

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
    /// The reverse proxies kalitka sits behind, in CIDR form. Forwarded headers
    /// are honoured <b>only</b> for requests arriving from one of these, and the
    /// client address is then found by walking <c>X-Forwarded-For</c> from the
    /// right past these entries.
    ///
    /// Empty means: trust no headers, decide on the socket address. That is the
    /// safe direction, but behind a proxy it makes every visitor look like the
    /// proxy — which is why <see cref="BypassNetworks"/> without this set is
    /// refused at startup rather than silently letting everyone in.
    /// </summary>
    public string[] TrustedProxies { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Networks that skip the gate entirely, in CIDR form. The forwardAuth is
    /// fail-closed, so this is the tested way back in when something breaks.
    /// Leave empty if the gate has no trusted network.
    /// </summary>
    public string[] BypassNetworks { get; set; } = Array.Empty<string>();

    // ---- Rate limiting ------------------------------------------------------

    /// <summary>
    /// How many times one address may ring within <see cref="RateWindowMinutes"/>.
    /// Beyond that the door simply does not answer: no page, no notification.
    /// <c>/mute</c> is the manual version of this; the limit is what stops the
    /// first hundred rings before you ever reach for it. 0 disables the limit.
    /// </summary>
    public int MaxRequestsPerIp { get; set; } = 5;

    public int RateWindowMinutes { get; set; } = 10;

    /// <summary>
    /// Ceiling on requests waiting for an answer at any moment. Protects the
    /// operator, not the server: nobody triages fifty notifications. 0 disables.
    /// </summary>
    public int MaxPending { get; set; } = 50;

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
    /// SQLite file for the durable audit log. Empty keeps audit in memory (lost on
    /// restart) — fine for a home instance; set a path on the data volume to keep
    /// history across restarts, e.g. <c>/data/audit.db</c>.
    /// </summary>
    public string AuditDbPath { get; set; } = "";

    /// <summary>
    /// SQLite file for the durable live state — pending requests, consumed one-time
    /// tokens (replay), and sessions. Empty keeps all three in memory (today's
    /// behaviour: lost on restart, single instance only). Set a path and the state
    /// survives a restart, and the atomic transitions (resolve-once, redeem-once,
    /// close-once) hold across every process pointed at the same file — the
    /// single-node durable step. For true multi-<i>node</i> use
    /// <see cref="PostgresConnectionString"/> instead.
    /// </summary>
    public string StateDbPath { get; set; } = "";

    /// <summary>
    /// Postgres connection string for the durable stores — the true multi-<i>node</i>
    /// backend. When set it takes precedence over <see cref="StateDbPath"/> and
    /// <see cref="AuditDbPath"/>: pending requests, replay, sessions <b>and</b> audit
    /// all live in the one Postgres database, so several kalitka instances share the
    /// same state and their atomic transitions hold across the cluster (state and
    /// audit commit in one transaction, since they share the connection). Empty falls
    /// back to the SQLite / in-memory selection above. Example:
    /// <c>Host=db;Username=kalitka;Password=…;Database=kalitka</c>.
    /// </summary>
    public string PostgresConnectionString { get; set; } = "";

    /// <summary>
    /// Secret for the <c>/internal/*</c> endpoints used to arm or disarm hosts
    /// from another service on the same network. Empty disables them. This is
    /// administrative — keep it off the SSH hosts (they use <see cref="AgentSecret"/>).
    /// </summary>
    public string InternalSecret { get; set; } = "";

    /// <summary>
    /// <b>Deprecated</b> (migration only): the single global secret SSH/PAM agents
    /// present on <c>/agent/*</c> via <c>X-Kalitka-Agent</c>. Superseded by the agent
    /// registry — per-agent id + secret (<c>X-Kalitka-Agent-Id</c> /
    /// <c>X-Kalitka-Agent-Secret</c>), individually revocable and resource-scoped.
    /// Kept working for one migration window; set it empty once every agent is
    /// enrolled. Still <b>separate</b> from <see cref="InternalSecret"/>.
    /// </summary>
    public string AgentSecret { get; set; } = "";

    /// <summary>
    /// <b>Deprecated</b> (migration only): resource binding for the legacy global
    /// <see cref="AgentSecret"/> caller (exact or scheme wildcard, e.g.
    /// <c>ssh:prod-01</c> / <c>ssh:*</c>; empty = any). Registered agents carry their
    /// own <c>allowed_resources</c> in the registry instead.
    /// </summary>
    public string[] AgentResources { get; set; } = Array.Empty<string>();

    // ---- Optional extras ----------------------------------------------------

    /// <summary>
    /// HTTP IP geolocation for the notification, <c>{ip}</c> is substituted. Purely
    /// informational: approving blind is worse than approving slowly. Convenient but
    /// it sends every visitor's IP to a third party (a GDPR consideration) — set
    /// <see cref="GeoDbPath"/> to keep the lookup on the box instead. Empty disables
    /// the HTTP lookup. Ignored when <see cref="GeoDbPath"/> is set.
    /// </summary>
    public string GeoUrl { get; set; } = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city";

    /// <summary>
    /// Local MaxMind GeoLite2/GeoIP2 database (.mmdb) for on-box geolocation — no
    /// visitor IP leaves the machine. When set it takes precedence over
    /// <see cref="GeoUrl"/>. The database is not shipped: create a free MaxMind
    /// account, download GeoLite2-City (or -Country), and refresh it periodically,
    /// e.g. <c>/data/GeoLite2-City.mmdb</c>. Empty falls back to <see cref="GeoUrl"/>,
    /// and if that is empty too, geolocation is off.
    /// </summary>
    public string GeoDbPath { get; set; } = "";

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

    // ---- Microsoft / Entra sign-in (a second control-plane provider) -------
    // Each self-hosting installer registers their own app in their Entra tenant and grants consent;
    // redirect URI is the same /admin/oauth2/callback. Empty client id = the button is not shown.
    public string MicrosoftClientId { get; set; } = "";
    public string MicrosoftClientSecret { get; set; } = "";

    /// <summary>The authority segment. A tenant GUID is the <b>safe default</b> (single-tenant: only
    /// that tenant's users can even authenticate). <c>organizations</c>/<c>common</c> are multi-tenant
    /// — then <see cref="MicrosoftAllowedTenants"/> is what stops any Microsoft account from signing
    /// in (the admin allowlist is the only other barrier).</summary>
    public string MicrosoftTenant { get; set; } = "organizations";

    /// <summary>Tenant ids (<c>tid</c>) allowed to sign in. Required in practice for a multi-tenant
    /// authority: identity is keyed on <c>tid+oid</c>, and an e-mail domain is only trustworthy when
    /// it belongs to an allowed tenant (Entra has no verified-domain guarantee across tenants).</summary>
    public string[] MicrosoftAllowedTenants { get; set; } = Array.Empty<string>();

    /// <summary>Who may enter as a <b>visitor</b> via Microsoft (the fast path): whole domains and/or
    /// single addresses. If both are empty, tenant-wide entry is allowed only when
    /// <see cref="MicrosoftAllowedTenants"/> restricts the tenant (else the fast path is fail-closed).</summary>
    public string[] MicrosoftDomains { get; set; } = Array.Empty<string>();
    public string[] MicrosoftEmails { get; set; } = Array.Empty<string>();

    // ---- Web control plane (admin) -----------------------------------------

    /// <summary>
    /// Who may operate kalitka through the web control plane (<c>/admin</c>) —
    /// distinct from <see cref="GoogleEmails"/> (who <i>enters</i> guarded hosts).
    /// <see cref="AdminEmails"/> is the primary mechanism (exact match).
    /// <see cref="AdminDomains"/> is a deliberately broader, explicitly-enabled
    /// mode: a whole domain is "anyone the org gave an account", a large blast
    /// radius for a plane that can approve access. With both set the check is OR.
    /// With neither set the web control plane's login is disabled (fail closed);
    /// Telegram approval still works independently.
    /// </summary>
    public string[] AdminEmails { get; set; } = Array.Empty<string>();
    public string[] AdminDomains { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Narrow admin roles (permission bundles), for granting less than full admin.
    /// <see cref="AdminEmails"/>/<see cref="AdminDomains"/> stay full admin (every
    /// permission). <see cref="ApproverEmails"/> may read and decide access requests
    /// and read history; <see cref="AgentAdminEmails"/> may manage agents, profiles,
    /// enrollment and reconciliation. Membership is additive: an address on several
    /// lists gets the union of their permissions. Exact e-mail match, like AdminEmails.
    /// </summary>
    public string[] ApproverEmails { get; set; } = Array.Empty<string>();
    public string[] AgentAdminEmails { get; set; } = Array.Empty<string>();

    /// <summary>Absolute lifetime of an admin session. Shorter than a visitor one.</summary>
    public int AdminSessionMinutes { get; set; } = 480;

    // ---- Email approval channel (optional) ---------------------------------

    /// <summary>
    /// SMTP for the e-mail approval channel: when configured, a new request also
    /// e-mails the operators (<see cref="AdminEmails"/>) an approve/deny link.
    /// Empty host disables the channel; Telegram is unaffected either way.
    /// </summary>
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public string SmtpUser { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
    public string SmtpFrom { get; set; } = "";
    public bool SmtpStartTls { get; set; } = true;

    /// <summary>Lifetime of a one-time approval link. Short: it is a capability.</summary>
    public int OneTimeMinutes { get; set; } = 15;

    /// <summary>Max lifetime of an open session before it is auto-closed as
    /// <c>expired</c> — so a crashed or missed close hook cannot leave a session open
    /// forever. 0 disables expiry.</summary>
    public int SessionMaxHours { get; set; } = 24;

    /// <summary>Lifetime of an agent enrollment token. Longer than an approval link:
    /// an operator may create it, then enrol the machine a while later.</summary>
    public int EnrollmentTokenMinutes { get; set; } = 60;

    // ---- WebAuthn: passkey registration and device-signed approval ----------

    /// <summary>The WebAuthn Relying Party id — the registrable domain a credential is bound to.
    /// A credential registered here is usable for every guarded host, because the gate is the only
    /// thing that authenticates. Defaults to <see cref="GateHost"/> when empty.</summary>
    public string WebAuthnRpId { get; set; } = "";

    /// <summary>The exact origin the browser reports in clientDataJSON, checked on every assertion.
    /// Defaults to <c>https://{GateHost}</c> when empty.</summary>
    public string WebAuthnOrigin { get; set; } = "";

    /// <summary>User-verification requirement: <c>preferred</c> (default) or <c>required</c>
    /// (force a PIN/biometric, not mere presence). Enterprise knob.</summary>
    public string WebAuthnUserVerification { get; set; } = "preferred";

    /// <summary>Require a <b>device-bound</b> credential for a signed approval — reject a
    /// cloud-synced passkey (WebAuthn BE flag). "Device-signed" only means device-bound for a
    /// non-syncable key; high-assurance deployments turn this on. Off by default.</summary>
    public bool WebAuthnRequireDeviceBound { get; set; } = false;

    /// <summary>Lifetime of a WebAuthn registration/approval challenge. Short: the operator is at
    /// the keyboard.</summary>
    public int WebAuthnChallengeMinutes { get; set; } = 5;

    // ---- Web Push (the installable PWA channel) -----------------------------

    /// <summary>The VAPID <c>sub</c> claim — a contact the push service can reach about this sender
    /// (a <c>mailto:</c> or an <c>https:</c> URL). Defaults to <c>mailto:</c> the first admin, else
    /// <c>https://{GateHost}</c>.</summary>
    public string VapidSubject { get; set; } = "";

    /// <summary>How long a push service should hold an undelivered notification (seconds). Default 28
    /// days — an approval request is worth keeping until the phone comes back online.</summary>
    public int PushTtlSeconds { get; set; } = 2_419_200;

    /// <summary>Lifetime of a device-enrolment invite. Short: it is a one-time capability that must
    /// end in an IdP sign-in, so an intercepted invite cannot enrol a stranger later.</summary>
    public int EnrollmentInviteMinutes { get; set; } = 30;

    // ---- RADIUS channel (confirm before login, no browser) -----------------
    // We are the auth server for a gateway (RD Gateway via NPS, VPN, Citrix, Wi-Fi 802.1X). The
    // gateway sends Access-Request; we verify the primary credentials, ask for approval, and answer.
    // Off unless a shared secret is set. The listener is not exposed publicly by default.

    /// <summary>Enable the RADIUS listener (also needs <see cref="RadiusSharedSecret"/>).</summary>
    public bool RadiusEnabled { get; set; } = false;
    public int RadiusPort { get; set; } = 1812;

    /// <summary>The RADIUS shared secret with the gateway. Legacy MD5-based; run in a protected
    /// segment or over RADIUS/TLS where the gateway supports it.</summary>
    public string RadiusSharedSecret { get; set; } = "";

    /// <summary>The resource a RADIUS approval is about — the perimeter, not a host (RADIUS rarely
    /// knows the target machine). Default <c>rdp:gateway</c>; the gateway's NAS-Identifier refines the
    /// label when present. Composes with a host agent: RADIUS gates who enters at all.</summary>
    public string RadiusResource { get; set; } = "rdp:gateway";

    /// <summary>How long an approval is held across Access-Challenge rounds before giving up. The
    /// human thinks longer than a single RADIUS timeout (30–60s), so the wait spans several rounds.</summary>
    public int RadiusChallengeSeconds { get; set; } = 120;

    /// <summary>DEV/DEMO ONLY: skip primary-credential verification and accept any password. Never in
    /// production — it turns the gateway into approval-only with no password check.</summary>
    public bool RadiusAcceptAnyCredentials { get; set; } = false;

    /// <summary>LDAP URL of a domain controller for primary-credential verification (a bind as the
    /// user). Empty = no LDAP (then only <see cref="RadiusAcceptAnyCredentials"/> can let RADIUS run).</summary>
    public string LdapUrl { get; set; } = "";

    /// <summary>How to turn a RADIUS username into a bind DN/UPN. <c>{0}</c> is the username;
    /// e.g. <c>{0}@corp.example</c> (UPN) or <c>CORP\{0}</c>.</summary>
    public string LdapBindFormat { get; set; } = "{0}";
}

/// <summary>How wide a Google-proven identity's session reaches. See
/// <see cref="GateOptions.SessionScope"/>.</summary>
public enum SessionScope
{
    /// <summary>One host per sign-in (default). Siblings ask again.</summary>
    Application,

    /// <summary>Every guarded host under the cookie domain, from one sign-in.</summary>
    Domain
}
