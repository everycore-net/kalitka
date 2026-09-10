# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-09-10

### Added

- **An approval is no longer an entry — SSH access is a one-time grant with a
  session.** When an `ssh:` request is approved, kalitka issues a short-lived,
  single-use *grant*. The PAM agent redeems it exactly once to start a session
  and reports when the session ends, so the audit log finally distinguishes "a
  human said yes" from "this login actually happened". A second approved login
  needs a second grant; a replayed grant is refused.
- **`grant.*` / `session.*` audit events.** `grant.created` (on approval),
  `grant.redeemed` and `session.started` (on redemption), `session.ended` (on
  logout) — each resource-scoped to the SSH host and carrying `grant_id` /
  `session_id`, so a session can be followed end to end. This retires the 0.8.1
  caveat that `session.*` were reserved and a PAM `exit 0` was all the log knew.
- **`ISessionStore` / `InMemorySessionStore`.** Records a live session
  (`session_id`, `grant_id`, `request_id`, subject, resource, `agent_id`,
  started/ended, outcome); atomic close so a session ends exactly once. The seam
  is where a durable, multi-instance session backend plugs in next.
- **Agent endpoints for the lifecycle.** `GET /agent/status` now returns the
  one-time `grant` alongside the state; `POST /agent/redeem` consumes it once and
  returns a `session_id` (`409` on replay); `POST /agent/session/end` closes it.
- **Session-close PAM hook** ([`deploy/ssh/kalitka-session-end.sh`](deploy/ssh/kalitka-session-end.sh)).
  Wired into PAM's `session` stack (`optional`, so a logout is never wedged), it
  reports the session end. The approve hook redeems the grant on entry and hands
  the session id to the close hook through `/run/kalitka/session-<user>`.

### Changed

- The single-use guarantee reuses the `IReplayStore` seam introduced for
  one-time e-mail tokens: redeeming a grant is the one atomic "consume the jti"
  step that turns a signed token into a capability.

### Notes

- Correlating exactly one session id per PAM close across concurrent logins by
  the same user is best-effort in this slice (one file per user under `/run`);
  robust per-session correlation is deeper-SSH work. An allow-list skip grants
  entry directly and starts no session — there is nothing to redeem.
- The state-then-append audit caveat from 0.8.1 still stands: durable,
  multi-instance stores (request/replay/session) are the next step, and only
  then is "compliance-grade immutable audit" a claim worth making.

## [0.8.1] - 2026-09-10

### Security

- **Access lists are resource-scoped.** Every allow/block entry now carries a
  resource (`web:*`, `web:<host>`, `ssh:*`, `ssh:<host>`), and a decision made for
  one resource no longer leaks to another — remembering the name `root` for an SSH
  host cannot wave in a web visitor named `root`, and a web allow-list never
  becomes an SSH auto-approval. `input` is now `subject` (types: ip | subject |
  country). **Legacy entries without a resource are read as `web:*`**, preserving
  web behaviour without turning old lists into PAM policy. Buttons on a request
  scope to that request's resource; manual `/allow` `/block` default to `web:*`.
- **The agent secret is separate from the internal secret.** `/agent/*` (SSH
  hosts) is guarded by `AgentSecret` / `X-Kalitka-Agent`; `/internal/*`
  (administrative) keeps `InternalSecret` / `X-Kalitka-Internal`. A compromised
  SSH host can no longer reach the administrative endpoints.
- **Agent resource binding (groundwork).** `AgentResources` optionally restricts
  which resources an agent may raise (e.g. `ssh:prod-01`), so a shared secret
  cannot claim `ssh:domain-controller-01`. Empty = any; a per-agent credential
  registry comes later.
- **SSH hook hardening.** `/etc/kalitka-approve.conf` must be root:root, and curl
  has bounded `--connect-timeout`/`--max-time` so a hung request cannot hold an
  SSH login past the poll window.

### Notes

- The audit records the state transition first, then appends the event, so a
  disk/IO failure could leave a decision without its durable event. Fine for now;
  "compliance-grade immutable audit" would need a transactional/outbox store —
  not claimed yet. And `session.started`/`session.ended` are still reserved:
  a PAM `exit 0` means "kalitka allowed it", not that the SSH session ran.

## [0.8.0] - 2026-09-10

### Added

- **SSH approval gate (experimental) — the first PAM axis.** A small `pam_exec`
  hook ([`deploy/ssh/`](deploy/ssh/)) raises an access request for `ssh:<host>`
  after sshd authenticates, then blocks until a human approves through any
  channel; on approval the session continues. A thin vertical slice — no
  certificates, credential brokering or proxy — that proves the mechanic end to
  end and records it in the audit log against the `ssh:` resource. It is a second
  factor, never the only one, and fail-closed (keep a break-glass path).
- Internal `/agent/request` and `/agent/status` endpoints (guarded by
  `X-Kalitka-Internal`) and a resource-centric `RaiseAction`, so a non-HTTP
  frontend reuses the same judging, channels and audit as a visitor request.

### Changed

- A pending request now carries a `Resource` (`web:<host>`, `ssh:<host>`), and
  the audit records that — the event envelope is genuinely resource-centric.

## [0.7.0] - 2026-09-10

### Added

- **Durable audit log.** `/admin/history` is now a queryable audit log rather than
  a peek at memory: resource-centric events with a fixed envelope (`id`,
  `timestamp`, `event_type`, `actor`, `subject`, `resource`, `request_id`,
  `grant_id`, `channel`, `metadata`), filterable by actor / resource / event and
  paged. Event types are `access.requested|approved|denied`, `admin.login`,
  `admin.login_denied` now, with `grant.*` / `session.*` reserved for the PAM
  axes so they fit without a schema change.
- **`IAuditStore` seam.** In-memory by default (a bounded ring); set `AuditDbPath`
  for a **SQLite** store that survives restarts — the single, first-party runtime
  dependency (`Microsoft.Data.Sqlite`), append-only, no ORM. New setting:
  `AuditDbPath`.

### Changed

- `GateService.Decide` is async now (the audit append is awaited, not
  fire-and-forget). No external behaviour change.

## [0.6.1] - 2026-09-10

### Security

- **Admin sessions are re-checked against the allowlist on every request.**
  Removing someone from `AdminEmails`/`AdminDomains` now revokes their session
  immediately, instead of leaving a valid cookie until it expires.
- **One central guard for the `/admin` protected routes** (a route-group filter)
  rather than each endpoint checking for itself — a new admin endpoint cannot be
  added without the auth check.

### Changed

- The audit actor for an admin is now the stable Google `sub` (`google:<sub>`),
  not the e-mail; the e-mail remains the display/audit identity (logged at login).

## [0.6.0] - 2026-09-10

### Added

- **E-mail approval channel.** With SMTP configured, a new request also mails the
  operators (`AdminEmails`) an approve and a deny link — a second channel beside
  Telegram, over the same engine. Empty `SmtpHost` disables it.
- **One-time capabilities.** The links are signed, single-use, short-lived tokens
  (`OneTimeMinutes`, default 15). A token points at a request and an action, not
  the decision's parameters; the action is resolved on the server at redemption.
  Opening a link (`GET /action`) only shows a confirmation page and consumes
  nothing — safe against mail-scanner pre-fetch; the `POST` consumes the token
  (`IReplayStore`) once and resolves the request. New settings: `Smtp*`,
  `OneTimeMinutes`.

### Internal

- `TokenSigner` gains the `one-time:v1` key; `OneTimeTokenService`, `IReplayStore`
  (`InMemoryReplayStore`), `IEmailSender` (`SmtpEmailSender`) and `EmailNotifier`
  (a second `INotifier`) are the pieces. `GateService` now announces to every
  registered `INotifier`, not Telegram alone.

## [0.5.1] - 2026-09-10

### Fixed

- **A request now resolves exactly once, atomically.** With two channels
  (Telegram and the web plane) an Approve and a Deny could in principle race and
  both take effect. The transition is now a single guarded step, so only the
  first wins and the list side-effect happens at most once.

### Internal

- Pending requests live behind a new `IRequestStore` seam (`InMemoryRequestStore`
  today) whose `TryResolve` carries that atomic guarantee. It is the place a
  durable/shared backend plugs in later for multi-instance — and the same shape
  the one-time-token replay store will take.

## [0.5.0] - 2026-09-10

### Added

- **Web control plane at `/admin`.** A second, authenticated channel over the
  same engine — dashboard, the waiting requests, one-request approve/deny/
  remember/block, and recent history — server-rendered, no build step. Telegram
  stays an independent channel; the console is additive.
  - **Admin login is Google OIDC + an explicit allowlist**, separate from who may
    enter guarded hosts: `AdminEmails` (exact match, primary) and `AdminDomains`
    (a broader, explicitly-enabled mode). With neither set the web login is
    disabled (fail-closed). Only a verified e-mail gets in; the stable Google
    `sub` keys the session. Register `https://<host>/admin/oauth2/callback` with
    Google.
  - The admin session is a separate signed cookie on its own derived key
    (`admin:v1`, `SameSite=Strict`, `Path=/admin`, short absolute lifetime), so
    web access to a guarded app grants nothing on `/admin`. State-changing actions
    are POSTs with a CSRF token.

### Changed

- Audit `actor` is now a typed string (`telegram:<id>`, `google:<email>`) instead
  of a bare Telegram id, so approvals stay distinguishable per channel.

### Internal

- New `TokenSigner` (HKDF-derived per-purpose keys) backs the admin session and
  its CSRF/state tokens; the visitor session is unchanged for now (no logout).
  `ApprovalEngine` gained a read-only `PendingSnapshot()` for the console.

## [0.4.0] - 2026-09-10

### Changed

- **Google sign-in is now per-host by default (`SessionScope=Application`).**
  It used to grant a session for *every* guarded host under the cookie domain;
  now it grants only the host it signed in for, exactly like a manual approval. A
  sibling host asks again — a single click, since Google remembers the account.
  **Breaking** if you relied on one sign-in opening all siblings: set
  `SessionScope=Domain` to restore that. Manual approvals are unchanged (always
  per-host).

### Added

- `SessionScope` option — `Application` (default) or `Domain`.

### Internal

- Extracted `SessionService` (the signed session and OAuth-state tokens) out of
  `ApprovalEngine`, with direct crypto tests, so the security-critical token code
  is small and testable on its own. No behaviour change.

## [0.3.0] - 2026-09-10

### Added

- **More reverse proxies.** A new status-only `/authz` endpoint for nginx
  `auth_request` — it answers `200` or `401` (never a redirect), and nginx does
  the redirect to the gate itself with `error_page`. Example configs for nginx
  and Envoy `ext_authz` join the existing Traefik one. Traefik, Caddy and Envoy
  use `/auth` (the `302`); nginx uses `/authz`. Both endpoints share one verdict,
  and both accept a trailing path prefix so Envoy's `path_prefix` works. A new
  [Reverse proxies](README.md#reverse-proxies) section explains which endpoint
  each proxy uses. Examples:
  [`deploy/nginx/kalitka.conf`](deploy/nginx/kalitka.conf),
  [`deploy/envoy/kalitka.yaml`](deploy/envoy/kalitka.yaml).

### Changed

- Internal refactor: `GateService` split into `ApprovalEngine` (the decision
  core, free of HTTP and Telegram), `INotifier`/`TelegramNotifier` (the Telegram
  face), and a thin `GateService` facade. No behaviour change — it makes room for
  more proxies and other notifiers without reopening the core.

## [0.2.1] - 2026-09-09

### Added

- **Test suite** (25 tests) covering the security-critical paths: forged and
  proxied `X-Forwarded-For`, cookie tampering / expiry / secret rotation, the
  `/auth` decision for armed, unarmed and bypass cases, the 401-vs-redirect
  split for sub-resources, wrong webhook secret, non-admin callback, and
  callback replay against resolved and expired requests. Time is injected via
  `TimeProvider`, so the time-based tests are deterministic.

### Changed

- `TelegramClient` now sits behind `ITelegramClient`, and `GateService` takes a
  `TimeProvider` — both to make the above testable, no behaviour change.

### Fixed

- **Sub-resources without a session now get `401`, not a redirect.** A `302` to
  the gate's HTML page is only meaningful to a top-level navigation. A WebSocket
  handshake cannot follow it, an XHR/fetch reads the HTML as its payload, and a
  single-page app behind the gate hung on a blank screen. The request kind is
  read from the browser's Fetch Metadata (`Sec-Fetch-Mode`; `Accept` as a
  fallback for older clients): only a real navigation is redirected, everything
  else fails cleanly with `401`. This is the "Single-page apps and a redirect
  gate" caveat, turned from a caveat into correct behaviour.
- `appsettings.json` carried JSON "comment" keys under `Logging:LogLevel` whose
  values were parsed as log levels and threw on first use. Removed; the tests
  caught it.

### Dependencies

- Adopted the safe GitHub Actions bumps (checkout, setup-dotnet, login,
  metadata, build-push). Major bumps of the .NET base images are held back and
  ignored by Dependabot — that is a runtime baseline change, done deliberately.

## [0.2.0] - 2026-09-09

First public release. The product is already whole — Telegram approval, allow
and block lists, optional Google sign-in, per-host arming, mute, session
control — so it ships now rather than waiting for thirty more features.

Not yet here: an automated test suite (tracked in the issues) and per-host
isolation of the Google session (see Known limitations).

### Added

- **Trusted proxies.** `TrustedProxies` (CIDR list) decides whether forwarded
  headers are believed at all. Requests that did not arrive from one of these
  are judged on the address the connection actually came from.
- **Rate limiting.** A sliding window per address (`MaxRequestsPerIp`,
  `RateWindowMinutes`) and a ceiling on requests waiting for an answer
  (`MaxPending`). Over the limit the door stays silent — the same answer a
  blocked caller gets, so there is nothing to learn from it.
- **Audit log.** One structured line per decision: request id, host, client
  address, identity, admin and reason. Secrets, tokens and cookie values are
  never logged.
- **`/allow` and `/block`.** Fill either list before anyone rings, instead of
  only being able to react to a request.

### Changed

- **`X-Forwarded-For` is read from the right**, past known proxies, instead of
  taking the leftmost entry. A proxy only ever appends on the right; everything
  to the left is whatever the caller wrote. Reading it the obvious way let a
  visitor choose their own address — and with it their own place on the allow
  list.
- **Redirect targets must be a currently guarded host**, not merely a name under
  the same domain. A forged `Host` header could otherwise steer visitors to a
  name that was never guarded.
- **Telegram callbacks expire.** A decision was already terminal after the first
  press; now the request also has to still be within its lifetime, so an old
  button cannot resurrect one.

### Security

- Startup refuses `BypassNetworks` without `TrustedProxies`. Behind a proxy every
  visitor would otherwise appear to come from the proxy, and a bypass range
  containing that address would wave everyone through while the configuration
  looked entirely correct.

### Known limitations

- A Google sign-in grants a session for every guarded host under the cookie
  domain. Manual approvals are already per-host. Per-host isolation of the
  Google session is tracked as a feature (one-time hand-off token) and is not in
  this release.

### Upgrading

Set `TrustedProxies` to the range your reverse proxy connects from. For Docker:

```
docker network inspect proxy -f '{{(index .IPAM.Config 0).Subnet}}'
```
