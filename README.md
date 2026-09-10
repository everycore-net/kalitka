# kalitka

A doorbell for your reverse proxy.

Something on your network has a login page that is fine, but you would rather
the whole internet did not get to see it — a Grafana, a Dockge, an admin panel,
a staging site. VPN is heavy, IP allow-lists break the moment you travel, and
basic auth in front of a login is a second password to lose.

Kalitka puts a doorbell there instead. A visitor states who they are, you get
a message on Telegram, and you decide. Nobody reaches the application until you
say so — and the application still asks for its own password.

```
visitor ──▶ reverse proxy ──forwardAuth──▶ kalitka ──▶ Telegram ──▶ you
                 │                            │
                 └──────── approved ──────────┘ ──▶ the actual login
```

It is a **pre-filter, not an authentication system**. It does not replace the
login behind it, and it is not meant to.

## What it does

- **Ask and wait.** The visitor types a name or an e-mail, you get a message
  with the target, what they typed, their IP and roughly where from — with
  buttons to let them in or refuse.
- **Never be asked twice.** Block by IP, by what they typed, or by country. A
  blocked caller is turned away silently and never rings again. That is the
  point: not to filter traffic, but to stop your phone from buzzing.
- **Remember the welcome ones.** An allow list lets known IPs and names through
  with no question at all.
- **Google sign-in (optional).** The people who belong get in with one click;
  everyone else still rings and waits.
- **Guard hosts one at a time.** Attach the middleware everywhere, then arm
  hosts individually. Unarmed hosts pass straight through.
- **Mute.** For the night someone decides to hammer the door: every new caller
  is silently added to the block list instead of notifying you.

## What it is not

- Not an identity provider. It proves nothing about who someone is — it only
  asks you.
- Not a WAF. Put it behind one.
- Not a replacement for the login behind it. If the app has no login of its own,
  kalitka is the only thing in the way, and a signed cookie is all that stands
  between the internet and it. Know that before you rely on it.

## Requirements

- A reverse proxy with an external-auth hook: Traefik `forwardAuth`, Caddy
  `forward_auth`, Envoy `ext_authz`, or nginx `auth_request`. See
  [Reverse proxies](#reverse-proxies) for which endpoint each one uses.
- A Telegram bot ([@BotFather](https://t.me/botfather)) and your Telegram user id.
- Docker, or .NET 9 if you would rather run it directly.

## Tests

```bash
dotnet test
```

The suite is small and pointed at the security-critical behaviour: forged and
proxied `X-Forwarded-For`, cookie tampering / expiry / secret rotation, the
`/auth` decision for armed, unarmed and bypass cases, a wrong Telegram webhook
secret, a non-admin callback, and callback replay against a resolved or expired
request. Time is driven by a fake clock, so nothing sleeps and nothing is flaky.

## Getting started

```bash
git clone https://github.com/everycore-net/kalitka
cd kalitka/deploy
cp .env.example .env      # fill in token, secrets, your host
docker compose up -d --build
```

Point the webhook at your instance once:

```bash
curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
     -d "url=https://gate.example.com<WEBHOOK_PATH>" \
     -d "secret_token=<WEBHOOK_SECRET>"
```

Attach the middleware in your proxy — see
[`deploy/traefik/kalitka.yml`](deploy/traefik/kalitka.yml) — and arm a host:

```
/hosts          in Telegram, or:
curl -X POST -H "X-Kalitka-Internal: <secret>" \
     "http://kalitka:8080/internal/toggle?host=app.example.com&on=1"
```

## Reverse proxies

Kalitka answers the proxy's auth check at one of two endpoints. They reach the
same verdict — unarmed hosts, the LAN bypass, the allow list and a valid session
pass; everything else has to ring — and differ only in how a challenge is
expressed, because the proxies differ in what they do with the answer.

| Proxy | Endpoint | A challenge is | Redirect to the gate is done by |
|---|---|---|---|
| Traefik `forwardAuth` | `/auth` | `302` (or `401` for a sub-resource) | kalitka; the proxy returns it |
| Caddy `forward_auth` | `/auth` | same | same |
| Envoy `ext_authz` (HTTP) | `/auth` | same | same |
| nginx `auth_request` | `/authz` | `401`, always | nginx, via `error_page` |

`/auth` redirects with a `302`, which the first three hand back to the visitor.
It also answers a sub-resource (a WebSocket, an XHR, an asset — anything that is
not a top-level navigation) with `401` instead of a `302`, so a single-page app
behind the gate fails cleanly rather than hanging on a blank page.

`/authz` only ever answers `200` or `401` — never a redirect — because
`auth_request` acts on the status code alone and a `3xx` would become a `500`.
nginx turns the `401` into the redirect itself. The gate URL is also returned in
the `Location` header, for a proxy that can use it.

Examples: [`deploy/traefik/kalitka.yml`](deploy/traefik/kalitka.yml),
[`deploy/nginx/kalitka.conf`](deploy/nginx/kalitka.conf) and
[`deploy/envoy/kalitka.yaml`](deploy/envoy/kalitka.yaml). Either way, point
`TrustedProxies` at the address your proxy connects from — see below.

Envoy `ext_authz` prepends its `path_prefix` to the original path, so the check
reaches kalitka as `/auth/<original>`; the verdict ignores the path, and both
`/auth` and `/authz` accept a trailing prefix for exactly this.

## Web control plane

Besides Telegram, kalitka has a small authenticated web console at `/admin` on
its own host (`https://gate.example.com/admin`) — a second channel over the same
engine. Telegram stays; the console is additive.

```
/admin/dashboard     overview + waiting count
/admin/requests      requests waiting for a decision
/admin/requests/{id} one request — approve / deny / remember / block
/admin/history       audit log, filter by actor/resource/event + paging
```

History is a durable **audit log** of resource-centric events (`access.requested`,
`access.approved`, `access.denied`, `admin.login`, …) with a fixed envelope, so
SSH/DB events fit later without a schema change. Set `AuditDbPath` (e.g.
`/data/audit.db`) to keep it across restarts via SQLite; empty keeps it in memory.

**Who may operate it** is a separate allowlist from who may *enter* guarded hosts:

- `AdminEmails` — the primary mechanism, exact match (`sergej@example.com`).
- `AdminDomains` — a deliberately broader, **explicitly-enabled** mode. A whole
  domain is "anyone the org gave an account", a large blast radius for a console
  that can approve access — so it is not an equivalent default. With both set the
  check is OR; with neither set the web login is **disabled** (fail-closed), and
  Telegram approval still works.

Login is Google OIDC (only a verified e-mail on the allowlist gets in; the stable
`sub` keys the session). Add the console's redirect URI to your Google client:

```
https://gate.example.com/admin/oauth2/callback
```

The admin session is a separate signed cookie (its own derived key, `SameSite=Strict`,
scoped to `/admin`, short absolute lifetime) — web access to a guarded app grants
nothing here. State-changing actions are POSTs with a CSRF token. Login is OIDC,
so there is no password to brute-force.

## E-mail approvals

A third way to answer, beside Telegram and the console: when SMTP is configured,
a new request also e-mails the operators (`AdminEmails`) an **Approve** and a
**Deny** link.

- Each link is a **one-time capability** — signed, single-use, and short-lived
  (`OneTimeMinutes`, default 15). It carries the request and which action it is
  for, not the decision's parameters; what the action means is resolved on the
  server when redeemed.
- Opening a link **changes nothing** — the `GET` shows a confirmation page, so a
  mail scanner that pre-fetches the link is harmless. Only the `Confirm` button
  (a `POST`) consumes the link and resolves the request. It works once; a second
  use, or the other link after the first decided it, says so.

Configure SMTP (`SmtpHost`, `SmtpPort`, `SmtpUser`, `SmtpPassword`, `SmtpFrom`,
`SmtpStartTls`); recipients are `AdminEmails`. Empty `SmtpHost` disables the
channel — Telegram is unaffected either way.

An e-mail link is a bearer capability: whoever holds it can act, so treat the
mailbox accordingly. It is a convenience channel, not proof of who clicked.

## Bot commands

| Command | What it does |
|---|---|
| `/allowed` | show the allow list, with buttons to remove entries |
| `/blocked` | show the block list |
| `/allow ip\|name <value>` | let someone through before they ever ask |
| `/block ip\|name\|country <value>` | turn someone away in advance |
| `/hosts` | which hosts are currently guarded |
| `/mute [min]` | stop notifying; silently block every new caller by IP |
| `/unmute` | back to normal |
| `/session [min]` | how long an approval lasts |

Entries also appear on the lists straight from a request: the buttons under a
notification let you approve *and* remember the IP or the name in one press.
The commands are for the cases where you know in advance — a colleague arriving
tomorrow, or an address you have already seen enough of.

`country` works on the block list only. As a way *in* it is far too coarse.

## Configuration

Everything is environment variables prefixed `Kalitka__`. The full list with
comments is in [`src/Kalitka/GateOptions.cs`](src/Kalitka/GateOptions.cs);
[`deploy/.env.example`](deploy/.env.example) has the ones you actually need.

The app refuses to start without `BotToken`, `WebhookPath`, `WebhookSecret`,
`HmacSecret` and `GateHost` — an open webhook or an unsigned cookie fails
silently, a service that does not come up does not.

## Things worth knowing before you deploy

**Set `TrustedProxies`, or none of the IP logic means anything.** Forwarded
headers are only believed when the request arrives from a proxy you name here,
and the client address is then read from `X-Forwarded-For` *from the right*,
past those proxies. Reading the leftmost entry — the obvious thing to do — lets
the caller choose their own address, and with it their own place on your allow
list.

If `TrustedProxies` is empty, headers are ignored entirely and every visitor
appears to come from the proxy. That is safe on its own, but combined with a
`BypassNetworks` entry that happens to contain the proxy's own address it would
wave everyone through — so that combination is refused at startup instead.

**Keep a way back in.** forwardAuth is fail-closed: if kalitka is down, nothing
reaches the guarded hosts. `BypassNetworks` (your LAN) is the tested way back;
removing the middleware line is the last resort. Test the bypass *before* you
need it.

**Only guarded hosts are valid targets.** A redirect target has to be a host
that is currently armed, not merely one under your domain — otherwise a forged
`Host` header could steer visitors to a name you never guarded.

**Sessions are a signed cookie, not server state.** Nothing to persist, and
rotating `HmacSecret` logs everyone out at once. The cookie is set on the parent
domain (`CookieDomain`, e.g. `.example.com`) so the browser carries it to every
guarded host — but what a session *opens* is the host signed into it, not the
cookie's domain.

**Know the scope of an approval.** A *manual* approval is always bound to the one
host it was granted for — the host is signed into the cookie, so it never opens a
sibling. A *Google sign-in* follows `SessionScope`:

- `Application` (default) — a session for the one host the sign-in was for. A
  sibling host asks again; because Google remembers the account, that is a single
  click, no password. No host opens another.
- `Domain` — one sign-in grants **every** guarded host under `CookieDomain`.
  Convenient when the hosts are equally sensitive; weigh it when they are not.

If you relied on the old behaviour, set `SessionScope=Domain` explicitly.

**The waiting page polls.** A human has to press a button somewhere, and no
callback can reach that browser. Behaviour-based protection (CrowdSec,
fail2ban) may read that as crawling and ban the visitor — at the *entrypoint*,
which then affects every host, not just the guarded ones. Exempt the `/wait`
path there, keyed on host and path.

**Single-page apps behind the gate.** Only a top-level navigation is redirected
to the gate; a WebSocket, an XHR/fetch or any sub-resource that arrives without
a session gets a `401` instead, because it cannot follow a redirect (the
handshake fails, the fetch reads HTML as its data — and the app hangs blank).
The request kind is read from `Sec-Fetch-Mode`, with `Accept` as a fallback for
older clients. So a cached SPA shell whose background call finds no session sees
a clean `401` rather than a blank page. It still cannot reach the app until you
approve — a `401` is not a way in — but it fails honestly instead of hanging.

**Country blocking is coarse.** It is offered for the block list only, and not
at all for the allow list — "everyone from this country walks in" is never right.

## Why the name

*Kalitka* (калитка) is the small garden gate next to the big one — the one with
a latch you open for people you recognise. That is the job.

## License

[MIT](LICENSE).
