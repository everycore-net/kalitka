# kalitka

A doorbell in front of your app.

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

That is what kalitka is: **a doorbell in front of your app** — wired in through your
reverse proxy's forwardAuth hook, which is how it sees the request before the app does, but
what it guards is the application, not the proxy. The
[SSH](#ssh-just-in-time-access) and [database](#database-just-in-time-access) sections are
the *same ask-a-human step reused elsewhere* — an **optional** extension that does **not**
go through the proxy (a local agent calls kalitka's `/agent/*` API instead) and does
nothing until you deploy it. If you only want the doorbell, they don't touch your setup.

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
- **Speak more than English.** The visitor and waiting pages detect the browser
  locale and render in English, German or Russian.
- **Gate more than the web.** The same approval flow fronts SSH and database
  access through a registered **agent** on the far host — see
  [SSH](#ssh-just-in-time-access) and [Database access](#database-just-in-time-access).

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

The suite is pointed at the security-critical behaviour: forged and proxied
`X-Forwarded-For`, cookie tampering / expiry / secret rotation, the `/auth` decision
for armed, unarmed and bypass cases, a wrong Telegram webhook secret, a non-admin
callback, callback replay against a resolved or expired request, agent signature and
replay, policy quorum with distinct approvers, bounded-grant and session lifecycle,
and command-aware / cert-principal binding. Time is driven by a fake clock, so nothing
sleeps and nothing is flaky. The Postgres-backed tests run only when
`KALITKA_TEST_POSTGRES` points at a throwaway instance.

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
/admin/sessions      live SSH/DB sessions — profile, uses-left, revoke
/admin/agents        registered agents — keys, capabilities, enrolment, revoke
/admin/profiles      agent profiles; /admin/reconcile applies profile changes
/admin/policies      access policies (quorum, grant TTL, profile match, require-command)
/admin/principals    operators — link channel identities so a quorum counts people
/admin/history       audit log, filter by actor/resource/event + paging
```

The nav shows only what your permissions allow (see below).

History is a durable **audit log** of resource-centric events (`access.requested`,
`access.approved`, `access.denied`, `admin.login`, `grant.redeemed`, `session.started`,
`session.provisioned`, `session.reconciled`, `session.ended`, `agent.*`, `policy.*`, …)
with a fixed envelope, so web, SSH and DB events all share one shape. Set `AuditDbPath`
(e.g. `/data/audit.db`) to keep it across restarts via SQLite; empty keeps it in memory.

**Durable live state.** Beyond the audit trail, the live state — pending requests,
consumed one-time tokens, and sessions — can be kept in SQLite too: set
`StateDbPath` (e.g. `/data/state.db`). Then that state survives a restart, and its
atomic transitions (resolve a request once, redeem a grant once, close a session
once) hold across every process pointed at the same file — the single-node durable
step. Empty keeps it in memory (single instance, lost on restart).

**Multi-node (Postgres).** For several kalitka instances behind a load balancer,
point them all at one Postgres with `PostgresConnectionString` — it takes
precedence over the SQLite paths and holds requests, replay, sessions, audit **and**
config, so the cluster shares one state and the atomic transitions hold across it.
Config (block/allow lists, armed hosts, settings) is shared too, via atomic
read-modify-write; it propagates between nodes within a short cache window (~10s),
not instantly. Still per-instance: the in-memory rate-limit and mute windows.

**Atomic state + audit.** With Postgres, or with `StateDbPath` and `AuditDbPath`
pointed at the *same* SQLite file, a decision and its audit event commit in one
transaction: if the audit write fails, the state change rolls back with it — no
access recorded without its history. Separate SQLite files (or in-memory) keep the
earlier behaviour, where the audit append is a best-effort second step.

**Who may operate it** is a separate allowlist from who may *enter* guarded hosts:

- `AdminEmails` — the primary mechanism, exact match (`sergej@example.com`). Full
  admin: every permission.
- `AdminDomains` — a deliberately broader, **explicitly-enabled** mode. A whole
  domain is "anyone the org gave an account", a large blast radius for a console
  that can approve access — so it is not an equivalent default. Also full admin.
  With both set the check is OR; with none of the lists set the web login is
  **disabled** (fail-closed), and Telegram approval still works.

The console is **permission-based**, so you can grant less than full admin with two
narrow roles (each is a bundle of permissions; membership is additive — an address on
several lists gets the union):

- `ApproverEmails` — **Approver**: read/approve/deny access requests and read history.
- `AgentAdminEmails` — **AgentAdmin**: manage agents, profiles, enrollment and
  reconciliation.

Every endpoint checks a permission; the nav only shows what you can use. Effective
permissions are resolved from the current config on each request, so removing an
address takes effect at once — not at session expiry. Managing access policies needs
`policies.manage`, which **full admin** has; a policy-only role bundle exists internally
but is not yet wired to its own e-mail list.

Login is Google OIDC (only a verified e-mail on the allowlist gets in; the stable
`sub` keys the session). Add the console's redirect URI to your Google client:

```
https://gate.example.com/admin/oauth2/callback
```

The admin session is a separate signed cookie (its own derived key, `SameSite=Lax`
so it survives the OIDC redirect, scoped to `/admin`, short absolute lifetime) — web
access to a guarded app grants nothing here. State-changing actions are POSTs with a
CSRF token, and the login is bound to the initiating browser by a state nonce. Login
is OIDC, so there is no password to brute-force.

## Access policies

Tags on agents can carry weight. A policy at `/admin/policies` matches a request by
resource glob (`ssh:*`) and tags that must **all** be present on the requesting agent
(`env:prod`), and adds constraints:

```yaml
name: prod-ssh
match:
  resource: "ssh:*"
  tags: { env: prod }
  profile: "sql-dba"   # optional: match only this grant profile (glob), e.g. DDL vs read-only
approval:
  required: 2               # distinct approvers before it is approved
  grant_ttl: 15m            # shorten the one-time grant
  require_command: true     # forbid an open shell — only a specific, approved command
  require_source: true      # pin the SSH cert to an approved source address
  allowed_principals: [deploy, readonly]   # which logins may be requested (never root)
  self: true                # route to the request's own subject (they confirm; only them)
```

A policy **only ever restricts** — it can require more approvals, shorten the grant, forbid
an open shell, require a source binding, or allow-list the logins that may be requested,
never grant a capability or resource an agent does not already have (the agent's own
authority is checked first). Several matching policies combine the strictest way: most
approvals (`max`), shortest grant (`min`), require-command / require-source if **any**
matches, allowed-principals **intersected** — there is no rule ordering. `match.profile`
lets the bar differ per operation class (a `sql-dba` grant needing four eyes while
`sql-readonly` stays single). A request that violates a restriction is refused up front
(`command-required` / `source-required` / `principal-not-allowed`), before anyone is asked.

`self` is the one non-restriction knob: it routes the request to its own subject (see
[Operators](#operators)) so the person acting confirms it, and must be set explicitly per
policy — it never overrides the quorum requirement.

Two things worth knowing about `required: 2`:

- A quorum counts **distinct operator principals** — people, not channels (see
  [Operators](#operators)). An identity linked to a principal (Telegram, later
  Slack/Teams/app) counts as that person; the same person on two channels counts once; an
  unlinked Google admin still counts as itself; any other unlinked channel can satisfy a
  single approval but does not count toward a quorum greater than one.
- A **denial from any channel denies immediately** — the quorum is only for approval.

Managing policies needs the `policies.manage` permission (full admin has it). With no
policies defined, every request needs one approval and the default grant lifetime.

## Operators

Approvals arrive as **channel identities** — `google:<sub>`, `telegram:<user_id>`, later
`slack:<team>:<user>`, `teams:<tenant>:<oid>`, `app:<id>`. An **operator principal** at
`/admin/principals` binds several of them to one person, so a quorum counts *people, not
channels*:

- a Telegram (or Slack/Teams/app) approval by a linked identity counts as that operator;
- the same operator on two channels counts **once** — you cannot satisfy four-eyes alone;
- an unlinked Google admin still counts as itself (no setup needed for the common case);
- any other unlinked identity can satisfy a single approval, but not a quorum.

Channels are **transports of one control plane**, not separate identity models: adding
Slack, Teams or a first-party app is a new identity scheme to link here — the quorum logic
does not change. An identity belongs to at most one operator (enforced on save). Managing
operators needs the `principals.manage` permission (full admin has it).

The link works **both directions**. Backward, an approval resolves to a person (the quorum
above). Forward, a request can be routed **to** a person: a request carries a
machine-readable `subject_identity` (e.g. `os:CONTOSO\anna`), which resolves to an operator
and asks *them* — not the global admins. A policy `self` mode routes a request to its own
subject (the person confirms their own action, and only they are asked); everything else
asks the operator **and** the admins. A subject that does not resolve falls back to the
admins, and that fallback is **audited** (`notify.fallback`) — never silent, and never a
lowering of the policy's approval requirement. This is what makes the solo tier and
self-confirmation flows possible without tenancy work in the core.

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

List entries are **scoped to a resource** (`web:*`, `web:<host>`, `ssh:<host>`, …):
a decision for one resource never leaks to another — remembering a name for an
SSH host does not admit a web visitor of that name, and vice versa. Buttons on a
request carry that request's resource; the `/allow` and `/block` commands default
to `web:*`.

## SSH just-in-time access

kalitka gates SSH the same way it gates the web — on a human's approval — in two
shapes that compose. Both run through a registered agent on the far host and land in
`/admin/history` against the `ssh:<host>` resource. See [`deploy/ssh/`](deploy/ssh/).

- **Login gate (PAM).** A small PAM hook (`deploy/ssh/kalitka-approve.sh`) raises a
  request *after* authentication and blocks until you approve; then the session
  continues. It is a *second* factor, never the only one, and fail-closed — keep a
  break-glass path. It brokers no credential; it only turns a yes/no into a PAM exit code.
- **JIT certificates (`kalitka-ssh`).** On a bastion, `kalitka-ssh connect --host prod-01`
  mints an ephemeral keypair, raises the request, and on approval signs a **short-lived
  OpenSSH user certificate** — principal bound to the approved login, validity exactly the
  grant's expiry — then `exec`s `ssh`. The cert self-expires: nothing to revoke, no orphan.
  Core never holds the CA key. Add `--command 'systemctl restart nginx'` for a
  **force-command** certificate: the human approves that exact command and the session can
  run *only* it (the SSH analogue of a pre-approved stored procedure). Add
  `--source-address CIDR` to pin the cert to an approved source (useless if stolen). A
  policy can `require_command`, `require_source`, or allow-list which logins may be
  requested — the signer applies only what Core approved, never a caller argument. The
  cert's key-id is `kalitka:<session-id>`, so sshd's auth log ties back to the audit trail.

## Database just-in-time access

`kalitka-db-agent` (see [`deploy/db/`](deploy/db/)) runs next to **SQL Server** or
**PostgreSQL** and turns an approved grant into real, time-boxed database access, then
removes it. Core is the control plane and **holds no database credential** — a grant
carries only a server-side *profile* (`sql-readonly`, `sql-writer`, …) the local connector
maps to a predefined role; no raw SQL ever comes from Core.

- **Modes.** *ephemeral* (default) creates a JIT login+role and drops it when the grant
  ends, returning the credential to the operator out of band; *grant* adds an existing
  principal to the role for the session; *action* hands out **no** login and instead runs
  one DBA-vetted stored procedure once, counting it as exactly one use.
- **Bounded grants.** A grant ends on the first of its `expires_at` (mandatory ceiling), a
  `max_uses` budget, or an explicit revoke — carried on the session (`profile`, uses-left)
  and shown at `/admin/sessions`.
- **Crash recovery.** The connector journals every provisioned principal (locally and in an
  in-DB ledger) with its expiry, and a `reconcile` pass revokes orphans left by an ungraceful
  death — a locally-known expiry is dropped even while Core is unreachable; a Core outage is
  never on its own a reason to revoke; and it never touches a principal without Kalitka
  provenance. The agent runs as a least-privilege identity (a gMSA on Windows), not a DB admin.

## Agent credentials

An `/agent/*` caller authenticates one of three ways, most-preferred first:

1. **Signed request.** The agent registers a public key (agent detail page) and signs
   each request, so no reusable secret is ever sent. The signature (`X-Kalitka-Signature`,
   base64) covers a canonical newline-joined string:

   ```
   kalitka-agent-sig-v1
   {METHOD}
   {path+query}
   {sha256hex(body)}
   {unix-timestamp}
   {nonce}
   ```

   sent with `X-Kalitka-Agent-Id`, `X-Kalitka-Timestamp`, `X-Kalitka-Nonce` (and an
   optional `X-Kalitka-Key-Id`). The signature binds the exact request; a 5-minute
   timestamp window plus a single-use nonce stop replay. (Application-level signatures
   rather than mTLS, on purpose: they reach the app unchanged whatever the reverse proxy
   does with TLS.)

   The key is stored as **`SubjectPublicKeyInfo`**, so the algorithm is derived from the
   credential, not the request — **Ed25519** and **ECDSA-P256** are supported behind one
   interface (ECDSA on the wire is IEEE P1363, 64 bytes). The key id is a fingerprint of
   the key (`base64url(SHA-256(SPKI))`). Each key also carries a `provider_hint` (a local
   claim: `software` / `windows-platform` / …) and an `assurance` (what Core has verified —
   `unverified` until attestation), so a policy can later demand a hardware-attested
   credential. The canonical string is unchanged, so the scheme stays `v1`.
2. **Per-agent shared secret** (`X-Kalitka-Agent-Id` + `X-Kalitka-Agent-Secret`) —
   registry credential, kept through the migration window.
3. **Legacy global secret** (`X-Kalitka-Agent`) — deprecated, one migration window.

Whichever path, authorization is still per-agent (capability + allowed resource); a
valid credential is never a licence for a resource outside the agent's scope.

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

kalitka is licensed under the **GNU Affero General Public License v3.0 or later**
(`AGPL-3.0-or-later`) — see [LICENSE](LICENSE). Copyright (C) 2026 everycore. In
short: you may run, study, share and modify it, but if you run a **modified**
kalitka as a network service, the AGPL requires you to offer that service's users
the source of your modifications.

**Commercial licensing.** If the AGPL does not fit — for example you want to embed
or offer kalitka without AGPL obligations — a separate commercial license is
available; contact everycore.

**Contributing.** See [CONTRIBUTING](CONTRIBUTING.md). Contributions are made under
the [Contributor License Agreement](CLA.md), which is what keeps the commercial
license possible alongside the open-source one.

Releases up to and including **0.11.0 were published under the MIT License** and
remain available under those terms; the AGPL applies from the next release onward.
