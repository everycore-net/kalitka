# kalitka

**Nothing gets in until a human says yes — and the yes is provable.**

Standing access is the problem. The admin account that can always log in, the database
login that exists all year for two hours of work in March, the RDP right nobody
remembers granting, the AI agent with a token that never expires. None of it is a
vulnerability on its own; all of it is access that outlives the reason it was granted.

Kalitka turns those into a question. Someone — or something — asks for access, a human
answers, and what they get is bounded: a profile, a clock, a number of uses, and a
revoke button. The answer is signed and chained into an audit log, so months later you
can show *who* allowed *what*, not merely that it happened.

```
        who is asking                                  who answers
  ┌──────────────────────────┐                  ┌───────────────────────┐
  │ browser → reverse proxy  │                  │ web console           │
  │ ssh → PAM hook           │  ──▶ kalitka ──▶ │ push app (signed)     │
  │ database connector       │      decides     │ Telegram              │
  │ RDP → Windows agent      │                  │ e-mail one-time links │
  │ gateway/VPN → RADIUS     │                  └───────────────────────┘
  │ AI tool call → MCP       │
  └──────────────────────────┘
```

It is a **pre-filter, not an authentication system**: it never replaces the login
behind it, and it proves nothing about who someone is — it asks a human who does know.

## What it guards

| Axis | How it is wired | What a grant does |
|---|---|---|
| **Web** `web:` | your reverse proxy's auth hook (Traefik `forwardAuth`, Caddy, Envoy, nginx) | a signed session cookie for the host that was approved |
| **SSH** `ssh:` | a PAM hook on the host, or a short-lived OpenSSH certificate | the login proceeds; the session is accounted and revocable |
| **Databases** `db:` | a connector beside SQL Server or PostgreSQL | a real, time-boxed SQL role, removed when the grant ends |
| **RDP** `rdp:` | a Windows agent (deny-by-default; a refused logon raises the request) | temporary membership, revoked and the session logged off |
| **Perimeter** | RADIUS — the auth server your RD Gateway or VPN already points at | confirm *before* the login, on the first attempt, with no browser |
| **AI tool calls** `mcp:` | a gateway in front of your MCP servers | one execution of one call, bound to its exact arguments |

## How you answer

Telegram, the web console, the installable push app, or a one-time e-mail link. They are
**transports of one control plane**, not four products: a quorum counts *people*, not
channels, so the same person tapping in two places is still one approval. You need at
least one configured — an install where Telegram is disallowed by policy runs on the
console or e-mail alone.

An approval from the push app or a passkey is **signed by the device**: the audit entry
holds a signature over that decision, by that credential — not "a session pressed
approve".

## What a yes buys

A **bounded grant**, which ends on the first of: its TTL, its uses being spent, an
admin revoke, or the session's maximum lifetime. Live sessions are listed at
`/admin/sessions` with their profile and remaining uses, and revoking one ends it where
it lives — the SQL role is dropped, the RDP session logged off, the process closed.

Kalitka **brokers authority, not credentials**: for a database it hands the connector a
profile name and the bounds; it never holds a database administrator credential itself.

## Policy

Tags on agents and resources carry weight:

```yaml
name: prod-ssh
match:
  resource: "ssh:*"
  tags: { env: prod }
approval:
  required: 2         # distinct people, not channels
  subject: required   # and the person themselves must confirm
grant:
  ttl: 15m
```

A policy **only ever restricts** — it can demand more approvals or a shorter grant,
never grant a capability the requester does not already have. Several matching policies
combine the strictest way, so there is no rule ordering to reason about.
`subject: forbidden` is there too, for the case where the requester must not be one of
the approvers.

## Proof

- **A tamper-evident audit log.** Every event carries the hash of the one before it,
  length-prefixed so nothing can be smuggled between fields, and the head is signed —
  editing, reordering or truncating history breaks the chain. `/admin/audit/verify`
  checks it.
- **`explain` and `simulate`.** "Would Anna be gated on WIN-PROD-03, and why two
  approvals?" is answered from the real matcher, not from a summary.
- **Strong agent credentials.** Agents sign each request (Ed25519 or ECDSA-P256, keys
  stored as SPKI, on Windows in the TPM where available); enrolment can be secretless,
  so no reusable secret exists at all.

## What it is not

- **Not an identity provider.** A passkey or a Google/Microsoft sign-in here is a
  cryptographic allow-list, not a directory.
- **Not a WAF.** Put it behind one.
- **Not a replacement for the login behind it.** If the app has no login of its own,
  kalitka is the only thing in the way, and a signed cookie is all that stands between
  it and the internet. Know that before relying on it.
- **Not a credential vault.**
- **Not a defence against someone who already administers the machine.** Endpoint
  controls — PAM hooks, Windows groups, logon scripts — are approval and a provable
  record, not a boundary against a local administrator. What holds against them is
  enforcement off their machine (a gateway, the KDC) or not being an administrator by
  default in the first place.

## Start

```bash
git clone https://github.com/everycore-net/kalitka
cd kalitka/deploy
cp .env.example .env      # gate host, secrets, at least one approval channel
docker compose up -d --build
```

Then attach the middleware in your proxy ([`deploy/traefik/kalitka.yml`](deploy/traefik/kalitka.yml),
[`nginx`](deploy/nginx/kalitka.conf), [`envoy`](deploy/envoy/kalitka.yaml)) and arm a
host. Nothing else is required: every other axis is opt-in and changes nothing until you
deploy its agent.

- SSH — [`deploy/ssh/`](deploy/ssh/)
- Databases — [`deploy/db/`](deploy/db/)
- RDP and Windows — [`src/KalitkaAgent.Windows/`](src/KalitkaAgent.Windows/)
- RADIUS — [`docs/design/radius.md`](docs/design/radius.md)
- AI tool calls — [`src/KalitkaMcpGateway/`](src/KalitkaMcpGateway/)

## Requirements

- Docker, or .NET 9 to run it directly.
- **At least one approval channel**: a Telegram bot, Google/Microsoft sign-in for the
  web console, the push app, or SMTP for e-mail links. `HmacSecret` and `GateHost` are
  always required; the app refuses to start with no channel configured.
- For the web axis: a reverse proxy with an auth hook. For anything else: the agent or
  connector for that axis.

Everything is environment variables prefixed `Kalitka__`; the full list with comments is
in [`src/Kalitka/GateOptions.cs`](src/Kalitka/GateOptions.cs), and
[`deploy/.env.example`](deploy/.env.example) has the ones you actually need.

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

**The waiting page polls.** A human has to press a button somewhere, and no
callback can reach that browser. Behaviour-based protection (CrowdSec,
fail2ban) may read that as crawling and ban the visitor — at the *entrypoint*,
which then affects every host, not just the guarded ones. Exempt the `/wait`
path there, keyed on host and path.

**Single-page apps behind the gate.** Only a top-level navigation is redirected
to the gate; a WebSocket, an XHR/fetch or any sub-resource that arrives without
a session gets a `401` instead, because it cannot follow a redirect. The request
kind is read from `Sec-Fetch-Mode`, with `Accept` as a fallback for older
clients — so a cached SPA shell whose background call finds no session sees a
clean `401` rather than a blank page. It still cannot reach the app until you
approve; it just fails honestly instead of hanging.

**Country blocking is coarse.** It is offered for the block list only, and not
at all for the allow list — "everyone from this country walks in" is never right.

## Why the name

*Kalitka* (калитка) is the small garden gate beside the big one — the one with a latch
you open for people you recognise. That is the job.

## License

AGPL-3.0-or-later; a commercial licence is available when the AGPL does not fit.
Contributions are under the CLA, which is what keeps both possible.
