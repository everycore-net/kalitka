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

- A reverse proxy that speaks forwardAuth (Traefik, nginx `auth_request`,
  Caddy `forward_auth`).
- A Telegram bot ([@BotFather](https://t.me/botfather)) and your Telegram user id.
- Docker, or .NET 9 if you would rather run it directly.

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

## Bot commands

| Command | What it does |
|---|---|
| `/blocked` | show the block list, with buttons to remove entries |
| `/allowed` | show the allow list |
| `/hosts` | which hosts are currently guarded |
| `/mute [min]` | stop notifying; silently block every new caller by IP |
| `/unmute` | back to normal |
| `/session [min]` | how long an approval lasts |

## Configuration

Everything is environment variables prefixed `Kalitka__`. The full list with
comments is in [`src/Kalitka/GateOptions.cs`](src/Kalitka/GateOptions.cs);
[`deploy/.env.example`](deploy/.env.example) has the ones you actually need.

The app refuses to start without `BotToken`, `WebhookPath`, `WebhookSecret`,
`HmacSecret` and `GateHost` — an open webhook or an unsigned cookie fails
silently, a service that does not come up does not.

## Things worth knowing before you deploy

**Keep a way back in.** forwardAuth is fail-closed: if kalitka is down, nothing
reaches the guarded hosts. `BypassNetworks` (your LAN) is the tested way back;
removing the middleware line is the last resort. Test the bypass *before* you
need it.

**Sessions are a signed cookie, not server state.** Nothing to persist, and
rotating `HmacSecret` logs everyone out at once. The cookie is set on the parent
domain, so one approval covers every guarded host.

**The waiting page polls.** A human has to press a button somewhere, and no
callback can reach that browser. Behaviour-based protection (CrowdSec,
fail2ban) may read that as crawling and ban the visitor — at the *entrypoint*,
which then affects every host, not just the guarded ones. Exempt the `/wait`
path there, keyed on host and path.

**Single-page apps and a redirect gate.** A cached SPA shell can hit the gate's
redirect with a background request and end up showing a blank page. Kalitka
suits things you open fresh far better than a PWA you keep installed.

**Country blocking is coarse.** It is offered for the block list only, and not
at all for the allow list — "everyone from this country walks in" is never right.

## Why the name

*Kalitka* (калитка) is the small garden gate next to the big one — the one with
a latch you open for people you recognise. That is the job.

## License

[MIT](LICENSE).
