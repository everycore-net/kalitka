# SSH approval gate (proof of concept)

Make an SSH login wait for a human's approval in kalitka — the same door, from a
phone or the web console — before the session is allowed. This is the first PAM
axis and is deliberately a thin vertical slice: it proves the mechanic and
nothing more.

```
ssh prod-01
   → sshd authenticates you (key/password) as usual
   → PAM runs kalitka-approve.sh, which raises an access request in kalitka
   → you approve on Telegram / the web console / an e-mail link
   → the script redeems a one-time grant → a session starts → it exits 0
   → on logout PAM runs kalitka-session-end.sh, which closes the session
   → the request, its approval and the whole session are in /admin/history
```

An approval is not the same as an entry. kalitka issues a short-lived,
single-use *grant* when the request is approved; the approve hook redeems it
exactly once to start a session, and the close hook ends that session. So the
audit log distinguishes `access.approved` (a human said yes) from
`grant.redeemed` / `session.started` / `session.ended` (this login actually
happened) — a second approved login needs a second grant.

## What it is not (yet)

No certificates, no credential brokering, no SSH proxy, no TCP-level gating.
kalitka only turns a human yes/no into a PAM exit code. Which of those to build
next is a decision to make *after* this slice works end to end.

## Install (on the SSH host)

1. `curl` must be present. sshd must use PAM (`UsePAM yes`, the default).
2. Copy both scripts and make them root-owned and executable:
   ```
   install -m 0755 -o root -g root kalitka-approve.sh     /usr/local/bin/kalitka-approve.sh
   install -m 0755 -o root -g root kalitka-session-end.sh /usr/local/bin/kalitka-session-end.sh
   ```
3. Create `/etc/kalitka-approve.conf`, **owned root:root, `chmod 600`** (it is
   sourced by a root PAM hook — treat it as executable input). Both scripts
   share it:
   ```
   install -m 0600 -o root -g root /dev/null /etc/kalitka-approve.conf
   # then edit — preferred: a registered agent (revocable, resource-scoped):
   KALITKA_URL=https://gate.example.com
   KALITKA_AGENT_ID=...               # from /admin/agents
   KALITKA_AGENT_SECRET=...           # shown once on create/rotate
   ```
   Create the agent in the **Agents** console (`/admin/agents`): give it the `ssh`
   capability and the resources it may raise (e.g. `ssh:prod-01`), then copy the id
   and the one-time secret here. Because the agent is individually identified, it
   can be **revoked or rotated** without touching any other host, and it can only
   raise the resources it is scoped to.

   *Deprecated migration path:* leave `KALITKA_AGENT_ID` empty and set
   `KALITKA_AGENT_SECRET` to kalitka's global `Kalitka__AgentSecret`. Either way this
   is **not** the administrative `InternalSecret` — this host never holds a
   credential that can reach `/internal/*`.
4. Add two lines to `/etc/pam.d/sshd`. The approve hook gates entry (after the
   auth/account stack); the session hook closes the session on logout:
   ```
   account required pam_exec.so quiet /usr/local/bin/kalitka-approve.sh
   session  optional pam_exec.so quiet /usr/local/bin/kalitka-session-end.sh
   ```
   The session line is `optional`: a logout cannot be vetoed, so a failure to
   report the close must never wedge it. The approve hook hands the session id
   to the close hook through `/run/kalitka/session-<user>`.

## ⚠️ Keep a way in

This gate is fail-closed: if kalitka is unreachable the script refuses, so a
login is denied. Because pam_exec runs *after* authentication it is a second
factor, not the only one — but do **not** put it on your only path to a host
without a break-glass (a console, or a second sshd/PAM profile without the line).
Test the bypass before you rely on it.

## How it maps to kalitka

- The script calls `POST /agent/request` (host, user, client IP) and polls
  `GET /agent/status?id=…`, both guarded by `X-Kalitka-Agent` (the agent secret,
  separate from the administrative internal secret). If `AgentResources` is set on
  kalitka, an agent may only raise the resources it lists (e.g. `ssh:prod-01`).
- kalitka raises a request for the resource `ssh:<host>`, notifies every
  configured channel, and records `access.requested` / `access.approved` /
  `access.denied` against that resource in the audit log.
- On approval, `GET /agent/status` carries a one-time `grant`. The script
  `POST`s it to `/agent/redeem` (with the agent id) which consumes it once and
  returns a `session_id`; a replayed grant is refused with `409`. The close
  hook then `POST`s that id to `/agent/session/end`. This adds
  `grant.created` / `grant.redeemed` / `session.started` / `session.ended` to
  the audit log — the single-use grant is what keeps an approval from becoming a
  reusable key.
- The allow and block lists work here too (by client IP or user), so a
  remembered source skips the wait and a blocked one is refused silently. An
  allow-list skip grants entry directly and starts no session — there is nothing
  to redeem.
