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

1. `bash`, `curl` and **OpenSSL 3** must be present (OpenSSL 3 signs Ed25519). sshd
   must use PAM (`UsePAM yes`, the default).
2. Install the reference client and both hooks, root-owned and executable:
   ```
   install -m 0755 -o root -g root kalitka-agent          /usr/local/bin/kalitka-agent
   install -m 0755 -o root -g root kalitka-approve.sh     /usr/local/bin/kalitka-approve.sh
   install -m 0755 -o root -g root kalitka-session-end.sh /usr/local/bin/kalitka-session-end.sh
   ```
   `kalitka-agent` is the universal client: it holds the key and speaks the
   `/agent/v1/*` protocol; the hooks are thin wrappers around it.
3. Create `/etc/kalitka-approve.conf`, **owned root:root, `chmod 600`** (it is
   sourced by a root PAM hook — treat it as executable input). The agent and both
   hooks share it:
   ```
   install -m 0600 -o root -g root /dev/null /etc/kalitka-approve.conf
   # then edit:
   KALITKA_URL=https://gate.example.com
   KALITKA_AGENT_ID=...                        # from /admin/agents
   KALITKA_AGENT_KEY=/etc/kalitka/agent.key    # Ed25519 private key (preferred)
   ```
   Create the agent in the **Agents** console (`/admin/agents`): give it the `ssh`
   capability and the resources it may raise (e.g. `ssh:prod-01`). Then, on the host,
   generate a key and register its public half — no reusable secret ever leaves the
   box:
   ```
   KALITKA_AGENT_KEY=/etc/kalitka/agent.key kalitka-agent keygen
   # → prints the base64 public key; paste it into the agent's "Add key" on /admin/agents
   ```
   The agent is individually identified, so it can be **revoked or rotated** (remove
   the key, or the whole agent) without touching any other host, and it can only
   raise the resources it is scoped to.

   *Migration fallback:* instead of a key, set `KALITKA_AGENT_SECRET` (the secret
   shown once on create/rotate); the client sends it with `X-Kalitka-Agent-Id`. Or,
   deprecated, leave `KALITKA_AGENT_ID` empty and set `KALITKA_AGENT_SECRET` to
   kalitka's global `Kalitka__AgentSecret`. Either way this is **not** the
   administrative `InternalSecret` — this host never holds a credential that can
   reach `/internal/*`. Prefer a key; drop the secret once signing works.

   *Key-based enrolment (alternative to create+add-key):* mint an enrollment token in
   the console, then `kalitka-agent enroll --token <token>` generates the key and
   registers its public half in one step.
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

- Via `kalitka-agent`, the approve hook calls `POST /agent/v1/requests` (host, user,
  client IP) and polls `GET /agent/v1/requests/{id}`. Each call is authenticated by an
  **Ed25519 signature** over the request (or, in the migration fallback, the shared
  secret). The signature/secret is separate from the administrative internal secret.
  An agent may only raise the resources it is scoped to (e.g. `ssh:prod-01`).
- kalitka raises a request for the resource `ssh:<host>`, notifies every configured
  channel, and records `access.requested` / `access.approved` / `access.denied`
  against that resource in the audit log.
- On approval, `GET /agent/v1/requests/{id}` carries a one-time `grant`. The client
  `POST`s it to `/agent/v1/grants/redeem`, which consumes it once and returns a
  `session_id`; a replayed grant is refused with `409`. The close hook then `POST`s
  that id to `/agent/v1/sessions/end`. This adds `grant.created` / `grant.redeemed` /
  `session.started` / `session.ended` to the audit log — the single-use grant is what
  keeps an approval from becoming a reusable key. (An access **policy** may also
  require more than one approver, or shorten the grant's TTL, for this resource.)
- The allow and block lists work here too (by client IP or user), so a remembered
  source skips the wait and a blocked one is refused silently. An allow-list skip
  grants entry directly and starts no session — there is nothing to redeem.
