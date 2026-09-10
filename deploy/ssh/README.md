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
   → the script exits 0 and the session continues
   → the request and its approval are in /admin/history
```

## What it is not (yet)

No certificates, no credential brokering, no SSH proxy, no TCP-level gating.
kalitka only turns a human yes/no into a PAM exit code. Which of those to build
next is a decision to make *after* this slice works end to end.

## Install (on the SSH host)

1. `curl` must be present. sshd must use PAM (`UsePAM yes`, the default).
2. Copy the script and make it root-owned and executable:
   ```
   install -m 0755 -o root -g root kalitka-approve.sh /usr/local/bin/kalitka-approve.sh
   ```
3. Create `/etc/kalitka-approve.conf`, **owned root:root, `chmod 600`** (it is
   sourced by a root PAM hook — treat it as executable input):
   ```
   install -m 0600 -o root -g root /dev/null /etc/kalitka-approve.conf
   # then edit:
   KALITKA_URL=https://gate.example.com
   KALITKA_AGENT_SECRET=...           # equals kalitka's Kalitka__AgentSecret
   ```
   Use `AgentSecret`, **not** the administrative `InternalSecret` — that is the
   point of the split: this host never holds a credential that can reach
   `/internal/*`.
4. Add one line to `/etc/pam.d/sshd`, **after** the auth/account stack:
   ```
   account required pam_exec.so quiet /usr/local/bin/kalitka-approve.sh
   ```

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
- The allow and block lists work here too (by client IP or user), so a
  remembered source skips the wait and a blocked one is refused silently.
