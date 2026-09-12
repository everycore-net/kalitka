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

## What it is not

The PAM hook gates entry as a second factor; it brokers no credential and does not
issue certificates. For **JIT access via short-lived certificates**, see the next
section — a different, self-expiring mechanism that composes the same approval flow.

## JIT certificates (`kalitka-ssh`)

The certificate analogue of the DB connector, same architecture and philosophy:

```
kalitka Core  --signed grant-->  kalitka-ssh (holds the CA)  -->  target host
 (control plane)                  (on a bastion)
```

On a host you already reach (a bastion), `kalitka-ssh connect --host prod-01` mints an
**ephemeral** keypair, raises an access request, waits for a human's approval, and on
approval signs a **short-lived OpenSSH user certificate** — principals from the request,
validity from the grant's `expires_at` (which already reflects any access policy) — then
`exec`s `ssh` onto the target. You land with a cert that **self-expires**: nothing to
revoke, nothing to leak, and a crash leaves no standing access. *Core never holds the CA
key* — it only decides yes/no. The certificate IS the time-boxed authority.

```
kalitka-ssh connect --host prod-01 --user sergej
   → ephemeral keypair in a tmpdir (shredded on exit)
   → raises ssh:prod-01, waits for approval, redeems a grant
   → signs a cert: principals=sergej, key-id=kalitka:<session>, valid ≈ grant TTL
   → exec ssh onto prod-01; on logout the session is reported ended
```

Why this is nice: the cert's `key-id` is `kalitka:<session-id>`, so sshd's auth log ties
straight back to the kalitka audit trail; and because access is a short cert rather than
a standing grant, there is no reconcile/orphan problem at all — expiry is intrinsic.

### Command-aware access (`--command`)

For a single, unambiguous operation, grant exactly that — not a shell. `--command` requests
a **force-command** certificate: the human approves the exact command (it is shown in the
approval and recorded in the audit trail), and the issued cert can run **only** it.

```
kalitka-ssh connect --host prod-01 --user deploy --command 'systemctl restart nginx'
   → the approval shows "Command: systemctl restart nginx"
   → the cert carries force-command="systemctl restart nginx"
   → the session can run nothing else, for the grant's short TTL
```

This is the SSH analogue of the database `action` mode (0.24): sergej → prod-01 → exactly
`systemctl restart nginx` → approved by N people (raise the quorum with a policy). The
command is bound the same way as the principal — Core returns the **approved** command on
redeem and the signer forces only that, never a caller argument chosen after approval.

A policy can **require** a command for a resource (no open shells): set *require a command*
on the policy (`RequireCommand`). A request for that resource with no command is refused
up front (`command-required`) — nobody is even asked to approve an open shell that policy
disallows.

### Install (on the bastion / CA host)

1. `bash`, `curl`, **OpenSSL 3**, and **`ssh`/`ssh-keygen`** must be present.
2. Install the reference client and the tool:
   ```
   install -m 0755 -o root -g root kalitka-agent /usr/local/bin/kalitka-agent
   install -m 0755 -o root -g root kalitka-ssh   /usr/local/bin/kalitka-ssh
   ```
3. Enrol this host as a kalitka agent (capability `ssh`, resources e.g. `ssh:*`) and give
   it a key, exactly as for the PAM hook above; its gate config is the shared
   `/etc/kalitka-approve.conf`. Optionally set `/etc/kalitka/ssh-ca.conf`
   (`KALITKA_SSH_CA_KEY`, `KALITKA_SSH_CERT_OPTS`).
4. Create the CA and print its public key: `kalitka-ssh keygen`. The CA **private** key
   stays here (`root:root`, `0600`); nothing else ever sees it.
5. On every **target** host, trust the CA and require a matching principal:
   ```
   # /etc/ssh/sshd_config
   TrustedUserCAKeys /etc/ssh/kalitka_ca.pub      # the output of `kalitka-ssh keygen`
   ```
   The cert is issued for the requested `--user`, which is the principal, so a standard
   login as that user is accepted. Restrict further with `AuthorizedPrincipalsFile` if
   you want a principal ↔ login map.

Certificates default to conservative options (`permit-pty` only — no agent/port/X11
forwarding); override with `KALITKA_SSH_CERT_OPTS`. `kalitka-ssh sign --pubkey FILE` is
the lower-level path when the user's key lives elsewhere and only the cert comes back.

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

   *Secretless enrolment (alternative to create+add-key):* mint an enrollment token in
   the console, then `kalitka-agent enroll --token <token>` generates the key, registers
   its public half, and sends **no secret** — the agent is created with no usable shared
   secret at all, so signatures are the only way in.
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
