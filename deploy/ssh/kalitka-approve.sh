#!/bin/sh
# kalitka SSH approval gate — proof of concept.
#
# Called by sshd via PAM (pam_exec) AFTER authentication. It raises an access
# request for ssh:<this host> by the logging-in user, then blocks until a human
# approves through Telegram, the web console or e-mail. Exit 0 lets the session
# continue; non-zero refuses it. Because pam_exec runs after authentication, it is
# a SECOND factor, never the only one. It brokers no credentials and proxies
# nothing — it only turns a human yes/no into an exit code.
#
# All gate I/O and credentials go through kalitka-agent: this hook is a thin
# wrapper, so the strong (Ed25519-signed) credential model is used automatically
# when a key is present. Config in /etc/kalitka-approve.conf (root:root, 600):
#   KALITKA_URL=https://gate.example.com
#   KALITKA_AGENT_ID=...                        # the registered agent id
#   KALITKA_AGENT_KEY=/etc/kalitka/agent.key    # Ed25519 private key (preferred)
#   # Migration fallback only, until the agent is key-based:
#   # KALITKA_AGENT_SECRET=...
#   KALITKA_AGENT_BIN=/usr/local/bin/kalitka-agent   # optional, this is the default
set -eu

[ -r /etc/kalitka-approve.conf ] && . /etc/kalitka-approve.conf
AGENT="${KALITKA_AGENT_BIN:-/usr/local/bin/kalitka-agent}"

# jq-free JSON field read: {"id":"AB","state":"waiting"} -> value by key.
field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }

host="$(hostname -s 2>/dev/null || hostname)"
user="${PAM_USER:-unknown}"
rhost="${PAM_RHOST:-}"

resp=$("$AGENT" request --host "$host" --user "$user" --ip "$rhost" 2>/dev/null) \
  || { echo "kalitka: gate unreachable, refusing." >&2; exit 1; }

state=$(printf '%s' "$resp" | field state)
id=$(printf '%s' "$resp" | field id)

case "$state" in
  allowed) exit 0 ;;                              # on the allow list, no wait
  blocked) echo "kalitka: refused." >&2; exit 1 ;;
esac

echo "kalitka: waiting for approval of ${user}@${host}..." >&2

# Poll for up to ~5 minutes — the request's own lifetime.
i=0
while [ "$i" -lt 100 ]; do
  sleep 3
  i=$((i + 1))
  st=$("$AGENT" poll --id "$id" 2>/dev/null) || continue
  case "$(printf '%s' "$st" | field state)" in
    approved)
      # Approval is not entry: redeem the one-time grant to start a session.
      grant=$(printf '%s' "$st" | field grant)
      red=$("$AGENT" redeem --grant "$grant" --agent "$host" 2>/dev/null) \
        || { echo "kalitka: grant redemption failed." >&2; exit 1; }
      sid=$(printf '%s' "$red" | field session_id)
      [ -n "$sid" ] || { echo "kalitka: grant not redeemable (already used or expired)." >&2; exit 1; }
      # Hand the session id to the PAM session-close hook (best effort; one
      # concurrent session per user in this PoC — robust correlation is later).
      mkdir -p /run/kalitka 2>/dev/null && printf '%s' "$sid" > "/run/kalitka/session-${user}" 2>/dev/null || true
      echo "kalitka: approved." >&2
      exit 0 ;;
    denied) echo "kalitka: denied." >&2; exit 1 ;;
    gone)   echo "kalitka: request expired." >&2; exit 1 ;;
  esac
done

echo "kalitka: timed out waiting for approval." >&2
exit 1
