#!/bin/sh
# kalitka SSH approval gate — proof of concept.
#
# Called by sshd via PAM (pam_exec) AFTER authentication. It raises an access
# request in kalitka for ssh:<this host> by the logging-in user, then blocks
# until a human approves through Telegram, the web console or e-mail. Exit 0 lets
# the session continue; non-zero refuses it.
#
# It brokers no credentials and proxies nothing — it only turns a human yes/no
# into an exit code. Because pam_exec runs after authentication, it is a SECOND
# factor, never the only one.
#
# Config in /etc/kalitka-approve.conf — this file is sourced by root into a PAM
# hook, so it is executable input: make it root:root and chmod 600.
#   KALITKA_URL=https://gate.example.com
#   # Preferred: a registered agent (individually revocable, resource-scoped) from
#   # the /admin/agents console:
#   KALITKA_AGENT_ID=...                  # the agent id
#   KALITKA_AGENT_SECRET=...              # its secret (shown once on create/rotate)
#   # Deprecated migration path: leave KALITKA_AGENT_ID empty and set
#   # KALITKA_AGENT_SECRET to kalitka's global Kalitka__AgentSecret.
#   # Either way this is NOT the administrative Kalitka__InternalSecret.
set -eu

[ -r /etc/kalitka-approve.conf ] && . /etc/kalitka-approve.conf
: "${KALITKA_URL:?set KALITKA_URL}"
: "${KALITKA_AGENT_SECRET:?set KALITKA_AGENT_SECRET}"

# Prefer per-agent credentials (the registry); fall back to the legacy global
# secret. Values are tokens without spaces, so unquoted $AUTH word-splits cleanly.
if [ -n "${KALITKA_AGENT_ID:-}" ]; then
  AUTH="-H X-Kalitka-Agent-Id:$KALITKA_AGENT_ID -H X-Kalitka-Agent-Secret:$KALITKA_AGENT_SECRET"
else
  AUTH="-H X-Kalitka-Agent:$KALITKA_AGENT_SECRET"
fi

# Hard caps so a hung TCP/TLS request cannot hold the SSH login open: this bounds
# each curl, not just the number of poll iterations.
CURL="curl -fsS --connect-timeout 5 --max-time 10"

host="$(hostname -s 2>/dev/null || hostname)"
user="${PAM_USER:-unknown}"
rhost="${PAM_RHOST:-}"

# jq-free JSON field read: {"id":"AB","state":"waiting"} -> value by key.
field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }

resp=$($CURL -X POST "$KALITKA_URL/agent/request" \
  $AUTH \
  --data-urlencode "host=$host" \
  --data-urlencode "user=$user" \
  --data-urlencode "ip=$rhost" 2>/dev/null) \
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
  st=$($CURL $AUTH \
       "$KALITKA_URL/agent/status?id=$id" 2>/dev/null) || continue
  case "$(printf '%s' "$st" | field state)" in
    approved)
      # Approval is not entry: redeem the one-time grant to start a session.
      grant=$(printf '%s' "$st" | field grant)
      red=$($CURL -X POST "$KALITKA_URL/agent/redeem" \
            $AUTH \
            --data-urlencode "grant=$grant" --data-urlencode "agent=$host" 2>/dev/null) \
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
