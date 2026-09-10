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
# Config in /etc/kalitka-approve.conf (chmod 600):
#   KALITKA_URL=https://gate.example.com
#   KALITKA_INTERNAL_SECRET=...          # must equal kalitka's Kalitka__InternalSecret
set -eu

[ -r /etc/kalitka-approve.conf ] && . /etc/kalitka-approve.conf
: "${KALITKA_URL:?set KALITKA_URL}"
: "${KALITKA_INTERNAL_SECRET:?set KALITKA_INTERNAL_SECRET}"

host="$(hostname -s 2>/dev/null || hostname)"
user="${PAM_USER:-unknown}"
rhost="${PAM_RHOST:-}"

# jq-free JSON field read: {"id":"AB","state":"waiting"} -> value by key.
field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }

resp=$(curl -fsS -X POST "$KALITKA_URL/agent/request" \
  -H "X-Kalitka-Internal: $KALITKA_INTERNAL_SECRET" \
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
  s=$(curl -fsS -H "X-Kalitka-Internal: $KALITKA_INTERNAL_SECRET" \
      "$KALITKA_URL/agent/status?id=$id" 2>/dev/null | field state) || continue
  case "$s" in
    approved) echo "kalitka: approved." >&2; exit 0 ;;
    denied)   echo "kalitka: denied." >&2;   exit 1 ;;
    gone)     echo "kalitka: request expired." >&2; exit 1 ;;
  esac
done

echo "kalitka: timed out waiting for approval." >&2
exit 1
