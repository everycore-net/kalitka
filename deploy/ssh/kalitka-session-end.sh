#!/bin/sh
# kalitka SSH session-close hook — proof of concept.
#
# Companion to kalitka-approve.sh. Wired into PAM's *session* stack, pam_exec
# runs this on both session open and close; we act only on close. When the
# approve hook redeemed a grant it left the session id in /run/kalitka/session-
# <user>; here we tell kalitka the session ended, closing the grant.* /
# session.* lifecycle so the audit log reflects a real session, not just an
# approval.
#
# This never blocks or refuses a logout: a session close cannot be vetoed, and a
# missing id (login predates this hook, or was an allow-list skip with no grant)
# is simply nothing to report. Correlating exactly one session id per PAM close
# across concurrent logins by the same user is best-effort here — robust
# per-session correlation is deeper-SSH work.
#
# Config is shared with kalitka-approve.sh: /etc/kalitka-approve.conf.
set -eu

# Only the close phase carries an ended session; open already ran the approve hook.
[ "${PAM_TYPE:-}" = "close_session" ] || exit 0

[ -r /etc/kalitka-approve.conf ] && . /etc/kalitka-approve.conf
: "${KALITKA_URL:?set KALITKA_URL}"
: "${KALITKA_AGENT_SECRET:?set KALITKA_AGENT_SECRET}"

# Same credential choice as the approve hook: per-agent registry, else legacy.
if [ -n "${KALITKA_AGENT_ID:-}" ]; then
  AUTH="-H X-Kalitka-Agent-Id:$KALITKA_AGENT_ID -H X-Kalitka-Agent-Secret:$KALITKA_AGENT_SECRET"
else
  AUTH="-H X-Kalitka-Agent:$KALITKA_AGENT_SECRET"
fi

user="${PAM_USER:-unknown}"
state="/run/kalitka/session-${user}"
[ -r "$state" ] || exit 0                      # nothing was redeemed for this user
sid=$(cat "$state" 2>/dev/null || true)
[ -n "$sid" ] || { rm -f "$state" 2>/dev/null || true; exit 0; }

# Bounded like the approve hook: a hung gate must not wedge logout.
curl -fsS --connect-timeout 5 --max-time 10 -X POST "$KALITKA_URL/agent/v1/sessions/end" \
  $AUTH \
  --data-urlencode "session_id=$sid" \
  --data-urlencode "outcome=closed" >/dev/null 2>&1 || true

rm -f "$state" 2>/dev/null || true
exit 0
