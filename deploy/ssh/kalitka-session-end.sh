#!/bin/sh
# kalitka SSH session-close hook — proof of concept.
#
# Companion to kalitka-approve.sh. Wired into PAM's *session* stack, pam_exec runs
# this on both session open and close; we act only on close. When the approve hook
# redeemed a grant it left the session id in /run/kalitka/session-<user>; here we
# tell kalitka the session ended, closing the grant.* / session.* lifecycle so the
# audit log reflects a real session, not just an approval.
#
# It never blocks or refuses a logout, and a missing id (login predates this hook,
# or was an allow-list skip with no grant) is simply nothing to report. Correlating
# exactly one session id per PAM close across concurrent logins by the same user is
# best-effort here — robust per-session correlation is deeper-SSH work.
#
# Like the approve hook, all gate I/O and credentials go through kalitka-agent.
# Config is shared: /etc/kalitka-approve.conf.
set -eu

# Only the close phase carries an ended session; open already ran the approve hook.
[ "${PAM_TYPE:-}" = "close_session" ] || exit 0

[ -r /etc/kalitka-approve.conf ] && . /etc/kalitka-approve.conf
AGENT="${KALITKA_AGENT_BIN:-/usr/local/bin/kalitka-agent}"

user="${PAM_USER:-unknown}"
state="/run/kalitka/session-${user}"
[ -r "$state" ] || exit 0                      # nothing was redeemed for this user
sid=$(cat "$state" 2>/dev/null || true)
[ -n "$sid" ] || { rm -f "$state" 2>/dev/null || true; exit 0; }

# Best effort: a hung gate must not wedge logout (kalitka-agent bounds each call).
"$AGENT" session-end --session-id "$sid" --outcome closed >/dev/null 2>&1 || true

rm -f "$state" 2>/dev/null || true
exit 0
