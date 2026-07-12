#!/usr/bin/env bash
# live-rigctl.sh -- OPERATOR/AGENT-run Phase-2 acceptance: the FULL agent control loop on real
# KVM, driven ONLY through the spool (no sudo, no /dev/kvm for the caller). Run as a member of
# the drvpsctl group, AFTER dr-vps-setup (watcher running) and with a golden already registered:
#
#     DRVPS_LIVE=1 tests/acceptance/live-rigctl.sh
#
# It proves: the agent can create -> wait -> run a DESTRUCTIVE command in the guest -> reset it
# with recreate -> verify clean -> destroy, all via rigctl, with the watcher (drvps) executing.
set -uo pipefail
[ "${DRVPS_LIVE:-}" = 1 ] || { echo "set DRVPS_LIVE=1 to run the live agent-loop acceptance"; exit 0; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RIGCTL="${DRVPS_RIGCTL:-$ROOT/bin/rigctl}"
DISTRO="${DRVPS_DISTRO:-fedora44}"
NAME="${DRVPS_NAME:-rigacc}"

fail() { echo "RIGCTL-ACCEPTANCE FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }
# run a verb, require status ok|preempted; echo the result; fail otherwise.
rc() {
  local out st
  out=$("$RIGCTL" "$@") || fail "rigctl $1 transport failed"
  st=$(printf '%s' "$out" | jq -r '.status // "?"')
  echo "  [$1] status=$st"
  case "$st" in ok|preempted) printf '%s' "$out" ;; *) echo "$out" >&2; fail "rigctl $1 -> $st" ;; esac
}

command -v jq >/dev/null || fail "jq required"
[ -x "$RIGCTL" ] || fail "no rigctl at $RIGCTL"

step "create a VM via the agent loop"
res=$(rc create "$NAME" "$DISTRO")
id=$(printf '%s' "$res" | jq -r '.stdout' | tr -d '[:space:]')
[ -n "$id" ] || fail "create returned no vm id"
echo "  vm: $id"

step "wait for readiness"
rc wait "$id" >/dev/null

step "useradd a marker user (proves a guest mutation), then run a DESTRUCTIVE command"
rc exec "$id" 'useradd marker 2>/dev/null; getent passwd marker >/dev/null && echo HAVE_MARKER' >/dev/null
rc exec "$id" 'echo c > /proc/sysrq-trigger 2>/dev/null; rm -rf /var/lib/* 2>/dev/null; true' >/dev/null

step "recreate -> reset to the pinned golden"
rc recreate "$id" >/dev/null
rc wait "$id" >/dev/null

step "verify the marker user is GONE (clean golden)"
res=$(rc exec "$id" 'getent passwd marker >/dev/null && echo STILL_HERE || echo GONE')
printf '%s' "$res" | jq -r '.stdout' | grep -q GONE || fail "recreate did NOT reset the guest"

step "console-dump returns NON-EMPTY serial output (real pty attach)"
# The seamed suite can't exercise the real `virsh console --force </dev/null` pty attach: on real
# KVM it could return an empty ok-envelope forever and no seamed test would go red. Prove here that
# a booted guest yields actual serial bytes (boot/login banner) through the guest-exec-gated verb.
res=$(rc console-dump "$id")
dump=$(printf '%s' "$res" | jq -r '.stdout')
[ -n "$dump" ] && [ "$(printf '%s' "$dump" | wc -c)" -ge 16 ] \
  || fail "console-dump returned empty/near-empty serial output (pty attach may be broken)"

step "destroy"
rc destroy "$id" >/dev/null

echo "RIGCTL-ACCEPTANCE PASS (agent loop: create/wait/exec-destructive/recreate/verify-clean/destroy)"
