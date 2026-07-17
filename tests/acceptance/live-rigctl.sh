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
# Resolve rig config the same way bin/rigctl does, so the S5 step below inspects the SAME spool the
# client uses (a custom-spool rig sets DR_VPS_SPOOL_DIR only in this file). The S5 privacy-mode
# verdict must NOT trust the merged environment (a stale session export would mask a real
# regression), so remember whether the CALLER explicitly set DR_VPS_RESULT_PRIVATE before the env
# file is sourced: an explicit session value is honored as a deliberate override (the documented
# escape for rigs whose opt-out lives in a systemd drop-in); otherwise the env FILE decides.
S5_SESSION_SET="${DR_VPS_RESULT_PRIVATE+x}"
S5_SESSION_VAL="${DR_VPS_RESULT_PRIVATE-}"
# shellcheck disable=SC1091
[ -r /etc/distro-rig-vps/env ] && . /etc/distro-rig-vps/env
RIGCTL="${DRVPS_RIGCTL:-$ROOT/bin/rigctl}"
DISTRO="${DRVPS_DISTRO:-fedora44}"
NAME="${DRVPS_NAME:-rigacc}"

fail() { echo "RIGCTL-ACCEPTANCE FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }
# run a verb, require status ok|preempted; echo the result; fail otherwise.
# Progress goes to STDERR: stdout must stay envelope-pure -- capturing callers pipe it to jq.
rc() {
  local out st
  out=$("$RIGCTL" "$@") || fail "rigctl $1 transport failed"
  st=$(printf '%s' "$out" | jq -r '.status // "?"')
  echo "  [$1] status=$st" >&2
  case "$st" in ok|preempted) printf '%s' "$out" ;; *) echo "$out" >&2; fail "rigctl $1 -> $st" ;; esac
}

command -v jq >/dev/null || fail "jq required"
[ -x "$RIGCTL" ] || fail "no rigctl at $RIGCTL"

step "create a VM via the agent loop"
res=$(rc create "$NAME" "$DISTRO")
id=$(printf '%s' "$res" | jq -r '.stdout' | tr -d '[:space:]')
[ -n "$id" ] || fail "create returned no vm id"
echo "  vm: $id"
# Any fail below would otherwise leak this VM until TTL-reap; best-effort destroy on abort.
trap '"$RIGCTL" destroy "$id" >/dev/null 2>&1 || true' EXIT

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
# On GENUINE success rigctl prints the DECODED SANITIZED dump text (not the JSON envelope) and
# exits 0; on any failure it prints the envelope and exits nonzero. So call it directly -- routing
# it through rc() would feed plain text to jq and false-FAIL a healthy rig.
if ! dump=$("$RIGCTL" console-dump "$id"); then
  printf '%s\n' "$dump" >&2
  fail "console-dump failed"
fi
echo "  [console-dump] status=ok"
[ -n "$dump" ] && [ "$(printf '%s' "$dump" | wc -c)" -ge 16 ] \
  || fail "console-dump returned empty/near-empty serial output (pty attach may be broken)"

step "result-store privacy (S5): THIS run's result is owner-granted, group/other-denied"
# Deterministic S5 proof on the real rig: submit one cheap read and inspect ITS OWN result file
# (results/<reqid>.json -- the envelope carries the reqid, and the watcher never unlinks results
# before the TTL sweep). That checks the file THIS uid caused, so we can assert the POSITIVE half
# of S5 (the requester's named-owner grant) as well as the negative (group/other denied), and a
# concurrent other-owner result cannot be sampled by mistake. The verdict is judged against the
# rig's CONFIGURED mode (explicit caller export, else the env FILE -- see the top-of-file note):
# a group-readable result is a FAIL unless DR_VPS_RESULT_PRIVATE=0 is actually configured -- an
# assumed "legacy opt-out" NOTE
# would bless exactly the regression this step exists to catch (stale pre-S5 watcher, launcher
# bypass, env drift). The earlier rc steps already proved membership + a working rig, so a missing
# results dir here is an anomaly (FAIL), not an environment limitation (SKIP); the offline suite
# (tests/drvps-write-result-test.py) asserts the exact ACL entry set.
SPOOL="${DR_VPS_SPOOL_DIR:-/var/spool/distro-rig-vps}"
S5_MODE="private"
if [ -n "$S5_SESSION_SET" ]; then
  [ "$S5_SESSION_VAL" = 0 ] && S5_MODE="legacy-optout"
elif [ -r /etc/distro-rig-vps/env ] && grep -Eq 'DR_VPS_RESULT_PRIVATE[:=]+ *"?0"?' /etc/distro-rig-vps/env; then
  S5_MODE="legacy-optout"
fi
S5_STATUS="unverified"
me=$(id -u)
[ -d "$SPOOL/results" ] || fail "results dir $SPOOL/results not visible although rigctl verbs succeeded (2750 group-listable is part of the install contract)"
sres=$(rc list)
rid=$(printf '%s' "$sres" | jq -r '.reqid // empty')
rf="$SPOOL/results/$rid.json"
{ [ -n "$rid" ] && [ -f "$rf" ]; } || fail "cannot locate this run's own result file (reqid='$rid')"
if ! command -v getfacl >/dev/null 2>&1; then
  # The S5 launcher hard-requires the acl package, so in private mode a missing getfacl means a
  # pre-S5 rig or a bypassed launcher -- exactly what must not pass silently.
  [ "$S5_MODE" = legacy-optout ] || fail "getfacl absent in private mode (pre-S5 rig or bypassed launcher?)"
  echo "  SKIP: getfacl absent -- structural check skipped (DR_VPS_RESULT_PRIVATE=0 is configured)"
  S5_STATUS="skipped-legacy-no-getfacl"
else
  facl=$(getfacl -pcn "$rf" 2>&1) || fail "getfacl failed on $rf: $facl"
  facl=$(printf '%s\n' "$facl" | sed 's/#.*//; s/[[:space:]]*$//' | grep -v '^$')
  [ -n "$facl" ] || fail "getfacl returned no ACL entries for $rf"
  printf '%s\n' "$facl" | grep -qx 'other::---' || fail "own result $rid.json is other-readable: $facl"
  # -n: named entries print by uid/gid; base entries keep an empty qualifier (user:: / group::).
  stray=$(printf '%s\n' "$facl" | grep -E '^(user|group):[^:]+:' | grep -Fxv "user:$me:r--" || true)
  case "$(printf '%s\n' "$facl" | grep '^group::')" in
    'group::---')
      printf '%s\n' "$facl" | grep -qx "user:$me:r--" \
        || fail "own result $rid.json lacks the named-owner grant user:$me:r--: $facl"
      printf '%s\n' "$facl" | grep -qx 'mask::r--' \
        || fail "own result $rid.json mask is not r-- (named-owner grant ineffective): $facl"
      [ -z "$stray" ] || fail "stray named ACL entries on own result $rid.json: $stray"
      [ "$S5_MODE" = private ] \
        || echo "  NOTE: DR_VPS_RESULT_PRIVATE=0 is configured but the result is private anyway (watcher not restarted since the env change, or a unit drop-in overrides it?)"
      echo "  result-store privacy OK: $rid.json owner-granted (uid $me), group+other denied, no strays"
      S5_STATUS="private-verified"
      ;;
    'group::r--')
      [ "$S5_MODE" = legacy-optout ] \
        || fail "own result $rid.json is GROUP-READABLE but the rig env does NOT set DR_VPS_RESULT_PRIVATE=0 -- S5 privacy is not in effect (stale pre-S5 watcher? launcher bypass? opt-out configured outside the env file, e.g. a unit drop-in? -- export DR_VPS_RESULT_PRIVATE=0 to this script if the opt-out is deliberate)"
      [ -z "$stray" ] || fail "stray named ACL entries on own result $rid.json: $stray"
      echo "  NOTE: legacy group-readable results -- DR_VPS_RESULT_PRIVATE=0 is explicitly configured"
      S5_STATUS="legacy-optout-configured"
      ;;
    *) fail "unexpected group ACL on own result $rid.json: $facl" ;;
  esac
fi

step "destroy"
rc destroy "$id" >/dev/null
trap - EXIT

echo "RIGCTL-ACCEPTANCE PASS (agent loop: create/wait/exec-destructive/recreate/verify-clean/destroy; S5=$S5_STATUS)"
