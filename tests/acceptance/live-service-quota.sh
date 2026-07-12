#!/usr/bin/env bash
# live-service-quota.sh -- OPERATOR/AGENT-run live acceptance for the drvpsvc service-plane gate.
# Run as a member of BOTH the drvpsctl and drvpsvc groups, after dr-vps-setup (watcher up) with a
# golden registered:
#
#     DRVPS_LIVE=1 tests/acceptance/live-service-quota.sh
#
# Proves the class=service admission gate end-to-end on real KVM (dr_vps_domain.sh _dr_vps_service_admit):
# a drvpsvc member can create class=service VMs up to the per-account quota, and the NEXT create is
# REFUSED fail-closed (E_CAP, "quota reached N/N"), counted PER OWNER uid. Service VMs are reaper-exempt,
# so the test destroys every one it creates (cleanup trap covers early exits too).
set -uo pipefail
[ "${DRVPS_LIVE:-}" = 1 ] || { echo "set DRVPS_LIVE=1 to run the live service-quota acceptance"; exit 0; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RIGCTL="${DRVPS_RIGCTL:-$ROOT/bin/rigctl}"
DISTRO="${DRVPS_DISTRO:-fedora44}"
MAXTRY="${DRVPS_MAXTRY:-8}"   # safety cap: the quota is small (default 3); stop well before a runaway

fail() { echo "SERVICE-QUOTA-ACCEPTANCE FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }
# field <key>: read one field from a rigctl JSON envelope on stdin (int-safe: 0 prints "0", absent prints "")
field() { python3 -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else str(v).strip())' "$1" 2>/dev/null; }

ids=()
cleanup() { [ "${#ids[@]}" -gt 0 ] && for v in "${ids[@]}"; do "$RIGCTL" destroy "$v" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT

created=0; refused=0; refmsg=""
for i in $(seq 1 "$MAXTRY"); do
  out="$("$RIGCTL" create "svcq-$$-$i" "$DISTRO" 24 1024 1 --class service 2>&1)" || true
  vm="$(printf '%s' "$out" | field stdout)"
  ec="$(printf '%s' "$out" | field exit_code)"
  err="$(printf '%s' "$out" | field stderr)"
  if [ -n "$vm" ] && [ "$ec" = 0 ]; then
    ids+=("$vm"); created=$((created + 1)); step "created #$created: $vm"
  else
    refused=1; refmsg="$err"; step "refused at attempt $i (exit=$ec): $err"; break
  fi
done

[ "$created" -ge 1 ] || fail "no service VM created -- is a '$DISTRO' golden registered and are you in drvpsvc?"
[ "$refused" = 1 ]   || fail "quota never fired within $MAXTRY attempts (created=$created; quota misconfigured?)"
case "$refmsg" in *"quota reached"*) : ;; *) fail "refusal was not a quota refusal: $refmsg" ;; esac
quota="$(printf '%s' "$refmsg" | grep -oE '\([0-9]+/[0-9]+\)' | tr -d '()')"
[ "${quota%%/*}" = "$created" ] || fail "quota count mismatch: message reports $quota but $created were created"
step "quota gate OK: $created created, next refused ($quota)"

step "destroy all $created service VMs (reaper-exempt -> explicit)"
for v in "${ids[@]}"; do
  d="$("$RIGCTL" destroy "$v" 2>&1)"
  [ "$(printf '%s' "$d" | field exit_code)" = 0 ] || fail "destroy $v failed: $d"
done
ids=(); trap - EXIT
left="$("$RIGCTL" list 2>&1 | field stdout)"
[ -z "$left" ] || fail "VMs remain after cleanup: $left"
echo "SERVICE-QUOTA-ACCEPTANCE PASS (quota=$quota, all created VMs destroyed, rig clean)"
