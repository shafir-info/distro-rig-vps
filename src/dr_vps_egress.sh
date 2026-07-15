#!/usr/bin/env bash
# dr_vps_egress.sh -- drvpsvc MEMBER-facing egress-splice registration (egress-splice task 1.4).
# A drvpsvc member submits/lists/queries splice-destination requests over the socket; the ROOT operator
# opens the approved ones with bin/drvps-egress-approve. This module is only the ADMIT gate + a thin
# wrapper over tools/drvps_egress_member.py (which holds the store logic, caps, idempotency, and
# already-active/absent). The owner (SO_PEERCRED uid) is threaded from the watcher as --owner and is the
# AUTHORITATIVE identity -- never a client-supplied value. ASCII only.

# v2 store anchor: a FIXED root-owned path (docs/EGRESS-STORE-ARCH-UPGRADE.md). It MUST equal
# drvps_egress_layout.ANCHOR and the approve tool's L.ANCHOR (the privileged approve CLI has NO runtime
# path seam, so the anchor + drvps identity are fixed constants everywhere -- a STATE_DIR-derived anchor
# would split the store from the approve tool). tests/egress-setup-lock.sh asserts
# this literal == L.ANCHOR. The member BINDS the lock to this base (no --lock seam).
: "${DR_VPS_EGRESS_BASE:=/var/lib/distro-rig-vps-egress}"

_dr_vps_egress_tools() { ( cd "$(dirname "${BASH_SOURCE[0]}")/../tools" && pwd ); }

# admit: empty owner OR uid 0 = the direct operator (admin) -> allowed. Otherwise the caller must be a
# member of the drvpsvc service group (same gate as class=service, minus the quota -- caps are in python).
_dr_vps_egress_admit() {  # <owner_uid|''>
  local owner="$1"
  { [ -z "$owner" ] || [ "$owner" = 0 ]; } && return 0
  local grp="${DR_VPS_SERVICE_GROUP:-drvpsvc}"
  _dr_vps_groups_of "$owner" | tr ' \t' '\n' | grep -qxF "$grp" \
    || { dr_vps_die "$DR_VPS_E_CAP" "egress registration requires membership in the '$grp' group (uid $owner)"; return $?; }
}

# dr-vps egress <subop> [host [port]] [--owner U]
# subop: add-splice | remove-splice | list | status. Prints the member module's JSON to stdout.
dr_vps_egress_cmd() {
  local subop="${1:-}"; [ "$#" -gt 0 ] && shift
  local owner="" ; local -a pos=()
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }
             owner="$2"; shift 2;;
    --) shift; while [ "$#" -gt 0 ]; do pos+=("$1"); shift; done;;
    -*) dr_vps_die "$DR_VPS_E_USAGE" "egress: unknown flag: $1"; return $?;;
    *)  pos+=("$1"); shift;;
  esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  _dr_vps_egress_admit "$owner" || return $?

  local base="$DR_VPS_EGRESS_BASE" fleet py owner_arg="${owner:-0}"
  py="$(_dr_vps_egress_tools)/drvps_egress_member.py"
  case "$subop" in
    add-splice|remove-splice)
      [ "${#pos[@]}" -ge 1 ] && [ "${#pos[@]}" -le 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "egress $subop <host> [port]"; return $?; }
      fleet="$(_dr_vps_fleet)" || return $?
      local host="${pos[0]}" port="${pos[1]:-443}"
      python3 "$py" submit --base "$base" --fleet "$fleet" --owner "$owner_arg" \
              --op "$subop" --host "$host" --port "$port" --ts "$(date +%s)" ;;
    list)
      [ "${#pos[@]}" -eq 0 ] || { dr_vps_die "$DR_VPS_E_USAGE" "egress list  (no arguments)"; return $?; }
      python3 "$py" list --base "$base" --owner "$owner_arg" ;;
    status)
      [ "${#pos[@]}" -eq 1 ] || { dr_vps_die "$DR_VPS_E_USAGE" "egress status <reqid>"; return $?; }
      python3 "$py" status --base "$base" --owner "$owner_arg" --reqid "${pos[0]}" ;;
    *) dr_vps_die "$DR_VPS_E_USAGE" "egress subcommand: add-splice|remove-splice|list|status"; return $?;;
  esac
}
