#!/usr/bin/env bash
# dr_vps_netgroup.sh -- DR-6 per-run network modes: the net-group record layer.
#
# Owner-namespaced group records + input validation + deterministic, IFNAMSIZ-safe bridge naming.
# Persistence is the net_groups table in the SQLite store (dr_vps_store.sh). shared/simnet NEVER uses this
# module -- it stays the store-INDEPENDENT legacy path (concept s5.2 / s7.1).
#
# STAGE 0: schema (store) + validation + naming + INERT record CRUD. No create-path caller yet; allocation
# (locked probe/reserve, concept s5) and the lifecycle state machine (s5.1) land in Stage 1 / Stage 3A.
# Requires dr_vps_store.sh to be sourced (dr_vps_sql, dr_vps_sql_str, dr_vps_die).
#
# SPDX-License-Identifier: GPL-3.0-or-later (see LICENSE)
# Copyright (c) 2026 Alexander Shafir <alexander@shafir.info> - https://www.shafir.info
# Vibe-coded with Claude (Anthropic).

# --- owner principal (owner-namespacing; concept s2) ------------------------------------------------------
# The namespace key is the AUTHENTICATED principal, NEVER a caller-supplied string. The rig already
# authenticates the owner (SO_PEERCRED uid at ingress -> --owner in the agent path). We take the caller's
# AUTHENTICATED owner via the seam DR_VPS_NETGROUP_OWNER; empty = the direct operator (admin), namespaced as
# the reserved literal '@operator' so it can never collide with a numeric uid.
dr_vps_netgroup_owner() {
  local o="${DR_VPS_NETGROUP_OWNER-}"
  if [ -n "$o" ]; then printf '%s' "$o"; else printf '@operator'; fi
}

# --- group-id sanitization + length limit -----------------------------------------------------------------
# A caller LABEL, not an authority (concept s2). Accept ONLY [a-z0-9] and '-', 1..DR_VPS_NETGROUP_MAX_ID_LEN
# chars, no leading '-', so it safely builds filesystem / libvirt / nft names. Everything else fails CLOSED.
# Prints the sanitized id on success; rc 2 on reject.
: "${DR_VPS_NETGROUP_MAX_ID_LEN:=40}"
dr_vps_netgroup_sanitize_id() {  # <raw> -> id | rc2
  local raw="${1-}"
  case "$raw" in ''|-*) return 2 ;; esac
  [ "${#raw}" -le "$DR_VPS_NETGROUP_MAX_ID_LEN" ] || return 2
  case "$raw" in *[!a-z0-9-]*) return 2 ;; esac
  printf '%s' "$raw"
}

# --- mode validation (isolated|routed ONLY; shared is the legacy path, never here) ------------------------
dr_vps_netgroup_valid_mode() {  # <mode> -> rc0 iff isolated|routed
  case "${1-}" in isolated|routed) return 0 ;; *) return 2 ;; esac
}

# --- deterministic bridge name (IFNAMSIZ-safe; concept s5.1) ----------------------------------------------
# drb-<11 hex of sha256(owner|group|nonce)>. 'drb-' (4) + 11 hex = 15 chars = the usable IFNAMSIZ limit.
# The nonce (stored per record) is the DETERMINISTIC re-salt on a name collision; default 0. Store collision
# detection + re-salt + live-interface-name check land in Stage 1 (this only computes the candidate).
dr_vps_netgroup_bridge_name() {  # <owner> <group> [nonce]
  local h
  h=$(printf '%s|%s|%s' "${1-}" "${2-}" "${3-0}" | "${DR_SHA256:-sha256sum}" | cut -c1-11)
  printf 'drb-%s' "$h"
}

# --- record CRUD over net_groups (INERT in Stage 0; no create-path caller) ---------------------------------
# get -> "mode|bridge|subnet|gw_ip|dhcp_range|lan_cidrs|state|generation|nonce" (empty if no such record).
dr_vps_netgroup_get() {  # <owner> <group>
  dr_vps_sql "SELECT mode||'|'||coalesce(bridge,'')||'|'||coalesce(subnet,'')||'|'||coalesce(gw_ip,'')||'|'||\
coalesce(dhcp_range,'')||'|'||lan_cidrs||'|'||state||'|'||generation||'|'||nonce \
FROM net_groups WHERE owner=$(dr_vps_sql_str "${1-}") AND group_id=$(dr_vps_sql_str "${2-}");"
}
# get_mode -> the pinned mode (empty if absent). Used by the join-mode-match guard (Stage 1).
dr_vps_netgroup_get_mode() {  # <owner> <group>
  dr_vps_sql "SELECT mode FROM net_groups WHERE owner=$(dr_vps_sql_str "${1-}") AND group_id=$(dr_vps_sql_str "${2-}");"
}
# reserve -> create the 'allocating' record, PINNING mode (idempotent on the PK; a re-create with a DIFFERENT
# mode is REFUSED = the join-mode-match invariant, concept s2). rc2 on invalid mode or a mode mismatch.
dr_vps_netgroup_reserve() {  # <owner> <group> <mode>
  local owner="${1-}" group="${2-}" mode="${3-}" existing
  dr_vps_netgroup_valid_mode "$mode" || return 2
  existing=$(dr_vps_netgroup_get_mode "$owner" "$group") || return 1
  if [ -n "$existing" ]; then
    [ "$existing" = "$mode" ] || return 2      # join must match the pinned mode
    return 0
  fi
  dr_vps_sql "INSERT INTO net_groups(owner,group_id,mode) VALUES($(dr_vps_sql_str "$owner"),$(dr_vps_sql_str "$group"),$(dr_vps_sql_str "$mode"));"
}
# set_state -> advance the s5.1 lifecycle machine (allocating->pending->live->destroying->gone).
dr_vps_netgroup_set_state() {  # <owner> <group> <state>
  dr_vps_sql "UPDATE net_groups SET state=$(dr_vps_sql_str "${3-}") WHERE owner=$(dr_vps_sql_str "${1-}") AND group_id=$(dr_vps_sql_str "${2-}");"
}

# ==========================================================================================================
# STAGE 1 -- locked subnet ALLOCATION (concept s5): deterministic candidate ORDER over a reserved pool ->
# reject any candidate overlapping live/stored state -> reserve under an exclusive lock -> fail CLOSED on
# exhaustion. The live-state probe is a SEAM (tests inject a fixed host state); the pool is config-driven.
# ==========================================================================================================

# Reserved allocation pool: 256 /24s in 10.124/16 (never overlaps drvps0's 10.123/16). Config-driven.
: "${DR_VPS_NETGROUP_POOL_BASE:=10.124}"
: "${DR_VPS_NETGROUP_LOCK:=${DR_VPS_STATE_DIR:-/run/drvps}/netgroup.lock}"

# _cidr_overlap A B -> rc0 iff the two IPv4 CIDRs overlap (python ipaddress; correct prefix math, not string cmp).
dr_vps_netgroup_cidr_overlap() {  # <cidrA> <cidrB>
  "${DR_PY:-python3}" - "$1" "$2" <<'PY'
import sys, ipaddress
try:
    a = ipaddress.ip_network(sys.argv[1], strict=False)
    b = ipaddress.ip_network(sys.argv[2], strict=False)
except ValueError:
    sys.exit(2)               # a malformed CIDR is treated as "cannot prove disjoint" by the caller (fail-closed)
sys.exit(0 if a.overlaps(b) else 1)
PY
}

# EMIT the forbidden CIDR set: the shared drvps0 subnet + every stored group subnet + the LIVE host state
# (routes, iface prefixes, libvirt net subnets). SEAM: tests override dr_vps_netgroup_live_cidrs to inject a
# fixed host state; the default best-effort-parses ip/virsh. A probe that yields nothing does NOT widen access
# on its own -- the post-start verify (Stage 2) re-checks the ACTUAL bridge/routes to close the TOCTOU window.
dr_vps_netgroup_live_cidrs() {
  "${DR_IP:-ip}" -o -4 route show 2>/dev/null | awk '{print $1}' | grep -E '^[0-9].*/[0-9]+$' || true
  "${DR_IP:-ip}" -o -4 addr show  2>/dev/null | awk '{print $4}' | grep -E '/[0-9]+$'       || true
  local n uri="${DR_LIBVIRT_URI:-qemu:///system}"
  for n in $("${DR_VIRSH:-virsh}" -c "$uri" net-list --all --name 2>/dev/null); do
    "${DR_VIRSH:-virsh}" -c "$uri" net-dumpxml "$n" 2>/dev/null \
      | grep -oE "<ip address='[0-9.]+' (netmask='[0-9.]+'|prefix='[0-9]+')" \
      | sed -E "s/<ip address='([0-9.]+)' prefix='([0-9]+)'/\1\/\2/; s/<ip address='([0-9.]+)' netmask='255\.255\.255\.0'/\1\/24/" || true
  done
}
dr_vps_netgroup_forbidden_cidrs() {
  printf '10.123.0.0/24\n'                                              # the shared simnet -- never reuse
  dr_vps_sql "SELECT subnet FROM net_groups WHERE subnet IS NOT NULL AND subnet<>'';" 2>/dev/null
  dr_vps_netgroup_live_cidrs
}

# candidate /24 #i (0..255): 10.<pool>.<(hash(owner,group)+i) mod 256>.0/24 -- deterministic START, then walk.
dr_vps_netgroup_candidate() {  # <owner> <group> <i>
  local start
  start=$(( 0x$(printf '%s|%s' "${1-}" "${2-}" | "${DR_SHA256:-sha256sum}" | cut -c1-4) % 256 ))
  printf '%s.%s.0/24' "$DR_VPS_NETGROUP_POOL_BASE" "$(( (start + ${3:-0}) % 256 ))"
}

# ALLOCATE (under the exclusive lock): walk the 256 candidates from the deterministic start; skip any that
# OVERLAP a forbidden CIDR (or that we can't prove disjoint); reserve the first free one into the record
# (subnet + gw_ip=.1 + bridge). Prints the chosen subnet. rc 3 = pool exhausted (FAIL CLOSED). Requires the
# record to already exist (reserve, Stage 0). The lock is the REAL lifecycle lock (broadened in Stage 3A).
dr_vps_netgroup_allocate() {  # <owner> <group>
  local owner="${1-}" group="${2-}"
  mkdir -p "$(dirname "$DR_VPS_NETGROUP_LOCK")" 2>/dev/null || true
  exec {_ngfd}>>"$DR_VPS_NETGROUP_LOCK" 2>/dev/null \
    || { dr_vps_die "${DR_VPS_E_GENERIC:-1}" "netgroup: cannot open alloc lock"; return $?; }
  "${DR_FLOCK:-flock}" -w 30 "$_ngfd" \
    || { exec {_ngfd}>&-; dr_vps_die "${DR_VPS_E_GENERIC:-1}" "netgroup: alloc lock timeout"; return 1; }
  local forbidden i cand ok chosen=""
  forbidden=$(dr_vps_netgroup_forbidden_cidrs)
  for i in $(seq 0 255); do
    cand=$(dr_vps_netgroup_candidate "$owner" "$group" "$i")
    ok=1
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      local orc=0; dr_vps_netgroup_cidr_overlap "$cand" "$f" || orc=$?   # || : errexit-safe rc capture
      [ "$orc" -eq 1 ] || { ok=0; break; }   # rc1=proven disjoint keeps it; rc0 overlap / rc2 malformed -> reject
    done <<<"$forbidden"
    [ "$ok" = 1 ] && { chosen="$cand"; break; }
  done
  if [ -z "$chosen" ]; then
    exec {_ngfd}>&-; dr_vps_die "${DR_VPS_E_GENERIC:-1}" "netgroup: allocation pool exhausted (256 /24s in ${DR_VPS_NETGROUP_POOL_BASE}/16)"; return 3
  fi
  local gw="${chosen%.0/24}.1"
  dr_vps_sql "UPDATE net_groups SET subnet=$(dr_vps_sql_str "$chosen"), gw_ip=$(dr_vps_sql_str "$gw") WHERE owner=$(dr_vps_sql_str "$owner") AND group_id=$(dr_vps_sql_str "$group");"
  dr_vps_netgroup_assign_bridge "$owner" "$group" >/dev/null || { exec {_ngfd}>&-; return 3; }
  exec {_ngfd}>&-
  printf '%s' "$chosen"
}

# REVALIDATE a stored subnet against the CURRENT forbidden set (pre-start + reassert; concept s5 step 5/6):
# rc0 = still free (only self), rc1 = a NEW overlap appeared -> caller FAILS CLOSED rather than (re)assert.
dr_vps_netgroup_revalidate() {  # <owner> <group>
  local subnet f uri
  subnet=$(dr_vps_sql "SELECT subnet FROM net_groups WHERE owner=$(dr_vps_sql_str "${1-}") AND group_id=$(dr_vps_sql_str "${2-}");")
  [ -n "$subnet" ] || return 1
  # forbidden set MINUS this group's own stored subnet
  local rc
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$f" = "$subnet" ] && continue
    rc=0; dr_vps_netgroup_cidr_overlap "$subnet" "$f" || rc=$?   # || : errexit-safe rc capture
    [ "$rc" -eq 1 ] || return 1        # rc0 overlap / rc2 malformed -> a NEW overlap or unprovable -> fail closed
  done < <(printf '10.123.0.0/24\n'; dr_vps_sql "SELECT subnet FROM net_groups WHERE owner=$(dr_vps_sql_str "${1-}") AND group_id<>$(dr_vps_sql_str "${2-}") AND subnet IS NOT NULL AND subnet<>'';" 2>/dev/null; dr_vps_netgroup_live_cidrs)
  return 0
}

# iface_exists: SEAM -- rc0 iff a LIVE interface with this name exists (default: ip link). Tests override.
dr_vps_netgroup_iface_exists() { "${DR_IP:-ip}" -o link show "${1-}" >/dev/null 2>&1; }

# Assign the group's bridge name into the record: drb-<hex(owner,group,nonce)>, DETERMINISTICALLY re-salting the
# nonce if the candidate collides with a DIFFERENT stored group's bridge OR a live interface (concept s5.1).
# Prints the chosen name; rc3 = re-salt space exhausted (FAIL CLOSED). Caller holds the alloc lock.
dr_vps_netgroup_assign_bridge() {  # <owner> <group>
  local owner="${1-}" group="${2-}" nonce=0 name clash
  while [ "$nonce" -lt 64 ]; do
    name=$(dr_vps_netgroup_bridge_name "$owner" "$group" "$nonce")
    clash=$(dr_vps_sql "SELECT 1 FROM net_groups WHERE bridge=$(dr_vps_sql_str "$name") AND NOT (owner=$(dr_vps_sql_str "$owner") AND group_id=$(dr_vps_sql_str "$group")) LIMIT 1;" 2>/dev/null)
    if [ -z "$clash" ] && ! dr_vps_netgroup_iface_exists "$name"; then
      dr_vps_sql "UPDATE net_groups SET bridge=$(dr_vps_sql_str "$name"), nonce=$nonce WHERE owner=$(dr_vps_sql_str "$owner") AND group_id=$(dr_vps_sql_str "$group");"
      printf '%s' "$name"; return 0
    fi
    nonce=$((nonce+1))
  done
  dr_vps_die "${DR_VPS_E_GENERIC:-1}" "netgroup: bridge-name re-salt exhausted for $owner/$group"; return 3
}
