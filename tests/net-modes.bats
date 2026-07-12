#!/usr/bin/env bats
# net-modes.bats -- DR-6 per-run network modes (design: docs/CONCEPT-NET-MODES.md; status: STATUS.md).
# Grows per implementation stage.
#
# STAGE 0 -- lock `shared`/simnet NON-REGRESSION (concept §7.1). `shared` must stay behaviourally IDENTICAL as
# `isolated`/`routed` are added. The golden below is gen-normalized (unrelated fleet.json additions -- routed
# allowlist, quotas -- must NOT false-break it), so ONLY a change to the shared render CODE trips the lock.
#
# SPDX-License-Identifier: GPL-3.0-or-later (see LICENSE)
# Copyright (c) 2026 Alexander Shafir <alexander@shafir.info> - https://www.shafir.info
# Vibe-coded with Claude (Anthropic).

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_net.sh
  dr_vps_fake_nft
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"
  # net-group record layer (Stage 0): the SQLite store + the netgroup module, on a throwaway test DB.
  dr_vps_load dr_vps_store.sh
  dr_vps_load dr_vps_netgroup.sh
  export DR_VPS_DB="$BATS_TEST_TMPDIR/store.db"
  export DR_VPS_NETGROUP_LOCK="$BATS_TEST_TMPDIR/ng.lock"     # Stage 1: writable alloc lock
  dr_vps_store_init
  # Stage-1 SEAM defaults: NO live host CIDRs, NO live interfaces (tests override per-test as needed).
  dr_vps_netgroup_live_cidrs() { :; }
  dr_vps_netgroup_iface_exists() { return 1; }
}

_norm_gen() { sed -E 's/drvps-gen-[0-9a-f]+/drvps-gen-NORM/'; }

@test "STAGE0 §7.1: shared render is BYTE-IDENTICAL to the golden (gen-normalized non-regression lock)" {
  run dr_vps_net_render simulated
  [ "$status" -eq 0 ]
  got=$(printf '%s\n' "$output" | _norm_gen)
  want=$(cat "$DR_VPS_SRC/../tests/goldens/net-render-shared.golden")
  [ "$got" = "$want" ]
}

@test "STAGE0 §7.1: no-arg render == 'simulated' render (default profile is the shared path, unchanged)" {
  run dr_vps_net_render; a="$output"
  run dr_vps_net_render simulated; b="$output"
  [ "$a" = "$b" ]
}

@test "STAGE0 §7.1: shared render still REFUSES a non-'simulated'/unknown profile (exit 2)" {
  run dr_vps_net_render open
  [ "$status" -eq 2 ]
}

# ---- STAGE 0: net-group record layer (dr_vps_netgroup.sh) -- INERT (no create path) --------------------

@test "STAGE0 netgroup: sanitize accepts good ids; rejects empty/leading-dash/bad-char/too-long" {
  run dr_vps_netgroup_sanitize_id "run-42"; [ "$status" -eq 0 ]; [ "$output" = "run-42" ]
  run dr_vps_netgroup_sanitize_id "";        [ "$status" -ne 0 ]
  run dr_vps_netgroup_sanitize_id "-lead";   [ "$status" -ne 0 ]
  run dr_vps_netgroup_sanitize_id "Bad_Ch";  [ "$status" -ne 0 ]   # uppercase + underscore
  run dr_vps_netgroup_sanitize_id "a/b";     [ "$status" -ne 0 ]
  run dr_vps_netgroup_sanitize_id "$(printf 'x%.0s' $(seq 41))"; [ "$status" -ne 0 ]   # length limit
}

@test "STAGE0 netgroup: mode validation is isolated|routed ONLY (shared/empty refused)" {
  run dr_vps_netgroup_valid_mode isolated; [ "$status" -eq 0 ]
  run dr_vps_netgroup_valid_mode routed;   [ "$status" -eq 0 ]
  run dr_vps_netgroup_valid_mode shared;   [ "$status" -ne 0 ]
  run dr_vps_netgroup_valid_mode "";       [ "$status" -ne 0 ]
}

@test "STAGE0 netgroup: bridge name is drb-<11hex>, <=15 chars (IFNAMSIZ), deterministic, owner+nonce salted" {
  b=$(dr_vps_netgroup_bridge_name owner grp 0)
  [[ "$b" =~ ^drb-[0-9a-f]{11}$ ]]
  [ "${#b}" -le 15 ]
  [ "$b" = "$(dr_vps_netgroup_bridge_name owner grp 0)" ]     # deterministic
  [ "$b" != "$(dr_vps_netgroup_bridge_name owner grp 1)" ]    # nonce re-salt changes it
  [ "$b" != "$(dr_vps_netgroup_bridge_name other grp 0)" ]    # owner-scoped
}

@test "STAGE0 netgroup: reserve PINS mode; idempotent same-mode join; WRONG-mode join refused; bad mode refused" {
  run dr_vps_netgroup_reserve o1 g1 isolated; [ "$status" -eq 0 ]
  [ "$(dr_vps_netgroup_get_mode o1 g1)" = isolated ]
  run dr_vps_netgroup_reserve o1 g1 isolated; [ "$status" -eq 0 ]   # idempotent, same mode
  run dr_vps_netgroup_reserve o1 g1 routed;   [ "$status" -eq 2 ]   # join with WRONG mode -> refused
  run dr_vps_netgroup_reserve o1 g2 shared;   [ "$status" -ne 0 ]   # invalid mode -> refused
}

@test "STAGE0 netgroup: state advances through the s5.1 lifecycle machine" {
  dr_vps_netgroup_reserve o1 g1 isolated
  dr_vps_netgroup_set_state o1 g1 pending
  [[ "$(dr_vps_netgroup_get o1 g1)" == *"|pending|"* ]]
}

@test "STAGE0 §7.1 call-path: the shared/simulated render+generation do NOT invoke net-group code" {
  # spy: replace each netgroup fn with a recorder; the shared path must never call them (regression guard
  # for when the Stage-2 mode dispatch lands -- shared must stay store-independent).
  spy="$BATS_TEST_TMPDIR/spy"; : > "$spy"
  for fn in dr_vps_netgroup_reserve dr_vps_netgroup_get dr_vps_netgroup_get_mode \
            dr_vps_netgroup_set_state dr_vps_netgroup_bridge_name; do
    eval "${fn}() { echo "'"'"called:$fn"'"'" >> '$spy'; }"
  done
  run dr_vps_net_render simulated; [ "$status" -eq 0 ]
  run dr_vps_net_generation;       [ "$status" -eq 0 ]
  [ ! -s "$spy" ]
}

# ---- STAGE 1: locked subnet ALLOCATION (dr_vps_netgroup allocate/overlap/revalidate) -------------------

@test "STAGE1 alloc: cidr_overlap -- overlap(rc0)/disjoint(rc1)/contained(rc0)/malformed(rc2)" {
  run dr_vps_netgroup_cidr_overlap 10.124.5.0/24 10.124.5.0/24; [ "$status" -eq 0 ]   # identical
  run dr_vps_netgroup_cidr_overlap 10.124.5.0/24 10.124.6.0/24; [ "$status" -eq 1 ]   # disjoint
  run dr_vps_netgroup_cidr_overlap 10.124.5.0/24 10.124.0.0/16; [ "$status" -eq 0 ]   # /16 contains /24
  run dr_vps_netgroup_cidr_overlap 10.124.5.0/24 10.123.0.0/24; [ "$status" -eq 1 ]   # different /16
  run dr_vps_netgroup_cidr_overlap NOTACIDR    10.124.5.0/24; [ "$status" -eq 2 ]     # malformed -> fail-closed signal
}

@test "STAGE1 alloc: allocate picks a free /24 in the pool, reserves subnet+gw_ip=.1 in the store" {
  dr_vps_netgroup_reserve o1 g1 isolated
  run dr_vps_netgroup_allocate o1 g1
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^10\.124\.[0-9]+\.0/24$ ]]
  got=$(dr_vps_netgroup_get o1 g1)              # mode|bridge|subnet|gw_ip|...
  sub=$(echo "$got" | cut -d'|' -f3); gw=$(echo "$got" | cut -d'|' -f4)
  [ "$sub" = "$output" ]
  [ "$gw" = "${output%.0/24}.1" ]
}

@test "STAGE1 alloc: allocate SKIPS a candidate overlapping the forbidden set (walks to the next)" {
  dr_vps_netgroup_reserve o1 g1 isolated
  cand0=$(dr_vps_netgroup_candidate o1 g1 0)
  dr_vps_netgroup_live_cidrs() { printf '%s\n' "$cand0"; }     # forbid the deterministic START /24
  run dr_vps_netgroup_allocate o1 g1
  [ "$status" -eq 0 ]
  [ "$output" != "$cand0" ]                                    # skipped the forbidden start
  run dr_vps_netgroup_cidr_overlap "$output" "$cand0"; [ "$status" -eq 1 ]   # chosen is disjoint from it
}

@test "STAGE1 alloc: FAIL CLOSED (rc3) when the whole pool is forbidden" {
  dr_vps_netgroup_reserve o1 g1 isolated
  dr_vps_netgroup_live_cidrs() { printf '10.124.0.0/16\n'; }   # every candidate overlaps
  run dr_vps_netgroup_allocate o1 g1
  [ "$status" -eq 3 ]
  [ "$(dr_vps_netgroup_get o1 g1 | cut -d'|' -f3)" = "" ]      # nothing reserved
}

@test "STAGE1 alloc: two groups get NON-overlapping subnets (stored subnet is forbidden to the 2nd)" {
  dr_vps_netgroup_reserve o1 g1 isolated; s1=$(dr_vps_netgroup_allocate o1 g1)
  dr_vps_netgroup_reserve o1 g2 isolated; s2=$(dr_vps_netgroup_allocate o1 g2)
  [ -n "$s1" ] && [ -n "$s2" ] && [ "$s1" != "$s2" ]
  run dr_vps_netgroup_cidr_overlap "$s1" "$s2"; [ "$status" -eq 1 ]
}

@test "STAGE1 alloc: revalidate rc0 while free; rc1 when a NEW overlap appears (TOCTOU/reassert guard)" {
  dr_vps_netgroup_reserve o1 g1 isolated; s1=$(dr_vps_netgroup_allocate o1 g1)
  # revalidate legitimately SKIPS the group's own subnet (once its bridge is up, `ip route` shows the group's
  # own /24 -- else it would always self-conflict). So a NEW overlap = an overlapping-but-DIFFERENT route.
  run dr_vps_netgroup_revalidate o1 g1; [ "$status" -eq 0 ]    # only our own subnet in the set -> still free
  dr_vps_netgroup_live_cidrs() { printf '10.124.0.0/16\n'; }   # a NEW broader host route now contains our /24
  run dr_vps_netgroup_revalidate o1 g1; [ "$status" -eq 1 ]    # fail-closed on the new overlap
}

@test "STAGE1 alloc: allocate assigns a bridge (nonce 0 free -> stored bridge + nonce=0)" {
  dr_vps_netgroup_reserve o1 g1 isolated
  dr_vps_netgroup_allocate o1 g1 >/dev/null
  got=$(dr_vps_netgroup_get o1 g1)              # mode|bridge|subnet|gw_ip|dhcp_range|lan_cidrs|state|gen|nonce
  br=$(echo "$got" | cut -d'|' -f2); nonce=$(echo "$got" | cut -d'|' -f9)
  [[ "$br" =~ ^drb-[0-9a-f]{11}$ ]]
  [ "$br" = "$(dr_vps_netgroup_bridge_name o1 g1 0)" ]
  [ "$nonce" = 0 ]
}

@test "STAGE1 alloc: a live-iface bridge-name collision RE-SALTS the nonce deterministically" {
  dr_vps_netgroup_reserve o2 g2 isolated
  b0=$(dr_vps_netgroup_bridge_name o2 g2 0)
  dr_vps_netgroup_iface_exists() { [ "$1" = "$b0" ]; }         # nonce-0 name already exists on the host
  dr_vps_netgroup_allocate o2 g2 >/dev/null
  got=$(dr_vps_netgroup_get o2 g2)
  br=$(echo "$got" | cut -d'|' -f2); nonce=$(echo "$got" | cut -d'|' -f9)
  [ "$br" != "$b0" ]                                          # re-salted off the colliding name
  [ "$nonce" -ge 1 ]
  [ "$br" = "$(dr_vps_netgroup_bridge_name o2 g2 "$nonce")" ] # deterministic
}
