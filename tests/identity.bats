#!/usr/bin/env bats
# Stage 1 -- identity: canonicalization + hashing + the drvps-raw-v1 golden digest.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_identity.sh
}

@test "canon: reordering JSON keys yields the same canonical form" {
  echo '{"b":1,"a":2}' >"$BATS_TEST_TMPDIR/x.json"
  echo '{"a":2,"b":1}' >"$BATS_TEST_TMPDIR/y.json"
  run dr_vps_canon "$BATS_TEST_TMPDIR/x.json"; [ "$status" -eq 0 ]; cx="$output"
  run dr_vps_canon "$BATS_TEST_TMPDIR/y.json"; [ "$status" -eq 0 ]; cy="$output"
  [ "$cx" = "$cy" ]
}

@test "canon: empty/invalid JSON is rejected (fail-closed)" {
  printf '' >"$BATS_TEST_TMPDIR/empty.json"
  run dr_vps_canon "$BATS_TEST_TMPDIR/empty.json"
  [ "$status" -ne 0 ]
}

@test "recipe_hash: same recipe (any key order) -> same hash" {
  echo '{"distro":"fedora44","url":"u","packages":["systemd","tmux"]}' >"$BATS_TEST_TMPDIR/r1.json"
  echo '{"packages":["systemd","tmux"],"url":"u","distro":"fedora44"}' >"$BATS_TEST_TMPDIR/r2.json"
  run dr_vps_recipe_hash "$BATS_TEST_TMPDIR/r1.json"; [ "$status" -eq 0 ]; h1="$output"
  run dr_vps_recipe_hash "$BATS_TEST_TMPDIR/r2.json"; [ "$status" -eq 0 ]; h2="$output"
  [ "$h1" = "$h2" ]
  [ "${#h1}" -eq 64 ]
}

@test "recipe_hash: different intent -> different hash" {
  echo '{"distro":"fedora44"}' >"$BATS_TEST_TMPDIR/r1.json"
  echo '{"distro":"ubuntu22"}' >"$BATS_TEST_TMPDIR/r2.json"
  run dr_vps_recipe_hash "$BATS_TEST_TMPDIR/r1.json"; h1="$output"
  run dr_vps_recipe_hash "$BATS_TEST_TMPDIR/r2.json"; h2="$output"
  [ "$h1" != "$h2" ]
}

@test "golden_digest: drvps-raw-v1 format with the virtual size" {
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/g.qcow2" 2097152 65536
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/g.qcow2"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^drvps-raw-v1-2097152-[0-9a-f]{64}$ ]]
}

@test "golden_digest TWO-DOMAIN control: same content, different qcow2 metadata -> SAME digest" {
  # identical raw content, different cluster_size => different qcow2 bytes/metadata
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/a.qcow2" 2097152 65536
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/b.qcow2" 2097152 524288
  # sanity: the qcow2 container bytes really do differ
  ! cmp -s "$BATS_TEST_TMPDIR/a.qcow2" "$BATS_TEST_TMPDIR/b.qcow2" || false
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/a.qcow2"; [ "$status" -eq 0 ]; da="$output"
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/b.qcow2"; [ "$status" -eq 0 ]; db="$output"
  [ "$da" = "$db" ]
}

@test "golden_digest: different content -> different digest" {
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/a.qcow2" 2097152 65536 ""
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/c.qcow2" 2097152 65536 "X"
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/a.qcow2"; da="$output"
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/c.qcow2"; dc="$output"
  [ "$da" != "$dc" ]
}

@test "golden_digest: missing file -> not-found (14)" {
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/nope.qcow2"
  [ "$status" -eq 14 ]
}

@test "instance_id: deterministic; name+project only; rejects bad names" {
  run dr_vps_instance_id "web1" "proj"; [ "$status" -eq 0 ]; i1="$output"
  run dr_vps_instance_id "web1" "proj"; i2="$output"
  [ "$i1" = "$i2" ]
  run dr_vps_instance_id "web1" "other"; [ "$output" != "$i1" ]
  run dr_vps_instance_id "bad name"; [ "$status" -eq 2 ]
}

@test "golden_digest REFUSES a qcow2 with an external DATA-FILE (anti-flatten TOCTOU) -> 18" {
  qemu-img create -f qcow2 -o data_file="$BATS_TEST_TMPDIR/df.raw",data_file_raw=on "$BATS_TEST_TMPDIR/dfg.qcow2" 1M >/dev/null 2>&1
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/dfg.qcow2"
  [ "$status" -eq 18 ]
  [[ "$output" == *"external data-file"* ]]
}

@test "golden_digest REFUSES a backed (non-standalone) golden -> 18" {
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/base.qcow2" 1048576 65536
  qemu-img create -f qcow2 -b "$BATS_TEST_TMPDIR/base.qcow2" -F qcow2 "$BATS_TEST_TMPDIR/backed.qcow2" >/dev/null 2>&1
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/backed.qcow2"
  [ "$status" -eq 18 ]
  [[ "$output" == *"not standalone"* ]]
}

@test "golden_digest REFUSES an absurd virtual-size (DoS cap) -> 18" {
  qemu-img create -f qcow2 "$BATS_TEST_TMPDIR/huge.qcow2" 2P >/dev/null 2>&1   # 2 PiB virtual size
  export DR_VPS_MAX_GOLDEN_GIB=512
  run dr_vps_golden_digest "$BATS_TEST_TMPDIR/huge.qcow2"
  [ "$status" -eq 18 ]
  [[ "$output" == *"exceeds"* ]]
}

@test "S2: instance_id is OWNER-NAMESPACED -- different owners of the same name get DISTINCT ids; operator keeps the historical id" {
  local op a b a2
  op=$(dr_vps_instance_id ch1 agent)            # operator (no owner) -> historical 2-field derivation
  a=$(dr_vps_instance_id ch1 agent 1001)        # owner 1001
  b=$(dr_vps_instance_id ch1 agent 2002)        # owner 2002, SAME name+project
  a2=$(dr_vps_instance_id ch1 agent 1001)       # owner 1001 again
  [ "$a" != "$b" ]                              # no cross-owner squat: distinct ids
  [ "$a" != "$op" ]                             # agent id differs from the operator id
  [ "$a" = "$a2" ]                              # deterministic for the same (name,project,owner)
  # backward-compat: the operator (no-owner) id is EXACTLY the pre-S2 2-field hash
  local legacy; legacy=$(printf 'drvps-vm-%s' "$(printf 'ch1\037agent' | sha256sum | awk '{print substr($1,1,16)}')")
  [ "$op" = "$legacy" ]
  case "$op$a" in drvps-vm-*drvps-vm-*) : ;; *) false ;; esac   # both well-formed
}

@test "S2: instance_id rejects a non-numeric owner_uid" {
  run dr_vps_instance_id ch1 agent abc; [ "$status" -eq 2 ]
}
