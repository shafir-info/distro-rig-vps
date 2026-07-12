#!/usr/bin/env bats
# Stage 1 -- store: schema, referrer ledger (the GC invariant), CAS, refcount-gated delete.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_store.sh
  dr_vps_store_init
}

AID="drvps-raw-v1-2097152-$(printf 'a%.0s' {1..64})"
PROV='{"distro":"fedora44","artifact_id":"x"}'

@test "sql_str: single-quotes are escaped (injection-safe)" {
  run dr_vps_sql_str "a'b"; [ "$output" = "'a''b'" ]
}

@test "sql_int: rejects non-integers, accepts ints" {
  run dr_vps_sql_int 42; [ "$status" -eq 0 ]; [ "$output" = "42" ]
  run dr_vps_sql_int -5; [ "$status" -eq 0 ]
  run dr_vps_sql_int "1; DROP TABLE vms"; [ "$status" -eq 2 ]
  run dr_vps_sql_int "x"; [ "$status" -eq 2 ]
}

@test "image register/get/ls round-trips" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  run dr_vps_store_image_get "$AID"; [ "$output" = "/pool/g.qcow2" ]
  run dr_vps_store_image_ls; [ "$output" = "$AID" ]
}

@test "image_register: non-JSON provenance refused" {
  run dr_vps_store_image_register "$AID" "not json" "/pool/g.qcow2"
  [ "$status" -ne 0 ]
}

@test "store_init: FAILS CLOSED if a Phase-2 column is missing after migration" {
  # simulate a migration failure: make `vms` a VIEW so ALTER TABLE ADD COLUMN cannot add net/uuid.
  # store_init must DIE, not continue (else get_net reads a missing column as an empty 'legacy' net).
  export DR_VPS_DB="$BATS_TEST_TMPDIR/fresh.db"
  dr_vps_sql "CREATE TABLE base(id TEXT PRIMARY KEY); CREATE VIEW vms AS SELECT id FROM base;"
  run dr_vps_store_init
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing after migration"* ]]
}

@test "vm net: a fresh row reads EMPTY (legacy default); set_net/get_net round-trips" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmnet" "$AID" "/pool/vmnet.qcow2" 1 24
  run dr_vps_store_vm_get_net "vmnet"; [ -z "$output" ]           # unset -> empty (recreate falls back)
  dr_vps_store_vm_set_net "vmnet" "simnet2"
  run dr_vps_store_vm_get_net "vmnet"; [ "$output" = "simnet2" ]
  # set_net PROVES one row changed -- a no-op on a missing id must FAIL, not silently pass
  run dr_vps_store_vm_set_net "ghost" "simnet"; [ "$status" -ne 0 ]
}

@test "vm contract (Stage-0 R0): legacy row reads EMPTY; canonical set/get round-trips; ghost set FAILS" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmc" "$AID" "/pool/vmc.qcow2" 1 24
  run dr_vps_store_vm_get_contract "vmc"; [ "$status" -eq 0 ]; [ -z "$output" ]     # legacy NULL -> empty
  dr_vps_store_vm_set_contract "vmc" "$(printf 'cpu_mode=host-model\nmachine=q35')" # canonical: sorted, safe
  run dr_vps_store_vm_get_contract "vmc"; [ "$status" -eq 0 ]
  [ "$output" = "$(printf 'cpu_mode=host-model\nmachine=q35')" ]
  run dr_vps_store_vm_set_contract "ghost" "cpu_mode=host-model"; [ "$status" -ne 0 ]   # no such row -> FAIL
}

@test "vm contract (Stage-0 R0): non-canonical / unsafe contracts are REJECTED (line-safe)" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmc2" "$AID" "/pool/vmc2.qcow2" 1 24
  run dr_vps_store_vm_set_contract "vmc2" "$(printf 'machine=q35\ncpu_mode=host-model')"; [ "$status" -ne 0 ] # unsorted
  run dr_vps_store_vm_set_contract "vmc2" "$(printf 'cpu_mode=a\ncpu_mode=b')"; [ "$status" -ne 0 ]           # dup key
  run dr_vps_store_vm_set_contract "vmc2" "no_equals_here"; [ "$status" -ne 0 ]                                # malformed
  run dr_vps_store_vm_set_contract "vmc2" "cpu_mode=host model"; [ "$status" -ne 0 ]                           # space in value
  run dr_vps_store_vm_set_contract "vmc2" "=host-model"; [ "$status" -ne 0 ]                                   # empty key
  run dr_vps_store_vm_set_contract "vmc2" "cpu_mode="; [ "$status" -ne 0 ]                                     # empty value
  run dr_vps_store_vm_get_contract "vmc2"; [ "$status" -eq 0 ]; [ -z "$output" ]     # nothing was written
}

@test "refcount-gated delete: a vm referrer blocks image delete (19); removing it unblocks" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vm1" "$AID" "/pool/vm1.qcow2" 1 24 "web" "proj"
  run dr_vps_store_image_refcount "$AID"; [ "$output" = "1" ]
  run dr_vps_store_image_delete "$AID"; [ "$status" -eq 19 ]
  dr_vps_store_vm_delete "vm1"
  run dr_vps_store_image_refcount "$AID"; [ "$output" = "0" ]
  run dr_vps_store_image_delete "$AID"; [ "$status" -eq 0 ]
}

@test "REFERRER-MATRIX control: vm / overlay / snapshot each independently blocks delete" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  for kind in vm overlay snapshot; do
    dr_vps_store_ref_add "$AID" "$kind" "ref-$kind"
    run dr_vps_store_image_delete "$AID"
    [ "$status" -eq 19 ] || { echo "kind=$kind did not block"; false; }
    dr_vps_store_ref_del "$AID" "$kind" "ref-$kind"
  done
  run dr_vps_store_image_delete "$AID"; [ "$status" -eq 0 ]
}

@test "vm_create: duplicate id loses with conflict (15) -- concurrent one-wins" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmX" "$AID" "/pool/x.qcow2" 1 24
  run dr_vps_store_vm_create "vmX" "$AID" "/pool/x.qcow2" 1 24
  [ "$status" -eq 15 ]
}

@test "vm_cas_generation: matching expected succeeds; stale fails (15)" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmG" "$AID" "/pool/g2.qcow2" 1 24
  run dr_vps_store_vm_cas_generation "vmG" 0 1; [ "$status" -eq 0 ]
  run dr_vps_store_vm_cas_generation "vmG" 0 2; [ "$status" -eq 15 ]   # stale expected
  run dr_vps_store_vm_cas_generation "vmG" 1 2; [ "$status" -eq 0 ]
}

@test "vm get/set_state round-trips" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmS" "$AID" "/pool/s.qcow2" 3 12 "n" "p"
  dr_vps_store_vm_set_state "vmS" "running"
  run dr_vps_store_vm_get "vmS"; [ "$output" = "running|0|$AID|3" ]
}

@test "net_record / egress_gen round-trips" {
  dr_vps_store_net_record "simnet" 7
  run dr_vps_store_egress_gen "simnet"; [ "$output" = "7" ]
}

@test "image_register: identical re-register is idempotent; different path -> conflict (15)" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  run dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"; [ "$status" -eq 0 ]   # idempotent
  run dr_vps_store_image_register "$AID" "$PROV" "/pool/OTHER.qcow2"; [ "$status" -eq 15 ]
}

@test "vm_create: missing image -> not-found (14); no orphan referrer left" {
  run dr_vps_store_vm_create "vmO" "drvps-raw-v1-1-missing" "/pool/o.qcow2" 1 24
  [ "$status" -eq 14 ]
  run dr_vps_store_image_refcount "drvps-raw-v1-1-missing"; [ "$output" = "0" ]
}

@test "vm_delete clears overlay referrers (no stale block on later image delete)" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmD" "$AID" "/pool/vmD.qcow2" 1 24
  dr_vps_store_overlay_add "vmD" "/pool/vmD.qcow2" "$AID"
  run dr_vps_store_image_refcount "$AID"; [ "$output" = "2" ]   # vm + overlay
  dr_vps_store_vm_delete "vmD"
  run dr_vps_store_image_refcount "$AID"; [ "$output" = "0" ]   # both gone
  run dr_vps_store_image_delete "$AID"; [ "$status" -eq 0 ]
}

@test "set_state/set_uuid PROVE one row changed (a no-op UPDATE on a missing row -> failure)" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g1.qcow2"
  dr_vps_store_vm_create "vmS" "$AID" "/pool/vmS.qcow2" 1 24
  dr_vps_store_vm_set_state "vmS" running         # existing row -> changes()=1 -> success
  dr_vps_store_vm_set_uuid  "vmS" 11111111-1111-1111-1111-111111111111
  run dr_vps_store_vm_set_state "nope" running     # missing row -> changes()=0 -> FAILURE (not silent ok)
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_set_uuid "nope" 22222222-2222-2222-2222-222222222222
  [ "$status" -ne 0 ]
}

@test "store helpers FAIL CLOSED on a DB error (no silent success)" {
  # DR_SQLITE is the sqlite3 binary path; pointing it at `false` makes every query exit 1, simulating a
  # DB error. NB: `run env DR_SQLITE=false <fn>` would exec the FUNCTION NAME as a binary (127) and pass
  # for the WRONG reason -- export it so the function actually runs the failing query path.
  export DR_SQLITE=false
  run dr_vps_store_image_register "$AID" "$PROV" /p
  [ "$status" -ne 0 ]
  run dr_vps_store_image_delete "$AID"
  [ "$status" -ne 0 ]
}

@test "overlay_add replacing a path leaves no stale referrer" {
  AID2="drvps-raw-v1-2-$(printf 'b%.0s' {1..62})"
  dr_vps_store_image_register "$AID"  "$PROV" "/pool/g1.qcow2"
  dr_vps_store_image_register "$AID2" "$PROV" "/pool/g2.qcow2"
  dr_vps_store_vm_create "vmR" "$AID" "/pool/vmR.qcow2" 1 24
  dr_vps_store_overlay_add "vmR" "/pool/vmR.qcow2" "$AID"
  dr_vps_store_overlay_add "vmR" "/pool/vmR.qcow2" "$AID2"   # same path, new artifact
  run dr_vps_store_image_refcount "$AID";  [ "$output" = "1" ]   # only the vm referrer remains
  run dr_vps_store_image_refcount "$AID2"; [ "$output" = "1" ]   # the new overlay referrer
}

# ---- S0 (service plane) no-op foundations: owner_uid + class columns ----

@test "S0: fresh vms table has owner_uid + class columns" {
  run dr_vps_sql "SELECT COUNT(*) FROM pragma_table_info('vms') WHERE name IN ('owner_uid','class');"
  [ "$output" = "2" ]
}

@test "S0: omitted owner -> SQL NULL (operator); omitted class -> 'throwaway' NOT NULL (reaper-safe)" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create "vmS0a" "$AID" "/pool/a.qcow2" 1 24
  run dr_vps_sql "SELECT (owner_uid IS NULL)||'|'||class FROM vms WHERE id='vmS0a';"
  [ "$output" = "1|throwaway" ]                                    # owner NULL (operator); class literal 'throwaway'
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='vmS0a' AND owner_uid='';"
  [ "$output" = "0" ]                                             # owner is NULL, NOT an empty string
  # the reaper footgun this prevents: `class != 'service'` MUST select a default VM (a NULL class would NOT)
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='vmS0a' AND class != 'service';"
  [ "$output" = "1" ]
}

@test "S0: owner_uid + class are stamped when provided" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create_from_golden "vmS0b" "$AID" "/pool/b.qcow2" 1 24 nm proj 1001 service
  run dr_vps_sql "SELECT owner_uid||'|'||class FROM vms WHERE id='vmS0b';"
  [ "$output" = "1001|service" ]
}

@test "S0: a non-numeric owner_uid is rejected (usage 2), nothing inserted" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  run dr_vps_store_vm_create_from_golden "vmS0c" "$AID" "/pool/c.qcow2" 1 24 nm proj abc
  [ "$status" -eq 2 ]
  [[ "$output" == *"numeric uid"* ]]
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='vmS0c';"; [ "$output" = "0" ]
}

@test "S0 migration: legacy vms table gains both columns; a POPULATED row survives (owner NULL, class backfilled 'throwaway')" {
  export DR_VPS_DB="$BATS_TEST_TMPDIR/legacy.db"
  # pre-S0 shape: has the Phase-2 cols the invariant needs, but NOT owner_uid/class
  dr_vps_sql "CREATE TABLE vms(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, overlay TEXT,
    egress_gen TEXT NOT NULL DEFAULT '0', ttl_hours INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'pending', generation INTEGER NOT NULL DEFAULT 0,
    name TEXT, project TEXT, domain_uuid TEXT, net TEXT, contract TEXT, created_at TEXT);"
  # a LIVE legacy row -- the REAL upgrade path (existing hosts have rows; an empty table wouldn't prove backfill)
  dr_vps_sql "INSERT INTO vms(id,artifact_id,state) VALUES ('legacyvm','aid1','running');"
  run dr_vps_store_init; [ "$status" -eq 0 ]                       # migrates + invariant passes
  run dr_vps_sql "SELECT COUNT(*) FROM pragma_table_info('vms') WHERE name IN ('owner_uid','class');"
  [ "$output" = "2" ]
  # the existing row survived intact: owner_uid NULL (operator), class backfilled to the NOT NULL default
  run dr_vps_sql "SELECT (owner_uid IS NULL)||'|'||class||'|'||state FROM vms WHERE id='legacyvm';"
  [ "$output" = "1|throwaway|running" ]
  run dr_vps_store_init; [ "$status" -eq 0 ]                       # second run = idempotent no-op
}

@test "S1a: vm_id_owned -- owner resolves its own; foreign uid + NULL(operator) row do NOT for a client; operator sees all" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create_from_golden vmOwn "$AID" /o 0 1 n p 1001 throwaway   # owned by uid 1001
  dr_vps_store_vm_create            vmOp  "$AID" /o 0 1 n p                    # operator (owner_uid NULL)
  run dr_vps_store_vm_id_owned vmOwn 1001; [ "$output" = "vmOwn" ]            # owner resolves its own
  run dr_vps_store_vm_id_owned vmOwn 2002; [ -z "$output" ]                   # foreign uid -> not-found (no leak)
  run dr_vps_store_vm_id_owned vmOp  1001; [ -z "$output" ]                   # NULL-owner is OPERATOR-only, NOT wildcard
  run dr_vps_store_vm_id_owned vmOwn;      [ "$output" = "vmOwn" ]            # operator (no arg) sees any ...
  run dr_vps_store_vm_id_owned vmOp;       [ "$output" = "vmOp" ]             # ... including the operator row
  run dr_vps_store_vm_id_owned ghost 1001; [ -z "$output" ]                   # nonexistent -> empty
}

@test "S1a: vm_do_owned -- owner match runs the action; foreign/operator behave; rc propagates; lock releases" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create_from_golden vmL "$AID" /o 0 1 n p 1001 throwaway
  run dr_vps_vm_do_owned vmL 1001 true;  [ "$status" -eq 0 ]        # owner -> runs
  run dr_vps_vm_do_owned vmL 1001 true;  [ "$status" -eq 0 ]        # REPEAT -> lock was released (no deadlock)
  run dr_vps_vm_do_owned vmL 2002 true;  [ "$status" -eq 14 ]       # foreign -> E_NOTFOUND, action NOT run
  run dr_vps_vm_do_owned vmL "" true;    [ "$status" -eq 0 ]        # operator ('') -> runs
  run dr_vps_vm_do_owned vmL 1001 bash -c 'exit 7'; [ "$status" -eq 7 ]   # action rc propagates
  run dr_vps_vm_do_owned ghost 1001 true; [ "$status" -eq 14 ]      # nonexistent -> not-found
}

@test "S1a: vm_assert_owned -- owner set enforces; owner '' (operator/internal) is a no-op" {
  dr_vps_store_image_register "$AID" "$PROV" "/pool/g.qcow2"
  dr_vps_store_vm_create_from_golden vmA "$AID" /o 0 1 n p 1001 throwaway
  run dr_vps_vm_assert_owned vmA 1001; [ "$status" -eq 0 ]          # match -> ok
  run dr_vps_vm_assert_owned vmA 2002; [ "$status" -eq 14 ]         # foreign -> not-found
  run dr_vps_vm_assert_owned vmA "";   [ "$status" -eq 0 ]          # operator/internal -> no check
  run dr_vps_vm_assert_owned ghost 1001; [ "$status" -eq 14 ]       # nonexistent -> not-found
}
