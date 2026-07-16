#!/usr/bin/env bats
# SNAPSHOT feature (CONCEPT-FORK.md ROUND-3). Offline: real qemu-img on tiny fixtures; seamed virsh +
# virt-sysprep (recorder) + a gate stub (the gate itself is exhaustively covered in gate.bats). Proves the
# store typing/segregation, the hardened create SEQUENCE ORDER, secret-bearing, typed resolvers, refcount-
# gated rm, use-from-snapshot, forced-shutdown-requires-validation, and the disposable-overlay validation flow.

load helpers

setup() {
  dr_vps_test_setup
  export DR_VPS_SNAP_DIR="${DR_VPS_STATE_DIR}/snapshots"; mkdir -p "$DR_VPS_SNAP_DIR"
  export DR_VPS_SNAP_ORDERLOG="${BATS_TEST_TMPDIR}/order.log"; : >"$DR_VPS_SNAP_ORDERLOG"
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_snapshot.sh          # pulls domain -> identity/store/image/storage/net/doctor/gate
  dr_vps_store_init

  # fake virsh: domstate scriptable; a `destroy` (force-off) flips domstate to 'shut off' via a marker so
  # the shutdown-escalation path is exercisable; shutdown/create/undefine no-op (create rc scriptable).
  export FAKEVIRSH_DESTROYED="${BATS_TEST_TMPDIR}/vm-destroyed"
  cat >"${BATS_TEST_TMPDIR}/fakevirsh" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "-c" ] && shift 2
case "${1:-}" in
  domstate) if [ -f "${FAKEVIRSH_DESTROYED:-/nonexistent}" ]; then printf 'shut off\n'; else printf '%s\n' "${FAKEVIRSH_STATE:-shut off}"; fi ;;
  destroy)  : >"${FAKEVIRSH_DESTROYED:-/dev/null}"; exit 0 ;;
  create)   [ "${FAKEVIRSH_CREATE_RC:-0}" = 0 ] || exit 1; exit 0 ;;
  *)        exit 0 ;;
esac
EOF
  chmod +x "${BATS_TEST_TMPDIR}/fakevirsh"; export DR_VIRSH="${BATS_TEST_TMPDIR}/fakevirsh"

  # virt-sysprep recorder: records the invocation, touches nothing (image stays the flattened standalone).
  export SYSPREP_LOG="${BATS_TEST_TMPDIR}/sysprep.log"; : >"$SYSPREP_LOG"
  cat >"${BATS_TEST_TMPDIR}/fakesysprep" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SYSPREP_LOG}"
exit 0
EOF
  chmod +x "${BATS_TEST_TMPDIR}/fakesysprep"; export DR_VIRT_SYSPREP="${BATS_TEST_TMPDIR}/fakesysprep"

  # the gate is stubbed here (its own correctness lives in gate.bats); scriptable via FAKE_GATE_RC.
  eval 'dr_vps_gate_vm() { return "${FAKE_GATE_RC:-0}"; }'
}

# a registered golden + a VM overlay backed by it + a vms row (with a domain_uuid) -> ready to snapshot.
# [owner_uid]: stamp the vms row with a CLIENT owner (S1a source-VM scoping tests); default = NULL (operator).
_mk_golden_and_vm() {  # [owner_uid]
  dr_vps_mk_qcow2 "${DR_VPS_POOL_DIR}/g.qcow2" 1048576 65536 base
  GAID=$(dr_vps_golden_digest "${DR_VPS_POOL_DIR}/g.qcow2")
  cp "${DR_VPS_POOL_DIR}/g.qcow2" "${DR_VPS_POOL_DIR}/${GAID}.qcow2"
  dr_vps_store_image_register "$GAID" '{"distro":"fedora44","family":"dnf","built_at":"2026-07-01T00:00:00Z"}' "${DR_VPS_POOL_DIR}/${GAID}.qcow2"
  VID="drvps-vm-testsnap01"
  qemu-img create -f qcow2 -b "${DR_VPS_POOL_DIR}/${GAID}.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/${VID}.qcow2" >/dev/null 2>&1
  dr_vps_store_vm_create_from_golden "$VID" "$GAID" "${DR_VPS_POOL_DIR}/${VID}.qcow2" "0" "24" "testsnap" "default" "${1:-}"
  dr_vps_store_vm_set_uuid "$VID" "11111111-1111-1111-1111-111111111111"
}
# a SECOND VM backed by the SAME golden (fresh empty overlay -> the flatten yields byte-identical content,
# so the SAME content id), owned by [owner_uid]. The cross-owner IDENTICAL-CONTENT tests need it now that
# create owner-scopes the SOURCE VM (a client can no longer snapshot another owner's VM to collide content).
_mk_vm2() {  # [owner_uid]
  VID2="drvps-vm-testsnap02"
  qemu-img create -f qcow2 -b "${DR_VPS_POOL_DIR}/${GAID}.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/${VID2}.qcow2" >/dev/null 2>&1
  dr_vps_store_vm_create_from_golden "$VID2" "$GAID" "${DR_VPS_POOL_DIR}/${VID2}.qcow2" "0" "24" "testsnap2" "default" "${1:-}"
  dr_vps_store_vm_set_uuid "$VID2" "22222222-2222-2222-2222-222222222222"
}

@test "snapshot --install-log: records a REDACTED install_path SIDECAR; content id stays the IMAGE digest" {
  _mk_golden_and_vm
  printf 'dnf -y install nginx\nmyapp install --token SECRETVALUE123\n' > "$BATS_TEST_TMPDIR/ilog"
  run dr_vps_snapshot_create "$VID" --install-log "$BATS_TEST_TMPDIR/ilog"
  [ "$status" -eq 0 ]; sid="$output"
  # CONTENT-ID INVARIANT: sid is the IMAGE digest, provenance (incl. install_path) is a pure sidecar
  [ "$sid" = "$(dr_vps_snapshot_digest "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2")" ]
  local ip; ip=$(jq -r '.install_path' "${DR_VPS_SNAP_DIR}/${sid}/provenance.json")
  [[ "$ip" == *'dnf -y install nginx'* ]]                          # benign line preserved
  [[ "$ip" != *'SECRETVALUE123'* ]]                                # secret gone
  [[ "$ip" == *'***REDACTED***'* ]]                                # ...replaced
  grep -qF 'dnf -y install nginx' "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"   # rendered into the md
}

@test "snapshot WITHOUT --install-log: install_path empty -> md shows 'not recorded' (backward compat)" {
  _mk_golden_and_vm
  run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 0 ]; sid="$output"
  [ "$(jq -r '.install_path' "${DR_VPS_SNAP_DIR}/${sid}/provenance.json")" = "" ]
  grep -qF 'cmdlog/shell-history not recorded' "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
}

@test "snapshot.md: validation 'skipped' renders a self-explanatory opt-in note" {
  _mk_golden_and_vm
  run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 0 ]; sid="$output"
  grep -qF 'boot-validation is opt-in' "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
}

@test "create: flatten->scrub->digest->register -> bare drvps-snap-v1 id + bundle + snapshots row" {
  _mk_golden_and_vm
  run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^drvps-snap-v1-1048576-[0-9a-f]{64}$ ]]
  sid="$output"
  [ -f "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" ]
  [ -f "${DR_VPS_SNAP_DIR}/${sid}/provenance.json" ]
  [ -f "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md" ]
  # registered kind='snapshot' in images AND has a snapshots row (bijection)
  run dr_vps_sql "SELECT kind FROM images WHERE artifact_id='$sid';"; [ "$output" = snapshot ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
  # sysprep WAS invoked with the explicit allow-list (never the default set)
  grep -q -- '--operations' "$SYSPREP_LOG"
  grep -q 'machine-id' "$SYSPREP_LOG"
}

@test "scrub: every --operations name is a REAL virt-sysprep operation (guards the invalid 'cloud-init' op)" {
  # The bats sysprep RECORDER does NOT validate op names, so an invalid one ('cloud-init' is NOT a virt-sysprep
  # operation on guestfs 1.55.8) made the scrub FAIL on every REAL host -- only a live run surfaced it. Validate
  # the allow-list against the real tool when present; skip on a host without guestfs-tools.
  local ops; ops=$(grep -oE 'ops="[^"]*"' "$DR_VPS_SRC/dr_vps_snapshot.sh" | grep machine-id | head -1 | sed 's/^ops="//; s/"$//')
  [ -n "$ops" ]
  [[ "$ops" != *cloud-init* ]]                              # the invalid op must never come back
  command -v virt-sysprep >/dev/null 2>&1 || skip "virt-sysprep not installed -- op-name validation needs the real tool"
  local valid; valid=$(virt-sysprep --list-operations 2>/dev/null | awk '{print $1}')
  local op; local IFS=,
  for op in $ops; do
    printf '%s\n' "$valid" | grep -qx "$op" || { echo "INVALID virt-sysprep operation in scrub allow-list: $op"; false; }
  done
  # the scrub also uses the --delete FLAG (per-instance cloud-init reset); guard it against the real tool too (I9)
  virt-sysprep --long-options 2>/dev/null | grep -qx -- '--delete' || { echo "virt-sysprep lacks --delete (the scrub uses it)"; false; }
}

@test "flatten/digest seam: qemu-img subcommands + qcow2 output format used are REAL (recorder-blesses-anything guard)" {
  # Same class as the sysprep op-name bug: the bats qemu-img seam blesses any arg, so a typo'd subcommand or an
  # unsupported output format would only fail on a real host. Validate what the code uses (info/create/convert +
  # qcow2 -- src/dr_vps_snapshot.sh + dr_vps_storage.sh) against the real tool, when present.
  command -v qemu-img >/dev/null 2>&1 || skip "qemu-img not installed -- subcommand/format validation needs the real tool"
  local help; help=$(qemu-img --help 2>&1)
  local sub
  for sub in info create convert; do printf '%s\n' "$help" | grep -qw "$sub" || { echo "qemu-img subcommand missing: $sub"; false; }; done
  printf '%s\n' "$help" | grep -qiw qcow2 || { echo "qemu-img lacks qcow2 support"; false; }
}

@test "create: the SEQUENCE ORDER is provenance->shutdown->flatten->assert->sysprep->assert->digest->rename->register" {
  _mk_golden_and_vm
  dr_vps_snapshot_create "$VID" >/dev/null
  run cat "$DR_VPS_SNAP_ORDERLOG"
  # provenance BEFORE sysprep; standalone asserted BOTH before and after sysprep; digest AFTER post-assert;
  # register AFTER the final rename.
  printf '%s\n' "$output" | tr ' ' '\n' >/dev/null
  ord=$(cat "$DR_VPS_SNAP_ORDERLOG" | tr '\n' ' ')
  [[ "$ord" == "provenance shutdown flatten assert_standalone_pre sysprep assert_standalone_post digest rename register "* ]]
}

@test "create --keep-secrets: NO sysprep, secret_bearing=1, image 0640 (qemu-readable backing), LOUD md" {
  _mk_golden_and_vm
  run dr_vps_snapshot_create "$VID" --keep-secrets
  [ "$status" -eq 0 ]; sid="$output"
  [ ! -s "$SYSPREP_LOG" ]                                   # sysprep never ran
  run dr_vps_store_snapshot_secret_bearing "$sid"; [ "$output" = 1 ]
  # 0640 (not 0600) so qemu can read the backing image; the 0750 bundle dir excludes non-TCB.
  run stat -c '%a' "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2"; [ "$output" = 640 ]
  run stat -c '%a' "${DR_VPS_SNAP_DIR}/${sid}"; [ "$output" = 750 ]
  grep -qi 'SECRET-BEARING' "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
}

@test "after snapshot the source VM's store state is 'stopped' (not lying 'running')" {
  _mk_golden_and_vm
  dr_vps_store_vm_set_state "$VID" running
  dr_vps_snapshot_create "$VID" >/dev/null
  run dr_vps_store_vm_get "$VID"                            # "state|generation|artifact_id|egress_gen"
  [[ "$output" == stopped\|* ]]
}

@test "snap-fsck runs under LENIENT init to DIAGNOSE a bijection corruption (not blocked by it)" {
  _mk_golden_and_vm
  # inject a corruption: an images(kind=snapshot) row with NO snapshots row (bijection violation).
  dr_vps_sql "INSERT INTO images(artifact_id,provenance,golden_path,kind,name) VALUES('drvps-snap-v1-1-orphanrow','{}','${DR_VPS_SNAP_DIR}/x/image.qcow2','snapshot','orphanrow');"
  run dr_vps_store_init;                             [ "$status" -ne 0 ]   # strict init REFUSES the inconsistent store
  DR_VPS_STORE_LENIENT_INIT=1 run dr_vps_store_init; [ "$status" -eq 0 ]   # lenient init proceeds so fsck can report
  run dr_vps_snapshot_fsck; [ "$status" -ne 0 ]; [[ "$output" == *"no snapshots row"* ]]
}

@test "create: the lifecycle GATE refusal aborts (E_EGRESS 24), nothing registered" {
  _mk_golden_and_vm
  FAKE_GATE_RC=1 run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 24 ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots;"; [ "$output" = 0 ]
}

@test "SEGREGATION: image_ls (distros) + resolve_golden never surface a snapshot; resolvers are typed" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # distros lists ONLY the golden
  run dr_vps_image_ls; [[ "$output" == *"$GAID"* ]]; [[ "$output" != *"$sid"* ]]
  # resolve_golden accepts the golden, REFUSES the snapshot id
  run dr_vps_resolve_golden "$GAID"; [ "$status" -eq 0 ]; [ "$output" = "$GAID" ]
  run dr_vps_resolve_golden "$sid";  [ "$status" -ne 0 ]
  # resolve_snapshot accepts the snapshot, REFUSES the golden id
  run dr_vps_resolve_snapshot "$sid"; [ "$status" -eq 0 ]; [ "$output" = "$sid" ]
  run dr_vps_resolve_snapshot "$GAID"; [ "$status" -ne 0 ]
}

@test "resolve_golden FAILS CLOSED on a DB read error -- no name-fallthrough, not 'not found' [fail-open sweep]" {
  _mk_golden_and_vm
  run dr_vps_resolve_golden "$GAID"; [ "$status" -eq 0 ]; [ "$output" = "$GAID" ]   # resolves cleanly first
  # a CORRUPT store (surrogate for a transient read error) must FAIL CLOSED (E_VERIFY 18), NOT fall through to
  # the NAME lookup and NOT report a plain not-found -- a transient error must never resolve the WRONG golden.
  printf 'not a sqlite database' > "$DR_VPS_DB"
  run dr_vps_resolve_golden "$GAID"; [ "$status" -eq 18 ]
}

@test "SEGREGATION: create-by-distro (resolve_artifact) never picks a snapshot as the newest golden" {
  _mk_golden_and_vm
  dr_vps_snapshot_create "$VID" >/dev/null                 # a snapshot with distro=fedora44 now exists
  run dr_vps_domain_resolve_artifact fedora44
  [ "$output" = "$GAID" ]                                  # the GOLDEN, not the (newer) snapshot
  [[ "$output" != drvps-snap-* ]]
}

@test "typed vm_create: creating a VM with expected_kind=golden REFUSES a snapshot artifact (and vice-versa)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  qemu-img create -f qcow2 -b "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/x.qcow2" >/dev/null 2>&1
  run dr_vps_store_vm_create_from_golden "drvps-vm-x" "$sid" "${DR_VPS_POOL_DIR}/x.qcow2" 0 24 x default
  [ "$status" -eq 14 ]                                     # no such image (kind=golden): the snapshot
  run dr_vps_store_vm_create_from_snapshot "drvps-vm-x" "$GAID" "${DR_VPS_POOL_DIR}/x.qcow2" 0 24 x default
  [ "$status" -eq 14 ]                                     # no such image (kind=snapshot): the golden
}

@test "rm: refcount-gated -- REFUSED (19) while a VM backs the snapshot, OK after the VM is gone" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # a VM backed by the snapshot (create the overlay + typed row directly)
  qemu-img create -f qcow2 -b "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/u.qcow2" >/dev/null 2>&1
  dr_vps_store_vm_create_from_snapshot "drvps-vm-u" "$sid" "${DR_VPS_POOL_DIR}/u.qcow2" 0 24 u default
  run dr_vps_snapshot_rm "$sid"; [ "$status" -eq 19 ]      # E_REFERENCED
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ]                       # bundle untouched
  dr_vps_store_vm_delete "drvps-vm-u"
  run dr_vps_snapshot_rm "$sid"; [ "$status" -eq 0 ]
  [ ! -e "${DR_VPS_SNAP_DIR}/${sid}" ]                     # bundle gone
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 0 ]
}

@test "image_delete REFUSES a snapshot kind (no orphaned snapshots row / generic GC cannot prune a snapshot)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  run dr_vps_store_image_delete "$sid"
  [ "$status" -ne 0 ]                                      # refused -> snapshots row + images row stay coupled
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
}

@test "use --from-snap: secret-bearing base DENIED without --allow-secret-bearing (E_SECRET 25)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID" --keep-secrets)
  run dr_vps_snapshot_use "drvps-vm-fromsnap" --from-snap "$sid"
  [ "$status" -eq 25 ]
}

@test "rename: valid rename round-trips; a hostile name is rejected (E_USAGE 2)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  run dr_vps_snapshot_rename "$sid" "my-good.name_1"; [ "$status" -eq 0 ]
  run dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';"; [ "$output" = "my-good.name_1" ]
  run dr_vps_snapshot_rename "$sid" 'bad name/../x'; [ "$status" -eq 2 ]
}

@test "duplicate content: re-snapshotting identical bytes is idempotent (same id), not a spurious conflict" {
  _mk_golden_and_vm
  sid1=$(dr_vps_snapshot_create "$VID")
  # second snapshot of the SAME (unchanged) overlay -> identical scrubbed bytes -> same content id
  run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 0 ]
  [ "$output" = "$sid1" ]
}

@test "forced shutdown REQUIRES a passing validation boot -> refuse (18) when validation is off" {
  _mk_golden_and_vm
  # domstate never reaches 'shut off' -> shutdown escalates to forced; VALIDATE off -> must refuse.
  FAKEVIRSH_STATE=running DR_VPS_SNAP_SHUTDOWN_TIMEOUT=1 run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 18 ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots;"; [ "$output" = 0 ]
}

@test "validation boot uses a DISPOSABLE overlay (boots the overlay, never the base); flow order-logged" {
  _mk_golden_and_vm
  DR_VPS_SNAPSHOT_VALIDATE=1 run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 0 ]; sid="$output"
  run dr_vps_sql "SELECT validation_status FROM snapshots WHERE id='$sid';"; [ "$output" = passed ]
  grep -q 'validate_overlay_created' "$DR_VPS_SNAP_ORDERLOG"
  grep -q 'validate_booted' "$DR_VPS_SNAP_ORDERLOG"
}

@test "snap-ls + snap-fsck: a freshly created snapshot lists and is consistent" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  run dr_vps_snapshot_ls; [[ "$output" == *"$sid"* ]]
  run dr_vps_snapshot_fsck; [ "$status" -eq 0 ]; [[ "$output" == *"OK"* ]]
}

@test "golden_match ACCEPTS a snapshot aid (kind-aware) -- the use --from-snap tamper gate" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # the create path runs dr_vps_doctor_golden_match on the pinned artifact; for a snapshot this must NOT
  # false-fire 'TAMPERED' just because the raw digest carries the drvps-raw prefix.
  run dr_vps_doctor_golden_match "$sid"; [ "$status" -eq 0 ]
  run dr_vps_doctor_golden_match "$GAID"; [ "$status" -eq 0 ]   # the golden still verifies too
}

@test "snapshot provenance carries TOP-LEVEL family (so export_family seeds the right pkg mgr)" {
  # golden family = apt this time; the snapshot must inherit family=apt at the TOP level of its provenance.
  dr_vps_mk_qcow2 "${DR_VPS_POOL_DIR}/g.qcow2" 1048576 65536 base
  GAID=$(dr_vps_golden_digest "${DR_VPS_POOL_DIR}/g.qcow2"); cp "${DR_VPS_POOL_DIR}/g.qcow2" "${DR_VPS_POOL_DIR}/${GAID}.qcow2"
  dr_vps_store_image_register "$GAID" '{"distro":"debian12","family":"apt","built_at":"2026-07-01T00:00:00Z"}' "${DR_VPS_POOL_DIR}/${GAID}.qcow2"
  VID="drvps-vm-aptsnap"
  qemu-img create -f qcow2 -b "${DR_VPS_POOL_DIR}/${GAID}.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/${VID}.qcow2" >/dev/null 2>&1
  dr_vps_store_vm_create_from_golden "$VID" "$GAID" "${DR_VPS_POOL_DIR}/${VID}.qcow2" 0 24 aptsnap default
  dr_vps_store_vm_set_uuid "$VID" "22222222-2222-2222-2222-222222222222"
  sid=$(dr_vps_snapshot_create "$VID")
  run jq -r '.family' "${DR_VPS_SNAP_DIR}/${sid}/provenance.json"; [ "$output" = apt ]
}

@test "snap-fsck REPORTS an orphan bundle dir (crash-after-rename / failed snap-rm)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # simulate a crash between rename and register: drop the DB rows but leave the bundle dir.
  dr_vps_sql "DELETE FROM snapshots WHERE id='$sid'; DELETE FROM images WHERE artifact_id='$sid';"
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ]
  run dr_vps_snapshot_fsck; [ "$status" -ne 0 ]; [[ "$output" == *"ORPHAN bundle dir"* ]]
}

@test "a crash-orphan bundle (present, no DB row) is ADOPTED on re-snapshot, not a permanent CONFLICT" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # simulate SIGKILL between mv and register: bundle stays on disk, DB rows gone.
  dr_vps_sql "DELETE FROM snapshots WHERE id='$sid'; DELETE FROM images WHERE artifact_id='$sid';"
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ] && [ -z "$(dr_vps_store_snapshot_golden_path "$sid")" ]
  # re-snapshot the same (unchanged) VM -> same content id -> ADOPT the orphan bundle + register; NOT E_CONFLICT.
  run dr_vps_snapshot_create "$VID"
  [ "$status" -eq 0 ]; [ "$output" = "$sid" ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
  run dr_vps_snapshot_fsck; [ "$status" -eq 0 ]
}

@test "a SYMLINK at the final bundle path is REFUSED by create (not adopted through it) + by snap-rm" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # simulate an attacker/corruption: DB rows gone, real bundle moved aside, a SYMLINK left at the final path.
  dr_vps_sql "DELETE FROM snapshots WHERE id='$sid'; DELETE FROM images WHERE artifact_id='$sid';"
  mv "${DR_VPS_SNAP_DIR}/${sid}" "${BATS_TEST_TMPDIR}/moved-bundle"
  ln -s "${BATS_TEST_TMPDIR}/moved-bundle" "${DR_VPS_SNAP_DIR}/${sid}"
  # re-snapshot identical content must REFUSE (CONFLICT), NOT adopt through the symlink into the moved dir.
  run dr_vps_snapshot_create "$VID"; [ "$status" -eq 15 ]
  [ -d "${BATS_TEST_TMPDIR}/moved-bundle" ]                 # the symlink target was NOT written/registered
  # and snap-rm on such a symlink row must not rm -rf the target dir.
  dr_vps_sql "INSERT INTO images(artifact_id,provenance,golden_path,kind,name) VALUES('$sid','{}','${DR_VPS_SNAP_DIR}/${sid}/image.qcow2','snapshot','sl');
              INSERT INTO snapshots(id,vm_id,artifact_id,secret_bearing,name,source_vm_id,parent_golden_id,bundle_relpath,scrub_profile,shutdown_mode,validation_status,created_at) VALUES('$sid','x','x',0,'sl','x','x','$sid','generic','clean','skipped',datetime('now'));"
  run dr_vps_snapshot_rm "$sid"; [ "$status" -ne 0 ]
  [ -d "${BATS_TEST_TMPDIR}/moved-bundle" ]                 # snap-rm refused the symlink -> target survives
}

@test "adopt REFUSES a real orphan dir whose image.qcow2 is a SYMLINK to outside (no path escape)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  dr_vps_sql "DELETE FROM snapshots WHERE id='$sid'; DELETE FROM images WHERE artifact_id='$sid';"
  # replace the orphan dir's image.qcow2 with a SYMLINK to a same-digest image OUTSIDE the bundle.
  mv "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" "${BATS_TEST_TMPDIR}/outside.qcow2"
  ln -s "${BATS_TEST_TMPDIR}/outside.qcow2" "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2"
  # re-snapshot identical content must REFUSE to adopt through the inner symlink (would register a backing
  # image OUTSIDE the fenced bundle). Expect E_CONFLICT, not adopt.
  run dr_vps_snapshot_create "$VID"; [ "$status" -eq 15 ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 0 ]
}

@test "adopt FAILS CLOSED on a planted sidecar symlink (never follows it to clobber outside)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  dr_vps_sql "DELETE FROM snapshots WHERE id='$sid'; DELETE FROM images WHERE artifact_id='$sid';"
  # real orphan dir + real same-digest image.qcow2, but a planted snapshot.md -> outside target.
  printf 'ORIGINAL\n' > "${BATS_TEST_TMPDIR}/outside-target"
  rm -f "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
  ln -s "${BATS_TEST_TMPDIR}/outside-target" "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
  # adoption refreshes sidecars fail-closed: it UNLINKS the symlink (clearing it) then writes a FRESH regular
  # file, so the outside target is NEVER written through the link. (Dir is writable here -> adopt succeeds.)
  run dr_vps_snapshot_create "$VID"; [ "$status" -eq 0 ]
  grep -q ORIGINAL "${BATS_TEST_TMPDIR}/outside-target"    # KEY: outside target NOT clobbered (link removed, not followed)
  [ -f "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md" ] && [ ! -L "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md" ]  # fresh regular file
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
}

@test "rename REFUSES a name equal to an artifact id; snapshot_id resolves EXACT id before name" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  # a name may not collide with any artifact id.
  run dr_vps_snapshot_rename "$sid" "$GAID"; [ "$status" -eq 2 ]           # E_USAGE: name == a golden id
  run dr_vps_snapshot_rename "$sid" "$sid";  [ "$status" -eq 2 ]           # name == its own id too
  # a legit rename works, and the id still resolves by EXACT id (not shadowed by the new name).
  dr_vps_snapshot_rename "$sid" "friendly-name"
  run dr_vps_store_snapshot_id "$sid"; [ "$output" = "$sid" ]              # exact id wins
  run dr_vps_store_snapshot_id "friendly-name"; [ "$output" = "$sid" ]     # name resolves too
}

@test "notes with newlines is SANITIZED to a single line (cannot forge Markdown in snapshot.md)" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID" --notes "$(printf 'ok\n## Forged\n- parent golden : fake')")
  # the forged '## Forged' heading must NOT appear as its own md line; notes collapsed to one line.
  ! grep -qE '^## Forged' "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md" || false
  ! grep -qE '^- parent golden : fake' "${DR_VPS_SNAP_DIR}/${sid}/snapshot.md" || false
  run dr_vps_sql "SELECT notes FROM snapshots WHERE id='$sid';"; [[ "$output" != *$'\n'* ]]
}

@test "an auto-generated name from a LONG distro stays <=128 (daemon SAFE_SNAP reachable)" {
  dr_vps_mk_qcow2 "${DR_VPS_POOL_DIR}/g.qcow2" 1048576 65536 base
  GAID=$(dr_vps_golden_digest "${DR_VPS_POOL_DIR}/g.qcow2"); cp "${DR_VPS_POOL_DIR}/g.qcow2" "${DR_VPS_POOL_DIR}/${GAID}.qcow2"
  longd=$(printf 'd%.0s' {1..94})
  dr_vps_store_image_register "$GAID" "{\"distro\":\"$longd\",\"family\":\"dnf\"}" "${DR_VPS_POOL_DIR}/${GAID}.qcow2"
  VID="drvps-vm-longd"
  qemu-img create -f qcow2 -b "${DR_VPS_POOL_DIR}/${GAID}.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/${VID}.qcow2" >/dev/null 2>&1
  dr_vps_store_vm_create_from_golden "$VID" "$GAID" "${DR_VPS_POOL_DIR}/${VID}.qcow2" 0 24 longd default
  dr_vps_store_vm_set_uuid "$VID" "33333333-3333-3333-3333-333333333333"
  sid=$(dr_vps_snapshot_create "$VID")
  nm=$(dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';")
  [ "${#nm}" -le 128 ]
}

@test "--profile with a newline/bad char is REJECTED (no md forgery via scrub_profile)" {
  _mk_golden_and_vm
  run dr_vps_snapshot_create "$VID" --profile "$(printf 'generic)\n## FORGED')"; [ "$status" -eq 2 ]
  run dr_vps_snapshot_create "$VID" --profile 'bad profile'; [ "$status" -eq 2 ]
  # a clean profile still works.
  run dr_vps_snapshot_create "$VID" --profile generic; [ "$status" -eq 0 ]
}

@test "a snapshot NAME longer than 128 (daemon SAFE_SNAP cap) is REJECTED by rename" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  run dr_vps_snapshot_rename "$sid" "$(printf 'a%.0s' {1..129})"; [ "$status" -eq 2 ]
  run dr_vps_snapshot_rename "$sid" "$(printf 'a%.0s' {1..120})"; [ "$status" -eq 0 ]
}

@test "migration enforcement fails CLOSED if a required unique-index NAME is squatted by a table" {
  # a TABLE squatting the index name makes CREATE UNIQUE INDEX fail (swallowed) -> the enforcement must catch
  # it by TYPE (not name), else the store runs WITHOUT uniqueness enforcement.
  dr_vps_sql "DROP INDEX IF EXISTS snapshots_name_uq; CREATE TABLE snapshots_name_uq(x);"
  run dr_vps_store_init; [ "$status" -ne 0 ]
  [[ "$output" == *"snapshots_name_uq"* ]]
}

@test "a CORRUPTED (hand-deleted) referrer does NOT let snap-rm delete an in-use snapshot" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  qemu-img create -f qcow2 -b "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" -F qcow2 "${DR_VPS_POOL_DIR}/u.qcow2" >/dev/null 2>&1
  dr_vps_store_vm_create_from_snapshot "drvps-vm-u" "$sid" "${DR_VPS_POOL_DIR}/u.qcow2" 0 24 u default
  # CORRUPT the ledger: delete the referrer row the VM should have (simulating a hand-edited store).
  dr_vps_sql "DELETE FROM referrers WHERE artifact_id='$sid';"
  # snap-rm must STILL refuse: the direct vms-table check blocks it, so the in-use image is NOT deleted.
  run dr_vps_snapshot_rm "$sid"; [ "$status" -eq 19 ]
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
}

# ---- OWNER SCOPING (same-host multi-client): the ingress accepter stamps owner_uid from SO_PEERCRED,
# threaded to the verbs as --owner. A client sees/acts on ONLY its own snapshots; the direct operator
# (no --owner) is admin (sees + can recover all). Registers synthetic bundles directly to give two
# DISTINCT-content snapshots with different owners (the create path would collide identical bytes to one id).
_reg_snap() {   # <id> <name> <owner_uid|''>
  local sid="$1" nm="$2" own="$3"
  mkdir -p "${DR_VPS_SNAP_DIR}/${sid}"
  printf 'img\n'          >"${DR_VPS_SNAP_DIR}/${sid}/image.qcow2"
  printf '{}'             >"${DR_VPS_SNAP_DIR}/${sid}/provenance.json"
  printf '# snap %s\n' "$sid" >"${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
  dr_vps_store_snapshot_register "$sid" "$nm" '{"distro":"fedora44","family":"dnf"}' \
    "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" srcvm parentgold "$sid" 0 generic clean skipped "" "$own"
}
_sid() { local h; h=$(printf '%064d' 0 | tr 0 "$1"); printf 'drvps-snap-v1-1048576-%s' "$h"; }   # a valid 64-char-shaped snap id from a filler char

@test "owner-scoping: snap-ls is per-owner -- a client sees only its own; the operator (no --owner) sees all" {
  local A=4001 B=4002 sa sb so; sa=$(_sid a); sb=$(_sid b); so=$(_sid c)
  _reg_snap "$sa" snap-a "$A"
  _reg_snap "$sb" snap-b "$B"
  _reg_snap "$so" snap-op ""                              # NULL owner == operator-created
  run dr_vps_snapshot_ls --owner "$A"                     # client A: ONLY its own
  [[ "$output" == *"$sa"* ]]; [[ "$output" != *"$sb"* ]]; [[ "$output" != *"$so"* ]]
  run dr_vps_snapshot_ls                                  # operator: ALL three
  [[ "$output" == *"$sa"* ]]; [[ "$output" == *"$sb"* ]]; [[ "$output" == *"$so"* ]]
}

@test "owner-scoping: a client cannot show/rm ANOTHER client's snapshot (not-found, no leak); the OWNER can" {
  local A=4001 B=4002 sa sb; sa=$(_sid a); sb=$(_sid b)
  _reg_snap "$sa" snap-a "$A"
  _reg_snap "$sb" snap-b "$B"
  # client A against B's snapshot -> E_NOTFOUND (14): identical to a nonexistent id (no existence leak).
  run dr_vps_snapshot_show "$sb" --owner "$A"; [ "$status" -eq 14 ]
  run dr_vps_snapshot_rm   "$sb" --owner "$A"; [ "$status" -eq 14 ]
  [ -d "${DR_VPS_SNAP_DIR}/${sb}" ]                       # B's bundle untouched by A
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sb';"; [ "$output" = 1 ]
  # the OWNER (B) shows + removes its own -- permission is bound to the uid, so it PERSISTS across sessions.
  run dr_vps_snapshot_show "$sb" --owner "$B"; [ "$status" -eq 0 ]
  run dr_vps_snapshot_rm   "$sb" --owner "$B"; [ "$status" -eq 0 ]
  [ ! -e "${DR_VPS_SNAP_DIR}/${sb}" ]
}

@test "owner-scoping: use --from-snap of ANOTHER client's snapshot is DENIED before any clone (fail-closed base)" {
  local A=4001 B=4002 sa sb; sa=$(_sid a); sb=$(_sid b)
  _reg_snap "$sa" snap-a "$A"
  _reg_snap "$sb" snap-b "$B"
  # client A tries to clone B's snapshot as a base -> E_NOTFOUND (14) BEFORE any domain clone, indistinguishable
  # from a nonexistent id (no existence leak). This is the confidentiality property the decider's fail-closed
  # `use` rule enforces on the agent path: an unscoped use could otherwise boot a VM off a FOREIGN owner's base.
  run dr_vps_snapshot_use "drvps-vm-x" --from-snap "$sb" --owner "$A"
  [ "$status" -eq 14 ]
  [ -d "${DR_VPS_SNAP_DIR}/${sb}" ]                         # B's bundle untouched
  # positive control -- the owner-scoped resolve that `use` gates on: B resolves its own base; A cannot.
  run dr_vps_resolve_snapshot "$sb" "$B"; [ "$status" -eq 0 ]; [ "$output" = "$sb" ]
  run dr_vps_resolve_snapshot "$sb" "$A"; [ "$status" -ne 0 ]
}

@test "owner-scoping: snapshot of ANOTHER client's SOURCE VM is refused (E_NOTFOUND) before any lifecycle step; the owner passes" {
  local A=4001 B=4002
  _mk_golden_and_vm "$B"                                    # the SOURCE VM belongs to client B
  # client A snapshots B's VM -> E_NOTFOUND (14), indistinguishable from a nonexistent id (no existence
  # leak). Without this gate A could shut B's VM down, flatten its disk, and register the copy under A
  # (data theft + DoS) -- the --owner stamp alone scopes only the RESULT snapshot, not the source.
  run dr_vps_snapshot_create "$VID" --owner "$A"
  [ "$status" -eq 14 ]
  [ ! -s "$DR_VPS_SNAP_ORDERLOG" ]                          # NOTHING ran: no provenance/shutdown/flatten
  [ ! -f "$FAKEVIRSH_DESTROYED" ]                           # never force-off'd
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots;"; [ "$output" = 0 ]
  run dr_vps_sql "SELECT state FROM vms WHERE id='$VID';"; [ "$output" != "stopped" ]   # source untouched
  # positive control: the OWNER (B) passes the source gate and the create succeeds end-to-end.
  run dr_vps_snapshot_create "$VID" --owner "$B"
  [ "$status" -eq 0 ]; local sid="$output"
  run dr_vps_sql "SELECT owner_uid FROM snapshots WHERE id='$sid';"; [ "$output" = "$B" ]   # result owner-stamped
}

@test "snap-show: a FAILED sidecar read/render propagates a NONZERO rc (never a silent success with no output)" {
  # The md is absent and the render fallback FAILS: show must return the READ status, not the
  # status of closing the lock fd (which is 0 -- a caller would treat garbage/empty as success).
  local A=4001 sa; sa=$(_sid a)
  _reg_snap "$sa" snap-a "$A"
  rm -f "${DR_VPS_SNAP_DIR}/${sa}/snapshot.md"
  dr_vps_snapshot_md_render() { return 7; }
  run dr_vps_snapshot_show "$sa" --owner "$A"
  unset -f dr_vps_snapshot_md_render
  [ "$status" -eq 7 ]
}

@test "owner-scoping: the operator (no --owner) can rm ANY client's snapshot -- admin recovery is always possible" {
  local A=4001 sa; sa=$(_sid a)
  _reg_snap "$sa" snap-a "$A"
  run dr_vps_snapshot_rm "$sa"; [ "$status" -eq 0 ]       # unscoped operator resolves + removes a client-owned snap
  [ ! -e "${DR_VPS_SNAP_DIR}/${sa}" ]
}

@test "owner-scoping: cross-owner denial holds BY NAME too; a client cannot reach a NULL-owner (operator) snapshot" {
  # The prior cross-owner test only used IDs. The NAME lookup in store_snapshot_id is ALSO owner-scoped
  # (WHERE name=? AND owner_uid=?), and a NULL-owner (operator) row must be invisible to any client (owner_uid=N
  # never matches NULL). Pin both, by id AND by name.
  local A=4001 B=4002 sb so; sb=$(_sid b); so=$(_sid c)
  _reg_snap "$sb" snap-b "$B"                             # client B's, human name snap-b
  _reg_snap "$so" snap-op ""                              # operator's (NULL owner), human name snap-op
  # BY NAME: client A resolving B's snapshot by NAME is also not-found (name lookup is owner-scoped, no leak)
  run dr_vps_snapshot_show snap-b --owner "$A"; [ "$status" -eq 14 ]
  run dr_vps_snapshot_rm   snap-b --owner "$A"; [ "$status" -eq 14 ]
  [ -d "${DR_VPS_SNAP_DIR}/${sb}" ]                       # untouched
  # NULL-owner (operator) snapshot: a CLIENT cannot show/rm it by id OR by name
  run dr_vps_snapshot_show "$so"    --owner "$A"; [ "$status" -eq 14 ]
  run dr_vps_snapshot_show snap-op  --owner "$A"; [ "$status" -eq 14 ]
  run dr_vps_snapshot_rm   snap-op  --owner "$A"; [ "$status" -eq 14 ]
  [ -d "${DR_VPS_SNAP_DIR}/${so}" ]                       # untouched by the client
  # but the OWNER B (by name) reaches its own, and the OPERATOR (no --owner) reaches the NULL-owner one
  run dr_vps_snapshot_show snap-b  --owner "$B"; [ "$status" -eq 0 ]
  run dr_vps_snapshot_show snap-op;              [ "$status" -eq 0 ]
}

@test "owner-scoping: snap-rm re-verifies ownership UNDER the lock (TOCTOU) -- aborts if the row changed owner, never deletes another's" {
  # TOCTOU: resolve is owner-scoped but happens BEFORE the lock; the store delete is by id (unscoped).
  # Simulate a delete+re-register under a DIFFERENT owner in the window: resolve (call 1) sees A's row, the
  # under-lock re-check (call 2) sees it no longer owned by A. rm must ABORT, not delete.
  _mk_golden_and_vm 4001
  sid=$(dr_vps_snapshot_create "$VID" --owner 4001)
  cnt="${BATS_TEST_TMPDIR}/rmtoctou"; printf 0 >"$cnt"
  eval "$(declare -f dr_vps_store_snapshot_id | sed '1s/^dr_vps_store_snapshot_id/_real_ssid/')"
  dr_vps_store_snapshot_id() {
    local n; n=$(cat "$cnt"); n=$((n+1)); printf '%s' "$n" >"$cnt"
    [ "$n" -ge 2 ] && return 0                # 2nd call = under-lock re-check -> empty (owner changed)
    _real_ssid "$@"                           # 1st call = resolve -> real (A owns sid)
  }
  run dr_vps_snapshot_rm "$sid" --owner 4001
  [ "$status" -ne 0 ]                          # aborted -- did NOT delete under changed ownership
  unset -f dr_vps_store_snapshot_id
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ]           # bundle NOT deleted
  run _real_ssid "$sid" 4001; [ "$output" = "$sid" ]   # A's row intact
}

@test "owner-scoping: snap-show re-verifies ownership UNDER the lock (TOCTOU) -- aborts if the row changed owner, never reads another's" {
  # Same TOCTOU on the read side (resolve then read sidecars). The under-lock re-check must
  # abort if ownership changed in the window, so a caller never reads another owner's refreshed metadata.
  _mk_golden_and_vm 4001
  sid=$(dr_vps_snapshot_create "$VID" --owner 4001)
  cnt="${BATS_TEST_TMPDIR}/showtoctou"; printf 0 >"$cnt"
  eval "$(declare -f dr_vps_store_snapshot_id | sed '1s/^dr_vps_store_snapshot_id/_real_ssid/')"
  dr_vps_store_snapshot_id() {
    local n; n=$(cat "$cnt"); n=$((n+1)); printf '%s' "$n" >"$cnt"
    [ "$n" -ge 2 ] && return 0                # 2nd call = under-lock re-check -> empty (owner changed)
    _real_ssid "$@"
  }
  run dr_vps_snapshot_show "$sid" --owner 4001
  [ "$status" -ne 0 ]                          # aborted before reading -- no cross-owner metadata read
}

@test "owner-scoping: store snapshot rename is owner-scoped + collision-guarded ATOMICALLY (RACE) -- refuses cross-owner + name==id" {
  # The rename UPDATE fires only when the row is still owned by this caller AND no artifact
  # id equals the new name -- so a delete+re-register under a different owner, or a concurrent artifact_id==name
  # registration, in the resolve..write window yields changes()=0 (refused), never a cross-owner rename or a
  # name==id ambiguity. Test the store layer directly (the atomic guard, independent of the verb pre-checks).
  _mk_golden_and_vm 4001
  sid=$(dr_vps_snapshot_create "$VID" --owner 4001)
  run dr_vps_store_snapshot_rename "$sid" newname 4002; [ "$status" -ne 0 ]                 # cross-owner refused
  run dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';"; [ "$output" != newname ]     # unchanged
  run dr_vps_store_snapshot_rename "$sid" newname 4001; [ "$status" -eq 0 ]                  # the owner can
  run dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';"; [ "$output" = newname ]
  run dr_vps_store_snapshot_rename "$sid" "$GAID" 4001; [ "$status" -ne 0 ]                  # name==golden id refused
  run dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';"; [ "$output" = newname ]      # still newname
}

@test "owner-scoping: use --from-snap re-verifies ownership UNDER the lock (TOCTOU) -- aborts if the row changed owner, never clones another's" {
  # TOCTOU: resolve is owner-scoped, but the secret-bearing read + VM clone act on the id unscoped.
  # Simulate a delete+re-register under a different owner in the window: resolve (call 1) sees A, the under-lock
  # re-check (call 2) sees it no longer owned by A -> use must ABORT before creating the VM.
  _mk_golden_and_vm 4001
  sid=$(dr_vps_snapshot_create "$VID" --owner 4001)
  cnt="${BATS_TEST_TMPDIR}/usetoctou"; printf 0 >"$cnt"
  eval "$(declare -f dr_vps_store_snapshot_id | sed '1s/^dr_vps_store_snapshot_id/_real_ssid/')"
  dr_vps_store_snapshot_id() {
    local n; n=$(cat "$cnt"); n=$((n+1)); printf '%s' "$n" >"$cnt"
    [ "$n" -ge 2 ] && return 0                # 2nd call = under-lock re-check -> empty (owner changed)
    _real_ssid "$@"
  }
  run dr_vps_snapshot_use newvm --from-snap "$sid" --owner 4001
  [ "$status" -ne 0 ]                          # aborted -- no VM cloned from a snapshot no longer owned by caller
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='drvps-vm-newvm';"; [ "$output" = 0 ]
}

@test "owner-scoping: image_delete FAILS CLOSED on a kind-read error (generic GC never prunes a snapshot's images row on a transient DB error)" {
  # An errored kind read must not pass the 'not a snapshot' guard and let generic GC delete a
  # snapshot's images row (orphaning its authoritative snapshots row).
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() { case "$1" in *"SELECT kind FROM images WHERE artifact_id="*) return 1;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_store_image_delete "$sid"
  [ "$status" -ne 0 ]; [[ "$output" == *"db read error"* ]]
  unset -f dr_vps_sql
  run _real_dr_vps_sql "SELECT COUNT(*) FROM images WHERE artifact_id='$sid';"; [ "$output" = 1 ]   # images row intact
  run _real_dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]         # snapshots row intact
}

@test "owner-scoping: create --owner stamps owner_uid + scopes the snapshot; a non-numeric owner is E_USAGE (2)" {
  _mk_golden_and_vm 4007
  run dr_vps_snapshot_create "$VID" --owner 4007; [ "$status" -eq 0 ]; sid="$output"
  run dr_vps_sql "SELECT owner_uid FROM snapshots WHERE id='$sid';"; [ "$output" = 4007 ]
  run dr_vps_snapshot_ls --owner 4007; [[ "$output" == *"$sid"* ]]     # owner sees it
  run dr_vps_snapshot_ls --owner 9999; [[ "$output" != *"$sid"* ]]     # a different client does not
  run dr_vps_snapshot_ls;              [[ "$output" == *"$sid"* ]]     # operator sees it
  # a non-numeric owner is refused at parse (never reaches the store)
  run dr_vps_snapshot_create "$VID" --owner 'root; DROP'; [ "$status" -eq 2 ]
}

@test "owner-scoping: create --owner B of content ALREADY OWNED by A is a CONFLICT (single-owner content), never a silent leak of A's id" {
  # Snapshots are content-addressed + SINGLE-OWNER in v1. If client B snapshots byte-identical content that
  # client A already owns, the idempotent short-circuit must NOT fire for B (which would silently hand B A's id
  # under A's ownership); it falls through to publish and surfaces an explicit E_CONFLICT.
  _mk_golden_and_vm 4001
  sa=$(dr_vps_snapshot_create "$VID" --owner 4001)
  run dr_vps_sql "SELECT owner_uid FROM snapshots WHERE id='$sa';"; [ "$output" = 4001 ]
  _mk_vm2 4002                                                  # B's OWN VM, byte-identical content
  run dr_vps_snapshot_create "$VID2" --owner 4002              # B: identical content -> conflict, not A's id
  [ "$status" -eq 15 ]
  run dr_vps_sql "SELECT owner_uid FROM snapshots WHERE id='$sa';"; [ "$output" = 4001 ]   # A's row untouched
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sa';"; [ "$output" = 1 ]        # still exactly one
  # the SAME owner (A) re-snapshotting identical content is STILL idempotent (returns its own id)
  run dr_vps_snapshot_create "$VID" --owner 4001; [ "$status" -eq 0 ]; [ "$output" = "$sa" ]
}

@test "owner-scoping: create --owner B of A-owned content whose BUNDLE IS MISSING is a CONFLICT (register never no-ops into A's row)" {
  # A's DB row exists but the bundle dir was deleted/stale. The owner-scoped short-circuit does
  # NOT fire (image absent), so without a guard B would publish a fresh bundle and register's INSERT-WHERE-NOT-
  # EXISTS would silently no-op -> B receives A's id under A's ownership + A's bundle overwritten by B. The
  # cross-owner guard must refuse BEFORE publish.
  _mk_golden_and_vm 4001
  sa=$(dr_vps_snapshot_create "$VID" --owner 4001)
  rm -rf "${DR_VPS_SNAP_DIR}/${sa}"                             # simulate a deleted/stale bundle (DB rows remain)
  [ ! -e "${DR_VPS_SNAP_DIR}/${sa}" ]
  _mk_vm2 4002                                                  # B's OWN VM, byte-identical content
  run dr_vps_snapshot_create "$VID2" --owner 4002              # B: identical content, A's bundle missing
  [ "$status" -eq 15 ]                                          # E_CONFLICT, not a silent rebuild into A's row
  run dr_vps_sql "SELECT owner_uid FROM snapshots WHERE id='$sa';"; [ "$output" = 4001 ]   # still A's
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sa';"; [ "$output" = 1 ]
  # the SAME owner (A) CAN still rebuild its own missing bundle (legit rebuild path preserved)
  run dr_vps_snapshot_create "$VID" --owner 4001; [ "$status" -eq 0 ]; [ "$output" = "$sa" ]
  [ -f "${DR_VPS_SNAP_DIR}/${sa}/image.qcow2" ]                 # bundle rebuilt
}

@test "owner-scoping: the idempotent short-circuit does NOT bless a SYMLINKED bundle (fails closed, not a false success)" {
  # `-f image.qcow2` follows symlinks; a bundle dir replaced by a symlink to outside would let a
  # same-owner re-create report SUCCESS for an unfenced/corrupt bundle. The short-circuit must require a REAL
  # (non-symlink) dir + regular image, else fall through to the publish `-L` guard -> E_CONFLICT.
  _mk_golden_and_vm 4001
  sa=$(dr_vps_snapshot_create "$VID" --owner 4001)
  mv "${DR_VPS_SNAP_DIR}/${sa}" "${BATS_TEST_TMPDIR}/moved-sa"    # real bundle aside
  ln -s "${BATS_TEST_TMPDIR}/moved-sa" "${DR_VPS_SNAP_DIR}/${sa}" # symlink at the canonical path (image resolves via it)
  [ -f "${DR_VPS_SNAP_DIR}/${sa}/image.qcow2" ]                   # `-f` follows the symlink (the trap)
  run dr_vps_snapshot_create "$VID" --owner 4001                 # same owner, identical content
  [ "$status" -eq 15 ]                                           # E_CONFLICT (symlink caught), NOT a false success
  [ -d "${BATS_TEST_TMPDIR}/moved-sa" ]                          # the moved-aside target was not written through
}

@test "owner-scoping: a MALFORMED --owner on the direct CLI fails CLOSED (E_USAGE), never silently admin/hang" {
  _mk_golden_and_vm 4001
  sid=$(dr_vps_snapshot_create "$VID" --owner 4001)
  run dr_vps_snapshot_ls --owner;            [ "$status" -eq 2 ]   # --owner with no value -> usage, not "list all"
  run dr_vps_snapshot_ls --owner abc;        [ "$status" -eq 2 ]   # non-numeric -> usage
  run dr_vps_snapshot_show "$sid" --owner;   [ "$status" -eq 2 ]   # loop parser: no value -> usage, must not hang
  run dr_vps_snapshot_rm   "$sid" --owner;   [ "$status" -eq 2 ]
  run dr_vps_snapshot_rename "$sid" nm --owner; [ "$status" -eq 2 ]
  # a WELL-FORMED --owner still works (regression guard)
  run dr_vps_snapshot_ls --owner 4001;       [ "$status" -eq 0 ]; [[ "$output" == *"$sid"* ]]
}

@test "owner-scoping: create FAILS CLOSED (not open) when the ownership DB read errors -- never publishes under unknown ownership" {
  # A transient SQLite lock/error during the ownership lookup must NOT look like "no row" and
  # slip past the idempotent + cross-owner guards. Fault-inject ONLY the owner-lookup SELECT (all other SQL
  # still works) and assert create refuses with a db-read error and registers nothing.
  _mk_golden_and_vm 4001
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() { case "$1" in *"COALESCE(owner_uid"*) return 1;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_snapshot_create "$VID" --owner 4001
  [ "$status" -ne 0 ]                                        # refused, not a false success
  [[ "$output" == *"db read error"* ]]
  run _real_dr_vps_sql "SELECT COUNT(*) FROM snapshots;"; [ "$output" = 0 ]   # nothing registered
}

@test "owner-scoping: a CLIENT cannot ADOPT a crash-orphan bundle (operator-only adoption); the operator still self-heals" {
  # A crash-orphan (present bundle, no DB row) has NO recorded owner. A client must not adopt it
  # (it could be ANOTHER client's in-flight content -> B would claim A's). Adoption is operator-only.
  _mk_golden_and_vm 4001
  sid=$(dr_vps_snapshot_create "$VID" --owner 4001)
  dr_vps_sql "DELETE FROM snapshots WHERE id='$sid'; DELETE FROM images WHERE artifact_id='$sid';"   # crash between mv and register
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ] && [ -z "$(dr_vps_store_snapshot_golden_path "$sid")" ]
  _mk_vm2 4002                                              # B's OWN VM, byte-identical content
  run dr_vps_snapshot_create "$VID2" --owner 4002           # client B, identical content
  [ "$status" -eq 15 ]                                      # E_CONFLICT -- refused, NOT adopted into B's ownership
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ]                        # orphan untouched
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 0 ]   # not registered to B
  # the OPERATOR (no --owner, admin) still self-heals -- adopts + registers
  run dr_vps_snapshot_create "$VID"; [ "$status" -eq 0 ]; [ "$output" = "$sid" ]
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
}

@test "owner-scoping: snap-fsck --prune removes a crash-orphan bundle but leaves a REGISTERED snapshot (operator cleanup path)" {
  # The operator needs a concrete CLEANUP path for final crash-orphans (not just a diagnostic).
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")                      # a REAL registered snapshot
  orph="drvps-snap-v1-1-$(printf '%064d' 0 | tr 0 f)"       # a bundle dir with a valid-shaped id but NO DB row
  mkdir -p "${DR_VPS_SNAP_DIR}/${orph}"; printf 'x' >"${DR_VPS_SNAP_DIR}/${orph}/image.qcow2"
  run dr_vps_snapshot_fsck; [ "$status" -ne 0 ]; [[ "$output" == *"ORPHAN bundle dir"* ]]   # read-only: reports
  [ -d "${DR_VPS_SNAP_DIR}/${orph}" ]                       # not removed by a plain fsck
  run dr_vps_snapshot_fsck --prune; [ "$status" -eq 0 ]; [[ "$output" == *"PRUNED"* ]]      # --prune: removes it
  [ ! -e "${DR_VPS_SNAP_DIR}/${orph}" ]                     # orphan gone
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ]                        # the REGISTERED snapshot is untouched
  run dr_vps_sql "SELECT COUNT(*) FROM snapshots WHERE id='$sid';"; [ "$output" = 1 ]
}

@test "owner-scoping: snap-fsck --prune refuses to follow a SYMLINKED orphan (never rm the link target)" {
  _mk_golden_and_vm
  printf 'ORIGINAL\n' >"${BATS_TEST_TMPDIR}/prune-outside"
  orph="drvps-snap-v1-1-$(printf '%064d' 0 | tr 0 e)"
  ln -s "${BATS_TEST_TMPDIR}" "${DR_VPS_SNAP_DIR}/${orph}"  # a symlinked "orphan" pointing outside the fence
  run dr_vps_snapshot_fsck --prune; [ "$status" -ne 0 ]; [[ "$output" == *"refusing to prune"* ]]
  [ -f "${BATS_TEST_TMPDIR}/prune-outside" ]                # the symlink target survived (link not followed)
}

@test "owner-scoping: snap-fsck --prune FAILS CLOSED on a DB read error -- never prunes a bundle under an unknown row state" {
  # An EMPTY read result must mean "no row", NOT "the read errored". Fault-inject the
  # snapshots-row lookup: if --prune treated the error as "orphan" it would rm -rf a REGISTERED bundle.
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")                      # a REGISTERED snapshot (real bundle + row)
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() { case "$1" in *"SELECT 1 FROM snapshots WHERE id="*) return 1;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_snapshot_fsck --prune
  [ "$status" -ne 0 ]                                       # reported an issue, did not silently prune
  [[ "$output" == *"db read error"* ]]
  [ -d "${DR_VPS_SNAP_DIR}/${sid}" ] && [ -f "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" ]   # REGISTERED bundle SURVIVED
}

@test "owner-scoping: snap-fsck --prune fails closed if the INSIDE-LOCK re-check errors (never prunes on an errored re-read)" {
  # The classification-read fault (above) skips before the inside-lock re-check, so it does not pin
  # that read's rc-check. Here the orphan's FIRST row lookup (classification) SUCCEEDS as an orphan (empty+ok)
  # but its SECOND (inside-lock re-check) ERRORS -> prune must REFUSE, not treat the errored re-read as "no row".
  _mk_golden_and_vm
  orph="drvps-snap-v1-1-$(printf '%064d' 0 | tr 0 c)"
  mkdir -p "${DR_VPS_SNAP_DIR}/${orph}"; printf 'x' >"${DR_VPS_SNAP_DIR}/${orph}/image.qcow2"
  cnt="${BATS_TEST_TMPDIR}/prune_cnt"; printf 0 >"$cnt"
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() {
    case "$1" in
      *"SELECT 1 FROM snapshots WHERE id="*"${orph}"*)     # ONLY the orphan's row check
        local n; n=$(cat "$cnt"); n=$((n+1)); printf '%s' "$n" >"$cnt"
        [ "$n" -ge 2 ] && return 1                         # 2nd call (inside-lock re-check) errors
        return 0 ;;                                         # 1st call (classification) -> empty + ok = orphan
      *) _real_dr_vps_sql "$1" ;;
    esac
  }
  run dr_vps_snapshot_fsck --prune
  [ "$status" -ne 0 ]
  [[ "$output" == *"could NOT prune"* ]]                    # inside-lock re-check errored -> refused
  [ -d "${DR_VPS_SNAP_DIR}/${orph}" ]                       # orphan NOT deleted under the errored re-read
}

@test "owner-scoping: snapshot_id FAILS CLOSED on an exact-id read error -- never falls through to a name-collision match" {
  # If the exact-id read errors and is read as "no id row", resolution falls through to a name
  # lookup and can act on a DIFFERENT snapshot whose name collides with the requested id. Inject a corrupt row
  # whose NAME equals sida's ID (rename now forbids creating this, so inject directly), then error the exact-id
  # read and assert snapshot_id does NOT resolve to the name-colliding row.
  _mk_golden_and_vm
  sida=$(dr_vps_snapshot_create "$VID")
  sidx="drvps-snap-v1-1-$(printf '%064d' 0 | tr 0 a)"
  dr_vps_sql "INSERT INTO snapshots(id,vm_id,artifact_id,secret_bearing,name,source_vm_id,parent_golden_id,bundle_relpath,scrub_profile,shutdown_mode,validation_status,created_at) VALUES('$sidx','v','v',0,'$sida','v','v','x','generic','clean','skipped',datetime('now'));"
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() { case "$1" in *"SELECT id FROM snapshots WHERE id="*) return 1;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_store_snapshot_id "$sida"
  [ "$status" -ne 0 ]                                       # failed closed
  [ "$output" != "$sidx" ]                                  # did NOT resolve via the name collision
  [ -z "$output" ]
}

@test "owner-scoping: snap-rename FAILS CLOSED if the artifact-id collision check errors (never creates name==id ambiguity)" {
  # An errored collision-guard read read as "no collision" would let rename create a name==an
  # existing artifact id -- the ambiguity the resolver depends on NOT existing.
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID")
  oldname=$(dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';")
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() { case "$1" in *"SELECT 1 FROM images WHERE artifact_id="*) return 1;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_snapshot_rename "$sid" some-new-name
  [ "$status" -ne 0 ]                                       # refused on the errored guard read
  [[ "$output" == *"db read error"* ]]
  unset -f dr_vps_sql
  run _real_dr_vps_sql "SELECT name FROM snapshots WHERE id='$sid';"; [ "$output" = "$oldname" ]   # unchanged
}

@test "snapshot idempotent shortcut RE-DIGESTS -- corrupted registered image -> FAIL CLOSED, not green" {
  _mk_golden_and_vm
  sid=$(dr_vps_snapshot_create "$VID"); [ -n "$sid" ]
  printf 'CORRUPT' > "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2"                    # tamper the registered image
  run dr_vps_snapshot_create "$VID"                                            # re-snapshot -> same sid
  [ "$status" -eq 18 ]
  [[ "$output" == *"digest"* ]]
}

@test "S1b/hot-path: use --from-snap --class service --owner M FORWARDS both --class AND --owner to the clone (no silent drop)" {
  local M=4001 sid; sid=$(_sid a); _reg_snap "$sid" snap-a "$M"
  # Capture EXACTLY what snapshot_use hands the clone step (domain_use_snapshot passes "$@" verbatim to
  # domain_create, which stamps class+owner -- proven in domain.bats). This closes the same silent-drop risk
  # that the --owner path once had. It is THE per-channel service path (build-once template -> use per channel).
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  run dr_vps_snapshot_use "drvps-vm-ch1" --from-snap "$sid" --class service --owner "$M"
  [ "$status" -eq 0 ]
  grep -q -- '--class service' "$BATS_TEST_TMPDIR/usecall"     # class reaches the clone -> not throwaway -> not reaped
  grep -q -- "--owner $M"      "$BATS_TEST_TMPDIR/usecall"     # owner reaches the clone -> caller owns the new VM
}

# ---- S6: same-user keep-secrets restore for service VMs (GATED: DR_VPS_ALLOW_SECRET_RESTORE, default OFF) --
_reg_snap_secret() {   # <id> <name> <owner_uid|''>  -- like _reg_snap but secret_bearing=1
  local sid="$1" nm="$2" own="$3"
  mkdir -p "${DR_VPS_SNAP_DIR}/${sid}"
  printf 'img\n'          >"${DR_VPS_SNAP_DIR}/${sid}/image.qcow2"
  printf '{}'             >"${DR_VPS_SNAP_DIR}/${sid}/provenance.json"
  printf '# snap %s\n' "$sid" >"${DR_VPS_SNAP_DIR}/${sid}/snapshot.md"
  dr_vps_store_snapshot_register "$sid" "$nm" '{"distro":"fedora44","family":"dnf"}' \
    "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" srcvm parentgold "$sid" 1 generic clean skipped "" "$own"
}

@test "S6: agent secret-restore with the policy flag OFF (default) is REFUSED even with --allow-secret-bearing" {
  local M=4001 sid; sid=$(_sid d); _reg_snap_secret "$sid" sb-a "$M"
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  unset DR_VPS_ALLOW_SECRET_RESTORE
  run dr_vps_snapshot_use "drvps-vm-r1" --from-snap "$sid" --allow-secret-bearing --class service --owner "$M"
  [ "$status" -eq 25 ]                                   # E_SECRET: the door stays closed by default
  [[ "$output" == *"DR_VPS_ALLOW_SECRET_RESTORE"* ]]     # names the operator opt-in
  [ ! -e "$BATS_TEST_TMPDIR/usecall" ]                   # never cloned
}

@test "S6: agent secret-restore REQUIRES class=service (throwaway/absent class refused, flag ON)" {
  local M=4001 sid; sid=$(_sid e); _reg_snap_secret "$sid" sb-b "$M"
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  export DR_VPS_ALLOW_SECRET_RESTORE=1
  run dr_vps_snapshot_use "drvps-vm-r2" --from-snap "$sid" --allow-secret-bearing --owner "$M"
  [ "$status" -eq 25 ]; [[ "$output" == *service* ]]
  run dr_vps_snapshot_use "drvps-vm-r2" --from-snap "$sid" --allow-secret-bearing --class throwaway --owner "$M"
  [ "$status" -eq 25 ]
  [ ! -e "$BATS_TEST_TMPDIR/usecall" ]
}

@test "S6: agent secret-restore is 1:1 -- refused while ANY persisted owner VM row (any state) references the snapshot (restore=replace, destroy must COMPLETE)" {
  local M=4001 sid; sid=$(_sid f); _reg_snap_secret "$sid" sb-c "$M"
  # a live VM of owner M already cloned from this snapshot (artifact_id == sid)
  dr_vps_store_vm_create_from_snapshot drvps-vm-old "$sid" /x.qcow2 0 1 old agent "$M" service
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  export DR_VPS_ALLOW_SECRET_RESTORE=1
  run dr_vps_snapshot_use "drvps-vm-r3" --from-snap "$sid" --allow-secret-bearing --class service --owner "$M"
  [ "$status" -eq 25 ]
  [[ "$output" == *"destroy"* ]]                         # tells the caller the replace contract
  [ ! -e "$BATS_TEST_TMPDIR/usecall" ]                   # no second live identity (no collision fan-out)
}

@test "S6: agent secret-restore SUCCEEDS when flag ON + class=service + no persisted owner VM record referencing it" {
  local M=4001 sid; sid=$(_sid 1); _reg_snap_secret "$sid" sb-d "$M"
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  export DR_VPS_ALLOW_SECRET_RESTORE=1
  run dr_vps_snapshot_use "drvps-vm-r4" --from-snap "$sid" --allow-secret-bearing --class service --owner "$M"
  [ "$status" -eq 0 ]
  grep -q -- '--class service' "$BATS_TEST_TMPDIR/usecall"   # restore lands in the service slot
  grep -q -- "--owner $M"      "$BATS_TEST_TMPDIR/usecall"
}

@test "S6: the OPERATOR direct path (no --owner) is UNCHANGED -- --allow-secret-bearing works with the flag OFF" {
  local sid; sid=$(_sid 2); _reg_snap_secret "$sid" sb-e ""
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  unset DR_VPS_ALLOW_SECRET_RESTORE
  run dr_vps_snapshot_use "drvps-vm-r5" --from-snap "$sid" --allow-secret-bearing
  [ "$status" -eq 0 ]                                    # operator trust unchanged (no S6 gate)
  [ -e "$BATS_TEST_TMPDIR/usecall" ]
}

@test "duplicate --class -- the gate validates the LAST value (what domain_create applies), never the first" {
  local M=4001 sid; sid=$(_sid 3); _reg_snap_secret "$sid" sb-f "$M"
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  export DR_VPS_ALLOW_SECRET_RESTORE=1
  # service FIRST, throwaway LAST: domain_create's last-wins parse would create a THROWAWAY -> must refuse
  run dr_vps_snapshot_use "drvps-vm-r6" --from-snap "$sid" --allow-secret-bearing \
      --class service --class throwaway --owner "$M"
  [ "$status" -eq 25 ]
  [ ! -e "$BATS_TEST_TMPDIR/usecall" ]
  # throwaway FIRST, service LAST: the applied value IS service -> admitted
  run dr_vps_snapshot_use "drvps-vm-r6" --from-snap "$sid" --allow-secret-bearing \
      --class throwaway --class service --owner "$M"
  [ "$status" -eq 0 ]
  [ -e "$BATS_TEST_TMPDIR/usecall" ]
}

@test "a FAILED 1:1 refcount query REFUSES (fail closed) -- a DB error must never count as zero references" {
  local M=4001 sid; sid=$(_sid 4); _reg_snap_secret "$sid" sb-g "$M"
  dr_vps_domain_use_snapshot() { printf '%s\n' "$*" >"$BATS_TEST_TMPDIR/usecall"; return 0; }
  export DR_VPS_ALLOW_SECRET_RESTORE=1
  eval "$(declare -f dr_vps_sql | sed '1s/^dr_vps_sql/_real_dr_vps_sql/')"
  dr_vps_sql() { case "$1" in *"COUNT(*) FROM vms"*) return 1;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_snapshot_use "drvps-vm-r7" --from-snap "$sid" --allow-secret-bearing --class service --owner "$M"
  [ "$status" -eq 1 ]                                    # E_GENERIC, NOT a pass-through to the clone
  [[ "$output" == *"fail closed"* ]]
  [ ! -e "$BATS_TEST_TMPDIR/usecall" ]
  # non-numeric garbage from the store is refused the same way
  dr_vps_sql() { case "$1" in *"COUNT(*) FROM vms"*) printf 'garbage\n'; return 0;; *) _real_dr_vps_sql "$1";; esac; }
  run dr_vps_snapshot_use "drvps-vm-r7" --from-snap "$sid" --allow-secret-bearing --class service --owner "$M"
  [ "$status" -eq 1 ]
  [ ! -e "$BATS_TEST_TMPDIR/usecall" ]
}
