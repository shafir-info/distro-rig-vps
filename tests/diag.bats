#!/usr/bin/env bats
# DR_VPS_DIAG: flag-gated, metadata-only diagnostic trace. Default OFF -> no-op. See SPEC-DIAG.md.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  export DR_VPS_SPOOL_DIR="$BATS_TEST_TMPDIR/spool"; mkdir -p "$DR_VPS_SPOOL_DIR"
  export DR_VPS_DIAG_FILE="$DR_VPS_SPOOL_DIR/diag/drvps-diag.log"
  unset DR_VPS_DIAG
}

@test "diag OFF (default): no-op, nothing created, op unaffected" {
  run dr_vps_diag "should NOT appear anywhere"
  [ "$status" -eq 0 ]
  [ ! -e "$DR_VPS_DIAG_FILE" ]
  [ ! -d "$(dirname "$DR_VPS_DIAG_FILE")" ]
}

@test "diag ON: loud stderr banner + metadata line + file header, file mode 0640" {
  export DR_VPS_DIAG=1
  run dr_vps_diag "admission: id=x existing=3 effective=4 max=64 OK"
  [ "$status" -eq 0 ]
  [[ "$output" == *"DIAG logging ENABLED"* ]]              # banner on stderr (run merges into output)
  [ -f "$DR_VPS_DIAG_FILE" ]
  grep -q "admission: id=x existing=3 effective=4 max=64 OK" "$DR_VPS_DIAG_FILE"
  grep -q "drvps-diag ENABLED" "$DR_VPS_DIAG_FILE"          # file header
  [ "$(stat -c '%a' "$DR_VPS_DIAG_FILE")" = 640 ]           # group-readable despite umask 0077
}

@test "diag ON: refuses a SYMLINK at the diag path (never writes through it), op still succeeds" {
  export DR_VPS_DIAG=1
  mkdir -p "$(dirname "$DR_VPS_DIAG_FILE")"
  local victim="$BATS_TEST_TMPDIR/victim"; : >"$victim"
  ln -s "$victim" "$DR_VPS_DIAG_FILE"
  run dr_vps_diag "must-not-write-through-the-symlink"
  [ "$status" -eq 0 ]                                       # a diag write NEVER fails the op
  ! grep -q "must-not-write-through" "$victim" || false              # the symlink target was NOT appended to
}

@test "diag: a failing sink (unwritable dir) never fails the caller" {
  export DR_VPS_DIAG=1
  export DR_VPS_DIAG_FILE="/proc/nonexistent/cannot/create/drvps-diag.log"
  run dr_vps_diag "x"
  [ "$status" -eq 0 ]
}
