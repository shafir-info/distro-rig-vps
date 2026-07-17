#!/usr/bin/env bats
# Stage 5 (Phase 2) -- the TTL reaper: destroys expired VMs but GATES each first (a stale row
# must not destroy an unrelated domain); within-TTL untouched; golden never touched.

load helpers

setup() {
  dr_vps_test_setup
  for m in api identity store storage net gate domain reaper; do dr_vps_load "dr_vps_${m}.sh"; done
  dr_vps_store_init
  dr_vps_fake_nft
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"; dr_vps_net_apply
  export DR_VPS_SPOOL_DIR="$BATS_TEST_TMPDIR/spool"; mkdir -p "$DR_VPS_SPOOL_DIR"
  export FV_XML="$BATS_TEST_TMPDIR/dom.xml" FV_NETXML="$BATS_TEST_TMPDIR/net.xml"
  printf "<network><name>simnet</name><bridge name='drvps0'/><dns enable='no'/><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>\n" >"$FV_NETXML"
  cat >"$BATS_TEST_TMPDIR/fv" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *net-dumpxml*) cat "${FV_NETXML:-/dev/null}" ;;
  *list*)        cat "${FV_NAMES:-/dev/null}" 2>/dev/null ;;   # `list --all --name` (presence helper)
  *dumpxml*)     cat "${FV_XML:-/dev/null}" ;;
esac
exit 0
EOF
  export FV_NAMES="$BATS_TEST_TMPDIR/names"; : >"$FV_NAMES"
  chmod +x "$BATS_TEST_TMPDIR/fv"; export DR_VIRSH="$BATS_TEST_TMPDIR/fv"
  # isolate the reaper from domain_destroy internals (tested in domain.bats): record calls.
  eval 'dr_vps_domain_destroy() { echo "$1" >>"'"$BATS_TEST_TMPDIR"'/destroyed"; }'
  : >"$BATS_TEST_TMPDIR/destroyed"
}

# register a vm; ttl_hours + age (hours ago) decide expiry; uuid="" => no stored uuid (legacy).
_mkvm() {  # <id> <uuid> <ttl_hours> <age_hours>
  local id="$1" uuid="$2" ttl="$3" age="$4" aid ov
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ] || dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2" 2>/dev/null || true
  ov="$DR_VPS_POOL_DIR/${id}.qcow2"; qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/g.qcow2" -F qcow2 "$ov" >/dev/null 2>&1
  dr_vps_store_vm_create "$id" "$aid" "$ov" "$(dr_vps_net_generation)" "$ttl" "$id" default
  [ -n "$uuid" ] && dr_vps_store_vm_set_uuid "$id" "$uuid"
  dr_vps_sql "UPDATE vms SET created_at=datetime('now','-${age} hours') WHERE id=$(dr_vps_sql_str "$id");"
  printf "<domain><uuid>%s</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$uuid" "$ov" >"$FV_XML"
  printf '%s\n' "$id" >"$FV_NAMES"          # this domain is PRESENT (for `list --all --name`)
}

@test "reaper: an EXPIRED + valid VM is destroyed (gate passes)" {
  _mkvm rexp 11111111-1111-1111-1111-111111111111 1 3     # ttl 1h, 3h old -> expired
  dr_vps_reaper_sweep
  grep -qx rexp "$BATS_TEST_TMPDIR/destroyed"
}

@test "reaper: size-rotates the DIAG file to .1 above the cap (bounds a long DR_VPS_DIAG session)" {
  export DR_VPS_DIAG_FILE="$BATS_TEST_TMPDIR/diag/drvps-diag.log"   # set explicitly (api derived the default at source time)
  mkdir -p "$(dirname "$DR_VPS_DIAG_FILE")"
  export DR_VPS_DIAG_MAX_BYTES=100
  head -c 500 /dev/zero | tr '\0' x >"$DR_VPS_DIAG_FILE"            # 500 bytes > 100 cap
  dr_vps_reaper_sweep
  [ ! -f "$DR_VPS_DIAG_FILE" ]                                      # rotated away
  [ -f "${DR_VPS_DIAG_FILE}.1" ]                                    # -> .1
}

@test "reaper: a WITHIN-TTL VM is left untouched" {
  _mkvm rfresh 22222222-2222-2222-2222-222222222222 24 1  # ttl 24h, 1h old -> not expired
  dr_vps_reaper_sweep
  [ ! -s "$BATS_TEST_TMPDIR/destroyed" ]
}

@test "reaper: an expired STALE row (live UUID mismatch) is REFUSED, not destroyed" {
  _mkvm rstale 33333333-3333-3333-3333-333333333333 1 3
  sed -i 's/33333333-3333-3333-3333-333333333333/99999999-9999-9999-9999-999999999999/' "$FV_XML"
  dr_vps_reaper_sweep
  [ ! -s "$BATS_TEST_TMPDIR/destroyed" ]              # gate refused -> NOT destroyed
  grep -q 'reap-refused-gate' "$DR_VPS_SPOOL_DIR/audit.log"
}

@test "reaper: ttl_hours=0 (no TTL) is never reaped" {
  _mkvm rnottl 44444444-4444-4444-4444-444444444444 0 100
  dr_vps_reaper_sweep
  [ ! -s "$BATS_TEST_TMPDIR/destroyed" ]
}

@test "reaper: sweeps ORPHANED build/digest temps in TMP_DIR by age; keeps fresh ones" {
  mkdir -p "$DR_VPS_TMP_DIR"
  : >"$DR_VPS_TMP_DIR/golden.OLD.raw"; touch -d '-3 hours' "$DR_VPS_TMP_DIR/golden.OLD.raw"
  : >"$DR_VPS_TMP_DIR/bake.OLD.log";   touch -d '-3 hours' "$DR_VPS_TMP_DIR/bake.OLD.log"
  : >"$DR_VPS_TMP_DIR/golden.FRESH.raw"                       # just now -> could be an in-flight convert
  : >"$DR_VPS_TMP_DIR/keepme.txt";     touch -d '-3 hours' "$DR_VPS_TMP_DIR/keepme.txt"
  dr_vps_reaper_sweep
  [ ! -e "$DR_VPS_TMP_DIR/golden.OLD.raw" ]                   # aged orphans reaped
  [ ! -e "$DR_VPS_TMP_DIR/bake.OLD.log" ]
  [ -e "$DR_VPS_TMP_DIR/golden.FRESH.raw" ]                   # a fresh (maybe in-flight) temp is kept
  [ -e "$DR_VPS_TMP_DIR/keepme.txt" ]                         # only our own temp patterns are swept
}

@test "reaper LAUNCHER: a broken spool lock -> NONZERO exit (unit shows failed, not silent-green)" {
  # If the lock can't be taken (broken perms/owner after a partial install), the launcher
  # must FAIL LOUD -- not exit 0 while TTL enforcement is silently off. Force it: make .lock a dir.
  local sp="$BATS_TEST_TMPDIR/brokenspool"; mkdir -p "$sp/.lock"      # .lock is a DIR -> open-for-write fails
  run env DR_VPS_SPOOL_DIR="$sp" "$DR_VPS_SRC/../bin/drvps-rigreaper"
  [ "$status" -ne 0 ]
  [[ "$output" == *"SKIPPED"* ]]
}

@test "reaper: count-cap GC deletes .claimed siblings too (no 'claimed but no result' orphan)" {
  # The count cap must prune result PAIRS. Pruning <reqid>.json but leaving <reqid>.claimed would
  # both let a resubmitted reqid REPLAY its verb and let .claimed markers grow past the cap.
  local rdir="$DR_VPS_SPOOL_DIR/results"; mkdir -p "$rdir"
  export DR_VPS_RESULT_MAX_FILES=2
  for i in 1 2 3 4; do                                   # 4 pairs, c1 oldest .. c4 newest
    printf '{"reqid":"c%s"}' "$i" >"$rdir/c$i.json"
    printf '{"reqid":"c%s"}' "$i" >"$rdir/c$i.claimed"
    touch -d "-$((10 - i)) seconds" "$rdir/c$i.json"     # recent (within TTL) + staggered for count-GC order
  done
  dr_vps_reaper_sweep
  for i in 1 2; do [ ! -e "$rdir/c$i.json" ]; [ ! -e "$rdir/c$i.claimed" ]; done   # 2 oldest pairs fully gone
  for i in 3 4; do [ -f "$rdir/c$i.json" ]; [ -f "$rdir/c$i.claimed" ]; done       # 2 newest pairs intact
  # invariant: NO orphan .claimed (every surviving .claimed has its .json)
  for f in "$rdir"/*.claimed; do [ -e "$f" ] || continue; [ -f "${f%.claimed}.json" ]; done
}

# --- Stage-1 console-log bound: tail-compaction (no-follow fd; keep the TAIL/newest; refuse tamper) ---
_CC() { python3 "$DR_VPS_SRC/drvps_common.py" console-compact "$@"; }

@test "console-compact: over-cap regular file -> keeps the TAIL, SAME inode, size<=cap" {
  f="$BATS_TEST_TMPDIR/c.log"
  { printf 'A%.0s' {1..100}; printf 'B%.0s' {1..100}; printf 'C%.0s' {1..100}; } >"$f"   # 300 B: A|B|C
  ino1=$(stat -c %i "$f")
  run _CC "$f" 150; [ "$status" -eq 0 ]                      # cap 150 -> keep last 150 = 50 B + 100 C
  [ "$(stat -c %s "$f")" -le 150 ]
  [ "$(stat -c %i "$f")" = "$ino1" ]                         # in-place: inode preserved
  [ "$(tail -c 1 "$f")" = C ]                                # ends with the newest byte
  [ "$(tr -dc A <"$f" | wc -c)" -eq 0 ]                      # the HEAD (A's) is gone, not kept
  [ "$(tr -dc B <"$f" | wc -c)" -le 50 ]                     # only the tail B's survive
}

@test "console-compact: under-cap file -> no-op (content intact)" {
  f="$BATS_TEST_TMPDIR/s.log"; printf 'hello' >"$f"
  run _CC "$f" 1000; [ "$status" -eq 0 ]; [ "$(cat "$f")" = hello ]
}

@test "console-compact: a SYMLINK is REFUSED (O_NOFOLLOW); target untouched" {
  t="$BATS_TEST_TMPDIR/real"; printf 'x%.0s' {1..500} >"$t"
  ln -s "$t" "$BATS_TEST_TMPDIR/link"
  run _CC "$BATS_TEST_TMPDIR/link" 100; [ "$status" -ne 0 ]
  [ "$(stat -c %s "$t")" -eq 500 ]
}

@test "console-compact: a HARD-LINKED file is REFUSED (nlink>1)" {
  f="$BATS_TEST_TMPDIR/h.log"; printf 'y%.0s' {1..500} >"$f"; ln "$f" "$BATS_TEST_TMPDIR/h2"
  run _CC "$f" 100; [ "$status" -ne 0 ]
  [ "$(stat -c %s "$f")" -eq 500 ]
}

@test "console-compact: a GROUP/OTHER-writable file is REFUSED (tamper-injectable)" {
  f="$BATS_TEST_TMPDIR/gw.log"; printf 'z%.0s' {1..500} >"$f"; chmod 0666 "$f"
  run _CC "$f" 100; [ "$status" -ne 0 ]
  [ "$(stat -c %s "$f")" -eq 500 ]
}

_ccvm() {  # <id> -- register a golden + a vm row so the console reap sees it
  local aid="drvps-raw-v1-2097152-$(printf 'a%.0s' {1..64})"
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "/pool/g.qcow2" 2>/dev/null || true
  dr_vps_store_vm_create "$1" "$aid" "/pool/$1.qcow2" 1 24
}

@test "reaper sweep (Stage-1): compacts each VM's over-cap console log + writes the full-sweep heartbeat" {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  export DR_VPS_CONSOLE_FILE_CAP=1000
  _ccvm vmlog
  f=$(dr_vps_console_log_path vmlog); printf 'Z%.0s' {1..5000} >"$f"    # 5000 B, over the 1000 cap
  rm -f "$DR_VPS_STATE_DIR/console-reaper.last"
  dr_vps_reaper_sweep
  [ "$(stat -c %s "$f")" -le 1000 ]                                     # log compacted in place
  [ "$(tail -c 1 "$f")" = Z ]                                           # kept the tail
  [ -f "$DR_VPS_STATE_DIR/console-reaper.last" ]                        # full clean sweep -> heartbeat refreshed
}

@test "reaper sweep (Stage-1): a tampered (symlink) console log -> compaction REFUSED -> NO heartbeat refresh" {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  export DR_VPS_CONSOLE_FILE_CAP=1000
  _ccvm vmsl
  printf 'x%.0s' {1..5000} >"$BATS_TEST_TMPDIR/real"
  ln -s "$BATS_TEST_TMPDIR/real" "$(dr_vps_console_log_path vmsl)"      # tamper: symlink where the log should be
  rm -f "$DR_VPS_STATE_DIR/console-reaper.last"
  dr_vps_reaper_sweep
  [ ! -f "$DR_VPS_STATE_DIR/console-reaper.last" ]                      # refusal -> heartbeat NOT refreshed
  [ "$(stat -c %s "$BATS_TEST_TMPDIR/real")" -eq 5000 ]                 # symlink target untouched
}

@test "reaper sweep (Stage-1): a DANGLING-symlink console log is TAMPER (not 'missing') -> NO heartbeat" {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  export DR_VPS_CONSOLE_FILE_CAP=1000
  _ccvm vmdang
  ln -s "$BATS_TEST_TMPDIR/no-such-target" "$(dr_vps_console_log_path vmdang)"   # dangling symlink
  rm -f "$DR_VPS_STATE_DIR/console-reaper.last"
  dr_vps_reaper_sweep
  [ ! -f "$DR_VPS_STATE_DIR/console-reaper.last" ]                      # -L caught before -e -> dirty -> no heartbeat
}

@test "reaper sweep (Stage-1): a DIRTY sweep INVALIDATES a pre-existing fresh heartbeat (no false-fresh)" {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  export DR_VPS_CONSOLE_FILE_CAP=1000
  _ccvm vmdirty
  printf 'x' >"$BATS_TEST_TMPDIR/real"
  ln -s "$BATS_TEST_TMPDIR/real" "$(dr_vps_console_log_path vmdirty)"   # tamper -> this sweep is dirty
  printf 'PREVIOUS-FRESH\n' >"$DR_VPS_STATE_DIR/console-reaper.last"    # a still-fresh stamp from a prior clean sweep
  dr_vps_reaper_sweep
  [ ! -f "$DR_VPS_STATE_DIR/console-reaper.last" ]                      # dirty sweep REMOVED the stale-fresh stamp
}

@test "reaper (S1b): a service-class VM past TTL is NOT reaped; a throwaway VM IS" {
  _mkvm tw  22222222-2222-2222-2222-222222222222 1 3     # throwaway, expired (1h ttl, 3h old)
  _mkvm svc 33333333-3333-3333-3333-333333333333 1 3     # expired; marked service below
  dr_vps_sql "UPDATE vms SET class='service' WHERE id='svc';"
  dr_vps_reaper_sweep
  grep -qx tw "$BATS_TEST_TMPDIR/destroyed"               # throwaway WAS reaped
  ! grep -qx svc "$BATS_TEST_TMPDIR/destroyed" || false            # service is EXEMPT ...
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='svc';"; [ "$output" = "1" ]   # ... and still exists
}

# ---- S4 idempotency-key journal GC (spool/idem/<owner>/<key>.json; drvps-private) ---------------

@test "reaper: S4 -- idem journal GC: TTL-expired entries deleted, fresh kept, emptied owner dirs pruned" {
  local idir="$DR_VPS_SPOOL_DIR/idem"; mkdir -p "$idir/4001" "$idir/4002"
  printf '{"state":"done"}' >"$idir/4001/old.json"; touch -d '-2 days' "$idir/4001/old.json"
  printf 'tmp' >"$idir/4001/.k9.a1b2c3"; touch -d '-2 days' "$idir/4001/.k9.a1b2c3"   # leaked mkstemp temp
  printf '{"state":"done"}' >"$idir/4002/new.json"
  dr_vps_reaper_sweep
  [ ! -e "$idir/4001/old.json" ]
  [ ! -e "$idir/4001/.k9.a1b2c3" ]                       # aged hidden temp swept too
  [ ! -d "$idir/4001" ]                                  # emptied owner dir pruned (no inode residue)
  [ -f "$idir/4002/new.json" ]                           # fresh entry survives
}

@test "reaper: NO global idem count-cap: many recent entries across owners are all KEPT (no cross-owner eviction)" {
  # The rig-wide count-cap was removed (it cross-evicted owners + could not converge).
  # Growth is bounded by the per-owner WRITE quota (watcher-side) + TTL. A count-cap env has NO effect.
  local idir="$DR_VPS_SPOOL_DIR/idem"; mkdir -p "$idir/4001" "$idir/4002"
  export DR_VPS_IDEM_MAX_FILES=1                       # must be IGNORED now
  for i in 1 2 3; do printf '{"state":"done"}' >"$idir/4001/a$i.json"; done   # all recent (within TTL)
  printf '{"state":"in-progress"}' >"$idir/4002/b1.json"
  dr_vps_reaper_sweep
  for i in 1 2 3; do [ -f "$idir/4001/a$i.json" ]; done   # NONE count-evicted (owner A intact)
  [ -f "$idir/4002/b1.json" ]                             # owner B's in-progress intact (no cross-owner evict)
}

@test "reaper: knob guard -- malformed GC/age knobs fall back to defaults LOUDLY, valid values pass through" {
  # find silently no-ops on a malformed -mmin argument (rc eaten by '|| true'), and the snap-bundle
  # age-gate's empty-means-old polarity would INVERT into reaping in-flight bundles -- so the knobs
  # are validated once, with an audit line on fallback.
  run _dr_vps_reap_knob DR_VPS_RESULT_TTL_MIN 1440
  [ "$status" -eq 0 ]; [ "$output" = 1440 ]                                # unset -> default
  DR_VPS_RESULT_TTL_MIN=90 run _dr_vps_reap_knob DR_VPS_RESULT_TTL_MIN 1440
  [ "$output" = 90 ]                                                      # valid passes through
  DR_VPS_RESULT_TTL_MIN=1d run _dr_vps_reap_knob DR_VPS_RESULT_TTL_MIN 1440
  [ "$output" = 1440 ]                                                    # malformed -> default ...
  grep -q '"reaper":"reap-bad-knob","id":"DR_VPS_RESULT_TTL_MIN"' "$DR_VPS_SPOOL_DIR/audit.log"  # ... loudly
  # and the sweep still GCs with the fallback: an old result survives a malformed knob's no-op no more
  mkdir -p "$DR_VPS_SPOOL_DIR/results"
  printf '{}' >"$DR_VPS_SPOOL_DIR/results/old1.json"
  touch -d '3 days ago' "$DR_VPS_SPOOL_DIR/results/old1.json"
  DR_VPS_RESULT_TTL_MIN=1d dr_vps_reaper_sweep
  [ ! -f "$DR_VPS_SPOOL_DIR/results/old1.json" ]                          # swept via the 1440 fallback
}
