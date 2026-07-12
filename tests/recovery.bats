#!/usr/bin/env bats
# Phase 2 recovery contract: a recreate that FAILS after deleting the old overlay must leave the
# store row CONSISTENT (overlay AND uuid) with the live domain, so destroy/reaper (gate-loaded, same
# as bin/dr-vps) can still clear the VM -- a broken VM must never wedge. And presence is a 3-STATE
# proof: a libvirt OUTAGE (indeterminate) must NEVER be treated as "absent" and trigger deletion.
# Gate IS loaded here (unlike domain.bats); destroy is REAL (unlike reaper.bats's stub).

load helpers

setup() {
  dr_vps_test_setup
  for m in api identity store image storage net gate domain reaper; do dr_vps_load "dr_vps_${m}.sh"; done
  dr_vps_store_init
  dr_vps_fake_nft
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"; dr_vps_net_apply
  export DR_VPS_SPOOL_DIR="$BATS_TEST_TMPDIR/spool"; mkdir -p "$DR_VPS_SPOOL_DIR"
  export DR_VPS_CONSOLE_LOG_DIR="$DR_VPS_STATE_DIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"   # else create's console_log_prepare mkdirs the unwritable default
  export FV_NETXML="$BATS_TEST_TMPDIR/net.xml" FV_DEF="$BATS_TEST_TMPDIR/def" FV_START="$BATS_TEST_TMPDIR/start.rc" FV_LIST="$BATS_TEST_TMPDIR/list.rc"
  mkdir -p "$FV_DEF"; echo 0 >"$FV_START"; echo 0 >"$FV_LIST"   # start rc 0; list rc 0 (libvirt up)
  printf "<network><name>simnet</name><bridge name='drvps0'/><dns enable='no'/><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>\n" >"$FV_NETXML"
  # Stateful fake virsh keyed on a DEF dir: define stores (injecting a uuid if the XML lacks one, like
  # libvirt); undefine removes; dominfo/list/dumpxml/domuuid read it; `list` rc is file-driven so a
  # test can simulate a libvirt OUTAGE (rc 2 path). start rc is file-driven (recreate start-failure).
  cat >"$BATS_TEST_TMPDIR/fv" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "-c" ] && shift 2
sub="$1"; shift
echo "$sub $*" >>"${FV_VLOG:-/dev/null}"
case "$sub" in
  destroy)  : ;;
  define)   xml=$(cat); name=$(printf '%s' "$xml" | sed -n 's:.*<name>\(.*\)</name>.*:\1:p')
            printf '%s' "$xml" | grep -q '<uuid>' || xml=$(printf '%s' "$xml" | sed 's:</name>:</name><uuid>'"$(cat /proc/sys/kernel/random/uuid)"'</uuid>:')
            [ -n "${FV_FORCE_UUID:-}" ] && xml=$(printf '%s' "$xml" | sed "s:<uuid>[^<]*</uuid>:<uuid>${FV_FORCE_UUID}</uuid>:")   # simulate an UNRELATED same-name domain
            printf '%s' "$xml" >"$FV_DEF/$name.xml" ;;
  undefine) rm -f "$FV_DEF/$1.xml" ;;
  dominfo)  [ -f "$FV_DEF/$1.xml" ] || exit 1 ;;
  domstate) if [ -n "${FV_DOMSTATE:-}" ] && [ -f "${FV_DOMSTATE:-}" ]; then cat "$FV_DOMSTATE"
            # faithful to real virsh: the state string is gettext-TRANSLATED under a non-C locale
            else case "${LC_ALL:-${LANG:-C}}" in C|C.*|POSIX|en*) echo "shut off" ;; *) echo "ausgeschaltet" ;; esac; fi ;;
  domuuid)  sed -n 's:.*<uuid>\(.*\)</uuid>.*:\1:p' "$FV_DEF/$1.xml" 2>/dev/null ;;
  dumpxml)  cat "$FV_DEF/$1.xml" 2>/dev/null ;;
  net-dumpxml) cat "$FV_NETXML" ;;
  list)     [ "$(cat "$FV_LIST")" = 0 ] || exit 1     # rc!=0 -> libvirt OUTAGE (indeterminate)
            for f in "$FV_DEF"/*.xml; do [ -e "$f" ] && basename "$f" .xml; done ;;
  start)    exit "$(cat "$FV_START")" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fv"; export DR_VIRSH="$BATS_TEST_TMPDIR/fv"
  export FV_VLOG="$BATS_TEST_TMPDIR/vlog"; : >"$FV_VLOG"
  # create prerequisites: a fake cloud-localds (seed), healthy doctor facts, a key, a golden.
  printf '#!/usr/bin/env bash\ncat "$2" "$3" >"$1"\n' >"$BATS_TEST_TMPDIR/fakelocalds"
  chmod +x "$BATS_TEST_TMPDIR/fakelocalds"; export DR_CLOUDLOCALDS="$BATS_TEST_TMPDIR/fakelocalds"
  export DR_VPS_TEST_SEAMS=1 DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000
  export DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true,"xmllint":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT=ok   # console subsystem healthy (seam)
  export RKEY="$BATS_TEST_TMPDIR/id.pub"; echo "ssh-ed25519 AAAAKEY test@h" >"$RKEY"
}

# register the shared golden (for create) -- idempotent.
_golden() {
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ] || dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  local aid; aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2" 2>/dev/null || true
}

# register a vm + real overlay backing a real golden, in 'broken' state, with a DEFINED domain whose
# uuid/disk/net match the row (the post-failed-recreate shape). uuid defaults to a fixed value.
_mkbroken() {  # <id> [uuid]
  local id="$1" uuid="${2:-11111111-1111-1111-1111-111111111111}" aid ov
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ] || dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2" 2>/dev/null || true
  ov="$DR_VPS_POOL_DIR/${id}.qcow2"; qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/g.qcow2" -F qcow2 "$ov" >/dev/null 2>&1
  dr_vps_store_vm_create "$id" "$aid" "$ov" "$(dr_vps_net_generation)" 1 "$id" default
  dr_vps_store_vm_set_uuid "$id" "$uuid"
  dr_vps_sql "UPDATE vms SET state='broken' WHERE id=$(dr_vps_sql_str "$id");"
  echo k >"$DR_VPS_SEED_DIR/${id}.pubkey"
  printf "<domain><name>%s</name><uuid>%s</uuid><memory unit='KiB'>1048576</memory><vcpu>2</vcpu><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$id" "$uuid" "$ov" >"$FV_DEF/${id}.xml"
}

@test "recovery: broken VM with a LIVE matching domain -> destroy clears it (gate passes)" {
  _mkbroken b1
  run dr_vps_domain_destroy b1
  [ "$status" -eq 0 ]
  [ -z "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='b1';")" ]
  [ ! -f "$DR_VPS_POOL_DIR/b1.qcow2" ]
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ]                           # golden untouched
}

@test "recovery: broken VM with NO live domain -> destroy still clears it (no-domain path)" {
  _mkbroken b2; rm -f "$FV_DEF/b2.xml"                        # absent (a failed recreate undefined it)
  run dr_vps_domain_destroy b2
  [ "$status" -eq 0 ]
  [ -z "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='b2';")" ]
  [ ! -f "$DR_VPS_POOL_DIR/b2.qcow2" ]
}

@test "recovery: a stale row whose LIVE domain MISMATCHES is still refused (no wedge bypass)" {
  _mkbroken b3 99999999-9999-9999-9999-999999999999          # live uuid != stored (set below)
  dr_vps_store_vm_set_uuid b3 11111111-1111-1111-1111-111111111111   # row says a DIFFERENT uuid
  run dr_vps_domain_destroy b3
  [ "$status" -ne 0 ]                                         # gate refuses a live mismatched domain
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='b3';")" ]   # row preserved
}

@test "recovery: libvirt OUTAGE (indeterminate) must NOT delete overlay or row" {
  _mkbroken b4; echo 1 >"$FV_LIST"                            # `list` fails -> indeterminate
  run dr_vps_domain_destroy b4
  [ "$status" -ne 0 ]                                         # fail-closed
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='b4';")" ]   # row preserved
  [ -f "$DR_VPS_POOL_DIR/b4.qcow2" ]                          # overlay preserved (could be a LIVE vm)
}

@test "recovery: recreate where define OK but START FAILS -> row uuid matches live, destroy clears" {
  export DR_VPS_TEST_SEAMS=1 DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000
  export DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true,"xmllint":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT=ok   # console subsystem healthy (seam)
  _mkbroken rr; dr_vps_sql "UPDATE vms SET state='running' WHERE id='rr';"
  echo 1 >"$FV_START"                                         # START fails
  run dr_vps_domain_recreate rr
  [ "$status" -ne 0 ]
  [ "$(dr_vps_sql "SELECT state FROM vms WHERE id='rr';")" = broken ]
  local u; u=$(dr_vps_sql "SELECT domain_uuid FROM vms WHERE id='rr';")
  [ -n "$u" ] && [ "$u" != "11111111-1111-1111-1111-111111111111" ]   # NEW pinned uuid, not the stale old one
  # the start-fail rollback tore down the row-owned domain -> destroy clears it (no wedge), whether
  # the domain is now absent (rolled back) or still present.
  echo 0 >"$FV_START"
  run dr_vps_domain_destroy rr; [ "$status" -eq 0 ]
  [ -z "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='rr';")" ]
}

@test "recovery: recreate uuid-MISMATCH rollback does NOT undefine the non-owned domain" {
  export DR_VPS_TEST_SEAMS=1 DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000
  export DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true,"xmllint":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT=ok   # console subsystem healthy (seam)
  _mkbroken rm2; dr_vps_sql "UPDATE vms SET state='running' WHERE id='rm2';"
  export FV_FORCE_UUID=77777777-7777-7777-7777-777777777777   # the redefined domain gets a FOREIGN uuid
  run dr_vps_domain_recreate rm2
  [ "$status" -ne 0 ]
  [ -f "$FV_DEF/rm2.xml" ]                                     # the mismatched (non-owned) domain was NOT undefined
  [ "$(dr_vps_sql "SELECT state FROM vms WHERE id='rm2';")" = broken ]   # row left broken
}

@test "recovery: recreate failure returns the REAL rc, not masked by the broken-state write" {
  export DR_VPS_TEST_SEAMS=1 DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000
  export DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true,"xmllint":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT=ok   # console subsystem healthy (seam)
  _mkbroken rg; dr_vps_sql "UPDATE vms SET state='running' WHERE id='rg';"
  eval 'dr_vps_doctor_golden_match() { return 18; }'         # simulate a tampered golden (verify=18)
  run dr_vps_domain_recreate rg
  [ "$status" -eq 18 ]                                        # the REAL rc, NOT 0 (set_state broken must not mask it)
  [ "$(dr_vps_sql "SELECT state FROM vms WHERE id='rg';")" = broken ]
}

@test "recovery: reaper clears an EXPIRED broken VM with no live domain (REAL destroy)" {
  _mkbroken rb; rm -f "$FV_DEF/rb.xml"                        # absent
  dr_vps_sql "UPDATE vms SET created_at=datetime('now','-3 hours') WHERE id='rb';"
  dr_vps_reaper_sweep
  [ -z "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='rb';")" ]
  grep -q 'reaped-no-domain' "$DR_VPS_SPOOL_DIR/audit.log"
}

@test "recovery: create start-fails with libvirt UP -> rolled back cleanly (row+overlay gone)" {
  _golden; echo 1 >"$FV_START"; echo 0 >"$FV_LIST"           # start fails; libvirt up (absence provable)
  run dr_vps_domain_create cw1 fedora44 --net simnet --ssh-key "$RKEY"
  [ "$status" -ne 0 ]
  local cid; cid=$(dr_vps_instance_id cw1 default)
  [ -z "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='$cid';")" ] # row gone (absent -> cleaned)
  [ ! -f "$DR_VPS_POOL_DIR/$cid.qcow2" ]
}

@test "recovery: create start-fails during a libvirt OUTAGE -> row+overlay LEFT broken (not deleted)" {
  _golden; echo 1 >"$FV_START"; echo 1 >"$FV_LIST"           # start fails AND libvirt down (indeterminate)
  run dr_vps_domain_create cw2 fedora44 --net simnet --ssh-key "$RKEY"
  [ "$status" -ne 0 ]
  local cid; cid=$(dr_vps_instance_id cw2 default)
  [ "$(dr_vps_sql "SELECT state FROM vms WHERE id='$cid';")" = broken ]   # LEFT broken (recoverable)
  [ -f "$DR_VPS_POOL_DIR/$cid.qcow2" ]                        # overlay preserved (may be a live vm)
}

@test "recovery: a crash-equivalent rowless create is impossible -- row exists in 'broken' before start" {
  # Proven indirectly by the OUTAGE test above: the row is present (broken) even though start never
  # succeeded, so there is never a live domain without a managed row for destroy to refuse.
  _golden; echo 1 >"$FV_START"; echo 1 >"$FV_LIST"
  run dr_vps_domain_create cw3 fedora44 --net simnet --ssh-key "$RKEY"
  local cid; cid=$(dr_vps_instance_id cw3 default)
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='$cid';")" ] # a managed row exists (no rowless domain)
}

@test "recovery: create rollback does NOT destroy a same-name domain it does not OWN (uuid mismatch)" {
  # Simulate a same-name libvirt domain whose uuid != the pinned/row uuid (a race). The post-define
  # uuid verify trips, rollback runs, but the gate proves the live domain is NOT row-owned -> rollback
  # must leave it DEFINED (never `undefine` by name) and the row 'broken'.
  _golden; export FV_FORCE_UUID=88888888-8888-8888-8888-888888888888
  run dr_vps_domain_create cw4 fedora44 --net simnet --ssh-key "$RKEY"
  [ "$status" -ne 0 ]
  local cid; cid=$(dr_vps_instance_id cw4 default)
  [ -f "$FV_DEF/${cid}.xml" ]                                 # the (foreign) domain was NOT undefined
  [ "$(dr_vps_sql "SELECT state FROM vms WHERE id='$cid';")" = broken ]   # row left broken, destroyed nothing
}

@test "recovery: destroy of a NO-DOMAIN VM never calls virsh destroy/undefine by name (TOCTOU-safe)" {
  _mkbroken bd; rm -f "$FV_DEF/bd.xml"; : >"$FV_VLOG"        # absent (a foreign same-name domain could race in)
  run dr_vps_domain_destroy bd
  [ "$status" -eq 0 ]
  ! grep -q 'undefine bd' "$FV_VLOG" || false                         # absent branch -> NO teardown by name
  ! grep -q 'destroy bd' "$FV_VLOG" || false
  [ -z "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='bd';")" ]  # row still cleaned (files are path-fenced)
}

@test "recovery: reaper does NOT reap during a libvirt OUTAGE (indeterminate != absent)" {
  _mkbroken ro; rm -f "$FV_DEF/ro.xml"; echo 1 >"$FV_LIST"   # would be absent, but libvirt is DOWN
  dr_vps_sql "UPDATE vms SET created_at=datetime('now','-3 hours') WHERE id='ro';"
  dr_vps_reaper_sweep
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='ro';")" ]  # row preserved (not reaped on indeterminate)
  grep -q 'reap-refused-gate' "$DR_VPS_SPOOL_DIR/audit.log"
}

@test "recovery: destroy REFUSES an overlay whose basename != <id>.qcow2 (path-fence, untested before)" {
  _mkbroken bn; rm -f "$FV_DEF/bn.xml"                       # no live domain -> gate skipped, basename fence fires
  : >"$DR_VPS_POOL_DIR/notbn.qcow2"
  dr_vps_sql "UPDATE vms SET overlay=$(dr_vps_sql_str "$DR_VPS_POOL_DIR/notbn.qcow2") WHERE id='bn';"
  run dr_vps_domain_destroy bn
  [ "$status" -ne 0 ]
  [[ "$output" == *"basename"* ]]
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='bn';")" ]  # refused BEFORE any delete -> row preserved
  [ -f "$DR_VPS_POOL_DIR/notbn.qcow2" ]                      # the wrong-basename file untouched
}

@test "recovery: destroy REFUSES a SYMLINK overlay pointing at a registered golden (golden-protection)" {
  _mkbroken bsl; rm -f "$FV_DEF/bsl.xml"                     # no live domain -> no-domain cleanup (gate skipped)
  rm -f "$DR_VPS_POOL_DIR/bsl.qcow2"; ln -s "$DR_VPS_POOL_DIR/g.qcow2" "$DR_VPS_POOL_DIR/bsl.qcow2"   # overlay -> golden
  run dr_vps_domain_destroy bsl
  [ "$status" -ne 0 ]
  [[ "$output" == *SYMLINK* || "$output" == *golden* ]]
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ]                          # the registered GOLDEN survives
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id='bsl';")" ] # row preserved (refused before delete)
}
