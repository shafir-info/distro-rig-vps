#!/usr/bin/env bats
# Stage 2 (Phase 2) -- guest-only verbs: gate-first, safe argv (`--` before destination, key,
# IdentitiesOnly), libvirt-resolved IP, bounded pull. ssh/scp/virsh seamed (print their argv).

load helpers

setup() {
  dr_vps_test_setup
  for m in api identity store storage net gate remote; do dr_vps_load "dr_vps_${m}.sh"; done
  dr_vps_store_init
  dr_vps_fake_nft
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"
  dr_vps_net_apply
  export DR_VPS_SSH_KEY="$BATS_TEST_TMPDIR/key"; echo k >"$DR_VPS_SSH_KEY"
  export FV_XML="$BATS_TEST_TMPDIR/dom.xml" FV_NETXML="$BATS_TEST_TMPDIR/net.xml"
  printf "<network><name>simnet</name><bridge name='drvps0'/><dns enable='no'/><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>\n" >"$FV_NETXML"
  cat >"$BATS_TEST_TMPDIR/fv" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *net-dumpxml*) cat "${FV_NETXML:-/dev/null}" ;;
  *domifaddr*)   echo " vnet0  52:54:00:aa:bb:cc  ipv4  10.123.0.55/24" ;;
  *console*)     printf 'CONSOLE-%0.s' {1..3}; exit "${FV_CONSOLE_RC:-0}" ;;   # small output + injectable rc
  *dumpxml*)     cat "${FV_XML:-/dev/null}" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fv"; export DR_VIRSH="$BATS_TEST_TMPDIR/fv"
  printf '#!/usr/bin/env bash\nprintf "SSH %%s\\n" "$*"\nexit 0\n' >"$BATS_TEST_TMPDIR/fssh"
  printf '#!/usr/bin/env bash\nprintf "SCP %%s\\n" "$*"\nexit 0\n' >"$BATS_TEST_TMPDIR/fscp"
  chmod +x "$BATS_TEST_TMPDIR/fssh" "$BATS_TEST_TMPDIR/fscp"
  export DR_SSH="$BATS_TEST_TMPDIR/fssh" DR_SCP="$BATS_TEST_TMPDIR/fscp"
}

_mkvm() {  # <id> <uuid>
  local id="$1" uuid="$2" aid ov
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ] || dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2" 2>/dev/null || true
  ov="$DR_VPS_POOL_DIR/${id}.qcow2"
  qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/g.qcow2" -F qcow2 "$ov" >/dev/null 2>&1
  dr_vps_store_vm_create "$id" "$aid" "$ov" "$(dr_vps_net_generation)" 24 "$id" default
  [ -n "$uuid" ] && dr_vps_store_vm_set_uuid "$id" "$uuid"
  printf "<domain><uuid>%s</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$uuid" "$ov" >"$FV_XML"
}

@test "exec: GATES FIRST -- unknown id is refused (14), never reaches ssh" {
  run dr_vps_exec nope 'whoami'; [ "$status" -eq 14 ]
  [[ "$output" != SSH* ]]
}

@test "exec: safe argv -- '--' before root@<libvirt-ip>, key, IdentitiesOnly, the guest cmd" {
  _mkvm vm1 11111111-1111-1111-1111-111111111111
  run dr_vps_exec vm1 'id -u'; [ "$status" -eq 0 ]
  [[ "$output" == *"-- root@10.123.0.55 export http_proxy="* ]]   # proxy exported before the cmd (M13)
  [[ "$output" == *"id -u"* ]]
  [[ "$output" == *"IdentitiesOnly=yes"* ]]
  [[ "$output" == *"-i $DR_VPS_SSH_KEY"* ]]
}

@test "pull: bounds DURING transfer -- head -c CAP+1 runs IN THE GUEST" {
  _mkvm vm2 22222222-2222-2222-2222-222222222222
  run dr_vps_pull vm2 /etc/hostname 100; [ "$status" -eq 0 ]
  [[ "$output" == *"head -c 101 --"* ]]
  [[ "$output" == *"/etc/hostname"* ]]
}

@test "pull: guest path uses POSIX single-quoting, NOT bash \$'...' (parses on dash/busybox guests)" {
  _mkvm vm2b 2b2b2b2b-2222-2222-2222-222222222222
  run dr_vps_pull vm2b "$(printf '/tmp/a\nb')" 100; [ "$status" -eq 0 ]
  [[ "$output" != *'$'\'''* ]]                 # no bash ANSI-C $'...' quoting (non-bash guests choke)
  [[ "$output" == *"'/tmp/a"* ]]              # single-quoted form (newline preserved literally inside)
}

@test "push: scp the local temp into the guest with safe argv" {
  _mkvm vm3 33333333-3333-3333-3333-333333333333
  echo payload >"$BATS_TEST_TMPDIR/up"
  run dr_vps_push vm3 "$BATS_TEST_TMPDIR/up" /tmp/x; [ "$status" -eq 0 ]
  [[ "$output" == *"SCP"* ]]
  [[ "$output" == *"-- $BATS_TEST_TMPDIR/up root@10.123.0.55:/tmp/x"* ]]
}

@test "push: a missing local temp is refused (14)" {
  _mkvm vm4 44444444-4444-4444-4444-444444444444
  run dr_vps_push vm4 "$BATS_TEST_TMPDIR/nope" /tmp/x; [ "$status" -eq 14 ]
}

@test "console-dump: reads the PERSISTENT console-log tail, byte-bounded (GUESTEXEC-gated)" {
  _mkvm vm5 55555555-5555-5555-5555-555555555555
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  printf 'BOOTLINE1\nBOOTLINE2\nBOOTLINE3\n' >"$DR_VPS_CONSOLE_LOG_DIR/vm5.log"
  run dr_vps_console_dump vm5 20; [ "$status" -eq 0 ]
  [ "${#output}" -le 20 ]                      # bounded to the byte cap
  [[ "$output" == *"BOOTLINE3"* ]]             # tail reads the END of the persisted log
}

@test "console-dump: NO persistent log (pre-observability VM) -> explicit 'recreate to enable' error, not empty-ok" {
  _mkvm vm5c 5c5c5c5c-5555-5555-5555-555555555555
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  run dr_vps_console_dump vm5c 20; [ "$status" -eq 14 ]   # E_NOTFOUND, not a silent empty success
  [[ "$output" == *"recreate to enable"* ]]
}

@test "console-dump: DIAG logs the log SIZE, NEVER the console content (no-leak)" {
  _mkvm vm5e 5e5e5e5e-5555-5555-5555-555555555555
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  printf 'TOPSECRET-boot-token-DO-NOT-LEAK\n' >"$DR_VPS_CONSOLE_LOG_DIR/vm5e.log"
  export DR_VPS_DIAG=1 DR_VPS_DIAG_FILE="$BATS_TEST_TMPDIR/diag/drvps-diag.log"   # set explicitly (api.sh derived the default at source time)
  run dr_vps_console_dump vm5e 100; [ "$status" -eq 0 ]
  [[ "$output" == *"TOPSECRET"* ]]                          # the DUMP itself returns the content (its job)
  diag="$DR_VPS_DIAG_FILE"
  [ -f "$diag" ]
  grep -q "console-dump: id=vm5e log_size=" "$diag"        # metadata (size) IS logged
  ! grep -q "TOPSECRET" "$diag" || false                             # NO-LEAK: content is NEVER in the diag
}

@test "console-dump: a '+N' / leading-zero / non-numeric byte cap is REFUSED (bounded-tail contract, direct CLI)" {
  _mkvm vm5d 5d5d5d5d-5555-5555-5555-555555555555
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  printf 'x\n' >"$DR_VPS_CONSOLE_LOG_DIR/vm5d.log"
  run dr_vps_console_dump vm5d '+1';  [ "$status" -eq 2 ]   # tail -c +1 = WHOLE file -> E_USAGE (refused first)
  run dr_vps_console_dump vm5d '010'; [ "$status" -eq 2 ]   # leading-zero octal
  run dr_vps_console_dump vm5d 'abc'; [ "$status" -eq 2 ]   # non-numeric
}

@test "console-dump: a tampered domain that fails guestexec (extra NIC) is REFUSED before the log is read" {
  _mkvm vm5b 5b5b5b5b-5555-5555-5555-555555555555
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  printf 'SECRET-BOOT-OUTPUT\n' >"$DR_VPS_CONSOLE_LOG_DIR/vm5b.log"
  sed -i "s:</devices>:<interface type='network'><source network='default'/></interface></devices>:" "$FV_XML"
  run dr_vps_console_dump vm5b 20; [ "$status" -ne 0 ]    # closed-shape proof refuses the guest->host channel
  [[ "$output" != *SECRET* ]]                              # gate refuses BEFORE the tail -> nothing leaked
}

@test "exec: a STALE egress generation is refused (24) before ssh" {
  _mkvm vm6 66666666-6666-6666-6666-666666666666
  jq '.block_cidrs += ["10.250.0.0/24"]' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/f2" && mv "$BATS_TEST_TMPDIR/f2" "$DR_VPS_FLEET_JSON"
  run dr_vps_exec vm6 'whoami'; [ "$status" -eq 24 ]
  [[ "$output" != SSH* ]]
}

@test "S1a: guest verbs (exec/pull/push/console-dump) refuse a FOREIGN --owner (E_NOTFOUND) before any gate/SSH" {
  dr_vps_store_init
  dr_vps_sql "INSERT INTO vms(id,artifact_id,owner_uid,class,state) VALUES ('rvm','a1','1001','throwaway','running');"
  run dr_vps_exec         rvm 'id' --owner 2002;            [ "$status" -eq 14 ]   # foreign -> not-found
  run dr_vps_pull         rvm '/etc/hostname' --owner 2002; [ "$status" -eq 14 ]
  run dr_vps_push         rvm /nonexistent /r --owner 2002; [ "$status" -eq 14 ]
  run dr_vps_console_dump rvm 100 --owner 2002;             [ "$status" -eq 14 ]
  run dr_vps_exec         ghost 'id' --owner 1001;          [ "$status" -eq 14 ]   # nonexistent vm -> not-found
  # (surplus-positional rejection is a DISPATCH concern -- need_eq_owner in bin/dr-vps -- covered by cli.bats)
}
