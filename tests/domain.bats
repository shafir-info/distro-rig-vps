#!/usr/bin/env bats
# Stage 6 -- domain lifecycle: templated-XML-only, autostart-off, recreate-pins-golden,
# verify-baseline, create/destroy roundtrip. virsh/ssh/cloud-localds seamed (no KVM).

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  for m in identity store image storage net doctor domain; do dr_vps_load "dr_vps_$m.sh"; done
  dr_vps_store_init
  # --- seams ---
  export DR_SSH=true
  dr_vps_fake_nft                          # live nft replay so create_guard passes
  export FAKEVIRSH_LOG="$BATS_TEST_TMPDIR/virsh.log"; : >"$FAKEVIRSH_LOG"
  export FAKEVIRSH_XML="$BATS_TEST_TMPDIR/domain.xml"
  export FAKEVIRSH_DEFINED="$BATS_TEST_TMPDIR/defined"; mkdir -p "$FAKEVIRSH_DEFINED"
  cat >"$BATS_TEST_TMPDIR/fakevirsh" <<'EOF'
#!/usr/bin/env bash
# stateful fake virsh: define/undefine track domains so dominfo reflects defined-state.
LOG="${FAKEVIRSH_LOG:-/dev/null}"; XMLOUT="${FAKEVIRSH_XML:-/dev/null}"; DEF="${FAKEVIRSH_DEFINED:-/tmp}"
[ "$1" = "-c" ] && shift 2
sub="$1"; shift
echo "$sub $*" >>"$LOG"
case "$sub" in
  define)   xml=$(cat); [ -n "${FAKEVIRSH_SMUGGLE:-}" ] && xml="${xml/<\/devices>/${FAKEVIRSH_SMUGGLE}<\/devices>}"; printf '%s' "$xml" >"$XMLOUT"
            name=$(printf '%s' "$xml" | sed -n 's:.*<name>\(.*\)</name>.*:\1:p'); [ -n "$name" ] && printf '%s' "$xml" >"$DEF/$name.xml" ;;
  undefine) rm -f "$DEF/$1.xml" ;;
  dominfo)  [ -f "$DEF/$1.xml" ] || exit 1 ;;
  domstate) if [ -n "${FAKEVIRSH_DOMSTATE:-}" ] && [ -f "${FAKEVIRSH_DOMSTATE:-}" ]; then cat "$FAKEVIRSH_DOMSTATE"
            # faithful to real virsh: the state string is gettext-TRANSLATED under a non-C locale
            else case "${LC_ALL:-${LANG:-C}}" in C|C.*|POSIX|en*) echo "shut off" ;; *) echo "ausgeschaltet" ;; esac; fi ;;
  domuuid)  sed -n 's:.*<uuid>\(.*\)</uuid>.*:\1:p' "$DEF/$1.xml" 2>/dev/null ;;
  list)     for f in "$DEF"/*.xml; do [ -e "$f" ] && basename "$f" .xml; done ;;   # `list --all --name`
  net-dumpxml) printf "<network><name>%s</name><bridge name='drvps0'/><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>\n" "$1" ;;  # isolated+dhcp (no forward)
  dumpxml)  [ "$1" = "--inactive" ] && shift; cat "$DEF/$1.xml" 2>/dev/null ;;   # skip the --inactive flag (closedshape)
  domifaddr) echo " vnet0 52:54:00:11:22:33 ipv4 10.123.0.5/24" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fakevirsh"; export DR_VIRSH="$BATS_TEST_TMPDIR/fakevirsh"
  cat >"$BATS_TEST_TMPDIR/fakelocalds" <<'EOF'
#!/usr/bin/env bash
cat "$2" "$3" >"$1"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fakelocalds"; export DR_CLOUDLOCALDS="$BATS_TEST_TMPDIR/fakelocalds"
  # healthy doctor facts (seam-gated)
  export DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000
  export DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT=ok   # console subsystem healthy (seam)
  export DR_VPS_CONSOLE_LOG_DIR="$DR_VPS_STATE_DIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"; export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"
  dr_vps_net_apply
  # a registered, matching golden for distro fedora44
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  AID=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  GOLDEN="$DR_VPS_POOL_DIR/g.qcow2"
  dr_vps_store_image_register "$AID" '{"distro":"fedora44"}' "$GOLDEN"
  KEY="$BATS_TEST_TMPDIR/id.pub"; echo "ssh-ed25519 AAAAKEY test@h" >"$KEY"
}

@test "render_xml is TEMPLATED-ONLY: overlay+seed+net+serial; NO hostdev/9p/graphics" {
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2
  [ "$status" -eq 0 ]
  [[ "$output" == *"<source file='/pool/vm1.qcow2'/>"* ]]
  [[ "$output" == *"<source file='/seed/vm1.iso'/>"* ]]
  [[ "$output" == *"<source network='simnet'/>"* ]]
  [[ "$output" == *"<console"* ]]
  [[ "$output" != *hostdev* ]]
  [[ "$output" != *filesystem* ]]
  [[ "$output" != *graphics* ]]
  [[ "$output" != *vnc* ]]
  [[ "$output" != *spice* ]]
}

@test "render_xml: exactly one canonical console <log> inside the serial pty (observability Step 6)" {
  export DR_VPS_CONSOLE_LOG_DIR=/var/log/distro-rig-vps/console
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2
  [ "$status" -eq 0 ]
  [ "$(printf '%s\n' "$output" | grep -c '<log ')" -eq 1 ]     # exactly ONE <log> in the whole domain
  [[ "$output" == *"<serial type='pty'><target type='isa-serial' port='0'/><log file='/var/log/distro-rig-vps/console/vm1.log' append='on'/></serial>"* ]]
}

@test "render_xml: the console log path is XML-ESCAPED (no template break via CONSOLE_LOG_DIR)" {
  export DR_VPS_CONSOLE_LOG_DIR="/var/log/a&b<x>"
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2
  [ "$status" -eq 0 ]
  [[ "$output" == *"a&amp;b&lt;x&gt;/vm1.log"* ]]
  [[ "$output" != *"a&b<x>/vm1.log"* ]]
}

@test "render_xml: a PINNED uuid is emitted INSIDE the template (H-2, no post-hoc sed); a bad uuid is refused" {
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2 11111111-2222-3333-4444-555555555555
  [ "$status" -eq 0 ]
  [[ "$output" == *"<uuid>11111111-2222-3333-4444-555555555555</uuid>"* ]]
  # the uuid sits between </name> and <memory> (template position, not appended)
  [[ "$output" == *"</name>"*"<uuid>"*"<memory"* ]]
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2 "not-a-uuid"
  [ "$status" -eq 2 ]
  # omitting the uuid arg is still valid (create passes it; other callers may not)
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2
  [ "$status" -eq 0 ]; [[ "$output" != *"<uuid>"* ]]
}

@test "render_xml: emits <cpu mode='host-model'> (host x86-64-v2/v3 -> el9-family boots; gate-allowed)" {
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2
  [ "$status" -eq 0 ]; [[ "$output" == *"<cpu mode='host-model'/>"* ]]
}

@test "render_xml: a host-passthrough cpu_mode ARG is REFUSED (defense-in-depth; gate-incompatible)" {
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2 "" host-passthrough
  [ "$status" -ne 0 ]; [[ "$output" == *"host-passthrough is gate-refused"* ]]
}

@test "resolve_vm_contract (Stage-0 seam): reads DR_VPS_CPU_MODE -> canonical cpu_mode; host-passthrough fails closed" {
  run resolve_vm_contract vm1 "" ""
  [ "$status" -eq 0 ]; [ "$output" = "cpu_mode=host-model" ]                     # env-default
  DR_VPS_CPU_MODE=host-passthrough run resolve_vm_contract vm1 "" ""
  [ "$status" -ne 0 ]; [[ "$output" == *"host-passthrough is gate-refused"* ]]  # unsatisfiable -> fail closed
}

@test "resolver seam ENV-POISON: render uses the RESOLVED cpu_mode, not the env (render reads no env)" {
  local contract cpu
  contract=$(resolve_vm_contract vm1 "" "")                                      # -> cpu_mode=host-model
  cpu=$(printf '%s\n' "$contract" | sed -n 's/^cpu_mode=//p'); [ "$cpu" = host-model ]
  export DR_VPS_CPU_MODE=host-passthrough                                        # POISON the env after resolve
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2 "" "$cpu"
  [ "$status" -eq 0 ]
  [[ "$output" == *"<cpu mode='host-model'/>"* ]]                                # resolved value used
  [[ "$output" != *"host-passthrough"* ]]                                        # env ignored
}

@test "create: seamed orchestration -> running vm + overlay + seed; define/start/autostart-off" {
  run dr_vps_domain_create web1 fedora44 --net simnet --ssh-key "$KEY" --seq 1
  [ "$status" -eq 0 ]; id="$output"
  run dr_vps_store_vm_get "$id"; [[ "$output" == running\|* ]]
  [ -f "$DR_VPS_POOL_DIR/$id.qcow2" ]
  [ -f "$DR_VPS_SEED_DIR/$id-seed.iso" ]
  grep -q "define" "$FAKEVIRSH_LOG"
  grep -q "start $id" "$FAKEVIRSH_LOG"
  grep -q "source network='simnet'" "$FAKEVIRSH_XML"
}

@test "create (Stage-0.B): persists the resolved contract in the row (stored == consumed)" {
  run dr_vps_domain_create webc fedora44 --net simnet --ssh-key "$KEY" --seq 1
  [ "$status" -eq 0 ]; id="$output"
  run dr_vps_store_vm_get_contract "$id"
  [ "$status" -eq 0 ]; [ "$output" = "cpu_mode=host-model" ]     # persisted == what render consumed
}

@test "create (Stage-0.C enforce): a closedshape-refused domain NEVER starts + rolls back (pre-start call order)" {
  dr_vps_load dr_vps_gate.sh
  export DR_VPS_PRESTART_GATE=enforce                  # gate ON for this test
  export FAKEVIRSH_SMUGGLE="<hostdev mode='subsystem' type='pci'/>"   # define stores this -> closedshape refuses
  run dr_vps_domain_create webCO fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]                                  # create fails closed
  grep -q "define" "$FAKEVIRSH_LOG"                    # it DID define (the gate runs post-define)
  ! grep -q "^start " "$FAKEVIRSH_LOG" || false                 # ...but NEVER reached start
  run dr_vps_store_vm_ls; [[ "$output" != *webCO* ]]   # rolled back: no webCO row anywhere (id-agnostic)
}

@test "create (Stage-0.C default OFF): pre-start gate NOT enforced -- install-safe (create unchanged)" {
  dr_vps_load dr_vps_gate.sh
  # DR_VPS_PRESTART_GATE defaults 'off' -> closedshape skipped -> create proceeds even past a smuggle
  export FAKEVIRSH_SMUGGLE="<hostdev mode='subsystem' type='pci'/>"
  run dr_vps_domain_create webOFF fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -eq 0 ]                                  # create SUCCEEDS (gate off = old behavior)
  grep -q "^start " "$FAKEVIRSH_LOG"                   # it DID start
}

@test "create (Stage-0.C enforce, gate fn UNAVAILABLE): FAILS CLOSED -- never starts unverified" {
  unset -f dr_vps_gate_vm                              # domain.sh normally sources it; simulate it unavailable
  export DR_VPS_PRESTART_GATE=enforce
  run dr_vps_domain_create webNG fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]                                  # unverifiable != bypass -> fail closed
  ! grep -q "^start " "$FAKEVIRSH_LOG" || false                 # never started unverified
}

@test "AUTOSTART-OFF control: create disables autostart, never enables it" {
  dr_vps_domain_create web2 fedora44 --net simnet --ssh-key "$KEY" >/dev/null
  grep -q 'autostart --disable' "$FAKEVIRSH_LOG"
  ! grep -Eq '^autostart [^-]' "$FAKEVIRSH_LOG" || false     # no bare 'autostart <id>' (enable)
}

@test "create: an unsafe (default-NAT) net is refused before boot (24)" {
  run dr_vps_domain_create web3 fedora44 --net default --ssh-key "$KEY"
  [ "$status" -eq 24 ]
  run dr_vps_store_vm_get "$(dr_vps_instance_id web3 default)"; [ -z "$output" ]   # nothing created
}

@test "RECREATE-PINS-GOLDEN control: new overlay backs the pinned golden; generation bumps" {
  id=$(dr_vps_domain_create web4 fedora44 --net simnet --ssh-key "$KEY")
  g0=$(dr_vps_store_vm_get "$id" | cut -d'|' -f2)
  dr_vps_domain_recreate "$id" >/dev/null
  run dr_vps_storage_backing_check "$DR_VPS_POOL_DIR/$id.qcow2" "$GOLDEN"; [ "$status" -eq 0 ]
  g1=$(dr_vps_store_vm_get "$id" | cut -d'|' -f2); [ "$g1" -gt "$g0" ]
}

@test "VERIFY-BASELINE control: clean passes; a re-pointed backing chain -> 18" {
  id=$(dr_vps_domain_create web5 fedora44 --net simnet --ssh-key "$KEY")
  run dr_vps_domain_verify_baseline "$id"; [ "$status" -eq 0 ]
  # re-point: overwrite the overlay to back a DIFFERENT golden
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/other.qcow2" 2097152 65536 "Z"
  qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/other.qcow2" -F qcow2 "$DR_VPS_POOL_DIR/$id.qcow2" >/dev/null 2>&1
  run dr_vps_domain_verify_baseline "$id"; [ "$status" -eq 18 ]
}

@test "destroy: undefine + path-fenced overlay/seed drop + vm row gone (golden untouched)" {
  id=$(dr_vps_domain_create web6 fedora44 --net simnet --ssh-key "$KEY")
  dr_vps_domain_destroy "$id"
  grep -q "undefine $id" "$FAKEVIRSH_LOG"
  [ ! -f "$DR_VPS_POOL_DIR/$id.qcow2" ]
  [ ! -f "$DR_VPS_SEED_DIR/$id-seed.iso" ]
  run dr_vps_store_vm_get "$id"; [ -z "$output" ]
  [ -f "$GOLDEN" ]                                  # golden untouched
}

@test "wait: ready when ssh answers (seamed)" {
  id=$(dr_vps_domain_create web7 fedora44 --net simnet --ssh-key "$KEY")
  run dr_vps_domain_wait "$id" 3; [ "$status" -eq 0 ]
}

@test "XML-INJECTION refused: bad --mem/--net rejected (2); render rejects unsafe net" {
  run dr_vps_domain_create webI fedora44 --net simnet --ssh-key "$KEY" --mem "1024 evil"; [ "$status" -eq 2 ]
  run dr_vps_domain_create webI fedora44 --net "ev'il" --ssh-key "$KEY";                 [ "$status" -eq 24 ]  # not allowlisted
  run dr_vps_domain_render_xml vm1 /o /s "ev'il<x>" 2048 2;                              [ "$status" -eq 2 ]   # charset
}

@test "CREATE ROLLBACK: a seed failure leaves no overlay / pubkey / store row / domain" {
  export DR_VPS_SEED_GROUP="nosuchgroup_drvps_$$"     # forces seed_build to fail
  run dr_vps_domain_create webR fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]
  id=$(dr_vps_instance_id webR default)
  [ ! -f "$DR_VPS_POOL_DIR/$id.qcow2" ]
  [ ! -f "$DR_VPS_SEED_DIR/$id.pubkey" ]
  run dr_vps_store_vm_get "$id"; [ -z "$output" ]
  ! grep -q "^define" "$FAKEVIRSH_LOG" || false
}

@test "CREATE capacity: a --mem larger than free RAM is refused (12), nothing created" {
  export DR_VPS_FACT_RAM_MB=10000
  run dr_vps_domain_create webC fedora44 --net simnet --ssh-key "$KEY" --mem 4096
  [ "$status" -eq 12 ]
  ! grep -q '^define' "$FAKEVIRSH_LOG" || false
}

@test "MEM-UNIT normalization: KiB/MiB/GiB single+double quoted -> MiB; unparseable -> fail-closed" {
  # file-based fake so the literal quote chars survive (echo would strip them)
  cat >"$BATS_TEST_TMPDIR/vm" <<'EOF'
#!/usr/bin/env bash
case "$*" in *dumpxml*) cat "$DOMXML";; esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/vm"; export DR_VIRSH="$BATS_TEST_TMPDIR/vm" DOMXML="$BATS_TEST_TMPDIR/dom.xml"
  mk() { printf '<domain><memory unit=%s%s%s>%s</memory></domain>\n' "$2" "$1" "$2" "$3" >"$DOMXML"; }
  mk MiB "'" 4096;     run _dr_vps_domain_mem_mib x; [ "$status" -eq 0 ]; [ "$output" = 4096 ]
  mk KiB "'" 4194304;  run _dr_vps_domain_mem_mib x; [ "$output" = 4096 ]
  mk GiB '"' 4;        run _dr_vps_domain_mem_mib x; [ "$output" = 4096 ]   # DOUBLE-quoted unit
  mk KiB '"' 4194304;  run _dr_vps_domain_mem_mib x; [ "$output" = 4096 ]   # DOUBLE-quoted unit
  printf '<domain/>\n' >"$DOMXML"
  run _dr_vps_domain_mem_mib x; [ "$status" -ne 0 ]      # unparseable -> fail-closed, not skip
}

@test "RECREATE gate: a missing/stale egress marker blocks recreate (24), like create" {
  id=$(dr_vps_domain_create webRG fedora44 --net simnet --ssh-key "$KEY")
  rm -f "$DR_VPS_NET_STATE"                  # applied-egress marker gone -> egress no longer proven
  run dr_vps_domain_recreate "$id"; [ "$status" -eq 24 ]
}

@test "recreate: REFUSES to drop the overlay while the guest is still running (backstop fires)" {
  id=$(dr_vps_domain_create webM8 fedora44 --net simnet --ssh-key "$KEY")
  ov=$(dr_vps_sql "SELECT overlay FROM vms WHERE id=$(dr_vps_sql_str "$id");")
  echo running >"$BATS_TEST_TMPDIR/domstate"
  export FAKEVIRSH_DOMSTATE="$BATS_TEST_TMPDIR/domstate"   # a swallowed `virsh destroy` left it running
  run dr_vps_domain_recreate "$id"
  [ "$status" -eq 13 ]
  [[ "$output" == *"not shut off"* ]]
  [ -e "$ov" ]                                             # the LIVE overlay was NOT unlinked
  run dr_vps_store_vm_get "$id"; [[ "$output" == broken\|* ]]
}

@test "recreate re-renders on the VM's RECORDED net, not DR_VPS_RECREATE_NET" {
  id=$(dr_vps_domain_create webNET fedora44 --net simnet --ssh-key "$KEY")
  run dr_vps_store_vm_get_net "$id"; [ "$output" = simnet ]        # create recorded the net
  # the OLD code re-rendered on DR_VPS_RECREATE_NET; set a DECOY to prove recreate ignores it now.
  DR_VPS_RECREATE_NET=decoynet run dr_vps_domain_recreate "$id"
  [ "$status" -eq 0 ]
  grep -q "<source network='simnet'/>" "$FAKEVIRSH_XML"            # redefined on the recorded net
  ! grep -q decoynet "$FAKEVIRSH_XML" || false                              # never the decoy default
}

@test "recreate: virsh state parsing is locale-proof (LC_ALL=C forced; a german shell must not wedge recreate)" {
  id=$(dr_vps_domain_create webL10N fedora44 --net simnet --ssh-key "$KEY")
  export LANG=de_DE.UTF-8; unset LC_ALL      # operator shell locale: virsh answers TRANSLATED
  run dr_vps_domain_recreate "$id"
  [ "$status" -eq 0 ]
}

@test "recreate: a FAILED recorded-net read (DB error) fails CLOSED, no wrong-net rebuild" {
  id=$(dr_vps_domain_create webNETF fedora44 --net simnet --ssh-key "$KEY")
  ov=$(dr_vps_sql "SELECT overlay FROM vms WHERE id=$(dr_vps_sql_str "$id");")
  dr_vps_store_vm_get_net() { return 1; }     # simulate a SQLite read error (locked/corrupt)
  run dr_vps_domain_recreate "$id"
  [ "$status" -ne 0 ]
  [[ "$output" == *"failed to read recorded net"* ]]
  [ -e "$ov" ]                                # died BEFORE the destructive rebuild -> overlay intact
}

@test "recreate: a failing egress-generation read FAILS the row commit (never writes an empty egress_gen)" {
  id=$(dr_vps_domain_create webEG fedora44 --net simnet --ssh-key "$KEY")
  dr_vps_net_create_guard() { return 0; }    # isolate the commit path (the guard has its own tests)
  dr_vps_net_generation()  { return 1; }     # fleet.json became unreadable mid-recreate
  run dr_vps_domain_recreate "$id"
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_get "$id"; [[ "$output" == broken\|* ]]
  g=$(dr_vps_sql "SELECT egress_gen FROM vms WHERE id=$(dr_vps_sql_str "$id");")
  [ -n "$g" ]                                # the row NEVER gets a silent '' generation
}

@test "DESTROY golden-guard: refuses when a vm's overlay points at a registered golden" {
  id=$(dr_vps_domain_create webG fedora44 --net simnet --ssh-key "$KEY")
  dr_vps_sql "UPDATE vms SET overlay=$(dr_vps_sql_str "$GOLDEN") WHERE id=$(dr_vps_sql_str "$id");"
  run dr_vps_domain_destroy "$id"; [ "$status" -ne 0 ]
  [ -f "$GOLDEN" ]
}

@test "create REFUSES a SYMLINK squatted at the overlay path (no write-through to a golden)" {
  sid=$(dr_vps_instance_id websl default)              # the REAL (hashed) overlay basename
  ln -s "$GOLDEN" "$DR_VPS_POOL_DIR/${sid}.qcow2"       # squat the deterministic overlay path -> golden
  gd0=$(dr_vps_golden_digest "$GOLDEN")
  run dr_vps_domain_create websl fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]
  [[ "$output" == *symlink* ]]
  [ -f "$GOLDEN" ]                                       # the registered golden survives...
  [ "$(dr_vps_golden_digest "$GOLDEN")" = "$gd0" ]       # ...byte-identical (never written through)
}

@test "wait: guestexec-gated -- a STALE egress generation REFUSES SSH (lifecycle alone would pass)" {
  id=$(dr_vps_domain_create web8 fedora44 --net simnet --ssh-key "$KEY")
  jq '.block_cidrs += ["10.250.0.0/24"]' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/f2" && mv "$BATS_TEST_TMPDIR/f2" "$DR_VPS_FLEET_JSON"
  run dr_vps_domain_wait "$id" 3
  [ "$status" -ne 0 ]                                    # stale egress -> guestexec gate refuses the SSH
}

@test "console: is GUESTEXEC-GATED -- an ungatable vm is refused, never attaches virsh console" {
  run dr_vps_domain_console nope; [ "$status" -ne 0 ]
}

@test "verify-baseline: an overlay with an external DATA-FILE is refused (hidden host channel) -> 18" {
  id=$(dr_vps_domain_create web9 fedora44 --net simnet --ssh-key "$KEY")
  ov="$DR_VPS_POOL_DIR/$id.qcow2"; rm -f "$ov"
  qemu-img create -f qcow2 -F qcow2 -b "$GOLDEN" -o data_file="$DR_VPS_POOL_DIR/leak2.raw" "$ov" >/dev/null 2>&1
  run dr_vps_domain_verify_baseline "$id"; [ "$status" -eq 18 ]
}

@test "render_xml: the NIC has <port isolated='yes'> -- no guest<->guest L2 (enforces CONCEPT 'no VM<->VM')" {
  run dr_vps_domain_render_xml vm1 /pool/vm1.qcow2 /seed/vm1.iso simnet 2048 2
  [ "$status" -eq 0 ]
  [[ "$output" == *"<port isolated='yes'/>"* ]]
}

# ---- Observability Step 9: lifecycle wiring (assert/admission/prepare + cleanup + gc) ---------------

@test "create: console subsystem UNHEALTHY -> fail-closed, NOTHING created" {
  export DR_VPS_FACT_CONSOLE='dir missing'
  run dr_vps_domain_create wc1 fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_get "$(dr_vps_instance_id wc1 default)"; [ -z "$output" ]
}

@test "create: console ADMISSION refused (DoS bound) -> fail-closed, NOTHING created" {
  export DR_VPS_FACT_CONSOLE_ADMIT='over budget'
  run dr_vps_domain_create wc2 fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_get "$(dr_vps_instance_id wc2 default)"; [ -z "$output" ]
}

@test "create: the id-specific admission enforces the (MAX+1) bound the doctor aggregate cannot" {
  # REAL (unseamed) admission with the assert seamed ok: MAX_VMS=1 + one existing VM ROW => a NEW create's
  # id-specific admission (existing 1 + 1 = 2 > 1) refuses, though the aggregate check (1 <= 1) passes.
  unset DR_VPS_FACT_CONSOLE_ADMIT
  export DR_VPS_VIRTLOGD_CONF="$BATS_TEST_TMPDIR/vl.conf"; printf 'max_size = 2097152\nmax_backups = 3\n' >"$DR_VPS_VIRTLOGD_CONF"
  export DR_VPS_FACT_CONSOLE_FREE=$((100 * 1024 * 1024 * 1024))
  export DR_VPS_CONSOLE_MAX_VMS=1
  dr_vps_sql "INSERT INTO vms(id,artifact_id) VALUES('existingvm','x');"   # 1 existing log-bearing VM (store row)
  run dr_vps_domain_create wc3 fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_get "$(dr_vps_instance_id wc3 default)"; [ -z "$output" ]
}

@test "create: a SYMLINK at the console-log path -> prepare fails closed + create rolls back" {
  id=$(dr_vps_instance_id wc4 default)
  ln -s /etc/passwd "$DR_VPS_CONSOLE_LOG_DIR/${id}.log"
  run dr_vps_domain_create wc4 fedora44 --net simnet --ssh-key "$KEY"
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_get "$id"; [ -z "$output" ]              # rolled back -> no row
  [ ! -f "$DR_VPS_POOL_DIR/${id}.qcow2" ]                      # overlay scrubbed
}

@test "destroy: removes the persistent console log (+ rotated backups)" {
  id=$(dr_vps_domain_create wc5 fedora44 --net simnet --ssh-key "$KEY")
  printf 'boot output\n' >"$DR_VPS_CONSOLE_LOG_DIR/${id}.log"   # virtlogd would have written this
  printf 'rotated\n'     >"$DR_VPS_CONSOLE_LOG_DIR/${id}.log.1"
  dr_vps_domain_destroy "$id"
  [ ! -e "$DR_VPS_CONSOLE_LOG_DIR/${id}.log" ]
  [ ! -e "$DR_VPS_CONSOLE_LOG_DIR/${id}.log.1" ]
}

@test "console_log_gc: reaps ONLY rowless + domainless orphan logs" {
  live=$(dr_vps_domain_create wc6 fedora44 --net simnet --ssh-key "$KEY")   # has a row + a defined domain
  printf 'x\n' >"$DR_VPS_CONSOLE_LOG_DIR/${live}.log"
  printf 'y\n' >"$DR_VPS_CONSOLE_LOG_DIR/orphan.log"           # no row, no domain
  dr_vps_console_log_gc
  [ -e "$DR_VPS_CONSOLE_LOG_DIR/${live}.log" ]                 # kept (row + domain)
  [ ! -e "$DR_VPS_CONSOLE_LOG_DIR/orphan.log" ]               # reaped (orphan)
}

@test "recreate: console subsystem UNHEALTHY -> fail-closed (VM left intact, not rebuilt)" {
  id=$(dr_vps_domain_create wc7 fedora44 --net simnet --ssh-key "$KEY")
  export DR_VPS_FACT_CONSOLE='dir missing'
  run dr_vps_domain_recreate "$id"
  [ "$status" -ne 0 ]
  run dr_vps_store_vm_get "$id"; [ -n "$output" ]              # row still present (not torn down)
}

# ---- Observability convergence r1: inspect must not be a foreign-domain existence oracle -----------

@test "inspect: a ROW-LESS id does NOT probe libvirt (no foreign same-name existence oracle)" {
  : >"$FAKEVIRSH_LOG"
  run dr_vps_domain_inspect "drvps-vm-rowlessxyz"
  [ "$status" -eq 0 ]
  [[ "$output" == *"domain=absent"* ]]
  ! grep -q "dominfo drvps-vm-rowlessxyz" "$FAKEVIRSH_LOG" || false   # never probed libvirt for a non-owned id
}

@test "inspect: an OWNED live VM shows present + console + state (store-gated libvirt probe)" {
  id=$(dr_vps_domain_create wI1 fedora44 --net simnet --ssh-key "$KEY")
  printf 'boot output\n' >"$DR_VPS_CONSOLE_LOG_DIR/${id}.log"
  run dr_vps_domain_inspect "$id"
  [ "$status" -eq 0 ]
  [[ "$output" == *"state=running"* ]]
  [[ "$output" == *"domain=present"* ]]
  [[ "$output" == *"console=available"* ]]
}

@test "inspect: an OWNED but domain-less (broken) VM stays inspectable -> domain=absent" {
  id=$(dr_vps_domain_create wI2 fedora44 --net simnet --ssh-key "$KEY")
  "$DR_VIRSH" undefine "$id" >/dev/null 2>&1   # row remains, live domain gone (broken)
  run dr_vps_domain_inspect "$id"
  [ "$status" -eq 0 ]
  [[ "$output" == *"domain=absent"* ]]
}

@test "S1a: destroy/recreate with a FOREIGN --owner is refused (E_NOTFOUND) before touching the domain; the row survives" {
  local id; id=$(dr_vps_instance_id fvm default)
  dr_vps_store_vm_create "$id" "$AID" "/pool/fvm.qcow2" 0 1 fvm default golden 1001   # owned by uid 1001
  run dr_vps_domain_destroy "$id" --owner 2002       # foreign -> resolves to nothing
  [ "$status" -eq 14 ]                                 # E_NOTFOUND (not a gate/domain error)
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='$id';"; [ "$output" = "1" ]   # NOT destroyed
  run dr_vps_domain_recreate "$id" --owner 2002; [ "$status" -eq 14 ]              # same for recreate
  run dr_vps_sql "SELECT COUNT(*) FROM vms WHERE id='$id';"; [ "$output" = "1" ]
  # the OWNER (1001) passes the owner gate (then proceeds into domain logic under the lock -- no owner refusal)
  run dr_vps_domain_destroy "$id" --owner 1001
  [ "$status" -ne 14 ] || { echo "owner 1001 wrongly refused as not-found: $output"; false; }
}

@test "S1a success-path: create --owner stamps owner_uid; recreate --owner PRESERVES owner_uid + class (service reset path)" {
  local id; id=$(dr_vps_domain_create svcvm fedora44 --net simnet --ssh-key "$KEY" --owner 1001)
  run dr_vps_sql "SELECT owner_uid||'|'||class FROM vms WHERE id='$id';"
  [ "$output" = "1001|throwaway" ]                                  # create stamped the owner
  dr_vps_domain_recreate "$id" --owner 1001 >/dev/null              # the owner resets a wedged driver
  run dr_vps_sql "SELECT owner_uid||'|'||class FROM vms WHERE id='$id';"
  [ "$output" = "1001|throwaway" ]                                  # recreate is UPDATE-in-place: ownership + class SURVIVE
}

@test "S1b: service-class admission -- non-member refused (E_CAP); member under quota succeeds; operator is admin" {
  printf '#!/usr/bin/env bash\ncase "$1" in 1001) echo "users drvpsvc";; *) echo "users";; esac\n' >"$BATS_TEST_TMPDIR/groups"
  chmod +x "$BATS_TEST_TMPDIR/groups"; export DR_VPS_GROUPS_OF="$BATS_TEST_TMPDIR/groups" DR_VPS_SERVICE_GROUP=drvpsvc
  run dr_vps_domain_create s1 fedora44 --net simnet --ssh-key "$KEY" --owner 2002 --class service   # NOT a member
  [ "$status" -eq 12 ]; [[ "$output" == *drvpsvc* ]]                                                 # E_CAP, names the group
  local id; id=$(dr_vps_domain_create s2 fedora44 --net simnet --ssh-key "$KEY" --owner 1001 --class service)  # member, under quota
  run dr_vps_sql "SELECT class||'|'||owner_uid FROM vms WHERE id='$id';"; [ "$output" = "service|1001" ]
  local oid; oid=$(dr_vps_domain_create s3 fedora44 --net simnet --ssh-key "$KEY" --class service)   # operator (no --owner) = admin
  run dr_vps_sql "SELECT class FROM vms WHERE id='$oid';"; [ "$output" = "service" ]
}

@test "S1b: service-VM quota (default 3) is per-owner and counts pending/broken; over-quota -> E_CAP; throwaway unaffected" {
  printf '#!/usr/bin/env bash\necho "users drvpsvc"\n' >"$BATS_TEST_TMPDIR/groups"
  chmod +x "$BATS_TEST_TMPDIR/groups"; export DR_VPS_GROUPS_OF="$BATS_TEST_TMPDIR/groups" DR_VPS_SERVICE_GROUP=drvpsvc
  for st in running pending broken; do
    dr_vps_sql "INSERT INTO vms(id,artifact_id,owner_uid,class,state) VALUES ('pre-$st','a1','1001','service','$st');"
  done   # 3 service rows for 1001 (incl pending+broken) = quota reached
  run dr_vps_domain_create qx fedora44 --net simnet --ssh-key "$KEY" --owner 1001 --class service
  [ "$status" -eq 12 ]; [[ "$output" == *quota* ]]                                    # 4th service VM refused
  run dr_vps_domain_create tw1 fedora44 --net simnet --ssh-key "$KEY" --owner 1001   # throwaway is NOT quota-limited
  [ "$status" -ne 12 ]
}

@test "S1b: inspect exposes class= (machine-readable); owner_uid is NOT leaked (global read)" {
  local id; id=$(dr_vps_domain_create iv fedora44 --net simnet --ssh-key "$KEY" --owner 1001 --class throwaway)
  run dr_vps_domain_inspect "$id"
  [[ "$output" == *"class=throwaway"* ]]
  [[ "$output" != *"owner_uid="* ]]                       # ownership map not exposed via the global read
}
