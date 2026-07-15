#!/usr/bin/env bats
# Cross-distro console-log-dir handling in dr-vps-setup.
# The ancestor-swap guard `_assert_ancestors_root` is STRICT on both families (root-owned + no group/other
# write). Debian/Ubuntu's /var/log is root:syslog 2775 (group-writable), so instead of relaxing the guard,
# detect_host relocates the console-log DEFAULT under the rig's root:root-ancestor state base
# (/var/lib/distro-rig-vps/console) on the apt family; Fedora keeps /var/log. An explicit operator
# DR_VPS_CONSOLE_LOG_DIR always wins.
#
# NB: dr-vps-setup defines its own run()/run_sh() helpers that would SHADOW bats's `run`, so we source it
# inside a fresh `bash -c` per test (with an accepted flag so its arg-parser does not die on bats's args).

BIN="${BATS_TEST_DIRNAME}/../bin/dr-vps-setup"
_insrc() { run bash -c ". '$BIN' --dry-run >/dev/null 2>/dev/null; $*"; }
# _insrc_seam: DR_VPS_TEST_SEAMS=1 so api.sh does NOT source the host's persisted env and the relocation
# guard treats it as a FIRST install -- makes the relocation tests deterministic on any CI host.
_insrc_seam() { run bash -c "export DR_VPS_TEST_SEAMS=1; . '$BIN' --dry-run >/dev/null 2>/dev/null; $*"; }
# _insrc_run: DRY_RUN=0 (source with --yes) so _fs_rm_rf_safe actually DELETES (not the dry-run print).
_insrc_run() { run bash -c ". '$BIN' --yes >/dev/null 2>/dev/null; $*"; }
# stubs so detect_host is deterministic regardless of the CI host; PM is set by the per-test override.
STUBS='_libvirt_unit(){ echo libvirtd.service; }; _selinux_on(){ return 1; }'

@test "_fs_rm_rf_safe: deletes a normal nested tree (rc0)" {
  t="$BATS_TEST_TMPDIR/aa/distro-rig-vps"; mkdir -p "$t/sub"; echo x > "$t/sub/f"; echo y > "$t/g"
  _insrc_run "_fs_rm_rf_safe '$t'; echo RC=\$?"
  [[ "$output" == *"RC=0"* ]]
  [ ! -e "$t" ]
}

@test "_fs_rm_rf_safe: a symlink CHILD is unlinked, its target's contents survive (no out-of-tree delete)" {
  ext="$BATS_TEST_TMPDIR/external"; mkdir -p "$ext"; echo keep > "$ext/keepme"
  t="$BATS_TEST_TMPDIR/bb/distro-rig-vps"; mkdir -p "$t/sub"; ln -s "$ext" "$t/sub/link_out"
  _insrc_run "_fs_rm_rf_safe '$t'; echo RC=\$?"
  [[ "$output" == *"RC=0"* ]]
  [ ! -e "$t" ]
  [ -f "$ext/keepme" ]
}

@test "_fs_rm_rf_safe: a leaf that IS a symlink is unlinked; the target survives" {
  ext="$BATS_TEST_TMPDIR/ext2"; mkdir -p "$ext"; echo keep > "$ext/f"
  mkdir -p "$BATS_TEST_TMPDIR/dir"; ln -s "$ext" "$BATS_TEST_TMPDIR/dir/leaflink"
  _insrc_run "_fs_rm_rf_safe '$BATS_TEST_TMPDIR/dir/leaflink'; echo RC=\$?"
  [[ "$output" == *"RC=0"* ]]
  [ ! -L "$BATS_TEST_TMPDIR/dir/leaflink" ]
  [ -f "$ext/f" ]
}

@test "_fs_rm_rf_safe: refuses when an ANCESTOR is a symlink (fail closed, nothing deleted)" {
  ext="$BATS_TEST_TMPDIR/realtarget"; mkdir -p "$ext/child"; echo keep > "$ext/child/f"
  ln -s "$ext" "$BATS_TEST_TMPDIR/symanc"
  _insrc_run "_fs_rm_rf_safe '$BATS_TEST_TMPDIR/symanc/child'; echo RC=\$?"
  [[ "$output" != *"RC=0"* ]]
  [ -f "$ext/child/f" ]
}

@test "_fs_rm_rf_safe: a non-existent path is idempotent success (rc0)" {
  _insrc_run "_fs_rm_rf_safe '$BATS_TEST_TMPDIR/nope/distro-rig-vps'; echo RC=\$?"
  [[ "$output" == *"RC=0"* ]]
}

@test "_fs_rm_rf_safe: refuses a shallow (<2-component) path (blast-radius guard)" {
  _insrc_run "_fs_rm_rf_safe /zzz-drvps-nonexistent; echo RC=\$?"
  [[ "$output" != *"RC=0"* ]]
}

@test "_fs_rm_rf_safe: a pathologically deep tree is refused (fail closed, no RecursionError)" {
  base="$BATS_TEST_TMPDIR/dd/distro-rig-vps"; d="$base"
  for i in $(seq 1 200); do d="$d/x"; done; mkdir -p "$d"
  _insrc_run "_fs_rm_rf_safe '$base'; echo RC=\$?"
  [[ "$output" != *"RC=0"* ]]
  [[ "$output" != *"RecursionError"* ]]
}

@test "_safe_path: rejects a '..' path component (closes the lexical-vs-kernel symlink bypass)" {
  _insrc '_safe_path /var/lib/distro-rig-vps/jump/../victim DR_TEST'
  [ "$status" -ne 0 ]
  [[ "$output" == *"'.' or '..' path component"* ]]
}

@test "_safe_path: rejects a '.' path component" {
  _insrc '_safe_path /var/lib/distro-rig-vps/./x DR_TEST'
  [ "$status" -ne 0 ]
}

@test "_safe_path: accepts a normal rig path (rc0)" {
  _insrc '_safe_path /var/lib/distro-rig-vps/console DR_TEST; echo "RC=$?"'
  [[ "$output" == *"RC=0"* ]]
}

@test "_assert_ancestors_root: an all-root non-writable path passes (rc0)" {
  _insrc '_assert_ancestors_root /usr/lib/distro-rig-vps/x DR_TEST; echo "RC=$?"'
  [[ "$output" == *"RC=0"* ]]
}

@test "_assert_ancestors_root: a world/group-writable ancestor is fatal" {
  # /tmp is root:root 1777 (group- AND other-writable) on every supported distro -- trips the strict
  # `find -perm /022` check before the 'distro-rig-vps' namespace component.
  _insrc '_assert_ancestors_root /tmp/distro-rig-vps/leaf DR_TEST'
  [ "$status" -ne 0 ]
  [[ "$output" == *"non-group/other-writable"* ]]
}

@test "detect_host: apt family relocates the console-log DEFAULT under /var/lib on a FIRST install" {
  _insrc_seam "$STUBS; detect_pm(){ echo apt; }; _DR_VPS_CONSOLE_DIR_OPERATOR=''; DR_VPS_CONSOLE_LOG_DIR=/var/log/distro-rig-vps/console; detect_host; echo \"CDIR=\$DR_VPS_CONSOLE_LOG_DIR\""
  [[ "$output" == *"CDIR=/var/lib/distro-rig-vps/console"* ]]
}

@test "detect_host: dnf family keeps the /var/log console-log default (Fedora unchanged)" {
  _insrc_seam "$STUBS; detect_pm(){ echo dnf; }; _DR_VPS_CONSOLE_DIR_OPERATOR=''; DR_VPS_CONSOLE_LOG_DIR=/var/log/distro-rig-vps/console; detect_host; echo \"CDIR=\$DR_VPS_CONSOLE_LOG_DIR\""
  [[ "$output" == *"CDIR=/var/log/distro-rig-vps/console"* ]]
}

@test "detect_host: an explicit operator DR_VPS_CONSOLE_LOG_DIR wins on apt (no relocation)" {
  _insrc_seam "$STUBS; detect_pm(){ echo apt; }; _DR_VPS_CONSOLE_DIR_OPERATOR='/srv/logs/console'; DR_VPS_CONSOLE_LOG_DIR='/srv/logs/console'; detect_host; echo \"CDIR=\$DR_VPS_CONSOLE_LOG_DIR\""
  [[ "$output" == *"CDIR=/srv/logs/console"* ]]
}

@test "detect_host: apt does NOT relocate a persisted value on reapply (env exists, TEST_SEAMS off)" {
  # mirror api.sh's persisted-env-loaded condition: with TEST_SEAMS unset and a readable env file, a value
  # equal to the /var/log default is a STORED choice and must be kept, not re-classified to /var/lib.
  [ -r /etc/distro-rig-vps/env ] || skip "no persisted env on this host to exercise the reapply branch"
  _insrc "$STUBS; detect_pm(){ echo apt; }; _DR_VPS_CONSOLE_DIR_OPERATOR=''; DR_VPS_CONSOLE_LOG_DIR=/var/log/distro-rig-vps/console; detect_host; echo \"CDIR=\$DR_VPS_CONSOLE_LOG_DIR\""
  [[ "$output" == *"CDIR=/var/log/distro-rig-vps/console"* ]]
}

# ---- DR_VPS_BRIDGE_IP: ONE knob the whole guest-subnet endpoint set derives from (nested-rig installs).
# Default MUST preserve the historical literals; an override re-derives net XML + dhcp + proxy pins in
# lockstep; anything malformed or diverging fails CLOSED (this is a root installer).
@test "bridge-ip: default preserves the historical simnet literals (10.123.0.1/24, dhcp .10-.250)" {
  _insrc "validate_env; _dr_vps_net_xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *'ip address="10.123.0.1" netmask="255.255.255.0"'* ]]
  [[ "$output" == *'range start="10.123.0.10" end="10.123.0.250"'* ]]
}

@test "bridge-ip: an override re-derives the net XML, dhcp range, and proxy pin defaults in lockstep" {
  _insrc "export DR_VPS_BRIDGE_IP=10.200.0.1; validate_env; _dr_vps_net_xml; echo \"pip=\$DR_VPS_PROXY_IP src=\$DR_VPS_PROXY_SRC\""
  [ "$status" -eq 0 ]
  [[ "$output" == *'ip address="10.200.0.1"'* ]]
  [[ "$output" == *'range start="10.200.0.10" end="10.200.0.250"'* ]]
  [[ "$output" == *"pip=10.200.0.1 src=10.200.0.0/24"* ]]
}

@test "bridge-ip: rejects a non-.1 ip, an out-of-range octet, and a DIVERGING explicit proxy pin (fail closed)" {
  run bash -c "export DR_VPS_BRIDGE_IP=10.200.0.5; . '$BIN' --dry-run >/dev/null 2>/dev/null; validate_env"
  [ "$status" -eq 2 ]
  run bash -c "export DR_VPS_BRIDGE_IP=10.999.0.1; . '$BIN' --dry-run >/dev/null 2>/dev/null; validate_env"
  [ "$status" -eq 2 ]
  run bash -c "export DR_VPS_BRIDGE_IP=10.200.0.1 DR_VPS_PROXY_IP=10.123.0.1; . '$BIN' --dry-run >/dev/null 2>/dev/null; validate_env"
  [ "$status" -eq 2 ]
}

@test "bridge-ip: fleet cache_cidr lockstep guard -- match passes, divergence fails (never a dead egress path)" {
  f="$BATS_TEST_TMPDIR/fleet.json"
  printf '{"simulated_allow":{"cache_cidr":"10.123.0.1/32"}}' >"$f"
  _insrc "validate_env; _dr_vps_fleet_cache_guard '$f'"
  [ "$status" -eq 0 ]
  _insrc "export DR_VPS_BRIDGE_IP=10.200.0.1; validate_env; _dr_vps_fleet_cache_guard '$f'"
  [ "$status" -ne 0 ]
}

@test "bridge-ip: the collision preflight keys on the DERIVED rig subnet, not the historical literal (nested-guest FATAL, live 2026-07-12)" {
  # Found LIVE: a nested guest sits on the OUTER 10.123.0.0/24; with the bridge renumbered to 10.200.0.1
  # the preflight must NOT fire on the guest's own uplink, and MUST fire on the new subnet.
  _insrc "export DR_VPS_BRIDGE_IP=10.200.0.1; validate_env; _cidr_overlaps_rig 10.123.0.109/24 && echo OLD-OVERLAPS || echo OLD-CLEAR; _cidr_overlaps_rig 10.200.0.55/24 && echo NEW-OVERLAPS || echo NEW-CLEAR"
  [ "$status" -eq 0 ]
  [[ "$output" == *"OLD-CLEAR"* ]]
  [[ "$output" == *"NEW-OVERLAPS"* ]]
}

@test "bridge-ip: rejects a NON-RFC1918 bridge even if it is the .1 of a /24 (root installer, no public bind)" {
  for ip in 8.8.8.1 100.64.0.1 172.32.0.1 192.169.0.1 224.0.0.1; do
    run bash -c "export DR_VPS_BRIDGE_IP=$ip; . '$BIN' --dry-run >/dev/null 2>/dev/null; validate_env"
    [ "$status" -eq 2 ]
  done
  for ip in 10.200.0.1 172.16.5.1 172.31.9.1 192.168.7.1; do
    run bash -c "export DR_VPS_BRIDGE_IP=$ip; . '$BIN' --dry-run >/dev/null 2>/dev/null; validate_env"
    [ "$status" -eq 0 ]
  done
}

@test "bridge-ip: collision preflight catches a host ROUTE overlapping the rig subnet (not just an iface addr)" {
  # A VPN/nested host with a ROUTE to the rig subnet but NO interface address in it: iface-only scan misses it.
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device "drvps0"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 via 192.168.122.1 dev ens3';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  # and a NON-overlapping route passes
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device "drvps0"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.50.0.0/24 via 192.168.122.1 dev ens3'; echo 'default via 192.168.122.1 dev ens3';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -eq 0 ]
}

# full-shape owned-net mock (bridge/dns/dhcp present): the reapply assert
# validates the WHOLE shape, so the pass-case mock must carry it.
_M1_VIRSH='virsh(){ case "$*" in *"net-list"*) echo simnet;; *"net-dumpxml"*) printf "<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"%s\">drvps</drvps:owner></metadata><bridge name=\"drvps0\"/><dns enable=\"no\"/><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"><dhcp/></ip></network>" "$DR_VPS_NET_MARKER";; esac; }'
@test "reapply-egress: refuses a DR_VPS_BRIDGE_IP that does not match the installed simnet (light path skips step_libvirt)" {
  # marked simnet live on 10.200.0.1; operator passes a DIFFERENT bridge -> must FATAL, not split-brain.
  run bash -c "
    export DR_VPS_BRIDGE_IP=192.168.50.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    $_M1_VIRSH
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"NOT an egress reapply"* ]]
  # a MATCHING bridge passes (live drvps0 carries the expected /24 -- the live-address requirement)
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    $_M1_VIRSH
    ip(){ case \"\$*\" in *'addr show'*) printf '4: drvps0    inet 10.200.0.1/24 brd 10.200.0.255 scope global drvps0\n';; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -eq 0 ]
}

@test "reapply-egress: FAILS CLOSED when libvirt state is unreadable (virsh absent / net-list errors / ip unparsable)" {
  run bash -c "export DR_VPS_BRIDGE_IP=10.200.0.1; . '$BIN' --dry-run >/dev/null 2>/dev/null; have(){ case \$1 in virsh) return 1;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }; _assert_reapply_bridge_matches"
  [ "$status" -ne 0 ]                                            # virsh absent -> refuse
  run bash -c "export DR_VPS_BRIDGE_IP=10.200.0.1; . '$BIN' --dry-run >/dev/null 2>/dev/null; have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }; virsh(){ return 1; }; _assert_reapply_bridge_matches"
  [ "$status" -ne 0 ]                                            # net-list errors (libvirt down) -> refuse
  run bash -c "export DR_VPS_BRIDGE_IP=10.200.0.1; . '$BIN' --dry-run >/dev/null 2>/dev/null; have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }; virsh(){ case \"\$*\" in *net-list*) echo simnet;; *) return 1;; esac; }; _assert_reapply_bridge_matches"
  [ "$status" -ne 0 ]                                            # net exists but ip unreadable -> refuse
  run bash -c "export DR_VPS_BRIDGE_IP=10.200.0.1; . '$BIN' --dry-run >/dev/null 2>/dev/null; have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }; virsh(){ case \"\$*\" in *net-list*) echo othernet;; esac; }; _assert_reapply_bridge_matches"
  [ "$status" -eq 0 ]                                            # authoritatively no such net -> allowed
}

@test "collision preflight: FAILS CLOSED when the route/addr probe errors (ip rc!=0)" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device "drvps0"' >&2; return 1;; *'addr show'*) echo '1: lo    inet 127.0.0.1/8 scope host lo';; *'route show'*) return 42;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
}

@test "collision preflight: catches a TYPED route (blackhole) and does not confuse drvps01 with drvps0" {
  # blackhole <rig-subnet>: dest is field 2, must still be checked
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device "drvps0"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo 'blackhole 10.200.0.0/24 proto static';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  # a route on drvps01 (NOT our drvps0) overlapping must NOT be excluded by a prefix match
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device "drvps0"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 dev drvps01 scope link';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  # our OWN drvps0 connected route is correctly EXCLUDED (no false collision)
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device "drvps0"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 dev drvps0 proto kernel scope link src 10.200.0.1'; echo 'default via 192.168.1.1 dev eth0';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -eq 0 ]
}

@test "collision: _scan_libvirt_nets FAILS CLOSED when net-list errors or a listed net's XML is unreadable" {
  # net-list itself errors -> must report a refusal string (not empty = 'no collision')
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    virsh(){ return 1; }
    out=\$(_scan_libvirt_nets); [ -n \"\$out\" ] && echo REFUSED || echo CLEAN
  "
  [[ "$output" == *REFUSED* ]]
  # net-list lists a net whose dumpxml is unreadable -> refuse (do not skip past it)
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    virsh(){ case \"\$*\" in *net-list*) echo foreignnet;; *net-dumpxml*) return 1;; esac; }
    _net_is_ours(){ return 1; }
    out=\$(_scan_libvirt_nets); [ -n \"\$out\" ] && echo REFUSED || echo CLEAN
  "
  [[ "$output" == *REFUSED* ]]
}

@test "collision: a MULTIPATH route with drvps0 as ONE nexthop is NOT skipped (dest still checked)" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 proto static nexthop via 192.0.2.1 dev drvps0 weight 1 nexthop via 192.0.2.2 dev eth0 weight 1';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
}

@test "collision: a link-probe ERROR (not 'does not exist') FAILS CLOSED" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'RTNETLINK answers: Operation not permitted' >&2; return 2;; *'addr show'*) : ;; *'route show'*) : ;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
}

@test "preflight: the 'ip' command is REQUIRED (collision gate is blind without it)" {
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    PM=dnf; SELINUX_ON=0; LIBVIRT_UNIT=libvirtd.service; DRY_RUN=1
    have(){ case \$1 in ip) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    step_preflight
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"(iproute2) is required"* ]]
}

@test "reapply-egress: the net-presence check is PIPE-FREE (a huge net-list with an early match is not a false-absent)" {
  # simnet early, then thousands of names (>pipe buffer). `printf|grep -qx` under pipefail would 141 -> false 'absent'.
  run bash -c "
    export DR_VPS_BRIDGE_IP=192.168.50.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    virsh(){ case \"\$*\" in *net-list*) echo simnet; for i in \$(seq 1 5000); do echo net\$i; done;; *net-dumpxml*) printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"%s\">drvps</drvps:owner></metadata><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"/></network>' \"\$DR_VPS_NET_MARKER\";; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]                                            # simnet present + on 10.200.0.1 != 192.168.50.1 -> mismatch FATAL
  [[ "$output" == *"NOT an egress reapply"* ]]
}

@test "reapply-egress / net-shape: a NON-/24 simnet is refused, not accepted as matching" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    virsh(){ case \"\$*\" in *net-list*) echo simnet;; *net-dumpxml*) printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"%s\">drvps</drvps:owner></metadata><ip address=\"10.200.0.1\" netmask=\"255.255.0.0\"/></network>' \"\$DR_VPS_NET_MARKER\";; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"/24"* ]]
}

@test "collision: a FOREIGN routed entry 'via <gw> dev drvps0' is NOT excluded (only our connected route is)" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 via 10.123.0.254 dev drvps0 proto static';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
}

@test "preflight: the fleet lockstep guard runs on the LITERAL runtime path BEFORE _preflight_collision, with a symlink refusal" {
  # The early guard must mirror step_env EXACTLY (literal /etc/distro-rig-vps/fleet.json + symlink refusal),
  # NOT a DR_VPS_FLEET_JSON override (preflight and step_env would otherwise gate different files).
  local pblk; pblk=$(sed -n '/^step_preflight() {/,/^}/p' "$BIN")
  [[ "$pblk" == *'/etc/distro-rig-vps/fleet.json'* ]]             # the literal runtime path, not an override
  [[ "$pblk" == *'_dr_vps_fleet_cache_guard'* ]]
  [[ "$pblk" == *'is a SYMLINK'* ]]                               # same symlink refusal as step_env
  # ordering: the fleet guard precedes the _preflight_collision CALL (a bare, indented call line -- not the
  # earlier comment that merely mentions _preflight_collision), so a mismatch refuses before net mutation
  local fg pc
  fg=$(awk '/^step_preflight\(\)/{f=1} f&&/_dr_vps_fleet_cache_guard/{print NR; exit}' "$BIN")
  pc=$(awk '/^step_preflight\(\)/{f=1} f&&/^[[:space:]]*_preflight_collision[[:space:]]*$/{print NR; exit}' "$BIN")
  [ -n "$fg" ] && [ -n "$pc" ] && [ "$fg" -lt "$pc" ]
  # functional (host-independent): the guard function refuses a mismatched fleet, passes a matching one
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    bad=$BATS_TEST_TMPDIR/bad.json; good=$BATS_TEST_TMPDIR/good.json
    printf '{\"simulated_allow\":{\"cache_cidr\":\"10.123.0.1/32\"}}' > \"\$bad\"
    printf '{\"simulated_allow\":{\"cache_cidr\":\"10.200.0.1/32\"}}' > \"\$good\"
    _dr_vps_fleet_cache_guard \"\$good\" && echo GOOD-OK
    _dr_vps_fleet_cache_guard \"\$bad\"  2>/dev/null && echo BAD-PASSED || echo BAD-REFUSED
  "
  [[ "$output" == *GOOD-OK* ]]
  [[ "$output" == *BAD-REFUSED* ]]
}

@test "reapply / net-shape: a MULTI-<ip> net (right /24 + a stray non-/24 IPv4) is REFUSED" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    virsh(){ case \"\$*\" in *net-list*) echo simnet;; *net-dumpxml*) printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"%s\">drvps</drvps:owner></metadata><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"/><ip address=\"192.168.50.1\" netmask=\"255.255.0.0\"/></network>' \"\$DR_VPS_NET_MARKER\";; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]
}

@test "collision: a more-specific 'local <rig>/25 dev drvps0' is NOT treated as our own /24 connected route" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo 'local 10.200.0.128/25 dev drvps0 table main scope host';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
}

@test "net-shape: the XML validator ignores an <ip> planted in <metadata> (tree-parse, not doc-wide regex)" {
  # A marked net whose only network-level <ip> is IPv6, with a spoofing <ip> inside <metadata>, must be REFUSED.
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    spoof='<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"x\">drvps</drvps:owner><ip xmlns=\"urn:other\" address=\"10.200.0.1\" prefix=\"24\"/></metadata><bridge name=\"drvps0\"/><dns enable=\"no\"/><ip family=\"ipv6\" address=\"fd00::1\" prefix=\"64\"/></network>'
    _dr_vps_net_shape_ok \"\$spoof\" && echo ACCEPTED || echo REFUSED
    # a genuine direct /24 <ip> (with an unrelated metadata <ip>) is ACCEPTED (single real IPv4)
    good='<network><name>simnet</name><metadata><ip xmlns=\"urn:other\" address=\"9.9.9.9\" prefix=\"8\"/></metadata><bridge name=\"drvps0\"/><dns enable=\"no\"/><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"><dhcp/></ip></network>'
    _dr_vps_net_shape_ok \"\$good\" && echo GOOD-OK || echo GOOD-BAD
  "
  [[ "$output" == *REFUSED* ]]
  [[ "$output" == *GOOD-OK* ]]
  [[ "$output" != *ACCEPTED* ]]
}

@test "preflight: a DANGLING fleet symlink is refused (test -L before -e)" {
  local pblk; pblk=$(sed -n '/^step_preflight() {/,/^}/p' "$BIN")
  [[ "$pblk" == *'[ -L "$_fj" ]'* ]]                              # -L tested FIRST (dangling symlink has -e false)
  # structural: the -L test precedes the -e test in step_preflight's fleet guard
  local ll ee
  ll=$(awk '/^step_preflight\(\)/{f=1} f&&/\[ -L "\$_fj" \]/{print NR; exit}' "$BIN")
  ee=$(awk '/^step_preflight\(\)/{f=1} f&&/elif \[ -e "\$_fj" \]/{print NR; exit}' "$BIN")
  [ -n "$ll" ] && [ -n "$ee" ] && [ "$ll" -lt "$ee" ]
}

@test "collision: exact-prefix 'local <rig> dev drvps0' and 'proto static' routes are CAUGHT (only the kernel connected route is our own)" {
  # a `local 10.200.0.0/24 dev drvps0 scope host` is FOREIGN (host-local), must be caught even though dest==rig
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo 'local 10.200.0.0/24 dev drvps0 table main scope host';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  # a `10.200.0.0/24 dev drvps0 proto static scope link metric 50` (proto STATIC, not kernel) is caught
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 dev drvps0 proto static scope link metric 50';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  # the GENUINE kernel connected route (proto kernel scope link src bridge) is still EXCLUDED (no false collision)
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show'*) echo '10.200.0.0/24 dev drvps0 proto kernel scope link src 10.200.0.1'; echo 'default via 192.168.1.1 dev eth0';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -eq 0 ]
}

@test "net-ownership: _net_is_ours is STRUCTURAL -- marker in <description> (not metadata/owner) is NOT ours" {
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    virsh(){ printf '<network><name>simnet</name><description>distro-rig-vps:net-owner:v1</description><bridge name=\"drvps0\"/></network>'; }
    _net_is_ours simnet && echo OURS || echo FOREIGN
  "
  [[ "$output" == *FOREIGN* ]]
  # the genuine metadata/owner marker IS ours
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    virsh(){ printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"distro-rig-vps:net-owner:v1\">drvps</drvps:owner></metadata><bridge name=\"drvps0\"/></network>'; }
    _net_is_ours simnet && echo OURS || echo FOREIGN
  "
  [[ "$output" == *OURS* ]]
}

@test "net-shape: _dr_vps_net_shape_ok is STRUCTURAL -- a spoofing <description> with a real foreign dns/bridge is refused" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    spoof='<network><name>simnet</name><description>dns enable=\"no\" bridge name=\"drvps0\"</description><dns enable=\"yes\"/><bridge name=\"foreign0\"/><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"><dhcp/></ip></network>'
    _dr_vps_net_shape_ok \"\$spoof\" && echo ACCEPTED || echo REFUSED
    real=\$(_dr_vps_net_xml)
    _dr_vps_net_shape_ok \"\$real\" && echo REAL-OK || echo REAL-BAD
  "
  [[ "$output" == *REFUSED* ]]
  [[ "$output" == *REAL-OK* ]]
  [[ "$output" != *ACCEPTED* ]]
}

@test "collision: _own_net_active requires the marked net's bridge to be drvps0 (a marked net on foreign0 is NOT proof of ownership of a manual drvps0)" {
  # marked+active simnet on foreign0 -> _own_net_active must be FALSE (so block 1 flags a foreign drvps0)
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    virsh(){ case \"\$*\" in *net-list*) echo simnet;; *net-dumpxml*) printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"distro-rig-vps:net-owner:v1\">drvps</drvps:owner></metadata><bridge name=\"foreign0\"/></network>';; esac; }
    _own_net_active && echo ACTIVE-OURS || echo NOT-OURS
  "
  [[ "$output" == *NOT-OURS* ]]
}

@test "collision: the route scan reads ALL policy-routing tables (table all), not just main" {
  grep -q 'ip -o -4 route show table all' "$BIN"
}

@test "verify-poll: _vp_squid_bound matches the EXACT ip:3128 field, not a substring (31280 / prefixed addr)" {
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    ss(){ printf 'LISTEN 0 128 10.200.0.1:31280 0.0.0.0:*\n'; }
    _vp_squid_bound 10.200.0.1 && echo BOUND || echo NOT
  "
  [[ "$output" == *NOT* ]]
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    ss(){ printf 'LISTEN 0 128 10.200.0.1:3128 0.0.0.0:*\n'; }
    _vp_squid_bound 10.200.0.1 && echo BOUND || echo NOT
  "
  [[ "$output" == *BOUND* ]]
}

@test "collision: with 'table all', the kernel-auto local/broadcast routes on drvps0 are EXCLUDED (reentrant install must not self-collide)" {
  # a REAL reentrant install's route table: connected + kernel local/broadcast entries on drvps0
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show table all'*) printf '10.200.0.0/24 dev drvps0 proto kernel scope link src 10.200.0.1\nlocal 10.200.0.1 dev drvps0 table local proto kernel scope host src 10.200.0.1\nbroadcast 10.200.0.0 dev drvps0 table local proto kernel scope link src 10.200.0.1\nbroadcast 10.200.0.255 dev drvps0 table local proto kernel scope link src 10.200.0.1\ndefault via 192.168.1.1 dev eth0\n';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -eq 0 ]
  # a FOREIGN route on drvps0 that is NOT proto kernel (or has a different src) is still CAUGHT
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo 'Cannot find device \"drvps0\"' >&2; return 1;; *'addr show'*) : ;; *'route show table all'*) echo '10.200.0.0/24 dev drvps0 proto static scope link';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
}

@test "collision: _scan_libvirt_nets is STRUCTURAL -- a foreign net with 'drvps0' only in <description> or a metadata <ip> does NOT false-collide" {
  # foreign net on virbr99 whose DESCRIPTION mentions drvps0 -> NOT a bridge collision
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    xml='<network><name>other</name><description>legacy: name=\"drvps0\" was considered</description><bridge name=\"virbr99\"/><ip address=\"192.168.99.1\" netmask=\"255.255.255.0\"/></network>'
    out=\$(_dr_vps_net_collides \"\$xml\" 10.200.0.0/24); echo \"[\$out]\"
  "
  [[ "$output" == *"[]"* ]]
  # a real drvps0 bridge or a real overlapping direct <ip> IS caught
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    xml='<network><name>x</name><bridge name=\"drvps0\"/><ip address=\"9.9.9.9\" netmask=\"255.0.0.0\"/></network>'
    _dr_vps_net_collides \"\$xml\" 10.200.0.0/24
    xml2='<network><name>y</name><metadata><ip xmlns=\"urn:m\" address=\"10.200.0.5\" prefix=\"24\"/></metadata><bridge name=\"virbr5\"/><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"/></network>'
    _dr_vps_net_collides \"\$xml2\" 10.200.0.0/24
  "
  [[ "$output" == *bridge* ]]
  [[ "$output" == *overlap* ]]
}

@test "reapply-egress: validates the FULL owned-net shape, not just the /24 tuple (foreign bridge / forward drift refused)" {
  # marked net with the CORRECT 10.200.0.1/24+dhcp but bridge foreign0 + forward NAT + dns on: the /24-only
  # check passed it, and reapply would refresh an nft fence keyed to drvps0 that the guests are not behind.
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    virsh(){ case \"\$*\" in *net-list*) echo simnet;; *net-dumpxml*) printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"%s\">drvps</drvps:owner></metadata><bridge name=\"foreign0\"/><forward mode=\"nat\"/><dns enable=\"yes\"/><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"><dhcp/></ip></network>' \"\$DR_VPS_NET_MARKER\";; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"NOT an egress reapply"* ]]
}

@test "collision: a live drvps0 address that DIFFERS from <bridge-ip>/24 is NOT exempt (live prefix drift caught)" {
  # own marked net active, but the LIVE drvps0 carries a widened /16 -> must collide, not be skipped as ours
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    _own_net_active(){ return 0; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo '4: drvps0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500';; *'addr show'*) printf '4: drvps0    inet 10.200.0.1/16 brd 10.200.255.255 scope global drvps0\n';; *'route show table all'*) : ;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"10.200.0.1/16"* ]]
  # the EXACT expected <bridge-ip>/24 on drvps0 stays exempt (no false self-collision on a reentrant run)
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    _own_net_active(){ return 0; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo '4: drvps0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500';; *'addr show'*) printf '4: drvps0    inet 10.200.0.1/24 brd 10.200.0.255 scope global drvps0\n';; *'route show table all'*) : ;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -eq 0 ]
}

@test "collision: an own-bridge kernel route whose dest is NOT contained in the rig /24 is CAUGHT (widened route drift)" {
  # dev drvps0 + proto kernel + src==bridge matched the exemption REGARDLESS of destination: a live /16
  # kernel route (from a widened address) was skipped and the widened route survived setup un-repaired.
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    _own_net_active(){ return 0; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo '4: drvps0: <UP>';; *'addr show'*) printf '4: drvps0    inet 10.200.0.1/24 brd 10.200.0.255 scope global drvps0\n';; *'route show table all'*) echo '10.200.0.0/16 dev drvps0 proto kernel scope link src 10.200.0.1';; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"10.200.0.0/16"* ]]
}

@test "collision: _dr_vps_net_collides cleans its XML temp file when killed mid-scan (INT/TERM trap, fail-closed rc)" {
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    td=\$(mktemp -d); export TMPDIR=\$td
    python3(){ sleep 2; }
    ( _dr_vps_net_collides '<network/>' 10.200.0.0/24 >/dev/null 2>&1 ) & pid=\$!
    sleep 0.5; kill -TERM \$pid 2>/dev/null; wait \$pid; rc=\$?
    left=\$(ls -A \"\$td\" | wc -l); rm -rf \"\$td\"
    echo \"rc=\$rc left=\$left\"
  "
  [[ "$output" == *"left=0"* ]]
  [[ "$output" != *"rc=0 "* ]]                                     # a killed scan must never read as 'no collision'
}

@test "collision: an owned ACTIVE drvps0 MISSING the expected <bridge-ip>/24 is refused (deleted/replaced live address)" {
  # stored XML right but live address DELETED: the overlap scans only see PRESENT addresses, reconcile
  # no-ops on the correct XML, and setup would report success with a bridge the guests cannot reach.
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    _own_net_active(){ return 0; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo '4: drvps0: <UP>';; *'addr show'*) : ;; *'route show table all'*) : ;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"does not carry the expected live address"* ]]
  # REPLACED with a non-overlapping foreign /24 -> same refusal (absence of the EXPECTED addr is the signal;
  # a non-overlapping replacement is invisible to the overlap scan)
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    _own_net_active(){ return 0; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo '4: drvps0: <UP>';; *'addr show'*) printf '4: drvps0    inet 192.168.77.1/24 brd 192.168.77.255 scope global drvps0\n';; *'route show table all'*) : ;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"192.168.77.1/24"* ]]
  # the healthy live layout (expected /24 present) still passes -- no false self-collision
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in ip) return 0;; virsh) return 1;; python3) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    _own_net_active(){ return 0; }
    ip(){ case \"\$*\" in *'link show drvps0'*) echo '4: drvps0: <UP>';; *'addr show'*) printf '4: drvps0    inet 10.200.0.1/24 brd 10.200.0.255 scope global drvps0\n';; *'route show table all'*) : ;; esac; }
    DRY_RUN=0 _preflight_collision
  "
  [ "$status" -eq 0 ]
}

@test "collision: _dr_vps_net_collides PRESERVES a direct caller's INT/TERM traps on normal return" {
  run bash -c "
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    trap 'echo CALLER-INT' INT; trap 'echo CALLER-TERM' TERM
    _dr_vps_net_collides '<network><name>x</name></network>' 10.200.0.0/24 >/dev/null
    ti=\$(trap -p INT); tt=\$(trap -p TERM)
    [[ \"\$ti\" == *CALLER-INT* ]] && [[ \"\$tt\" == *CALLER-TERM* ]] && echo TRAPS-PRESERVED || echo TRAPS-CLOBBERED
  "
  [[ "$output" == *TRAPS-PRESERVED* ]]
}

@test "reapply-egress: an owned ACTIVE net whose live drvps0 is MISSING the expected /24 is refused (ip_nonlocal_bind masks the bind-poll)" {
  # reapply never runs _preflight_collision, and step_proxy sets ip_nonlocal_bind=1 -- squid can bind a
  # MISSING bridge address and the bind-poll false-passes. The light path must verify the live address.
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh|ip) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    $_M1_VIRSH
    ip(){ case \"\$*\" in *'addr show'*) : ;; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"does not carry the expected live address"* ]]
  # probe error (ip rc!=0) fails CLOSED too
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh|ip) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    $_M1_VIRSH
    ip(){ case \"\$*\" in *'addr show'*) return 3;; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -ne 0 ]
  # an owned but INACTIVE net (not in the active list) skips the live check (nothing is live to verify)
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    have(){ case \$1 in virsh) return 0;; *) command -v \"\$1\" >/dev/null 2>&1;; esac; }
    virsh(){ case \"\$*\" in *'net-list --all'*) echo simnet;; *net-list*) : ;; *net-dumpxml*) printf '<network><name>simnet</name><metadata><drvps:owner xmlns:drvps=\"%s\">drvps</drvps:owner></metadata><bridge name=\"drvps0\"/><dns enable=\"no\"/><ip address=\"10.200.0.1\" netmask=\"255.255.255.0\"><dhcp/></ip></network>' \"\$DR_VPS_NET_MARKER\";; esac; }
    _assert_reapply_bridge_matches
  "
  [ "$status" -eq 0 ]
}

@test "collision: a LARGE foreign net XML (> MAX_ARG_STRLEN) with a drvps0 bridge is CAUGHT, not fail-open" {
  run bash -c "
    export DR_VPS_BRIDGE_IP=10.200.0.1
    . '$BIN' --dry-run >/dev/null 2>/dev/null
    big=\$(python3 -c 'print(\"<network><name>big</name><metadata>\" + \"x\"*200000 + \"</metadata><bridge name=\\\"drvps0\\\"/></network>\")')
    out=\$(_dr_vps_net_collides \"\$big\" 10.200.0.0/24); rc=\$?
    echo \"rc=\$rc out=[\$out]\"
  "
  [[ "$output" == *"out=[bridge]"* ]]
  [[ "$output" == *"rc=0"* ]]
}
