#!/usr/bin/env bats
# Stage 2 -- doctor: the create gate + the registered-golden tamper control.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_identity.sh
  dr_vps_load dr_vps_store.sh
  dr_vps_load dr_vps_doctor.sh
  dr_vps_store_init
  # default: everything healthy (overridden per-test)
  export DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok
  export DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000 DR_VPS_FACT_NESTED=Y
  export DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT=ok   # console subsystem healthy (seam)
  export DR_VPS_FACT_CONSOLE_REAPER=fresh                      # reaper heartbeat fresh (doctor-only check)
}

@test "doctor: all healthy -> 0" {
  run dr_vps_doctor; [ "$status" -eq 0 ]
}

@test "doctor --json: emits the facts schema" {
  run dr_vps_doctor --json; [ "$status" -eq 0 ]
  echo "$output" | jq -e '.kvm and .libvirt and (.ram_free_mb|type=="number") and .tools.nft' >/dev/null
}

@test "doctor: /dev/kvm absent -> capability (12)" {
  export DR_VPS_FACT_KVM=absent
  run dr_vps_doctor; [ "$status" -eq 12 ]
  [[ "$output" == *"dr-vps-setup"* ]]
}

@test "doctor: stale group session -> 12 with re-login hint; relogin_check detects it" {
  export DR_VPS_FACT_KVM=stale-group
  run dr_vps_doctor; [ "$status" -eq 12 ]
  [[ "$output" == *"re-login"* ]]
  run dr_vps_doctor_relogin_check; [ "$status" -eq 0 ]
}

@test "doctor: libvirt unreachable -> 13" {
  export DR_VPS_FACT_LIBVIRT=unreachable
  run dr_vps_doctor; [ "$status" -eq 13 ]
}

@test "doctor: a missing tool -> 12" {
  export DR_VPS_FACT_TOOLS='{"cloud_localds":false,"nft":true,"qemu_img":true}'
  run dr_vps_doctor; [ "$status" -eq 12 ]
}

@test "doctor: insufficient RAM -> 12" {
  export DR_VPS_FACT_RAM_MB=1024
  run dr_vps_doctor; [ "$status" -eq 12 ]
}

@test "doctor: insufficient disk -> 12" {
  export DR_VPS_FACT_DISK_MB=100
  run dr_vps_doctor; [ "$status" -eq 12 ]
}

@test "REGISTERED-GOLDEN-TAMPER control: match ok, then corrupt-on-disk -> 18" {
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2"
  run dr_vps_doctor_golden_match "$aid"; [ "$status" -eq 0 ]
  # tamper: rewrite the on-disk golden with different content
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536 "TAMPER"
  run dr_vps_doctor_golden_match "$aid"; [ "$status" -eq 18 ]
}

@test "golden_match: unregistered/missing artifact -> 18" {
  run dr_vps_doctor_golden_match "drvps-raw-v1-1-nope"; [ "$status" -eq 18 ]
}

@test "CAPACITY-PER-REQUEST: a request bigger than free RAM is refused (12)" {
  export DR_VPS_FACT_RAM_MB=10000          # 10G free; reserve is 8192
  run dr_vps_doctor_capacity 1024;  [ "$status" -eq 0 ]    # 1024 + 8192 <= 10000
  run dr_vps_doctor_capacity 4096;  [ "$status" -eq 12 ]   # 4096 + 8192 > 10000
}

@test "PROD-BYPASS control: FACT_* are IGNORED without DR_VPS_TEST_SEAMS" {
  unset DR_VPS_TEST_SEAMS
  # facts say all-healthy, but seams are off -> doctor must use REAL host facts and
  # REFUSE, proving env alone cannot trick the gate open. The exact code depends on the host
  # (12 if no /dev/kvm; 13 if kvm present but libvirt unreachable for this user) -- never 0.
  run dr_vps_doctor
  [ "$status" -eq 12 ] || [ "$status" -eq 13 ]
}

# ---- Observability Step 4: console_assert + console_admission (capability gate) --------------------
# A healthy, BOUNDED console subsystem in the test tmpdir. The SELinux label + virtlogd-active are
# SEAMED (podman-only in real life); the FACT OVERRIDE seams are UNSET so the REAL assert/admission
# logic runs. Free space is seamed BIG so the floor passes deterministically (the tmpfs may be small).
_console_env_ok() {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"
  mkdir -m 750 -p "$DR_VPS_CONSOLE_LOG_DIR"
  export DR_VPS_SERVICE_USER="$(id -un)"          # helpers.bash sets DR_VPS_SEED_GROUP=$(id -gn)
  export DR_VPS_VIRTLOGD_CONF="$BATS_TEST_TMPDIR/virtlogd.conf"
  printf 'max_size = 2097152\nmax_backups = 3\n' >"$DR_VPS_VIRTLOGD_CONF"
  export DR_VPS_FACT_VIRTLOGD=active
  export DR_VPS_FACT_CONSOLE_LABEL='system_u:object_r:virt_log_t:s0'
  export DR_VPS_FACT_CONSOLE_FREE=$((100 * 1024 * 1024 * 1024))    # 100 GiB -> above any floor
  export DR_VPS_FACT_CONSOLE_REAPER=fresh                          # Stage-1: reaper heartbeat fresh
  unset DR_VPS_FACT_CONSOLE DR_VPS_FACT_CONSOLE_ADMIT
}

@test "console_assert: healthy dir + bounded virtlogd -> 0" {
  _console_env_ok
  run dr_vps_console_assert; [ "$status" -eq 0 ]
}

@test "console_assert (Stage-1): a STALE reaper heartbeat does NOT fail console_assert (create-safe via emergency floor)" {
  _console_env_ok
  export DR_VPS_FACT_CONSOLE_REAPER=stale
  run dr_vps_console_assert; [ "$status" -eq 0 ]           # subsystem still healthy; reaper-freshness is doctor's job
}

@test "doctor (Stage-1): a STALE reaper heartbeat FAILS the operator doctor run (health signal)" {
  export DR_VPS_FACT_CONSOLE_REAPER=stale                  # default setup otherwise healthy
  run dr_vps_doctor; [ "$status" -ne 0 ]
  [[ "$output" == *"reaper heartbeat"* ]]
}

@test "doctor --no-ram (Stage-1): a STALE reaper heartbeat does NOT block the CREATE gate (emergency floor covers safety)" {
  export DR_VPS_FACT_CONSOLE_REAPER=stale
  run dr_vps_doctor --no-ram; [ "$status" -eq 0 ]          # create/recreate proceed; reaper cadence never gates creates
}

@test "console_admission (Stage-1): the NORMAL floor binds when FILE_CAP+overshoot > the emergency cap" {
  _console_env_ok
  export DR_VPS_CONSOLE_FILE_CAP=$((50 * 1024 * 1024)) DR_VPS_CONSOLE_OVERSHOOT_BYTES=0
  export DR_VPS_CONSOLE_MAX_VMS=2 DR_VPS_CONSOLE_RESERVE_MARGIN=0
  # normal_floor = 2*50MiB = 100 MiB; emergency = 2*(2MiB*4) = 16 MiB; max = 100 MiB
  export DR_VPS_FACT_CONSOLE_FREE=$((50 * 1024 * 1024))          # 50 MiB < the 100 MiB normal floor
  run dr_vps_console_admission; [ "$status" -ne 0 ]
  [[ "$output" == *"normal="* ]]
}

@test "console_assert: missing dir -> fail closed (12)" {
  _console_env_ok; rmdir "$DR_VPS_CONSOLE_LOG_DIR"
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: dir is a SYMLINK -> fail closed (12)" {
  _console_env_ok; rmdir "$DR_VPS_CONSOLE_LOG_DIR"
  ln -s "$BATS_TEST_TMPDIR" "$DR_VPS_CONSOLE_LOG_DIR"
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: group/world-writable mode -> fail closed (12)" {
  _console_env_ok; chmod 0770 "$DR_VPS_CONSOLE_LOG_DIR"
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: wrong owner -> fail closed (12)" {
  _console_env_ok; export DR_VPS_SERVICE_USER="not-$(id -un)-xyz"
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: wrong SELinux label -> fail closed (12)" {
  _console_env_ok; export DR_VPS_FACT_CONSOLE_LABEL='system_u:object_r:tmp_t:s0'
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: virtlogd inactive -> fail closed (12)" {
  _console_env_ok; export DR_VPS_FACT_VIRTLOGD=inactive
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: UNBOUNDED virtlogd (max_size=0) -> fail closed (12)" {
  _console_env_ok; printf 'max_size = 0\nmax_backups = 3\n' >"$DR_VPS_VIRTLOGD_CONF"
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_assert: virtlogd.conf UNREADABLE (0700 /etc/libvirt) -> per_vm_cap falls back to the env knobs -> OK" {
  _console_env_ok
  export DR_VPS_VIRTLOGD_CONF="$BATS_TEST_TMPDIR/unreadable/virtlogd.conf"   # nonexistent -> [ -r ] false
  export DR_VPS_CONSOLE_VIRTLOGD_MAX_SIZE=2097152 DR_VPS_CONSOLE_VIRTLOGD_MAX_BACKUPS=3
  run dr_vps_console_assert; [ "$status" -eq 0 ]
  run dr_vps_console_admission newvm; [ "$status" -eq 0 ]
}

@test "console_assert: virtlogd.conf unreadable AND the env knob is unbounded (0) -> still fail closed (12)" {
  _console_env_ok
  export DR_VPS_VIRTLOGD_CONF="$BATS_TEST_TMPDIR/unreadable/virtlogd.conf"
  export DR_VPS_CONSOLE_VIRTLOGD_MAX_SIZE=0
  run dr_vps_console_assert; [ "$status" -eq 12 ]
}

@test "console_admission: within bounds -> 0" {
  _console_env_ok
  run dr_vps_console_admission newvm; [ "$status" -eq 0 ]
}

@test "console_admission: real df branch (small floor) -> 0" {
  _console_env_ok; unset DR_VPS_FACT_CONSOLE_FREE
  export DR_VPS_CONSOLE_MAX_VMS=1 DR_VPS_CONSOLE_RESERVE_MARGIN=1   # floor ~8MB, tmpdir has more
  run dr_vps_console_admission newvm; [ "$status" -eq 0 ]
}

@test "console_admission: (MAX+1)th log-bearing VM is refused (12)" {
  _console_env_ok; export DR_VPS_CONSOLE_MAX_VMS=2
  dr_vps_sql "INSERT INTO vms(id,artifact_id) VALUES('a','x'),('b','x');"    # 2 store rows = 2 log-bearing VMs
  run dr_vps_console_admission cnew; [ "$status" -eq 12 ]          # 2 rows + 1 fresh id = 3 > 2
}

@test "console_admission: recreate/self (own ROW exists) is NOT double-counted -> 0" {
  _console_env_ok; export DR_VPS_CONSOLE_MAX_VMS=2
  dr_vps_sql "INSERT INTO vms(id,artifact_id) VALUES('a','x'),('b','x');"
  run dr_vps_console_admission a; [ "$status" -eq 0 ]              # 'a' already a row -> 2 <= 2
}

@test "console_admission: authoritative count uses STORE ROWS, not .log files (mid-create no-log VM still counts)" {
  _console_env_ok; export DR_VPS_CONSOLE_MAX_VMS=1
  dr_vps_sql "INSERT INTO vms(id,artifact_id) VALUES('midcreate','x');"       # a row but NO .log file yet
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]         # 1 row + 1 fresh = 2 > 1 (would fail-open if counting *.log)
}

@test "console_admission: an overflow-scale virtlogd max_size -> fail closed (no 64-bit wrap bypass)" {
  _console_env_ok; printf 'max_size = 9223372036854775807\nmax_backups = 1\n' >"$DR_VPS_VIRTLOGD_CONF"
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]
}

@test "console_admission: an out-of-bounds DR_VPS_CONSOLE_MAX_VMS -> fail closed (overflow guard)" {
  _console_env_ok; export DR_VPS_CONSOLE_MAX_VMS=99999999999
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]
}

@test "console_admission: a LEADING-ZERO MAX_VMS (octal trap) -> fail closed, not a mis-bounded pass" {
  _console_env_ok; export DR_VPS_CONSOLE_MAX_VMS=010     # '010' would be OCTAL 8 in bash arithmetic
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]
}

@test "console_admission: a LEADING-ZERO virtlogd max_size -> fail closed (strict base-10)" {
  _console_env_ok; printf 'max_size = 010\nmax_backups = 3\n' >"$DR_VPS_VIRTLOGD_CONF"
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]
}

@test "console_admission: below the free-space floor -> fail closed (12)" {
  _console_env_ok; export DR_VPS_FACT_CONSOLE_FREE=1000            # << MAX*cap + reserve
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]
}

@test "console_admission: unprovable/unbounded virtlogd -> fail closed (12)" {
  _console_env_ok; printf '# no bounds set\n' >"$DR_VPS_VIRTLOGD_CONF"
  run dr_vps_console_admission newvm; [ "$status" -eq 12 ]
}

@test "doctor GATE: console subsystem unhealthy -> refuses (12)" {
  export DR_VPS_FACT_CONSOLE='dir missing'        # assert seam reports unhealthy
  run dr_vps_doctor; [ "$status" -eq 12 ]
}

@test "doctor GATE: console admission unhealthy -> refuses (12)" {
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_ADMIT='over budget'
  run dr_vps_doctor; [ "$status" -eq 12 ]
}

# ---- S5/M6: the ACL precondition is a WATCHER-boundary check, NOT the generic create gate ----
@test "doctor: the generic create gate does NOT gate on result-store ACL support (operator creates unaffected)" {
  # Coupling the ACL check to dr_vps_doctor wrongly refused direct operator `dr-vps create`
  # on a non-ACL host. The generic gate must PASS regardless of ACL support; the boundary is the watcher.
  export DR_VPS_RESULT_PRIVATE=1 DR_VPS_FACT_ACL=unsupported
  run dr_vps_doctor; [ "$status" -eq 0 ]
}

@test "doctor: S5 -- the ACL check helper is available + independent (ok/unsupported seam), for the watcher/operator boundary" {
  export DR_VPS_RESULT_PRIVATE=1
  DR_VPS_FACT_ACL=ok run dr_vps_doctor_result_acl; [ "$status" -eq 0 ]
  DR_VPS_FACT_ACL=unsupported run dr_vps_doctor_result_acl; [ "$status" -ne 0 ]
  DR_VPS_RESULT_PRIVATE=0 DR_VPS_FACT_ACL=unsupported run dr_vps_doctor_result_acl; [ "$status" -eq 0 ]  # legacy: no ACL needed
}
