#!/usr/bin/env bats
# Stage 7 -- CLI dispatch + dr-vps-setup installer (dry-run / re-entrancy / refusals).

load helpers

setup() {
  dr_vps_test_setup
  BIN="$(cd "$DR_VPS_SRC/../bin" && pwd)"
  # dr_vps_test_setup points DR_VPS_NET_STATE at a /tmp seam for the net LIBRARY tests; the installer
  # tests here exercise the REAL installer, whose validate_env (correctly) rejects non-rig paths -- so
  # let it use its own rig-namespace default instead of inheriting the seam.
  unset DR_VPS_NET_STATE
}

@test "dr-vps: no verb -> usage (2)" {
  run "$BIN/dr-vps"; [ "$status" -eq 2 ]
}

@test "dr-vps: unknown verb -> usage (2)" {
  run "$BIN/dr-vps" frobnicate; [ "$status" -eq 2 ]
}

@test "dr-vps --help -> 0" {
  run "$BIN/dr-vps" --help; [ "$status" -eq 0 ]
}

@test "dr-vps version -> 0; prints version + driver_version + a 16-hex build fingerprint" {
  run "$BIN/dr-vps" version
  [ "$status" -eq 0 ]
  [[ "$output" == *"version: "* ]]
  [[ "$output" == *"driver_version: "* ]]
  echo "$output" | grep -Eq 'build_fingerprint: [0-9a-f]{16}'          # a real per-build fingerprint, not 'unknown', in-tree
}

@test "dr-vps version: surplus argument -> usage (2)" {
  run "$BIN/dr-vps" version extra; [ "$status" -eq 2 ]
}

@test "dr-vps exec-detach/exec-status/exec-output/exec-errors: verb dispatch + arity + bad-job-id guard" {
  run "$BIN/dr-vps" exec-detach onlyone; [ "$status" -eq 2 ]           # exec-detach needs <vm> <cmd>
  run "$BIN/dr-vps" exec-status; [ "$status" -eq 2 ]                    # exec-status needs <job>
  run "$BIN/dr-vps" exec-output; [ "$status" -eq 2 ]                    # exec-output needs <job>
  run "$BIN/dr-vps" exec-errors; [ "$status" -eq 2 ]                    # exec-errors needs <job>
  run "$BIN/dr-vps" exec-status '../etc/passwd'; [ "$status" -eq 2 ]    # non-hex job id (path traversal) rejected
  run "$BIN/dr-vps" exec-errors '../etc/passwd'; [ "$status" -eq 2 ]    # same fence on the stderr reader
  run "$BIN/dr-vps" exec-status ffffffffffffffffffffffffffffffff        # valid hex, unknown -> missing (rc 0)
  [ "$status" -eq 0 ]; [ "$output" = "state=missing" ]
}

@test "dr-vps doctor on a VIRGIN install (store never initialized) -> no 'cannot read the VM store' refusal" {
  # Live nested-dogfood finding (2026-07-16): a fresh install's FIRST `dr-vps doctor` died E_CAP
  # "no such table: vms" -- doctor was the only store-reading dispatch without dr_vps_store_init,
  # so the installer's own documented sanity command failed on a virgin host (non-gating, unnoticed).
  export DR_VPS_FACT_KVM=ok DR_VPS_FACT_LIBVIRT=ok DR_VPS_FACT_RAM_MB=60000 DR_VPS_FACT_DISK_MB=80000
  export DR_VPS_FACT_NESTED=Y DR_VPS_FACT_TOOLS='{"cloud_localds":true,"nft":true,"qemu_img":true}'
  export DR_VPS_FACT_CONSOLE=ok DR_VPS_FACT_CONSOLE_REAPER=fresh
  # DR_VPS_FACT_CONSOLE_ADMIT deliberately NOT seamed: the REAL admission path must read the store,
  # which on a virgin state dir exists only if the dispatch initializes it. Only the console LOG DIR
  # is redirected (its free-space probe needs an existing dir in the sandbox).
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR"
  run "$BIN/dr-vps" doctor
  [[ "$output" != *"cannot read the VM store"* ]]
  [ "$status" -eq 0 ]
}

@test "dr-vps verify: matching sha256 -> 0; mismatch -> 18 (binary validation, fail-closed)" {
  echo "a binary blob" >"$BATS_TEST_TMPDIR/blob"
  sha=$(sha256sum "$BATS_TEST_TMPDIR/blob" | awk '{print $1}')
  run "$BIN/dr-vps" verify "$BATS_TEST_TMPDIR/blob" "$sha"; [ "$status" -eq 0 ]
  run "$BIN/dr-vps" verify "$BATS_TEST_TMPDIR/blob" "0000000000000000000000000000000000000000000000000000000000000000"
  [ "$status" -eq 18 ]
}

@test "dr-vps verify: too few args -> usage (2)" {
  run "$BIN/dr-vps" verify /tmp/x; [ "$status" -eq 2 ]
}

@test "dr-vps create: too few args -> usage (2)" {
  run "$BIN/dr-vps" create onlyname; [ "$status" -eq 2 ]
}

@test "dr-vps create: a value flag with a MISSING value -> usage (2), not a bash unbound abort" {
  run "$BIN/dr-vps" create n1 fedora44 --mem
  [ "$status" -eq 2 ]
  [[ "$output" == *"needs a value"* ]]
}

@test "dr-vps exec/push/pull: SURPLUS argv -> usage (2), never a silently truncated guest command" {
  run "$BIN/dr-vps" exec vm1 echo hello; [ "$status" -eq 2 ]   # unquoted cmd would run as just `echo`
  run "$BIN/dr-vps" push vm1 ./f /r extra; [ "$status" -eq 2 ]
  run "$BIN/dr-vps" pull vm1 /r extra; [ "$status" -eq 2 ]
}

@test "dr-vps fixed-argv verbs (status/inspect/console/build/gate/exec-status|output|errors): SURPLUS argv -> usage (2)" {
  # These handlers consume fixed positionals, so a surplus arg (typo'd flag, mis-split word) was
  # silently DISCARDED -- `dr-vps status vm1 --typo` succeeded as if the flag existed.
  run "$BIN/dr-vps" status vm1 --typo;  [ "$status" -eq 2 ]
  run "$BIN/dr-vps" inspect vm1 extra;  [ "$status" -eq 2 ]
  run "$BIN/dr-vps" console vm1 extra;  [ "$status" -eq 2 ]
  run "$BIN/dr-vps" build fedora44 extra; [ "$status" -eq 2 ]
  run "$BIN/dr-vps" gate lifecycle vm1 extra; [ "$status" -eq 2 ]
  run "$BIN/dr-vps" exec-status ffffffffffffffffffffffffffffffff extra; [ "$status" -eq 2 ]
  run "$BIN/dr-vps" exec-output ffffffffffffffffffffffffffffffff extra; [ "$status" -eq 2 ]
  run "$BIN/dr-vps" exec-errors ffffffffffffffffffffffffffffffff extra; [ "$status" -eq 2 ]
  # the watcher's appended `--owner UID` still passes the exact-arity gate on the job readers
  run "$BIN/dr-vps" exec-status ffffffffffffffffffffffffffffffff --owner 4001
  [ "$status" -eq 0 ]; [ "$output" = "state=missing" ]
  # zero-positional verbs (re-review): surplus argv was silently ignored on these too
  run "$BIN/dr-vps" distros extra;      [ "$status" -eq 2 ]
  run "$BIN/dr-vps" list extra;         [ "$status" -eq 2 ]
  run "$BIN/dr-vps" snap-ls bogusarg;   [ "$status" -eq 2 ]
  run "$BIN/dr-vps" snap-ls --owner 4001 extra; [ "$status" -eq 2 ]   # only a trailing --owner pair is allowed
}

@test "dr-vps distros: empty store -> 0, no rows" {
  run "$BIN/dr-vps" distros; [ "$status" -eq 0 ]; [ -z "$output" ]
}

@test "dr-vps list: empty -> 0" {
  run "$BIN/dr-vps" list; [ "$status" -eq 0 ]
}

@test "dr-vps wait: too few args -> usage (2)" {
  run "$BIN/dr-vps" wait; [ "$status" -eq 2 ]
}

@test "dr-vps wait: is GUESTEXEC-GATED at the CLI -- an ungatable vm is refused, never reaches SSH" {
  # wait reaches the guest over SSH, so the CLI must run the FULL guestexec gate first (not just
  # lifecycle). With no store row the gate refuses, so wait never dispatches SSH. (The happy
  # ready-via-ssh path is covered faithfully in domain.bats, which builds a real gated VM.)
  cat >"$BATS_TEST_TMPDIR/fv" <<'EOF'
#!/usr/bin/env bash
case "$*" in *domifaddr*) echo " vnet0 52:54:00 ipv4 10.123.0.5/24";; esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fv"
  run env DR_VIRSH="$BATS_TEST_TMPDIR/fv" DR_SSH=true "$BIN/dr-vps" wait someid 3
  [ "$status" -ne 0 ]                          # gated -> refused, not a "ready" 0
}

@test "dr-vps doctor: real gate REFUSES for the agent (12 no-kvm OR 13 libvirt-unreachable, never 0)" {
  run env -u DR_VPS_TEST_SEAMS "$BIN/dr-vps" doctor
  [ "$status" -eq 12 ] || [ "$status" -eq 13 ]   # depends on whether qemu-kvm/libvirtd is installed
}

@test "dr-vps-setup --dry-run: NO changes, exits 0, detects a package manager" {
  run "$BIN/dr-vps-setup" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"package manager"* ]]
  [[ "$output" == *"re-login"* ]]            # the group gotcha is surfaced
}

@test "dr-vps-setup: not root + not dry-run -> need-root refusal (12)" {
  run "$BIN/dr-vps-setup"
  [ "$status" -eq 12 ]
}

@test "dr-vps-setup --uninstall --dry-run: 0, no changes" {
  run "$BIN/dr-vps-setup" --uninstall --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"UNINSTALL"* ]]
}

@test "dr-vps-setup: unknown flag -> 2" {
  run "$BIN/dr-vps-setup" --bogus; [ "$status" -eq 2 ]
}

@test "watcher launcher EXPORTS the conditional-:= env to python (set -a), not shell-only" {
  grep -q 'set -a' "$BIN/drvps-rigctl"                     # allexport around the env source
  grep -q 'set -a' "$BIN/drvps-rigreaper"
  # functional: the launcher's set-a + source pattern makes a ':='-assigned var visible to PYTHON
  # (a plain source would leave it shell-only -> the watcher's os.environ[...] would KeyError).
  local envf="$BATS_TEST_TMPDIR/env"; printf ': "${DR_VPS_SPOOL_DIR:=/var/spool/distro-rig-vps}"\n' >"$envf"
  run bash -c "set -a; . '$envf'; set +a; python3 -c 'import os; print(os.environ[\"DR_VPS_SPOOL_DIR\"])'"
  [ "$status" -eq 0 ]
  [ "$output" = "/var/spool/distro-rig-vps" ]
}

@test "installer: the agent spool lives OUTSIDE the qemu-private state tree (drvpsctl can traverse)" {
  # The agent is only in drvpsctl, not the qemu group; a spool under /var/lib/distro-rig-vps (0750
  # :qemu) would be untraversable. Assert the spool base is a separate parent + the postcondition exists.
  grep -q 'DR_VPS_SPOOL_BASE:=/var/spool/distro-rig-vps' "$BIN/dr-vps-setup"
  grep -q 'spool .* is under the qemu-private' "$BIN/dr-vps-setup"   # fail-closed postcondition
  ! grep -q 'sp="$DR_VPS_SYS_STATE/spool"' "$BIN/dr-vps-setup" || false       # not the old buried path
}

@test "installer: step_console (virt_log_t console dir + BOUNDED virtlogd) is wired into do_install (observability)" {
  grep -q 'step_console()' "$BIN/dr-vps-setup"                          # the step exists
  grep -q "semanage fcontext -a -t virt_log_t" "$BIN/dr-vps-setup"     # console dir labeled for virtlogd writes
  grep -q '/etc/libvirt/virtlogd.conf' "$BIN/dr-vps-setup"             # bounded rotation config written
  grep -q 'step_state && step_console && step_env' "$BIN/dr-vps-setup" # runs after state, before env
}

@test "installer: step_env PERSISTS the console knobs so an install-time override reaches runtime (convergence r1)" {
  grep -q 'DR_VPS_CONSOLE_LOG_DIR:=' "$BIN/dr-vps-setup"               # the runtime dir the installer set up
  grep -q 'DR_VPS_CONSOLE_MAX_VMS:=' "$BIN/dr-vps-setup"               # admission bound
  grep -q 'DR_VPS_CONSOLE_VIRTLOGD_MAX_SIZE:=' "$BIN/dr-vps-setup"     # per-VM cap source
}

@test "installer: an INJECTION/malformed console knob is REJECTED before it reaches the root-sourced env" {
  # these knobs are persisted into /etc/distro-rig-vps/env, which api.sh sources AS ROOT -- a '$(cmd)' or
  # non-integer override must fail validate_env (exit 2), never be written into the root-sourced file.
  DR_VPS_CONSOLE_MAX_VMS='$(touch /tmp/drvps-pwn-should-not-exist)' run "$BIN/dr-vps-setup" --dry-run
  [ "$status" -eq 2 ]
  [ ! -e /tmp/drvps-pwn-should-not-exist ]                            # the substitution never executed
  DR_VPS_CONSOLE_TAIL_MAX_BYTES=abc run "$BIN/dr-vps-setup" --dry-run; [ "$status" -eq 2 ]
  DR_VPS_CONSOLE_RESERVE_MARGIN=-1  run "$BIN/dr-vps-setup" --dry-run; [ "$status" -eq 2 ]
}

@test "installer: DR_VPS_PROXY_IP/SRC diverging from the bridge/guest-subnet is REJECTED" {
  # a custom proxy IP/src that isn't the bridge/guest-subnet makes squid bind an address guests can't
  # reach (guest proxy URL + nft cache_cidr are keyed to 10.123.0.1) -> setup must FAIL, not "succeed".
  DR_VPS_PROXY_IP=127.0.0.1 run "$BIN/dr-vps-setup" --dry-run
  [ "$status" -eq 2 ]; [[ "$output" == *"must equal the bridge"* ]]
  DR_VPS_PROXY_SRC=192.168.0.0/24 run "$BIN/dr-vps-setup" --dry-run
  [ "$status" -eq 2 ]; [[ "$output" == *"must equal the guest subnet"* ]]
  run "$BIN/dr-vps-setup" --dry-run; [ "$status" -eq 0 ]         # the matching defaults still pass
}

@test "installer: ssl_db at the SELinux-policy-labeled path + restorecon + squid error surfaced (first-contact SELinux fix)" {
  # squid's cert helper runs confined (squid_t); ssl_db must live where the stock policy labels it
  # squid_cache_t (/var/lib/ssl_db) AND be restorecon'd -- else installer-created files inherit
  # var_lib_t -> AVC denials -> squid never signals ready -> systemd start times out.
  grep -q '/var/lib/ssl_db -M' "$BIN/dr-vps-setup"            # sslcrtd_program uses the policy-labeled path
  ! grep -q '/var/lib/squid/ssl_db' "$BIN/dr-vps-setup" || false       # NOT the unlabeled /var/lib/squid/ssl_db
  grep -q 'restorecon -RF /var/lib/ssl_db' "$BIN/dr-vps-setup"   # relabel applied (no-op off SELinux)
  grep -q 'journalctl -u squid' "$BIN/dr-vps-setup"           # the not-listening check prints squid's real error
}

@test "installer _fs_guard_py putfile: write-ALL loop + partial-file cleanup (no truncated SSH key)" {
  # a single os.write can short-write -> a truncated VM ssh key installs 'successfully' then breaks
  # all guest ssh. The putfile guard must loop until all bytes are written and unlink on failure.
  grep -q 'while total < len(mv)' "$BIN/dr-vps-setup"          # write-all loop present
  grep -q 'os.unlink(leaf, dir_fd=dirfd)' "$BIN/dr-vps-setup"  # partial dest removed on any failure
  # and the inline guard still parses as valid python (a heredoc syntax error would break install)
  awk "/<<'PY'/{f=1;next} /^PY\$/{f=0} f" "$BIN/dr-vps-setup" >"$BATS_TEST_TMPDIR/g.py"
  python3 -m py_compile "$BATS_TEST_TMPDIR/g.py"
}

@test "dr-vps gate dispatch runs store_init -> migrates an UPGRADED store before gaterow reads new columns" {
  # simulate a pre-hardening store: a vms table WITHOUT domain_uuid/net. The gate path must run the
  # migration (store_init) before gaterow selects domain_uuid, else every gated verb refuses legit VMs.
  sqlite3 "$DR_VPS_DB" "CREATE TABLE vms(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, overlay TEXT, egress_gen TEXT NOT NULL DEFAULT '0', ttl_hours INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'pending', generation INTEGER NOT NULL DEFAULT 0, name TEXT, project TEXT);"
  ! sqlite3 "$DR_VPS_DB" "SELECT domain_uuid FROM vms;" >/dev/null 2>&1 || false   # old schema: column absent
  run "$BIN/dr-vps" gate lifecycle ghostvm                                # dispatch -> store_init -> migrate
  # the gate ran the migration: the new columns now EXIST (this SELECT succeeds only post-migration)
  sqlite3 "$DR_VPS_DB" "SELECT domain_uuid, net FROM vms;" >/dev/null 2>&1
}

@test "installer: DR_VPS_NET_STATE is persisted to BOTH the env file and the egress unit" {
  # The marker the ROOT egress apply WRITES must match the one the watcher/guard READ. A custom
  # DR_VPS_NET_STATE that setup validates but never persists -> setup succeeds while runtime rejects
  # on the default marker. Assert statically (project convention for the root installer).
  grep -q 'DR_VPS_NET_STATE:=' "$BIN/dr-vps-setup"            # -> /etc/distro-rig-vps/env (watcher/guard/CLI)
  grep -q 'Environment=DR_VPS_NET_STATE=' "$BIN/dr-vps-setup" # -> the egress unit that WRITES the marker
}

@test "installer: drvps-egress is RETRIGGERABLE -- a timer + NO RemainAfterExit (so re-apply fires)" {
  # The periodic nft re-assertion needs the oneshot to return to inactive; RemainAfterExit=yes would
  # make the timer's re-start a no-op. Assert the invariant statically on the generated unit text.
  grep -q 'drvps-egress.timer' "$BIN/dr-vps-setup"
  grep -q 'OnUnitActiveSec=' "$BIN/dr-vps-setup"
  ! grep -q 'RemainAfterExit=yes' "$BIN/dr-vps-setup" || false
}

@test "installer CA nameConstraints: _drvps_ca_nc output makes a VALID cert via real openssl (regression guard)" {
  # CIDR (IP:0.0.0.0/0) was rejected by OpenSSL -> the whole CA gen (and install) failed. The builder
  # must emit the address/mask form. Source the installer in an ISOLATED subshell (it defines its own
  # run()/say() that would otherwise shadow bats's run), build the cnf from _drvps_ca_nc, run openssl.
  cat >"$BATS_TEST_TMPDIR/cat.sh" <<SH
source "$BIN/dr-vps-setup" >/dev/null 2>&1 || true
nc=\$(_drvps_ca_nc "fedoraproject.org debian.org")
case "\$nc" in *"IP:0.0.0.0/0.0.0.0"*) ;; *) echo "BAD_NC:\$nc" >&2; exit 3;; esac
cnf=\$(mktemp)
{ printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\n'
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
  printf 'nameConstraints=critical,%s\n' "\$nc"; } >"\$cnf"
openssl req -new -newkey rsa:2048 -sha256 -days 1 -nodes -x509 -config "\$cnf" -extensions v3_ca -subj "/CN=t" -keyout /dev/null -out "$BATS_TEST_TMPDIR/ca.crt" 2>/dev/null
SH
  run bash "$BATS_TEST_TMPDIR/cat.sh"
  [ "$status" -eq 0 ]                                   # cert generates (the old CIDR form FAILED here)
  openssl x509 -in "$BATS_TEST_TMPDIR/ca.crt" -text -noout | grep -q 'Name Constraints'
}

@test "installer CA nameConstraints: cache CA VERIFIES a squid wildcard leaf yet rejects off-list (DR-3 regression guard)" {
  # DR-3: squid ssl-bump mints a leaf mimicking the origin's WILDCARD SAN (e.g. *.fedoraproject.org).
  # The OLD CA permitted only exact host FQDNs (dl.fedoraproject.org), so OpenSSL rejected the wildcard
  # with "permitted subtree violation (47)" and every proxied HTTPS fetch failed. The fix permits the
  # PARENT domain. Prove BOTH directions with real openssl: the wildcard leaf VERIFIES, and an off-list
  # mirror/domain is STILL rejected (the constraint must not become permit-all).
  cat >"$BATS_TEST_TMPDIR/dr3.sh" <<SH
set -e
source "$BIN/dr-vps-setup" >/dev/null 2>&1 || true
T="$BATS_TEST_TMPDIR"
# derive parents from a mirror allowlist (the real code path) then build the NC
printf '{"mirror_allowlist":["dl.fedoraproject.org","mirrors.fedoraproject.org","deb.debian.org"]}' > "\$T/fleet.json"
parents=\$(_drvps_ca_parents "\$T/fleet.json") || { echo "PARENTS_FAILED" >&2; exit 2; }
nc=\$(_drvps_ca_nc "\$parents")
case "\$nc" in *"permitted;DNS:fedoraproject.org"*) ;; *) echo "NO_PARENT:\$nc" >&2; exit 3;; esac
case "\$nc" in *"permitted;DNS:dl.fedoraproject.org"*) echo "STILL_EXACT:\$nc" >&2; exit 4;; esac
cacnf=\$(mktemp)
{ printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\n'
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
  printf 'nameConstraints=critical,%s\n' "\$nc"; } >"\$cacnf"
openssl req -new -newkey rsa:2048 -sha256 -days 1 -nodes -x509 -config "\$cacnf" -extensions v3_ca -subj "/CN=ca" -keyout "\$T/ca.key" -out "\$T/ca.crt" 2>/dev/null
mkleaf(){ local c="\$T/\$2.cnf"; printf '[req]\ndistinguished_name=dn\nreq_extensions=e\n[dn]\n[e]\nsubjectAltName=DNS:%s\n' "\$1" >"\$c"
  openssl req -new -newkey rsa:2048 -nodes -keyout /dev/null -out "\$T/\$2.csr" -subj "/CN=\$1" -config "\$c" 2>/dev/null
  openssl x509 -req -in "\$T/\$2.csr" -CA "\$T/ca.crt" -CAkey "\$T/ca.key" -CAcreateserial -days 1 -extfile "\$c" -extensions e -out "\$T/\$2.crt" 2>/dev/null; }
mkleaf '*.fedoraproject.org' wild
mkleaf 'dl.rockylinux.org'   offset
# the wildcard leaf (what squid mints) MUST verify under the parent-domain constraint
openssl verify -CAfile "\$T/ca.crt" "\$T/wild.crt" >/dev/null 2>&1 || { echo "WILDCARD_REJECTED" >&2; exit 20; }
# an off-list domain MUST still fail (constraint not permit-all)
openssl verify -CAfile "\$T/ca.crt" "\$T/offset.crt" >/dev/null 2>&1 && { echo "OFFLIST_ACCEPTED" >&2; exit 21; }
echo OK
SH
  run bash "$BATS_TEST_TMPDIR/dr3.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *OK* ]]
}

@test "installer CA parents: FAIL CLOSED on a multi-label public-suffix mirror (never emit permitted;DNS:co.uk)" {
  # A mirror under a public suffix (repo.example.co.uk) must NOT let last-two-labels widen the CA to
  # co.uk. _drvps_ca_parents must exit 2 and tell the operator to set mirror_ca_parents explicitly.
  cat >"$BATS_TEST_TMPDIR/psl.sh" <<SH
source "$BIN/dr-vps-setup" >/dev/null 2>&1 || true
printf '{"mirror_allowlist":["repo.example.co.uk"]}' > "$BATS_TEST_TMPDIR/f.json"
out=\$(_drvps_ca_parents "$BATS_TEST_TMPDIR/f.json" 2>&1); rc=\$?
echo "rc=\$rc"
case "\$out" in *permitted*) echo "LEAKED_PERMIT" ;; esac   # must NEVER emit a permitted;DNS: entry
SH
  run bash "$BATS_TEST_TMPDIR/psl.sh"
  [[ "$output" == *"rc=2"* ]]              # fail-closed
  [[ "$output" != *"LEAKED_PERMIT"* ]]     # never emitted permitted;DNS:co.uk
}

@test "installer CA parents: EXPLICIT mirror_ca_parents used verbatim + canonical (order-insensitive)" {
  cat >"$BATS_TEST_TMPDIR/canon.sh" <<SH
source "$BIN/dr-vps-setup" >/dev/null 2>&1 || true
# explicit list wins over derivation; two different orders must yield the SAME canonical output.
# The mirror_allowlist must be COVERED by the parents.
printf '{"mirror_ca_parents":["debian.org","fedoraproject.org"],"mirror_allowlist":["dl.fedoraproject.org","deb.debian.org"]}' > "$BATS_TEST_TMPDIR/a.json"
printf '{"mirror_ca_parents":["fedoraproject.org","debian.org"],"mirror_allowlist":["deb.debian.org","dl.fedoraproject.org"]}' > "$BATS_TEST_TMPDIR/b.json"
a=\$(_drvps_ca_parents "$BATS_TEST_TMPDIR/a.json")
b=\$(_drvps_ca_parents "$BATS_TEST_TMPDIR/b.json")
echo "a=[\$a] b=[\$b]"
[ "\$a" = "\$b" ] || { echo NOT_CANONICAL >&2; exit 5; }
case "\$a" in *fedoraproject.org*debian.org*|*debian.org*fedoraproject.org*) ;; *) echo MISSING >&2; exit 6;; esac
echo CANON_OK
SH
  run bash "$BATS_TEST_TMPDIR/canon.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *CANON_OK* ]]
}

@test "installer CA parents: FAIL CLOSED when a mirror is NOT covered by the explicit parents" {
  # explicit mirror_ca_parents that does not cover a mirror_allowlist host would re-introduce DR-3 for
  # that mirror (its bumped cert violates the CA constraint) -- must fail closed, not silently ship it.
  cat >"$BATS_TEST_TMPDIR/cov.sh" <<SH
source "$BIN/dr-vps-setup" >/dev/null 2>&1 || true
printf '{"mirror_ca_parents":["debian.org"],"mirror_allowlist":["dl.fedoraproject.org"]}' > "$BATS_TEST_TMPDIR/c.json"
out=\$(_drvps_ca_parents "$BATS_TEST_TMPDIR/c.json" 2>&1); rc=\$?
echo "rc=\$rc :: \$out"
SH
  run bash "$BATS_TEST_TMPDIR/cov.sh"
  [[ "$output" == *"rc=2"* ]]
  [[ "$output" == *"not covered"* ]]
}

@test "installer CA parents: auto-derive FAILS CLOSED for a non-known family mirror (no unsafe last-two-labels)" {
  # without explicit parents, a mirror outside the known default families must NOT be auto-derived
  # (last-two-labels can't tell a registrable domain from a public suffix). co.kr / a corp mirror both fail.
  cat >"$BATS_TEST_TMPDIR/unk.sh" <<SH
source "$BIN/dr-vps-setup" >/dev/null 2>&1 || true
for host in repo.example.co.kr mirror.mycorp.example; do
  printf '{"mirror_allowlist":["%s"]}' "\$host" > "$BATS_TEST_TMPDIR/u.json"
  out=\$(_drvps_ca_parents "$BATS_TEST_TMPDIR/u.json" 2>&1); rc=\$?
  echo "\$host -> rc=\$rc"
  [ "\$rc" = 2 ] || { echo "NOT_FAIL_CLOSED:\$host:\$out" >&2; exit 7; }
  case "\$out" in *permitted*) echo "LEAKED:\$out" >&2; exit 8;; esac   # the real leak = a permitted;DNS entry
done
echo UNK_OK
SH
  run bash "$BATS_TEST_TMPDIR/unk.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *UNK_OK* ]]
}

@test "installer validate_env REFUSES a shell-injection in a privileged path override (exit 2)" {
  # all inside the subshell -- do NOT source the installer in the test shell (it shadows bats's run()).
  local marker="$BATS_TEST_TMPDIR/pwn_marker"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_SYS_STATE='/x; touch $marker #' validate_env"
  [ "$status" -eq 2 ]                                   # rejected before any interpolation
  [ ! -f "$marker" ]                                    # the injected command never EXECUTED (key check)
}

@test "installer validate_env REJECTS semantically-dangerous overrides (system root / root user / default net)" {
  # incl. NON-RIG service dirs that pass the denylist but are not in the rig namespace (libvirt/squid)
  for ov in "DR_VPS_SYS_STATE=/etc" "DR_VPS_SYS_STATE=/var/lib" "DR_VPS_SYS_STATE=/var/lib/libvirt" \
            "DR_VPS_SPOOL_BASE=/var/spool" "DR_VPS_SPOOL_BASE=/var/spool/squid" \
            "DR_VPS_SERVICE_USER=root" "DR_VPS_NET_NAME=default" "DR_VPS_NET_NAME=rig2" \
            "DR_VPS_PROXY_IP=0.0.0.0" "DR_VPS_PROXY_SRC=0.0.0.0/0" \
            "DR_VPS_CACHE_MB=abc" "DR_VPS_CACHE_MAXOBJ_MB=1 x" "DR_VPS_EGRESS_REAPPLY_SEC=10;reboot" \
            "DR_VPS_NET_STATE=/etc/cron.d/drvps-clobber" "DR_VPS_NET_STATE=/tmp/victim" "DR_NFT=nft;reboot"; do
    run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; export ${ov%%=*}=\"${ov#*=}\"; validate_env"
    [ "$status" -eq 2 ] || { echo "override $ov was NOT rejected (status=$status)"; false; }
  done
  # the safe defaults must still PASS, and a rig-namespace override is accepted
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; validate_env"
  [ "$status" -eq 0 ]
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_SYS_STATE=/opt/distro-rig-vps/state validate_env"
  [ "$status" -eq 0 ]
}

@test "installer step_units: the root-tree safety guard runs BEFORE any unit file is written" {
  # the ancestor/ownership guard must precede the 'cat >/etc/systemd/system/...' writes, else a
  # writable-checkout --reapply-egress leaves POISONED units on disk before aborting.
  guard=$(grep -n '_assert_install_tree_safe "\$root"' "$BIN/dr-vps-setup" | head -1 | cut -d: -f1)
  firstwrite=$(grep -n 'cat >/etc/systemd/system/' "$BIN/dr-vps-setup" | head -1 | cut -d: -f1)
  [ -n "$guard" ] && [ -n "$firstwrite" ]
  [ "$guard" -lt "$firstwrite" ]                       # guard precedes the first unit write
}

@test "installer uninstall: the gated-destroy query uses the REAL column domain_uuid (not 'uuid')" {
  grep -q 'COALESCE(domain_uuid,' "$BIN/dr-vps-setup"
  ! grep -q 'COALESCE(uuid,' "$BIN/dr-vps-setup" || false        # the old typo would read zero rows -> orphan domains
}

@test "installer REFUSES a metacharacter-bearing install path (root-shell injection via \$SRC/\$root)" {
  # the checkout path is interpolated into root bash -c / env / unit ExecStart -- a path with shell
  # metachars would inject root commands. The charset guard at the top must refuse before any use.
  local base="$BATS_TEST_TMPDIR/r; touch $BATS_TEST_TMPDIR/pwn #"
  mkdir -p "$base"; cp -a "$BIN" "$DR_VPS_SRC" "$base"/ 2>/dev/null
  run bash -c "source '$base/bin/dr-vps-setup' >/dev/null 2>&1; echo SOURCED"
  [ "$status" -eq 2 ]                                    # refused at the charset guard
  [ ! -f "$BATS_TEST_TMPDIR/pwn" ]                       # the injected command never executed
}

@test "installer tree-safety guard runs BEFORE step_env (no env-file poisoning from an unsafe checkout)" {
  # _assert_install_tree_safe must precede the first privileged write (step_env writes DR_VPS_BIN); a
  # non-root-owned (charset-safe) checkout would otherwise poison /etc/distro-rig-vps/env before any
  # later step_units guard. Assert (a) the guard refuses a non-root tree, (b) it precedes the chain.
  local T="$BATS_TEST_TMPDIR/tree"; mkdir -p "$T/src" "$T/bin"; : >"$T/src/x.sh"; : >"$T/bin/y"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; _assert_install_tree_safe '$T'"
  [ "$status" -ne 0 ]                                   # non-root-owned tree refused
  for fn in do_install do_reapply_egress; do
    local g c
    g=$(awk "/^$fn\\(\\)/{f=1} f&&/_assert_install_tree_safe/{print NR; exit}" "$BIN/dr-vps-setup")
    c=$(awk "/^$fn\\(\\)/{f=1} f&&/if step_/{print NR; exit}" "$BIN/dr-vps-setup")
    [ -n "$g" ] && [ -n "$c" ] && [ "$g" -lt "$c" ]     # guard precedes the step chain
  done
}

@test "installer run()/run_sh are ARGV-based + injection-safe (no eval of interpolated values)" {
  # the structural defense: values are literal argv args (run) or quoted positional params (run_sh),
  # never eval'd. A value carrying ';touch X' must create a literal-named file, NOT execute the touch.
  local d="$BATS_TEST_TMPDIR/x"; mkdir -p "$d"
  cat >"$BATS_TEST_TMPDIR/sm.sh" <<'SH'
set --                                  # clear args so the installer arg-parser sees nothing
source "$BINDIR/dr-vps-setup" >/dev/null 2>&1
DRY_RUN=0
run install -d -m 0755 "$OUT/lit;touch $OUT/PWNED_RUN"
run_sh 'printf "%s" "$1" > "$2"' "v;touch $OUT/PWNED_SH" "$OUT/val.txt"
SH
  BINDIR="$BIN" OUT="$d" run bash "$BATS_TEST_TMPDIR/sm.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$d/PWNED_RUN" ]                                # run: the ';touch' was a literal arg, not a command
  [ ! -e "$d/PWNED_SH" ]                                 # run_sh: the value never became shell code
  [ "$(cat "$d/val.txt")" = "v;touch $d/PWNED_SH" ]      # run_sh value passed as a literal positional
}

@test "installer run() is ARGV-based -- executes \$@, never eval (structural injection defense)" {
  sed -n '/^run() {/,/^}/p' "$BIN/dr-vps-setup" | grep -q '"\$@"'         # invokes argv directly
  ! sed -n '/^run() {/,/^}/p' "$BIN/dr-vps-setup" | grep -qw eval || false        # no eval in the run() body
  ! sed -n '/^run_sh() {/,/^}/p' "$BIN/dr-vps-setup" | grep -qw eval || false     # run_sh uses bash -c on a LITERAL, no eval
}

@test "installer validates the service-user HOME before writing it to the env file (config-content injection)" {
  # the passwd home flows into /etc/distro-rig-vps/env (DR_VPS_SSH_KEY=$dhome/...), sourced as root.
  # both step_sshkey ($home) and step_env ($dhome) must _safe_path it.
  grep -q '_safe_path "$home"'  "$BIN/dr-vps-setup"
  grep -q '_safe_path "$dhome"' "$BIN/dr-vps-setup"
  # and _safe_path actually rejects a command-substitution home
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; _safe_path '/home/drvps\$(touch /tmp/x)' home"
  [ "$status" -eq 2 ]
}

@test "installer resolves the install path PHYSICALLY -- a symlinked logical path can't be persisted/swapped" {
  # HERE/SRC/root must be the canonical physical path (cd -P/pwd -P): the path is written into the env
  # file + unit ExecStart, so a symlinked logical path would let an attacker swap it post-install.
  local phys; phys=$(cd -P "$DR_VPS_SRC/.." && pwd -P)
  ln -sfn "$phys" "$BATS_TEST_TMPDIR/link"
  run bash -c "set --; source '$BATS_TEST_TMPDIR/link/bin/dr-vps-setup' >/dev/null 2>&1; echo \"\$HERE\""
  [ "$status" -eq 0 ]
  [[ "$output" != *"$BATS_TEST_TMPDIR/link"* ]]          # NOT the logical symlink path
  [ "$output" = "$phys/bin" ]                            # the physical target
}

@test "installer runs a root-only tree-safety PREFLIGHT before sourcing the API libs (no source-as-root of an unsafe tree)" {
  # the '. \$SRC/dr_vps_api.sh' source happens early; a root preflight (id -u = 0 + ownership/ancestor
  # check) must precede it so root never sources an attacker-controlled src tree.
  pre=$(grep -n 'PREFLIGHT (root only)' "$BIN/dr-vps-setup" | head -1 | cut -d: -f1)
  src=$(grep -n '\. "\$SRC/dr_vps_api.sh"' "$BIN/dr-vps-setup" | head -1 | cut -d: -f1)
  [ -n "$pre" ] && [ -n "$src" ] && [ "$pre" -lt "$src" ]
}

@test "installer IGNORES inherited tool-binary seams (DR_NFT) in production -- only honored under TEST_SEAMS=1" {
  # an inherited DR_NFT=/tmp/evil would be exec'd AS ROOT by dr_vps_net_apply; charset validation can't
  # stop a charset-safe attacker PATH, so the root installer must drop the seam outside test mode.
  run bash -c "set --; DR_NFT=/tmp/pwnft; unset DR_VPS_TEST_SEAMS; source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$DR_NFT\""
  [ "$status" -eq 0 ]; [ "$output" = nft ]                 # inherited override dropped -> trusted default
  run bash -c "set --; DR_NFT=/tmp/fake; DR_VPS_TEST_SEAMS=1; source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$DR_NFT\""
  [ "$output" = /tmp/fake ]                                # test seam still honored under TEST_SEAMS=1
}

@test "installer pins an absolute interpreter + trusted PATH (inherited-PATH root-exec seam closed)" {
  head -1 "$BIN/dr-vps-setup" | grep -qx '#!/bin/bash -p'                    # absolute interpreter + privileged (-p)
  grep -qE '^export PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$BIN/dr-vps-setup"  # PATH pinned before any command
  # functional: a fake 'bash' + tool earlier in PATH must NOT run (absolute shebang + pinned PATH)
  mkdir -p "$BATS_TEST_TMPDIR/pp"; printf '#!/bin/sh\ntouch %s/RAN\nexit 42\n' "$BATS_TEST_TMPDIR" >"$BATS_TEST_TMPDIR/pp/bash"
  chmod +x "$BATS_TEST_TMPDIR/pp/bash"
  PATH="$BATS_TEST_TMPDIR/pp:/usr/bin:/bin" run "$BIN/dr-vps-setup" --dry-run
  [ "$status" -eq 0 ]
  [ ! -e "$BATS_TEST_TMPDIR/RAN" ]                                           # the fake bash never executed
}

@test "installer scrubs bash-startup env (BASH_ENV + exported BASH_FUNC_*) -- no pre-guard root exec" {
  # bash startup runs BEFORE the script body: an inherited BASH_ENV is sourced, and exported BASH_FUNC_*
  # functions shadow unqualified commands (incl. in child shells). -p + a re-exec under env -i close both.
  rm -f "$BATS_TEST_TMPDIR/be" "$BATS_TEST_TMPDIR/fn"
  printf 'touch %s/be\n' "$BATS_TEST_TMPDIR" >"$BATS_TEST_TMPDIR/be_evil"
  BASH_ENV="$BATS_TEST_TMPDIR/be_evil" run "$BIN/dr-vps-setup" --dry-run
  [ ! -e "$BATS_TEST_TMPDIR/be" ]                                            # BASH_ENV not sourced
  run env "BASH_FUNC_id%%=() { touch $BATS_TEST_TMPDIR/fn; /usr/bin/id \"\$@\"; }" "$BIN/dr-vps-setup" --dry-run
  [ ! -e "$BATS_TEST_TMPDIR/fn" ]                                            # exported function not imported (parent or child)
}

@test "installer re-exec parses env NUL-safely + drops tool seams unconditionally as root (no newline smuggle)" {
  # (a) static: the re-exec keep-loop reads /proc/self/environ NUL-delimited, not 'env' line-parsing
  grep -q 'read -r -d' "$BIN/dr-vps-setup"
  grep -q '/proc/self/environ' "$BIN/dr-vps-setup"
  ! grep -q 'done < <(env)' "$BIN/dr-vps-setup" || false
  # (b) static: the seam-drop drops UNCONDITIONALLY when root (can't be kept via DR_VPS_TEST_SEAMS=1)
  grep -F '[ "$(id -u)" = 0 ] || [ "${DR_VPS_TEST_SEAMS' "$BIN/dr-vps-setup" >/dev/null
  # (c) functional: a value with embedded newlines must NOT smuggle a kept DR_NFT entry
  out=$(env -i "X=$(printf 'foo\nDR_NFT=/tmp/evil')" PATH=/usr/bin:/bin /bin/bash -c '
    k=(); while IFS= read -r -d "" e; do n="${e%%=*}"; case "$n" in DR_VPS_[A-Z_]*|DR_NFT) k+=("$n=${e#*=}");; esac; done < /proc/self/environ; printf "%s\n" "${k[@]}"')
  ! printf '%s' "$out" | grep -q 'DR_NFT=/tmp/evil' || false
}

@test "installer rejects an env path with a NON-root-writable ANCESTOR (symlink-swap TOCTOU on root fs ops)" {
  # DR_VPS_SYS_STATE=/home/<user>/distro-rig-vps/etc passes namespace+charset but its ancestor
  # /home/<user> is attacker-writable -> swap to a symlink after validation -> root install/rm resolves
  # elsewhere. _assert_ancestors_root must reject any non-root-owned/writable ancestor ABOVE the rig dir.
  mkdir -p "$BATS_TEST_TMPDIR/distro-rig-vps"     # BATS_TEST_TMPDIR is test-user-owned (writable ancestor)
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_SYS_STATE='$BATS_TEST_TMPDIR/distro-rig-vps/etc' validate_env"
  [ "$status" -eq 2 ]
  [[ "$output" == *ancestor* ]]
  # the rig defaults (root-owned ancestors) + a /opt rig path still PASS
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; validate_env"; [ "$status" -eq 0 ]
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_SYS_STATE=/opt/distro-rig-vps/state validate_env"; [ "$status" -eq 0 ]
}

@test "installer judges env paths LEXICALLY (realpath -ms) -- a symlink can't introduce the rig namespace" {
  # link -> a rig dir makes readlink -m resolve to a safe path; the guard must judge the LITERAL path
  # (realpath -ms, no symlink follow), so /tmp/.../link/etc has no rig namespace component -> rejected.
  ln -s /opt/distro-rig-vps "$BATS_TEST_TMPDIR/link"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_SYS_STATE='$BATS_TEST_TMPDIR/link/etc' validate_env"
  [ "$status" -eq 2 ]
  grep -q 'realpath -ms' "$BIN/dr-vps-setup"             # static: no symlink-following readlink -m
  ! grep -q 'readlink -m "\$1"' "$BIN/dr-vps-setup" || false
}

@test "installer _safe_mkdir_owned refuses a SYMLINK at a rig child (drvps->root out-of-tree chown/create)" {
  # the rig subtree is drvps-owned; drvps could plant a symlink at pool/seed/requests before a root
  # re-run. _safe_mkdir_owned (+ _assert_ancestors_root's symlink-everywhere check) must refuse it
  # BEFORE any chown -- so root never follows it out of tree.
  local T="$BATS_TEST_TMPDIR/distro-rig-vps"; mkdir -p "$T"; mkdir -p "$BATS_TEST_TMPDIR/outside"
  ln -s "$BATS_TEST_TMPDIR/outside" "$T/pool"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DRY_RUN=0; _safe_mkdir_owned '$T/pool' $(id -un) $(id -gn) 0750"
  [ "$status" -ne 0 ]                                    # refused
  [[ "$output" == *SYMLINK* || "$output" == *symlink* ]]
  [ "$(stat -c '%U' "$BATS_TEST_TMPDIR/outside")" = "$(id -un)" ]   # target NOT chowned by the installer
  # static: install/spool dirs use the no-follow helper, not raw `install -d` of the subtree
  grep -q '_safe_mkdir_owned "$DR_VPS_SYS_STATE/pool"' "$BIN/dr-vps-setup"
  grep -q '_safe_mkdir_owned "$sp/requests"' "$BIN/dr-vps-setup"
}

@test "installer: requests/ is drvps-ONLY 0700 (agent has NO spool write -> no poison-dir DoS)" {
  # The agent submits via the ingress socket; requests/ must NOT be agent(group)-writable. A
  # group-writable requests/ (the old 3730) let the agent `mkdir requests/x.json/` + `chmod 000` it,
  # which a NEVER-ROOT watcher cannot reclaim (can't traverse a 000 dir it doesn't own) -> an
  # unbounded host disk/inode DoS with no non-root remedy. Assert the drvps-only owner+group+mode.
  local line; line=$(grep -F '_safe_mkdir_owned "$sp/requests"' "$BIN/dr-vps-setup")
  [[ "$line" == *'"$DR_VPS_SERVICE_USER" "$DR_VPS_SERVICE_USER" 0700'* ]]   # owner==group==drvps, no group write
  [[ "$line" != *3730* ]]                                                    # not the old sticky+setgid group-writable
  [[ "$line" != *DR_VPS_CTL_GROUP* ]]                                        # requests/ is NOT drvpsctl-owned anymore
}

@test "installer step_units: the drvps-rigsubmit ingress socket + never-root handler are installed, enabled, torn down" {
  grep -qF 'drvps-rigsubmit.socket'                       "$BIN/dr-vps-setup"
  grep -qF 'drvps-rigsubmit@.service'                     "$BIN/dr-vps-setup"
  grep -qF 'ListenStream=/run/drvps-submit.sock'          "$BIN/dr-vps-setup"
  grep -qF 'SocketGroup=$DR_VPS_CTL_GROUP'                "$BIN/dr-vps-setup"   # ONLY the agent group may connect
  grep -qF 'SocketMode=0660'                              "$BIN/dr-vps-setup"
  grep -qF 'StandardInput=socket'                         "$BIN/dr-vps-setup"   # Accept=yes hands the socket as stdio
  grep -qF 'ExecStart=$root/bin/drvps-rigsubmit'          "$BIN/dr-vps-setup"
  grep -qF 'systemctl enable --now drvps-rigsubmit.socket' "$BIN/dr-vps-setup"
  grep -qF 'drvps-rigsubmit@*.service'                    "$BIN/dr-vps-setup"   # uninstall stops live handlers
  grep -qF 'drvps-rigsubmit@.service'                     "$BIN/dr-vps-setup"   # uninstall rm's the unit
  # the handler runs as the never-root service user (the whole runtime stays never-root)
  local blk; blk=$(sed -n '/drvps-rigsubmit@.service <<EOF/,/^EOF/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'User=$DR_VPS_SERVICE_USER'* ]]
  [[ "$blk" != *'User=root'* ]]
}

@test "installer step_sshkey uses no-follow ~/.ssh creation (drvps symlink at ~/.ssh can't chown out-of-tree)" {
  # ~drvps is drvps-owned; a symlink planted at ~/.ssh (or the keyfiles) must not make root chown/write
  # out of tree. .ssh via _safe_mkdir_owned + keyfiles via _safe_file_owned (fd-based, O_NOFOLLOW).
  local H="$BATS_TEST_TMPDIR/home"; mkdir -p "$H" "$BATS_TEST_TMPDIR/target"
  ln -s "$BATS_TEST_TMPDIR/target" "$H/.ssh"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DRY_RUN=0; _safe_mkdir_owned '$H/.ssh' $(id -un) $(id -gn) 0700"
  [ "$status" -ne 0 ]
  [ "$(stat -c '%U' "$BATS_TEST_TMPDIR/target")" = "$(id -un)" ]     # target NOT chowned
  grep -q '_safe_mkdir_owned "$home/.ssh"' "$BIN/dr-vps-setup"       # step_sshkey uses the no-follow helper
  grep -q '_safe_put_file "$keyf"' "$BIN/dr-vps-setup"               # keyfiles fd-INSTALLED (O_EXCL|O_NOFOLLOW) from a root temp
  grep -q 'ssh-keygen .* -f "$ktmp/k"' "$BIN/dr-vps-setup"           # generated in a root-owned temp, not the service dir
}

@test "installer fs guards are FD-based (openat O_NOFOLLOW + fchown/fchmod) -- race-free, not path-based" {
  grep -q 'O_NOFOLLOW' "$BIN/dr-vps-setup"                 # openat no-follow
  grep -q 'os.fchown' "$BIN/dr-vps-setup"; grep -q 'os.fchmod' "$BIN/dr-vps-setup"  # by-fd, race-free
  grep -q '_safe_file_owned "$sp/audit.log"' "$BIN/dr-vps-setup"   # audit.log uses the fd-based file helper
  # functional: _safe_file_owned refuses a symlinked file target (O_NOFOLLOW), same-uid create OK
  local me mg; me=$(id -un); mg=$(id -gn); local d="$BATS_TEST_TMPDIR/fd"; mkdir -p "$d" "$BATS_TEST_TMPDIR/ftgt"
  ln -s "$BATS_TEST_TMPDIR/ftgt/x" "$d/link"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DRY_RUN=0; _safe_file_owned '$d/link' $me $mg 0600"
  [ "$status" -ne 0 ]                                      # symlink target refused
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DRY_RUN=0; _safe_file_owned '$d/real' $me $mg 0600"
  [ "$status" -eq 0 ] && [ -f "$d/real" ]                  # fresh regular file created + owned
}

@test "installer confines DR_VPS_NET_STATE to /run (root-owned tmpfs, non-drvps-writable)" {
  # the marker is written path-based by net_apply -- a rig-namespace (drvps-owned) marker would be
  # symlink-swappable, so require /run.
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_NET_STATE=/var/lib/distro-rig-vps/nft.applied validate_env"
  [ "$status" -eq 2 ]
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_NET_STATE=/run/distro-rig-vps/nft.applied validate_env"
  [ "$status" -eq 0 ]
}

@test "installer drops DR_LIBVIRT_URI (a root-exec seam via libvirt qemu+ext ?command=) in production" {
  # qemu+ext:///system?command=/path makes `virsh -c` run an arbitrary command AS ROOT (via dr-vps
  # doctor). Not preserved through the re-exec allowlist; dropped in the root seam-drop -> safe default.
  run bash -c "set --; DR_LIBVIRT_URI='qemu+ext:///system?command=/tmp/pwn'; unset DR_VPS_TEST_SEAMS; source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$DR_LIBVIRT_URI\""
  [ "$output" = "qemu:///system" ]                        # attacker ext URI dropped -> trusted default
  ! grep -qE 'DR_LIBVIRT_URI\)' "$BIN/dr-vps-setup" || false        # not in the re-exec keep allowlist
  grep -q 'unset .*DR_LIBVIRT_URI' "$BIN/dr-vps-setup"     # dropped in the root seam-drop
}

@test "installer ssh key: a planted .pub symlink can't make root write a key out-of-tree (O_EXCL|O_NOFOLLOW put)" {
  # ssh-keygen -f writes .pub with O_CREAT|O_TRUNC (no O_NOFOLLOW) -> would follow a drvps-planted .pub
  # symlink (e.g. -> /root/.ssh/authorized_keys). Fix: generate in a root temp, fd-INSTALL with O_EXCL.
  local me mg; me=$(id -un); mg=$(id -gn)
  local d="$BATS_TEST_TMPDIR/ssh"; mkdir -p "$d" "$BATS_TEST_TMPDIR/authk"; echo ROOTKEYS >"$BATS_TEST_TMPDIR/authk/authorized_keys"
  echo FRESHKEY >"$BATS_TEST_TMPDIR/src"
  ln -s "$BATS_TEST_TMPDIR/authk/authorized_keys" "$d/key.pub"        # drvps pre-plants the .pub symlink
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DRY_RUN=0; _safe_put_file '$d/key.pub' $me $mg 0644 '$BATS_TEST_TMPDIR/src'"
  [ "$status" -ne 0 ]                                                 # refused (dest exists as a symlink)
  [ "$(cat "$BATS_TEST_TMPDIR/authk/authorized_keys")" = ROOTKEYS ]   # target NOT overwritten with the key
  ! grep -q 'ssh-keygen .* -f "$keyf"' "$BIN/dr-vps-setup" || false           # ssh-keygen no longer writes into the service dir
}

# ---- installer: detection spine ----

@test "installer detect_pm: os-release FAMILY (ID/ID_LIKE), not command existence" {
  # a Debian host with dnf installed for RPM tooling must still get apt; a rhel-like gets dnf.
  local d="$BATS_TEST_TMPDIR/osr"; mkdir -p "$d"
  printf 'ID=debian\n'                       >"$d/deb"
  printf 'ID=ubuntu\nID_LIKE=debian\n'       >"$d/ubu"
  printf 'ID=fedora\n'                       >"$d/fed"
  printf 'ID=rocky\nID_LIKE="rhel centos"\n' >"$d/rocky"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_OSRELEASE='$d/deb'   detect_pm"; [ "$output" = apt ]
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_OSRELEASE='$d/ubu'   detect_pm"; [ "$output" = apt ]
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_OSRELEASE='$d/fed'   detect_pm"; [ "$output" = dnf ]
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_OSRELEASE='$d/rocky' detect_pm"; [ "$output" = dnf ]
  # os-release is parsed as DATA, NEVER sourced: a crafted ID_LIKE="$(cmd)" must not run as root
  ! grep -qE '\. "\$osr"' "$BIN/dr-vps-setup" || false                       # no source/. of os-release
  grep -q '_osrelease_val()' "$BIN/dr-vps-setup"                    # data-parse helper present
  printf 'ID=fedora\nID_LIKE="$(touch %s/PWNED)"\n' "$d" >"$d/evil"; rm -f "$d/PWNED"
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; DR_VPS_OSRELEASE='$d/evil' detect_pm"
  [ ! -e "$d/PWNED" ]                                               # the command substitution did NOT execute
}

@test "installer: modular-libvirt portability -- units order against the DETECTED libvirt unit, not hardcoded libvirtd" {
  # a modular-only host ships virtqemud.service, not libvirtd.service. The generated units + enable
  # must key to $LIBVIRT_UNIT so ordering is against a real unit.
  grep -q '_libvirt_unit()' "$BIN/dr-vps-setup"
  grep -q 'virtqemud.service' "$BIN/dr-vps-setup"                 # the modular unit is a candidate
  grep -q 'systemctl enable --now "\$LIBVIRT_UNIT"' "$BIN/dr-vps-setup"
  # the egress + watcher units + squid drop-in interpolate the detected unit, not a bare literal
  grep -q 'After=\$LIBVIRT_UNIT' "$BIN/dr-vps-setup"
  grep -q 'Wants=\$LIBVIRT_UNIT' "$BIN/dr-vps-setup"
  ! grep -qE '^After=libvirtd\.service$'  "$BIN/dr-vps-setup" || false     # no hardcoded literal left in a unit body
  # default stays libvirtd.service so the common (Fedora/Debian) host behavior is unchanged
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$LIBVIRT_UNIT\""; [ "$output" = libvirtd.service ]
}

@test "installer step_preflight: unsupported distro FAILS CLOSED before any mutation" {
  # preflight must gate BEFORE step_deps/user/network. An unknown pm -> exit 11 with an actionable cause.
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; PM=unknown DRY_RUN=1 step_preflight"
  [ "$status" -eq 11 ]
  [[ "$output" == *"unsupported host distro"* ]]
  # step_preflight is the FIRST link in the do_install chain (precedes step_deps = first mutation)
  local chain; chain=$(grep -n 'if step_preflight && step_deps' "$BIN/dr-vps-setup" | head -1)
  [ -n "$chain" ]
  grep -q 'detect_host  *#' "$BIN/dr-vps-setup"                   # detect_host fills PM/LIBVIRT_UNIT/SELINUX_ON first
}

@test "installer step_preflight: /dev/kvm gate is skipped in --dry-run (agent can preview without KVM), enforced otherwise" {
  # the kvm check must be gated on non-dry so the unprivileged agent preview never trips it.
  grep -q '\[ "\$DRY_RUN" -ne 1 \]' "$BIN/dr-vps-setup"
  local blk; blk=$(sed -n '/^step_preflight() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'/dev/kvm'* ]]
  [[ "$blk" == *'no usable KVM'* ]]
}

@test "installer _preflight_collision: REAL CIDR-overlap detection, unowned-drvps0 fatal, force override" {
  local blk; blk=$(sed -n '/^_preflight_collision() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'collision preflight'* ]]                         # actionable fail-closed message
  [[ "$blk" == *'_cidr_overlaps_rig'* ]]                          # REAL overlap, not string-match
  [[ "$blk" == *'not owned by the drvps'* ]]                      # a stale/foreign drvps0 link is fatal
  [[ "$blk" == *'_own_net_active'* ]]                             # ownership via the marker helper (pipe-free)
  grep -q '^_own_net_active()' "$BIN/dr-vps-setup"
  local oblk; oblk=$(sed -n '/^_own_net_active() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$oblk" == *'_net_is_ours'* ]]                               # ownership is still marker-based inside the helper
  [[ "$oblk" == *'_lines_has'* ]]                                 # pipe-free membership (no `| grep -qx` under pipefail)
  [[ "$blk" == *'DR_VPS_FORCE_COLLISION'* ]]                      # explicit operator override exists
  [[ "$blk" == *'DRY_RUN'* ]]                                     # dry-run previews, never exits
  # python3 is REQUIRED at preflight so _cidr_overlaps_rig can't fail OPEN if python3 is absent
  grep -q 'python3 is required (fd-safe' "$BIN/dr-vps-setup"
  local pblk; pblk=$(sed -n '/^step_preflight() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$pblk" == *'have python3'* ]]
  # after libvirt is UP, a STRICT recheck (fail-closed if net-list unreadable) runs before defining our net
  grep -q '_collision_libvirt_strict()' "$BIN/dr-vps-setup"
  grep -q "cannot read 'virsh net-list' after enabling" "$BIN/dr-vps-setup"
  local lblk; lblk=$(sed -n '/^step_libvirt() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$lblk" == *'_collision_libvirt_strict'* ]]                  # called from step_libvirt (post-enable)
  # functional: the exact overlap cases the review named (miss under string-match) are detected; disjoint ones are clear
  for c in 10.123.0.254/24 10.123.1.1/16 10.123.0.0/24; do
    run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; _cidr_overlaps_rig '$c'"; [ "$status" -eq 0 ]
  done
  for c in 192.168.1.1/24 10.124.0.1/24; do
    run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; _cidr_overlaps_rig '$c'"; [ "$status" -ne 0 ]
  done
  # _net_ip_cidrs extracts both netmask + prefix forms from libvirt net XML
  run bash -c "source '$BIN/dr-vps-setup' >/dev/null 2>&1; printf '%s' \"<ip address='10.9.0.1' netmask='255.255.255.0'/>\" | _net_ip_cidrs"
  [ "$output" = "10.9.0.1/255.255.255.0" ]
}

# ---- installer: coexistence guards ----

@test "installer squid coexistence: a FOREIGN squid.conf is refused without --force-squid; ours carries a marker" {
  # the generated conf carries an ownership marker so re-runs recognize it; a foreign conf (no marker,
  # no prior .drvps-orig backup) is refused unless --force-squid.
  grep -qF 'distro-rig-vps-managed squid.conf' "$BIN/dr-vps-setup"          # marker written into the generated conf
  local blk; blk=$(sed -n '/^step_proxy() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'squid coexistence'* ]]                                     # the guard exists
  [[ "$blk" == *'FOREIGN (non-drvps) config'* ]]                            # actionable refusal
  [[ "$blk" == *'FORCE_SQUID'* ]]                                           # --force-squid override
  [[ "$blk" == *'grep -qF "$drvps_marker"'* ]]                              # recognizes its own prior conf (re-run safe)
  # refuse is based SOLELY on the missing marker, NOT on backup presence: a foreign conf
  # RESTORED after a prior takeover (so .drvps-orig exists) must STILL be refused. Pin the exact
  # marker-only refusal condition (.drvps-orig may appear only in the separate backup-once step).
  [[ "$blk" == *'if [ -f /etc/squid/squid.conf ] && ! grep -qF "$drvps_marker" /etc/squid/squid.conf; then'* ]]
  # --force-squid parses to FORCE_SQUID=1
  run bash -c "set -- --force-squid; source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$FORCE_SQUID\""
  [ "$output" = 1 ]
  # uninstall restores the operator's original (or removes ours) -- but ONLY if the rig owns squid
  grep -qF 'mv -f /etc/squid/squid.conf.drvps-orig /etc/squid/squid.conf' "$BIN/dr-vps-setup"
  grep -q '(uninstall) /etc/squid/squid.conf is not drvps-managed .* leaving squid untouched' "$BIN/dr-vps-setup"
}

@test "installer net coexistence: ownership by <metadata> MARKER; an UNMARKED net is refused (not destroyed) unless --adopt-simnet" {
  local blk xmlblk; blk=$(sed -n '/^step_libvirt() {/,/^}/p' "$BIN/dr-vps-setup")
  xmlblk=$(sed -n '/^_dr_vps_net_xml() {/,/^}/p' "$BIN/dr-vps-setup")   # the canonical XML generator (bridge-ip refactor)
  # our net XML carries a distinctive ownership marker; ownership is checked via _net_is_ours (not just bridge)
  grep -q 'DR_VPS_NET_MARKER' "$BIN/dr-vps-setup"
  grep -q '_net_is_ours()' "$BIN/dr-vps-setup"
  [[ "$xmlblk" == *'drvps:owner'* ]]                               # marker embedded in the defined net XML
  [[ "$blk" == *'_dr_vps_net_xml >"$x"'* ]]                        # step_libvirt defines FROM that generator
  [[ "$blk" == *'_net_is_ours "$DR_VPS_NET_NAME"'* ]]              # reconcile keys on the marker
  [[ "$blk" == *'NOT drvps-owned (no drvps metadata marker)'* ]]   # an unmarked net -> refuse
  [[ "$blk" == *'--adopt-simnet'* ]]                              # explicit override to take it over
  # the destroy/undefine of an unmarked net happens ONLY under _net_is_ours or --adopt-simnet, never blindly
  local ours adopt refuse
  ours=$(awk '/^step_libvirt\(\)/{f=1} f&&/if _net_is_ours "\$DR_VPS_NET_NAME"/{print NR; exit}' "$BIN/dr-vps-setup")
  refuse=$(awk '/^step_libvirt\(\)/{f=1} f&&/NOT drvps-owned/{print NR; exit}' "$BIN/dr-vps-setup")
  [ -n "$ours" ] && [ -n "$refuse" ] && [ "$ours" -lt "$refuse" ]
  # uninstall also destroys the net ONLY when owned/adopted
  grep -q '(uninstall) .* is not drvps-owned (no marker) -- leaving it' "$BIN/dr-vps-setup"
}

@test "installer net: --adopt-simnet RE-MARKS the adopted net (redefines from the marked XML -> one-time, not perpetual re-collision)" {
  # A net adopted from an OLDER drvps (no marker) is undefined+redefined from OUR canonical XML ($x), which
  # embeds <drvps:owner> -- so after ONE adopt the net is marked and every FUTURE upgrade takes the
  # _net_is_ours reconcile path (no re-collision). Structural: the net path has no live virsh seam.
  local blk xmlblk; blk=$(sed -n '/^step_libvirt() {/,/^}/p' "$BIN/dr-vps-setup")
  xmlblk=$(sed -n '/^_dr_vps_net_xml() {/,/^}/p' "$BIN/dr-vps-setup")   # canonical XML generator (bridge-ip refactor)
  [[ "$xmlblk" == *'<drvps:owner xmlns:drvps='* ]]                 # the canonical XML embeds the owner marker
  [[ "$xmlblk" == *'"$DR_VPS_NET_MARKER"'* ]]                      # ...interpolated from the marker constant
  [[ "$blk" == *'_dr_vps_net_xml >"$x"'* ]]                        # $x is written FROM that marked generator
  # the --adopt-simnet branch redefines the unmarked net from that SAME marked $x (undefine -> net-define "$x")
  local adopt; adopt=$(awk '/taking over an UNMARKED/{f=1} f{print} f&&/net-define "\$x"/{exit}' "$BIN/dr-vps-setup")
  [[ "$adopt" == *'net-undefine "$DR_VPS_NET_NAME"'* ]]            # tears down the old unmarked net
  [[ "$adopt" == *'net-define "$x"'* ]]                            # then redefines from the MARKED doc -> re-marks it
}

# ---- installer: SELinux auto-handling ----

@test "installer SELinux: install-tree restorecon before enabling units (203/EXEC class) + actionable diag on failure" {
  local blk; blk=$(sed -n '/^step_units() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'restorecon -RF "$root"'* ]]                       # relabel the install tree
  [[ "$blk" == *'container_file_t'* ]]                             # the failure class is documented
  # the relabel precedes the watcher enable (so the unit can exec the tree)
  local rl en
  rl=$(awk '/^step_units\(\)/{f=1} f&&/restorecon -RF "\$root"/{print NR; exit}' "$BIN/dr-vps-setup")
  en=$(awk '/^step_units\(\)/{f=1} f&&/enable --now drvps-rigctl.service/{print NR; exit}' "$BIN/dr-vps-setup")
  [ -n "$rl" ] && [ -n "$en" ] && [ "$rl" -lt "$en" ]
  # the watcher enable prints ls -Z + journal on failure (203/EXEC actionable), not a bare message
  [[ "$blk" == *'ls -Zd "$root/bin/drvps-rigctl"'* ]]
  [[ "$blk" == *'203/EXEC'* ]]
  # gated on SELinux (no-op off SELinux)
  [[ "$blk" == *'[ "$SELINUX_ON" = 1 ]'* ]]
  # FAIL-CLOSED: a failed relabel aborts before enabling units; not `|| true`-masked
  [[ "$blk" == *'FATAL (SELinux): restorecon failed on $root'* ]]
  ! [[ "$blk" == *'restorecon -RF "$root" >/dev/null 2>&1 || true'* ]] || false
  [[ "$blk" == *'still labeled container_file_t after restorecon'* ]]        # verify the launcher label post-relabel
}

@test "installer SELinux: stale /run/squid.pid removed before restart, ONLY when squid is inactive" {
  local blk; blk=$(sed -n '/^step_proxy() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'is-active --quiet squid'* ]]                      # guarded on inactive (never yank a running squid's pid)
  [[ "$blk" == *'rm -f /run/squid.pid'* ]]
  # the cleanup precedes the restart
  local rm re shm
  rm=$(awk '/^step_proxy\(\)/{f=1} f&&/rm -f \/run\/squid.pid/{print NR; exit}' "$BIN/dr-vps-setup")
  re=$(awk '/^step_proxy\(\)/{f=1} f&&/systemctl restart squid/{print NR; exit}' "$BIN/dr-vps-setup")
  [ -n "$rm" ] && [ -n "$re" ] && [ "$rm" -lt "$re" ]
  # same failure class, second residue (nested live 2026-07-12): stale /dev/shm/squid-* segments FATAL
  # the next start (Ipc::Mem::Segment "File exists"). NOT a pre-emptive sweep
  # (raced with any squid, since /dev/shm/squid-* is a GLOBAL namespace) -- instead RECOVERY only inside
  # the failed-restart branch, gated on the shm error in the journal AND pgrep proving NO squid (rc==1),
  # then one retry. So the /dev/shm rm must come AFTER the first `systemctl restart squid`, not before.
  [[ "$blk" == *'rm -f /dev/shm/squid-*'* ]]
  [[ "$blk" == *'Ipc::Mem::Segment'* ]]                           # scoped to the actual shm error
  [[ "$blk" == *'pgrep -x squid'* ]]
  [[ "$blk" == *'_prc'* ]] && [[ "$blk" == *'-eq 1'* ]]           # clean only on pgrep rc==1 (no squid)
  shm=$(awk '/^step_proxy\(\)/{f=1} f&&/rm -f \/dev\/shm\/squid-/{print NR; exit}' "$BIN/dr-vps-setup")
  # the FIRST `systemctl restart squid` (the recovery is triggered by ITS failure) precedes the shm rm
  [ -n "$shm" ] && [ -n "$re" ] && [ "$re" -lt "$shm" ]
}

@test "installer SELinux: storage label is idempotent + VERIFIED + fail-closed, not best-effort-suppressed" {
  local blk; blk=$(sed -n '/^step_state() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'fcontext -a -t virt_image_t'* ]]                  # add rule
  [[ "$blk" == *'fcontext -m -t virt_image_t'* ]]                  # idempotent modify if it already exists
  [[ "$blk" == *'restorecon -RF "$DR_VPS_SYS_STATE"'* ]]
  # EXACT type match: parse the SELinux type field, accept only virt_image_t/svirt_image_t
  [[ "$blk" == *'cut -d: -f3'* ]]
  [[ "$blk" == *'virt_image_t|svirt_image_t'* ]]
  [[ "$blk" == *'not virt_image_t/svirt_image_t'* ]]               # fail-closed on any other type
  [[ "$blk" == *'semanage is missing but SELinux is enabled'* ]]   # missing-tool is fatal, not silently skipped
  # gated on SELinux + dry-run safe (must NOT mutate policy in a preview)
  [[ "$blk" == *'[ "$DRY_RUN" -eq 1 ]'* ]]
  [[ "$blk" == *'[ "$SELINUX_ON" = 1 ]'* ]]
  # the OLD best-effort suppressed form is gone
  ! grep -q 'semanage fcontext -a -t virt_image_t "$1(/.*)?" 2>/dev/null; restorecon -R' "$BIN/dr-vps-setup" || false
}

# ---- installer: local hardening ----

@test "installer net: autostart failure is FAIL-CLOSED + verified (survives reboot), not masked" {
  local blk; blk=$(sed -n '/^step_libvirt() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'net-autostart failed'* ]]                         # autostart failure aborts
  ! [[ "$blk" == *'virsh net-autostart "$DR_VPS_NET_NAME" 2>/dev/null || true'* ]] || false   # the masked form is gone
  [[ "$blk" == *'_vp_net_autostart'* ]]                            # postcondition verifies autostart is enabled (via the predicate)
  [[ "$blk" == *'would not survive a reboot'* ]]
  grep -q "autostart:\[\[:space:\]\]\*yes" "$BIN/dr-vps-setup"     # the predicate (file scope) checks the "Autostart: yes" flag
}

@test "installer net: the autostart verify POLLS (bounded retry via the shared verify-poll), not a one-shot read racing socket-activated libvirt" {
  # A single net-info read right after net-autostart false-negatived on fc44 (virtnetworkd lags reflecting the
  # flag) -> install aborted though autostart WAS set. The verify must poll; net-autostart's success is
  # authoritative. Refactored 2026-07-06: the ad-hoc loop is now the SHARED _dr_vps_verify_poll primitive.
  local blk; blk=$(sed -n '/^step_libvirt() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$blk" == *'_dr_vps_verify_poll'*'_vp_net_autostart'* ]]      # autostart verify routes through the bounded poll
  [[ "$blk" == *'would not survive a reboot'* ]]                   # still fail-closed if never enabled
  # the shared primitive is genuinely BOUNDED (fixed try budget + inter-poll sleep + timeout fail), not read-once
  local pf; pf=$(sed -n '/^_dr_vps_verify_poll() {/,/^}/p' "$BIN/dr-vps-setup")
  [[ "$pf" == *'while [ "$i" -lt "$tries" ]'* ]]                   # bounded loop
  [[ "$pf" == *'sleep "$nap"'* ]]                                  # inter-poll wait
  [[ "$pf" == *'verify-poll TIMEOUT'* ]]                           # fail-closed on exhaustion (the negative-assertion trap)
}

@test "installer uninstall: the guest-enum SQL is VALID (single-quoted literals), runs without SQLite 'no such column'" {
  # SQLite reads "|"/"" as IDENTIFIERS -> 'no such column' -> do_uninstall fail-closed + refused to strip state
  # on any installed host (blocks every real uninstall). Extract the exact query + RUN it (behavioral).
  local blk; blk=$(sed -n '/^do_uninstall() {/,/^}/p' "$BIN/dr-vps-setup")
  ! [[ "$blk" == *'id||"|"||COALESCE(domain_uuid,"")'* ]] || false         # the buggy double-quoted form is gone
  local sql; sql=$(printf '%s\n' "$blk" | grep -oE "SELECT id\|\|.*FROM vms;" | head -1)
  [ -n "$sql" ]
  local db="$BATS_TEST_TMPDIR/store.db"
  sqlite3 "$db" "CREATE TABLE vms(id TEXT, domain_uuid TEXT); INSERT INTO vms VALUES('drvps-vm-a','u1'); INSERT INTO vms VALUES('drvps-vm-b',NULL);"
  run sqlite3 "$db" "$sql"
  [ "$status" -eq 0 ]                                              # no 'no such column'
  [[ "$output" == *"drvps-vm-a|u1"* ]]                            # id|uuid
  [[ "$output" == *"drvps-vm-b|"* ]]                              # NULL -> empty via COALESCE
}

@test "installer squid: parse stderr is SURFACED + a restart failure prints diagnostics" {
  local blk; blk=$(sed -n '/^step_proxy() {/,/^}/p' "$BIN/dr-vps-setup")
  # parse failure prints squid's real message (a build missing ssl-bump), not a bare line
  [[ "$blk" == *'squid -f "$conf" -k parse 2>&1 >/dev/null'* ]]
  [[ "$blk" == *'squid says:'* ]]
  ! [[ "$blk" == *'squid -f "$conf" -k parse >/dev/null 2>&1'* ]] || false  # the stderr-hiding form is gone
  # restart failure prints status+journal (was: run() aborts before the listener diagnostic)
  [[ "$blk" == *'squid restart FAILED'* ]]
  [[ "$blk" == *'journalctl -u squid -n 30'* ]]
  ! [[ "$blk" == *'run systemctl restart squid'* ]] || false                # no longer routed through run()
}

@test "installer _fs_guard_py: a non-regular leaf (dir/FIFO) at a FILE path is REFUSED, not chmod'd" {
  awk "/<<'PY'/{f=1;next} /^PY\$/{f=0} f" "$BIN/dr-vps-setup" >"$BATS_TEST_TMPDIR/g.py"
  local me mg d; me=$(id -un); mg=$(id -gn); d="$BATS_TEST_TMPDIR/m5"; mkdir -p "$d"
  # (a) a planted FIFO where a regular file is expected -> S_ISREG assert refuses (open flags miss this)
  mkfifo "$d/audit.log"
  run python3 "$BATS_TEST_TMPDIR/g.py" file "$d/audit.log" "$me" "$mg" 0640
  [ "$status" -ne 0 ]; [[ "$output" == *"not a regular file"* ]]
  # (b) a directory where a file is expected -> refused
  mkdir "$d/asdir"; run python3 "$BATS_TEST_TMPDIR/g.py" file "$d/asdir" "$me" "$mg" 0640
  [ "$status" -ne 0 ]
  # (c) a regular file where a dir is expected -> refused
  touch "$d/asfile"; run python3 "$BATS_TEST_TMPDIR/g.py" dir "$d/asfile" "$me" "$mg" 0750
  [ "$status" -ne 0 ]
  # control: a fresh regular file is created + owned
  run python3 "$BATS_TEST_TMPDIR/g.py" file "$d/fresh" "$me" "$mg" 0640
  [ "$status" -eq 0 ]; [ -f "$d/fresh" ]
  grep -q 'stat.S_ISREG' "$BIN/dr-vps-setup"                       # the type assert is present
}

# ---- installer: install-time gate self-test ----

@test "installer --gate-selftest: parses (both forms), routes through need_root, surfaces-but-never-auto-allows" {
  # arg parsing: value form + =form + missing-value error
  run bash -c "set -- --gate-selftest fedora44; source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$GATE_SELFTEST\""; [ "$output" = fedora44 ]
  run bash -c "set -- --gate-selftest=deb12;   source '$BIN/dr-vps-setup' >/dev/null 2>&1; echo \"\$GATE_SELFTEST\""; [ "$output" = deb12 ]
  run "$BIN/dr-vps-setup" --gate-selftest;      [ "$status" -eq 2 ]           # missing value
  # dispatch: --gate-selftest <x> routes to do_gate_selftest, which is root-gated (never mutates as non-root)
  run "$BIN/dr-vps-setup" --gate-selftest fedora44; [ "$status" -eq 12 ]      # need_root
  # the self-test reuses the REAL gate path + tears the probe down + NEVER auto-allows
  local blk; blk=$(sed -n '/^do_gate_selftest() {/,/^}/p' "$BIN/dr-vps-setup")
  # gates + destroys the CREATED VM ID (from create's stdout), NOT the name
  [[ "$blk" == *'gate guestexec "$probe_id"'* ]]                             # REAL gate on the id, not the name
  # NO leak, even mid-create: the deterministic id is PRECOMPUTED before create (so the
  # trap always has it), NO EXIT trap (fires after the local is gone), INT/TERM only, explicit destroy
  # on both paths, and the created id is verified against the precomputed one (no id-scheme drift leak).
  [[ "$blk" == *'probe_id="drvps-vm-$(printf'* ]]                             # id precomputed BEFORE the create window
  [[ "$blk" == *'created id'* ]] && [[ "$blk" == *'!= expected'* ]]           # drift guard destroys both + aborts
  ! grep -qE "^[[:space:]]*trap[^#]*\bEXIT\b" "$BIN/dr-vps-setup" || false             # no EXIT trap command anywhere
  [[ "$blk" == *"trap '_gst_cleanup; exit 130' INT TERM"* ]]                  # interrupt-only cleanup
  [[ "$blk" == *'"$cli" destroy "$probe_id" >/dev/null 2>&1 || true   # ALWAYS'* ]]  # explicit destroy both paths
  [[ "$blk" == *'trap - INT TERM'* ]]                                        # trap cleared before return
  [[ "$blk" == *'virsh dumpxml "$probe_id"'* ]]                              # surfaces the offending XML on failure (before destroy)
  # the precomputed id matches the real dr_vps_instance_id scheme (functional)
  run bash -c ". '$DR_VPS_SRC/dr_vps_api.sh' >/dev/null 2>&1; . '$DR_VPS_SRC/dr_vps_identity.sh' >/dev/null 2>&1; dr_vps_instance_id drvps-gate-selftest default"
  [ "$output" = "drvps-vm-$(printf '%s\037%s' drvps-gate-selftest default | sha256sum | awk '{print substr($1,1,16)}')" ]
  [[ "$blk" == *'DO NOT auto-allow'* ]]                                       # the hard limit is enforced in the message
  [[ "$blk" == *'add a NARROWED rule to src/dr_vps_gate.sh'* ]]              # surfaces for a HUMAN to curate
  ! [[ "$blk" == *'semanage'* ]] || false                                             # never mutates policy/whitelist itself
  # help documents both new flags
  run "$BIN/dr-vps-setup" --help; [[ "$output" == *"--gate-selftest"* ]] && [[ "$output" == *"--force-squid"* ]]
}

# ---- installer: dependency completeness ----

@test "installer: env-readable postcondition uses runuser (util-linux), NOT sudo (not a dep)" {
  # sudo is not in the package set; a minimal host would command-not-found on `sudo -u ... test`. runuser
  # is always present (util-linux) and needs no PAM auth as root.
  grep -q 'runuser -u "$DR_VPS_SERVICE_USER" -- test -r /etc/distro-rig-vps/env' "$BIN/dr-vps-setup"
  ! grep -qE 'sudo -u "\$DR_VPS_SERVICE_USER" test -r' "$BIN/dr-vps-setup" || false     # the sudo postcondition is gone
  # the DONE banner's acceptance hint is also sudo-free (runuser -l picks up new groups + HOME)
  grep -q "runuser -l \$DR_VPS_SERVICE_USER -c" "$BIN/dr-vps-setup"
}

@test "installer: semanage (policycoreutils-python-utils) is in the dnf dep set (SELinux Fedora)" {
  # a fresh SELinux-on Fedora without it would fatal LATE in step_state; install it up front.
  grep -qE 'PKGS_dnf=.*policycoreutils-python-utils' "$BIN/dr-vps-setup"
}

# ---- installer: Debian squid flavor ----

@test "installer: apt installs squid-openssl (SSL-bump flavor), not base squid" {
  # step_proxy generates an SSL-bump config unconditionally; Debian/Ubuntu base `squid` lacks SSL-bump
  # (it's in squid-openssl) -> a clean Debian host would fail squid -k parse / certgen discovery LATE.
  grep -qE 'PKGS_apt=.*\bsquid-openssl\b' "$BIN/dr-vps-setup"
  ! grep -qE 'PKGS_apt=.*[^-]\bsquid\b( |")' "$BIN/dr-vps-setup" || false      # not the bare non-SSL-bump squid
  # (the existing squid -k parse + certgen-not-found checks remain the fail-closed backstop)
  grep -q 'security_file_certgen not found' "$BIN/dr-vps-setup"
}
