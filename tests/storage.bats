#!/usr/bin/env bats
# Stage 4 -- storage safety: path-fence, COW overlays, backing-chain, seed lifecycle.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_identity.sh
  dr_vps_load dr_vps_store.sh
  dr_vps_load dr_vps_storage.sh
  dr_vps_store_init
  # seam cloud-localds: seed := the user-data file (lets us inspect what got written)
  cat >"$BATS_TEST_TMPDIR/fakelocalds" <<'EOF'
#!/usr/bin/env bash
# fake cloud-localds: bundle user-data ($2) + meta-data ($3) into the "seed" ($1)
cat "$2" "$3" >"$1"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fakelocalds"
  export DR_CLOUDLOCALDS="$BATS_TEST_TMPDIR/fakelocalds"
  KEY="$BATS_TEST_TMPDIR/id.pub"
  echo "ssh-ed25519 AAAASECRETKEYMATERIAL test@host" >"$KEY"
}

@test "PATH-FENCE control: overlay_delete refuses a path OUTSIDE the pool" {
  outside="$BATS_TEST_TMPDIR/evil.qcow2"; echo x >"$outside"
  run dr_vps_storage_overlay_delete "$outside"
  [ "$status" -ne 0 ]
  [ -f "$outside" ]                       # NOT deleted
}

@test "PATH-FENCE: traversal out of the pool is refused" {
  run dr_vps_storage_path_fence "$DR_VPS_POOL_DIR/../../etc/passwd"
  [ "$status" -ne 0 ]
}

@test "PATH-FENCE: the pool root itself is refused" {
  run dr_vps_storage_path_fence "$DR_VPS_POOL_DIR"
  [ "$status" -ne 0 ]
}

@test "PATH-FENCE: a real pool child resolves" {
  run dr_vps_storage_path_fence "$DR_VPS_POOL_DIR/vm1.qcow2"
  [ "$status" -eq 0 ]; [ "$output" = "$DR_VPS_POOL_DIR/vm1.qcow2" ]
}

@test "overlay_create: COW overlay backed by the pinned golden; backing_check passes" {
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  aid=$(dr_vps_golden_digest "$DR_VPS_POOL_DIR/g.qcow2")
  dr_vps_store_image_register "$aid" '{"distro":"fedora44"}' "$DR_VPS_POOL_DIR/g.qcow2"
  run dr_vps_storage_overlay_create "vm1" "$aid"; [ "$status" -eq 0 ]; ov="$output"
  [ -f "$ov" ]
  run dr_vps_storage_backing_check "$ov" "$DR_VPS_POOL_DIR/g.qcow2"; [ "$status" -eq 0 ]
}

@test "backing_check: a re-pointed backing file is caught (18)" {
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/g.qcow2" 2097152 65536
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/other.qcow2" 2097152 65536 "Z"
  qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/other.qcow2" -F qcow2 "$DR_VPS_POOL_DIR/o.qcow2" >/dev/null
  run dr_vps_storage_backing_check "$DR_VPS_POOL_DIR/o.qcow2" "$DR_VPS_POOL_DIR/g.qcow2"
  [ "$status" -eq 18 ]
}

@test "overlay_delete: a real pool overlay is removed" {
  echo data >"$DR_VPS_POOL_DIR/vmx.qcow2"
  run dr_vps_storage_overlay_delete "$DR_VPS_POOL_DIR/vmx.qcow2"; [ "$status" -eq 0 ]
  [ ! -e "$DR_VPS_POOL_DIR/vmx.qcow2" ]
}

@test "seed_build: ssh-key-only seed; 0640 not world-readable; key present in seed" {
  run dr_vps_storage_seed_build "vm1" "$KEY" "seq1"; [ "$status" -eq 0 ]; seed="$output"
  [ -f "$seed" ]
  perm=$(stat -c '%a' "$seed"); [ "$perm" = "640" ]
  grep -q "AAAASECRETKEYMATERIAL" "$seed"                 # key landed in the seed
  grep -q "ssh_pwauth: false" "$seed"                     # no password auth
}

@test "seed_build: cloud-localds ABSENT -> genisoimage fallback (volid cidata, graft-pinned names; el9)" {
  # EPEL9 packages NO cloud-utils/cloud-localds at all (live centos9 nested finding, 2026-07-16);
  # for a NoCloud seed cloud-localds IS genisoimage with -volid cidata over user-data/meta-data.
  # The recorder pins that ISO contract; graft-points force the in-ISO names whatever the temp paths.
  cat >"$BATS_TEST_TMPDIR/fakegeniso" <<'EOF'
#!/usr/bin/env bash
out=""; args="$*"
while [ "$#" -gt 0 ]; do case "$1" in -output) out="$2"; shift 2;; *) shift;; esac; done
printf '%s\n' "$args" >"${out}.argv"
printf 'ISO\n' >"$out"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fakegeniso"
  export DR_CLOUDLOCALDS="$BATS_TEST_TMPDIR/no-such-cloud-localds"    # tool absent (el9)
  export DR_GENISOIMAGE="$BATS_TEST_TMPDIR/fakegeniso"
  run dr_vps_storage_seed_build "vmgi" "$KEY" "seq1"; [ "$status" -eq 0 ]; seed="$output"
  [ -f "$seed" ]
  grep -q -- '-volid cidata' "${seed}.argv"                            # NoCloud label
  grep -qE -- '-graft-points .*user-data=' "${seed}.argv"              # pinned in-ISO names
  grep -qE -- ' meta-data=' "${seed}.argv"
  [ "$(stat -c '%a' "$seed")" = 640 ]                                  # same perms contract as the localds path
}

@test "seed_build: NEITHER cloud-localds nor genisoimage -> fails CLOSED (no seed, key temp cleaned)" {
  export DR_CLOUDLOCALDS="$BATS_TEST_TMPDIR/absent-localds" DR_GENISOIMAGE="$BATS_TEST_TMPDIR/absent-geniso"
  run dr_vps_storage_seed_build "vmno" "$KEY" "seq1"
  [ "$status" -ne 0 ]
  [ ! -e "$DR_VPS_SEED_DIR/vmno-seed.iso" ]
  # the 0600 key-bearing temp dir must not leak on the failure path
  [ -z "$(find "$DR_VPS_SEED_DIR" -maxdepth 1 -name 'seed.*' -type d 2>/dev/null)" ]
}

@test "SEED-SECRET control: the key never appears in seed_build output OR a set -x trace" {
  run dr_vps_storage_seed_build "vm2" "$KEY" "seq1"
  [[ "$output" != *AAAASECRETKEYMATERIAL* ]]               # not on stdout/stderr
  # run under xtrace; the key must not leak into the trace (passed by path, not value)
  trace=$(bash -x -c '. src/dr_vps_api.sh; . src/dr_vps_identity.sh; . src/dr_vps_store.sh; . src/dr_vps_storage.sh; dr_vps_storage_seed_build vm3 "'"$KEY"'" seq1' 2>&1 >/dev/null) || true
  [[ "$trace" != *AAAASECRETKEYMATERIAL* ]]
}

@test "seed_build: unique instance-id per seq (recreate re-runs cloud-init)" {
  s1=$(dr_vps_storage_seed_build "vmu" "$KEY" "seqA")
  cp "$s1" "$BATS_TEST_TMPDIR/seedA"
  s2=$(dr_vps_storage_seed_build "vmu" "$KEY" "seqB")
  ! grep -q 'instance-id: vmu-seqA' "$s2" || false
  grep -q 'instance-id: vmu-seqB' "$s2"
}

@test "seed DNF plumbing: proxy + pinned allowlisted repo + metalink-repo removal" {
  seed=$(dr_vps_storage_seed_build vmd "$KEY" seq1)
  grep -q 'proxy=http://10.123.0.1:3128' "$seed"               # use the cache proxy
  grep -q 'baseurl=https://dl.fedoraproject.org' "$seed"       # repos pinned to an allowlisted host
  grep -q 'rm -f /etc/yum.repos.d/fedora.repo' "$seed"         # drop Fedora's metalink repos
}

@test "seed APT family (Phase 3): routes apt through the cache proxy, NO dnf plumbing" {
  DR_VPS_DISTRO_FAMILY=apt run dr_vps_storage_seed_build vmapt "$KEY" seq1
  [ "$status" -eq 0 ]; seed="$output"
  grep -q 'Acquire::http::Proxy "http://10.123.0.1:3128/"' "$seed"  # apt -> cache proxy (trailing slash)
  grep -q '99drvps-proxy' "$seed"
  ! grep -q 'yum.repos.d' "$seed" || false                                   # not the dnf shape
}

@test "seed: an UNKNOWN distro family FAILS CLOSED (no silent no-plumbing boot)" {
  DR_VPS_DISTRO_FAMILY=bogus run dr_vps_storage_seed_build vmb "$KEY" seq1
  [ "$status" -ne 0 ]                                               # not 0 -> refused, not silent
}

@test "seed_build: an emitter failure CLEANS UP the key-bearing temp dir (no leak)" {
  DR_VPS_DISTRO_FAMILY=bogus run dr_vps_storage_seed_build vmleak "$KEY" seq1
  [ "$status" -ne 0 ]
  # the mktemp'd seed.XXXXXX/ (holding the 0600 user-data with the key) must NOT survive the failure
  run find "$DR_VPS_SEED_DIR" -maxdepth 1 -type d -name 'seed.*'
  [ -z "$output" ]
}

@test "seed_build: an UNREADABLE ssh key FAILS the build (no keyless seed) + leaves no temp dir" {
  cp "$KEY" "$BATS_TEST_TMPDIR/unreadable.pub"; chmod 000 "$BATS_TEST_TMPDIR/unreadable.pub"
  run dr_vps_storage_seed_build vmnokey "$BATS_TEST_TMPDIR/unreadable.pub" seq1
  chmod 644 "$BATS_TEST_TMPDIR/unreadable.pub"                      # restore so teardown can clean up
  [ "$status" -ne 0 ]                                              # cat failed -> build refused, not a keyless seed
  [ ! -e "$DR_VPS_SEED_DIR/vmnokey-seed.iso" ]
  run find "$DR_VPS_SEED_DIR" -maxdepth 1 -type d -name 'seed.*'; [ -z "$output" ]
}

@test "seed DNF recipe-driven (Phase 3): a recipe repo_content overrides the Fedora default" {
  DR_VPS_REPO_CONTENT=$'[rocky-drvps]\nbaseurl=https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os/\nenabled=1\n' \
  DR_VPS_REPO_REMOVE='/etc/yum.repos.d/rocky*.repo' run dr_vps_storage_seed_build vmr "$KEY" s
  [ "$status" -eq 0 ]; seed="$output"
  grep -q 'dl.rockylinux.org' "$seed"                              # uses the recipe's repo
  grep -q 'rm -f /etc/yum.repos.d/rocky' "$seed"                   # drops the recipe's repos
  ! grep -q 'dl.fedoraproject.org' "$seed" || false                         # NOT the Fedora default
}

@test "seed ZYPPER family (Phase 3): recipe repo + system proxy; needs repo_content" {
  DR_VPS_DISTRO_FAMILY=zypper DR_VPS_REPO_CONTENT=$'[oss-drvps]\nbaseurl=https://download.opensuse.org/distribution/leap/x\n' \
    run dr_vps_storage_seed_build vmz "$KEY" s
  [ "$status" -eq 0 ]; seed="$output"
  grep -q '/etc/zypp/repos.d/drvps.repo' "$seed"
  grep -q 'PROXY_ENABLED="yes"' "$seed"
  # missing repo_content -> fail closed
  DR_VPS_DISTRO_FAMILY=zypper DR_VPS_REPO_CONTENT="" run dr_vps_storage_seed_build vmz2 "$KEY" s
  [ "$status" -ne 0 ]
}

@test "seed APK family (Phase 3): persists the cache proxy env (Alpine)" {
  DR_VPS_DISTRO_FAMILY=apk run dr_vps_storage_seed_build vmk "$KEY" s
  [ "$status" -eq 0 ]; seed="$output"
  grep -q 'http_proxy=http://10.123.0.1:3128/' "$seed"
  grep -q '/etc/profile.d/drvps-proxy.sh' "$seed"
}

@test "seed_cleanup: removes the seed (path-fenced under seed dir)" {
  seed=$(dr_vps_storage_seed_build "vmc" "$KEY" "seq1")
  [ -f "$seed" ]
  run dr_vps_storage_seed_cleanup "vmc"; [ "$status" -eq 0 ]
  [ ! -e "$seed" ]
}

@test "CREATE-PATH FENCE: overlay_create + seed_build reject an unsafe vm_id" {
  run dr_vps_storage_overlay_create "../evil" "anyaid"; [ "$status" -eq 2 ]
  run dr_vps_storage_seed_build "../evil" "$KEY";       [ "$status" -eq 2 ]
  run dr_vps_storage_seed_build "a/b" "$KEY";           [ "$status" -eq 2 ]
}

@test "SEED FAIL-CLOSED: refuses (and leaves no seed) if the seed group can't be set" {
  export DR_VPS_SEED_GROUP="nosuchgroup_drvps_$$"
  run dr_vps_storage_seed_build "vmf" "$KEY" "seq1"
  [ "$status" -ne 0 ]
  [ ! -e "$DR_VPS_SEED_DIR/vmf-seed.iso" ]
}

@test "backing_check rejects a non-standalone golden (golden itself has a backing)" {
  dr_vps_mk_qcow2 "$DR_VPS_POOL_DIR/base.qcow2" 2097152 65536
  qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/base.qcow2" -F qcow2 "$DR_VPS_POOL_DIR/mid.qcow2" >/dev/null
  qemu-img create -f qcow2 -b "$DR_VPS_POOL_DIR/mid.qcow2"  -F qcow2 "$DR_VPS_POOL_DIR/ov.qcow2"  >/dev/null
  run dr_vps_storage_backing_check "$DR_VPS_POOL_DIR/ov.qcow2" "$DR_VPS_POOL_DIR/mid.qcow2"
  [ "$status" -eq 18 ]    # immediate backing matches, but 'mid' is not standalone
}

@test "console-tail (Stage-1): an EXISTING but unreadable (root-owned pre-change) log -> 'recreate to enable READABLE console'" {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  f=$(dr_vps_console_log_path vmpre); printf 'boot log' >"$f"; chmod 000 "$f"   # simulate a root-owned unreadable log
  run dr_vps_console_log_tail vmpre 100
  chmod 644 "$f"                                          # cleanup first so bats can remove the tmpdir
  [ "$status" -ne 0 ]
  [[ "$output" == *"recreate to enable READABLE console"* ]]
}

@test "console-tail (Stage-1): a MISSING log (append-off VM) -> 'recreate to enable' not-found" {
  export DR_VPS_CONSOLE_LOG_DIR="$BATS_TEST_TMPDIR/console"; mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"
  run dr_vps_console_log_tail vmnolog 100
  [ "$status" -ne 0 ]; [[ "$output" == *"recreate to enable"* ]]
}
