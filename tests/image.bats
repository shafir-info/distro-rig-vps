#!/usr/bin/env bats
# Stage 3 -- golden image supply chain: fetch/verify/bake/digest/provenance/register.
# Uses file:// fixtures + a seamed (no-op/fake) virt-customize; no network, no KVM.

load helpers

setup() {
  dr_vps_test_setup
  # a published cache CA is present on a real installed host (dr-vps-setup writes it); provide one so
  # the bake doesn't emit its (correct) "CA absent" warning into the build's captured output.
  export DR_VPS_CACHE_CA="$BATS_TEST_TMPDIR/cache-ca.crt"; echo "CACERT" >"$BATS_TEST_TMPDIR/cache-ca.crt"
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_identity.sh
  dr_vps_load dr_vps_store.sh
  dr_vps_load dr_vps_image.sh
  dr_vps_store_init
  export DR_VIRT_CUSTOMIZE=true          # no-op bake by default
  export DR_QEMU=true                     # net_shims resolves a "real qemu" without needing qemu-system here
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/cloud.qcow2" 2097152 65536
  SHA=$(sha256sum "$BATS_TEST_TMPDIR/cloud.qcow2" | awk '{print $1}')
  cat >"$BATS_TEST_TMPDIR/recipe.json" <<EOF
{"distro":"fedora44","upstream_url":"file://$BATS_TEST_TMPDIR/cloud.qcow2","upstream_sha256":"$SHA","packages":["systemd","tmux"]}
EOF
}

@test "build: fetch+verify+bake+digest+register -> artifact_id at content-addressed path" {
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^drvps-raw-v1-2097152-[0-9a-f]{64}$ ]]
  aid="$output"
  [ -f "$DR_VPS_POOL_DIR/$aid.qcow2" ]
  run dr_vps_store_image_get "$aid"; [ "$output" = "$DR_VPS_POOL_DIR/$aid.qcow2" ]
}

@test "build: ordering guard warns TTY-gated to stderr when /etc/distro-rig-vps/env is absent -- build goldens AFTER install" {
  # TTY-gated (like the build progress lines) so it never noises scripts/tests; the passing build test above
  # (stdout == bare artifact_id) already proves the stdout contract survives. Assert the guard's shape here.
  local blk; blk=$(sed -n '/^dr_vps_image_build() {/,/1\/5 fetch/p' "$DR_VPS_SRC/dr_vps_image.sh")
  [[ "$blk" == *'[ -t 2 ] && [ ! -e /etc/distro-rig-vps/env ]'* ]]   # TTY + not-installed gate
  [[ "$blk" == *'Build goldens AFTER'* ]]                            # actionable operator guidance
}

@test "bake failure carries the stable common-cause remediation (kernel chmod + appliance DNS + enable debug)" {
  # A bake failure attaches a version/locale-STABLE hint (no fragile log-scraping) naming the two common
  # Debian/Ubuntu build-host causes -- unreadable 0600 host kernel, and the systemd-resolved stub resolv.conf
  # the libguestfs appliance can't use -- plus how to get full libguestfs diagnostics.
  export DR_VIRT_CUSTOMIZE=/bin/false          # any nonzero bake, deterministic + host/root-independent
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"bake (virt-customize) failed"* ]]
  [[ "$output" == *"chmod 0644 /boot/vmlinuz"* ]]                                  # cause 1: kernel
  [[ "$output" == *"ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf"* ]] # cause 2: appliance DNS
  [[ "$output" == *"Common build-host causes"* ]]                                  # not falsely Debian/Ubuntu-scoped
  [[ "$output" == *"DR_VPS_LIBGUESTFS_DEBUG=1"* ]]                                 # full diagnostics
}

@test "bake: LIBGUESTFS debug/trace default to VALID off ('0', not '' or '1') so env parsing + backend survive" {
  # empty '' is an INVALID libguestfs boolean -> TRACE parse returns early -> DEBUG + LIBGUESTFS_BACKEND
  # are skipped. Defaults MUST be '0'.
  local blk; blk=$(sed -n '/dr_vps_image_bake() {/,/^}/p' "$DR_VPS_SRC/dr_vps_image.sh")
  [[ "$blk" == *'LIBGUESTFS_DEBUG="${DR_VPS_LIBGUESTFS_DEBUG:-0}"'* ]]
  [[ "$blk" == *'LIBGUESTFS_TRACE="${DR_VPS_LIBGUESTFS_TRACE:-0}"'* ]]
  ! [[ "$blk" == *'LIBGUESTFS_DEBUG="${DR_VPS_LIBGUESTFS_DEBUG:-1}"'* ]] || false   # not always-on
  ! [[ "$blk" == *':-}"'* ]] || false                                              # not the invalid empty default
  [[ "$blk" == *'LC_ALL=C'* ]]
}

@test "bake seam: every virt-customize FLAG is a REAL virt-customize option (recorder-blesses-anything guard, like the sysprep op-name check)" {
  # The bake RECORDER does not validate flags; an invalid one (cf. the sysprep 'cloud-init' op bug that only
  # surfaced on a real host) would pass the seam silently. Validate the flags the bake actually passes against
  # the real tool, when present; skip on a host without guestfs-tools.
  # extract the virt-customize flags from the arg-assembly lines (caargs/vcnet) + the CA-only invocation.
  # deliberately NOT the guest flags inside the --run-command probe string (those are $(...), not literals).
  local flags; flags=$(grep -E 'caargs=\(|vcnet=\(|DR_VIRT_CUSTOMIZE" --' "$DR_VPS_SRC/dr_vps_image.sh" | grep -oE '[-][-][a-z][a-z-]+' | sort -u)
  [ -n "$flags" ]                                                    # extraction found the bake flags
  command -v virt-customize >/dev/null 2>&1 || skip "virt-customize not installed -- flag validation needs the real tool"
  local valid; valid=$(virt-customize --long-options 2>/dev/null)
  local f
  for f in $flags; do printf '%s\n' "$valid" | grep -qx -- "$f" || { echo "INVALID virt-customize flag in bake: $f"; false; }; done
}

@test "TAMPERED-UPSTREAM control: wrong checksum -> verify refused (18)" {
  sed 's/"upstream_sha256":"[0-9a-f]*"/"upstream_sha256":"0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$BATS_TEST_TMPDIR/recipe.json" >"$BATS_TEST_TMPDIR/bad.json"
  run dr_vps_image_build "$BATS_TEST_TMPDIR/bad.json"
  [ "$status" -eq 18 ]
  # nothing registered on failure
  run dr_vps_image_ls; [ -z "$output" ]
}

@test "build is reproducible: same recipe+content -> same artifact_id" {
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"; a1="$output"
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"; a2="$output"
  [ "$a1" = "$a2" ]
}

@test "provenance round-trips (distro, artifact_id, recipe_hash present)" {
  aid=$(dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json")
  run dr_vps_image_provenance "$aid"; [ "$status" -eq 0 ]
  echo "$output" | jq -e --arg a "$aid" '.distro=="fedora44" and .artifact_id==$a and (.recipe_hash|length==64) and (.packages|index("tmux"))' >/dev/null
}

@test "distros lists the registered golden with its distro" {
  aid=$(dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json")
  run dr_vps_image_ls
  [[ "$output" == *"$aid"* ]]; [[ "$output" == *"fedora44"* ]]
}

@test "refresh: different content -> new artifact_id; old retained" {
  aid1=$(dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json")
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/cloud2.qcow2" 2097152 65536 "NEW"
  s2=$(sha256sum "$BATS_TEST_TMPDIR/cloud2.qcow2" | awk '{print $1}')
  cat >"$BATS_TEST_TMPDIR/r2.json" <<EOF
{"distro":"fedora44","upstream_url":"file://$BATS_TEST_TMPDIR/cloud2.qcow2","upstream_sha256":"$s2","packages":[]}
EOF
  aid2=$(dr_vps_image_refresh "$BATS_TEST_TMPDIR/r2.json")
  [ "$aid1" != "$aid2" ]
  run dr_vps_image_ls; [[ "$output" == *"$aid1"* ]]; [[ "$output" == *"$aid2"* ]]
}

@test "bake is actually invoked when packages are present" {
  cat >"$BATS_TEST_TMPDIR/fakevc" <<EOF
#!/usr/bin/env bash
echo invoked >"$BATS_TEST_TMPDIR/bake.marker"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fakevc"
  export DR_VIRT_CUSTOMIZE="$BATS_TEST_TMPDIR/fakevc"
  dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json" >/dev/null
  [ -f "$BATS_TEST_TMPDIR/bake.marker" ]
}

@test "FAILED-BAKE control: a nonzero virt-customize -> build fails, nothing registered (no unbaked golden)" {
  # negative control for the swallowed-bake class (a real live-KVM bug per STATUS): if the rc check
  # regresses, an UNBAKED image (missing packages + cache-CA trust) would register as a good golden.
  export DR_VIRT_CUSTOMIZE=/bin/false
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"bake"* ]]
  run dr_vps_image_ls; [ -z "$output" ]                     # nothing registered
}

@test "golden CA-bake injects the per-FAMILY trust anchor (dnf vs apt path)" {
  cat >"$BATS_TEST_TMPDIR/fakevc" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$BATS_TEST_TMPDIR/vcargs"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fakevc"; export DR_VIRT_CUSTOMIZE="$BATS_TEST_TMPDIR/fakevc"
  echo CACERT >"$BATS_TEST_TMPDIR/ca.crt"; export DR_VPS_CACHE_CA="$BATS_TEST_TMPDIR/ca.crt"
  dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json" >/dev/null            # dnf default
  grep -q -- "--copy-in $BATS_TEST_TMPDIR/ca.crt:/etc/pki/ca-trust/source/anchors/" "$BATS_TEST_TMPDIR/vcargs"
  grep -q -- "update-ca-trust extract" "$BATS_TEST_TMPDIR/vcargs"
  sed 's/"distro":"fedora44"/"distro":"debian13","family":"apt"/' "$BATS_TEST_TMPDIR/recipe.json" >"$BATS_TEST_TMPDIR/apt.json"
  dr_vps_image_build "$BATS_TEST_TMPDIR/apt.json" >/dev/null               # apt family -> Debian path
  grep -q -- "--copy-in $BATS_TEST_TMPDIR/ca.crt:/usr/local/share/ca-certificates/" "$BATS_TEST_TMPDIR/vcargs"
  grep -q -- "update-ca-certificates" "$BATS_TEST_TMPDIR/vcargs"
}

@test "build: recipe missing required fields -> usage (2)" {
  echo '{"distro":"x"}' >"$BATS_TEST_TMPDIR/incomplete.json"
  run dr_vps_image_build "$BATS_TEST_TMPDIR/incomplete.json"
  [ "$status" -eq 2 ]
}

@test "build REFUSES a backed (non-standalone) golden (18); nothing registered" {
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/base.qcow2" 2097152 65536
  qemu-img create -f qcow2 -b "$BATS_TEST_TMPDIR/base.qcow2" -F qcow2 "$BATS_TEST_TMPDIR/backed.qcow2" >/dev/null
  s=$(sha256sum "$BATS_TEST_TMPDIR/backed.qcow2" | awk '{print $1}')
  cat >"$BATS_TEST_TMPDIR/backed.json" <<EOF
{"distro":"fedora44","upstream_url":"file://$BATS_TEST_TMPDIR/backed.qcow2","upstream_sha256":"$s","packages":[]}
EOF
  run dr_vps_image_build "$BATS_TEST_TMPDIR/backed.json"
  [ "$status" -eq 18 ]
  run dr_vps_image_ls; [ -z "$output" ]
}

@test "build: zypper family WITHOUT repo_content -> USAGE refusal (2), nothing registered" {
  sed 's/"distro":"fedora44"/"distro":"opensuse-leap","family":"zypper"/' "$BATS_TEST_TMPDIR/recipe.json" >"$BATS_TEST_TMPDIR/zy.json"
  run dr_vps_image_build "$BATS_TEST_TMPDIR/zy.json"
  [ "$status" -eq 2 ]
  run dr_vps_image_ls; [ -z "$output" ]
}

@test "verify: an UPPERCASE-hex vendor sha256 is ACCEPTED (case-insensitive compare)" {
  printf 'payload' >"$BATS_TEST_TMPDIR/p"
  local up; up=$(sha256sum "$BATS_TEST_TMPDIR/p" | awk '{print toupper($1)}')
  run dr_vps_image_verify "$BATS_TEST_TMPDIR/p" "$up"
  [ "$status" -eq 0 ]
}

@test "build: missing cache CA -> REFUSED by default (no silent cache-untrusted golden); override builds" {
  export DR_VPS_CACHE_CA=/no/such/ca.crt                # absent CA
  # the setup's recipe has packages -> bake runs -> CA-absent must fail closed
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"
  [ "$status" -ne 0 ]
  run dr_vps_image_ls; [ -z "$output" ]                 # nothing registered
  # explicit override builds (deliberate no-proxy)
  export DR_VPS_ALLOW_NO_CACHE_CA=1
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"
  [ "$status" -eq 0 ]
}

@test "provenance FAILS CLOSED on a DB READ ERROR (E_VERIFY 18), distinct from absent (E_NOTFOUND 14)" {
  # absent image -> E_NOTFOUND (14): genuinely no such row (callers keep their back-compat default).
  run dr_vps_image_provenance "drvps-raw-v1-1-nope"; [ "$status" -eq 14 ]
  # a CORRUPT store (surrogate for a transient IO/lock read error) -> the SELECT errors. This must NOT look
  # like 'absent' -- a caller would otherwise seed a VM / register a snapshot with DEFAULT provenance. E_VERIFY.
  printf 'this is not a sqlite database' > "$DR_VPS_DB"
  run dr_vps_image_provenance "drvps-raw-v1-1-any"; [ "$status" -eq 18 ]
}

@test "build idempotent shortcut RE-DIGESTS -- a corrupted registered golden -> FAIL CLOSED, not false green" {
  aid=$(dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"); [ -n "$aid" ]
  printf 'CORRUPT-NOT-THE-REGISTERED-CONTENT' > "$DR_VPS_POOL_DIR/$aid.qcow2"   # tamper the registered golden
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"                        # rebuild same recipe -> same aid
  [ "$status" -eq 18 ]                          # E_VERIFY -- not a green idempotent no-op over corruption
  [[ "$output" == *"digest"* ]]
}

@test "a golden MOVE failure returns nonzero, not false success (the 'if ! cmd; rc=\$?' bug is fixed)" {
  [ "$(id -u)" -eq 0 ] && skip "root ignores directory perms"
  chmod 0555 "$DR_VPS_POOL_DIR"                          # pool read-only -> the mv $work -> $gpath fails
  run dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json"
  chmod 0755 "$DR_VPS_POOL_DIR"
  [ "$status" -ne 0 ]                                    # NOT rc 0 (false success)
  run dr_vps_image_ls; [ -z "$output" ]                 # nothing registered
}

@test "register-conflict handler treats a concurrent-winner as idempotent (does NOT rm the winner's golden; race-only path)" {
  local blk; blk=$(sed -n '/dr_vps_store_image_register "\$aid" "\$prov"/,/^  }/p' "$DR_VPS_SRC/dr_vps_image.sh")
  [[ "$blk" == *'dr_vps_store_image_get "$aid"'* ]]          # on failure, re-check registration
  [[ "$blk" == *'dr_vps_golden_digest "$gpath"'* ]]          # + content digest match
  [[ "$blk" == *'idempotent'* ]]                             # -> idempotent success, no rm of the registered file
}

@test "two CONCURRENT identical builds -> same aid, golden intact + registered (per-aid flock)" {
  dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json" >"$BATS_TEST_TMPDIR/a1" 2>/dev/null &
  dr_vps_image_build "$BATS_TEST_TMPDIR/recipe.json" >"$BATS_TEST_TMPDIR/a2" 2>/dev/null &
  wait
  local a1 a2; a1=$(cat "$BATS_TEST_TMPDIR/a1"); a2=$(cat "$BATS_TEST_TMPDIR/a2")
  [ -n "$a1" ]; [ "$a1" = "$a2" ]                                  # both produced the same deterministic aid
  [ -f "$DR_VPS_POOL_DIR/$a1.qcow2" ]                              # golden intact (loser did NOT delete it)
  run dr_vps_store_image_get "$a1"; [ "$output" = "$DR_VPS_POOL_DIR/$a1.qcow2" ]   # still registered
}

@test "build takes a per-aid flock before publish+register (structural)" {
  local blk; blk=$(sed -n '/dr_vps_image_build() {/,/^}/p' "$DR_VPS_SRC/dr_vps_image.sh")
  [[ "$blk" == *'.build-${aid}.lock'* ]]; [[ "$blk" == *'flock 9'* ]]
}
