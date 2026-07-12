#!/usr/bin/env bats
# CONCEPT-BUILD-NET: appliance-network backend select/observe/enforce (+ probe/taxonomy/progress).
# UNIT layer -- controllable fakes for passt/qemu/virt-customize; NO real libguestfs/KVM. The real
# libguestfs->shim->qemu/passt INTEGRATION + real cgroup scope-kill are LIVE-ONLY (Stage 8 blind spot).

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_identity.sh
  dr_vps_load dr_vps_store.sh
  dr_vps_load dr_vps_image.sh
  FAKEBIN="$BATS_TEST_TMPDIR/fakebin"; mkdir -p "$FAKEBIN"; PATH="$FAKEBIN:$PATH"
  ARCH=$(uname -m)
}

_fake() {  # <name> <body-line...>  -- writes an executable fake onto PATH (FAKEBIN is first)
  local n="$1"; shift; { printf '#!/usr/bin/env bash\n'; printf '%s\n' "$@"; } >"$FAKEBIN/$n"; chmod +x "$FAKEBIN/$n"; }

# --- Stage 1: net_mode ---------------------------------------------------------------------------
@test "net_mode: valid modes echo; invalid -> USAGE(2); non-direct backend -> CAP(12)" {
  DR_VPS_LIBGUESTFS_NET=auto  run dr_vps_net_mode; [ "$status" -eq 0 ]; [ "$output" = auto ]
  DR_VPS_LIBGUESTFS_NET=passt run dr_vps_net_mode; [ "$status" -eq 0 ]; [ "$output" = passt ]
  DR_VPS_LIBGUESTFS_NET=slirp run dr_vps_net_mode; [ "$status" -eq 0 ]; [ "$output" = slirp ]
  DR_VPS_LIBGUESTFS_NET=nope  run dr_vps_net_mode; [ "$status" -eq 2 ]
  DR_VPS_LIBGUESTFS_NET=auto DR_VPS_LIBGUESTFS_BACKEND=libvirt run dr_vps_net_mode; [ "$status" -eq 12 ]
}

@test "net_mode: default is auto" {
  run dr_vps_net_mode; [ "$status" -eq 0 ]; [ "$output" = auto ]
}

# --- Stage 1: net_shims (slirp refuser) ----------------------------------------------------------
@test "net_shims slirp -> passt shim REFUSES with exit 2 (so libguestfs falls back to slirp)" {
  _fake "qemu-system-$ARCH" 'exit 0'
  run dr_vps_net_shims "$BATS_TEST_TMPDIR/s" slirp; [ "$status" -eq 0 ]
  run "$BATS_TEST_TMPDIR/s/bin/passt" --help; [ "$status" -eq 2 ]     # 2 (NOT 1): triggers slirp
}

# --- Stage 1: net_shims (passt observer) ---------------------------------------------------------
@test "net_shims passt observer resolves real passt, passes --help through, records --one-off nonzero (BACKEND_START signal)" {
  _fake passt 'case " $* " in *" --one-off "*) exit 1 ;; *) exit 0 ;; esac'   # oneoff FAILS, help OK
  _fake "qemu-system-$ARCH" 'exit 0'
  run dr_vps_net_shims "$BATS_TEST_TMPDIR/p" passt; [ "$status" -eq 0 ]
  sh="$BATS_TEST_TMPDIR/p/bin/passt"; mk="$BATS_TEST_TMPDIR/p/markers"
  run "$sh" --help;            [ "$status" -eq 0 ]                    # exit passthrough (help ok)
  run "$sh" --one-off --socket /x; [ "$status" -eq 1 ]               # observer exits SAME status
  [ "$(cat "$mk/passt.oneoff_rc")" = 1 ]                             # recorded -> BACKEND_START
  grep -q '^oneoff 1$' "$mk/passt.log"
}

@test "net_shims passt observer with NO real passt on PATH -> exit 127 + err marker (not a silent success)" {
  # no fake passt -> command -v passt empty -> observer records no-real-passt, exit 127
  ( command -v passt >/dev/null 2>&1 ) && skip "a real passt is on PATH in this env"
  _fake "qemu-system-$ARCH" 'exit 0'
  run dr_vps_net_shims "$BATS_TEST_TMPDIR/p" passt; [ "$status" -eq 0 ]
  run "$BATS_TEST_TMPDIR/p/bin/passt" --one-off; [ "$status" -eq 127 ]
  [ -f "$BATS_TEST_TMPDIR/p/markers/passt.err" ]
}

# --- Stage 1: net_shims (qemu HV wrapper: passthrough vs enforce) ---------------------------------
@test "net_shims qemu-hv passes THROUGH feature probes (no -netdev) and enforces only the final -netdev launch" {
  _fake passt 'exit 1'                                                 # passt "available"
  _fake "qemu-system-$ARCH" 'echo "RAN $*" >>"'"$BATS_TEST_TMPDIR"'/qrun"; exit 0'
  run dr_vps_net_shims "$BATS_TEST_TMPDIR/p" passt; [ "$status" -eq 0 ]
  hv="$BATS_TEST_TMPDIR/p/bin/qemu-hv"; mk="$BATS_TEST_TMPDIR/p/markers"
  run "$hv" -version;                    [ "$status" -eq 0 ]; [ ! -f "$mk/qemu.backend" ]   # passthrough
  run "$hv" -m 1024 -netdev stream,id=usernet,addr.type=unix -drive x; [ "$status" -eq 0 ]  # match
  [ "$(cat "$mk/qemu.backend")" = passt ]; [ ! -f "$mk/qemu.mismatch" ]
}

@test "net_shims qemu-hv REFUSES (exit 3) on a backend MISMATCH (expected passt, got -netdev user)" {
  _fake passt 'exit 1'; _fake "qemu-system-$ARCH" 'echo RAN >>"'"$BATS_TEST_TMPDIR"'/qrun"; exit 0'
  dr_vps_net_shims "$BATS_TEST_TMPDIR/p" passt
  hv="$BATS_TEST_TMPDIR/p/bin/qemu-hv"; mk="$BATS_TEST_TMPDIR/p/markers"
  run "$hv" -netdev user,id=usernet; [ "$status" -eq 3 ]
  [ "$(cat "$mk/qemu.backend")" = slirp ]; [ -f "$mk/qemu.mismatch" ]
  [ ! -f "$BATS_TEST_TMPDIR/qrun" ]                                    # real qemu NEVER ran on mismatch
}

@test "net_shims: fails closed (CAP 12) when no real qemu is resolvable (structural -- clean 'no qemu but yes coreutils' isn't unit-simulable)" {
  local blk; blk=$(sed -n '/^dr_vps_net_shims() {/,/^}/p' "$DR_VPS_SRC/dr_vps_image.sh")
  [[ "$blk" == *'realqemu=$(command -v "${DR_QEMU:-qemu-system-$(uname -m)}"'* ]]   # resolves the real hypervisor (DR_QEMU seam)
  [[ "$blk" == *'[ -n "$realqemu" ]'*'DR_VPS_E_CAP'* ]]                    # fail-closed CAP guard when absent
}

# --- Stage 3: probe command (family-specific, strict) ---------------------------------------------
@test "probe_cmd: dnf strict + Yum-3 branch; apt strict error-mode; apk/zypper refresh; all emit markers" {
  run _dr_vps_bake_probe_cmd dnf
  [[ "$output" == *"dnf makecache --refresh --setopt=skip_if_unavailable=false"* ]]
  [[ "$output" == *"yum clean expire-cache && yum -y makecache"* ]]      # Yum-3 branch (no makecache --refresh)
  [[ "$output" == *'M=DRVPS_PROBE'* ]]; [[ "$output" == *'${M}_OK'* ]]; [[ "$output" == *'${M}_FAILED'* ]]
  [[ "$output" != *"DRVPS_PROBE_OK"* ]]      # the CONTIGUOUS token must NOT be in the command text
  run _dr_vps_bake_probe_cmd apt;    [[ "$output" == *"APT::Update::Error-Mode=any"* ]]
  run _dr_vps_bake_probe_cmd apk;    [[ "$output" == *"apk update"* ]]
  run _dr_vps_bake_probe_cmd zypper; [[ "$output" == *"zypper --non-interactive refresh"* ]]
}

# --- Stage 4: classify (marker + rc + log -> token) -----------------------------------------------
@test "classify: rc0->OK; qemu mismatch/passt-oneoff-nonzero->BACKEND_START; probe fail->REPO_PROBE_FAILED; probe ok+fail->INSTALL_FAILED; else PROBE_INFRA" {
  md="$BATS_TEST_TMPDIR/md"; mkdir -p "$md"; log="$BATS_TEST_TMPDIR/log"; : >"$log"
  run _dr_vps_bake_classify 0 "$md" "$log"; [ "$output" = OK ]
  echo x >"$md/qemu.mismatch"; run _dr_vps_bake_classify 1 "$md" "$log"; [ "$output" = BACKEND_START ]; rm -f "$md/qemu.mismatch"
  echo 1 >"$md/passt.oneoff_rc"; run _dr_vps_bake_classify 1 "$md" "$log"; [ "$output" = BACKEND_START ]
  echo 0 >"$md/passt.oneoff_rc"; echo DRVPS_PROBE_FAILED >"$log"; run _dr_vps_bake_classify 42 "$md" "$log"; [ "$output" = REPO_PROBE_FAILED ]
  echo DRVPS_PROBE_OK >"$log"; run _dr_vps_bake_classify 1 "$md" "$log"; [ "$output" = INSTALL_FAILED ]
  : >"$log"; run _dr_vps_bake_classify 1 "$md" "$log"; [ "$output" = PROBE_INFRA ]
}

# --- Stage 2+4: transactional matrix via dr_vps_image_bake ----------------------------------------
_bakefix() {  # <family> -- golden.qcow2 + recipe + CA + fake vc that simulates per-backend outcomes
  export DR_QEMU=true
  export DR_VPS_CACHE_CA="$BATS_TEST_TMPDIR/ca.crt"; echo CA >"$DR_VPS_CACHE_CA"
  dr_vps_mk_qcow2 "$BATS_TEST_TMPDIR/golden.qcow2" 2097152 65536
  cat >"$BATS_TEST_TMPDIR/r.json" <<EOF
{"distro":"d","family":"${1:-dnf}","upstream_url":"x","upstream_sha256":"y","packages":["p"]}
EOF
  export SIMLOG="$BATS_TEST_TMPDIR/sim"
  cat >"$FAKEBIN/virt-customize" <<'VC'
#!/usr/bin/env bash
[ "$1" = --version ] && { echo "virt-customize 1.59.0"; exit 0; }   # mimic real --version (no side effects)
md="${DR_VPS_NET_MARKERS:-}"; exp="${DR_VPS_NET_EXPECT:-none}"
printf '%s\n' "$*" >>"$SIMLOG.args"; printf 'x\n' >>"$SIMLOG.count"
outcome=ok
[ "$exp" = passt ] && outcome="${DRVPS_SIM_PASST:-ok}"
[ "$exp" = slirp ] && outcome="${DRVPS_SIM_SLIRP:-ok}"
case "$outcome" in
  ok)      echo DRVPS_PROBE_OK; exit 0 ;;
  start)   [ -n "$md" ] && echo 1 >"$md/passt.oneoff_rc"; exit 1 ;;
  repo)    echo DRVPS_PROBE_FAILED; exit 42 ;;
  install) echo DRVPS_PROBE_OK; echo err >&2; exit 1 ;;
  infra)   exit 1 ;;
esac
VC
  chmod +x "$FAKEBIN/virt-customize"; export DR_VIRT_CUSTOMIZE="$FAKEBIN/virt-customize"
}
_backing() { qemu-img info --output=json "$1" 2>/dev/null | jq -r '."backing-filename" // ""'; }
_count()   { [ -f "$SIMLOG.count" ] && wc -l <"$SIMLOG.count" | tr -d ' ' || echo 0; }

@test "auto: passt BACKEND_START -> falls back to slirp -> promotes a STANDALONE golden (2 attempts)" {
  _bakefix
  DRVPS_SIM_PASST=start DRVPS_SIM_SLIRP=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -eq 0 ]
  [ -z "$(_backing "$BATS_TEST_TMPDIR/golden.qcow2")" ]     # promoted golden is standalone (no backing chain)
  [ "$(_count)" -eq 2 ]                                     # passt then slirp
}

@test "auto: passt OK -> baked on passt, NO slirp attempt (1 attempt)" {
  _bakefix
  DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -eq 0 ]; [ "$(_count)" -eq 1 ]
}

@test "auto: BOTH fail -> dies, and does NOT offer 'DR_VPS_LIBGUESTFS_NET=slirp' (hard remedy invariant: slirp never demonstrated)" {
  _bakefix
  DRVPS_SIM_PASST=start DRVPS_SIM_SLIRP=repo run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no usable appliance backend"* ]]
  [[ "$output" != *"DR_VPS_LIBGUESTFS_NET=slirp"* ]]       # never advise forcing slirp when slirp failed
}

@test "auto: PROBE_INFRA on passt -> FATAL immediately with the kernel/DNS hint, NO slirp fallback (1 attempt)" {
  _bakefix
  DRVPS_SIM_PASST=infra run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 0644 /boot/vmlinuz"* ]]          # infra -> the stable kernel hint
  [ "$(_count)" -eq 1 ]                                     # no wasted slirp attempt on a clear infra failure
}

@test "auto: probe OK then INSTALL fails -> ordinary bake failure, NO backend retry (1 attempt)" {
  _bakefix
  DRVPS_SIM_PASST=install run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"package install failed"* ]]; [ "$(_count)" -eq 1 ]
}

@test "explicit slirp: forces one slirp attempt; failure reports without backend-causal 'passt' language" {
  _bakefix
  DR_VPS_LIBGUESTFS_NET=slirp DRVPS_SIM_SLIRP=repo run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]; [ "$(_count)" -eq 1 ]
  [[ "$output" == *"Explicit slirp"* ]]
}

@test "CA-only bake (no packages) -> --no-network single run, NO probe/shims (no --install, no makecache)" {
  _bakefix
  sed 's/"packages":\["p"\]/"packages":[]/' "$BATS_TEST_TMPDIR/r.json" >"$BATS_TEST_TMPDIR/ca-only.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/ca-only.json"
  [ "$status" -eq 0 ]
  grep -q -- '--no-network' "$SIMLOG.args"
  ! grep -q -- '--install' "$SIMLOG.args" || false
  ! grep -q 'makecache' "$SIMLOG.args" || false                     # no network probe on a CA-only bake
}

# --- Stage 5: progress path (tee + atomic PIPESTATUS) ---------------------------------------------
@test "progress path (DR_VPS_BAKE_PROGRESS=1): tee preserves the log so classify still works -> success" {
  _bakefix
  DR_VPS_BAKE_PROGRESS=1 DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -eq 0 ]; [ -z "$(_backing "$BATS_TEST_TMPDIR/golden.qcow2")" ]
}

@test "progress path: PIPESTATUS[0] (virt-customize), not tee/filter, drives the result -> passt repo-fail falls back" {
  _bakefix
  DR_VPS_BAKE_PROGRESS=1 DRVPS_SIM_PASST=repo DRVPS_SIM_SLIRP=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -eq 0 ]; [ "$(_count)" -eq 2 ]        # DRVPS_PROBE_FAILED survived through tee -> REPO_PROBE_FAILED -> slirp
}

# --- Stage 6: outer deadline + cgroup-scope seam --------------------------------------------------
@test "outer deadline: DR_VPS_BAKE_TIMEOUT fires -> attempt killed -> classified infra, bake fails" {
  _bakefix
  # fake vc that hangs; a 1s deadline must kill it (timeout -> nonzero, no markers -> PROBE_INFRA -> fatal)
  cat >"$FAKEBIN/virt-customize" <<'VC'
#!/usr/bin/env bash
[ "$1" = --version ] && { echo "virt-customize 1.59.0"; exit 0; }   # --version must not hang the preflight
sleep 5; echo DRVPS_PROBE_OK; exit 0
VC
  chmod +x "$FAKEBIN/virt-customize"
  DR_VPS_BAKE_TIMEOUT=1 DR_VPS_LIBGUESTFS_NET=passt run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]
}

@test "cgroup-scope seam: DR_VPS_CGROUP_RUN wraps the attempt (so a real scope reaps daemonized passt/qemu)" {
  _bakefix
  cat >"$FAKEBIN/wrapmark" <<EOF
#!/usr/bin/env bash
echo ran >"$BATS_TEST_TMPDIR/wrap.marker"
exec "\$@"
EOF
  chmod +x "$FAKEBIN/wrapmark"
  DR_VPS_CGROUP_RUN="$FAKEBIN/wrapmark" DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -eq 0 ]
  [ -f "$BATS_TEST_TMPDIR/wrap.marker" ]                 # the scope wrapper actually ran around the attempt
}

@test "attempt structurally wraps in cgroup-scope + timeout + env (SIGKILL-safe reap + deadline)" {
  local blk; blk=$(sed -n '/^_dr_vps_bake_attempt() {/,/^}/p' "$DR_VPS_SRC/dr_vps_image.sh")
  [[ "$blk" == *'DR_VPS_CGROUP_RUN'* ]]
  [[ "$blk" == *'timeout -k 30 "${DR_VPS_BAKE_TIMEOUT:-1800}"'* ]]
}

# --- probe/bake fail-closed regression coverage ----------------------------------------------------
@test "a real passt --help returning a WEIRD code (42) does NOT false-fire CAP (canary gates exec, not passt exit)" {
  _fake passt 'exit 42'                                   # real passt --help -> 42 (not in {0,1,2,127})
  _fake "qemu-system-$ARCH" 'exit 0'
  run dr_vps_net_shims "$BATS_TEST_TMPDIR/p" passt
  [ "$status" -eq 0 ]                                     # succeeds now (was CAP 12 before the canary fix)
  run "$BATS_TEST_TMPDIR/p/bin/.canary"; [ "$status" -eq 0 ]   # the deterministic canary exists + execs
}

@test "recipe .packages of the wrong type (a bare string) -> USAGE(2), never a package-less golden" {
  cat >"$BATS_TEST_TMPDIR/badpkg.json" <<'EOF'
{"distro":"d","family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":"systemd"}
EOF
  run dr_vps_image_build "$BATS_TEST_TMPDIR/badpkg.json"
  [ "$status" -eq 2 ]
  [[ "$output" == *"schema invalid"* ]]
}

@test "promotion FAILS CLOSED when qemu-img info errors (does not accept a maybe-backed golden)" {
  _bakefix
  local real; real=$(PATH=/usr/bin:/bin command -v qemu-img)
  cat >"$FAKEBIN/qemu-img" <<QI
#!/usr/bin/env bash
[ "\$1" = info ] && exit 9          # info FAILS -> standalone check must fail closed, not accept
exec "$real" "\$@"
QI
  chmod +x "$FAKEBIN/qemu-img"; export DR_QEMU_IMG="$FAKEBIN/qemu-img"
  DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"qemu-img info failed"* ]]
}

@test "qemu-img info exit 0 but EMPTY output -> promotion fails CLOSED (not accepted as no-backing)" {
  _bakefix
  local real; real=$(PATH=/usr/bin:/bin command -v qemu-img)
  cat >"$FAKEBIN/qemu-img" <<QI
#!/usr/bin/env bash
[ "\$1" = info ] && { printf ''; exit 0; }     # exit 0 but EMPTY stdout -> must NOT read as 'no backing'
exec "$real" "\$@"
QI
  chmod +x "$FAKEBIN/qemu-img"; export DR_QEMU_IMG="$FAKEBIN/qemu-img"
  DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]; [[ "$output" == *"no valid JSON object"* ]]
}

@test "dr_vps_image_bake called DIRECTLY with string .packages -> USAGE(2), not a package-less golden" {
  _bakefix
  sed 's/"packages":\["p"\]/"packages":"p"/' "$BATS_TEST_TMPDIR/r.json" >"$BATS_TEST_TMPDIR/badp.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/badp.json"
  [ "$status" -eq 2 ]; [[ "$output" == *"schema invalid"* ]]
}

@test ".packages == false (not null) -> USAGE(2), not a silent CA-only bake (false // [] trap)" {
  _bakefix
  sed 's/"packages":\["p"\]/"packages":false/' "$BATS_TEST_TMPDIR/r.json" >"$BATS_TEST_TMPDIR/pf.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/pf.json"
  [ "$status" -eq 2 ]; [[ "$output" == *"schema invalid"* ]]
}

@test "qemu-img info emitting MULTI-VALUE JSON (null + object) -> fail closed (length==1 guard)" {
  _bakefix
  local real; real=$(PATH=/usr/bin:/bin command -v qemu-img)
  cat >"$FAKEBIN/qemu-img" <<QI
#!/usr/bin/env bash
[ "\$1" = info ] && { printf 'null\n{"format":"qcow2"}\n'; exit 0; }   # two top-level values -> malformed
exec "$real" "\$@"
QI
  chmod +x "$FAKEBIN/qemu-img"; export DR_QEMU_IMG="$FAKEBIN/qemu-img"
  DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]; [[ "$output" == *"no valid JSON object"* ]]
}

@test "a MULTI-object JSON recipe stream -> USAGE(2) (single-object envelope, not fail-open)" {
  _bakefix
  cat >"$BATS_TEST_TMPDIR/multi.json" <<'EOF'
{"distro":"d","family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":["p"]}
{"distro":"d2","family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":null}
EOF
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/multi.json"
  [ "$status" -eq 2 ]; [[ "$output" == *"single JSON object"* ]]
}

@test "recipe field-TYPE fail-opens rejected (distro:false, family:false, packages:[\"\"]) -> USAGE(2)" {
  _bakefix
  printf '{"distro":false,"family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":["p"]}' >"$BATS_TEST_TMPDIR/d.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/d.json"; [ "$status" -eq 2 ]
  printf '{"distro":"d","family":false,"upstream_url":"x","upstream_sha256":"y","packages":["p"]}' >"$BATS_TEST_TMPDIR/f.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/f.json"; [ "$status" -eq 2 ]
  printf '{"distro":"d","family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":[""]}' >"$BATS_TEST_TMPDIR/e.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/e.json"; [ "$status" -eq 2 ]
}

@test "probe emits START (proves-ran) + TOOLERR (missing-PM) markers, assembled (no log collision)" {
  run _dr_vps_bake_probe_cmd dnf
  [[ "$output" == *'${M}_START'* ]]; [[ "$output" == *'${M}_TOOLERR'* ]]
  [[ "$output" == *'command -v dnf'* ]]
  [[ "$output" != *"DRVPS_PROBE_START"* ]]     # contiguous token only in OUTPUT, not the command text
}

@test "classify PROBE_TOOL (missing PM) and START-only (hung -> network path, not infra)" {
  md="$BATS_TEST_TMPDIR/md"; mkdir -p "$md"; log="$BATS_TEST_TMPDIR/log"
  echo DRVPS_PROBE_TOOLERR >"$log"; run _dr_vps_bake_classify 43  "$md" "$log"; [ "$output" = PROBE_TOOL ]
  echo DRVPS_PROBE_START   >"$log"; run _dr_vps_bake_classify 124 "$md" "$log"; [ "$output" = REPO_PROBE_FAILED ]
}

@test "PROBE_TOOL (family/image mismatch) is FATAL, NO slirp fallback (1 attempt)" {
  _bakefix
  cat >"$FAKEBIN/virt-customize" <<'VC'
#!/usr/bin/env bash
[ "$1" = --version ] && { echo "virt-customize 1.59.0"; exit 0; }
printf 'x\n' >>"$SIMLOG.count"
echo DRVPS_PROBE_TOOLERR; exit 43
VC
  chmod +x "$FAKEBIN/virt-customize"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]; [[ "$output" == *"lacks a package manager"* ]]; [ "$(_count)" -eq 1 ]
}

@test "optional field type fail-opens rejected (upstream_sig:false, repo_content:[]) -> USAGE(2)" {
  _bakefix
  printf '{"distro":"d","family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":["p"],"upstream_sig":false}' >"$BATS_TEST_TMPDIR/s.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/s.json"; [ "$status" -eq 2 ]
  printf '{"distro":"d","family":"dnf","upstream_url":"x","upstream_sha256":"y","packages":["p"],"repo_content":[]}' >"$BATS_TEST_TMPDIR/rc.json"
  run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/rc.json"; [ "$status" -eq 2 ]
}

@test "HUNG passt (oneoff_started, no oneoff_rc) -> BACKEND_START (auto falls back, not infra)" {
  md="$BATS_TEST_TMPDIR/md"; mkdir -p "$md"; log="$BATS_TEST_TMPDIR/log"; : >"$log"
  printf 1 >"$md/passt.oneoff_started"                # started but never returned (killed by the outer timeout)
  run _dr_vps_bake_classify 124 "$md" "$log"; [ "$output" = BACKEND_START ]
}

@test "standalone check rejects a wrong-typed backing-filename (false) -> fail closed" {
  _bakefix
  local real; real=$(PATH=/usr/bin:/bin command -v qemu-img)
  cat >"$FAKEBIN/qemu-img" <<QI
#!/usr/bin/env bash
[ "\$1" = info ] && { printf '{"format":"qcow2","backing-filename":false}'; exit 0; }
exec "$real" "\$@"
QI
  chmod +x "$FAKEBIN/qemu-img"; export DR_QEMU_IMG="$FAKEBIN/qemu-img"
  DRVPS_SIM_PASST=ok run dr_vps_image_bake "$BATS_TEST_TMPDIR/golden.qcow2" "$BATS_TEST_TMPDIR/r.json"
  [ "$status" -ne 0 ]; [[ "$output" == *"no valid JSON object"* ]]
}
