#!/usr/bin/env bash
# dr_vps_image.sh -- golden image supply chain (Stage 3). BUILD plane only:
# fetch (controlled host egress) -> VERIFY vendor checksum/sig (18 on mismatch) ->
# bake stable deps (virt-customize, seamed) -> drvps-raw-v1 digest -> provenance ->
# register (refcount 0). The test VM's `simulated` egress is a SEPARATE plane.
# ASCII only; bins run set -uo pipefail (code is also -e-safe).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_identity.sh
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_identity.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_store.sh
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_store.sh"

: "${DR_VPS_DRIVER_VERSION:=0.2.0}"

# fetch an upstream cloud image to dest (file:// or path = local copy; http(s) = curl).
dr_vps_image_fetch() {  # <url> <dest>
  local url="$1" dest="$2"
  case "$url" in
    file://*) cp -f "${url#file://}" "$dest" ;;
    # --progress-bar streams a download meter to STDERR (build stdout must stay the bare artifact_id);
    # -f fail-on-error, -L follow redirects. (was -fsSL: the -s silenced all progress -> "feels frozen".)
    http://*|https://*) curl -fL --progress-bar -o "$dest" "$url" ;;
    *) cp -f "$url" "$dest" ;;
  esac || { dr_vps_die "$DR_VPS_E_GENERIC" "fetch failed: $url"; return $?; }
  [ -s "$dest" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "fetched empty file: $url"; return $?; }
}

# VERIFY the vendor checksum (and an optional detached GPG sig). 18 on any mismatch.
dr_vps_image_verify() {  # <file> <expected_sha256> [sig_file]
  local file="$1" expect="$2" sig="${3:-}" actual
  [ -f "$file" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "verify: no file: $file"; return $?; }
  actual=$(sha256sum "$file" | awk '{print $1}')
  # case-insensitive compare: a legitimate vendor checksum in UPPERCASE hex passes the format guard
  # but would false-reject against sha256sum's lowercase output. Normalize both to lowercase.
  [ "${actual,,}" = "${expect,,}" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "checksum mismatch: $actual != $expect"; return $?; }
  if [ -n "$sig" ]; then
    dr_vps_have gpg || { dr_vps_die "$DR_VPS_E_VERIFY" "sig given but gpg absent"; return $?; }
    gpg --verify "$sig" "$file" >/dev/null 2>&1 || { dr_vps_die "$DR_VPS_E_VERIFY" "GPG verify failed: $file"; return $?; }
  fi
}

# --- appliance-network backend selection (BUILD plane; CONCEPT-BUILD-NET rev5) ----------------------
# libguestfs gives the throwaway bake appliance usermode networking, PREFERS passt, and only falls back
# to slirp if no `passt` returns --help exit 0/1. Where passt is broken (e.g. Ubuntu 26.04) the appliance
# has NO network and the bake dies at dnf/apt. This layer OBSERVES + ENFORCES the backend per attempt via
# a PATH `passt` shim + a `LIBGUESTFS_HV` qemu wrapper, with no host change. Observe/enforce needs the
# `direct` backend (only it exposes the qemu argv); the knob fails closed on any other backend.

# Resolve + validate the requested net mode. Echoes auto|passt|slirp; dies on invalid / non-direct.
dr_vps_net_mode() {
  local m="${DR_VPS_LIBGUESTFS_NET:-auto}"
  case "$m" in auto|passt|slirp) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "DR_VPS_LIBGUESTFS_NET must be auto|passt|slirp (got '$m')"; return $?;; esac
  case "${DR_VPS_LIBGUESTFS_BACKEND:-direct}" in
    direct) ;;
    *) dr_vps_die "$DR_VPS_E_CAP" "DR_VPS_LIBGUESTFS_NET=$m needs the 'direct' libguestfs backend (only it exposes the qemu argv to observe); got DR_VPS_LIBGUESTFS_BACKEND='${DR_VPS_LIBGUESTFS_BACKEND}'"; return $?;;
  esac
  printf '%s\n' "$m"
}

# Write the per-attempt shims into <dir> for the EXPECTED backend (passt|slirp) and set three globals:
#   DR_VPS_NET_BINDIR  -- prepend to PATH (holds the `passt` shim)
#   DR_VPS_NET_HV      -- LIBGUESTFS_HV (the qemu wrapper)
#   DR_VPS_NET_MARKERS -- dir the shims write observations into
# passt EXPECTED  -> `passt` shim is an OBSERVER: it resolves the REAL passt path FIRST (before <dir>/bin
#                    is on PATH, so it cannot recurse into itself), RUNS it as a child, WAITs, records the
#                    invocation kind (--help vs the real --one-off) + exit, and exits the SAME status.
# slirp EXPECTED  -> `passt` shim REFUSES (exit 2, NOT 1: libguestfs treats --help 0/1 as "passt present")
#                    so libguestfs falls back to slirp.
# The qemu wrapper PASSES THROUGH libguestfs feature probes (-version/KVM detect: no -netdev) unchanged and
# only on the FINAL appliance launch (argv carries -netdev) records the observed backend (stream=passt /
# user=slirp) and REFUSES (exit 3) if it != EXPECTED. The shim dir is verified EXECUTABLE (noexec tmpfs ->
# a SETUP error, never mistaken for "backend unavailable").
dr_vps_net_shims() {  # <dir> <expected: passt|slirp>
  local dir="$1" expect="$2" realpasst realqemu bindir mdir _ec
  case "$expect" in passt|slirp) ;; *) dr_vps_die "$DR_VPS_E_GENERIC" "net-shims: bad expected backend '$expect'"; return $?;; esac
  bindir="$dir/bin"; mdir="$dir/markers"
  mkdir -p "$bindir" "$mdir" || { dr_vps_die "$DR_VPS_E_GENERIC" "net-shims: mkdir failed under $dir"; return $?; }
  # resolve REAL binaries NOW, before $bindir is prepended to PATH (recursion guard for the passt shim).
  realpasst=$(command -v passt 2>/dev/null || true)
  realqemu=$(command -v "${DR_QEMU:-qemu-system-$(uname -m)}" 2>/dev/null || command -v qemu-kvm 2>/dev/null || true)
  [ -n "$realqemu" ] || { dr_vps_die "$DR_VPS_E_CAP" "net-shims: real qemu (${DR_QEMU:-qemu-system-$(uname -m)}) not found -- cannot wrap the hypervisor"; return $?; }
  if [ "$expect" = slirp ]; then
    # REFUSER: any invocation (incl. --help) exits 2 -> libguestfs uses slirp.
    printf '#!/bin/sh\nexit 2\n' >"$bindir/passt"
  else
    # OBSERVER: run the real passt as a child (NOT exec -- exec never returns to record), append kind+rc.
    # shellcheck disable=SC2016  # printf templates are LITERAL by design: $real/$@/$rc expand in the
    # GENERATED shim at runtime, not here.
    { printf '#!/usr/bin/env bash\nset -u\n'
      printf 'real=%q\nmdir=%q\n' "$realpasst" "$mdir"
      printf 'kind=help; case " $* " in *" --one-off "*) kind=oneoff ;; esac\n'
      printf 'if [ -z "$real" ] || [ ! -x "$real" ]; then printf no-real-passt >"$mdir/passt.err"; exit 127; fi\n'
      printf '[ "$kind" = oneoff ] && printf 1 >"$mdir/passt.oneoff_started"\n'   # BEFORE exec: a hung+killed passt is observable
      printf '"$real" "$@"; rc=$?\n'
      printf 'printf "%%s %%s\\n" "$kind" "$rc" >>"$mdir/passt.log"\n'
      printf '[ "$kind" = oneoff ] && printf "%%s" "$rc" >"$mdir/passt.oneoff_rc"\n'
      printf 'exit "$rc"\n'
    } >"$bindir/passt"
  fi
  # qemu wrapper: passthrough feature probes; enforce -netdev only on the final appliance launch.
  # shellcheck disable=SC2016  # printf templates are LITERAL by design (expanded by the generated wrapper).
  { printf '#!/usr/bin/env bash\nset -u\n'
    printf 'realqemu=%q\nmdir=%q\nexpect=%q\n' "$realqemu" "$mdir" "$expect"
    printf 'nd=; want=\n'
    printf 'for a in "$@"; do\n'
    printf '  if [ -n "$want" ]; then nd="$a"; want=; continue; fi\n'
    printf '  case "$a" in -netdev) want=1 ;; -netdev=*) nd="${a#-netdev=}" ;; esac\n'
    printf 'done\n'
    printf 'if [ -z "$nd" ]; then exec "$realqemu" "$@"; fi\n'
    printf 'obs=other; case "$nd" in stream*) obs=passt ;; user*) obs=slirp ;; esac\n'
    printf 'printf "%%s\\n" "$obs" >"$mdir/qemu.backend"\n'
    printf 'if [ "$obs" != "$expect" ]; then printf "%%s!=%%s" "$obs" "$expect" >"$mdir/qemu.mismatch"; exit 3; fi\n'
    printf 'exec "$realqemu" "$@"\n'
  } >"$bindir/qemu-hv"
  chmod 0500 "$bindir/passt" "$bindir/qemu-hv" || { dr_vps_die "$DR_VPS_E_GENERIC" "net-shims: chmod failed"; return $?; }
  # actually EXECUTE the shim once -- a noexec tmpfs would let chmod succeed yet block exec (SETUP error,
  # NOT "backend unavailable"). The refuser exits 2 and the observer with no real passt exits 127; both
  # PROVE the mount allows exec, which is all we assert here.
  # Verify the shim dir permits EXEC (a noexec tmpfs lets chmod succeed yet blocks exec) with a
  # DETERMINISTIC canary -- NOT the passt shim, whose exit relays REAL passt (any value: 42, 126, a signal)
  # and would false-fire CAP and, in auto, suppress the slirp fallback. This also keeps real passt OUT of a
  # pre-timeout preflight.
  { printf '#!/bin/sh\nexit 0\n' >"$bindir/.canary" && chmod 0500 "$bindir/.canary"; } \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "net-shims: canary write failed under $bindir"; return $?; }
  "$bindir/.canary" >/dev/null 2>&1 && _ec=0 || _ec=$?
  [ "$_ec" -eq 0 ] || { dr_vps_die "$DR_VPS_E_CAP" "net-shims: shim dir not executable (noexec $bindir?) -- cannot select the backend"; return $?; }
  DR_VPS_NET_BINDIR="$bindir"; DR_VPS_NET_HV="$bindir/qemu-hv"; DR_VPS_NET_MARKERS="$mdir"
}

# A recipe MUST be exactly ONE top-level JSON object. A multi-value JSON stream makes `jq -e`/`jq -r`
# evaluate EVERY value (exit status = the LAST result; field reads emit multiple lines), which would fail
# the recipe/packages validators OPEN and produce multi-line field reads. Gate it ONCE, up front. (CODE r4.)
_dr_vps_recipe_ok() {  # <recipe> -- exactly ONE JSON object with the required field TYPES
  # disk_size (optional): a qemu-img size, digits + optional K/M/G/T suffix (e.g. "12G"). GROWS the
  # golden's virtual disk (see the build resize step); absent = keep the upstream image's size.
  jq -es 'length==1 and (.[0]|type=="object") and (.[0] as $r | ($r.distro|type=="string" and length>0) and ($r.upstream_url|type=="string" and length>0) and ($r.upstream_sha256|type=="string" and length>0) and (($r.family|type=="null") or (["dnf","apt","zypper","apk"]|index($r.family)!=null)) and (($r.packages|type=="null") or (($r.packages|type=="array") and ($r.packages|map(type=="string" and length>0)|all))) and ($r.upstream_sig|(type=="null") or (type=="string")) and ($r.repo_content|(type=="null") or (type=="string")) and ($r.repo_remove|(type=="null") or (type=="string")) and (($r.disk_size|type=="null") or (($r.disk_size|type=="string") and ($r.disk_size|test("^[0-9]+[KMGT]?$")))))' \
    -- "$1" >/dev/null 2>&1
}

# Light libguestfs version gate: observe/enforce assumes libguestfs's STABLE passt integration
# (`passt --one-off` found via PATH) + the direct-backend qemu argv, present since ~1.48. Outside the
# tested range we WARN (not fail): auto's differential fallback still works WITHOUT observation, and
# failing would break every build on a libguestfs upgrade. A seamed fake prints no version -> skip silently.
# (A documented, reasoned softening of the design's fail-closed default.)
_dr_vps_libguestfs_ver_warn() {
  local v maj min
  v=$(timeout -k 5 15 "$DR_VIRT_CUSTOMIZE" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)  # hard-bounded (CODE r2/r3)
  [ -n "$v" ] || return 0
  maj=${v%%.*}; min=${v#*.}
  if [ "$maj" -lt 1 ] || { [ "$maj" -eq 1 ] && [ "$min" -lt 48 ]; }; then
    printf 'dr_vps_image_bake: WARNING -- libguestfs %s is older than the tested range (>=1.48); appliance-network observe/enforce may be unreliable.\n' "$v" >&2
  fi
  return 0
}

# The STABLE common-cause remediation attached to a launch/infra bake failure (no fragile log-scraping;
# version/locale-stable). Reused by the CA-only path and the transactional PROBE_INFRA class.
_dr_vps_bake_hint() {  # <bakelog>
  printf "see %s ; last lines: %s || Common build-host causes: (1) [Debian/Ubuntu] the non-root build user cannot READ the host kernel (they ship /boot/vmlinuz-* mode 0600) -> 'sudo chmod 0644 /boot/vmlinuz-*'; (2) [ANY host on a loopback-stub resolver, incl. Fedora] the libguestfs appliance cannot resolve DNS ('Could not resolve host ...') because /etc/resolv.conf is the systemd-resolved stub (127.0.0.53), useless inside the appliance -> point it at the uplink 'sudo ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf' (record the original target first; see the runbook for the guarded steps + split-DNS caveat). Re-run with DR_VPS_LIBGUESTFS_DEBUG=1 for full libguestfs diagnostics. See docs/INSTALL-RUNBOOK.md." \
    "$1" "$(tail -5 "$1" 2>/dev/null | tr '\n' '|')"
}

# The FIRST network-bearing bake action: a STRICT, bounded package-manager refresh against the REAL repos
# the --install will use (portable, binary-free). Prints DRVPS_PROBE_OK / DRVPS_PROBE_FAILED (+ exit 42 on
# fail so virt-customize aborts BEFORE the slow install). No `timeout` binary reliance (the outer deadline
# bounds it). dnf branches from legacy Yum-3 (no `makecache --refresh` on Yum 3); apt/dnf force strict-error.
_dr_vps_bake_probe_cmd() {  # <family>
  # `M=DRVPS_PROBE; ... "${M}_OK"` so the CONTIGUOUS token DRVPS_PROBE_OK/DRVPS_PROBE_FAILED appears ONLY in
  # the probe OUTPUT, never in the command TEXT that virt-customize echoes ("Running: ...") into the bake log
  # -- otherwise the classifier would false-match the echoed command (a successful probe then a failed
  # --install would read as REPO_PROBE_FAILED and wrongly retry).
  # A MISSING package manager is a TOOL error ("${M}_TOOLERR", exit 43 -> PROBE_TOOL, fatal, NO fallback) --
  # NOT a network failure. A "${M}_START" marker BEFORE the refresh proves the probe RAN, so a hang killed by
  # the outer timeout classifies as a network-PATH failure (REPO_PROBE_FAILED -> auto still falls back to
  # slirp), not infra.
  local m='M=DRVPS_PROBE; '
  case "$1" in
    apt)    printf '%scommand -v apt-get >/dev/null 2>&1 || { echo "${M}_TOOLERR"; exit 43; }; echo "${M}_START"; apt-get update -o APT::Update::Error-Mode=any && echo "${M}_OK" || { echo "${M}_FAILED"; exit 42; }' "$m" ;;
    apk)    printf '%scommand -v apk >/dev/null 2>&1 || { echo "${M}_TOOLERR"; exit 43; }; echo "${M}_START"; apk update && echo "${M}_OK" || { echo "${M}_FAILED"; exit 42; }' "$m" ;;
    zypper) printf '%scommand -v zypper >/dev/null 2>&1 || { echo "${M}_TOOLERR"; exit 43; }; echo "${M}_START"; zypper --non-interactive refresh && echo "${M}_OK" || { echo "${M}_FAILED"; exit 42; }' "$m" ;;
    *)      printf '%s{ command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; } || { echo "${M}_TOOLERR"; exit 43; }; echo "${M}_START"; if command -v dnf >/dev/null 2>&1; then dnf makecache --refresh --setopt=skip_if_unavailable=false; else yum clean expire-cache && yum -y makecache; fi && echo "${M}_OK" || { echo "${M}_FAILED"; exit 42; }' "$m" ;;
  esac
}

# Classify ONE attempt from its exit + the shim markers + the log (OBSERVED, never log-scraping the backend):
#   OK                 -- virt-customize succeeded
#   BACKEND_START      -- qemu-wrapper backend MISMATCH, or passt --one-off recorded a nonzero exit
#   REPO_PROBE_FAILED  -- appliance up but the strict PM refresh failed (the network path is unusable)
#   INSTALL_FAILED     -- probe passed (network OK) but a later --install action failed (ordinary bake fail)
#   PROBE_INFRA        -- appliance never reached the probe (launch/kernel/kvm/tool) -- fatal, no fallback
_dr_vps_bake_classify() {  # <rc> <markerdir> <bakelog>
  local rc="$1" md="$2" log="$3" oneoff
  [ "$rc" -eq 0 ] && { printf 'OK\n'; return 0; }
  [ -f "$md/qemu.mismatch" ] && { printf 'BACKEND_START\n'; return 0; }
  # passt STARTED its --one-off but never recorded an exit -> it hung and the outer timeout killed it =
  # a backend-start failure (auto should fall back), NOT infra.
  { [ -f "$md/passt.oneoff_started" ] && [ ! -f "$md/passt.oneoff_rc" ]; } && { printf 'BACKEND_START\n'; return 0; }
  if [ -f "$md/passt.oneoff_rc" ]; then oneoff=$(cat "$md/passt.oneoff_rc" 2>/dev/null || true); [ "$oneoff" = 0 ] || { printf 'BACKEND_START\n'; return 0; }; fi
  grep -qa DRVPS_PROBE_TOOLERR "$log" 2>/dev/null && { printf 'PROBE_TOOL\n'; return 0; }         # missing PM (family/image mismatch)
  grep -qa DRVPS_PROBE_FAILED  "$log" 2>/dev/null && { printf 'REPO_PROBE_FAILED\n'; return 0; }
  grep -qa DRVPS_PROBE_OK      "$log" 2>/dev/null && { printf 'INSTALL_FAILED\n'; return 0; }
  grep -qa DRVPS_PROBE_START   "$log" 2>/dev/null && { printf 'REPO_PROBE_FAILED\n'; return 0; }  # started+hung (timeout) -> network PATH, not infra
  printf 'PROBE_INFRA\n'
}

# Progress filter (G6): echo virt-customize's timestamped `[  N.N] step` markers to stderr, consuming the
# WHOLE stream to EOF so the producer never blocks (a stderr-write failure is ignored, not fatal).
_dr_vps_bake_progress() {
  local line
  while IFS= read -r line; do
    case "$line" in \[*\]*) printf '  %s\n' "$line" >&2 || true ;; esac
  done
  return 0
}

# Run ONE bake attempt: customize <overlay> with the network vcargs under the EXPECTED backend's shims,
# capture to <bakelog>, echo the classification. Returns nonzero ONLY on a FATAL setup error (net-shims CAP).
_dr_vps_bake_attempt() {  # <overlay> <expected> <attemptroot> <bakelog> -- <vcnet...>
  local overlay="$1" expect="$2" aroot="$3" bakelog="$4"; shift 4; [ "${1:-}" = -- ] && shift
  dr_vps_net_shims "$aroot" "$expect" || return $?
  local rc; local -a vc st run cmd; vc=("-a" "$overlay" "$@")
  # Per-attempt deadline + best-effort reap. `timeout -k 30 <deadline>` bounds the attempt (SIGTERM then a
  # SIGKILL 30s later); on SIGTERM libguestfs tears down its OWN passt/qemu -- the common path. An OPTIONAL
  # wrapper (DR_VPS_CGROUP_RUN, e.g. 'systemd-run --scope --collect', operator/systemd-set) contains the
  # attempt in a cgroup. KNOWN LIMITATION: on a HARD (SIGKILL) timeout a
  # daemonized passt can survive in that cgroup until it is explicitly scope-killed -- drvps does NOT itself
  # kill the scope (a live-only op needing the unit name + systemctl), so a residual passt is possible on
  # that rare path; orphaned overlay/log TEMPS are GC'd by drvps-rigreaper. See docs/CONCEPT-BUILD-NET.md
  # (Isolation) + docs/CONCEPT-BUILD-NET.md. `env` carries the shim PATH/HV + the fixed direct backend into the
  # (possibly wrapped) child; markers + expected backend are exported so a real run's shims (and, in tests,
  # the fake virt-customize) record here.
  run=(); [ -n "${DR_VPS_CGROUP_RUN:-}" ] && read -r -a run <<<"$DR_VPS_CGROUP_RUN"
  cmd=("${run[@]}" timeout -k 30 "${DR_VPS_BAKE_TIMEOUT:-1800}"
       env "PATH=$DR_VPS_NET_BINDIR:$PATH" "LIBGUESTFS_HV=$DR_VPS_NET_HV" "DR_VPS_NET_MARKERS=$DR_VPS_NET_MARKERS"
           "DR_VPS_NET_EXPECT=$expect" "LC_ALL=C" "LIBGUESTFS_BACKEND=direct"
           "LIBGUESTFS_DEBUG=${DR_VPS_LIBGUESTFS_DEBUG:-0}" "LIBGUESTFS_TRACE=${DR_VPS_LIBGUESTFS_TRACE:-0}"
       "$DR_VIRT_CUSTOMIZE" "${vc[@]}")
  # On a TTY (or DR_VPS_BAKE_PROGRESS=1) stream step markers live while STILL capturing the full log via tee.
  if [ -t 2 ] || [ "${DR_VPS_BAKE_PROGRESS:-}" = 1 ]; then
    "${cmd[@]}" 2>&1 | tee "$bakelog" | _dr_vps_bake_progress
    st=("${PIPESTATUS[@]}"); rc="${st[0]}"          # ATOMIC capture FIRST (a later cmd resets PIPESTATUS)
    # tee failure -> the diagnostic log is UNRELIABLE (partial); do NOT classify from it (a partial probe
    # token could mis-trigger a fallback). Report PROBE_INFRA directly (fatal, no fallback). The progress
    # filter (st[2]) is WARNING only: a cosmetic render failure never invalidates a correctly baked golden.
    if [ "${st[1]:-0}" -ne 0 ]; then printf 'PROBE_INFRA\n'; return 0; fi
  else
    "${cmd[@]}" >"$bakelog" 2>&1 && rc=0 || rc=$?
  fi
  _dr_vps_bake_classify "$rc" "$DR_VPS_NET_MARKERS" "$bakelog"
}

# bake stable deps + the cache CA into the golden. CONCEPT-BUILD-NET rev5: the cache CA is baked FIRST
# (offline), then -- when packages are present (network needed) -- a TRANSACTIONAL passt->slirp bake runs on
# a FRESH overlay per attempt, promoting ONLY the successful overlay (never a partial). A CA-only bake needs
# no egress and runs once with --no-network. Seamed (DR_VIRT_CUSTOMIZE/DR_QEMU/DR_QEMU_IMG) for unit tests.
# Pre-bake free-disk GUARD. An unguarded bake filling DR_VPS_TMP_DIR let a CONCURRENT system rewrite of
# /etc/hosts (NetworkManager/cloud-init/systemd truncate-then-write) hit ENOSPC and leave it EMPTY -- the
# reported "/etc/hosts truncated in place". Refuse a bake below DR_VPS_MIN_FREE_MB (default 10 GiB: a
# growing per-attempt overlay + a promoted flat copy). An unreadable/malformed df reading FAILS CLOSED
# (the guard's whole point is disk-full safety) unless DR_VPS_ALLOW_UNKNOWN_FREE=1; a low reading also fails.
_dr_vps_bake_disk_ok() {  # <dir> [min_mb]  -- refuse if <dir>'s filesystem has < min_mb free (MiB)
  local dir="$1" min="${2:-${DR_VPS_MIN_FREE_MB:-10240}}" avail
  case "$min" in ''|*[!0-9]*) min=10240;; esac
  avail=$(LC_ALL=C df -P -B1M -- "$dir" 2>/dev/null | awk 'NR==2{print $4}')
  case "$avail" in ''|*[!0-9]*)
    # unreadable/malformed df: FAIL CLOSED (the whole point is to prevent a disk-full truncation), unless
    # the operator explicitly opts out. Fail-open would drop the guard exactly when accounting misbehaves.
    [ "${DR_VPS_ALLOW_UNKNOWN_FREE:-0}" = 1 ] \
      && { printf 'dr_vps_image_bake: WARNING -- free space for %s unreadable; DR_VPS_ALLOW_UNKNOWN_FREE=1 -> proceeding.\n' "$dir" >&2; return 0; }
    dr_vps_die "$DR_VPS_E_CAP" "bake refused: cannot read free space for '$dir' (df failed/malformed). Free the disk, or set DR_VPS_ALLOW_UNKNOWN_FREE=1 to override."; return $? ;;
  esac
  [ "$avail" -ge "$min" ] \
    || { dr_vps_die "$DR_VPS_E_CAP" "bake refused: only ${avail} MiB free in $dir (need >= ${min} MiB). A full disk DURING a bake can truncate host files (e.g. /etc/hosts). Free space on that filesystem, or lower the bake free-space floor deliberately (DR_VPS_MIN_FREE_MB for the package bake)."; return $?; }
}

# NOTE (appliance DNS): a systemd-resolved loopback stub (127.0.0.53) breaks the libguestfs bake
# appliance's DNS. An earlier auto-fix that rewrote the GUEST image's /etc/resolv.conf was WITHDRAWN
# libguestfs temporarily substitutes the appliance resolver while networked guest commands
# run, and rewriting that path FAILED with EROFS on the tested stack -- so it is not a reliable appliance
# DNS override. A candidate host-non-invasive fix (a per-process mount-namespace resolv.conf override for
# virt-customize) needs a real KVM/libguestfs integration test before it lands; until then the operator
# hint (_dr_vps_bake_hint) stands.

dr_vps_image_bake() {  # <golden> <recipe.json>
  local golden="$1" recipe="$2" pkgs fam cadir cacmd mode bakelog rc
  # realpath canonicalizes the path (an absolute path can never be mistaken for a jq option, e.g. a file
  # literally named --version); -e requires it to exist. Then the schema envelope guarantees a SINGLE object
  # with correct field types, so every subsequent `jq ... "$recipe"` reads one trusted object. (CODE r4/r5.)
  recipe=$(realpath -e -- "$recipe" 2>/dev/null) || { dr_vps_die "$DR_VPS_E_NOTFOUND" "recipe not found: $2"; return $?; }
  _dr_vps_recipe_ok "$recipe" || { dr_vps_die "$DR_VPS_E_USAGE" "recipe schema invalid -- need a single JSON object with distro/upstream_url/upstream_sha256 nonempty strings, family dnf|apt|zypper|apk (or absent), packages absent or an array of nonempty strings: $recipe"; return $?; }
  pkgs=$(jq -r '(.packages // []) | join(",")' "$recipe")
  fam=$(jq -r '.family // "dnf"' "$recipe")
  # --- offline cache-CA args FIRST (trust store before ANY network action); fail-closed policy unchanged.
  local -a caargs=()
  if [ -f "${DR_VPS_CACHE_CA:-/nonexistent}" ]; then
    case "$fam" in
      apt|apk) cadir=/usr/local/share/ca-certificates; cacmd='update-ca-certificates' ;;
      zypper)  cadir=/etc/pki/trust/anchors;           cacmd='update-ca-certificates' ;;
      *)       cadir=/etc/pki/ca-trust/source/anchors; cacmd='update-ca-trust extract' ;;
    esac
    caargs=(--copy-in "${DR_VPS_CACHE_CA}:${cadir}/" --run-command "$cacmd")
  elif [ "${DR_VPS_ALLOW_NO_CACHE_CA:-0}" = 1 ]; then
    printf 'dr_vps_image_bake: WARNING -- DR_VPS_CACHE_CA (%s) absent and DR_VPS_ALLOW_NO_CACHE_CA=1; building a golden WITHOUT the cache trust anchor (HTTPS-through-proxy will FAIL).\n' "${DR_VPS_CACHE_CA:-/etc/distro-rig-vps/cache-ca.crt}" >&2
  else
    dr_vps_die "$DR_VPS_E_CAP" "DR_VPS_CACHE_CA (${DR_VPS_CACHE_CA:-/etc/distro-rig-vps/cache-ca.crt}) absent -- refusing to build a cache-untrusted golden (run dr-vps-setup to publish the CA, or set DR_VPS_ALLOW_NO_CACHE_CA=1 for a deliberate no-proxy build)"; return $?
  fi
  { [ -z "$pkgs" ] && [ "${#caargs[@]}" -eq 0 ]; } && return 0     # nothing to bake (no pkgs AND no CA)
  dr_vps_have "$DR_VIRT_CUSTOMIZE" \
    || { dr_vps_die "$DR_VPS_E_CAP" "virt-customize ($DR_VIRT_CUSTOMIZE) absent -- install guestfs-tools to bake"; return $?; }
  mkdir -p "$DR_VPS_TMP_DIR" || { dr_vps_die "$DR_VPS_E_GENERIC" "bake: cannot create tmp dir $DR_VPS_TMP_DIR"; return $?; }
  local goldendir; goldendir=$(dirname -- "$golden")
  # --- CA-ONLY (no packages): no egress needed -> single --no-network run IN PLACE, no shims/probe/fallback.
  if [ -z "$pkgs" ]; then
    _dr_vps_bake_disk_ok "$goldendir" 512 || return $?   # CA-only edits the golden IN PLACE -> only a modest floor
    bakelog=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" bake.XXXXXX.log) || { dr_vps_die "$DR_VPS_E_GENERIC" "bake: mktemp bakelog failed"; return $?; }
    [ -t 2 ] && printf '[build] bake log (tail -f to watch): %s\n' "$bakelog" >&2
    LC_ALL=C LIBGUESTFS_BACKEND="${DR_VPS_LIBGUESTFS_BACKEND:-direct}" \
    LIBGUESTFS_DEBUG="${DR_VPS_LIBGUESTFS_DEBUG:-0}" LIBGUESTFS_TRACE="${DR_VPS_LIBGUESTFS_TRACE:-0}" \
      "$DR_VIRT_CUSTOMIZE" --no-network -a "$golden" "${caargs[@]}" >"$bakelog" 2>&1 && rc=0 || rc=$?
    [ "$rc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "bake (virt-customize) failed -- $(_dr_vps_bake_hint "$bakelog")"; return $?; }
    rm -f -- "$bakelog"; return 0
  fi
  # --- PACKAGES: network needed -> OBSERVED, TRANSACTIONAL passt->slirp on fresh overlays -----------------
  _dr_vps_bake_disk_ok "$DR_VPS_TMP_DIR" || return $?   # the per-attempt overlay + attempt root grow here (base is $golden)
  _dr_vps_bake_disk_ok "$goldendir" || return $?        # + a promoted flat copy is created & atomically mv'd here
  mode=$(dr_vps_net_mode) || return $?                 # validates + requires the direct backend
  _dr_vps_libguestfs_ver_warn                          # warn on an untested libguestfs (observe/enforce risk)
  local -a vcnet=("${caargs[@]}" --run-command "$(_dr_vps_bake_probe_cmd "$fam")" --install "$pkgs")
  local -a seq; case "$mode" in passt) seq=(passt);; slirp) seq=(slirp);; *) seq=(passt slirp);; esac
  local base="$golden" bexpect overlay aroot result arc promoted
  local -a report=()
  for bexpect in "${seq[@]}"; do
    overlay=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" bake.XXXXXX.qcow2) || return $?
    rm -f "$overlay"
    "$DR_QEMU_IMG" create -f qcow2 -F qcow2 -b "$base" "$overlay" >/dev/null 2>&1 \
      || { rm -f "$overlay"; dr_vps_die "$DR_VPS_E_GENERIC" "bake: overlay create failed (base=$base)"; return $?; }
    aroot=$(mktemp -d --tmpdir="$DR_VPS_TMP_DIR" bakeattempt.XXXXXX) || { rm -f "$overlay"; return 1; }
    bakelog=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" bake.XXXXXX.log) || { rm -rf "$aroot"; rm -f "$overlay"; return 1; }
    [ -t 2 ] && printf '[build] bake attempt via %s (log: %s)\n' "$bexpect" "$bakelog" >&2
    result=$(_dr_vps_bake_attempt "$overlay" "$bexpect" "$aroot" "$bakelog" -- "${vcnet[@]}"); arc=$?
    [ "$arc" -eq 0 ] || { rm -rf "$aroot"; rm -f "$overlay" "$bakelog"; return "$arc"; }   # net-shims CAP -> fatal
    report+=("$bexpect=$result")
    case "$result" in
      OK)
        # PROMOTE: flatten overlay -> a NEW standalone temp, verify no backing, atomically replace the base.
        promoted=$(mktemp --tmpdir="$goldendir" bake.XXXXXX.qcow2) || { rm -rf "$aroot"; rm -f "$overlay" "$bakelog"; return 1; }  # same FS as $golden -> mv is atomic
        "$DR_QEMU_IMG" convert -O qcow2 "$overlay" "$promoted" >/dev/null 2>&1 \
          || { rm -f "$promoted" "$overlay" "$bakelog"; rm -rf "$aroot"; dr_vps_die "$DR_VPS_E_GENERIC" "bake: promote convert failed"; return $?; }
        # FAIL CLOSED: a failed qemu-img info / invalid JSON / jq error must NOT read as "no backing"
        # (a fail-open substitution would accept a non-standalone golden).
        local pinfo pback
        pinfo=$("$DR_QEMU_IMG" info --output=json "$promoted" 2>/dev/null) \
          || { rm -f "$promoted" "$overlay" "$bakelog"; rm -rf "$aroot"; dr_vps_die "$DR_VPS_E_VERIFY" "bake: qemu-img info failed on promoted golden (cannot verify standalone)"; return $?; }
        # reject EMPTY/null/whitespace stdout (info exit 0 but no JSON): `jq -r ... // ""` yields "" on no
        # input -> would fail OPEN. Require a valid JSON object with a string .format FIRST.
        printf '%s' "$pinfo" | jq -es 'length==1 and (.[0]|type=="object") and (.[0].format|type=="string") and (.[0]."backing-filename"|(type=="null") or (type=="string"))' >/dev/null 2>&1 \
          || { rm -f "$promoted" "$overlay" "$bakelog"; rm -rf "$aroot"; dr_vps_die "$DR_VPS_E_VERIFY" "bake: qemu-img info produced no valid JSON object -- cannot verify promoted golden standalone"; return $?; }
        pback=$(printf '%s' "$pinfo" | jq -rs '.[0]."backing-filename" // ""') \
          || { rm -f "$promoted" "$overlay" "$bakelog"; rm -rf "$aroot"; dr_vps_die "$DR_VPS_E_VERIFY" "bake: qemu-img info JSON parse failed on promoted golden"; return $?; }
        if [ -n "$pback" ]; then
          rm -f "$promoted" "$overlay" "$bakelog"; rm -rf "$aroot"; dr_vps_die "$DR_VPS_E_VERIFY" "bake: promoted golden not standalone (backing: $pback)"; return $?
        fi
        mv -f "$promoted" "$golden" || { rm -f "$promoted" "$overlay" "$bakelog"; rm -rf "$aroot"; return 1; }
        rm -f "$overlay" "$bakelog"; rm -rf "$aroot"
        [ -t 2 ] && printf '[build] baked via %s\n' "$bexpect" >&2
        return 0 ;;
      BACKEND_START|REPO_PROBE_FAILED)
        rm -rf "$aroot"; rm -f "$overlay" "$bakelog"; continue ;;     # discard, try next backend if any
      INSTALL_FAILED)
        rm -rf "$aroot"; rm -f "$overlay"
        dr_vps_die "$DR_VPS_E_GENERIC" "bake: appliance network OK via $bexpect but package install failed -- see $bakelog ; last lines: $(tail -5 "$bakelog" 2>/dev/null | tr '\n' '|')"; return $? ;;
      PROBE_TOOL)   # the guest lacks its package manager (family/image mismatch) -> fatal, NO fallback (slirp would hit the same).
        rm -rf "$aroot"; rm -f "$overlay" "$bakelog"   # a recipe-mismatch needs no bake log -> don't leak one
        dr_vps_die "$DR_VPS_E_GENERIC" "bake: the guest image lacks a package manager for family '$fam' (recipe family/image mismatch?) -- not a network problem. See docs/INSTALL-RUNBOOK.md#appliance-networking"; return $? ;;
      *)   # PROBE_INFRA (launch/kernel/kvm) -> fatal, no fallback; carry the stable kernel/DNS hint.
        rm -rf "$aroot"; rm -f "$overlay"
        dr_vps_die "$DR_VPS_E_GENERIC" "bake (virt-customize) failed -- $(_dr_vps_bake_hint "$bakelog")"; return $? ;;
    esac
  done
  # Sequence exhausted with only fallback-class failures and NO SLIRP_OK -> report WITHOUT offering slirp as
  # a fix (hard remedy invariant), naming each attempt's class.
  local msg="bake: no usable appliance backend (${report[*]})."
  # NEUTRAL wording -- a BACKEND_START class is a backend/launch fault, NOT "repo/DNS/egress"; only when
  # BOTH classes are REPO_PROBE_FAILED is a shared repo/egress cause likely (no false causal claim).
  case "$mode" in
    slirp) msg="$msg Explicit slirp requested; its attempt failed with the class above. See docs/INSTALL-RUNBOOK.md#appliance-networking." ;;
    passt) msg="$msg Explicit passt requested; its attempt failed with the class above. Investigate passt on this host. See docs/INSTALL-RUNBOOK.md#appliance-networking." ;;
    *)     msg="$msg Neither backend produced a working appliance network. If BOTH classes are REPO_PROBE_FAILED it is most likely a host repo/DNS/egress issue; a BACKEND_START class means passt/qemu failed to start or enforce. See docs/INSTALL-RUNBOOK.md#appliance-networking." ;;
  esac
  dr_vps_die "$DR_VPS_E_GENERIC" "$msg"; return $?
}

# build: fetch -> verify -> bake -> digest -> provenance -> register. Prints artifact_id.
dr_vps_image_build() {  # <recipe.json>
  local recipe="$1" url sha sig pkgs distro family repoc repor rhash work aid gpath prov ts
  recipe=$(realpath -e -- "$recipe" 2>/dev/null) || { dr_vps_die "$DR_VPS_E_NOTFOUND" "recipe not found: $recipe"; return $?; }
  _dr_vps_recipe_ok "$recipe" || { dr_vps_die "$DR_VPS_E_USAGE" "recipe schema invalid -- need a single JSON object with distro/upstream_url/upstream_sha256 nonempty strings, family dnf|apt|zypper|apk (or absent), packages absent or an array of nonempty strings: $recipe"; return $?; }
  # Ordering guard (deploy ordering: golden build vs fresh install): a golden built BEFORE
  # `dr-vps-setup` wrote /etc/distro-rig-vps/env registers under the DEV DEFAULT store paths, so a later
  # `create` on the installed rig fails "no greened golden" though build returned rc=0. Warn LOUD to STDERR
  # (stdout stays the artifact_id contract) so goldens are built AFTER the fresh install. TTY-gated like the
  # build progress lines below, so it never noises up scripts/tests (which have no installed env by design).
  if [ -t 2 ] && [ ! -e /etc/distro-rig-vps/env ]; then
    printf '[build] WARNING: /etc/distro-rig-vps/env absent -- drvps may not be installed; this golden would\n' >&2
    printf '[build]          register under DEFAULT store paths and a later `create` on the installed rig may\n' >&2
    printf '[build]          not find it. Build goldens AFTER `dr-vps-setup` (deploy ordering).\n' >&2
  fi
  url=$(jq -r '.upstream_url' "$recipe");    sha=$(jq -r '.upstream_sha256' "$recipe")
  sig=$(jq -r '.upstream_sig // ""' "$recipe"); distro=$(jq -r '.distro' "$recipe")
  family=$(jq -r '.family // "dnf"' "$recipe")   # Phase-3 package-manager family (dnf|apt|zypper|apk)
  repoc=$(jq -r '.repo_content // ""' "$recipe") # mirrorlist families (dnf/zypper): the pinned .repo body
  repor=$(jq -r '.repo_remove // ""' "$recipe")  # glob of default repo files to drop (avoid mirror sprawl)
  pkgs=$(jq -c '.packages // []' "$recipe")
  local dsize; dsize=$(jq -r '.disk_size // ""' "$recipe")   # optional: GROW the golden's virtual disk (e.g. "12G")
  { [ -n "$url" ] && [ "$url" != null ] && [ -n "$sha" ] && [ "$sha" != null ] && [ -n "$distro" ] && [ "$distro" != null ]; } \
    || { dr_vps_die "$DR_VPS_E_USAGE" "recipe needs distro, upstream_url, upstream_sha256"; return $?; }
  case "$family" in dnf|apt|zypper|apk) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "unknown distro family '$family' (dnf|apt|zypper|apk)"; return $?;; esac
  # (.packages / field types are already validated up front by _dr_vps_recipe_ok.)
  # zypper REQUIRES a pinned repo_content (seed_build dies without it) -- fail EARLY at build, not at
  # first create, so we never register a guaranteed-unusable golden.
  if [ "$family" = zypper ] && [ -z "$repoc" ]; then
    dr_vps_die "$DR_VPS_E_USAGE" "zypper family needs repo_content in the recipe (pinned .repo body)"; return $?
  fi
  case "$sha" in PIN_ME*) dr_vps_die "$DR_VPS_E_USAGE" "upstream_sha256 is not pinned (PIN_ME...) -- set the vendor sha256 first"; return $?;; esac
  { [ "${#sha}" -eq 64 ] && [[ "$sha" =~ ^[0-9a-fA-F]+$ ]]; } || { dr_vps_die "$DR_VPS_E_USAGE" "upstream_sha256 must be 64 hex chars (got: $sha)"; return $?; }
  rhash=$(dr_vps_recipe_hash "$recipe") || return $?
  mkdir -p "$DR_VPS_POOL_DIR" "$DR_VPS_TMP_DIR"
  work=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" build.XXXXXX.qcow2) || return $?
  local rc
  # PROGRESS (all to STDERR -- stdout stays the artifact_id): dr-vps build is 5-20 min silent otherwise.
  [ -t 2 ] && printf '[build %s] 1/5 fetch %s\n'   "$(date -u +%H:%M:%SZ)" "$url" >&2
  dr_vps_image_fetch "$url" "$work"          || { rc=$?; rm -f "$work"; return "$rc"; }
  [ -t 2 ] && printf '[build %s] 2/5 verify sha256\n' "$(date -u +%H:%M:%SZ)" >&2
  dr_vps_image_verify "$work" "$sha" "$sig"  || { rc=$?; rm -f "$work"; return "$rc"; }
  # OPTIONAL disk GROW: resize the VIRTUAL disk AFTER the sha verify (so upstream_sha256 still checks
  # the ORIGINAL vendor download -- no re-pinning) and BEFORE bake/digest (so the golden, and every VM
  # overlay cloned from it, carries the bigger size; cloud-init growpart expands the guest root on
  # first boot). GROW-only: qemu-img resize refuses to shrink without --shrink, so a disk_size smaller
  # than the base image fails CLOSED here with qemu's own message rather than silently truncating.
  if [ -n "$dsize" ]; then
    [ -t 2 ] && printf '[build %s] 2b/5 grow virtual disk -> %s\n' "$(date -u +%H:%M:%SZ)" "$dsize" >&2
    "$DR_QEMU_IMG" resize "$work" "$dsize" >/dev/null 2>&1 \
      || { rm -f "$work"; dr_vps_die "$DR_VPS_E_USAGE" "disk_size resize to '$dsize' failed (must be LARGER than the upstream image's virtual size; qemu-img refuses to shrink)"; return $?; }
  fi
  [ -t 2 ] && printf '[build %s] 3/5 bake (virt-customize -- this is the slow phase)\n' "$(date -u +%H:%M:%SZ)" >&2
  dr_vps_image_bake "$work" "$recipe"        || { rc=$?; rm -f "$work"; return "$rc"; }
  # A golden MUST be standalone -- a backing chain makes its digest depend on external
  # state that can vanish/change while the DB still claims the same artifact_id.
  # FAIL CLOSED on a qemu-img info / jq failure -- an empty fail-open substitution would accept a
  # non-standalone golden as if it had no backing chain (same class as the bake).
  local winfo wback
  winfo=$("$DR_QEMU_IMG" info --output=json "$work" 2>/dev/null) \
    || { rm -f "$work"; dr_vps_die "$DR_VPS_E_VERIFY" "qemu-img info failed on baked image (cannot verify standalone): $url"; return $?; }
  printf '%s' "$winfo" | jq -es 'length==1 and (.[0]|type=="object") and (.[0].format|type=="string") and (.[0]."backing-filename"|(type=="null") or (type=="string"))' >/dev/null 2>&1 \
    || { rm -f "$work"; dr_vps_die "$DR_VPS_E_VERIFY" "qemu-img info produced no valid JSON object -- cannot verify standalone: $url"; return $?; }
  wback=$(printf '%s' "$winfo" | jq -rs '.[0]."backing-filename" // ""') \
    || { rm -f "$work"; dr_vps_die "$DR_VPS_E_VERIFY" "qemu-img info JSON parse failed: $url"; return $?; }
  if [ -n "$wback" ]; then
    rm -f "$work"; dr_vps_die "$DR_VPS_E_VERIFY" "refusing backed (non-standalone) golden: $url"; return $?
  fi
  [ -t 2 ] && printf '[build %s] 4/5 digest (qemu-img convert of the full virtual size)\n' "$(date -u +%H:%M:%SZ)" >&2
  aid=$(dr_vps_golden_digest "$work")        || { rc=$?; rm -f "$work"; return "$rc"; }
  gpath="${DR_VPS_POOL_DIR}/${aid}.qcow2"
  ts=$(date -u +%FT%TZ)
  prov=$(jq -n --arg d "$distro" --arg fam "$family" --arg u "$url" --arg s "$sha" --argjson p "$pkgs" \
    --arg rc "$repoc" --arg rr "$repor" \
    --arg rh "$rhash" --arg aid "$aid" --arg dv "$DR_VPS_DRIVER_VERSION" --arg ts "$ts" \
    '{distro:$d,family:$fam,repo_content:$rc,repo_remove:$rr,upstream_url:$u,upstream_sha256:$s,
      packages:$p,recipe_hash:$rh,artifact_id:$aid,driver_version:$dv,built_at:$ts}') \
    || { rm -f "$work"; dr_vps_die "$DR_VPS_E_GENERIC" "provenance assembly failed (jq)"; return $?; }
  # Serialize concurrent IDENTICAL builds (same deterministic aid -> same gpath) so the whole publish +
  # register + failure-cleanup below is ATOMIC per aid. Without it the check-then-rm on a register failure
  # has a TOCTOU that can delete a concurrent winner's golden. FD 9 (a per-aid lockfile in the scratch dir,
  # GC'd by the reaper) is held until this process exits or the next build reopens it; a crash releases it.

  exec 9>"${DR_VPS_TMP_DIR}/.build-${aid}.lock" || { rm -f "$work"; dr_vps_die "$DR_VPS_E_GENERIC" "cannot open per-aid build lock"; return $?; }
  flock 9 || { rm -f "$work"; dr_vps_die "$DR_VPS_E_GENERIC" "cannot acquire per-aid build lock"; return $?; }
  # idempotent rebuild: if this exact golden is already registered at gpath, keep it as-is
  # (never overwrite/delete a live golden).
  if [ -f "$gpath" ] && [ "$(dr_vps_store_image_get "$aid")" = "$gpath" ]; then
    # RE-DIGEST the registered golden before claiming idempotent success: a corrupted/replaced
    # $gpath must NOT be reported as a good build. Content-match -> idempotent no-op; mismatch -> FAIL CLOSED
    # (do not return a green over a broken registered artifact; operator repairs explicitly).
    if [ "$(dr_vps_golden_digest "$gpath" 2>/dev/null)" = "$aid" ]; then
      [ -t 2 ] && printf '[build %s] already registered (idempotent, no change): %s\n' "$(date -u +%H:%M:%SZ)" "$aid" >&2
      rm -f "$work"; printf '%s\n' "$aid"; return 0
    fi
    rm -f "$work"; dr_vps_die "$DR_VPS_E_VERIFY" "registered golden $aid at $gpath FAILS its content digest (corrupt/tampered) -- refusing idempotent success; operator repair required"; return $?
  fi
  # a pre-existing but UNregistered path must not be clobbered
  if [ -e "$gpath" ]; then rm -f "$work"; dr_vps_die "$DR_VPS_E_CONFLICT" "golden path exists unregistered: $gpath"; return $?; fi
  # NOTE: `if ! cmd; then rc=$?` captures the NEGATION's status (0) -> false success on failure; use `|| {}`.
  # rm BOTH $work AND $gpath: a cross-filesystem mv can create $gpath then fail on source removal, orphaning
  # $gpath (a future build would then hit "golden path exists unregistered").
  mv "$work" "$gpath" || { rc=$?; rm -f "$work" "$gpath"; return "$rc"; }
  # qemu (the VM) reads the golden as a backing file; libvirt chowns the OWNER to qemu on VM
  # start but preserves group+mode, so group=qemu + group-read (0640) keeps the rig (drvps,
  # in the qemu group) able to re-read/re-digest it afterwards. Fail-closed: an inaccessible
  # golden either breaks VM boot (qemu) or recreate (drvps).
  chgrp "$DR_VPS_SEED_GROUP" "$gpath" || { rm -f "$gpath"; dr_vps_die "$DR_VPS_E_GENERIC" "chgrp golden to '$DR_VPS_SEED_GROUP' failed"; return $?; }
  chmod 0640 "$gpath"                 || { rm -f "$gpath"; dr_vps_die "$DR_VPS_E_GENERIC" "chmod golden failed"; return $?; }
  # register is gated; clean ONLY the file we just created if registration fails.
  [ -t 2 ] && printf '[build %s] 5/5 register\n' "$(date -u +%H:%M:%SZ)" >&2
  dr_vps_store_image_register "$aid" "$prov" "$gpath" || {
    rc=$?
    # CONCURRENCY: two identical builds share a deterministic $aid + $gpath. If a concurrent
    # build WON the register race, $aid is now registered at $gpath with matching content -- that is idempotent
    # success, so do NOT rm the winner's file. Only clean up + fail on a genuine registration error.
    if [ -f "$gpath" ] && [ "$(dr_vps_store_image_get "$aid")" = "$gpath" ] && [ "$(dr_vps_golden_digest "$gpath" 2>/dev/null)" = "$aid" ]; then
      [ -t 2 ] && printf '[build %s] registered by a concurrent identical build (idempotent): %s\n' "$(date -u +%H:%M:%SZ)" "$aid" >&2
      printf '%s\n' "$aid"; return 0
    fi
    rm -f "$gpath"; return "$rc"
  }
  [ -t 2 ] && printf '[build %s] done -> %s\n' "$(date -u +%H:%M:%SZ)" "$aid" >&2
  printf '%s\n' "$aid"
}

dr_vps_image_refresh() { dr_vps_image_build "$@"; }   # new artifact_id; old retained (gc-gated)

dr_vps_image_provenance() {  # <artifact_id>
  local p rc; p=$(dr_vps_sql "SELECT provenance FROM images WHERE artifact_id=$(dr_vps_sql_str "$1");"); rc=$?
  # FAIL CLOSED on a DB READ ERROR (E_VERIFY), kept DISTINCT from 'row absent' (E_NOTFOUND): callers seed a VM
  # (or register a snapshot) with a DEFAULT family/repo on ABSENCE, which would be WRONG if a transient sqlite
  # error (lock/IO) merely LOOKED empty. rc!=0 -> read error (fail closed); rc==0 + empty -> genuinely absent.
  [ "$rc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_VERIFY" "provenance read failed for image: $1"; return $?; }
  [ -n "$p" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such image: $1"; return $?; }
  printf '%s\n' "$p"
}

# distros = the registered golden library (id + distro + built_at). GOLDEN-ONLY (CONCEPT R3.1): filter
# kind='golden' so a registered SNAPSHOT (kind='snapshot') can NEVER surface in the golden library listing.
dr_vps_image_ls() {
  dr_vps_sql "SELECT artifact_id||'  '||json_extract(provenance,'\$.distro')||'  '||json_extract(provenance,'\$.built_at')
    FROM images WHERE kind='golden' ORDER BY created_at;"
}
