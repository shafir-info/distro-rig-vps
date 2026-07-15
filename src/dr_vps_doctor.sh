#!/usr/bin/env bash
# dr_vps_doctor.sh -- capability planner / the `create` gate (Stage 2).
# Verifies (fail-closed) before any boot: /dev/kvm usable BY THE RUN USER, libvirt
# reachable, free RAM/disk vs request + host reserve, cloud-localds/nft/qemu-img
# present, nested-virt facts, and the registered-golden digest still matches
# (tamper gate). Host facts are seamed via DR_VPS_FACT_* so unit tests need no KVM.
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

: "${DR_VPS_KVM_DEV:=/dev/kvm}"
: "${DR_VPS_NESTED_PATH:=/sys/module/kvm_intel/parameters/nested}"
: "${DR_VPS_MIN_DISK_MB:=10240}"
: "${DR_VPS_VIRTLOGD_CONF:=/etc/libvirt/virtlogd.conf}"   # bounded max_size/max_backups (installer writes it)

# Test seams (DR_VPS_FACT_*) are honored ONLY under DR_VPS_TEST_SEAMS=1 -- never in a
# real run, so the gate cannot be tricked fail-open by environment alone.
_dr_vps_seam_on() { [ "${DR_VPS_TEST_SEAMS:-}" = 1 ]; }

# kvm fact: ok | stale-group | absent  (test seam: DR_VPS_FACT_KVM)
dr_vps_doctor_kvm() {
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_KVM:-}" ]; then printf '%s\n' "$DR_VPS_FACT_KVM"; return 0; fi
  if [ -r "$DR_VPS_KVM_DEV" ] && [ -w "$DR_VPS_KVM_DEV" ]; then printf 'ok\n'; return 0; fi
  # not openable: is the user a kvm member per /etc/group but NOT in this session?
  local u; u=$(id -un)
  if getent group kvm 2>/dev/null | awk -F: -v u="$u" '{n=split($4,m,",");for(i=1;i<=n;i++)if(m[i]==u)exit 0;exit 1}'; then
    if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx kvm; then printf 'absent\n'; else printf 'stale-group\n'; fi
  else
    printf 'absent\n'
  fi
}

# libvirt fact: ok | unreachable  (test seam: DR_VPS_FACT_LIBVIRT)
dr_vps_doctor_libvirt() {
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_LIBVIRT:-}" ]; then printf '%s\n' "$DR_VPS_FACT_LIBVIRT"; return 0; fi
  if "$DR_VIRSH" -c "$DR_LIBVIRT_URI" version >/dev/null 2>&1; then printf 'ok\n'; else printf 'unreachable\n'; fi
}

dr_vps_doctor_relogin_check() { [ "$(dr_vps_doctor_kvm)" = "stale-group" ]; }

# S5 private result store: when enabled (DR_VPS_RESULT_PRIVATE != 0, the default), the never-root watcher
# grants the agent-owner read on a 0600 drvps-owned result via `setfacl u:<owner>:r` -- which REQUIRES the
# spool fs to support POSIX ACLs. Verify it (fail closed), else a private-mode rig would write results NO
# agent can read (every request would time out). Seam-overridable (DR_VPS_FACT_ACL=ok|unsupported) for unit
# tests; live it probes the real spool fs. Returns 0 = ok / not-required, nonzero = private-mode but no ACL.
dr_vps_doctor_result_acl() {
  [ "${DR_VPS_RESULT_PRIVATE:-1}" = 0 ] && return 0        # legacy 0640 group-read: no ACL needed
  # Under the test seam NEVER probe the real fs: use DR_VPS_FACT_ACL, defaulting to ok when a test does
  # not inject one (so unrelated suites that run doctor don't fail on a live probe). Live probe only off-seam.
  if _dr_vps_seam_on; then
    [ "${DR_VPS_FACT_ACL:-ok}" = ok ]; return $?
  fi
  dr_vps_have setfacl || return 1
  local sp="${DR_VPS_SPOOL_DIR:-}" t rc=1
  [ -n "$sp" ] && [ -d "$sp" ] || return 1
  t=$(mktemp "$sp/.aclprobe.XXXXXX" 2>/dev/null) || return 1
  # probe with a real ACL set + read-back (a fs mounted without 'acl' fails the setfacl or drops the entry).
  if setfacl -m u:0:r "$t" 2>/dev/null && getfacl -pcn "$t" 2>/dev/null | grep -q '^user:0:r'; then
    rc=0
  fi
  rm -f "$t"
  return $rc
}

# registered-artifact tamper gate: the on-disk image must still match its artifact_id. Works for BOTH a
# golden (drvps-raw-v1-*) AND a SNAPSHOT (drvps-snap-v1-*): the raw-stream digest is prefix-agnostic, and a
# snapshot's content id maps 1:1 to the raw digest (same vsize+sha, different prefix), so we map the expected
# id back to the raw form and compare -- no dependency on dr_vps_snapshot.sh here .
dr_vps_doctor_golden_match() {  # <artifact_id: golden OR snapshot>  -> 0 match ; 18 mismatch/missing
  local aid="$1" path actual expect
  path=$(dr_vps_store_image_get "$aid")
  [ -n "$path" ] && [ -f "$path" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "artifact missing for $aid"; return $?; }
  actual=$(dr_vps_golden_digest "$path") || { dr_vps_die "$DR_VPS_E_VERIFY" "cannot digest artifact for $aid"; return $?; }
  case "$aid" in
    drvps-snap-v1-*) expect="drvps-raw-v1-${aid#drvps-snap-v1-}" ;;   # snapshot id -> its raw-digest equivalent
    *)               expect="$aid" ;;
  esac
  [ "$actual" = "$expect" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "artifact TAMPERED: $aid != $actual"; return $?; }
}

_dr_vps_fact_num() { local ov="$1" comp="$2"; if [ -n "$ov" ]; then printf '%s' "$ov"; else printf '%s' "$comp"; fi; }

dr_vps_doctor_host_facts() {  # -> JSON
  local kvm libvirt ram disk nested cl nft qi xl fr="" fd="" fn="" ft=""
  if _dr_vps_seam_on; then
    fr="${DR_VPS_FACT_RAM_MB:-}"; fd="${DR_VPS_FACT_DISK_MB:-}"
    fn="${DR_VPS_FACT_NESTED:-}"; ft="${DR_VPS_FACT_TOOLS:-}"
  fi
  kvm=$(dr_vps_doctor_kvm); libvirt=$(dr_vps_doctor_libvirt)
  ram=$(_dr_vps_fact_num "$fr" "$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)")
  disk=$(_dr_vps_fact_num "$fd" "$(df -Pm "$DR_VPS_STATE_DIR" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)")
  nested=$(_dr_vps_fact_num "$fn" "$(cat "$DR_VPS_NESTED_PATH" 2>/dev/null || echo unknown)")
  if [ -n "$ft" ]; then
    cl=$(printf '%s' "$ft" | jq -r '.cloud_localds'); nft=$(printf '%s' "$ft" | jq -r '.nft'); qi=$(printf '%s' "$ft" | jq -r '.qemu_img')
    xl=$(printf '%s' "$ft" | jq -r '.xmllint // "true"')   # default true so pre-Phase-2 seam facts still pass
  else
    dr_vps_have "$DR_CLOUDLOCALDS" && cl=true || cl=false
    dr_vps_have "$DR_NFT" && nft=true || nft=false
    dr_vps_have "$DR_QEMU_IMG" && qi=true || qi=false
    dr_vps_have "$DR_XMLLINT" && xl=true || xl=false       # Phase-2 gate hard-requires xmllint
  fi
  jq -n --arg kvm "$kvm" --arg lv "$libvirt" --argjson ram "${ram:-0}" --argjson disk "${disk:-0}" \
        --arg nested "$nested" --argjson cl "$cl" --argjson nft "$nft" --argjson qi "$qi" --argjson xl "$xl" \
    '{kvm:$kvm,libvirt:$lv,ram_free_mb:$ram,disk_free_mb:$disk,nested:$nested,
      tools:{cloud_localds:$cl,nft:$nft,qemu_img:$qi,xmllint:$xl}}'
}

# The gate. Returns 12 capability / 13 libvirt-unusable / 0 ok. --json prints facts.
dr_vps_doctor() {
  local json=0 skipram=0 a
  for a in "$@"; do case "$a" in --json) json=1;; --no-ram) skipram=1;; esac; done
  local facts; facts=$(dr_vps_doctor_host_facts)
  [ "$json" -eq 1 ] && printf '%s\n' "$facts"
  local kvm lv ram disk cl nft qi xl
  kvm=$(printf '%s' "$facts" | jq -r '.kvm'); lv=$(printf '%s' "$facts" | jq -r '.libvirt')
  ram=$(printf '%s' "$facts" | jq -r '.ram_free_mb'); disk=$(printf '%s' "$facts" | jq -r '.disk_free_mb')
  cl=$(printf '%s' "$facts" | jq -r '.tools.cloud_localds'); nft=$(printf '%s' "$facts" | jq -r '.tools.nft'); qi=$(printf '%s' "$facts" | jq -r '.tools.qemu_img')
  xl=$(printf '%s' "$facts" | jq -r '.tools.xmllint // "true"')
  case "$kvm" in
    ok) ;;
    stale-group) dr_vps_die "$DR_VPS_E_CAP" "in kvm/libvirt group but this session is STALE -- re-login (or 'newgrp kvm') before /dev/kvm works"; return $? ;;
    *) dr_vps_die "$DR_VPS_E_CAP" "/dev/kvm not usable by $(id -un) -- operator must run dr-vps-setup, then re-login"; return $? ;;
  esac
  [ "$lv" = "ok" ] || { dr_vps_die "$DR_VPS_E_LIBVIRT" "libvirt ($DR_LIBVIRT_URI) unreachable"; return $?; }
  { [ "$cl" = true ] && [ "$nft" = true ] && [ "$qi" = true ] && [ "$xl" = true ]; } \
    || { dr_vps_die "$DR_VPS_E_CAP" "missing tools (cloud_localds=$cl nft=$nft qemu_img=$qi xmllint=$xl)"; return $?; }
  # The private-result-store ACL precondition is DELIBERATELY NOT checked here. This is
  # the generic VM-CREATE gate (also used by direct operator `dr-vps create`), which does NOT consume the
  # agent result store -- coupling it would wrongly refuse operator creates on a non-ACL host. The ACL
  # support is enforced at the WATCHER boundary (drvps_rigctl startup probe) + as a setup postcondition;
  # `dr_vps_doctor_result_acl` remains available for the operator's explicit checks.
  # --no-ram: recreate calls this BEFORE powering off the VM, so the RAM check (which would still
  # count the running VM's own memory) must be skipped here -- recreate runs the real per-request
  # capacity check AFTER destroy, when that RAM is freed. Without this, recreating a VM at the
  # minimum-safe capacity could be wrongly refused.
  if [ "$skipram" -eq 0 ] && [ "$ram" -lt "$(( DR_VPS_DEFAULT_MEM_MB + DR_VPS_HOST_RESERVE_MB ))" ]; then
    dr_vps_die "$DR_VPS_E_CAP" "insufficient free RAM: ${ram}MB < need ${DR_VPS_DEFAULT_MEM_MB}+reserve ${DR_VPS_HOST_RESERVE_MB}MB"; return $?
  fi
  if [ "$disk" -lt "$DR_VPS_MIN_DISK_MB" ]; then
    dr_vps_die "$DR_VPS_E_CAP" "insufficient free disk: ${disk}MB < ${DR_VPS_MIN_DISK_MB}MB"; return $?
  fi
  # Observability: the console-capture subsystem must be healthy + within the DoS budget (fail closed).
  # Placed LAST so the PROD-BYPASS control still trips on kvm/libvirt first; a half-applied deploy (code
  # live but the setup console step not yet run) refuses to create rather than fail open.
  dr_vps_console_assert || return $?
  dr_vps_console_admission "" || return $?
  # Reaper-heartbeat freshness is a HEALTH signal (is the NORMAL readable bound being maintained?), NOT a create
  # precondition: console_admission's EMERGENCY floor already reserves disk for the worst case even if the reaper
  # never runs, so a create is host-safe regardless. Checked ONLY on the operator `dr-vps doctor` run (skipram=0),
  # NOT the create/recreate gate (--no-ram) -- else creates would intermittently fail whenever the reaper timer
  # interval exceeds DR_VPS_CONSOLE_SWEEP_MAX_AGE_S, and always right after a deploy before the first sweep.
  if [ "$skipram" -eq 0 ]; then
    _dr_vps_console_reaper_fresh || { dr_vps_die "$DR_VPS_E_CAP" "console: reaper heartbeat stale/missing (${DR_VPS_STATE_DIR}/console-reaper.last older than ${DR_VPS_CONSOLE_SWEEP_MAX_AGE_S:-1800}s) -- the NORMAL FILE_CAP bound is not being maintained; check 'systemctl status drvps-rigreaper.timer'"; return $?; }
  fi
  return 0
}

# Capacity check for a SPECIFIC request: free RAM must cover the requested mem + the host
# reserve (no overcommit). The generic doctor only knows the default size; create/recreate
# call this with the actual --mem.
dr_vps_doctor_capacity() {  # <mem_mb>
  local req="${1:-0}" facts ram
  [[ "$req" =~ ^[0-9]+$ ]] || { dr_vps_die "$DR_VPS_E_USAGE" "capacity: bad mem: $req"; return $?; }
  facts=$(dr_vps_doctor_host_facts); ram=$(printf '%s' "$facts" | jq -r '.ram_free_mb')
  [ "$ram" -ge "$(( req + DR_VPS_HOST_RESERVE_MB ))" ] \
    || { dr_vps_die "$DR_VPS_E_CAP" "request ${req}MB + reserve ${DR_VPS_HOST_RESERVE_MB}MB > free ${ram}MB"; return $?; }
}

# ---- Observability: console-capture capability + DoS bound (CONCEPT-OBSERVABILITY E/F) ----------
# dr_vps_console_assert: the console-log SUBSYSTEM is healthy (dir owner/mode/label + virtlogd active &
# bounded). dr_vps_console_admission <id>: the AGGREGATE DoS bound (log-bearing VM count + free-space floor
# + per-VM cap from the bounded virtlogd config). Both are wired into the create/recreate hot path (Step 9)
# AND the doctor gate. Both FAIL CLOSED. SELinux label + virtlogd-active are seamed (DR_VPS_FACT_*, honored
# ONLY under DR_VPS_TEST_SEAMS) so unit tests need no root/SELinux/virtlogd; they are exercised for real in
# podman + the live smoke.

# One uncommented `key = value` from the virtlogd config (last wins); empty + rc=1 if unreadable/absent.
_dr_vps_virtlogd_conf_val() {  # <key>
  local key="$1" conf="$DR_VPS_VIRTLOGD_CONF" v
  [ -r "$conf" ] || return 1
  v=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$conf" 2>/dev/null | tail -1)
  [ -n "$v" ] || return 1
  v=${v#*=}; v=${v%%#*}                              # strip key + trailing comment
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"   # trim
  v=${v#\"}; v=${v%\"}
  printf '%s' "$v"
}
# EMERGENCY per-VM cap = virtlogd max_size*(max_backups+1) -- the SYNCHRONOUS host-DoS fail-safe (Stage-1). The
# NORMAL per-log bound is the reaper's FILE_CAP (kept drvps-readable); admission requires free >= max(both floors).
# Echo the cap; return 1 (FAIL CLOSED) if the config is unreadable or not bounded positive ints (max_size=0
# DISABLES rotation -> the emergency fail-safe would be unbounded, so it MUST stay strictly nonzero).
_dr_vps_console_per_vm_cap() {
  local ms mb
  if [ -r "$DR_VPS_VIRTLOGD_CONF" ]; then
    # STRONG: verify virtlogd's ACTUAL config is bounded (readable-but-missing/zero -> fail closed below).
    ms=$(_dr_vps_virtlogd_conf_val max_size)    || return 1
    mb=$(_dr_vps_virtlogd_conf_val max_backups) || return 1
  else
    # FIRST-LIVE-RUN FIX: modern libvirt makes /etc/libvirt mode 0700 (root-only traverse), so the
    # unprivileged watcher CANNOT read virtlogd.conf at all (`[ -r ]` fails on the parent traverse). Fall
    # back to the installer-PERSISTED, validate_env-bounded knobs -- EXACTLY what step_console wrote to
    # virtlogd.conf, and drvps-readable in /etc/distro-rig-vps/env. The admission free-space floor is the
    # independent disk guard regardless of which source proves the per-VM cap.
    ms="${DR_VPS_CONSOLE_VIRTLOGD_MAX_SIZE:-}"
    mb="${DR_VPS_CONSOLE_VIRTLOGD_MAX_BACKUPS:-}"
  fi
  # STRICT base-10 (convergence r3): reject leading zeros -- bash arithmetic reads '010' as OCTAL (8) and
  # '08'/'09' error, so a "validated" leading-zero value would silently mis-bound or fail. `0?*` matches a
  # zero followed by >=1 char (00/08/010...); a bare '0' is allowed (then rejected below by -gt 0 for ms).
  case "$ms" in ''|*[!0-9]*|0?*) return 1 ;; esac
  case "$mb" in ''|*[!0-9]*|0?*) return 1 ;; esac
  [ "$ms" -gt 0 ] || return 1
  # convergence r1: BOUND the inputs so DR_VPS_CONSOLE_MAX_VMS*max_size*(max_backups+1)+reserve cannot
  # overflow 64-bit bash arithmetic (which WRAPS -> negative/tiny floor -> free-floor bypass). 4 GiB/log and
  # 1024 backups are far above any sane virtlogd config; larger = misconfiguration -> fail closed.
  { [ "$ms" -le 4294967296 ] && [ "$mb" -le 1024 ]; } || return 1
  printf '%s' "$(( ms * (mb + 1) ))"
}
# virtlogd is the ACTIVE log manager (socket-activated). Seam: DR_VPS_FACT_VIRTLOGD.
_dr_vps_virtlogd_active() {
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_VIRTLOGD:-}" ]; then [ "$DR_VPS_FACT_VIRTLOGD" = active ]; return; fi
  systemctl is-active --quiet virtlogd.socket 2>/dev/null || systemctl is-active --quiet virtlogd 2>/dev/null
}
# SELinux type of the console dir. Seam: DR_VPS_FACT_CONSOLE_LABEL (the context string). Echoes the context
# (or empty when SELinux is off / no seam -> caller treats "no SELinux" as label-not-applicable).
_dr_vps_console_label() {
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_CONSOLE_LABEL:-}" ]; then printf '%s' "$DR_VPS_FACT_CONSOLE_LABEL"; return 0; fi
  command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || return 0   # no SELinux -> nothing to check
  stat -c '%C' "$DR_VPS_CONSOLE_LOG_DIR" 2>/dev/null
}
# free bytes on the console-dir filesystem. Seam: DR_VPS_FACT_CONSOLE_FREE. return 1 on a non-numeric read.
_dr_vps_console_free_bytes() {
  local v
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_CONSOLE_FREE:-}" ]; then v="$DR_VPS_FACT_CONSOLE_FREE"
  else v=$(df -PB1 "$DR_VPS_CONSOLE_LOG_DIR" 2>/dev/null | awk 'NR==2{print $4}'); fi
  case "$v" in ''|*[!0-9]*|0?*) return 1 ;; esac   # strict base-10 (r4 consistency; a bare 0-free is allowed)
  printf '%s' "$v"
}
# Reaper heartbeat freshness (Stage-1): the FILE_CAP NORMAL bound is enforced only while the reaper sweep runs.
# The reaper writes <STATE>/console-reaper.last at the end of every FULL clean sweep; fresh = mtime within
# DR_VPS_CONSOLE_SWEEP_MAX_AGE_S. Seam: DR_VPS_FACT_CONSOLE_REAPER (fresh|stale). rc 0 fresh, 1 stale/missing.
_dr_vps_console_reaper_fresh() {
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_CONSOLE_REAPER:-}" ]; then [ "$DR_VPS_FACT_CONSOLE_REAPER" = fresh ]; return; fi
  local stamp="${DR_VPS_STATE_DIR}/console-reaper.last" mt now age
  { [ -f "$stamp" ] && [ ! -L "$stamp" ]; } || return 1     # missing/symlink -> stale
  mt=$(stat -c %Y "$stamp" 2>/dev/null) || return 1
  case "$mt" in ''|*[!0-9]*) return 1 ;; esac
  now=$(date +%s); age=$(( now - mt ))
  [ "$age" -ge 0 ] && [ "$age" -le "${DR_VPS_CONSOLE_SWEEP_MAX_AGE_S:-1800}" ]
}

# Console subsystem healthy? Fail closed (12) otherwise. Seam override: DR_VPS_FACT_CONSOLE (ok | <reason>).
dr_vps_console_assert() {
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_CONSOLE:-}" ]; then
    [ "$DR_VPS_FACT_CONSOLE" = ok ] && return 0
    dr_vps_die "$DR_VPS_E_CAP" "console assert (seam): $DR_VPS_FACT_CONSOLE"; return $?
  fi
  local d="$DR_VPS_CONSOLE_LOG_DIR" owner group mode ctx
  [ -n "$d" ] || { dr_vps_die "$DR_VPS_E_CAP" "console: DR_VPS_CONSOLE_LOG_DIR is unset"; return $?; }
  [ ! -L "$d" ] || { dr_vps_die "$DR_VPS_E_CAP" "console dir is a SYMLINK (tamper): $d"; return $?; }
  [ -d "$d" ]   || { dr_vps_die "$DR_VPS_E_CAP" "console dir missing: $d -- run dr-vps-setup"; return $?; }
  owner=$(stat -c '%U' "$d" 2>/dev/null); group=$(stat -c '%G' "$d" 2>/dev/null); mode=$(stat -c '%a' "$d" 2>/dev/null)
  [ "$owner" = "$DR_VPS_SERVICE_USER" ] || { dr_vps_die "$DR_VPS_E_CAP" "console dir owner '$owner' != $DR_VPS_SERVICE_USER: $d"; return $?; }
  [ "$group" = "$DR_VPS_SEED_GROUP" ]   || { dr_vps_die "$DR_VPS_E_CAP" "console dir group '$group' != $DR_VPS_SEED_GROUP: $d"; return $?; }
  # Accept 750 or 2750 (setgid): setgid is NOT a write bit (2750 = rwxr-x---) and is desirable here -- it makes
  # virtlogd's / the pre-created log inherit the dir's group (qemu) so drvps reads it. Reject anything with a
  # group/other WRITE bit or other special bits.
  case "$mode" in 750|2750) ;; *) dr_vps_die "$DR_VPS_E_CAP" "console dir mode '$mode' not in {750,2750} (no group/world write; setgid OK): $d"; return $?; esac
  ctx=$(_dr_vps_console_label)
  if [ -n "$ctx" ]; then
    case "$ctx" in *:virt_log_t:*) ;; *) dr_vps_die "$DR_VPS_E_CAP" "console dir SELinux type != virt_log_t (context '$ctx'): $d"; return $? ;; esac
  fi
  _dr_vps_virtlogd_active || { dr_vps_die "$DR_VPS_E_CAP" "virtlogd is not the active log manager -- console logging unproven"; return $?; }
  _dr_vps_console_per_vm_cap >/dev/null || { dr_vps_die "$DR_VPS_E_CAP" "virtlogd config ($DR_VPS_VIRTLOGD_CONF) not bounded (max_size>0 + max_backups) -- refusing unbounded console logging (EMERGENCY floor)"; return $?; }
  # NB: reaper-heartbeat freshness is NOT checked here -- console_assert is on the CREATE path, and the EMERGENCY
  # virtlogd cap + console_admission's emergency floor already keep a create host-safe even if the reaper is dead.
  # A dead reaper only degrades the NORMAL (readable) bound -> a HEALTH signal reported by `dr-vps doctor`, not a
  # create precondition (else creates would fail between reaper-timer runs). See dr_vps_doctor (skipram=0 branch).
  dr_vps_diag "assert: dir=$d owner=$owner group=$group mode=$mode virtlogd=active bounded OK"
  return 0
}

# Aggregate DoS bound. <id> optional (empty = a health check with no self-exemption / no +1). Fail closed
# (12). Seam override: DR_VPS_FACT_CONSOLE_ADMIT (ok | <reason>).
dr_vps_console_admission() {  # [id]
  local id="${1:-}"
  if _dr_vps_seam_on && [ -n "${DR_VPS_FACT_CONSOLE_ADMIT:-}" ]; then
    [ "$DR_VPS_FACT_CONSOLE_ADMIT" = ok ] && return 0
    dr_vps_die "$DR_VPS_E_CAP" "console admission (seam): $DR_VPS_FACT_CONSOLE_ADMIT"; return $?
  fi
  local cap existing effective free floor _self
  # BOUND the aggregate-arithmetic inputs so the floor cannot overflow 64-bit bash arithmetic (fix r1):
  # STRICT base-10 (convergence r3): `0?*` rejects leading-zero values (octal trap in the arithmetic below).
  case "$DR_VPS_CONSOLE_MAX_VMS"        in ''|*[!0-9]*|0?*) dr_vps_die "$DR_VPS_E_CAP" "console admission: DR_VPS_CONSOLE_MAX_VMS not a base-10 non-negative integer"; return $? ;; esac
  case "$DR_VPS_CONSOLE_RESERVE_MARGIN" in ''|*[!0-9]*|0?*) dr_vps_die "$DR_VPS_E_CAP" "console admission: DR_VPS_CONSOLE_RESERVE_MARGIN not a base-10 non-negative integer"; return $? ;; esac
  { [ "$DR_VPS_CONSOLE_MAX_VMS" -le 1048576 ] && [ "$DR_VPS_CONSOLE_RESERVE_MARGIN" -le 1125899906842624 ]; } \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: MAX_VMS/RESERVE_MARGIN out of sane bounds (overflow guard)"; return $?; }
  cap=$(_dr_vps_console_per_vm_cap) \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: virtlogd config not bounded/provable -- refusing"; return $?; }
  # AUTHORITATIVE count (fix r1): log-bearing VM count = the rig's STORE ROWS. A row exists from create-commit
  # (BEFORE define + virtlogd), so a just-started / mid-create VM whose <id>.log has not YET materialized
  # (virtlogd writes async) is STILL counted -- counting *.log files UNDERcounts (fail open). Every post-
  # observability VM is log-bearing; a legacy no-log VM is over-counted, which fails SAFE (toward refusing).
  existing=$(dr_vps_sql "SELECT COUNT(*) FROM vms;") \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: cannot read the VM store -- refusing"; return $?; }
  case "$existing" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_CAP" "console admission: bad VM count -- refusing"; return $? ;; esac
  effective="$existing"
  if [ -n "$id" ]; then
    # id-fence inlined (mirrors _dr_vps_safe_id, which lives in storage.sh -- NOT sourced by doctor.sh).
    case "$id" in .|..|-*|*[!A-Za-z0-9_.-]*) dr_vps_die "$DR_VPS_E_USAGE" "console admission: unsafe id: $id"; return $? ;; esac
    # a recreate/retry whose OWN row already exists is already inside `existing` (no +1); a FRESH id adds one.
    _self=$(dr_vps_sql "SELECT 1 FROM vms WHERE id=$(dr_vps_sql_str "$id");") \
      || { dr_vps_die "$DR_VPS_E_CAP" "console admission: self-row read failed -- refusing"; return $?; }
    [ -n "$_self" ] || effective=$(( existing + 1 ))
  fi
  [ "$effective" -le "$DR_VPS_CONSOLE_MAX_VMS" ] \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: $effective log-bearing VMs > DR_VPS_CONSOLE_MAX_VMS=$DR_VPS_CONSOLE_MAX_VMS"; return $?; }
  free=$(_dr_vps_console_free_bytes) \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: cannot read free space on $DR_VPS_CONSOLE_LOG_DIR -- refusing"; return $?; }
  # TWO-TIER floor (Stage-1): NORMAL = reaper cap FILE_CAP + overshoot slack; EMERGENCY = virtlogd ms*(mb+1).
  # Require free >= max(both): emergency is the HARD synchronous guarantee, normal the soft (reaper) target.
  local normal_cap normal_floor emergency_floor
  case "$DR_VPS_CONSOLE_FILE_CAP"        in ''|*[!0-9]*|0?*) dr_vps_die "$DR_VPS_E_CAP" "console admission: DR_VPS_CONSOLE_FILE_CAP not a base-10 positive integer"; return $? ;; esac
  case "$DR_VPS_CONSOLE_OVERSHOOT_BYTES" in ''|*[!0-9]*|0?*) dr_vps_die "$DR_VPS_E_CAP" "console admission: DR_VPS_CONSOLE_OVERSHOOT_BYTES not a base-10 non-negative integer"; return $? ;; esac
  { [ "$DR_VPS_CONSOLE_FILE_CAP" -gt 0 ] && [ "$DR_VPS_CONSOLE_FILE_CAP" -le 4294967296 ] && [ "$DR_VPS_CONSOLE_OVERSHOOT_BYTES" -le 4294967296 ]; } \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: FILE_CAP/OVERSHOOT out of sane bounds (overflow guard)"; return $?; }
  normal_cap=$(( DR_VPS_CONSOLE_FILE_CAP + DR_VPS_CONSOLE_OVERSHOOT_BYTES ))
  normal_floor=$(( DR_VPS_CONSOLE_MAX_VMS * normal_cap + DR_VPS_CONSOLE_RESERVE_MARGIN ))
  emergency_floor=$(( DR_VPS_CONSOLE_MAX_VMS * cap + DR_VPS_CONSOLE_RESERVE_MARGIN ))
  floor=$emergency_floor; [ "$normal_floor" -gt "$floor" ] && floor=$normal_floor      # max(normal, emergency)
  [ "$free" -ge "$floor" ] \
    || { dr_vps_die "$DR_VPS_E_CAP" "console admission: free ${free}B < floor ${floor}B (max normal=${normal_floor} emergency=${emergency_floor})"; return $?; }
  dr_vps_diag "admission: id=${id:-<none>} existing=$existing effective=$effective max=$DR_VPS_CONSOLE_MAX_VMS normal_floor=${normal_floor}B emergency_floor=${emergency_floor}B free=${free}B floor=${floor}B OK"
  return 0
}

# ---- version / build identity (the `version` verb: agent + operator introspection) ---------------
# Emits the static VERSION + DR_VPS_DRIVER_VERSION AND a per-build FINGERPRINT (sha256 over the running
# src/+bin/ trees) so a single `dr-vps version` / `rigctl version` tells you EXACTLY which build is live
# and whether the daemon matches the on-disk tree -- closes the old/new-build confusion. Pure read; no seams.
_dr_vps_build_fingerprint() {  # -> 16-hex over $DR_VPS_ROOT/{src,bin} file CONTENT, path-relative + deterministic
  local root="${DR_VPS_ROOT:-}" f h
  { [ -n "$root" ] && [ -d "$root/src" ]; } || { printf 'unknown'; return 0; }
  {
    # exclude GENERATED files (__pycache__/*.pyc) so the fingerprint tracks SOURCE, not the Python bytecode
    # cache that drifts by interpreter version / import side effects.
    find "$root/src" "$root/bin" -type f -not -path '*/__pycache__/*' -not -name '*.pyc' -print0 2>/dev/null | LC_ALL=C sort -z |
    while IFS= read -r -d '' f; do
      h="$(sha256sum -- "$f" 2>/dev/null | cut -d' ' -f1)"
      printf '%s\0%s\0' "${f#"$root"/}" "$h"   # NUL-framed (relpath, content-hash): injective even for a path with space/newline; path-prefix independent
    done
  } | sha256sum | cut -c1-16
}

dr_vps_version() {  # 3 lines: version / driver_version / build_fingerprint  (stdout is the contract)
  local ver="unknown"
  [ -r "${DR_VPS_ROOT:-}/VERSION" ] && ver="$(cat "${DR_VPS_ROOT}/VERSION" 2>/dev/null)"
  printf 'version: %s\n'           "${ver:-unknown}"
  printf 'driver_version: %s\n'    "${DR_VPS_DRIVER_VERSION:-0.2.0}"
  printf 'build_fingerprint: %s\n' "$(_dr_vps_build_fingerprint)"
}
