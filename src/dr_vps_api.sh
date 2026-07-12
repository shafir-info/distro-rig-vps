#!/usr/bin/env bash
# dr_vps_api.sh -- the LOCKED dr_vps_* signature contract + shared constants/seams.
#
# Sourced FIRST by bin/dr-vps and by every module. It defines: exit-code constants,
# the command seams (so unit tests run with no real KVM), the path/config defaults,
# and -- as the authoritative comment manifest below -- every dr_vps_* function
# signature. Later stages fill the bodies in src/dr_vps_<module>.sh; they MUST NOT
# reshape these signatures. ASCII only; bins run set -uo pipefail (code is also -e-safe).
#
# Phase 1 scope (CONCEPT rev2 / PLAN rev2): local VM backend + bootstrap + `simulated`
# deny-by-default egress + dogfood. No broker / tenants / quotas / remote (P3/P4).

# Constants and seam vars below are the shared contract, consumed by sourcing modules
# and bin/dr-vps -- not unused within this file.
# shellcheck disable=SC2034
# ---- guard against double-source -------------------------------------------------
[ -n "${DR_VPS_API_SOURCED:-}" ] && return 0
DR_VPS_API_SOURCED=1

# ---- exit codes (authoritative; CONCEPT s9) --------------------------------------
# 0 ok . 1 generic . 2 usage . 10 unknown-distro . 11 ungreened . 12 capability
# 13 libvirt-unusable . 14 not-found . 15 conflict/lease . 16 ip/port-collision
# 17 timeout . 18 golden-verify-failed . 19 referenced (gc-gated) . 20 quarantined
# 24 egress-policy-refused . 25 secret-policy-refused . (22 quota / 23 authz = P3)
readonly DR_VPS_E_OK=0          DR_VPS_E_GENERIC=1     DR_VPS_E_USAGE=2
readonly DR_VPS_E_UNKNOWN=10    DR_VPS_E_UNGREENED=11  DR_VPS_E_CAP=12
readonly DR_VPS_E_LIBVIRT=13    DR_VPS_E_NOTFOUND=14   DR_VPS_E_CONFLICT=15
readonly DR_VPS_E_COLLISION=16  DR_VPS_E_TIMEOUT=17    DR_VPS_E_VERIFY=18
readonly DR_VPS_E_REFERENCED=19 DR_VPS_E_QUARANTINED=20
readonly DR_VPS_E_EGRESS=24     DR_VPS_E_SECRET=25

# ---- command seams (override in tests to avoid real KVM/privileged ops) ----------
: "${DR_VIRSH:=virsh}"
: "${DR_QEMU_IMG:=qemu-img}"
: "${DR_VIRT_CUSTOMIZE:=virt-customize}"
: "${DR_VIRT_SYSPREP:=virt-sysprep}"          # SNAPSHOT feature: identity/secret scrub (guestfs-tools); seamed in bats
: "${DR_CLOUDLOCALDS:=cloud-localds}"
: "${DR_NFT:=nft}"
: "${DR_SQLITE:=sqlite3}"
: "${DR_SSH:=ssh}"
: "${DR_SCP:=scp}"
: "${DR_LIBVIRT_URI:=qemu:///system}"
# Agent-control-loop seams -- see CONCEPT.md.
: "${DR_XMLLINT:=xmllint}"
: "${DR_INOTIFYWAIT:=inotifywait}"
: "${DR_FLOCK:=flock}"
: "${DR_SETSID:=setsid}"
: "${DR_TIMEOUT:=timeout}"

# An installed deployment writes its system paths here; source it FIRST so the CLI + lib
# use the same pool/seed/state the installer prepared, without the operator exporting env
# forever. Explicit env still wins (sourced values feed the ':=' below).
# shellcheck disable=SC1091  # optional runtime file written by the installer
# Skipped under tests (DR_VPS_TEST_SEAMS=1) so a host's installed env can't override a test's
# DR_VPS_STATE_DIR etc. The file itself uses ':=' so explicit env still wins in production.
[ "${DR_VPS_TEST_SEAMS:-}" = 1 ] || { [ -r /etc/distro-rig-vps/env ] && . /etc/distro-rig-vps/env; }

# ---- path / config defaults (no operational magic; all overridable) --------------
: "${DR_VPS_STATE_DIR:=${HOME}/.local/state/distro-rig-vps}"
: "${DR_VPS_POOL_DIR:=${DR_VPS_STATE_DIR}/pool}"      # goldens + overlays (fixed prefix)
: "${DR_VPS_SNAP_DIR:=${DR_VPS_STATE_DIR}/snapshots}" # SNAPSHOT bundles (drvps-owned; SEGREGATED from POOL_DIR)
: "${DR_VPS_SNAPSHOT_VALIDATE:=0}"                    # 1 = run the disposable-overlay validation boot (live)
: "${DR_VPS_SEED_DIR:=${DR_VPS_STATE_DIR}/seed}"      # NoCloud seeds (0640 drvps:qemu)
: "${DR_VPS_DB:=${DR_VPS_STATE_DIR}/store.db}"
: "${DR_VPS_TMP_DIR:=${DR_VPS_STATE_DIR}/tmp}"        # raw-export scratch for the digest
: "${DR_VPS_SSH_MUX:=0}"                              # Fix 1: guest-exec SSH connection reuse (0=off default, 1=on)
: "${DR_VPS_CTRL_DIR:=${DR_VPS_STATE_DIR}/ctrl}"      # per-VM ssh control sockets (0700; kept short for ControlPath limit)
: "${DR_VPS_SSH_MUX_PERSIST:=300}"                    # ControlPersist seconds (one scenario's exec burst; self-expires)
: "${DR_VPS_JOBS_DIR:=${DR_VPS_STATE_DIR}/jobs}"      # native async-exec: host-side job table (0700)
: "${DR_VPS_JOB_MAX_RUNTIME:=3600}"                   # a running job older than this -> driver-timeout (fail-closed)
: "${DR_VPS_JOB_TTL:=86400}"                          # terminal job dirs older than this -> reaped (bounded state)
: "${DR_VPS_JOB_MAX_PER_VM:=64}"                       # cap live jobs per VM (disk/handle exhaustion guard)
: "${DR_VPS_JOB_REAP_EXEC_TIMEOUT:=10}"                # SHORT per-guest-exec timeout in the reaper sweep (r8: don't hold the work-lock for minutes)
: "${DR_VPS_JOB_REAP_MAX_PER_SWEEP:=128}"              # cap guest probes per sweep so the timer can't starve the watcher
: "${DR_VPS_JOB_REAP_MAX_SECONDS:=60}"                 # WALL-CLOCK cap on guest-probing per sweep (r9: count budget alone could still hold the work-lock ~40min)
: "${DR_VPS_ETC_DIR:=$(cd "$(dirname "${BASH_SOURCE[0]}")/../etc" 2>/dev/null && pwd || echo /etc/distro-rig-vps)}"
: "${DR_VPS_ROOT:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || echo /opt/distro-rig-vps)}"   # install root (src/+bin/); used by the version verb's build fingerprint
: "${DR_VPS_SERVICE_USER:=drvps}"
: "${DR_VPS_HOST_RESERVE_MB:=8192}"                   # never allocate the host's last RAM
: "${DR_VPS_DEFAULT_MEM_MB:=4096}"
: "${DR_VPS_DEFAULT_VCPUS:=2}"
# Guest CPU model (config-driven, NOT hardcoded). host-model exposes the host's real feature level
# (x86-64-v2/v3) so el9-family glibc (centos9/rocky9) boots -- omitting <cpu> defaulted to qemu64 (v1) and
# PANICKED those guests at init. Bounded to what the GATE permits: host-passthrough is gate-REFUSED (bare
# host CPU, dr_vps_gate.sh badconf); render validates against this allowlist and fails closed otherwise.
: "${DR_VPS_CPU_MODE:=host-model}"
# Machine type + guest features knobs -- RESERVED for Stage 7 (NOT yet wired into render_xml, which currently
# HARDCODES machine='q35' + <features><acpi/></features>). Defaults defined here so the Stage-7 wiring is a
# config change, not a new knob; do NOT treat as live-tunable yet.
: "${DR_VPS_MACHINE:=q35}"
: "${DR_VPS_FEATURES:=acpi}"
# Stage-0.C pre-start closedshape gate: off (default -- SAFE TO INSTALL; create/recreate unchanged) | warn
# (run + DIAG a would-refuse, don't block -- observe on real creates) | enforce (block + rollback on refusal).
# Ships default OFF because the sweep is proven offline on the RENDERED XML but not yet on the LIVE inactive
# dumpxml (libvirt augments a defined domain). Flip to warn then enforce after a live smoke validates it.
: "${DR_VPS_PRESTART_GATE:=off}"
: "${DR_VPS_TTL_DEFAULT:=24}"                          # hours; mandatory TTL (reaper is P2)
: "${DR_VPS_SSH_KEY:=${HOME}/.ssh/drvps_vm_ed25519}"  # PRIVATE key for VM-readiness ssh; its .pub is the create default seeded into the guest
# Guest package plumbing (so dnf works under `simulated` egress: proxy to the cache, repos
# PINNED to an allowlisted host so Fedora's metalink mirror-sprawl can't bypass the squid
# allowlist). Bridge IP = 10.123.0.1; dl.fedoraproject.org is in fleet.json mirror_allowlist.
: "${DR_VPS_GUEST_PROXY:=http://10.123.0.1:3128}"
: "${DR_VPS_REPO_HOST:=dl.fedoraproject.org}"
# HTTPS to the canonical official master -- the cache proxy SSL-bumps it (the guest trusts the
# rig's cache CA, baked into the golden), so the otherwise-opaque TLS package traffic is CACHED.
: "${DR_VPS_REPO_SCHEME:=https}"
: "${DR_VPS_CACHE_CA:=/etc/distro-rig-vps/cache-ca.crt}"  # published CA cert (baked into goldens)
# Disks (golden/overlay/seed) are group-owned by the group qemu:///system runs as, with
# group perms, so BOTH the VM (qemu, via group) and the rig (drvps, in that group) can use
# them even after libvirt chowns the OWNER to qemu on VM start (it preserves group+mode).
: "${DR_VPS_SEED_GROUP:=qemu}"
: "${DR_VPS_FLEET_JSON:=${DR_VPS_ETC_DIR}/fleet.json}" # the always-blocked + simulated-allow inventory
: "${DR_VPS_NET_STATE:=/run/distro-rig-vps/nft.applied}" # egress-gen marker on TMPFS (root-owned):
# gone after reboot -> create_guard fails CLOSED until the boot egress oneshot re-applies; the
# unprivileged rig user can read but not FORGE it (root /run dir). Tests override this path.
# ---- Phase-2 agent control loop (spool + caps; all overridable) --------------------
: "${DR_VPS_SPOOL_DIR:=${DR_VPS_STATE_DIR}/spool}"   # requests/processing/results + .lock
: "${DR_VPS_CTL_GROUP:=drvpsctl}"                    # agent + drvps share this; spool group
: "${DR_VPS_REQ_MAX_BYTES:=1048576}"                 # 1 MiB hard cap on a request file
: "${DR_VPS_RESULT_MAX_BYTES:=1048576}"              # 1 MiB hard cap on a result envelope
: "${DR_VPS_TRANSFER_MAX_BYTES:=262144}"             # push/pull base64 payload cap (256 KiB)
: "${DR_VPS_VERB_TIMEOUT:=300}"                       # default per-verb hard timeout (s)
: "${DR_VPS_EXEC_TIMEOUT:=300}"                       # exec/push/pull guest op timeout (s)

# ---- Observability: persistent console capture (CONCEPT-OBSERVABILITY) --------
# A per-VM serial <log file> persisted by virtlogd so `console-dump` has boot output to read.
# The guestexec GATE allows EXACTLY this one canonical path per VM (fenced under CONSOLE_LOG_DIR).
: "${DR_VPS_CONSOLE_LOG_DIR:=/var/log/distro-rig-vps/console}"   # drvps:qemu 0750, virt_log_t
: "${DR_VPS_CONSOLE_TAIL_MAX_BYTES:=65536}"           # console-dump bounded tail (64 KiB)
# Stage-1 TWO-TIER DoS bound: the drvps reaper tail-compacts each log to FILE_CAP (NORMAL, keeps readability);
# virtlogd MAX_SIZE is the EMERGENCY synchronous fail-safe (>> FILE_CAP; if it fires the log degrades to
# root-owned/unreadable but the HOST is protected). Admission asserts BOTH floors (doctor.sh).
: "${DR_VPS_CONSOLE_FILE_CAP:=524288}"                # reaper NORMAL per-log cap (512 KiB); tail-compacted in place
: "${DR_VPS_CONSOLE_OVERSHOOT_BYTES:=524288}"         # ADMISSION-slack only (free-space budgeting) -- NOT an enforced per-log loss bound
: "${DR_VPS_CONSOLE_VIRTLOGD_MAX_SIZE:=2097152}"      # EMERGENCY rotation cap (>> FILE_CAP); virtlogd max_size
: "${DR_VPS_CONSOLE_VIRTLOGD_MAX_BACKUPS:=3}"         # EMERGENCY rotated backups kept (virtlogd max_backups)
: "${DR_VPS_CONSOLE_MAX_VMS:=64}"                     # admission: max concurrent log-bearing VMs
: "${DR_VPS_CONSOLE_RESERVE_MARGIN:=1073741824}"      # free-space margin above the worst-case budget (1 GiB)
: "${DR_VPS_CONSOLE_SWEEP_MAX_AGE_S:=1800}"           # doctor-ONLY: heartbeat older = reaper dead. MUST exceed the drvps-rigreaper.timer interval (OnUnitActiveSec=15min) or doctor false-alarms between sweeps

# ---- DIAG: flag-gated, metadata-only diagnostic trace of the tricky RUNTIME acts (SPEC-DIAG.md) -----
# DR_VPS_DIAG unset = OFF (dr_vps_diag is a no-op). When set, gate/admission/assert/prepare/gc/console-dump/
# inspect/ready append ONE metadata line each (ids/counts/decisions -- NEVER console content or secrets) to
# a drvps:drvpsctl 0640 file under the SPOOL (agent-readable, not world; the reaper size-rotates it).
: "${DR_VPS_DIAG_FILE:=${DR_VPS_SPOOL_DIR}/diag/drvps-diag.log}"
: "${DR_VPS_DIAG_MAX_BYTES:=16777216}"                # reaper rotates the diag file to .1 above this (16 MiB)

# Shared SSH hardening opts (observability: kill the known_hosts collision rc=255). Defined HERE (not
# in remote.sh) because dr_vps_domain.sh does NOT source remote.sh but every module sources api.sh.
# Disposable egress-fenced guests reached with a dedicated key gain nothing from persistent TOFU; the
# gate + egress fence + dedicated key are the controls. LogLevel=ERROR silences "Permanently added".
# shellcheck disable=SC2034  # consumed by _dr_vps_ssh/_dr_vps_scp (remote.sh) + dr_vps_domain_ready (domain.sh)
_DR_VPS_SSH_HARDEN=(-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no
                    -o StrictHostKeyChecking=no -o LogLevel=ERROR)

# =================================================================================
# SIGNATURE MANIFEST (the locked contract). Bodies land in the named module files.
# =================================================================================
#
# src/dr_vps_identity.sh
#   dr_vps_sha256 <file>                         -> sha256 hex on stdout
#   dr_vps_canon <<<json | dr_vps_canon <file>   -> canonical JSON (sorted keys)
#   dr_vps_recipe_hash <recipe.json>             -> recipe_hash (build intent only)
#   dr_vps_golden_digest <golden.qcow2>          -> artifact_id (drvps-raw-v1, D-P4)
#   dr_vps_instance_id <name> [project]          -> instance id (pins one artifact)
#
# src/dr_vps_store.sh
#   dr_vps_sql_str <s> / dr_vps_sql_int <n>      -> one safe-quoting path
#   dr_vps_store_init [db]
#   dr_vps_store_image_register <artifact_id> <provenance_json> <golden_path>
#   dr_vps_store_image_get <artifact_id> / dr_vps_store_image_ls
#   dr_vps_store_image_refcount <artifact_id>    -> integer
#   dr_vps_store_image_delete <artifact_id>      -> refcount-gated (19 if referenced)
#   dr_vps_store_vm_create <id> <artifact_id> <overlay> <egress_gen> <ttl>
#   dr_vps_store_vm_get <id> / dr_vps_store_vm_set_state <id> <state>
#   dr_vps_store_vm_set_contract <id> <contract> / dr_vps_store_vm_get_contract <id>   (Stage-0 resolved contract)
#   dr_vps_store_vm_cas_generation <id> <expected> <new>   -> 15 on stale
#   dr_vps_store_vm_delete <id>
#   dr_vps_store_overlay_add <vm_id> <overlay_path>
#   dr_vps_store_net_record <name> <egress_gen>  / dr_vps_store_egress_gen
#
# src/dr_vps_doctor.sh
#   dr_vps_doctor [--json]                       -> gate; 12/13 on miss
#   dr_vps_doctor_host_facts                     -> JSON (seamed: kvm/libvirt/ram/disk/nested)
#   dr_vps_doctor_kvm / dr_vps_doctor_libvirt
#   dr_vps_doctor_relogin_check                  -> in group per id but /dev/kvm not open
#   dr_vps_doctor_golden_match <artifact_id>     -> registered-golden tamper gate (18)
#   dr_vps_console_assert                        -> console dir owner/mode/label + virtlogd active+bounded (fail-closed)
#   dr_vps_console_admission [id]                -> aggregate DoS bound: log-bearing count<=MAX_VMS + free-floor (fail-closed)
#
# src/dr_vps_image.sh                            [BUILD plane -- controlled host egress]
#   dr_vps_image_build <recipe.json>             -> fetch+verify+bake+digest+provenance+register
#   dr_vps_image_fetch <url> <dest>
#   dr_vps_image_verify <file> <sha256> [sig]    -> 18 on mismatch
#   dr_vps_image_bake <golden> <recipe.json>     -> virt-customize build-time installs
#   dr_vps_image_provenance <artifact_id>       -> the stored provenance JSON
#   dr_vps_image_ls    (= `dr-vps distros`)      / dr_vps_image_refresh <recipe.json>
#
# src/dr_vps_storage.sh                          [path-fence + seed lifecycle]
#   dr_vps_storage_path_fence <path>             -> realpath under DR_VPS_POOL_DIR or refuse
#   dr_vps_storage_overlay_create <vm_id> <artifact_id>  -> overlay path
#   dr_vps_storage_overlay_delete <overlay_path> -> path-fenced
#   dr_vps_storage_backing_check <overlay> <expected_golden>
#   dr_vps_storage_seed_build <vm_id> <ssh_key_file>     -> seed path (0640 drvps:qemu, labeled)
#   dr_vps_storage_seed_cleanup <vm_id>
#   dr_vps_console_log_prepare <id>              -> fresh-inode serial-log slot (fenced; refuse symlink)
#   dr_vps_console_log_tail <id> <cap>           -> bounded tail of the persisted console log
#   dr_vps_console_log_cleanup <id>              -> path-fenced remove (log + rotated .N)
#   dr_vps_console_log_path <id>  [api.sh]       -> canonical ${DR_VPS_CONSOLE_LOG_DIR}/<id>.log
#
# src/dr_vps_net.sh                              [simulated deny-by-default]
#   dr_vps_net_render [profile]                  -> nft ruleset from the fleet inventory
#   dr_vps_net_apply                             -> load ruleset (privileged; installer)
#   dr_vps_net_generation                        -> current egress-generation
#   dr_vps_net_create_guard <vm_net>             -> refuse unsafe/missing/stale (24)
#   dr_vps_net_dns_policy                        -> render DNS policy (no internal resolver)
#   dr_vps_proxy_allowlist_check <host>          -> SSRF: non-mirror -> refuse
#
# src/dr_vps_domain.sh
#   dr_vps_domain_render_xml <vm_id> <overlay> <seed> <net> [mem_mb] [vcpus] [uuid] [cpu_mode]
#                                                -> TEMPLATED+escaped xml only; autostart OFF
#   dr_vps_domain_create <name> <distro> [--net N][--ttl H][--mem M][--cpus N][--ssh-key F][--project P]
#   dr_vps_domain_wait <id> [timeout]            -> boot + cloud-init + ssh reachable
#   dr_vps_domain_console <id>                   -> serial (break-glass)
#   dr_vps_domain_recreate <id>                  -> drop overlay + new-from-pinned-golden
#   dr_vps_domain_destroy <id>                   -> stop + undefine + path-fenced overlay drop
#   dr_vps_domain_verify_baseline <id>           -> pin/backing-chain/policy (NOT live-clean)
#   dr_vps_domain_inspect <id>                   -> read-only HOST-side facts (lifecycle-gated; no SSH)
#   dr_vps_console_log_gc                        -> reap fenced console logs with no store row + no live domain (needs _dr_virsh)
#
# bin/dr-vps        : dispatch (distros|create|list|status|console|recreate|destroy|doctor)
# bin/dr-vps-setup  : privileged one-time installer (operator sudo; CONCEPT s7)
# =================================================================================

# ---- tiny shared helpers (real, used everywhere) ---------------------------------
dr_vps_die() {            # dr_vps_die <code> <msg...>   (human -> stderr)
  local code="$1"; shift
  printf 'dr-vps: %s\n' "$*" >&2
  return "$code"
}
dr_vps_have() { command -v "$1" >/dev/null 2>&1; }   # tool presence

# Canonical per-VM console-log path (SINGLE source of truth used by render, gate, tail, cleanup,
# inspect). Pure path computation; the caller supplies an already-safe-id (_dr_vps_safe_id upstream).
dr_vps_console_log_path() { printf '%s/%s.log' "$DR_VPS_CONSOLE_LOG_DIR" "$1"; }

# ---- DIAG diagnostic trace (SPEC-DIAG.md) ----------------------------------------------------------
# METADATA ONLY: ids, counts, decisions, byte-counts, the console path (agent-derivable). NEVER pass
# console/guest content, secrets, or golden/overlay host paths. Best-effort: a diag failure never fails an op.
_DR_VPS_DIAG_BANNERED=""
# shellcheck disable=SC2034  # _DR_VPS_DIAG_BANNERED is per-process banner state
_dr_vps_diag_write() {  # <line>  -- lazy dir (drvps:drvpsctl 2750 setgid) + file (0640), symlink-refusing append
  local f="${DR_VPS_DIAG_FILE:-}" d
  [ -n "$f" ] || return 0
  d=$(dirname "$f")
  if [ ! -d "$d" ]; then
    mkdir -p "$d" 2>/dev/null || return 0
    chgrp "${DR_VPS_CTL_GROUP:-drvpsctl}" "$d" 2>/dev/null || true   # drvps is usermod -aG drvpsctl (best-effort in tests)
    chmod 2750 "$d" 2>/dev/null || true                             # setgid -> files inherit the drvpsctl group
  fi
  [ ! -L "$f" ] || return 0                                          # never write THROUGH a symlink at the path
  if [ ! -e "$f" ]; then
    : >"$f" 2>/dev/null || return 0
    chmod 0640 "$f" 2>/dev/null || true                             # group-read despite the environment umask 0077
  fi
  printf '%s\n' "$1" >>"$f" 2>/dev/null || true
}
dr_vps_diag() {  # <metadata...>  -- NO-OP unless DR_VPS_DIAG is set. Loud banner on the first emit.
  [ -n "${DR_VPS_DIAG:-}" ] || return 0
  if [ -z "${_DR_VPS_DIAG_BANNERED:-}" ]; then
    _DR_VPS_DIAG_BANNERED=1
    printf 'drvps: DIAG logging ENABLED (debug, metadata-only) -> %s\n' "${DR_VPS_DIAG_FILE:-}" >&2
    _dr_vps_diag_write "=== drvps-diag ENABLED pid=$$ user=$(id -un 2>/dev/null) file=${DR_VPS_DIAG_FILE:-} (metadata-only; debug) ==="
  fi
  _dr_vps_diag_write "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) [$$] $*"
}
