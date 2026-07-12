#!/usr/bin/env bash
# dr_vps_domain.sh -- domain lifecycle (Stage 6, review-hardened). Emits TEMPLATED,
# VALIDATED + XML-ESCAPED libvirt XML only. create/recreate gate (doctor + net_guard +
# golden_match) and roll back partial state on any failure; start failure is FATAL; destroy
# is id-validated, path-fenced, and refuses to touch a registered golden. virsh/ssh/
# cloud-localds/nft are seamed for unit tests. ASCII only; set -uo pipefail safe.

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
# gate is sourced here too: create/recreate/destroy MUST run the live-domain identity gate, and that
# security invariant must NOT depend on a caller's source order (the watcher does not pre-gate destroy,
# so dr-vps destroy's OWN gate is authoritative). gate sources storage/net/api -- already in this list
# -- so there is no cycle.
for _m in identity store image storage net doctor gate; do
  # shellcheck source-path=SCRIPTDIR
  # shellcheck source=/dev/null
  . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_${_m}.sh"
done
unset _m

# LC_ALL=C: virsh output (domstate!) is gettext-translated; state-string parsing must be locale-proof.
_dr_virsh() { LC_ALL=C "$DR_VIRSH" -c "$DR_LIBVIRT_URI" "$@"; }

_dr_vps_xml_escape() {  # minimal XML entity escaping for interpolated values
  # bash 5.2+ REGRESSION GUARD: an unescaped '&' in a ${var//pat/repl} REPLACEMENT means "the matched
  # text" (patsub_replacement, on by default), so a bare '&lt;' would turn '<' into '<lt;'. Write the
  # literal ampersands as '\&'. (The old bare-'&' form only worked because the '&'->'&amp;' case matches
  # '&' anyway; '<'/'>'/'"'/''' were silently mis-escaped for any value containing them.)
  local s="${1-}"; s="${s//&/\&amp;}"; s="${s//</\&lt;}"; s="${s//>/\&gt;}"
  s="${s//\"/\&quot;}"; s="${s//\'/\&apos;}"; printf '%s' "$s"
}
# ^(0|[1-9]...)$: reject leading zeros so `[ "$x" -ge ... ]` can't reinterpret e.g. 0123 as OCTAL.
_dr_vps_is_uint() { [[ "${1-}" =~ ^(0|[1-9][0-9]*)$ ]] && [ "$1" -ge "${2:-1}" ] && [ "$1" -le "${3:-1000000}" ]; }
# mirror _dr_vps_safe_id's fence: no '.'/'..'/leading-dash net names (defence-in-depth; net is fixed today).
_dr_vps_is_netname() { case "${1-}" in ''|.|..|-*|*[!A-Za-z0-9_.-]*) return 1;; *) return 0;; esac; }

# Render the domain XML from a fixed template, with every interpolated value VALIDATED and
# XML-ESCAPED -- so --mem/--cpus/--net cannot break out of the template.
# Stage-0 resolver seam: the SINGLE place that reads the VM's hardware inputs (env-default <- recipe-requirement
# <- create-arg escape hatch) and returns a CANONICAL contract (dr_vps_store canonical k=v format). render +
# preflight + inspect consume THIS -- render itself reads NO env for these fields. Stage-0 emits only cpu_mode
# (host-model today). Recipe REQUIREMENTS are HARD constraints: any value not satisfiable by THIS build FAILS
# CLOSED (never a silent fallback). distro/args are accepted for the Stage-2+ requirement precedence; unused now.
resolve_vm_contract() {  # <id> <distro> [create_args] -> canonical contract on stdout; dies on bad/unsatisfiable
  local id="${1:-}" distro="${2:-}" args="${3:-}"
  _dr_vps_safe_id "$id" || return $?
  # cpu_mode: env-default today (recipe/arg precedence arrives with the Stage-2 cpu_baseline requirement).
  local cpu_mode="${DR_VPS_CPU_MODE:-host-model}"
  case "$cpu_mode" in
    host-model) ;;
    *) dr_vps_die "$DR_VPS_E_USAGE" "unsupported cpu_mode '${cpu_mode}' (allowed: host-model; host-passthrough is gate-refused)"; return $? ;;
  esac
  printf 'cpu_mode=%s\n' "$cpu_mode"   # canonical k=v (sorted); a single line today
}

# Stage-0.C PRE-START GATE dispatcher (DR_VPS_PRESTART_GATE = off|warn|enforce). The closedshape sweep is proven
# offline on the RENDERED XML but NOT yet on the LIVE `dumpxml --inactive` (libvirt augments a defined domain --
# the console-mirror-bug class), so it ships WIRED but DEFAULT OFF: a live smoke validates, then flip to enforce.
#   off     = skip (create/recreate unchanged -- SAFE TO INSTALL)
#   warn    = run + DIAG a would-refuse, but DO NOT block (observe on real creates)
#   enforce = run + roll back + abort on refusal
# rc 0 = proceed to start; rc != 0 = caller must abort (rollback already ran).
_dr_vps_prestart_gate() {  # <id> <overlay> <create|recreate>
  local id="$1" overlay="$2" kind="$3" mode="${DR_VPS_PRESTART_GATE:-off}" ok=1
  case "$mode" in
    off) return 0 ;;
    warn|enforce) ;;
    *) dr_vps_die "$DR_VPS_E_USAGE" "bad DR_VPS_PRESTART_GATE '$mode' (off|warn|enforce)"; return $? ;;
  esac
  # Verify via the gate if loaded; else stay UNVERIFIED (ok=1). enforce treats "refused OR unverifiable" as a
  # refusal and FAILS CLOSED (never start an unverified domain -- a missing gate module must not silently bypass
  # enforcement); warn only logs and proceeds.
  if declare -F dr_vps_gate_vm >/dev/null 2>&1; then
    if dr_vps_gate_vm closedshape "$id" >/dev/null 2>&1; then ok=0; fi
  else
    dr_vps_diag "prestart-gate: gate module not loaded ($kind $id)"
  fi
  [ "$ok" = 0 ] && return 0                                        # SAFE TO BOOT
  if [ "$mode" = warn ]; then
    dr_vps_diag "prestart-gate WARN: closedshape would refuse / could not verify $id ($kind); not enforced"
    return 0
  fi
  if [ "$kind" = create ]; then _dr_vps_create_rollback  "$id" "$overlay" "$DR_VPS_E_EGRESS" "closedshape refused/unverifiable $id (unsafe to boot)"; return $?
  else                          _dr_vps_recreate_rollback "$id"           "$DR_VPS_E_EGRESS" "closedshape refused/unverifiable $id (unsafe to boot)"; return $?; fi
}

dr_vps_domain_render_xml() {  # <vm_id> <overlay> <seed> <net> [mem_mb] [vcpus] [uuid] [cpu_mode]
  local id="$1" overlay="$2" seed="$3" net="$4" mem="${5:-$DR_VPS_DEFAULT_MEM_MB}" vcpus="${6:-$DR_VPS_DEFAULT_VCPUS}" uuid="${7:-}" cpu_mode="${8:-host-model}"
  _dr_vps_safe_id "$id" || return $?
  _dr_vps_is_uint "$mem" 256 1048576 || { dr_vps_die "$DR_VPS_E_USAGE" "bad mem (MiB): $mem"; return $?; }
  _dr_vps_is_uint "$vcpus" 1 256      || { dr_vps_die "$DR_VPS_E_USAGE" "bad vcpus: $vcpus"; return $?; }
  _dr_vps_is_netname "$net"           || { dr_vps_die "$DR_VPS_E_USAGE" "bad net name: $net"; return $?; }
  # CPU model: RESOLVED by resolve_vm_contract (the single seam that reads DR_VPS_CPU_MODE) and PASSED IN as
  # arg 8 -- render reads NO env for it (Stage-0 resolver seam). Re-validate the ARG here (allowlist,
  # defense-in-depth: never trust the caller); host-passthrough is gate-REFUSED, so reject it now with a clear
  # message rather than letting the create fail later at the gate.
  case "$cpu_mode" in
    host-model) ;;
    *) dr_vps_die "$DR_VPS_E_USAGE" "unsupported cpu_mode '${cpu_mode}' (allowed: host-model; host-passthrough is gate-refused)"; return $? ;;
  esac
  # The PINNED uuid is now emitted INSIDE the template (validated here), not sed-injected
  # after the fact by the callers -- so render_xml stays the single templating/escaping choke point.
  local uuid_line=""
  if [ -n "$uuid" ]; then
    case "$uuid" in
      [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;;
      *) dr_vps_die "$DR_VPS_E_USAGE" "bad uuid: $uuid"; return $? ;;
    esac
    uuid_line="  <uuid>${uuid}</uuid>"$'\n'
  fi
  local e_id e_ov e_seed e_net e_clog
  e_id=$(_dr_vps_xml_escape "$id"); e_ov=$(_dr_vps_xml_escape "$overlay")
  e_seed=$(_dr_vps_xml_escape "$seed"); e_net=$(_dr_vps_xml_escape "$net")
  # Observability (Step 6): persist this VM's serial console to the ONE canonical path virtlogd bounds and
  # the guestexec gate accepts (Step 5). Path derived from the id in-template -> render_xml signature UNCHANGED.
  e_clog=$(_dr_vps_xml_escape "$(dr_vps_console_log_path "$id")")
  cat <<EOF
<domain type='kvm'>
  <name>${e_id}</name>
${uuid_line}  <memory unit='MiB'>${mem}</memory>
  <vcpu>${vcpus}</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>
  <features><acpi/></features>
  <cpu mode='${cpu_mode}'/>
  <on_reboot>restart</on_reboot>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${e_ov}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${e_seed}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='${e_net}'/>
      <model type='virtio'/>
      <port isolated='yes'/>
    </interface>
    <serial type='pty'><target type='isa-serial' port='0'/><log file='${e_clog}' append='on'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
  </devices>
</domain>
EOF
}

dr_vps_domain_resolve_artifact() {  # <distro> -> newest registered golden
  # GOLDEN-ONLY (CONCEPT R3.1): `AND kind='golden'` so a SNAPSHOT with a matching distro can NEVER be
  # picked as the "newest golden" for a create-by-distro (the exact snapshot-passes-as-golden risk).
  dr_vps_sql "SELECT artifact_id FROM images
    WHERE json_extract(provenance,'\$.distro')=$(dr_vps_sql_str "$1") AND kind='golden'
    ORDER BY created_at DESC LIMIT 1;"
}

# SNAPSHOT feature: create a VM FROM a snapshot (the snapshot id is ALREADY typed-resolved by the caller,
# dr_vps_snapshot_use). Reuses the FULL create machinery via the pre-resolved-artifact seam -- the overlay
# backs the snapshot's standalone image, and vm_create is typed kind='snapshot'. The guestexec/identity GATE
# still applies to the resulting VM (no privilege gained -- the agent reuses its own installed state).
dr_vps_domain_use_snapshot() {  # <name> <snap_id> [create flags...]
  local name="$1" sid="$2"; shift 2
  local distro _drc; distro=$(dr_vps_sql "SELECT json_extract(provenance,'\$.distro') FROM images WHERE artifact_id=$(dr_vps_sql_str "$sid") AND kind='snapshot';"); _drc=$?
  # FAIL CLOSED on a DB read error (fail-open class): don't fall back to the "snapshot" label on a transient
  # error. (domain_create's export_family re-reads provenance + also fails closed; stop here explicitly too.)
  [ "$_drc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_VERIFY" "use: snapshot distro read failed for $sid"; return $?; }
  # INTERNAL seam only (bin/dr-vps clears any ambient value at entry). Set -> call -> unset so it never leaks.
  local _rc; _DR_VPS_CREATE_AID="$sid" _DR_VPS_CREATE_KIND=snapshot dr_vps_domain_create "$name" "${distro:-snapshot}" "$@"; _rc=$?
  unset _DR_VPS_CREATE_AID _DR_VPS_CREATE_KIND
  return "$_rc"
}

# remove any partial create artifacts for an id (overlay, seed, saved key)
_dr_vps_domain_scrub_files() {  # <id> [overlay]
  local id="$1" overlay="${2:-}"
  [ -n "$overlay" ] && dr_vps_storage_overlay_delete "$overlay" 2>/dev/null || true
  dr_vps_storage_seed_cleanup "$id" 2>/dev/null || true
  local pkp="${DR_VPS_SEED_DIR}/${id}.pubkey"; { dr_vps_storage_path_fence "$pkp" "$DR_VPS_SEED_DIR" >/dev/null 2>&1 && [ ! -L "$pkp" ] && rm -f -- "$pkp"; } || true
  dr_vps_console_log_cleanup "$id" 2>/dev/null || true    # Observability (Step 9): drop this id's console log
}

# Phase 3: export the golden's distro FAMILY + pinned repo from provenance so seed_build emits
# the right per-family cloud-init. Defaults (dnf, empty repo) preserve Fedora back-compat.
_dr_vps_domain_export_family() {  # <artifact_id>
  local prov fam rc rr rce
  prov=$(dr_vps_image_provenance "$1" 2>/dev/null); rce=$?
  # A genuine READ ERROR (E_VERIFY) must FAIL CLOSED: defaulting to dnf/empty-repo on a transient DB error would
  # seed the VM against the WRONG repo state. Provenance legitimately ABSENT (E_NOTFOUND, e.g. a legacy golden
  # with no provenance row) keeps the Fedora/dnf back-compat default below.
  [ "$rce" -ne "$DR_VPS_E_VERIFY" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "cannot read provenance for $1 -- refusing to seed with a default family"; return $?; }
  fam=$(printf '%s' "$prov" | jq -r '.family // "dnf"')
  rc=$(printf '%s' "$prov" | jq -r '.repo_content // ""')
  rr=$(printf '%s' "$prov" | jq -r '.repo_remove // ""')
  export DR_VPS_DISTRO_FAMILY="$fam" DR_VPS_REPO_CONTENT="$rc" DR_VPS_REPO_REMOVE="$rr"
}

# S1b: the OS groups a uid belongs to (seam DR_VPS_GROUPS_OF lets the suite inject membership without real
# accounts). Default = the real lookup. Empty output on an unknown uid -> membership fails closed.
_dr_vps_groups_of() {  # <uid> -> group names (whitespace-separated)
  if [ -n "${DR_VPS_GROUPS_OF:-}" ]; then "$DR_VPS_GROUPS_OF" "$1" 2>/dev/null; else id -nG "$1" 2>/dev/null; fi
}
# S1b: admit a service-class request. The direct OPERATOR (no owner) is admin -> allowed. An AGENT (owner set)
# must (a) be a member of the service group AND (b) be under its per-account service-VM quota. Runs under the
# watcher work-lock (single request queue), so the count->create window is not racy. Quota counts EVERY
# persisted class='service' row for the owner incl pending/broken (any state) -- only destroy frees a slot.
_dr_vps_service_admit() {  # <owner_uid|''>
  local owner="$1"
  [ -z "$owner" ] && return 0                                    # direct operator = admin
  local grp="${DR_VPS_SERVICE_GROUP:-drvpsvc}"
  _dr_vps_groups_of "$owner" | tr ' \t' '\n' | grep -qxF "$grp" \
    || { dr_vps_die "$DR_VPS_E_CAP" "service class requires membership in the '$grp' group (uid $owner)"; return $?; }
  local q used f; f=$(_dr_vps_fleet) || return $?
  q=$(jq -r '.service_quota // 3' "$f" 2>/dev/null); case "$q" in ''|*[!0-9]*) q=3;; esac
  used=$(dr_vps_sql "SELECT COUNT(*) FROM vms WHERE owner_uid=$(dr_vps_sql_str "$owner") AND class='service';")
  case "$used" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "service quota count read failed for uid $owner"; return $?;; esac
  [ "$used" -lt "$q" ] || { dr_vps_die "$DR_VPS_E_CAP" "service-VM quota reached ($used/$q) for uid $owner"; return $?; }
}

# create: gate -> preflight conflicts -> build -> define/autostart-off/start (all fatal,
# rolled back) -> store. No partial state survives a failure.
dr_vps_domain_create() {  # <name> <distro> [--net N][--ttl H][--mem M][--cpus N][--ssh-key F][--project P][--seq S][--owner U][--class C]
  local name="$1" distro="$2"; shift 2
  local net="simnet" ttl="$DR_VPS_TTL_DEFAULT" mem="$DR_VPS_DEFAULT_MEM_MB" cpus="$DR_VPS_DEFAULT_VCPUS"
  local key="${DR_VPS_DEFAULT_SSH_KEY:-${DR_VPS_SSH_KEY}.pub}" proj="default" seq="1" owner="" class="throwaway"   # S1a owner + S1b class
  while [ "$#" -gt 0 ]; do case "$1" in
    --net|--ttl|--mem|--cpus|--ssh-key|--project|--seq|--owner|--class)
      # a trailing value flag must be a USAGE error (2), not a set -u unbound-variable abort (1)
      [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "$1 needs a value"; return $?; }
      case "$1" in
        --net) net="$2";; --ttl) ttl="$2";; --mem) mem="$2";; --cpus) cpus="$2";;
        --ssh-key) key="$2";; --project) proj="$2";; --seq) seq="$2";; --owner) owner="$2";; --class) class="$2";;
      esac; shift 2;;
    *) dr_vps_die "$DR_VPS_E_USAGE" "unknown flag: $1"; return $?;;
  esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  case "$class" in throwaway|service) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "--class must be 'throwaway' or 'service' (got '$class')"; return $?;; esac
  if [ "$class" = service ]; then _dr_vps_service_admit "$owner" || return $?; fi   # S1b: membership + quota (operator = admin)
  { [ -n "$key" ] && [ -f "$key" ]; } || { dr_vps_die "$DR_VPS_E_USAGE" "--ssh-key <pubkey file> required (ssh-key-only)"; return $?; }
  _dr_vps_is_uint "$mem" 256 1048576 || { dr_vps_die "$DR_VPS_E_USAGE" "bad --mem: $mem"; return $?; }
  _dr_vps_is_uint "$cpus" 1 256      || { dr_vps_die "$DR_VPS_E_USAGE" "bad --cpus: $cpus"; return $?; }
  local aid id overlay seed xml egen new_uuid _u2
  # SNAPSHOT feature: a caller (dr_vps_domain_use_snapshot) may pre-resolve the backing artifact + its kind
  # so the SAME create machinery seeds a VM from a snapshot. Default (unset) = resolve the newest GOLDEN by
  # distro, kind='golden' -- unchanged for every existing caller.
  local _ckind="${_DR_VPS_CREATE_KIND:-golden}"
  if [ -n "${_DR_VPS_CREATE_AID:-}" ]; then aid="$_DR_VPS_CREATE_AID"; else
    aid=$(dr_vps_domain_resolve_artifact "$distro"); [ -n "$aid" ] || { dr_vps_die "$DR_VPS_E_UNKNOWN" "no greened golden for distro: $distro"; return $?; }
  fi
  dr_vps_doctor --no-ram >/dev/null   || return $?      # caps/tools/libvirt/kvm (RAM checked per-request next)
  dr_vps_doctor_capacity "$mem"       || return $?      # free RAM vs THIS request + reserve (handles small --mem)
  dr_vps_net_create_guard "$net"      || return $?
  dr_vps_doctor_golden_match "$aid"   || return $?
  id=$(dr_vps_instance_id "$name" "$proj" "$owner") || return $?   # S2: owner-namespaced (agent) -- operator (no owner) keeps the historical id
  # Observability (Step 9): fail closed BEFORE any side effect if the console subsystem is unhealthy or the
  # per-VM DoS admission bound would be exceeded by THIS id. (dr_vps_doctor above ALSO asserts console health
  # + the aggregate count; the id-specific admission adds the +1 bound the aggregate check cannot enforce.)
  dr_vps_console_assert          || return $?
  dr_vps_console_admission "$id" || return $?
  # preflight conflicts BEFORE any side effect. rc-check the row read (SWEEP-1, fail-open class): a read error
  # collapsing to empty would proceed as if no row exists -> overlay_create's publish guard could then delete an
  # EXISTING VM's overlay. Fail closed on a read error, DISTINCT from a genuine no-row.
  local _existing _exrc; _existing=$(dr_vps_store_vm_get "$id"); _exrc=$?
  [ "$_exrc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "create: vm row read failed for $id (fail-closed)"; return $?; }
  [ -z "$_existing" ] || { dr_vps_die "$DR_VPS_E_CONFLICT" "vm exists: $id"; return $?; }
  ! _dr_virsh dominfo "$id" >/dev/null 2>&1 || { dr_vps_die "$DR_VPS_E_CONFLICT" "libvirt domain exists: $id"; return $?; }
  egen=$(dr_vps_net_generation) || return $?
  new_uuid=$(_dr_vps_gen_uuid) || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot generate a uuid for $id"; return $?; }
  overlay=$(dr_vps_storage_overlay_create "$id" "$aid") || return $?
  # no-follow/no-clobber: `cp -f` would FOLLOW a squatted pubkey symlink and clobber its target (e.g. a
  # registered golden). Refuse a pre-existing destination first, then copy onto the fresh path.
  _dr_vps_publish_guard "${DR_VPS_SEED_DIR}/${id}.pubkey" || { _dr_vps_domain_scrub_files "$id" "$overlay"; return 1; }
  if ! cp -f "$key" "${DR_VPS_SEED_DIR}/${id}.pubkey"; then _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_die "$DR_VPS_E_GENERIC" "saving key failed"; return $?; fi
  # Phase 3: the seed plumbing follows the golden's family + pinned repo (from provenance). CHECK the return
  # export_family fails closed (E_VERIFY) on a provenance READ ERROR, but set -uo (not set -e) means
  # an unchecked call would fall through to seed_build with the DEFAULT dnf family -> wrong repo/proxy seed.
  # Unwind the overlay/pubkey already created + propagate the error.
  _dr_vps_domain_export_family "$aid" || { local _efrc=$?; _dr_vps_domain_scrub_files "$id" "$overlay"; return "$_efrc"; }
  if ! seed=$(dr_vps_storage_seed_build "$id" "$key" "$seq"); then _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_die "$DR_VPS_E_GENERIC" "seed build failed"; return $?; fi
  # COMMIT the store row (state='broken', with the PRE-GENERATED uuid + overlay) BEFORE define/start.
  # A crash after start but before the row would otherwise leave a ROWLESS live domain (destroy
  # refuses a row-less id -> manual cleanup needed). Pre-committing makes every post-define failure
  # recoverable by destroy/reaper, and the row's uuid is pinned to match the (rendered) live uuid.
  if ! dr_vps_store_vm_create "$id" "$aid" "$overlay" "$egen" "$ttl" "$name" "$proj" "$_ckind" "$owner" "$class"; then
    _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_die "$DR_VPS_E_CONFLICT" "store vm_create failed for $id"; return $?
  fi
  # CHECKED: a silent DB failure on any of these (no domain exists yet) must scrub + drop the row,
  # not leave a half-committed row whose overlay/uuid/state lie about the real state.
  dr_vps_store_overlay_add "$id" "$overlay" "$aid" \
    || { _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_store_vm_delete "$id" 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "overlay-ledger commit failed for $id"; return $?; }
  dr_vps_store_vm_set_uuid "$id" "$new_uuid" \
    || { _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_store_vm_delete "$id" 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "uuid commit failed for $id"; return $?; }
  dr_vps_store_vm_set_net "$id" "$net" \
    || { _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_store_vm_delete "$id" 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "net commit failed for $id"; return $?; }
  dr_vps_store_vm_set_state "$id" broken \
    || { _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_store_vm_delete "$id" 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "state commit failed for $id"; return $?; }
  # Observability (Step 9): prepare a FRESH-INODE console-log slot for virtlogd BEFORE define (no stale-
  # generation output can bleed in). Fail closed (symlink/non-regular tamper) -> roll the create back.
  dr_vps_console_log_prepare "$id" || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_GENERIC" "console log prepare failed"; return $?; }
  # PIN the uuid INSIDE the template (H-2): render_xml validates + emits it, no post-hoc sed.
  local _contract _cpumode
  _contract=$(resolve_vm_contract "$id" "$distro" "") || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_GENERIC" "resolve failed"; return $?; }
  _cpumode=$(printf '%s\n' "$_contract" | sed -n 's/^cpu_mode=//p')
  # stored==consumed: the resolver MUST produce cpu_mode; an empty extract = a resolver bug -> FAIL CLOSED
  # (never mask it with render's host-model default).
  [ -n "$_cpumode" ] || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_GENERIC" "resolver produced no cpu_mode for $id"; return $?; }
  # Stage-0.B: persist the resolved contract in the row BEFORE start (fail-closed -- a persist failure must NOT
  # leave a running VM with a missing/wrong contract, so roll back). Stored == the object render consumes below.
  dr_vps_store_vm_set_contract "$id" "$_contract" || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_GENERIC" "contract persist failed"; return $?; }
  xml=$(dr_vps_domain_render_xml "$id" "$overlay" "$seed" "$net" "$mem" "$cpus" "$new_uuid" "$_cpumode") || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_GENERIC" "render failed"; return $?; }
  if ! printf '%s' "$xml" | _dr_virsh define /dev/stdin >/dev/null 2>&1; then
    _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_LIBVIRT" "virsh define failed"; return $?
  fi
  # Verify libvirt honored the pinned uuid IMMEDIATELY AFTER define (before autostart/start) -- a
  # mismatch here is rolled back while the row still matches; deferring it past start could strand a
  # broken row whose uuid != the live domain (which the gate would then refuse). Empty read tolerated.
  _u2=$(_dr_virsh domuuid "$id" 2>/dev/null | tr -d '[:space:]')
  { [ -z "$_u2" ] || [ "$_u2" = "$new_uuid" ]; } \
    || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_LIBVIRT" "live uuid $_u2 != pinned $new_uuid"; return $?; }
  if ! _dr_virsh autostart --disable "$id" >/dev/null 2>&1; then     # FAIL-CLOSED on autostart
    _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_LIBVIRT" "could not disable autostart for $id"; return $?
  fi
  # Stage-0.C PRE-START GATE (define -> uuid -> autostart-off -> closedshape -> start). GATED off by default
  # until a live smoke proves closedshape on the LIVE inactive dumpxml (see _dr_vps_prestart_gate).
  _dr_vps_prestart_gate "$id" "$overlay" create || return $?
  if ! _dr_virsh start "$id" >/dev/null 2>&1; then
    _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_LIBVIRT" "virsh start failed for $id"; return $?
  fi
  dr_vps_store_vm_set_state "$id" running \
    || { _dr_vps_create_rollback "$id" "$overlay" "$DR_VPS_E_GENERIC" "final running-state commit failed for $id"; return $?; }
  printf '%s\n' "$id"
}

# Roll back a create AFTER the row + domain may exist: tear the domain down, then ONLY scrub files +
# drop the row if the domain is PROVABLY absent. If present/indeterminate (libvirt down or a swallowed
# undefine), leave the row+files 'broken' so a normal destroy/reaper clears it later -- never unlink a
# possibly-live VM's overlay (a standing invariant, applied to create too).
_dr_vps_create_rollback() {  # <id> <overlay> <errcode> <msg>
  local id="$1" overlay="$2" code="$3" msg="$4" pr
  _dr_vps_domain_presence "$id" && pr=0 || pr=$?
  case "$pr" in
    1) # ABSENT: no domain to tear down -> scrub files + drop the row.
       _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_store_vm_delete "$id" 2>/dev/null || true
       dr_vps_die "$code" "create rollback: $msg" ;;
    0) # PRESENT: only destroy/undefine if the live domain is PROVABLY ROW-OWNED (identity gate) --
       # NEVER destroy by name (a same-name race could hit an unrelated libvirt domain). The row was
       # pre-committed with the pinned uuid + overlay, so the gate can bind. Gate-unavailable or a
       # MISMATCH -> leave the row broken and destroy NOTHING.
       if declare -F dr_vps_gate_vm >/dev/null 2>&1 && dr_vps_gate_vm lifecycle "$id" >/dev/null 2>&1; then
         _dr_virsh destroy "$id" >/dev/null 2>&1 || true
         _dr_virsh undefine "$id" >/dev/null 2>&1 || true
         _dr_vps_domain_presence "$id" && pr=0 || pr=$?
         if [ "$pr" -eq 1 ]; then
           _dr_vps_domain_scrub_files "$id" "$overlay"; dr_vps_store_vm_delete "$id" 2>/dev/null || true
           dr_vps_die "$code" "create rollback: $msg"
         else
           dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true
           dr_vps_die "$code" "create rollback: $msg (teardown incomplete; left broken)"
         fi
       else
         dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true
         dr_vps_die "$code" "create rollback: $msg (live domain not provably row-owned; left broken, destroyed nothing)"
       fi ;;
    *) # INDETERMINATE (libvirt down): destroy nothing, leave the row broken for later recovery.
       dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true
       dr_vps_die "$code" "create rollback: $msg (libvirt indeterminate; left broken)" ;;
  esac
}

# Roll back a recreate post-define failure. The row is already committed 'broken' (with newov + pinned
# uuid), so we LEAVE it broken (recoverable) and only `undefine` the live domain if it is PROVABLY
# row-owned (identity gate) -- never by name (a same-name race could undefine a foreign domain). A
# uuid MISMATCH naturally fails the gate -> we touch nothing.
_dr_vps_recreate_rollback() {  # <id> <errcode> <msg>
  local id="$1" code="$2" msg="$3" pr
  _dr_vps_domain_presence "$id" && pr=0 || pr=$?
  if [ "$pr" -eq 0 ] && declare -F dr_vps_gate_vm >/dev/null 2>&1 && dr_vps_gate_vm lifecycle "$id" >/dev/null 2>&1; then
    _dr_virsh undefine "$id" >/dev/null 2>&1 || true     # row-owned -> safe; no-domain cleanup can then clear it
  fi
  dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true
  dr_vps_die "$code" "recreate rollback: $msg"
}

# Clean-shutdown for the SNAPSHOT flatten (a live overlay cannot be flattened consistently). ACPI shutdown
# + bounded poll to 'shut off'; escalate to force-destroy on timeout. Prints the mode: clean | forced.
# Lifecycle-gated by the CALLER (snapshot_create gates first) -- this is host-side, NOT guestexec.
dr_vps_domain_shutdown() {  # <id> [timeout_s] -> stdout: clean|forced
  local id="$1" timeout="${2:-60}" waited=0 st
  st=$(_dr_virsh domstate "$id" 2>/dev/null)
  [ "$st" = "shut off" ] && { printf 'clean\n'; return 0; }
  _dr_virsh shutdown "$id" >/dev/null 2>&1 || true          # ACPI request (best-effort)
  while [ "$waited" -lt "$timeout" ]; do
    st=$(_dr_virsh domstate "$id" 2>/dev/null)
    [ "$st" = "shut off" ] && { printf 'clean\n'; return 0; }
    sleep 1; waited=$(( waited + 1 ))
  done
  _dr_virsh destroy "$id" >/dev/null 2>&1 || true           # escalate: force-off
  st=$(_dr_virsh domstate "$id" 2>/dev/null)
  [ "$st" = "shut off" ] || { dr_vps_die "$DR_VPS_E_LIBVIRT" "shutdown: $id not 'shut off' after force-destroy (state=$st)"; return $?; }
  printf 'forced\n'
}

dr_vps_domain_ready() {  # <id> -> 0 when ssh answers (dedicated key); sets _DR_VPS_READY_REASON (why-failed)
  local id="$1" ip out rc
  _DR_VPS_READY_REASON=unknown
  # Capture domifaddr rc SEPARATELY (host lease only; never guest-agent). A FAILED query is NOT "no-ip":
  # collapsing an errored read into no-ip would be fail-OPEN diagnostics. rc!=0 -> domifaddr-error, fail closed.
  out=$(_dr_virsh domifaddr "$id" --source lease 2>/dev/null); rc=$?
  if [ "$rc" -ne 0 ]; then _DR_VPS_READY_REASON=domifaddr-error; return 1; fi
  ip=$(printf '%s\n' "$out" | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
  if [ -z "$ip" ]; then _DR_VPS_READY_REASON=no-ip; return 1; fi
  # WRAP in DR_TIMEOUT: ConnectTimeout caps only the TCP/handshake phase; a guest
  # that accepts TCP then stalls mid-session could otherwise hang one probe for the TCP stack's own
  # (long) timeout, blowing the wait deadline. Bound the WHOLE ssh session at ConnectTimeout+2s.
  if "$DR_TIMEOUT" 5 "$DR_SSH" -o BatchMode=yes -o ConnectTimeout=3 "${_DR_VPS_SSH_HARDEN[@]}" \
       -o IdentitiesOnly=yes -i "$DR_VPS_SSH_KEY" "root@${ip}" true 2>/dev/null; then
    _DR_VPS_READY_REASON=ready; return 0
  fi
  _DR_VPS_READY_REASON=ssh-probe-failed; return 1
}
dr_vps_domain_wait() {  # <id> [timeout_s]
  local id="$1" t="${2:-120}"
  # wait POLLS the guest over SSH -- a guest-reaching op. It MUST pass the FULL guestexec gate
  # (closed-shape + fresh egress), not merely lifecycle identity: a domain that binds identity but
  # fails guestexec (extra NIC, hostdev, host-path backend, stale egress) must not be SSH-reachable.
  if declare -F dr_vps_gate_vm >/dev/null 2>&1; then
    dr_vps_gate_vm guestexec "$id" >/dev/null || { dr_vps_die "$DR_VPS_E_EGRESS" "wait: guestexec gate refused $id"; return $?; }
  else
    dr_vps_die "$DR_VPS_E_EGRESS" "wait: guestexec gate unavailable -- refusing SSH to $id"; return $?
  fi
  # DEADLINE on wall-clock, not an iteration COUNT: the old `i < t` loop counted
  # each probe's own cost (domifaddr + a bounded ssh) as if it were 1s, so `wait <id> 120` could run
  # far longer than 120s. Compare `date +%s` against a fixed deadline so t is a real second budget.
  local deadline; deadline=$(( $(date +%s) + t ))
  while [ "$(date +%s)" -lt "$deadline" ]; do dr_vps_domain_ready "$id" && return 0; sleep 1; done
  dr_vps_die "$DR_VPS_E_TIMEOUT" "vm $id not ready in ${t}s (last: ${_DR_VPS_READY_REASON:-unknown})"; return $?
}
dr_vps_domain_console() {  # interactive, BIDIRECTIONAL guest reach -> full guestexec gate (never attach
  _dr_vps_safe_id "$1" || return $?      # to a foreign same-name domain; require closed-shape+fresh egress).
  if declare -F dr_vps_gate_vm >/dev/null 2>&1; then
    dr_vps_gate_vm guestexec "$1" >/dev/null || { dr_vps_die "$DR_VPS_E_EGRESS" "console: guestexec gate refused $1"; return $?; }
  else
    dr_vps_die "$DR_VPS_E_EGRESS" "console: guestexec gate unavailable -- refusing"; return $?
  fi
  _dr_virsh console "$1"
}

# inspect: READ-ONLY host-side facts for diagnosing a VM (CONCEPT-OBSERVABILITY Part A). NO SSH / no
# guest I/O -- MUST NOT call dr_vps_domain_ready (it SSHes -> would open an SSH path behind a light gate).
# The store row is always readable (like status: works on BROKEN/undefined VMs -- the state you most need to
# diagnose). LIVE virsh facts (guest_ip from the host DHCP LEASE, dominfo) are read ONLY when a domain is live
# AND passes the lifecycle-IDENTITY gate, so a foreign same-name domain never leaks its facts. Normalized
# key=value output. NOTE (deviates from PLAN wording "pre-gated"): conditional gate like destroy, so a broken
# VM stays inspectable -- flagged for code convergence.
dr_vps_domain_inspect() {  # <id>
  local id="$1" row state gen aid ip="" dom="absent" clog out rc _irc
  _dr_vps_safe_id "$id" || return $?
  # convergence r3: FAIL CLOSED on a store READ ERROR (transient DB fault) rather than reporting it as a
  # normal absent VM -- reserve the empty-row path for a genuinely-absent id. (The libvirt dominfo / console
  # fs checks below remain best-effort: a probe error is reported as absent/none, acceptable for a diagnostic.)
  row=$(dr_vps_store_vm_get "$id"); _irc=$?
  [ "$_irc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "inspect: store read failed for $id (fail-closed)"; return $?; }
  IFS='|' read -r state gen aid _ <<<"$row"
  printf 'state=%s\n' "${state:-unknown}"
  printf 'generation=%s\n' "${gen:-}"
  printf 'artifact_id=%s\n' "${aid:-}"
  # S1b: expose the VM class (throwaway|service) machine-readably. owner_uid is deliberately NOT printed --
  # inspect is a GLOBAL read, and the ownership map is not something a co-tenant needs from it.
  printf 'class=%s\n' "$(dr_vps_sql "SELECT class FROM vms WHERE id=$(dr_vps_sql_str "$id");" 2>/dev/null || printf throwaway)"
  # convergence r1: probe libvirt ONLY for a STORE-OWNED id. A row-less id must NEVER touch virsh, else the
  # "identity-gate-refused" (a foreign same-name domain exists) vs "absent" (none) distinction is a
  # foreign-domain EXISTENCE ORACLE. With a row we own the id, so reporting our domain's identity state
  # (present / gate-refused / absent) leaks nothing the agent didn't already know.
  if [ -n "$row" ] && _dr_virsh dominfo "$id" >/dev/null 2>&1; then
    if ! declare -F dr_vps_gate_vm >/dev/null 2>&1 || dr_vps_gate_vm lifecycle "$id" >/dev/null 2>&1; then
      dom="present"
      out=$(_dr_virsh domifaddr "$id" --source lease 2>/dev/null); rc=$?
      if [ "$rc" -eq 0 ]; then ip=$(printf '%s\n' "$out" | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
      else ip="(domifaddr-error)"; fi
    else
      dom="identity-gate-refused"
    fi
  fi
  printf 'domain=%s\n' "$dom"
  printf 'guest_ip=%s\n' "${ip:-(none)}"
  clog=$(dr_vps_console_log_path "$id")
  if [ -f "$clog" ] && [ ! -L "$clog" ]; then printf 'console=available\n'; else printf 'console=none\n'; fi
  local _rst=absent; [ -n "$row" ] && _rst=present   # metadata only (present/absent, NOT the row content)
  dr_vps_diag "inspect: id=$id row=$_rst domain=$dom"
  return 0
}

# verify-baseline: store-pin + overlay-backing-chain + golden-digest (NOT a live-domain-XML
# nor a live-clean claim -- narrow by design).
dr_vps_domain_verify_baseline() {  # <id>
  local id="$1" row aid overlay golden
  _dr_vps_safe_id "$id" || return $?
  row=$(dr_vps_store_vm_get "$id"); [ -n "$row" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such vm: $id"; return $?; }
  aid=$(printf '%s' "$row" | cut -d'|' -f3)
  local _vbrc
  overlay=$(dr_vps_sql "SELECT overlay FROM vms WHERE id=$(dr_vps_sql_str "$id");"); _vbrc=$?
  [ "$_vbrc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "verify: overlay read failed for $id (fail-closed)"; return $?; }
  golden=$(dr_vps_store_image_get "$aid"); [ -n "$golden" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden gone for $aid"; return $?; }
  dr_vps_storage_backing_check "$overlay" "$golden" || return $?
  dr_vps_doctor_golden_match "$aid" || return $?
}

# Defined memory of a domain in MiB, normalizing the libvirt unit (KiB/MiB/GiB). Fail-CLOSED
# if it cannot be determined (never silently skip the capacity gate).
_dr_vps_domain_mem_mib() {  # <id> -> MiB
  local id="$1" line unit val
  line=$(_dr_virsh dumpxml "$id" 2>/dev/null | grep -o "<memory[^>]*>[0-9]*</memory>" | head -1)
  [ -n "$line" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "cannot read defined memory for $id"; return $?; }
  unit=$(printf '%s' "$line" | sed -n "s/.*unit=[\"']\([^\"']*\)[\"'].*/\1/p")
  val=$(printf '%s' "$line" | sed -n "s/.*>\([0-9]*\)<.*/\1/p")
  [[ "$val" =~ ^[0-9]+$ ]] || { dr_vps_die "$DR_VPS_E_VERIFY" "bad memory value for $id"; return $?; }
  case "$unit" in
    KiB) printf '%s\n' "$(( val / 1024 ))" ;;
    ''|MiB) printf '%s\n' "$val" ;;
    GiB) printf '%s\n' "$(( val * 1024 ))" ;;
    *) dr_vps_die "$DR_VPS_E_VERIFY" "unknown memory unit '$unit' for $id"; return $? ;;
  esac
}

# recreate: GATE first (golden_match), then rebuild from the PINNED golden; start is FATAL;
# DB is updated only after a successful start.
dr_vps_domain_recreate() {  # <id> [--owner UID]  -- S1a: owner-scope + serialize, then the impl below
  local id="" owner=""
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) owner="${2:-}"; shift 2;;
    -*) dr_vps_die "$DR_VPS_E_USAGE" "recreate: unknown flag: $1"; return $?;;
    *)  if [ -z "$id" ]; then id="$1"; shift; else dr_vps_die "$DR_VPS_E_USAGE" "recreate: too many arguments"; return $?; fi;;
  esac; done
  [ -n "$id" ] || { dr_vps_die "$DR_VPS_E_USAGE" "recreate <id> [--owner UID]"; return $?; }
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  dr_vps_vm_do_owned "$id" "$owner" _dr_vps_domain_recreate_impl "$id"
}
_dr_vps_domain_recreate_impl() {  # <id>  (invoked ONLY via dr_vps_domain_recreate, under the per-VM lock, owner-verified)
  local id="$1" row aid overlay keyf newov mem cpus seed xml _u new_uuid _pr rc
  _dr_vps_safe_id "$id" || return $?
  row=$(dr_vps_store_vm_get "$id"); [ -n "$row" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such vm: $id"; return $?; }
  aid=$(printf '%s' "$row" | cut -d'|' -f3)
  keyf="${DR_VPS_SEED_DIR}/${id}.pubkey"
  [ -f "$keyf" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "missing saved key for $id"; return $?; }
  # Re-render on the VM's OWN create-time network, not a hardcoded default -- else a VM
  # created on a second allowlisted net would be silently migrated to simnet on recreate. Legacy rows
  # (created before the `net` column) read empty -> fall back to DR_VPS_RECREATE_NET (simnet).
  # FAIL CLOSED on a failed net read: treat ONLY a SUCCESSFUL empty result as a genuine
  # legacy NULL (-> default). A DB error (locked/corrupt) returns empty too, but with a nonzero rc --
  # falling back to simnet there would destroy+rebuild the VM on the WRONG network before we know it.
  local rnet
  if ! rnet=$(dr_vps_store_vm_get_net "$id"); then
    dr_vps_die "$DR_VPS_E_GENERIC" "recreate: failed to read recorded net for $id (DB error) -- refusing"; return $?
  fi
  rnet="${rnet:-${DR_VPS_RECREATE_NET:-simnet}}"     # empty NOW == a genuine legacy NULL (query succeeded)
  _dr_vps_is_netname "$rnet" || { dr_vps_die "$DR_VPS_E_USAGE" "recreate: bad recorded net '$rnet' for $id"; return $?; }
  # Full live-domain identity gate (UUID+disk+backing). gate.sh is sourced by domain.sh, so it is
  # always present; FAIL CLOSED if it somehow is not (never rebuild over an unverified live domain).
  if declare -F dr_vps_gate_vm >/dev/null 2>&1; then
    dr_vps_gate_vm lifecycle "$id" >/dev/null 2>&1 \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "recreate: live-domain identity gate refused $id"; return $?; }
  else
    dr_vps_die "$DR_VPS_E_EGRESS" "recreate: identity gate unavailable -- refusing"; return $?
  fi
  # SAME pre-boot confinement gate as create -- a stale/flushed nft or changed net must
  # block recreate too. Phase 1 is simnet-only. --no-ram: the VM is still
  # RUNNING here, so its own RAM must not be counted against free RAM (the real per-request capacity
  # check runs AFTER destroy below); else recreating a min-capacity VM would be wrongly refused.
  dr_vps_doctor --no-ram >/dev/null              || return $?
  dr_vps_net_create_guard "$rnet" || return $?
  # Observability (Step 9): fail closed BEFORE the destructive rebuild if console is unhealthy / over budget
  # (doctor above also asserts; the id-specific admission self-exempts this id's existing log -> no false +1).
  dr_vps_console_assert          || return $?
  dr_vps_console_admission "$id" || return $?
  # Mark 'broken' BEFORE the destructive rebuild (destroy/undefine/overlay-drop): a hard crash in
  # that window must not leave a 'running'-labeled but domain-less row. Flipped back to 'running'
  # only after a successful start (the row is also re-committed 'broken' with newov mid-rebuild).
  dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true
  mem=$(_dr_vps_domain_mem_mib "$id") || return $?              # fail-closed if undeterminable
  cpus=$(_dr_virsh dumpxml "$id" 2>/dev/null | sed -n 's:.*<vcpu[^>]*>\([0-9]\{1,\}\)</vcpu>.*:\1:p' | head -1)
  case "$cpus" in ''|*[!0-9]*) cpus="$DR_VPS_DEFAULT_VCPUS";; esac
  _dr_virsh destroy "$id" >/dev/null 2>&1 || true              # frees the VM's RAM AND releases
  # CAPTURE rc BEFORE set_state (a successful cleanup write must NOT mask the real failure rc=0). The
  # VM is already powered off here, so any post-destroy failure must leave the row 'broken'.
  dr_vps_doctor_capacity "$mem" || { rc=$?; dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; return "$rc"; }
  # golden_match AFTER destroy: re-digesting the golden needs it UNLOCKED -- a RUNNING VM holds
  # a lock on it as its backing file, which blocks qemu-img check (proven on live KVM). The VM
  # is already stopped here; refuse to re-clone a tampered golden, leaving it stopped+broken.
  dr_vps_doctor_golden_match "$aid" || { rc=$?; dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; return "$rc"; }
  # M8: confirm the guest is actually stopped before unlinking its overlay -- a swallowed
  # `virsh destroy` failure must NOT delete the live disk out from under a running qemu.
  [ "$(_dr_virsh domstate "$id" 2>/dev/null)" = "shut off" ] \
    || { dr_vps_store_vm_set_state "$id" broken; dr_vps_die "$DR_VPS_E_LIBVIRT" "recreate: '$id' not shut off after destroy (refusing to drop a live overlay)"; return $?; }
  # The old domain is now PROVABLY shut off -> tombstone ONLY its (old-uuid) async jobs.
  # Placed AFTER the stop proof (not right after the best-effort destroy) so a FAILED destroy -- which aborts
  # recreate just above -- can NEVER false-mark a still-running VM's jobs 'destroyed'. The store row still holds
  # the OLD uuid here (the new uuid is committed below), so a fresh-instance job (if any) is spared by the filter.
  if declare -F dr_vps_jobs_cleanup_vm >/dev/null 2>&1 && declare -F _dr_vps_job_cur_uuid >/dev/null 2>&1; then
    # FAIL CLOSED: tombstone ONLY with a KNOWN old uuid. `_dr_vps_job_cur_uuid` returns rc!=0 on a
    # store-read failure (no pipe to mask it) -> `if _u=$(...)` skips cleanup rather than widening to "tombstone
    # all". A missed cleanup is safe: the reaper backstop promotes the stale jobs on a later tick.
    if _u=$(_dr_vps_job_cur_uuid "$id") && [ -n "$_u" ]; then dr_vps_jobs_cleanup_vm "$id" "$_u" || true; fi
    _u=""
  fi
  # UNDEFINE the old domain HERE (its identity was already gate-verified above), BEFORE touching
  # overlay/seed -- and FAIL CLOSED. If undefine fails or absence can't be PROVEN, the old domain may
  # still be defined, so we must not delete its overlay (leave the VM recoverable by a normal destroy).
  if ! _dr_virsh undefine "$id" >/dev/null 2>&1; then
    dr_vps_store_vm_set_state "$id" broken
    dr_vps_die "$DR_VPS_E_LIBVIRT" "recreate: could not undefine old domain $id -- refusing to drop overlay"; return $?
  fi
  _dr_vps_domain_presence "$id" && _pr=0 || _pr=$?
  [ "$_pr" -eq 1 ] \
    || { dr_vps_store_vm_set_state "$id" broken; dr_vps_die "$DR_VPS_E_LIBVIRT" "recreate: $id not provably absent after undefine -- refusing to drop overlay"; return $?; }
  local _rcov
  overlay=$(dr_vps_sql "SELECT overlay FROM vms WHERE id=$(dr_vps_sql_str "$id");"); _rcov=$?
  # FAIL CLOSED on a DB read error (fail-open class): an errored (empty) read must NOT skip deleting the OLD
  # overlay before a new one is cloned -> the old overlay would be orphaned on disk.
  [ "$_rcov" -eq 0 ] || { dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "recreate: overlay read failed for $id (fail-closed)"; return $?; }
  [ -n "$overlay" ] && dr_vps_storage_overlay_delete "$overlay" 2>/dev/null || true
  dr_vps_storage_seed_cleanup "$id" || true
  newov=$(dr_vps_storage_overlay_create "$id" "$aid") || { rc=$?; dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; return "$rc"; }
  # CHECK the return: a provenance read error must fail closed, not fall through to seed_build with
  # the default dnf family. Remove the just-created newov + mark broken (the old overlay is already gone).
  _dr_vps_domain_export_family "$aid" || { rc=$?; dr_vps_storage_overlay_delete "$newov" 2>/dev/null || true; dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; return "$rc"; }
  # seed failure: capture rc AND remove the just-created (untracked) newov so it can't leak (the row
  # still points at the old, already-deleted overlay at this point).
  seed=$(dr_vps_storage_seed_build "$id" "$keyf" "re-$(date -u +%s)-${RANDOM}") \
    || { rc=$?; dr_vps_storage_overlay_delete "$newov" 2>/dev/null || true; dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; return "$rc"; }
  # PRE-GENERATE the new domain UUID; commit it (with newov + state='broken') to the row BEFORE define,
  # AND render it into the XML so libvirt PINS it. This removes the post-define stale-UUID window:
  # a crash/kill ANYWHERE after define still leaves row-uuid == live-uuid, so destroy/reaper can bind
  # + clear it. The row is also kept CONSISTENT with the on-disk overlay (newov), not the deleted old one.
  new_uuid=$(_dr_vps_gen_uuid) || { dr_vps_store_vm_set_state "$id" broken; dr_vps_die "$DR_VPS_E_GENERIC" "recreate: cannot generate a uuid for $id"; return $?; }
  # CHECKED generation read: an inline $(dr_vps_net_generation) would swallow its rc and commit
  # egress_gen='' silently on failure -- capture + check it first (rc discipline).
  local egen
  egen=$(dr_vps_net_generation) \
    || { dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "recreate: cannot read the egress generation for $id"; return $?; }
  # CHECKED commit: a SILENT DB failure here would leave the row pointing at the OLD overlay/uuid
  # while libvirt gets the new one -> the gate would refuse the live domain (wedge). Fail closed.
  dr_vps_sql_update1 "UPDATE vms SET overlay=$(dr_vps_sql_str "$newov"), domain_uuid=$(dr_vps_sql_str "$new_uuid"), generation=generation+1, state='broken', egress_gen=$(dr_vps_sql_str "$egen") WHERE id=$(dr_vps_sql_str "$id");" \
    || { dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "recreate: row commit failed for $id"; return $?; }
  dr_vps_store_overlay_add "$id" "$newov" "$aid" \
    || { dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "recreate: overlay-ledger commit failed for $id"; return $?; }
  # REDEFINE from the clean template before start: a tampered live XML (extra NIC/hostdev/host path)
  # whose identity still matches must NOT be restarted -- the closed-shape proof is guestexec-only,
  # so recreate enforces the safe shape by rebuilding the definition from render_xml (with our uuid).
  # Observability (Step 9): fresh-inode console-log slot before redefine. recreate does NOT destroy, so
  # unlink the prior generation's log here -> no stale-gen output bleeds into the new instance. Fail closed
  # leaves the row 'broken' (recoverable), consistent with the rest of recreate's post-commit failures.
  dr_vps_console_log_prepare "$id" || { dr_vps_store_vm_set_state "$id" broken 2>/dev/null || true; dr_vps_die "$DR_VPS_E_GENERIC" "recreate: console log prepare failed for $id"; return $?; }
  local _rcontract _rcpumode
  _rcontract=$(resolve_vm_contract "$id" "" "") || return $?    # distro through the seam is Stage-2 (recreate)
  _rcpumode=$(printf '%s\n' "$_rcontract" | sed -n 's/^cpu_mode=//p')
  [ -n "$_rcpumode" ] || { _dr_vps_recreate_rollback "$id" "$DR_VPS_E_GENERIC" "resolver produced no cpu_mode for $id"; return $?; }
  # Stage-0.B: persist the re-resolved contract (fail-closed). Coherent restore-prior-on-later-failure = 0.C.
  dr_vps_store_vm_set_contract "$id" "$_rcontract" || return $?
  xml=$(dr_vps_domain_render_xml "$id" "$newov" "$seed" "$rnet" "$mem" "$cpus" "$new_uuid" "$_rcpumode") || return $?
  if ! printf '%s' "$xml" | _dr_virsh define /dev/stdin >/dev/null 2>&1; then dr_vps_die "$DR_VPS_E_LIBVIRT" "recreate: redefine failed for $id (state broken, row consistent)"; return $?; fi
  # Defense: verify libvirt honored the pinned uuid (the row already matches it). An empty read is
  # tolerated (seam); a DIFFERENT uuid -> undefine + fail closed (the row+live would diverge).
  _u=$(_dr_virsh domuuid "$id" 2>/dev/null | tr -d '[:space:]')
  { [ -z "$_u" ] || [ "$_u" = "$new_uuid" ]; } \
    || { _dr_vps_recreate_rollback "$id" "$DR_VPS_E_LIBVIRT" "live uuid $_u != pinned $new_uuid for $id"; return $?; }
  # FAIL-CLOSED like create: autostart-off is a safety invariant (libvirt autostart could boot the
  # guest before the rig's confinement path runs); a failure here must not be swallowed.
  if ! _dr_virsh autostart --disable "$id" >/dev/null 2>&1; then
    _dr_vps_recreate_rollback "$id" "$DR_VPS_E_LIBVIRT" "autostart-disable failed for $id"; return $?
  fi
  # Stage-0.C PRE-START GATE (recreate); GATED off by default (see _dr_vps_prestart_gate).
  _dr_vps_prestart_gate "$id" "$newov" recreate || return $?
  if ! _dr_virsh start "$id" >/dev/null 2>&1; then
    _dr_vps_recreate_rollback "$id" "$DR_VPS_E_LIBVIRT" "start failed for $id"; return $?
  fi
  dr_vps_sql_update1 "UPDATE vms SET state='running' WHERE id=$(dr_vps_sql_str "$id");" \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "recreate: final state commit failed for $id"; return $?; }   # checked
  printf '%s\n' "$id"
}

# 3-state domain presence: 0 present / 1 absent / 2 indeterminate. Uses `virsh list --all --name`
# so a SUCCESSFUL query distinguishes "exact name absent" from "query failed" -- `! virsh dominfo`
# conflates absent with libvirt-DOWN, and treating a libvirt outage as "absent" would let destroy
# unlink a still-live VM's overlay. Indeterminate MUST fail closed (delete nothing).
_dr_vps_domain_presence() {  # <id> -> rc 0 present / 1 absent / 2 indeterminate
  local id="$1" names
  names=$(_dr_virsh list --all --name 2>/dev/null) || return 2
  printf '%s\n' "$names" | grep -Fxq -- "$id" && return 0
  return 1
}

# Generate a fresh domain UUID (uuidgen, fallback to the kernel's). Validated as STRICT 8-4-4-4-12 hex.
_dr_vps_gen_uuid() {
  local u; u=$(uuidgen 2>/dev/null) || u=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || return 1
  [[ "$u" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    && printf '%s' "$u" || return 1
}

# destroy: id-validated; refuses to delete an overlay that IS a registered golden or whose
# basename != <id>.qcow2; verifies undefine; only then removes files + the store row
#
dr_vps_domain_destroy() {  # <id> [--owner UID]  -- S1a: owner-scope + serialize, then the impl below
  local id="" owner=""
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) owner="${2:-}"; shift 2;;
    -*) dr_vps_die "$DR_VPS_E_USAGE" "destroy: unknown flag: $1"; return $?;;
    *)  if [ -z "$id" ]; then id="$1"; shift; else dr_vps_die "$DR_VPS_E_USAGE" "destroy: too many arguments"; return $?; fi;;
  esac; done
  [ -n "$id" ] || { dr_vps_die "$DR_VPS_E_USAGE" "destroy <id> [--owner UID]"; return $?; }
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  dr_vps_vm_do_owned "$id" "$owner" _dr_vps_domain_destroy_impl "$id"
}
_dr_vps_domain_destroy_impl() {  # <id>  (invoked ONLY via dr_vps_domain_destroy, under the per-VM lock, owner-verified)
  local id="$1" overlay isgolden pk presence _pp
  _dr_vps_safe_id "$id" || return $?
  # Require a store row: never `virsh undefine` a domain the rig didn't create (a direct
  # `dr-vps destroy <name>` must not hit an unrelated libvirt domain; the agent path also gates).
  [ -n "$(dr_vps_sql "SELECT 1 FROM vms WHERE id=$(dr_vps_sql_str "$id");")" ] \
    || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such rig vm: $id (refusing destroy of an unmanaged domain)"; return $?; }
  # PRESENT -> full live-domain identity gate (UUID+disk+backing) where the gate is loaded.
  # ABSENT  -> a broken recreate left no domain; the golden-guard + basename path-fence below still
  #            protect the file deletion, so skipping the (inapplicable) gate adds no host-reach.
  # INDETERMINATE (libvirt unreachable) -> FAIL CLOSED: we cannot prove the domain's state, so we
  #            must not gate-skip and delete a possibly-live VM's overlay/row.
  _dr_vps_domain_presence "$id" && presence=0 || presence=$?   # capture rc errexit-safely (0/1/2)
  case "$presence" in
    0) # PRESENT -> the live-domain identity gate MUST run. domain.sh sources gate.sh, so it is always
       # available; if it somehow is not, FAIL CLOSED (never destroy a live domain ungated).
       if declare -F dr_vps_gate_vm >/dev/null 2>&1; then
         dr_vps_gate_vm lifecycle "$id" >/dev/null 2>&1 \
           || { dr_vps_die "$DR_VPS_E_EGRESS" "destroy: live-domain identity gate refused $id"; return $?; }
       else
         dr_vps_die "$DR_VPS_E_EGRESS" "destroy: identity gate unavailable -- refusing to destroy LIVE domain $id"; return $?
       fi ;;
    2) dr_vps_die "$DR_VPS_E_LIBVIRT" "destroy: libvirt unreachable -- refusing (cannot prove $id is not live)"; return $? ;;
  esac
  # Fix 1: close the pooled ssh master + drop its socket before the domain goes away (no-op when DR_VPS_SSH_MUX=0
  # or the module is absent). id-prefix glob -> works even in the ABSENT-domain-with-row branch (no IP needed).
  if declare -F dr_vps_mux_close >/dev/null 2>&1; then dr_vps_mux_close "$id" || true; fi
  # Do NOT tombstone jobs here -- a destroy that later FAILS would falsely mark still-running
  # jobs 'destroyed'. Terminalization is authoritative in exec-status (uuid-check) + the reaper backstop (promotes
  # a stale non-terminal job only after a SUCCESSFUL store read proves the VM gone). recreate tombstones on reuse.
  local _ovrc
  overlay=$(dr_vps_sql "SELECT overlay FROM vms WHERE id=$(dr_vps_sql_str "$id");"); _ovrc=$?
  # FAIL CLOSED on a DB read error: an errored (empty) overlay read must NOT skip the
  # golden-protection block below and fall through to seed-cleanup + row-delete -> orphaned overlay.
  [ "$_ovrc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "destroy: overlay read failed for $id (fail-closed)"; return $?; }
  if [ -n "$overlay" ]; then
    isgolden=$(dr_vps_sql "SELECT COUNT(*) FROM images WHERE golden_path=$(dr_vps_sql_str "$overlay");")
    case "$isgolden" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "golden-count read failed for $id (fail-closed)"; return $?;; esac
    [ "$isgolden" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "overlay equals a registered golden -- refusing destroy"; return $?; }
    [ "$(basename "$overlay")" = "${id}.qcow2" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "overlay basename != ${id}.qcow2 -- refusing"; return $?; }
    # The above checks the RAW overlay path. A SYMLINK overlay would let the path resolve to a
    # registered golden (esp. in the no-domain cleanup branch where the live gate is skipped). Refuse a
    # symlink AND a path whose CANONICAL target is a registered golden -- never delete a golden.
    [ ! -L "$overlay" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "overlay is a SYMLINK -- refusing destroy (golden-protection): $overlay"; return $?; }
    local _rovl _gm _gmrc; _rovl=$(realpath -m "$overlay" 2>/dev/null)
    if [ -n "$_rovl" ]; then
      _gm=$(dr_vps_sql "SELECT 1 FROM images WHERE golden_path=$(dr_vps_sql_str "$_rovl");"); _gmrc=$?
      # FAIL CLOSED: a read error must NOT be read as 'not a golden' -- that would let destroy delete a golden.
      [ "$_gmrc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "destroy: golden-match read failed for $id (fail-closed)"; return $?; }
      [ -z "$_gm" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "overlay resolves to a registered golden ($_rovl) -- refusing destroy"; return $?; }
    fi
  fi
  # Tear the domain down ONLY if it was INITIALLY PRESENT + gate-proven row-owned. In the ABSENT
  # branch there is no rig domain, so we must NEVER `destroy`/`undefine` by name -- a same-name
  # FOREIGN domain that appears in the TOCTOU window must not be hit (the final absence proof catches it).
  if [ "$presence" -eq 0 ]; then
    _dr_virsh destroy "$id" >/dev/null 2>&1 || true
    _dr_virsh undefine "$id" >/dev/null 2>&1 || true
  fi
  # POSITIVE absence proof before deleting files: require absent. PRESENT (undefine failed, or a
  # foreign same-name domain appeared) OR INDETERMINATE (libvirt down) both fail closed -- a failed
  # `dominfo` alone is NOT proof of absence.
  _dr_vps_domain_presence "$id" && _pp=0 || _pp=$?
  [ "$_pp" -eq 1 ] \
    || { dr_vps_die "$DR_VPS_E_LIBVIRT" "destroy: $id still present or libvirt unreachable -- refusing to delete files"; return $?; }
  [ -n "$overlay" ] && { dr_vps_storage_overlay_delete "$overlay" || return $?; }
  dr_vps_storage_seed_cleanup "$id" || return $?
  { pkp="${DR_VPS_SEED_DIR}/${id}.pubkey"; dr_vps_storage_path_fence "$pkp" "$DR_VPS_SEED_DIR" >/dev/null 2>&1 && [ ! -L "$pkp" ] && rm -f -- "$pkp"; } || true
  dr_vps_console_log_cleanup "$id" 2>/dev/null || true    # Observability (Step 9): drop the persisted console log
  # CHECKED row delete: files are already gone, so a silent vm_delete DB failure would leave the row +
  # its referrers pointing at a now-missing overlay -> it blocks the golden's GC with no signal.
  dr_vps_store_vm_delete "$id" \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "destroy: files removed but store vm_delete FAILED for $id -- DANGLING row/referrers (operator: clean the store row to unblock golden GC)"; return $?; }
}

# Observability (Step 9): reap ORPHANED console logs -- a fenced <id>.log whose id has NEITHER a store row
# NOR a live libvirt domain (the create/recreate/destroy lifecycle already cleans logs on the normal paths;
# this backstops a crash between virtlogd writing a log and the row/domain existing). It needs BOTH the live
# domain list (_dr_virsh) and the store, so it lives here, not in storage.sh; it calls the storage cleanup
# helper. BOUNDED (a per-sweep cap) + safe-id only. Wired into dr_vps_reaper_sweep (timer-driven).
dr_vps_console_log_gc() {
  local d="$DR_VPS_CONSOLE_LOG_DIR" f id live rows n=0 mv="$DR_VPS_CONSOLE_MAX_VMS"
  # convergence r2: clamp a possibly-malformed/hand-edited MAX_VMS before the per-sweep cap arithmetic so GC
  # can't error/overflow (the timer re-runs; the sweep is never unbounded regardless of the env value).
  case "$mv" in ''|*[!0-9]*|0?*) mv=64 ;; esac; [ "$mv" -le 1048576 ] || mv=1048576   # strict base-10 (r3: no octal)
  local cap=$(( mv * 4 + 64 ))
  [ -d "$d" ] || return 0
  # FAIL CLOSED: a libvirt read error reaps NOTHING (never delete a possibly-live VM's log on a transient fault).
  live=$(_dr_virsh list --all --name 2>/dev/null) || return 0
  for f in "$d"/*.log; do
    [ -f "$f" ] || continue                            # only primary regular <id>.log (skip globs/rotated .N)
    [ ! -L "$f" ] || continue                          # never follow a symlink anomaly (cleanup refuses it too)
    n=$((n + 1)); [ "$n" -le "$cap" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "console_log_gc: >$cap logs in $d -- stopping this sweep (next timer tick continues)" >&2 || true; break; }
    id=$(basename "$f" .log)
    case "$id" in ''|.|..|-*|*[!A-Za-z0-9_.-]*) continue ;; esac   # safe-id only; leave anomalies for an operator
    printf '%s\n' "$live" | grep -Fxq -- "$id" && continue        # a live domain owns it -> keep
    rows=$(dr_vps_sql "SELECT 1 FROM vms WHERE id=$(dr_vps_sql_str "$id");") || continue   # DB error -> keep (fail closed)
    [ -z "$rows" ] || continue                         # a store row owns it -> keep
    dr_vps_console_log_cleanup "$id" 2>/dev/null || true          # rowless AND domainless -> orphan; path-fenced remove
    dr_vps_diag "gc: reaped orphan console log id=$id (no store row, no live domain)"   # metadata-only (SPEC-DIAG)
  done
  return 0
}
