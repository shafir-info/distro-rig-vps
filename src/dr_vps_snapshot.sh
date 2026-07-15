#!/usr/bin/env bash
# dr_vps_snapshot.sh -- SNAPSHOT feature (installed-state artifacts). Design: CONCEPT-FORK.md.
# Freeze a VM's installed state into a standalone, scrubbed, self-contained artifact BUNDLE that is
# UNPRIVILEGED to create/delete (the daemon runs `dr-vps snapshot` as drvps), HARD-SEGREGATED from trusted
# goldens (kind='snapshot', drvps-snap-v1-* prefix, DR_VPS_SNAP_DIR, snapshots table), with JSON+MD sidecar
# metadata, and usable to seed new VMs. Reuses the golden supply chain (digest/standalone/register/refcount).
# ASCII only; bins run set -uo pipefail (code is also -e-safe). STDOUT contract: create/use STDOUT = the
# bare id; ALL progress to stderr.

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
# domain.sh pulls identity/store/image/storage/net/doctor/gate -> everything the engine needs.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_domain.sh
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_domain.sh"

# ---- order-log seam (bats asserts the create sequence order) -----------------------
_snap_order_log() { [ -n "${DR_VPS_SNAP_ORDERLOG:-}" ] && printf '%s\n' "$1" >>"$DR_VPS_SNAP_ORDERLOG" || true; }

# ---- TYPED RESOLVERS (CONCEPT R3.1): the ONLY user-facing artifact resolution. -----
# id-or-name -> golden artifact_id | die. Enforces kind + raw prefix + POOL_DIR fence + NOT-a-snapshot.
dr_vps_resolve_golden() {  # <id_or_name>
  local q="$1" aid gp rc _snx _snxrc
  # EXACT ID WINS before name (an older golden whose NAME equals a newer golden's ID must NOT be
  # resolved on an exact-id query). Try id first; only fall back to a name lookup if no id matches.
  # FAIL CLOSED on a read error (like dr_vps_store_snapshot_id): an errored exact-id read must NOT fall through
  # to the NAME lookup -- an empty result there is indistinguishable from 'no exact id', so a transient error
  # could resolve <id> via a name collision and act on the WRONG golden.
  aid=$(dr_vps_sql "SELECT artifact_id FROM images WHERE kind='golden' AND artifact_id=$(dr_vps_sql_str "$q") LIMIT 1;"); rc=$?
  [ "$rc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden id read failed for $q (fail-closed)"; return $?; }
  if [ -z "$aid" ]; then
    aid=$(dr_vps_sql "SELECT artifact_id FROM images WHERE kind='golden' AND name=$(dr_vps_sql_str "$q") ORDER BY created_at LIMIT 1;"); rc=$?
    [ "$rc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden name read failed for $q (fail-closed)"; return $?; }
  fi
  [ -n "$aid" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such golden: $q"; return $?; }
  case "$aid" in drvps-raw-v1-*) ;; *) dr_vps_die "$DR_VPS_E_VERIFY" "golden has non-golden prefix: $aid"; return $?;; esac
  # disambiguation read (golden id must not also be a snapshot id) must FAIL CLOSED on error, not read empty
  # (=> 'not a snapshot') and proceed.
  _snx=$(dr_vps_sql "SELECT 1 FROM snapshots WHERE id=$(dr_vps_sql_str "$aid");"); _snxrc=$?
  [ "$_snxrc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden/snapshot disambiguation read failed for $aid (fail-closed)"; return $?; }
  [ -z "$_snx" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden id also present in snapshots: $aid"; return $?; }
  gp=$(dr_vps_store_image_get "$aid")
  dr_vps_storage_path_fence "$gp" "$DR_VPS_POOL_DIR" >/dev/null \
    || { dr_vps_die "$DR_VPS_E_VERIFY" "golden path not under pool: $gp"; return $?; }
  printf '%s\n' "$aid"
}
# id-or-name -> snapshot id | die. Enforces kind + snap prefix + snapshots membership + canonical image path.
dr_vps_resolve_snapshot() {  # <id_or_name> [owner_uid]  -- if owner_uid is given, resolve ONLY a snapshot
  # owned by that uid (a non-owner client -> not-found, no existence leak). The direct operator passes no owner.
  local q="$1" own="${2:-}" id gp exp
  id=$(dr_vps_store_snapshot_id "$q" "$own")
  [ -n "$id" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such snapshot: $q"; return $?; }
  case "$id" in drvps-snap-v1-*) ;; *) dr_vps_die "$DR_VPS_E_VERIFY" "snapshot has non-snapshot prefix: $id"; return $?;; esac
  [ "$(dr_vps_sql "SELECT kind FROM images WHERE artifact_id=$(dr_vps_sql_str "$id");")" = snapshot ] \
    || { dr_vps_die "$DR_VPS_E_VERIFY" "snapshot not registered kind=snapshot: $id"; return $?; }
  gp=$(dr_vps_store_snapshot_golden_path "$id"); exp="${DR_VPS_SNAP_DIR}/${id}/image.qcow2"
  [ "$gp" = "$exp" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "snapshot image path mismatch: '$gp' != '$exp'"; return $?; }
  dr_vps_storage_path_fence "$gp" "$DR_VPS_SNAP_DIR" >/dev/null \
    || { dr_vps_die "$DR_VPS_E_VERIFY" "snapshot path not under snap dir: $gp"; return $?; }
  printf '%s\n' "$id"
}

# ---- digest: content id with the drvps-snap-v1 prefix (HARDCODED here -> an unprivileged caller can never
# mint a drvps-raw-v1-* golden). Reuses dr_vps_golden_digest's raw-stream digest + standalone assertion.
dr_vps_snapshot_digest() {  # <qcow2> -> drvps-snap-v1-<vsize>-<sha>
  local raw; raw=$(dr_vps_golden_digest "$1") || return $?
  printf 'drvps-snap-v1-%s\n' "${raw#drvps-raw-v1-}"
}

# ---- standalone assertion (no backing, no external data-file) -- reused twice in create ----
_dr_vps_snapshot_assert_standalone() {  # <qcow2>
  local qi back df
  qi=$("$DR_QEMU_IMG" info -U --output=json -f qcow2 "$1" 2>/dev/null)
  back=$(printf '%s' "$qi" | jq -r '."backing-filename" // ""')
  df=$(printf '%s' "$qi" | jq -r '."format-specific".data."data-file" // ""')
  [ -z "$back" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "snapshot image not standalone (backs $back)"; return $?; }
  [ -z "$df" ]   || { dr_vps_die "$DR_VPS_E_VERIFY" "snapshot image has external data-file ($df)"; return $?; }
}

# ---- scrub: EXPLICIT allow-list virt-sysprep (never the default everything-set). PRESERVES rpm-db,
# selinux modules, enabled units, package state. A per-profile hook appends app-specific paths so
# the GENERIC core stays application-free (CONCEPT R3.4). Seamed via DR_VIRT_SYSPREP (bats sets a recorder).
_dr_vps_snapshot_scrub() {  # <qcow2> <profile>
  # NOTE: `cloud-init` is NOT a valid virt-sysprep --operations name (guestfs-tools 1.55.8 / Fedora 44 -- see
  # `virt-sysprep --list-operations`), so including it made the scrub FAIL on every real host; only the bats
  # sysprep RECORDER hid it (LIVE fix 2026-07-04). Reset cloud-init's PER-INSTANCE state via --delete instead,
  # so a VM cloned from the snapshot re-initializes cloud-init from its own fresh seed.
  local img="$1" profile="$2" ops="machine-id,ssh-hostkeys,ssh-userdir,logfiles,tmp-files,bash-history,udev-persistent-net"
  # Reset ALL of cloud-init's RUNTIME state dir (/var/lib/cloud): instance dirs, the `instance` symlink, the
  # data/instance-id cache, and semaphores. This is the canonical "prepare a cloud image for reuse" reset --
  # it (a) makes a VM cloned from the snapshot re-init cloud-init from its own fresh seed, and (b) removes the
  # random/timestamped per-instance state so IDENTICAL installs digest to the SAME content id (reproducible
  # content-addressing). Distro-general: /var/lib/cloud is the standard path on every cloud-init distro
  # (dnf/apt/zypper), and virt-sysprep --delete globs -> a NO-OP where it is absent (e.g. alpine/tiny-cloud).
  # NOT /etc/cloud (config) -- only the state dir, which cloud-init recreates on next boot.
  local -a extra=(--delete /var/lib/cloud)
  # profile hook: a function named _dr_vps_snapshot_scrub_profile_<name> (one --delete path per line)
  # is invoked when --profile <name> is given. Generic = the cloud-init reset above.
  if declare -F "_dr_vps_snapshot_scrub_profile_${profile}" >/dev/null 2>&1; then
    while IFS= read -r _p; do [ -n "$_p" ] && extra+=(--delete "$_p"); done < <("_dr_vps_snapshot_scrub_profile_${profile}")
  fi
  dr_vps_have "$DR_VIRT_SYSPREP" \
    || { dr_vps_die "$DR_VPS_E_CAP" "virt-sysprep ($DR_VIRT_SYSPREP) absent -- install guestfs-tools to scrub (or --keep-secrets)"; return $?; }
  # --operations is the EXPLICIT allow-list (NOT the default set); no rpm-db op -> package state stays
  # consistent. CAPTURE the output to a log + surface the tail on failure -- a swallowed sysprep error is
  # undiagnosable (exactly why the invalid `cloud-init` op took a live run to find; cf. the bake's $bakelog).
  mkdir -p "$DR_VPS_TMP_DIR"
  local _sl; _sl=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" sysprep.XXXXXX.log)
  if ! LIBGUESTFS_BACKEND="${DR_VPS_LIBGUESTFS_BACKEND:-direct}" \
       "$DR_VIRT_SYSPREP" -a "$img" --operations "$ops" "${extra[@]}" >"$_sl" 2>&1; then
    dr_vps_die "$DR_VPS_E_GENERIC" "virt-sysprep scrub failed -- see $_sl ; last lines: $(tail -5 "$_sl" 2>/dev/null | tr '\n' '|')"; return $?
  fi
  rm -f -- "$_sl"
}

# App-specific scrub profiles live OUT of the generic core (CONCEPT R3.4): define
# _dr_vps_snapshot_scrub_profile_<name>() emitting one --delete path per line, e.g.
#   _dr_vps_snapshot_scrub_profile_myapp() { printf '%s\n' '/opt/myapp' '/home/*/myapp-*.log'; }
# and snapshot with --profile myapp.

# ---- validation boot via a DISPOSABLE overlay (CONCEPT R3.4 CRITICAL: booting the base itself would
# regenerate identity + CHANGE THE DIGEST). Create a throwaway overlay backed by the scrubbed base, START it
# (transient), then discard; the base is NEVER mutated. Seamed: DR_VIRSH/DR_QEMU_IMG.
# SCOPE (v1, honest): this proves STRUCTURAL bootability -- libvirt+qemu accept AND start the flattened image
# (catches a corrupt/unbacked/unbootable disk from e.g. a force-off flatten). It is NOT full guest health:
# deeper checks (getenforce, expected SELinux modules, AVC delta, app healthcheck) need an ssh-seeded guest and are the operator's
# LIVE ACCEPTANCE layer -- extensible here via the optional per-profile hook `_dr_vps_snapshot_validate_profile_<p>`.
dr_vps_snapshot_validate_boot() {  # <base_image> <profile> -> 0 pass / nonzero fail
  local base="$1" profile="$2" ov dom rc=0 st
  ov=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" snapval.XXXXXX.qcow2) || return 1
  # disposable overlay backed by the (immutable) scrubbed base -- boot THIS, never the base.
  if ! "$DR_QEMU_IMG" create -f qcow2 -b "$base" -F qcow2 "$ov" >/dev/null 2>&1; then rm -f "$ov"; return 1; fi
  chmod 0640 "$ov" 2>/dev/null || true; chgrp "$DR_VPS_SEED_GROUP" "$ov" 2>/dev/null || true   # qemu must read the val overlay 
  _snap_order_log validate_overlay_created
  dom="drvps-snapval-$(/usr/bin/basename "$ov" .qcow2 2>/dev/null || echo "$$")"   # unique transient name (no $$ collision)
  # transient domain (virsh create, NOT define -> auto-gone on destroy). Actually START it (no --paused).
  if "$DR_VIRSH" -c "$DR_LIBVIRT_URI" create /dev/stdin >/dev/null 2>&1 <<EOF
<domain type='kvm'><name>$dom</name><memory unit='MiB'>512</memory><vcpu>1</vcpu>
<os><type arch='x86_64'>hvm</type></os><devices><disk type='file' device='disk'>
<source file='$ov'/><target dev='vda' bus='virtio'/></disk></devices></domain>
EOF
  then
    _snap_order_log validate_booted
    # optional extended guest-health hook (a profile may ssh in + probe); absent -> structural-only pass.
    if declare -F "_dr_vps_snapshot_validate_profile_${profile}" >/dev/null 2>&1; then
      "_dr_vps_snapshot_validate_profile_${profile}" "$dom" "$ov" || rc=1
    fi
    "$DR_VIRSH" -c "$DR_LIBVIRT_URI" destroy "$dom" >/dev/null 2>&1 || true
    st=$("$DR_VIRSH" -c "$DR_LIBVIRT_URI" domstate "$dom" 2>/dev/null)
    case "$st" in ''|"shut off") ;; *) rc=1;; esac   # still defined/running -> FAIL (and leave the overlay below)
  else
    rc=1
  fi
  # discard the disposable overlay ONLY when the transient domain is provably gone -- NEVER rm a disk out from
  # under a still-running domain (destroy-failed leak-safety).
  case "${st:-gone}" in ''|gone|"shut off") rm -f "$ov";; esac
  return "$rc"
}

# ---- name generation: drvps-snap-<distro>-<UTCYYYYmmddTHHMMZ>-<short8> (short8 = first 8 of the content sha).
_dr_vps_snapshot_name() {  # <distro> <snap_id> <utc>
  local distro="$1" sid="$2" utc="$3" sha short8
  sha="${sid##*-}"; short8="${sha:0:8}"
  distro="${distro//[^A-Za-z0-9._:-]/_}"
  distro="${distro:0:40}"   # cap the variable segment so the auto-name stays well under the 128 SAFE_SNAP/rename cap 
  printf 'drvps-snap-%s-%s-%s' "$distro" "$utc" "$short8"
}

# ======================================================================================================
# CREATE: the hardened R3.4 sequence. STDOUT = the bare snapshot id.
# ======================================================================================================
# ---- install-path cmdlog: the commands the driver ran on the SOURCE VM, captured HOST-SIDE (the
# guest history is scrubbed for reproducible content-addressing). Recorded into the provenance SIDECAR, NOT the
# content digest ($sid is the image digest, computed before this) -- two identical installs with different
# cmdlogs keep the SAME id. Best-effort secret redaction (the caller owns what it logs) + a hard size/line cap;
# control chars stripped; ``` fences neutralized (install_path is rendered VERBATIM into snapshot.md).
_dr_vps_snapshot_redact_installlog() {  # <file> -> a fenced md command block (redacted, capped); prints '' if empty
  local f="$1" body
  body=$(
    head -c "${DR_VPS_INSTALL_LOG_MAX_BYTES:-65536}" -- "$f" 2>/dev/null \
    | tr -d '\000-\010\013\014\016-\037' \
    | sed -E \
        -e 's/(-{1,2}(password|passwd|token|secret|api[_-]?key|auth)([=[:space:]]))[^[:space:]]*/\1***REDACTED***/gI' \
        -e 's/(^|[[:space:]])(([A-Za-z_][A-Za-z0-9_]*_)?(PASS|PASSWD|PASSWORD|TOKEN|SECRET|APIKEY|API_KEY|AUTH)(_[A-Za-z0-9_]+)?=)[^[:space:]]*/\1\2***REDACTED***/gI' \
        -e 's/([Bb]earer )[A-Za-z0-9._~+/=-]+/\1***REDACTED***/g' \
        -e 's/`{3,}/(fence)/g' \
    | head -n "${DR_VPS_INSTALL_LOG_MAX_LINES:-500}"
  )
  [ -n "$body" ] || return 0
  printf '```\n%s\n```' "$body"
}

dr_vps_snapshot_create() {  # <vm> [--keep-secrets] [--notes STR] [--profile NAME] [--install-log FILE]
  local vm="$1"; shift || true
  local keep=0 notes="" profile="generic" owner="" install_log=""
  while [ "$#" -gt 0 ]; do case "$1" in
    --keep-secrets) keep=1; shift;;
    --notes)   [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--notes needs a value"; return $?; }; notes="$2"; shift 2;;
    --profile) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--profile needs a value"; return $?; }; profile="$2"; shift 2;;
    --owner)   [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }; owner="$2"; shift 2;;   # client OS uid (from ingress SO_PEERCRED); empty = direct operator
    --install-log) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--install-log needs a file"; return $?; }; install_log="$2"; shift 2;;   # host-side cmdlog -> provenance SIDECAR (I7)
    *) dr_vps_die "$DR_VPS_E_USAGE" "snapshot: unknown flag: $1"; return $?;;
  esac; done
  local install_path_md=""
  if [ -n "$install_log" ]; then
    { [ -f "$install_log" ] && [ -r "$install_log" ]; } || { dr_vps_die "$DR_VPS_E_NOTFOUND" "--install-log not a readable file: $install_log"; return $?; }
    install_path_md=$(_dr_vps_snapshot_redact_installlog "$install_log")
  fi
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid: $owner"; return $?; };; esac
  [ -n "$vm" ] || { dr_vps_die "$DR_VPS_E_USAGE" "snapshot <vm> [--keep-secrets] [--notes STR] [--profile NAME]"; return $?; }
  # SANITIZE free-text notes to a SINGLE LINE (strip control chars; collapse CR/LF/TAB to spaces) so a
  # `--notes $'\n## Forged\n- parent golden : fake'` can't forge Markdown structure in snapshot.md .
  notes=$(printf '%s' "$notes" | tr -d '\000-\010\013\014\016-\037' | tr '\r\n\t' '   ')
  # --profile selects a hook function name (_dr_vps_snapshot_scrub_profile_<p>) + lands in the md; restrict it
  # to a plain identifier so it can't inject a function name OR forge Markdown structure .
  case "$profile" in ''|*[!A-Za-z0-9_-]*) dr_vps_die "$DR_VPS_E_USAGE" "bad --profile (allowed [A-Za-z0-9_-]): $profile"; return $?;; esac
  _dr_vps_safe_id "$vm" || return $?

  # 1. LOCK (per-VM): the gate proves identity, it does NOT serialize. Non-blocking -> busy is a CONFLICT.
  local lockdir="${DR_VPS_STATE_DIR}/locks" lockf lfd
  mkdir -p "$lockdir"; lockf="${lockdir}/vm-${vm}.lock"
  exec {lfd}>"$lockf" || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot open lock $lockf"; return $?; }
  if ! "$DR_FLOCK" -n "$lfd"; then exec {lfd}>&-; dr_vps_die "$DR_VPS_E_CONFLICT" "vm $vm busy (lifecycle lock held)"; return $?; fi

  # 2. GATE (lifecycle, host-side).
  if declare -F dr_vps_gate_vm >/dev/null 2>&1; then
    dr_vps_gate_vm lifecycle "$vm" >/dev/null 2>&1 || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_EGRESS" "snapshot: lifecycle gate refused $vm"; return $?; }
  else
    exec {lfd}>&-; dr_vps_die "$DR_VPS_E_EGRESS" "snapshot: identity gate unavailable -- refusing"; return $?
  fi

  # 3. CAPTURE PROVENANCE **before** any scrub (sysprep removes the evidence).
  _snap_order_log provenance
  local row overlay aid dom_uuid parent_prov distro _pprc _grc
  row=$(dr_vps_store_vm_gaterow "$vm"); _grc=$?   # overlay|artifact_id|egress_gen|domain_uuid|state|net
  # A transient store READ FAILURE is infra (retriable), not NOTFOUND (genuinely-absent VM).
  [ "$_grc" -eq 0 ] || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "snapshot: store read failed for $vm (transient) -- refusing"; return $?; }
  overlay=$(printf '%s' "$row" | cut -d'|' -f1); aid=$(printf '%s' "$row" | cut -d'|' -f2)
  dom_uuid=$(printf '%s' "$row" | cut -d'|' -f4)
  { [ -n "$overlay" ] && [ -n "$aid" ]; } || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_NOTFOUND" "no vm row/overlay for $vm"; return $?; }
  # FAIL CLOSED on a provenance READ ERROR (E_VERIFY): registering a snapshot with parent_provenance:{} +
  # distro:"unknown" would corrupt the metadata the matrix base-selection + snap-show rely on. A legitimately
  # ABSENT parent provenance (E_NOTFOUND) is still tolerated as '{}'/"unknown" (a golden should carry one, but
  # absence is not a transient read failure).
  parent_prov=$(dr_vps_image_provenance "$aid" 2>/dev/null); _pprc=$?
  [ "$_pprc" -ne "$DR_VPS_E_VERIFY" ] || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_VERIFY" "cannot read parent provenance for $aid"; return $?; }
  [ -n "$parent_prov" ] || parent_prov='{}'
  distro=$(printf '%s' "$parent_prov" | jq -r '.distro // "unknown"')

  # 3b. CAPACITY PRE-CHECK : the flatten writes up to the overlay's VIRTUAL SIZE to SNAP_DIR and
  # the digest writes the same to TMP_DIR (~2x). Verify free space on BOTH filesystems BEFORE shutting the VM
  # down, so ENOSPC doesn't leave the source powered off with nothing produced. Best-effort (skip if unknown).
  mkdir -p "$DR_VPS_SNAP_DIR" "$DR_VPS_TMP_DIR" 2>/dev/null || true
  local _vsize _need _avails _availt
  _vsize=$("$DR_QEMU_IMG" info -U --output=json "$overlay" 2>/dev/null | jq -r '."virtual-size" // 0')
  case "$_vsize" in ''|*[!0-9]*) _vsize=0;; esac
  if [ "$_vsize" -gt 0 ]; then
    _need=$(( _vsize / 1024 ))                                   # KiB (conservative: full virtual size)
    _avails=$(df -Pk "$DR_VPS_SNAP_DIR" 2>/dev/null | awk 'NR==2{print $4}')
    _availt=$(df -Pk "$DR_VPS_TMP_DIR"  2>/dev/null | awk 'NR==2{print $4}')
    case "$_avails" in ''|*[!0-9]*) _avails="";; esac; case "$_availt" in ''|*[!0-9]*) _availt="";; esac
    if { [ -n "$_avails" ] && [ "$_avails" -lt "$_need" ]; } || { [ -n "$_availt" ] && [ "$_availt" -lt "$_need" ]; }; then
      exec {lfd}>&-; dr_vps_die "$DR_VPS_E_CAP" "insufficient free space for snapshot of $vm (need ~${_need}KiB in SNAP_DIR + TMP_DIR; have snap=${_avails:-?} tmp=${_availt:-?} KiB) -- freeing space, VM left running"; return $?
    fi
  fi

  # 4. SHUTDOWN (clean ACPI + bounded wait; force-off fallback records shutdown_mode='forced').
  _snap_order_log shutdown
  local sd rc; sd=$(dr_vps_domain_shutdown "$vm" "${DR_VPS_SNAP_SHUTDOWN_TIMEOUT:-60}") \
    || { rc=$?; exec {lfd}>&-; return "$rc"; }   # preserve the real shutdown rc (e.g. E_LIBVIRT), not a generic 1
  # STORE STATE MUST REFLECT LIFECYCLE TRUTH : the source VM is now powered OFF but still defined
  # ('left powered off' by design). Record 'stopped' so list/status don't lie 'running'. Best-effort (this is
  # informational; the gate uses live domstate, not this). It persists on later snapshot failure = honest.
  dr_vps_store_vm_set_state "$vm" stopped 2>/dev/null || true

  # 5. FLATTEN into a TEMP bundle (fenced, atomic-rename later).
  mkdir -p "$DR_VPS_SNAP_DIR"
  # SNAP_DIR must be TRAVERSABLE by the qemu group so a VM can later back onto a snapshot image inside it
  # (mirrors the golden pool). Best-effort (a deploy/setup also ensures it).
  chgrp "$DR_VPS_SEED_GROUP" "$DR_VPS_SNAP_DIR" 2>/dev/null || true
  chmod 0750 "$DR_VPS_SNAP_DIR" 2>/dev/null || true
  # Self-heal: sweep our OWN stale temp bundles (the daemon SIGKILLs a lifecycle op past its timeout, leaving
  # no trap to clean a .snap.* mid-create -- no reaper covers SNAP_DIR). Remove .snap.* dirs older than the
  # sweep age (default 2h). Bounded to OUR prefix under the fenced SNAP_DIR; never touches a final bundle.
  local _sd _sage="${DR_VPS_SNAP_TMP_SWEEP_MIN:-120}"
  for _sd in "$DR_VPS_SNAP_DIR"/.snap.*/; do
    [ -d "$_sd" ] || continue
    # only reap a temp bundle whose NEWEST entry is older than the age (a live flatten writes image.qcow2 and
    # keeps it fresh; the dir mtime alone freezes at mktemp).
    [ -n "$(find "$_sd" -mmin "-${_sage}" -print -quit 2>/dev/null)" ] || rm -rf "$_sd" 2>/dev/null || true
  done
  local tmpb tmpimg
  tmpb=$(mktemp -d --tmpdir="$DR_VPS_SNAP_DIR" .snap.XXXXXX) || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "mktemp snap bundle failed"; return $?; }
  dr_vps_storage_path_fence "$tmpb" "$DR_VPS_SNAP_DIR" >/dev/null || { rm -rf "$tmpb"; exec {lfd}>&-; return 1; }
  tmpimg="$tmpb/image.qcow2"
  _snap_order_log flatten
  "$DR_QEMU_IMG" convert -O qcow2 "$overlay" "$tmpimg" >/dev/null 2>&1 \
    || { rm -rf "$tmpb"; exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "flatten (qemu-img convert) failed for $vm"; return $?; }
  _snap_order_log assert_standalone_pre
  _dr_vps_snapshot_assert_standalone "$tmpimg" || { rm -rf "$tmpb"; exec {lfd}>&-; return 1; }

  # 6. SCRUB (default) unless --keep-secrets.
  local secret=0
  if [ "$keep" -eq 1 ]; then secret=1; else
    _snap_order_log sysprep
    _dr_vps_snapshot_scrub "$tmpimg" "$profile" || { rm -rf "$tmpb"; exec {lfd}>&-; return 1; }
  fi

  # 7. assert standalone AGAIN, then DIGEST the scrubbed base.
  _snap_order_log assert_standalone_post
  _dr_vps_snapshot_assert_standalone "$tmpimg" || { rm -rf "$tmpb"; exec {lfd}>&-; return 1; }
  _snap_order_log digest
  local sid; sid=$(dr_vps_snapshot_digest "$tmpimg") || { rm -rf "$tmpb"; exec {lfd}>&-; return 1; }
  # Make the TEMP bundle + image qemu-group readable NOW -- BEFORE validation boots a VM backed by them (and
  # carried through the mv to final). Else the 0600 image inside a 0700 mktemp dir is unreadable by qemu and
  # the validation boot fails E_VERIFY on a normal host . (The publish re-applies the same perms.)
  chmod 0640 "$tmpimg" 2>/dev/null || true; chgrp "$DR_VPS_SEED_GROUP" "$tmpimg" 2>/dev/null || true
  chmod 0750 "$tmpb"   2>/dev/null || true; chgrp "$DR_VPS_SEED_GROUP" "$tmpb"   2>/dev/null || true

  # ARTIFACT LOCK: serialize the idempotent-check -> publish -> register section on
  # THIS content id, so (a) two concurrent creates of identical content from different VMs cannot race the
  # publish (nest bundles / mismatch provenance), and (b) a crash-orphaned final bundle can be adopted
  # atomically instead of wedging retries. Non-blocking -> busy = CONFLICT. `_x` closes BOTH fds + drops tmpb.
  local alockf="${lockdir}/snap-${sid}.lock" alfd
  exec {alfd}>"$alockf" || { rm -rf "$tmpb"; exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "cannot open artifact lock $alockf"; return $?; }
  if ! "$DR_FLOCK" -n "$alfd"; then exec {alfd}>&-; exec {lfd}>&-; rm -rf "$tmpb"; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot $sid busy (another create of identical content in flight)"; return $?; fi
  _snap_x() { rm -rf "$tmpb" 2>/dev/null; exec {alfd}>&-; exec {lfd}>&-; }   # unwind helper for this section

  # 8a. FORCED-SHUTDOWN GATE (before the idempotent shortcut, so a force-killed image can NEVER slip through
  # as a "matching" id): a forced shutdown is untrustworthy without a validation boot .
  if [ "$sd" = forced ] && [ "${DR_VPS_SNAPSHOT_VALIDATE:-0}" != 1 ]; then
    _snap_x; dr_vps_die "$DR_VPS_E_VERIFY" "forced shutdown requires DR_VPS_SNAPSHOT_VALIDATE=1 (cannot trust a force-killed image)"; return $?
  fi
  # 8b. OWNERSHIP DECISION for this content id, from ONE authoritative DB read that FAILS CLOSED on error
  # The prior version derived the idempotent + cross-owner checks from reads
  # that returned EMPTY on a SQL error, so a transient SQLite lock/error would look like "no row" and skip BOTH
  # guards -- if the DB then recovered before register, client B could receive owner A's id. Read the sid row's
  # owner ONCE ("Y"+owner, or empty for no row); a nonzero rc = an UNREADABLE db -> refuse (never publish under
  # an unknown ownership state). `_ex_own` empty = genuinely no row; "Y" = a NULL-owner (operator) row; "Y<uid>"
  # = a client-owned row.
  local _ex_own _ex_rc
  _ex_own=$(dr_vps_sql "SELECT 'Y'||COALESCE(owner_uid,'') FROM snapshots WHERE id=$(dr_vps_sql_str "$sid") LIMIT 1;"); _ex_rc=$?
  if [ "$_ex_rc" -ne 0 ]; then
    _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "snapshot owner lookup failed (db read error) -- refusing to publish"; return $?
  fi
  # 8b-i. IDEMPOTENT no-op: a row THIS caller may claim (the operator [empty owner] matches ANY row -- admin
  # idempotency; a client matches only its OWN uid) whose bundle is a REAL dir + REAL regular image.qcow2. The
  # bundle must NOT be a symlink: `-f`/`-d` follow symlinks, so a tampered `${SNAP_DIR}/${sid}` -> external-dir
  # symlink would otherwise let create report SUCCESS for an unfenced/corrupt bundle, bypassing the publish `-L`
  # guards . If symlinked/corrupt or the image is missing we DON'T short-circuit -> fall through
  # (a legit same-owner rebuild, or the publish `-L`/CONFLICT guards fail CLOSED).
  if [ -n "$_ex_own" ] && { [ -z "$owner" ] || [ "${_ex_own#Y}" = "$owner" ]; } \
     && [ ! -L "${DR_VPS_SNAP_DIR}/${sid}" ] && [ -d "${DR_VPS_SNAP_DIR}/${sid}" ] \
     && [ ! -L "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" ] && [ -f "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" ]; then
    # RE-DIGEST the registered image before claiming idempotent success: a corrupted/replaced
    # image.qcow2 at the same path must NOT be reported as a good snapshot. Content-match -> idempotent no-op;
    # mismatch -> FAIL CLOSED (never silently return a corrupt artifact; operator repairs via snap-fsck --prune).
    if [ "$(dr_vps_snapshot_digest "${DR_VPS_SNAP_DIR}/${sid}/image.qcow2" 2>/dev/null)" = "$sid" ]; then
      _snap_x; printf '%s\n' "$sid"; return 0
    fi
    _snap_x; dr_vps_die "$DR_VPS_E_VERIFY" "registered snapshot $sid image FAILS its content digest (corrupt/tampered) -- refusing; operator repair required (snap-fsck --prune)"; return $?
  fi
  # 8b-ii. CROSS-OWNER GUARD: a CLIENT (non-empty owner) whose content id already
  # exists under a DIFFERENT owner -> REFUSE before any publish. Otherwise B would publish a fresh bundle and
  # register's INSERT-WHERE-NOT-EXISTS would silently no-op, handing B owner A's id (+ overwriting A's bundle/
  # sidecars). Snapshots are content-addressed + SINGLE-OWNER in v1. The operator (empty owner) never conflicts
  # here -- it is admin and either short-circuited above or rebuilds. Serialized by the per-content artifact lock.
  if [ -n "$_ex_own" ] && [ -n "$owner" ] && [ "${_ex_own#Y}" != "$owner" ]; then
    _snap_x; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot content already owned by a different client (single-owner v1)"; return $?
  fi

  # 8c. VALIDATION BOOT (disposable overlay). Runs when enabled OR when the shutdown was forced.
  local val=skipped
  if [ "${DR_VPS_SNAPSHOT_VALIDATE:-0}" = 1 ]; then
    if dr_vps_snapshot_validate_boot "$tmpimg" "$profile"; then val=passed; else val=failed; fi
  fi
  if [ "$val" = failed ]; then _snap_x; dr_vps_die "$DR_VPS_E_VERIFY" "snapshot validation boot FAILED for $vm"; return $?; fi
  if [ "$sd" = forced ] && [ "$val" != passed ]; then _snap_x; dr_vps_die "$DR_VPS_E_VERIFY" "forced shutdown requires a PASSING validation boot (got '$val')"; return $?; fi

  # 9. build sidecar + publish under the artifact lock.
  local utc name finalb prov_json
  utc=$(date -u +%Y%m%dT%H%MZ)
  name=$(_dr_vps_snapshot_name "$distro" "$sid" "$utc")
  finalb="${DR_VPS_SNAP_DIR}/${sid}"
  prov_json=$(jq -n --arg k snapshot --arg sid "$sid" --arg nm "$name" --arg pg "$aid" \
      --argjson pp "$parent_prov" --arg svm "$vm" --arg du "$dom_uuid" --arg utc "$utc" \
      --arg dv "${DR_VPS_DRIVER_VERSION:-0.2.0}" --arg sd "$sd" --arg prof "$profile" \
      --argjson sysprep "$([ "$keep" -eq 1 ] && echo false || echo true)" \
      --argjson sec "$secret" --arg val "$val" --arg notes "$notes" --arg distro "$distro" \
      --arg ip "$install_path_md" \
      '{kind:$k,snap_artifact_id:$sid,name:$nm,distro:$distro,parent_golden_id:$pg,parent_provenance:$pp,
        family:($pp.family // "dnf"),repo_content:($pp.repo_content // ""),repo_remove:($pp.repo_remove // ""),
        source_vm_id:$svm,source_domain_uuid:$du,created_at:$utc,driver_version:$dv,shutdown_mode:$sd,
        scrub_profile:$prof,sysprep:$sysprep,secret_bearing:($sec==1),validation_status:$val,notes:$notes,
        install_path:$ip}')
  printf '%s' "$prov_json" | jq -e . >/dev/null 2>&1 || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "provenance JSON build failed"; return $?; }
  printf '%s\n' "$prov_json" > "$tmpb/provenance.json" || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "write provenance.json failed"; return $?; }
  dr_vps_snapshot_md_render "$prov_json" > "$tmpb/snapshot.md" || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "write snapshot.md failed"; return $?; }
  chmod 0640 "$tmpb/provenance.json" "$tmpb/snapshot.md" 2>/dev/null || true
  # image.qcow2 perms: 0640 drvps:qemu for BOTH secret + non-secret.
  chmod 0640 "$tmpimg" 2>/dev/null || true
  chgrp "$DR_VPS_SEED_GROUP" "$tmpimg" 2>/dev/null || true
  # PUBLISH under the artifact lock. REJECT a symlink FIRST : the adopt digest-check must NOT follow a
  # symlinked final path into an attacker-controlled dir (which would then also mislead snap-rm's realpath).
  if [ -L "$finalb" ]; then
    _snap_x; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot final path is a symlink (refusing to follow): $finalb"; return $?
  elif [ -d "$finalb" ] && [ -f "$finalb/image.qcow2" ] && [ ! -L "$finalb/image.qcow2" ] \
     && [ -z "$(dr_vps_store_snapshot_golden_path "$sid")" ] \
     && [ "$(dr_vps_snapshot_digest "$finalb/image.qcow2" 2>/dev/null)" = "$sid" ]; then
    # (a) CRASH-ORPHAN of THIS content: a REAL dir whose image.qcow2 is a REAL regular file (NOT a symlink to
    # outside), digests to sid, no DB row -> ADOPT: refresh the sidecars from this run + register.
    # OWNER SAFETY: a crash-orphan carries NO DB row, hence NO recorded owner -- its
    # true owner is unknowable. A CLIENT must NOT adopt it: it could be ANOTHER client's crash-orphan (B would
    # otherwise claim + register A's in-flight content as B's). Adoption is OPERATOR-ONLY (empty owner = admin);
    # a client is refused fail-closed and the operator cleans the orphan up (snap-fsck --prune, or re-snapshot).
    if [ -n "$owner" ]; then
      _snap_x; dr_vps_die "$DR_VPS_E_CONFLICT" "an unregistered bundle already exists at this content path; a client cannot adopt it (operator cleanup required: snap-fsck --prune)"; return $?
    fi
    # FAIL CLOSED : each sidecar must be CLEARED to a non-existent path (proving a planted symlink is
    # gone -- if rm can't remove it, the assert catches it) THEN written as a fresh REGULAR file; a failed
    # unlink/copy or a surviving symlink ABORTS adoption (never follow a planted link to clobber outside).
    local _f
    for _f in provenance.json snapshot.md; do
      rm -f "$finalb/$_f" 2>/dev/null
      { [ ! -e "$finalb/$_f" ] && [ ! -L "$finalb/$_f" ]; } \
        || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "adopt: could not clear pre-existing sidecar $_f (planted symlink?)"; return $?; }
    done
    { cp -f "$tmpb/provenance.json" "$finalb/provenance.json" && cp -f "$tmpb/snapshot.md" "$finalb/snapshot.md"; } \
      || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "adopt: sidecar copy failed"; return $?; }
    { [ -f "$finalb/provenance.json" ] && [ ! -L "$finalb/provenance.json" ] \
      && [ -f "$finalb/snapshot.md" ] && [ ! -L "$finalb/snapshot.md" ]; } \
      || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "adopt: sidecar not a fresh regular file after refresh"; return $?; }
    rm -rf "$tmpb"
  elif [ -e "$finalb" ]; then
    # (b) a DIFFERENT / already-registered entry sits at the final path -> CONFLICT.
    _snap_x; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot final path already exists with other content: $finalb"; return $?
  else
    # (c) fresh publish. mv -T = no-target-directory, so it FAILS (never nests) if finalb races into existence.
    _snap_order_log rename
    mv -T "$tmpb" "$finalb" || { _snap_x; dr_vps_die "$DR_VPS_E_GENERIC" "bundle rename failed"; return $?; }
  fi
  # bundle dir must be qemu-group TRAVERSABLE so a VM can back onto image.qcow2 inside it.
  chgrp "$DR_VPS_SEED_GROUP" "$finalb" 2>/dev/null || true
  chmod 0750 "$finalb" 2>/dev/null || true

  # 10. REGISTER LAST. Capture the rc DIRECTLY (an `if ! cmd` would read `!`'s status = 0).
  _snap_order_log register
  dr_vps_store_snapshot_register "$sid" "$name" "$prov_json" "${finalb}/image.qcow2" "$vm" "$aid" "$sid" "$secret" "$profile" "$sd" "$val" "$notes" "$owner"
  local rc=$?
  if [ "$rc" -ne 0 ]; then rm -rf "$finalb"; exec {alfd}>&-; exec {lfd}>&-; return "$rc"; fi
  exec {alfd}>&-; exec {lfd}>&-
  printf '%s\n' "$sid"
}

# ---- md renderer (JSON -> human markdown; header golden-provenance -> installation path) ----
dr_vps_snapshot_md_render() {  # <provenance_json> on argv (or stdin)
  local j="${1:-}"; [ -n "$j" ] || j=$(cat)
  printf '%s' "$j" | jq -r '
    # collapse CR/LF in any free-text field so a hostile provenance value cannot forge md structure .
    def clean: (. // "?") | tostring | gsub("[\r\n]";" ");
    "# Snapshot " + (.name | clean),
    "",
    "- content id : " + .snap_artifact_id,
    "- distro     : " + (.distro | clean),
    "- created    : " + (.created_at // "?") + "  (driver " + (.driver_version // "?") + ")",
    "- shutdown   : " + (.shutdown_mode // "?") + "   validation: " + (if (.validation_status // "?") == "skipped" then "skipped (boot-validation is opt-in; set DR_VPS_SNAPSHOT_VALIDATE=1 to enable)" else (.validation_status // "?") end),
    "- scrub      : " + (if .sysprep then ("virt-sysprep allow-list (profile " + (.scrub_profile | clean) + ")") else "NONE (--keep-secrets)" end),
    (if .secret_bearing then "\n> **SECRET-BEARING**: identity + secrets are BAKED into image.qcow2 (0640 drvps:qemu, inside a 0750 bundle dir that excludes non-TCB users; qemu is inside the TCB). Not a safe multi-clone base; `use` requires --allow-secret-bearing." else "" end),
    "",
    "## Basic golden provenance (what this was installed ON)",
    "- parent golden : " + (.parent_golden_id | clean),
    "- parent distro : " + (.parent_provenance.distro | clean) + "  family " + (.parent_provenance.family | clean),
    "- parent built  : " + (.parent_provenance.built_at // "?"),
    "",
    "## Installation path (what was done on top)",
    "- source VM     : " + (.source_vm_id | clean) + "  (domain " + (.source_domain_uuid | clean) + ")",
    (if (.notes // "") != "" then "- notes         : " + (.notes | clean) else "" end),
    (if (.install_path // "") != "" then .install_path else "- (installation-path capture: cmdlog/shell-history not recorded for this snapshot)" end)
  '
}

# ---- lifecycle verbs ---------------------------------------------------------------
# Validate an optional --owner value: a numeric uid, or empty (= direct operator / admin). A MALFORMED
# --owner must fail CLOSED (E_USAGE), never silently degrade to admin scope . Reused by every
# snapshot verb so the direct-CLI path matches the create path's own numeric guard.
_dr_vps_snap_ck_owner() {  # <owner-or-empty>
  case "${1:-}" in ''|*[!0-9]*) [ -z "${1:-}" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid: $1"; return $?; };; esac
}

dr_vps_snapshot_ls() {  # [--owner UID]  -- a client (owner set) sees only its own; the operator sees all.
  local own=""
  if [ "${1:-}" = --owner ]; then
    [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }
    own="$2"
  fi
  _dr_vps_snap_ck_owner "$own" || return $?
  dr_vps_store_snapshot_ls "$own"
}

dr_vps_snapshot_show() {  # <id_or_name> [--owner UID]  -> renders snapshot.md (owner-gated for a client)
  local ref="" own=""
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }; own="$2"; shift 2;;
    *) ref="$1"; shift;;
  esac; done
  _dr_vps_snap_ck_owner "$own" || return $?
  local id; id=$(dr_vps_resolve_snapshot "$ref" "$own") || return $?
  # TOCTOU RE-CHECK: take the per-content lock + re-verify ownership UNDER it before reading
  # the sidecars, so a concurrent delete+re-register under a DIFFERENT owner (in the window resolve..read) cannot
  # make this caller read another owner's refreshed metadata. (Content is content-addressed, so the image is
  # immutable; only the sidecars get refreshed on adopt -- this closes the sidecar-metadata read.)
  local lockdir="${DR_VPS_STATE_DIR}/locks" slfd
  mkdir -p "$lockdir"
  exec {slfd}>"${lockdir}/snap-${id}.lock" || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot open artifact lock for $id"; return $?; }
  if ! "$DR_FLOCK" -n "$slfd"; then exec {slfd}>&-; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot $id busy (create/rm in flight)"; return $?; fi
  local _rid _rrc; _rid=$(dr_vps_store_snapshot_id "$id" "$own"); _rrc=$?
  if [ "$_rrc" -ne 0 ] || [ "$_rid" != "$id" ]; then
    exec {slfd}>&-; dr_vps_die "$DR_VPS_E_NOTFOUND" "snapshot $id no longer resolves for this owner (changed under lock)"; return $?
  fi
  local md="${DR_VPS_SNAP_DIR}/${id}/snapshot.md" _src=0
  if [ -f "$md" ]; then cat "$md" || _src=$?; else
    dr_vps_snapshot_md_render "$(cat "${DR_VPS_SNAP_DIR}/${id}/provenance.json" 2>/dev/null || printf '{}')" || _src=$?
  fi
  exec {slfd}>&-           # close the lock fd, but return the READ status
}

dr_vps_snapshot_rename() {  # <id_or_name> <new_name> [--owner UID]
  local _a=() own=""
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }; own="$2"; shift 2;;
    *) _a+=("$1"); shift;;
  esac; done
  _dr_vps_snap_ck_owner "$own" || return $?
  local newn="${_a[1]:-}"; local id; id=$(dr_vps_resolve_snapshot "${_a[0]:-}" "$own") || return $?
  case "$newn" in *[!A-Za-z0-9._:-]*|'') dr_vps_die "$DR_VPS_E_USAGE" "bad snapshot name (allowed [A-Za-z0-9._:-]): $newn"; return $?;; esac
  # cap the length to the daemon's SAFE_SNAP (128) so a renamed snapshot stays reachable via rigctl .
  [ "${#newn}" -le 128 ] || { dr_vps_die "$DR_VPS_E_USAGE" "snapshot name too long (max 128): ${#newn} chars"; return $?; }
  # a NAME must NOT collide with ANY artifact id (else id-or-name lookups become ambiguous).
  # FAIL CLOSED on a DB read error : an errored guard read must NOT be read as "no collision" --
  # that would let a rename create a name==artifact-id ambiguity (the very state that makes snapshot resolution
  # by name able to shadow an exact id). Capture rc; refuse on a nonzero read.
  local _cx _cxrc; _cx=$(dr_vps_sql "SELECT 1 FROM images WHERE artifact_id=$(dr_vps_sql_str "$newn");"); _cxrc=$?
  [ "$_cxrc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "rename: artifact-id collision check failed (db read error)"; return $?; }
  [ -z "$_cx" ] || { dr_vps_die "$DR_VPS_E_USAGE" "snapshot name must not equal an existing artifact id: $newn"; return $?; }
  # TOCTOU re-check (consistency with rm/show): re-verify ownership right before the write, so a
  # delete+re-register under a different owner between resolve and here cannot let this caller rename another
  # owner's snapshot. rename is operator-only over the socket (the daemon never routes it to a client), so this
  # is defense-in-depth for the direct CLI --owner path. Fail closed on a read error.
  local _rid _rrc; _rid=$(dr_vps_store_snapshot_id "$id" "$own"); _rrc=$?
  { [ "$_rrc" -eq 0 ] && [ "$_rid" = "$id" ]; } || { dr_vps_die "$DR_VPS_E_NOTFOUND" "snapshot $id no longer resolves for this owner (changed before rename)"; return $?; }
  # the store UPDATE is OWNER-SCOPED + collision-guarded ATOMICALLY (TOCTOU race): even if the fast-fail checks
  # above raced, a cross-owner rename or a name==artifact-id collision yields changes()=0 -> refused.
  dr_vps_store_snapshot_rename "$id" "$newn" "$own"
}

# rm: refcount-gated (refuse while a VM backs it), then remove the bundle dir. DB first (authoritative);
# only unlink the fenced bundle after the row is gone.
dr_vps_snapshot_rm() {  # <id_or_name> [--owner UID]  -- owner-gated for a client (a non-owner -> not-found)
  local ref="" own=""
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }; own="$2"; shift 2;;
    *) ref="$1"; shift;;
  esac; done
  _dr_vps_snap_ck_owner "$own" || return $?
  local id; id=$(dr_vps_resolve_snapshot "$ref" "$own") || return $?
  # PER-ARTIFACT LOCK : the SAME snap-<id>.lock create/adopt holds, so delete+unlink SERIALIZES with a
  # concurrent create-adopt of identical content. Without it: rm deletes the DB rows, a create adopts the
  # still-present bundle + re-registers, then rm unlinks -> a registered row pointing at missing files.
  local lockdir="${DR_VPS_STATE_DIR}/locks" alockf alfd
  mkdir -p "$lockdir"; alockf="${lockdir}/snap-${id}.lock"
  exec {alfd}>"$alockf" || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot open artifact lock $alockf"; return $?; }
  if ! "$DR_FLOCK" -n "$alfd"; then exec {alfd}>&-; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot $id busy (create/rm in flight)"; return $?; fi
  # TOCTOU RE-CHECK: the owner-scoped resolve happened BEFORE the lock. Re-verify UNDER the
  # lock that this content id STILL resolves to the SAME id for THIS owner -- otherwise a delete+re-register
  # under a DIFFERENT owner in the window (resolve..lock) would let this caller delete ANOTHER owner's snapshot
  # by content id (the store delete is by id, unscoped). Fail closed on a read error. (The socket path is
  # already serialized by the daemon; this also closes the direct-op path.)
  local _rid _rrc; _rid=$(dr_vps_store_snapshot_id "$id" "$own"); _rrc=$?
  if [ "$_rrc" -ne 0 ] || [ "$_rid" != "$id" ]; then
    exec {alfd}>&-; dr_vps_die "$DR_VPS_E_NOTFOUND" "snapshot $id no longer resolves for this owner (changed under lock)"; return $?
  fi
  dr_vps_store_snapshot_delete "$id" || { local _rc=$?; exec {alfd}>&-; return "$_rc"; }   # E_REFERENCED(19) if a VM backs it
  # DB rows gone (authoritative). Remove the fenced bundle; NEVER follow a SYMLINK bundle (rm -rf on
  # path_fence's REALPATH would delete the symlink TARGET). Reject a symlink + rm the LITERAL path.
  local raw="${DR_VPS_SNAP_DIR}/${id}"
  if [ -L "$raw" ]; then
    exec {alfd}>&-
    printf 'snap-rm: WARNING -- bundle path is a SYMLINK; refusing to follow (DB rows removed; link left): %s\n' "$raw" >&2
    return "$DR_VPS_E_GENERIC"
  fi
  dr_vps_storage_path_fence "$raw" "$DR_VPS_SNAP_DIR" >/dev/null 2>&1 || { exec {alfd}>&-; return 0; }
  if [ ! -e "$raw" ]; then exec {alfd}>&-; return 0; fi
  if ! rm -rf -- "$raw" 2>/dev/null; then
    exec {alfd}>&-
    printf 'snap-rm: WARNING -- DB rows removed but the bundle dir could not be deleted (orphan): %s\n' "$raw" >&2
    return "$DR_VPS_E_GENERIC"
  fi
  exec {alfd}>&-
}

# use: create a VM FROM a snapshot (typed). Secret-bearing snapshots are DENIED as a base unless
# --allow-secret-bearing (the clone inherits the snapshot's machine-id + device-bound session state;
# ssh host keys are NOT duplicated -- cloud-init regenerates them on first boot per new instance-id).
dr_vps_snapshot_use() {  # <name> --from-snap <id_or_name> [--allow-secret-bearing] [create flags...]
  local vmname="$1"; shift || true
  local snapref="" allow=0 own=""; local -a passthru=()
  while [ "$#" -gt 0 ]; do case "$1" in
    --from-snap) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--from-snap needs a value"; return $?; }; snapref="$2"; shift 2;;
    --allow-secret-bearing) allow=1; shift;;
    --owner) [ "$#" -ge 2 ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner needs a value"; return $?; }; own="$2"; shift 2;;
    *) passthru+=("$1"); shift;;
  esac; done
  _dr_vps_snap_ck_owner "$own" || return $?
  { [ -n "$vmname" ] && [ -n "$snapref" ]; } || { dr_vps_die "$DR_VPS_E_USAGE" "use <name> --from-snap <snap-id> [--allow-secret-bearing] [--ttl H --mem M --cpus N --project P --ssh-key F]"; return $?; }
  local sid; sid=$(dr_vps_resolve_snapshot "$snapref" "$own") || return $?
  # TOCTOU (TOCTOU race): resolve is owner-scoped but the secret-bearing read + VM clone below act on the
  # id UNSCOPED. Take the per-content lock and re-verify ownership UNDER it, then hold it across the clone so a
  # delete+re-register under a DIFFERENT owner cannot slip a foreign snapshot under this caller between resolve
  # and use. Held until dr_vps_domain_use_snapshot returns (which registers the VM's referrer, refcount-blocking
  # a later snap-rm). (Reachable on the operator direct path AND, since S6, on the gated agent path below.)
  local lockdir="${DR_VPS_STATE_DIR}/locks" ulfd
  mkdir -p "$lockdir"
  exec {ulfd}>"${lockdir}/snap-${sid}.lock" || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot open artifact lock for $sid"; return $?; }
  if ! "$DR_FLOCK" -n "$ulfd"; then exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot $sid busy (create/rm in flight)"; return $?; fi
  local _rid _rrc; _rid=$(dr_vps_store_snapshot_id "$sid" "$own"); _rrc=$?
  if [ "$_rrc" -ne 0 ] || [ "$_rid" != "$sid" ]; then
    exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_NOTFOUND" "snapshot $sid no longer resolves for this owner (changed under lock)"; return $?
  fi
  # FAIL CLOSED : treat ANY value that is not exactly "0" (incl. empty / corrupt / a
  # non-1 int) as secret-bearing -> require --allow-secret-bearing. A `= 1`-only test would fail OPEN on a
  # tampered row.
  local _sb; _sb=$(dr_vps_store_snapshot_secret_bearing "$sid")
  if [ "$_sb" != 0 ] && [ "$allow" -ne 1 ]; then
    exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_SECRET" "snapshot $sid is SECRET-BEARING (or its secret_bearing flag is not provably 0); refusing as a clone base. Re-run with --allow-secret-bearing if you accept duplicating its machine-id / device-bound session (ssh host keys regenerate on first boot)."; return $?
  fi
  # S6 (GATED): the AGENT path (owner set) may restore a SECRET-BEARING snapshot only under a narrow gate.
  # The OPERATOR direct path (no owner) keeps its historical trust and is untouched. Conditions, ALL under
  # this same per-content lock so the 1:1 refcount is TOCTOU-safe:
  #   (a) the operator policy flag DR_VPS_ALLOW_SECRET_RESTORE is on (default OFF -> door closed);
  #   (b) target class == service (a throwaway has no session worth the collision risk);
  #   (c) 1:1 -- NO existing VM RECORD of this owner references $sid as its base (any state -- the check
  #       is deliberately conservative: a stopped/broken row still blocks until destroyed), so a
  #       restore is a REPLACE (destroy the old driver first), never a clone -> no identity fan-out.
  if [ "$_sb" != 0 ] && [ "$allow" -eq 1 ] && [ -n "$own" ]; then
    if [ "${DR_VPS_ALLOW_SECRET_RESTORE:-0}" != 1 ]; then
      exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_SECRET" "secret-bearing restore is DISABLED on this rig (agent path); the operator must enable DR_VPS_ALLOW_SECRET_RESTORE to permit same-user keep-secrets restore of a service VM."; return $?
    fi
    # LAST --class occurrence wins: dr_vps_domain_create's parser is last-wins, so
    # the gate must validate the value that will actually be APPLIED -- a first-wins read here plus a
    # duplicated --class would admit a "service"-gated restore that lands as throwaway.
    local _class=""; local _i
    for (( _i=0; _i<${#passthru[@]}; _i++ )); do
      [ "${passthru[$_i]}" = "--class" ] && _class="${passthru[$((_i+1))]:-}"
    done
    if [ "$_class" != service ]; then
      exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_SECRET" "secret-bearing restore is allowed ONLY for --class service (got '${_class:-<none>}'); a throwaway restore is refused."; return $?
    fi
    # FAIL CLOSED: a failed or garbled refcount read must REFUSE, never count as
    # zero -- an empty result from a DB error would otherwise admit a second live identity.
    local _live _lrc; _live=$(dr_vps_sql "SELECT COUNT(*) FROM vms WHERE artifact_id=$(dr_vps_sql_str "$sid") AND owner_uid=$(dr_vps_sql_str "$own");"); _lrc=$?
    if [ "$_lrc" -ne 0 ] || [ -z "$_live" ]; then
      exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "secret-restore refcount query FAILED -- refusing (fail closed; retry when the store is healthy)."; return $?
    fi
    case "$_live" in *[!0-9]*)
      exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "secret-restore refcount query returned a non-numeric result -- refusing (fail closed)."; return $?;;
    esac
    if [ "$_live" != 0 ]; then
      exec {ulfd}>&-; dr_vps_die "$DR_VPS_E_SECRET" "secret-bearing restore is 1:1 -- you already have a VM record restored from $sid (any state counts); destroy it FIRST, then restore (a restore REPLACES, it does not clone -- two VMs off one secret base would share the machine-id / device-bound session)."; return $?
    fi
  fi
  # S1a: RE-THREAD --owner into the NEW VM. `own` scopes the SNAPSHOT lookup above; the created VM must ALSO
  # be stamped with it (else the clone would be owner-NULL = operator, and the caller could not manage it).
  local -a ownargs=(); [ -n "$own" ] && ownargs=(--owner "$own")
  dr_vps_domain_use_snapshot "$vmname" "$sid" "${passthru[@]}" "${ownargs[@]}"; local _urc=$?
  exec {ulfd}>&-
  return "$_urc"
}

# ---- snap-fsck: images(kind=snapshot) <-> snapshots <-> bundle files consistency. Read-only by default;
# `--prune` (OPERATOR-ONLY -- fsck is not in the daemon verb set) additionally REMOVES orphan bundle dirs
# (present bundle, NO snapshots row) so the operator has a concrete cleanup path for crash-orphans that a
# client is (deliberately) refused from adopting (operator recovery completeness).
dr_vps_snapshot_fsck() {  # [--prune] -> prints issues; nonzero rc if any unresolved
  local prune=0; [ "${1:-}" = --prune ] && prune=1
  local issues=0 id gp f bd bid
  # ledger bijection
  while IFS='|' read -r id; do [ -z "$id" ] && continue
    [ -n "$(dr_vps_sql "SELECT 1 FROM images WHERE artifact_id=$(dr_vps_sql_str "$id") AND kind='snapshot';")" ] \
      || { printf 'FSCK: snapshots row %s has no images(kind=snapshot) ledger row\n' "$id"; issues=$((issues+1)); }
    gp=$(dr_vps_store_snapshot_golden_path "$id")
    [ "$gp" = "${DR_VPS_SNAP_DIR}/${id}/image.qcow2" ] || { printf 'FSCK: %s golden_path off-canon: %s\n' "$id" "$gp"; issues=$((issues+1)); }
    for f in image.qcow2 provenance.json snapshot.md; do
      [ -f "${DR_VPS_SNAP_DIR}/${id}/${f}" ] || { printf 'FSCK: %s missing bundle file %s\n' "$id" "$f"; issues=$((issues+1)); }
    done
  done < <(dr_vps_sql "SELECT id FROM snapshots;")
  # images(kind=snapshot) without a snapshots row
  while IFS='|' read -r id; do [ -z "$id" ] && continue
    [ -n "$(dr_vps_sql "SELECT 1 FROM snapshots WHERE id=$(dr_vps_sql_str "$id");")" ] \
      || { printf 'FSCK: images(kind=snapshot) %s has no snapshots row\n' "$id"; issues=$((issues+1)); }
  done < <(dr_vps_sql "SELECT artifact_id FROM images WHERE kind='snapshot';")
  # ORPHAN bundle DIRS: a <SNAP_DIR>/drvps-snap-v1-*/ with NO snapshots row -- a crash between the create
  # rename and the DB register, or a snap-rm whose bundle-delete failed. Read-only report.
  local row rc praw pfd
  for bd in "$DR_VPS_SNAP_DIR"/drvps-snap-v1-*/; do
    [ -d "$bd" ] || continue
    bid=$(/usr/bin/basename -- "$bd")
    # FAIL CLOSED on a DB read error : an EMPTY result must mean "no row", NOT "the read
    # errored" -- otherwise a transient SQLite lock/error would misclassify a REGISTERED bundle as an orphan
    # and --prune would rm -rf a live snapshot's bundle. Capture rc; on any nonzero read, report + skip.
    row=$(dr_vps_sql "SELECT 1 FROM snapshots WHERE id=$(dr_vps_sql_str "$bid");"); rc=$?
    if [ "$rc" -ne 0 ]; then
      printf 'FSCK: db read error classifying %s -- skipping (fail-closed, never prune on an unknown row state)\n' "$bd"; issues=$((issues+1)); continue
    fi
    [ -n "$row" ] && continue                              # registered -> not an orphan
    if [ "$prune" -eq 0 ]; then
      printf 'FSCK: ORPHAN bundle dir (no snapshots row -- crash-after-rename or failed snap-rm): %s\n' "$bd"; issues=$((issues+1)); continue
    fi
    # --prune: remove the orphan under its per-content lock (never race a concurrent create-adopt of the same
    # content), fenced, and NEVER following a symlink (rm -rf on a symlink target would escape the fence).
    praw="${DR_VPS_SNAP_DIR}/${bid}"; pfd=""
    if [ -L "$praw" ]; then
      printf 'FSCK: orphan is a SYMLINK -- refusing to prune (left in place): %s\n' "$bd"; issues=$((issues+1)); continue
    fi
    mkdir -p "${DR_VPS_STATE_DIR}/locks"
    exec {pfd}>"${DR_VPS_STATE_DIR}/locks/snap-${bid}.lock" || pfd=""
    # Inside-lock re-check, ALSO rc-checked: prune ONLY on a SUCCESSFUL read that returns NO row (never on an
    # errored read). Any lock/fence/read/rm failure leaves the bundle in place.
    row=""; rc=1
    if [ -n "$pfd" ] && "$DR_FLOCK" -n "$pfd" \
       && dr_vps_storage_path_fence "$praw" "$DR_VPS_SNAP_DIR" >/dev/null 2>&1; then
      row=$(dr_vps_sql "SELECT 1 FROM snapshots WHERE id=$(dr_vps_sql_str "$bid");"); rc=$?
    fi
    if [ "$rc" -eq 0 ] && [ -z "$row" ] && rm -rf -- "$praw" 2>/dev/null; then
      printf 'FSCK: PRUNED orphan bundle dir: %s\n' "$bd"
    else
      printf 'FSCK: could NOT prune orphan (busy/fence/db-error/rm failure -- left in place): %s\n' "$bd"; issues=$((issues+1))
    fi
    [ -n "$pfd" ] && exec {pfd}>&-
  done
  [ "$issues" -eq 0 ] && { printf 'FSCK: OK (snapshots consistent)\n'; return 0; }
  printf 'FSCK: %d issue(s)\n' "$issues"; return 1
}
