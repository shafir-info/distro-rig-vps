#!/usr/bin/env bash
# dr_vps_reaper.sh -- Phase-2 TTL reaper. Destroys VMs past their stored TTL, but GATES each id
# first (a stale/corrupt row must not let `destroy` hit an unrelated libvirt domain). Runs as
# drvps under the SAME work-lock as the watcher (taken by bin/drvps-rigreaper), so it interleaves
# between watcher ops -- no race. ASCII only. See CONCEPT.md (agent control loop).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_gate.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_gate.sh"
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_domain.sh"
# The reaper sweep calls dr_vps_jobs_reap (the async-job TTL/promotion backstop), which lives
# in remote.sh. Without this source the `declare -F` guard silently skips it -> un-polled jobs never terminalize
# in the INSTALLED reaper (only exec-status polling would). Source it here so the daemon + tests both get it.
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_remote.sh"

_dr_vps_reap_audit() {  # <id> <verdict>
  local log="${DR_VPS_SPOOL_DIR}/audit.log"
  [ -d "$(dirname "$log")" ] || return 0
  printf '{"reaper":"%s","id":"%s","at":"%s"}\n' "$2" "$1" "$(date -u +%FT%TZ)" >>"$log" 2>/dev/null || true
}

# Stage-1 console-log bound: tail-compact every log-bearing VM's console log to FILE_CAP (keeps the log
# drvps-readable; virtlogd MAX_SIZE is the emergency synchronous fail-safe). Refreshes the FULL-sweep heartbeat
# `<STATE>/console-reaper.last` ONLY if EVERY log was compacted-or-under-cap with NO refusal/error (a symlink/
# owner/nlink refusal, a store-read error, or any per-log error does NOT refresh it -> doctor flags staleness).
# Never unlinks/renames a live log (compaction is in-place via a no-follow fd). Runs under the reaper work-lock.
_dr_vps_console_reap() {
  local cap="${DR_VPS_CONSOLE_FILE_CAP:-524288}" clean=1 id _ f vms
  local py; py="$(dirname "${BASH_SOURCE[0]}")/drvps_common.py"
  local stamp="${DR_VPS_STATE_DIR}/console-reaper.last"
  # FILE_CAP is the enforcement input -- validate it locally (strict base-10 positive) before shelling out.
  case "$cap" in ''|0|*[!0-9]*|0?*) clean=0; cap= ;; esac
  if ! vms=$(dr_vps_store_vm_ls 2>/dev/null); then clean=0; vms=; fi     # store read failed -> NOT clean (set -e safe)
  if [ -n "$vms" ] && [ -n "$cap" ]; then
    while read -r id _; do                                  # default IFS -> id = first field (the vm id)
      [ -n "$id" ] || continue
      # a CORRUPT store row must not escape the console dir: SAFE-ID + PATH-FENCE before building/using the path.
      _dr_vps_safe_id "$id" >/dev/null 2>&1 || { clean=0; _dr_vps_reap_audit "$id" console-unsafe-id; continue; }
      f=$(dr_vps_console_log_path "$id") || { clean=0; continue; }
      dr_vps_storage_path_fence "$f" "$DR_VPS_CONSOLE_LOG_DIR" >/dev/null 2>&1 \
        || { clean=0; _dr_vps_reap_audit "$id" console-path-fence; continue; }
      [ ! -L "$f" ] || { clean=0; _dr_vps_reap_audit "$id" console-symlink; continue; }   # symlink (incl DANGLING) = tamper
      [ -e "$f" ] || continue                                # no log yet (pre-boot / pre-change VM) -> skip
      python3 "$py" console-compact "$f" "$cap" >/dev/null 2>&1 \
        || { clean=0; _dr_vps_reap_audit "$id" console-compact-refused; }
    done <<< "$vms"
  fi
  if [ "$clean" -eq 1 ]; then                                # FULL clean sweep -> refresh heartbeat (atomic)
    local t="${stamp}.$$"
    { printf '%s\n' "$(date -u +%FT%TZ)" >"$t" && mv -f "$t" "$stamp"; } 2>/dev/null || rm -f "$t" 2>/dev/null || true
  else
    rm -f "$stamp" 2>/dev/null || true                       # DIRTY sweep -> INVALIDATE the stamp: doctor fails closed NOW
  fi
}

# Egress-splice request maintenance (egress-splice task 1.6): under the egress global lock, EXPIRE
# un-approved past-TTL requests (self-attributing `expired` terminal so the member learns it via
# `rigctl egress status`), suppress expiry on leased/under-review reqids (surfacing malformed/stale root
# claims as faults), clear decided pending, and retention-GC old expiry terminals. Runs only if the egress
# store exists (feature in use). Bounded by
# DR_VPS_EGRESS_TTL_MIN (request TTL) + DR_VPS_EGRESS_RETENTION_MIN (terminal retention; MUST exceed TTL --
# the member module GCs only when retention > ttl). Failure is non-fatal to the rest of the sweep.
_dr_vps_egress_reap() {
  local base="${DR_VPS_EGRESS_BASE:-/var/lib/distro-rig-vps-egress}"   # v2 FIXED root-owned anchor (= L.ANCHOR)
  [ -e "$base" ] || return 0
  local py; py="$(dirname "${BASH_SOURCE[0]}")/../tools/drvps_egress_member.py"
  [ -f "$py" ] || return 0
  local ttl=$(( ${DR_VPS_EGRESS_TTL_MIN:-4320} * 60 )) ret=$(( ${DR_VPS_EGRESS_RETENTION_MIN:-10080} * 60 ))
  # SURFACE root-zone faults: do NOT /dev/null the output. A non-empty lease_faults
  # (a malformed/wrongly-owned root claim) or a damaged store (status=error) is logged to the journal for the
  # operator; a clean sweep is silent. Failure stays non-fatal to the rest of the reaper.
  local out rc
  out="$(python3 "$py" expire --base "$base" --ttl "$ttl" --now "$(date +%s)" --retention "$ret" 2>&1)"; rc=$?
  # Detect a root-zone fault WITHOUT depending on jq (grep is always present): a non-empty "lease_faults"
  # array or a non-ok status. A clean sweep is silent; a fault is logged to the journal for the operator.
  if [ "$rc" -ne 0 ] \
     || printf '%s' "$out" | grep -qE '"lease_faults": ?\[[^]]' \
     || printf '%s' "$out" | grep -qE '"status": ?"(error|abort)"'; then
    logger -t drvps-egress "egress reaper fault (rc=$rc): ${out:0:400}" 2>/dev/null \
      || echo "drvps-egress reaper fault (rc=$rc): ${out:0:400}" >&2
  fi
}

# One sweep: destroy every expired VM, gate-checked. Idempotent + safe to interleave.
dr_vps_reaper_sweep() {
  local id expired
  # Egress-splice maintenance runs FIRST + is independent of the VM store, so a VM-DB read error (early
  # return below) never starves egress expiry/GC/claim-recovery.
  _dr_vps_egress_reap
  # M22: 'broken' VMs ARE reaped when expired (else their overlay + defined domain leak forever);
  # the gate still guards each id, so a stale row whose live domain mismatches is refused, not destroyed.
  # Distinguish a DB read ERROR from an empty result: `|| return 0` would silently no-op the TTL
  # sweep forever on a broken store (expired VMs leak with zero signal). Audit the error instead.
  if ! expired=$(dr_vps_sql "SELECT id FROM vms
    WHERE ttl_hours>0
      AND state != 'destroyed'                          -- forward-compat filter: no code sets 'destroyed'
                                                         -- today (destroy drops the row); kept for a future soft-delete
      AND class != 'service'                            -- S1b: service-class VMs are NEVER auto-reaped (owner/
                                                         -- operator destroy only). class is NOT NULL DEFAULT
                                                         -- 'throwaway' (S0), so this compare never drops a NULL row.
      AND datetime(created_at,'+'||ttl_hours||' hours') < datetime('now');"); then
    _dr_vps_reap_audit "-" reap-db-error
    return 1
  fi
  for id in $expired; do
    if dr_vps_gate_vm lifecycle "$id" >/dev/null 2>&1; then
      if dr_vps_domain_destroy "$id" >/dev/null 2>&1; then
        _dr_vps_reap_audit "$id" reaped
      else
        _dr_vps_reap_audit "$id" reap-failed
      fi
    else
      # The gate refused. Route to no-domain cleanup ONLY if the domain is PROVABLY absent (e.g. a
      # broken recreate that undefined). A libvirt OUTAGE returns INDETERMINATE -> NOT absent -> never
      # deletes. A LIVE mismatched domain stays refused too.
      local _pr; _dr_vps_domain_presence "$id" && _pr=0 || _pr=$?
      if [ "$_pr" -eq 1 ]; then
        if dr_vps_domain_destroy "$id" >/dev/null 2>&1; then
          _dr_vps_reap_audit "$id" reaped-no-domain
        else
          _dr_vps_reap_audit "$id" reap-failed
        fi
      else
        _dr_vps_reap_audit "$id" reap-refused-gate    # LIVE+mismatch OR libvirt-indeterminate -- never destroy
      fi
    fi
  done
  # M21: GC old result + claimed markers -- the agent (results group-read-only) can't prune them,
  # so the spool would grow unbounded on the Restart=always loop. Runs under the reaper work-lock.
  # NOTE (intentional bound): the `.claimed` marker is also the at-most-once REPLAY tombstone, so
  # replay protection is bounded by this retention (DR_VPS_RESULT_TTL_MIN / DR_VPS_RESULT_MAX_FILES) --
  # after eviction a resubmitted old reqid can re-run. Accepted by design: (1) the at-most-once guard
  # exists to stop ACCIDENTAL duplication (client retry / watcher crash mid-op), which the 24h window
  # covers; (2) under the SINGLE-AGENT trust model the agent can already re-run any verb with a FRESH
  # reqid, so replay-after-eviction grants nothing new; (3) keeping tombstones forever is the very
  # unbounded-growth this GC exists to prevent. A durable seen_reqids ledger is the fix IF a stronger
  # guarantee is ever needed (see README known-limitations); not warranted for the single-agent rig.
  local rdir="${DR_VPS_SPOOL_DIR:-/var/spool/distro-rig-vps}/results"
  if [ -d "$rdir" ]; then
    find "$rdir" -maxdepth 1 -type f \( -name '*.json' -o -name '*.claimed' \) \
      -mmin "+${DR_VPS_RESULT_TTL_MIN:-1440}" -delete 2>/dev/null || true
    # Also a COUNT cap (not just the 24h TTL): a high request throughput could accumulate millions of
    # result files within the TTL window. Delete the OLDEST beyond DR_VPS_RESULT_MAX_FILES.
    local cap="${DR_VPS_RESULT_MAX_FILES:-20000}" n
    n=$(find "$rdir" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l)
    if [ "$n" -gt "$cap" ]; then
      # Delete the OLDEST results beyond the cap AS PAIRS -- each pruned <reqid>.json together with its
      # <reqid>.claimed sibling. Pruning the .json alone would leave a "claimed but no result" orphan
      # that (a) lets a resubmitted reqid REPLAY its verb (the watcher's replay guard treats a lone
      # .claimed as already-done) and (b) lets .claimed markers accumulate past the cap unbounded.
      find "$rdir" -maxdepth 1 -type f -name '*.json' -printf '%T@ %p\0' 2>/dev/null \
        | sort -zn | head -zn "$(( n - cap ))" | sed -z 's/^[^ ]* //' \
        | while IFS= read -r -d '' f; do rm -f "$f" "${f%.json}.claimed"; done 2>/dev/null || true
    fi
  fi
  # S4: GC the idempotency-key journal (spool/idem/<owner_uid>/<key>.json, drvps-private). TTL-only
  # eviction (after eviction a resubmitted old key re-EXECUTES instead of replaying -- accepted; the
  # 24h window covers the accidental-duplication cases idem exists for). An in-progress entry older
  # than the TTL is a crash artifact; evicting it un-poisons the key. Emptied per-owner dirs are pruned.
  # Runs under the same work-lock as the watcher, so a sweep never races an in-flight journal write.
  # There is DELIBERATELY no global count-cap here -- a rig-wide count cap sorts all
  # owners together and would let one owner's key churn EVICT ANOTHER owner's (possibly in-progress)
  # protection (cross-owner re-execution), and a head-before-filter cap may never converge. Growth is
  # bounded instead by the per-owner WRITE quota (DR_VPS_IDEM_OWNER_MAX, admission-refused watcher-side
  # in idem_begin) plus this TTL -- total <= (#owners x owner-quota), all expiring within the TTL.
  local idir="${DR_VPS_SPOOL_DIR:-/var/spool/distro-rig-vps}/idem"
  if [ -d "$idir" ]; then
    # TTL sweep covers hidden '.<key>.XXXXXX' mkstemp temps too (belt-and-suspenders: the watcher
    # unlinks them on failure, but a SIGKILL mid-write can still strand one and nothing else looks here).
    find "$idir" -mindepth 2 -maxdepth 2 -type f \( -name '*.json' -o -name '.*' \) \
      -mmin "+${DR_VPS_IDEM_TTL_MIN:-1440}" -delete 2>/dev/null || true
    find "$idir" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null || true
  fi
  # Reap ORPHANED build/digest temps in DR_VPS_TMP_DIR. golden.XXXXXX.raw (per
  # create/recreate digest) and bake.XXXXXX.log (per build) are removed straight-line on the happy
  # path, but an operator interrupt or the watcher's SIGKILL (no trap can run) leaves GB-scale
  # orphans that nothing else sweeps -> the state fs fills and doctor then refuses all creates. Age-
  # gate so a temp for an IN-FLIGHT convert (minutes) is never pulled from under it.
  local tdir="${DR_VPS_TMP_DIR:-/var/lib/distro-rig-vps/tmp}"
  if [ -d "$tdir" ]; then
    # + snapval.*.qcow2 = SNAPSHOT validation-boot disposable overlays (age-gated so an in-flight one -- which
    # lives only seconds -- is never pulled; a leaked one from a destroy-failed validation is reaped).
    find "$tdir" -maxdepth 1 -type f \( -name 'golden.*.raw' -o -name 'bake.*.log' -o -name 'snapval.*.qcow2' \) \
      -mmin "+${DR_VPS_TMP_TTL_MIN:-120}" -delete 2>/dev/null || true
  fi
  # SNAPSHOT temp BUNDLES (.snap.* dirs under DR_VPS_SNAP_DIR) from a SIGKILL'd snapshot op: no other sweep
  # covers SNAP_DIR (snapshot create self-heals only opportunistically). Age-gate; NEVER a final drvps-snap-v1-*
  # bundle.
  local sdir="${DR_VPS_SNAP_DIR:-${DR_VPS_STATE_DIR:-/var/lib/distro-rig-vps}/snapshots}"
  if [ -d "$sdir" ]; then
    # A LIVE flatten continuously WRITES image.qcow2 (the temp DIR mtime freezes at mktemp -- writing a file
    # inside does not bump it). Reap a .snap.* temp bundle only if its NEWEST entry (dir OR any file) is older
    # than the age, i.e. nothing is being written -> never pull a slow >age flatten out from under qemu-img

    local _d _age="${DR_VPS_TMP_TTL_MIN:-120}"
    for _d in "$sdir"/.snap.*/; do
      [ -d "$_d" ] || continue
      [ -n "$(find "$_d" -mmin "-${_age}" -print -quit 2>/dev/null)" ] || rm -rf "$_d" 2>/dev/null || true
    done
  fi
  # Fix 1: orphan ssh control SOCKETS (crash-stragglers only -- dr_vps_domain_destroy closes them on every normal
  # reap/destroy). Reap a socket ONLY if its master is DEAD (-O check fails) AND it is older than ControlPersist +
  # grace, so a live/busy VM (master answers) or a just-started master is never pulled. OFF-guarded.
  if [ "${DR_VPS_SSH_MUX:-0}" = 1 ] && [ -d "${DR_VPS_CTRL_DIR:-}" ]; then
    local _s _grace=$(( ${DR_VPS_SSH_MUX_PERSIST:-300} / 60 + 2 ))   # minutes
    for _s in "${DR_VPS_CTRL_DIR}"/*.sock; do
      [ -S "$_s" ] || continue
      [ -n "$(find "$_s" -mmin "-${_grace}" -print -quit 2>/dev/null)" ] && continue                 # too young -> keep
      "$DR_TIMEOUT" 3 "$DR_SSH" -O check -o "ControlPath=$_s" -- drvps-mux >/dev/null 2>&1 && continue # live master -> keep
      rm -f "$_s" 2>/dev/null || true
    done
  fi
  # Purge TERMINAL async-job dirs older than the TTL so the job table can't grow unbounded.
  if declare -F dr_vps_jobs_reap >/dev/null 2>&1; then dr_vps_jobs_reap || true; fi
  # Observability (Step 9): reap ORPHANED console logs (no store row + no live domain) -- bounded, fail-closed.
  if declare -F dr_vps_console_log_gc >/dev/null 2>&1; then dr_vps_console_log_gc || true; fi
  # DIAG (SPEC-DIAG): size-rotate the debug diag file to .1 so a long DR_VPS_DIAG session cannot fill disk.
  # Gated on the FILE (existence+size), NOT on DR_VPS_DIAG: the flag may be set only in the WATCHER's env
  # (which grows the file) while the reaper's env lacks it -- a flag-gated rotation would then never bound a
  # growing diag. Consequence (accepted): with the flag OFF the common case is
  # ZERO mutation (the file does not exist), but a leftover OVERSIZE diag from a PRIOR session may still be
  # tidied once (a harmless mv). "Default-off = no logging"; the reaper may clean up a pre-existing debug log.
  { [ -f "${DR_VPS_DIAG_FILE:-}" ] && [ "$(stat -c '%s' "${DR_VPS_DIAG_FILE}" 2>/dev/null || echo 0)" -gt "${DR_VPS_DIAG_MAX_BYTES:-16777216}" ]; } \
    && mv -f "${DR_VPS_DIAG_FILE}" "${DR_VPS_DIAG_FILE}.1" 2>/dev/null || true
  # Stage-1: bound every VM's console log (tail-compact to FILE_CAP) + refresh the full-sweep heartbeat.
  _dr_vps_console_reap
}
