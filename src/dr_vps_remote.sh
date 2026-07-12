#!/usr/bin/env bash
# dr_vps_remote.sh -- Phase-2 guest-only verbs (exec/push/pull/console-dump). Every verb GATES
# first (dr_vps_gate_vm), resolves the guest IP from LIBVIRT (never the agent), and builds the
# ssh/scp argv with `--` BEFORE the destination so a '-'-leading value can never become a local
# option. The guest command is confined to the disposable VM. ASCII only; set -uo pipefail safe.
# See CONCEPT.md (agent control loop).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_gate.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_gate.sh"

# POSIX-safe single-quote for a value that will be parsed by the GUEST shell: the guest's
# /bin/sh may be dash/busybox-ash (Debian/Alpine -- both supported families), which do NOT understand
# bash's `$'...'` ANSI-C quoting that `printf '%q'` emits for newlines/specials. Single-quoting (with
# each embedded ' rendered as '\'') is universally POSIX-portable, so any guest shell parses the exact
# path. Runs on the HOST bash; the OUTPUT is what crosses to the guest.
_dr_vps_shq() { local s=${1//\'/\'\\\'\'}; printf "'%s'" "$s"; }

# Resolve the guest IPv4 from libvirt (TRUSTED -- the agent never supplies an IP).
_dr_vps_guest_ip() {  # <id>
  "$DR_VIRSH" -c "$DR_LIBVIRT_URI" domifaddr "$1" 2>/dev/null \
    | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1
}

# --- SSH connection multiplexing (Fix 1; GATED by DR_VPS_SSH_MUX, default 0=OFF) --------------------------------
# Pool ONE ssh master per live VM to erase the measured ~2.76s/exec connect+auth+teardown tax. The socket is named
# <id_hash>.<dst_hash>.sock so destroy/reaper can glob <id_hash>.* WITHOUT the (by-then-gone) IP. Every helper is a
# strict NO-OP when the knob is off (returns before any dir/socket/argv side effect), so the OFF path is EXACTLY the
# prior behaviour. Opts are appended to a caller argv ARRAY (never word-split command substitution).
_dr_vps_mux_sock() {  # <id> <ip> -> control socket path (empty if OFF)
  [ "${DR_VPS_SSH_MUX:-0}" = 1 ] || return 0
  local ih dh
  ih=$(printf '%s' "$1" | sha1sum | cut -c1-12)
  dh=$(printf 'root@%s' "$2" | sha1sum | cut -c1-12)
  printf '%s/%s.%s.sock' "${DR_VPS_CTRL_DIR}" "$ih" "$dh"
}
# Drop a STALE socket before use: a dead master fails `-O check`; but keep a just-created one (mtime grace) so we
# do not race a master mid-startup. All output redirected -- never leaks into caller stdout/stderr.
_dr_vps_mux_precheck() {  # <id> <ip> <sock>
  [ "${DR_VPS_SSH_MUX:-0}" = 1 ] || return 0
  local sock="$3"
  [ -n "$sock" ] && [ -S "$sock" ] || return 0
  if ! "$DR_TIMEOUT" 3 "$DR_SSH" -O check -o "ControlPath=$sock" -- "root@$2" >/dev/null 2>&1; then
    local age; age=$(( $(date +%s) - $(stat -c %Y "$sock" 2>/dev/null || echo 0) ))
    [ "$age" -ge 2 ] && rm -f "$sock" 2>/dev/null
  fi
  return 0
}
# Fill a caller ARRAY (by name) with the mux ssh/scp opts; establishes the 0700 ctrl dir on first ON use.
_dr_vps_mux_setup() {  # <arrayname> <id> <ip>
  [ "${DR_VPS_SSH_MUX:-0}" = 1 ] || return 0
  local -n _mo="$1"; local _sock; _sock=$(_dr_vps_mux_sock "$2" "$3")
  [ -n "$_sock" ] || return 0
  [ "${#_sock}" -lt 104 ] || return 0                                  # ControlPath > unix-socket limit -> fall back to NO mux (safer than failing exec)
  install -d -m 0700 -- "${DR_VPS_CTRL_DIR}" 2>/dev/null || return 0   # idempotent: create the dir if absent
  { [ -d "${DR_VPS_CTRL_DIR}" ] && [ ! -L "${DR_VPS_CTRL_DIR}" ]; } || return 0   # never a symlink
  chmod 0700 -- "${DR_VPS_CTRL_DIR}" 2>/dev/null || return 0           # ENFORCE 0700 even on a pre-existing looser dir
  _dr_vps_mux_precheck "$2" "$3" "$_sock"
  _mo=(-o ControlMaster=auto -o "ControlPersist=${DR_VPS_SSH_MUX_PERSIST:-300}" -o "ControlPath=$_sock")
}
# rc-255 safety (v1, NO retry): ssh returns the REMOTE command's exit -- a guest cmd can legitimately exit 255,
# indistinguishable from a transport failure without perturbing stdout/stderr. So on 255 we merely DROP a possibly
# broken master (next call re-establishes cleanly) and return 255 UNCHANGED. No retry.
_dr_vps_mux_on_rc() {  # <id> <ip> <rc>
  [ "${DR_VPS_SSH_MUX:-0}" = 1 ] || return 0
  [ "$3" = 255 ] || return 0
  local sock; sock=$(_dr_vps_mux_sock "$1" "$2")
  [ -n "$sock" ] && rm -f "$sock" 2>/dev/null
  return 0
}
# Close the master + remove ALL sockets for this VM by id-prefix glob (IP not required -- safe at destroy/reap time).
dr_vps_mux_close() {  # <id>
  [ "${DR_VPS_SSH_MUX:-0}" = 1 ] || return 0
  local ih; ih=$(printf '%s' "$1" | sha1sum | cut -c1-12)
  local s
  for s in "${DR_VPS_CTRL_DIR}/$ih."*.sock; do
    [ -e "$s" ] || continue                                                                    # unmatched glob -> skip
    [ -S "$s" ] && "$DR_TIMEOUT" 3 "$DR_SSH" -O exit -o "ControlPath=$s" -- drvps-mux >/dev/null 2>&1 || true
    rm -f "$s" 2>/dev/null || true                                                             # socket OR stale leftover at our id-prefix path
  done
  return 0
}

# Safe ssh into the guest: GATE (guestexec) -> libvirt IP -> `--` before the destination.
# M13: export the cache proxy in the remote shell BEFORE the command, so package managers that
# only read env (apk -- the exec ssh is non-interactive/no-PAM, so profile.d + /etc/environment
# are NOT applied) reach the cache through the egress fence. Harmless for dnf/apt/zypper (they use
# their own proxy config), and correct for any tool the agent runs (the guest can only reach squid).
_dr_vps_ssh() {  # <id> <timeout> [remote cmd...]
  local id="$1" t="$2"; shift 2
  dr_vps_gate_vm guestexec "$id" >/dev/null || return $?
  local ip; ip=$(_dr_vps_guest_ip "$id")
  [ -n "$ip" ] || { dr_vps_die "$DR_VPS_E_LIBVIRT" "no guest IP for $id"; return $?; }
  local p pq; p="${DR_VPS_GUEST_PROXY%/}"   # normalize: strip trailing slash (consistent with seed proxy plumbing)
  pq=$(_dr_vps_shq "$p")                     # shell-quote for the GUEST shell (a weird/hostile proxy config must not inject)
  local penv="export http_proxy=$pq https_proxy=$pq HTTP_PROXY=$pq HTTPS_PROXY=$pq;"
  local -a mux=(); _dr_vps_mux_setup mux "$id" "$ip"   # empty (no argv delta) unless DR_VPS_SSH_MUX=1
  "$DR_TIMEOUT" "$t" "$DR_SSH" -o BatchMode=yes -o IdentitiesOnly=yes "${_DR_VPS_SSH_HARDEN[@]}" \
    -o ConnectTimeout=8 "${mux[@]}" -i "$DR_VPS_SSH_KEY" -- "root@${ip}" "$penv" "$@"
  local rc=$?; _dr_vps_mux_on_rc "$id" "$ip" "$rc"; return "$rc"
}

# exec: run <cmd> INSIDE the guest. Unrestricted (safe by confinement). Output flows to the
# caller; the python watcher caps it DURING read (no unbounded slurp) -- see Stage 3.
dr_vps_exec() {  # <id> <cmd> [timeout] [--owner UID]   -- fixed positionals FIRST (an agent cmd may be "--owner"), then flags
  local id="$1" cmd="$2" owner="" t=""; if [ "$#" -ge 2 ]; then shift 2; else shift "$#"; fi
  while [ "$#" -gt 0 ]; do case "$1" in --owner) owner="${2:-}"; shift 2;; *) t="$1"; shift;; esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  { [ -n "$id" ] && [ -n "$cmd" ]; } || { dr_vps_die "$DR_VPS_E_USAGE" "exec <id> <cmd> [timeout]"; return $?; }
  dr_vps_vm_assert_owned "$id" "$owner" || return $?
  _dr_vps_ssh "$id" "${t:-$DR_VPS_EXEC_TIMEOUT}" "$cmd"
}

# pull: read a GUEST file, bounded DURING transfer -- `head -c CAP+1` runs IN THE GUEST so only
# CAP+1 bytes ever cross the wire (a huge guest file can't fill host disk). Emits the RAW bytes; the
# watcher (drvps_rigctl.py) is the caller that rejects a length of CAP+1 as over-cap and base64s the
# rest into the result's content_b64 (D7: bytes move through the channel as size-capped base64).
dr_vps_pull() {  # <id> <remote> [cap] [timeout] [--owner UID]
  local id="$1" remote="$2" owner="" cap="" t=""; if [ "$#" -ge 2 ]; then shift 2; else shift "$#"; fi
  while [ "$#" -gt 0 ]; do case "$1" in
    --owner) owner="${2:-}"; shift 2;;
    *) if [ -z "$cap" ]; then cap="$1"; else t="$1"; fi; shift;;
  esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  { [ -n "$id" ] && [ -n "$remote" ]; } || { dr_vps_die "$DR_VPS_E_USAGE" "pull <id> <remote> [cap] [timeout]"; return $?; }
  dr_vps_vm_assert_owned "$id" "$owner" || return $?
  cap="${cap:-$DR_VPS_TRANSFER_MAX_BYTES}"; t="${t:-$DR_VPS_EXEC_TIMEOUT}"
  _dr_vps_ssh "$id" "$t" "head -c $((cap + 1)) -- $(_dr_vps_shq "$remote") 2>/dev/null"
}

# push: scp a WATCHER-OWNED local temp (already size-capped at base64 decode) INTO the guest.
dr_vps_push() {  # <id> <localfile> <remote> [timeout] [--owner UID]
  local id="$1" lf="$2" remote="$3" owner="" t=""; if [ "$#" -ge 3 ]; then shift 3; else shift "$#"; fi
  while [ "$#" -gt 0 ]; do case "$1" in --owner) owner="${2:-}"; shift 2;; *) t="$1"; shift;; esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  { [ -n "$id" ] && [ -n "$lf" ] && [ -n "$remote" ]; } || { dr_vps_die "$DR_VPS_E_USAGE" "push <id> <localfile> <remote>"; return $?; }
  dr_vps_vm_assert_owned "$id" "$owner" || return $?
  t="${t:-$DR_VPS_EXEC_TIMEOUT}"
  dr_vps_gate_vm guestexec "$id" >/dev/null || return $?
  [ -f "$lf" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "push: local temp not found: $lf"; return $?; }
  local ip; ip=$(_dr_vps_guest_ip "$id")
  [ -n "$ip" ] || { dr_vps_die "$DR_VPS_E_LIBVIRT" "no guest IP for $id"; return $?; }
  local -a mux=(); _dr_vps_mux_setup mux "$id" "$ip"   # precheck + opts (empty unless DR_VPS_SSH_MUX=1)
  # NOTE: do NOT shell-quote the scp remote path -- modern OpenSSH scp uses the SFTP protocol,
  # where the remote path is a LITERAL (no remote-shell interpretation), so there is no injection to quote and
  # quoting would make the quotes part of the filename. The path is charset-bounded upstream regardless.
  "$DR_TIMEOUT" "$t" "$DR_SCP" -o BatchMode=yes -o IdentitiesOnly=yes "${_DR_VPS_SSH_HARDEN[@]}" \
    -o ConnectTimeout=8 "${mux[@]}" -i "$DR_VPS_SSH_KEY" -- "$lf" "root@${ip}:${remote}"
  local rc=$?; _dr_vps_mux_on_rc "$id" "$ip" "$rc"; return "$rc"
}

# console-dump: a BOUNDED snapshot of the PERSISTENT serial-console log (virtlogd <log file>, Observability
# Step 8). It runs no guest CODE, but it RETURNS the guest's serial output to the agent -- a guest->host DATA
# channel -- so it is GUESTEXEC-gated, not lifecycle: a tampered domain (extra NIC/host path feeding data to
# the serial console) must not be observable without the closed-shape + fresh-egress proof. Reading the
# PERSISTED log (not a live `virsh console` attach) gives the FULL boot output, survives the VM being off,
# and never races the pty. A pre-observability VM (no persistent log) returns an EXPLICIT E_NOTFOUND
# "recreate to enable" (via dr_vps_console_log_tail), never an empty-as-success.
dr_vps_console_dump() {  # <id> [bytes] [--owner UID]
  local id="$1" owner="" cap=""; if [ "$#" -ge 1 ]; then shift; else shift "$#"; fi
  while [ "$#" -gt 0 ]; do case "$1" in --owner) owner="${2:-}"; shift 2;; *) cap="$1"; shift;; esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  [ -n "$id" ] || { dr_vps_die "$DR_VPS_E_USAGE" "console-dump <id> [bytes]"; return $?; }
  cap="${cap:-$DR_VPS_CONSOLE_TAIL_MAX_BYTES}"
  # convergence r3: the cap must be a strict base-10 POSITIVE byte count. Reject '+N' (tail -c +N reads the
  # WHOLE file from byte N -- breaks the bounded-tail contract on the direct-CLI path), leading-zero octal,
  # and non-numeric; clamp above 4 MiB. (The agent path already passes a clamped console_max.)
  case "$cap" in ''|0|*[!0-9]*|0?*) dr_vps_die "$DR_VPS_E_USAGE" "console-dump: byte cap must be a positive base-10 integer: $cap"; return $?;; esac
  [ "$cap" -le 4194304 ] || cap=4194304
  dr_vps_vm_assert_owned "$id" "$owner" || return $?
  dr_vps_gate_vm guestexec "$id" >/dev/null || return $?
  # metadata-only diag (SPEC-DIAG): log the LOG SIZE + cap, NOT the content. `stat` guarded so it costs
  # nothing when DIAG is off.
  [ -z "${DR_VPS_DIAG:-}" ] || dr_vps_diag "console-dump: id=$id log_size=$(stat -c '%s' "$(dr_vps_console_log_path "$id")" 2>/dev/null || printf '?')B cap=$cap"
  dr_vps_console_log_tail "$id" "$cap"
}

# ============================================================================================
# NATIVE ASYNC / DETACHED EXEC -- one audited long-exec path replacing the per-caller
# setsid+poll workaround. Additive verbs; dr_vps_exec (bounded) is UNCHANGED. Model: a "job" is a
# guest command launched detached (own session/pgroup), output+rc captured to guest files, tracked by
# a HOST-side job dir (survives a watcher restart). Taxonomy is PRESERVED EXACTLY -- exec-status
# distinguishes guest-rc vs infra-failure vs driver-timeout vs destroyed vs missing (never collapsed).
# Converged guardrails: opaque 128-bit ids (not derived), namespace by VM domain UUID (a recreated
# VM cannot inherit a stale job), atomic rc marker (mv), terminal tombstones (poll never deletes),
# per-VM quota + age TTL, host job dir 0700.
# KNOWN LIMITATIONS (deliberate -- documented, not bugs):
#  - CONCURRENCY MODEL: the gate->act pattern (gate binds name->uuid, then SSH-by-IP/name) is SINGLE-WRITER per VM.
#    The AGENT path guarantees it (the watcher serializes every op under the global work-lock). DIRECT-CLI callers
#    are operator-disciplined single-writer; running `dr-vps recreate/destroy` concurrently with a guest op on the
#    same VM is out of contract (the launch-race re-checks bound the async window; full atomicity would need a
#    shared per-VM lifecycle/guestexec lock -- a design change, not taken here).
#  - GUEST CONTRACT: async launch requires `bash` + util-linux `setsid --fork` in the guest golden (validated on
#    fedora/debian/rocky/opensuse). A busybox-only guest (alpine minimal) FAILS CLOSED at launch (E_LIBVIRT), it
#    does not silently misbehave; a POSIX-sh portable launcher is a follow-on if alpine async is needed.
#  - TRANSPORT: dr_vps_push relies on modern OpenSSH scp (SFTP protocol: remote path is a literal, not shell-
#    interpreted). A legacy/`-O` scp would re-introduce remote-shell path interpretation; a doctor version-check is
#    a follow-on. (Guest is unrestricted root under agent exec regardless, so this is guest-side only.)
#  - WATCHER-BOUNDARY jid (r10): if the watcher SIGKILLs `dr-vps exec-detach` after the reservation but before the
#    job id reaches its stdout, the client sees a timeout without the id. The job is NOT leaked (the reaper bounds
#    it), and a mid-flight kill on the agent path almost always means the VM is being torn down (job is moot). Early
#    jid publication (before the slow guest steps) would fully close it -- a follow-on; not done to keep the "id is
#    returned only after a confirmed launch" contract.
_dr_vps_job_id() {  # 128-bit opaque hex -- NEVER derived from cmd/vm/pid/path/time
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 16
  else head -c16 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n'; fi
}
_dr_vps_job_dir() {  # <job_id> -> host job dir; charset+length fenced (path-traversal guard)
  case "${1:-}" in ''|*[!0-9a-f]*) dr_vps_die "$DR_VPS_E_USAGE" "bad job id"; return $?;; esac
  { [ "${#1}" -ge 16 ] && [ "${#1}" -le 64 ]; } || { dr_vps_die "$DR_VPS_E_USAGE" "bad job id length"; return $?; }
  printf '%s/%s' "${DR_VPS_JOBS_DIR}" "$1"
}
_dr_vps_job_terminal() {  # <jobdir> <state-line> -- FIRST WRITER WINS: unique temp + hard-link (ln is atomic and
  local dir="$1" line="$2" tmp                                  # fails if terminal already exists -> a racing writer's state loses cleanly)
  [ -f "$dir/terminal" ] && return 0
  tmp=$(mktemp "$dir/.term.XXXXXX" 2>/dev/null) || return 0
  printf '%s\n' "$line" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  ln "$tmp" "$dir/terminal" 2>/dev/null || true
  rm -f "$tmp"
}
_dr_vps_job_emit_terminal() {  # <jobdir> <state> -- record (first-writer-wins) then PRINT THE STATE THAT WON, not the attempt
  _dr_vps_job_terminal "$1" "$2"; cat "$1/terminal" 2>/dev/null || printf '%s\n' "$2"
}
_dr_vps_job_meta_get() { sed -n "s/^$2=//p" "$1/meta" 2>/dev/null | head -1; }   # <jobdir> <key>
_dr_vps_job_cur_uuid() {  # <vm> -> prints current domain uuid ('' if the VM row is gone); RETURNS 0 iff the store
  local row rc                                            # READ SUCCEEDED. rc!=0 = a store read FAILURE (transient) --
  row=$(dr_vps_store_vm_gaterow "$1"); rc=$?              # the caller must treat that as infra, NOT a 'destroyed' verdict
  [ "$rc" -eq 0 ] || return 1                             # (was `gaterow | cut`, which masked the rc)
  printf '%s' "$row" | cut -d'|' -f4
}
# SHARED "terminate a guest job + PROVE it" primitive: EVERY timeout/cleanup path routes through
# this so none re-implements (and forgets) the kill or the verify. pgid is UNTRUSTED guest data -> require an
# integer >= 2 (reject '' 0 1 and non-numeric: `kill -- -1` is the ALL-PROCESSES special case, and pgid 1 is init
# -- signalling either would nuke the guest; r7). pgid `0*` (leading zeros: 00, 01) is also rejected (r8) -- some
# `kill` parse it as 0. CONTAINMENT CONTRACT (r7 design decision): "job == the ORIGINAL process group". A payload
# that daemonizes / setsid's into a NEW session escapes this kill and returns CLEAN while a descendant lives --
# ACCEPTED here because the rig VM is DISPOSABLE (any escapee dies when the VM is destroyed) and async-exec runs
# test commands, not daemons. Full containment (guest cgroup/systemd scope) is a follow-on. COMPLETION-AWARE (r8):
# the rc marker is checked BEFORE TERM, after TERM, and after KILL -- a job that finishes DURING the kill window is
# reported DONE:<rc> (real rc preserved), never killed-and-deleted. Prints exactly: CLEAN (original pgroup PROVEN
# gone via `kill -0`, tag files removed) | RUNNING (alive after SIGKILL) | DONE:<rc> (completed) | UNKNOWN (no valid
# pgid / probe/transport failed). Caller tombstones driver-timeout ONLY on CLEAN, done+rc on DONE. `tag` MUST be
# derived from the VALIDATED job id by the caller (never untrusted meta). Optional 3rd arg = per-exec timeout secs.
_dr_vps_job_kill() {  # <vm> <tag> [timeout]
  local out prc t="${3:-}"
  # rc-FIRST (r9): a job that already COMPLETED -> DONE:<rc> even if the pgid is missing/corrupt (never lost to an
  # UNKNOWN). Only if rc is absent do we validate pgid + TERM/KILL (re-checking rc after each signal, r8).
  out=$(dr_vps_exec "$1" "if [ -f $2.rc ]; then printf 'DONE:%s' \"\$(cat $2.rc 2>/dev/null)\"; else p=\$(cat $2.pgid 2>/dev/null); case \"\$p\" in ''|0*|1|*[!0-9]*) printf UNKNOWN;; *) kill -TERM -- \"-\$p\" 2>/dev/null; sleep 0.3; if [ -f $2.rc ]; then printf 'DONE:%s' \"\$(cat $2.rc 2>/dev/null)\"; else kill -KILL -- \"-\$p\" 2>/dev/null; sleep 0.1; if [ -f $2.rc ]; then printf 'DONE:%s' \"\$(cat $2.rc 2>/dev/null)\"; elif kill -0 -- \"-\$p\" 2>/dev/null; then printf RUNNING; else rm -f $2.sh $2.out $2.err $2.rc $2.pgid 2>/dev/null; printf CLEAN; fi; fi;; esac; fi" ${t:+"$t"} 2>/dev/null); prc=$?
  [ "$prc" -eq 0 ] || { printf UNKNOWN; return 0; }
  case "$out" in CLEAN|RUNNING|DONE:*) printf '%s' "$out";; *) printf UNKNOWN;; esac
}

# exec-detach: launch <cmd> in the guest DETACHED; print an opaque job id. 3 guest round-trips (mkdir,
# push cmd, launch); subsequent status polls are single round-trips.
dr_vps_exec_detach() {  # <id> <cmd> [--owner UID] -> job_id on stdout
  local id="$1" cmd="$2" owner=""; if [ "$#" -ge 2 ]; then shift 2; else shift "$#"; fi
  while [ "$#" -gt 0 ]; do case "$1" in --owner) owner="${2:-}"; shift 2;; *) dr_vps_die "$DR_VPS_E_USAGE" "exec-detach: unknown flag: $1"; return $?;; esac; done
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "--owner must be a numeric uid"; return $?; };; esac
  [ -n "$id" ] && [ -n "$cmd" ] || { dr_vps_die "$DR_VPS_E_USAGE" "exec-detach <vm> <cmd>"; return $?; }
  dr_vps_vm_assert_owned "$id" "$owner" || return $?   # S1a: the VM must belong to the caller (job was already owner-tagged)
  local dom_uuid _drc; dom_uuid=$(_dr_vps_job_cur_uuid "$id"); _drc=$?
  [ "$_drc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "exec-detach: store read failed for $id (transient)"; return $?; }   # read-fail is infra, not NOTFOUND
  [ -n "$dom_uuid" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no domain uuid for $id (not created?)"; return $?; }
  # PREFLIGHT the guest contract BEFORE reserving: `setsid --fork` returns success once it forks,
  # so it does NOT propagate "child could not exec bash" -- a missing-bash / busybox-setsid guest would otherwise
  # become a phantom FORKED_NO_PGID job that never terminalizes. Prove bash + `setsid --fork` here -> a failure is
  # a PROVEN not-started (fail closed, no reservation), not an immortal job.
  local _pf; _pf=$(dr_vps_exec "$id" "command -v bash >/dev/null 2>&1 && setsid --fork true </dev/null >/dev/null 2>&1 && printf OK" 2>/dev/null)
  [ "$_pf" = OK ] || { dr_vps_die "$DR_VPS_E_CAP" "exec-detach: guest lacks bash + 'setsid --fork' (required for detached exec) for $id"; return $?; }
  local jid jobdir tag; jid=$(_dr_vps_job_id)
  { [ -n "$jid" ] && [ "${#jid}" -ge 16 ]; } || { dr_vps_die "$DR_VPS_E_GENERIC" "job id generation failed"; return $?; }
  jobdir=$(_dr_vps_job_dir "$jid") || return $?
  tag="/tmp/.drvps-jobs/$jid"
  install -d -m 0700 "${DR_VPS_JOBS_DIR}" 2>/dev/null || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot create jobs dir"; return $?; }
  # PER-VM LOCK around the quota COUNT + the RESERVATION (jobdir/meta) so concurrent detaches cannot all pass a
  # stale under-limit count and over-launch (check-then-act race). Short critical section; released before the
  # slow guest launch. The reservation (meta, no terminal) is what a concurrent caller counts.
  local lkf lfd; lkf="${DR_VPS_JOBS_DIR}/.lock.$(printf '%s' "$id" | sha1sum | cut -c1-16)"
  exec {lfd}>"$lkf" || { dr_vps_die "$DR_VPS_E_GENERIC" "job lock open failed"; return $?; }
  "$DR_FLOCK" "$lfd" || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "job lock failed"; return $?; }
  local live=0 d
  for d in "${DR_VPS_JOBS_DIR}"/*/; do
    [ -L "${d%/}" ] && continue
    [ -f "${d}meta" ] || continue
    [ "$(_dr_vps_job_meta_get "${d%/}" vm)" = "$id" ] && [ ! -f "${d}terminal" ] && live=$((live+1))
  done
  if [ "$live" -ge "${DR_VPS_JOB_MAX_PER_VM:-64}" ]; then exec {lfd}>&-; dr_vps_die "$DR_VPS_E_CONFLICT" "job quota reached for $id (${DR_VPS_JOB_MAX_PER_VM} live)"; return $?; fi
  install -d -m 0700 "$jobdir" 2>/dev/null || { exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "cannot create job dir $jobdir"; return $?; }
  # ATOMIC + CHECKED meta write: a partial meta (ENOSPC / crash mid-write) would leave an
  # immortal/unpollable job -> write to a temp with a CHECKED redirection, then mv into place; roll back on failure.
  if ! { printf 'vm=%s\n' "$id"; printf 'dom_uuid=%s\n' "$dom_uuid"; printf 'tag=%s\n' "$tag"; printf 'start=%s\n' "$(date +%s)"; printf 'owner=%s\n' "$owner"; } > "$jobdir/.meta.tmp" 2>/dev/null || ! mv -f "$jobdir/.meta.tmp" "$jobdir/meta" 2>/dev/null; then
    rm -rf -- "$jobdir"; exec {lfd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "exec-detach: reservation write failed for $id"; return $?
  fi
  exec {lfd}>&-   # reservation committed -> release; a failed launch below rolls it back (rm -rf jobdir)
  # 1. guest setup dir; 2. push the cmd as a FILE (never interpolated into the launch string); 3. launch.
  dr_vps_exec "$id" "mkdir -p -m 0700 /tmp/.drvps-jobs" >/dev/null 2>&1 \
    || { rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_LIBVIRT" "exec-detach: guest setup failed for $id"; return $?; }
  local htmp; htmp=$(mktemp "${DR_VPS_TMP_DIR:-/tmp}/drvpsjob.XXXXXX") || { rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_GENERIC" "mktemp failed"; return $?; }
  printf '%s\n' "$cmd" > "$htmp" || { rm -f "$htmp"; rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_GENERIC" "exec-detach: staging command failed for $id (ENOSPC?)"; return $?; }   # r10: unchecked write could push a TRUNCATED script
  dr_vps_push "$id" "$htmp" "${tag}.sh" >/dev/null 2>&1 || { rm -f "$htmp"; rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_LIBVIRT" "exec-detach: push cmd failed for $id"; return $?; }
  rm -f "$htmp"
  # setsid --fork => the bash -c is a session/group LEADER (its $$ == pgid, recorded for a best-effort kill);
  # \$\$/\$? stay LITERAL for the guest shell; the tag is host-expanded. rc written atomically (mv). `&& echo
  # LAUNCHED` so a setsid failure is NOT reported as launched (false-positive guard).
  # PRE-LAUNCH re-check: catch a raced direct-CLI recreate/destroy BEFORE starting the guest
  # command, so we never orphan a process. Split the taxonomy (r5): a store-read FAILURE is infra (nothing
  # launched), NOT a CONFLICT; only a proven uuid MISMATCH is CONFLICT.
  local _cu _crc
  _cu=$(_dr_vps_job_cur_uuid "$id"); _crc=$?
  [ "$_crc" -eq 0 ] || { rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_GENERIC" "exec-detach: store read failed before launch for $id (transient)"; return $?; }
  [ "$_cu" = "$dom_uuid" ] || { rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_CONFLICT" "exec-detach: $id changed identity before launch (raced a lifecycle op)"; return $?; }
  # LAUNCH: the detached child writes its pgid ATOMICALLY first; the launcher WAITS for that tag before echoing
  # LAUNCHED so cleanup can always rely on a real pgid -- closes the LAUNCHED-before-pgid race.
  # pgid publication is a HARD PRECONDITION: `&& ... || exit 125` -> the payload does NOT run
  # unless the pgid tag was written, so a pgid-publish failure can never leave a running-but-unkillable payload.
  # The launcher reports NOFORK (setsid itself failed -> nothing started, safe to delete) vs LAUNCHED (pgid
  # appeared) vs FORKED_NO_PGID (forked but pgid never showed -> the child MAY be running, must NOT delete blindly).
  local launch="setsid --fork bash -c 'echo \$\$ > ${tag}.pgid.tmp && mv -f ${tag}.pgid.tmp ${tag}.pgid && [ -f ${tag}.pgid ] || exit 125; bash ${tag}.sh > ${tag}.out 2>${tag}.err; echo \$? > ${tag}.rc.tmp; mv -f ${tag}.rc.tmp ${tag}.rc' </dev/null >/dev/null 2>&1; _s=\$?; [ \$_s -eq 0 ] || { echo NOFORK; exit 0; }; _i=0; while [ \$_i -lt 20 ]; do [ -f ${tag}.pgid ] && break; _i=\$((_i+1)); sleep 0.1; done; [ -f ${tag}.pgid ] && echo LAUNCHED || echo FORKED_NO_PGID"
  local lout; lout=$(dr_vps_exec "$id" "$launch" 2>/dev/null)
  case "$lout" in
    *LAUNCHED*) ;;
    *NOFORK*) # setsid itself failed -> nothing started -> safe to delete (PROVEN not-started).
      rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_LIBVIRT" "exec-detach: setsid fork failed for $id (nothing started)"; return $? ;;
    *) # FORKED_NO_PGID / transport failure / ambiguous: the child MAY be running. Do NOT delete blindly -- run the
       # completion-aware kill-verify; delete ONLY on a PROVEN CLEAN. DONE/RUNNING/UNKNOWN -> keep the job observable
       # so exec-status + the reaper resolve it (never orphan an untracked process).
       if [ "$(_dr_vps_job_kill "$id" "$tag")" = CLEAN ]; then
         rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_LIBVIRT" "exec-detach: launch unconfirmed for $id (guest job proven cleaned up)"; return $?
       fi
       printf '%s\n' "$jid"; return 0 ;;
  esac
  # POST-LAUNCH re-check (fork-stopper): the command has STARTED. INVARIANT -- once LAUNCHED,
  # either RETURN an observable job id OR PROVE the guest process was cleaned up. On a proven uuid MISMATCH: kill
  # the pgroup (TERM -> KILL) and VERIFY the group is gone (kill -0); only THEN delete the reservation. If cleanup
  # cannot be PROVEN (still running / probe failed / store read failed), KEEP the job observable (return its id) --
  # exec-status + the reaper resolve it; never leave an untracked running process with no host record.
  _cu=$(_dr_vps_job_cur_uuid "$id"); _crc=$?
  if [ "$_crc" -eq 0 ] && [ "$_cu" != "$dom_uuid" ]; then
    if [ "$(_dr_vps_job_kill "$id" "$tag")" = CLEAN ]; then   # shared kill+verify primitive
      rm -rf -- "$jobdir"; dr_vps_die "$DR_VPS_E_CONFLICT" "exec-detach: $id changed identity during launch (raced a lifecycle op; guest job PROVEN cleaned up)"; return $?
    fi
    # cleanup NOT proven (RUNNING/UNKNOWN) -> fall through: keep the job observable; exec-status/reaper report it destroyed.
  fi
  printf '%s\n' "$jid"
}

# exec-status: PRESERVE THE TAXONOMY. missing | destroyed | driver-timeout | infra-failed | running | done+rc.
dr_vps_exec_status() {  # <job_id>
  local jid="$1" owner=""; shift || true
  while [ "$#" -gt 0 ]; do case "$1" in --owner) owner="${2:-}"; shift 2;; *) shift;; esac; done
  local jobdir; jobdir=$(_dr_vps_job_dir "$jid") || return $?
  [ -d "$jobdir" ] || { printf 'state=missing\n'; return 0; }
  # OWNER SCOPING: a client (owner set) that does not own this job sees it as missing (no cross-owner leak).
  if [ -n "$owner" ] && [ "$(_dr_vps_job_meta_get "$jobdir" owner)" != "$owner" ]; then printf 'state=missing\n'; return 0; fi
  [ -f "$jobdir/terminal" ] && { cat "$jobdir/terminal"; return 0; }   # tombstone -> stable, no re-probe
  local vm tag start dom_uuid; vm=$(_dr_vps_job_meta_get "$jobdir" vm); tag="/tmp/.drvps-jobs/$jid"   # DERIVE from the validated jid, not untrusted meta (r7)
  start=$(_dr_vps_job_meta_get "$jobdir" start); dom_uuid=$(_dr_vps_job_meta_get "$jobdir" dom_uuid)
  # VM IDENTITY: a gone/recreated VM (uuid changed) can never serve this job -> destroyed (tombstoned). A store
  # READ FAILURE is transient -> infra-failed, NEVER a permanent 'destroyed' tombstone.
  local cur urc; cur=$(_dr_vps_job_cur_uuid "$vm"); urc=$?
  [ "$urc" -eq 0 ] || { printf 'state=infra-failed\n'; return 0; }
  [ "$cur" = "$dom_uuid" ] || { _dr_vps_job_emit_terminal "$jobdir" "state=destroyed"; return 0; }
  # PROBE rc FIRST: a job that already COMPLETED must resolve to done+guest_rc even if it is now
  # past the runtime ceiling -- never kill/timeout a finished job and discard its real rc/output. The guest `if`
  # always succeeds, so exec RC!=0 means INFRA (transport); a rc-file read failure -> PROBEERR (never a fabricated rc).
  local probe="if [ -f ${tag}.rc ]; then rc=\$(cat ${tag}.rc 2>/dev/null) && printf 'RC:%s' \"\$rc\" || printf PROBEERR; else printf RUNNING; fi"
  local out prc; out=$(dr_vps_exec "$vm" "$probe" 2>/dev/null); prc=$?
  [ "$prc" -eq 0 ] || { printf 'state=infra-failed\n'; return 0; }   # transient -> NOT tombstoned; caller retries
  # RE-CHECK uuid AFTER the probe: a destroy/recreate during the probe must not be trusted as this job's state (TOCTOU).
  cur=$(_dr_vps_job_cur_uuid "$vm"); urc=$?
  [ "$urc" -eq 0 ] || { printf 'state=infra-failed\n'; return 0; }
  [ "$cur" = "$dom_uuid" ] || { _dr_vps_job_emit_terminal "$jobdir" "state=destroyed"; return 0; }
  case "$out" in
    RC:*) local rc="${out#RC:}"
          # VALIDATE, do not sanitize: only a clean 0..255 is a real guest rc; garbage -> infra, never fabricated.
          case "$rc" in
            ''|*[!0-9]*) printf 'state=infra-failed\n' ;;
            *) { [ "$rc" -le 255 ] 2>/dev/null && _dr_vps_job_emit_terminal "$jobdir" "state=done guest_rc=$rc"; } || printf 'state=infra-failed\n' ;;
          esac
          return 0 ;;
    RUNNING*) : ;;                                   # still running -> fall through to the driver-timeout check
    *) printf 'state=infra-failed\n'; return 0 ;;    # PROBEERR / unexpected -> infra
  esac
  # DRIVER-TIMEOUT (only a STILL-RUNNING job, r7): past the ceiling -> KILL via the shared primitive; tombstone
  # ONLY on a PROVEN kill (else report driver-timeout WITHOUT tombstoning so a re-poll/reaper retries -- never
  # tombstone over a running process). `start` is UNTRUSTED -> validate decimal before arithmetic (r6 set-u).
  local now; now=$(date +%s)
  case "$start" in ''|*[!0-9]*) ;; *)
    if [ $((now - start)) -gt "${DR_VPS_JOB_MAX_RUNTIME:-3600}" ]; then
      local k; k=$(_dr_vps_job_kill "$vm" "$tag")   # completion-aware: may return DONE:<rc> if it finished during the kill
      case "$k" in
        DONE:*) local drc="${k#DONE:}"; case "$drc" in ''|*[!0-9]*) printf 'state=infra-failed\n';; *) { [ "$drc" -le 255 ] 2>/dev/null && _dr_vps_job_emit_terminal "$jobdir" "state=done guest_rc=$drc"; } || printf 'state=infra-failed\n';; esac ;;
        CLEAN)  _dr_vps_job_emit_terminal "$jobdir" "state=driver-timeout" ;;
        *)      printf 'state=driver-timeout\n' ;;   # RUNNING/UNKNOWN -> report but do NOT tombstone (retriable)
      esac
      return 0
    fi ;;
  esac
  printf 'state=running\n'
}

# exec-output: pull the job's captured stdout (bounded head -c cap IN THE GUEST). Read NEVER deletes.
dr_vps_exec_output() {  # <job_id>
  local jid="$1" owner=""; shift || true
  while [ "$#" -gt 0 ]; do case "$1" in --owner) owner="${2:-}"; shift 2;; *) shift;; esac; done
  local jobdir; jobdir=$(_dr_vps_job_dir "$jid") || return $?
  [ -d "$jobdir" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such job: $jid"; return $?; }
  # OWNER SCOPING: a client cannot read another owner's job output (NOTFOUND, indistinguishable from absent).
  if [ -n "$owner" ] && [ "$(_dr_vps_job_meta_get "$jobdir" owner)" != "$owner" ]; then dr_vps_die "$DR_VPS_E_NOTFOUND" "no such job: $jid"; return $?; fi
  local vm tag dom_uuid cur urc; vm=$(_dr_vps_job_meta_get "$jobdir" vm); tag="/tmp/.drvps-jobs/$jid"   # DERIVE from the validated jid, not untrusted meta (r7)
  dom_uuid=$(_dr_vps_job_meta_get "$jobdir" dom_uuid)
  # do NOT serve a recreated VM's file as this job's output (stale-id confusion); a store read failure is infra.
  cur=$(_dr_vps_job_cur_uuid "$vm"); urc=$?
  [ "$urc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_LIBVIRT" "job $jid: store read failed"; return $?; }
  [ "$cur" = "$dom_uuid" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "job $jid: source VM gone/recreated"; return $?; }
  local otmp; otmp=$(mktemp "${DR_VPS_TMP_DIR:-/tmp}/drvpsout.XXXXXX") || { dr_vps_die "$DR_VPS_E_GENERIC" "mktemp failed"; return $?; }
  dr_vps_pull "$vm" "${tag}.out" > "$otmp" 2>/dev/null; local prc=$?     # bounded IN-GUEST (head -c cap+1) by dr_vps_pull
  # CHECK the pull rc: an SSH/guest/read failure must NOT become a silent successful EMPTY output.
  [ "$prc" -eq 0 ] || { rm -f "$otmp"; dr_vps_die "$DR_VPS_E_LIBVIRT" "job $jid: pull output failed (guest/transport)"; return $?; }
  # RE-CHECK uuid AFTER the pull: a destroy/recreate during the read must not serve the new VM's bytes (TOCTOU).
  cur=$(_dr_vps_job_cur_uuid "$vm"); urc=$?
  { [ "$urc" -eq 0 ] && [ "$cur" = "$dom_uuid" ]; } || { rm -f "$otmp"; dr_vps_die "$DR_VPS_E_NOTFOUND" "job $jid: source VM recreated during read"; return $?; }
  cat "$otmp"; rm -f "$otmp"
}

# destroy hook: tombstone the VM's jobs (the VM teardown reaps the guest procs). Keeps terminal status for TTL.
dr_vps_jobs_cleanup_vm() {  # <vm> [expected_dom_uuid] -- tombstone the vm's non-terminal jobs. If a uuid is given,
  [ -d "${DR_VPS_JOBS_DIR:-}" ] || return 0            # ONLY those whose meta matches it -> a fresh-instance job is spared
  local d want="${2:-}"
  for d in "${DR_VPS_JOBS_DIR}"/*/; do
    [ -L "${d%/}" ] && continue                       # never follow a symlinked job dir
    [ -f "${d}meta" ] || continue
    [ "$(_dr_vps_job_meta_get "${d%/}" vm)" = "$1" ] || continue
    { [ -n "$want" ] && [ "$(_dr_vps_job_meta_get "${d%/}" dom_uuid)" != "$want" ]; } && continue
    [ -f "${d}terminal" ] || _dr_vps_job_terminal "${d%/}" "state=destroyed"
  done
}

# reaper sweep: purge job dirs whose terminal tombstone is older than the TTL (bounded state growth).
dr_vps_jobs_reap() {
  [ -d "${DR_VPS_JOBS_DIR:-}" ] || return 0
  local d jb now vm dom_uuid start tag cur urc cur2 urc2 prc age rout rc k budget rt maxsec deadline _bad; now=$(date +%s)
  budget="${DR_VPS_JOB_REAP_MAX_PER_SWEEP:-128}"; rt="${DR_VPS_JOB_REAP_EXEC_TIMEOUT:-10}"; maxsec="${DR_VPS_JOB_REAP_MAX_SECONDS:-60}"
  case "$budget" in ''|*[!0-9]*) budget=128;; esac; case "$rt" in ''|*[!0-9]*) rt=10;; esac   # r9: validate numeric env caps
  case "$maxsec" in ''|*[!0-9]*) maxsec=60;; esac; deadline=$(( now + maxsec ))
  for d in "${DR_VPS_JOBS_DIR}"/*/; do
    [ -L "${d%/}" ] && continue                        # never follow/rm through a symlinked job dir
    jb=$(basename "${d%/}"); case "$jb" in ''|*[!0-9a-f]*) continue;; esac   # only real hex job-id dirs (r7: tag derives from this)
    { [ "${#jb}" -ge 16 ] && [ "${#jb}" -le 64 ]; } || continue             # r8: match the public job-id length validator
    # PROMOTE a stale NON-terminal job so it terminalizes even if the agent NEVER polls (backstop).
    # Mirror exec-status EXACTLY (r8): SHORT per-exec timeout ($rt), a per-sweep guest-probe BUDGET so the timer
    # never holds the work-lock for minutes, check the transport rc, and RE-CHECK the uuid AFTER the probe (TOCTOU).
    # Only a PROVEN state acts; a completed job -> done+rc; a still-running over-ceiling job -> kill+driver-timeout
    # (proven CLEAN only), and the kill is completion-aware (DONE:<rc> if it finished mid-kill).
    if [ ! -f "${d}terminal" ] && [ -f "${d}meta" ]; then
      start=$(_dr_vps_job_meta_get "${d%/}" start)
      # IMMORTAL ESCAPE (r9, cheap -- no guest exec): a job never resolved within DR_VPS_JOB_TTL is force-tombstoned
      # driver-timeout (honest: cleanup UNPROVEN) so it can be TTL-purged -- bounds phantom no-pgid/no-rc jobs.
      # Guest files are NOT deleted (we cannot prove the process is gone; full proof needs a guest cgroup scope).
      case "$start" in ''|*[!0-9]*) ;; *)
        [ $((now - start)) -gt "${DR_VPS_JOB_TTL:-86400}" ] && _dr_vps_job_terminal "${d%/}" "state=driver-timeout" ;;
      esac
      # WALL-CLOCK + BUDGET gated guest promotion (r8/r9): stop once the per-sweep budget OR the wall-clock deadline
      # is spent, so the reaper never holds the work-lock long enough to starve the watcher.
      if [ ! -f "${d}terminal" ] && [ "$budget" -gt 0 ] && [ "$(date +%s)" -lt "$deadline" ]; then
      budget=$((budget-1))
      vm=$(_dr_vps_job_meta_get "${d%/}" vm); dom_uuid=$(_dr_vps_job_meta_get "${d%/}" dom_uuid)
      tag="/tmp/.drvps-jobs/$jb"   # DERIVE from validated basename (r7); start read above
      cur=$(_dr_vps_job_cur_uuid "$vm"); urc=$?
      if [ "$urc" -eq 0 ]; then                                                    # store read PROVEN (else leave, transient)
        if [ "$cur" != "$dom_uuid" ]; then
          _dr_vps_job_terminal "${d%/}" "state=destroyed"                          # VM gone/recreated (proven)
        else
          rout=$(dr_vps_exec "$vm" "if [ -f ${tag}.rc ]; then rc=\$(cat ${tag}.rc 2>/dev/null) && printf 'RC:%s' \"\$rc\" || printf PROBEERR; else printf RUNNING; fi" "$rt" 2>/dev/null); prc=$?
          if [ "$prc" -eq 0 ]; then                                               # transport ok (else leave, transient)
            cur2=$(_dr_vps_job_cur_uuid "$vm"); urc2=$?                            # RE-CHECK uuid after the probe (TOCTOU)
            if [ "$urc2" -eq 0 ] && [ "$cur2" != "$dom_uuid" ]; then
              _dr_vps_job_terminal "${d%/}" "state=destroyed"
            elif [ "$urc2" -eq 0 ]; then
              case "$rout" in
                RC:*) rc="${rout#RC:}"; case "$rc" in ''|*[!0-9]*) ;; *) { [ "$rc" -le 255 ] 2>/dev/null && _dr_vps_job_terminal "${d%/}" "state=done guest_rc=$rc"; } || true;; esac ;;
                RUNNING*) case "$start" in ''|*[!0-9]*) ;; *)
                    if [ $((now - start)) -gt "${DR_VPS_JOB_MAX_RUNTIME:-3600}" ]; then
                      k=$(_dr_vps_job_kill "$vm" "$tag" "$rt")
                      case "$k" in
                        DONE:*) rc="${k#DONE:}"; case "$rc" in ''|*[!0-9]*) ;; *) { [ "$rc" -le 255 ] 2>/dev/null && _dr_vps_job_terminal "${d%/}" "state=done guest_rc=$rc"; } || true;; esac ;;
                        CLEAN)  _dr_vps_job_terminal "${d%/}" "state=driver-timeout" ;;
                      esac
                    fi ;;
                  esac ;;
                # PROBEERR -> leave non-terminal (transient; retry next tick)
              esac
            fi
          fi
        fi
      fi
      fi
    fi
    # TTL-purge TERMINAL dirs (a just-promoted one has a fresh terminal -> it outlives this tick).
    if [ -f "${d}terminal" ]; then
      age=$(( now - $(stat -c %Y "${d}terminal" 2>/dev/null || echo "$now") ))
      [ "$age" -gt "${DR_VPS_JOB_TTL:-86400}" ] && rm -rf -- "${d}" 2>/dev/null || true
    fi
    # PURGE a MALFORMED/partial reservation (r10): a non-terminal hex job dir with NO valid meta (missing, or start
    # not decimal) older than TTL (by DIR mtime) is a failed reservation / corrupt state -> reclaim it, else a
    # partial-write crash could leave an immortal, unpollable dir consuming quota forever.
    if [ ! -f "${d}terminal" ]; then
      _bad=0; [ -f "${d}meta" ] || _bad=1
      [ "$_bad" = 0 ] && case "$(_dr_vps_job_meta_get "${d%/}" start)" in ''|*[!0-9]*) _bad=1;; esac
      if [ "$_bad" = 1 ]; then
        age=$(( now - $(stat -c %Y "${d%/}" 2>/dev/null || echo "$now") ))
        [ "$age" -gt "${DR_VPS_JOB_TTL:-86400}" ] && rm -rf -- "${d}" 2>/dev/null || true
      fi
    fi
  done
}
