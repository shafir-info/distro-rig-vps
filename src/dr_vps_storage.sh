#!/usr/bin/env bash
# dr_vps_storage.sh -- storage safety (Stage 4): COW overlays under a fixed
# pool prefix, PATH-FENCED deletion (never rm -rf an unvalidated path), backing-chain
# validation, and the secret-safe NoCloud seed lifecycle. ASCII only; set -e safe.
#
# Seed seam (Fedora/SELinux): the seed must be PRIVATE yet readable by
# qemu:///system -- so 0640 in a labeled libvirt pool dir, group qemu; NOT 0600 (qemu
# couldn't read it), NOT world-readable. ssh-key material is written to a 0600 file and
# passed to cloud-localds as a PATH -- never on argv, never logged.

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_store.sh
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_store.sh"

: "${DR_VPS_SEED_GROUP:=qemu}"   # group that qemu:///system runs as (installer ensures)

# A vm_id used in a path MUST be a safe filename component -- no '/' or '..' that could
# escape the pool/seed dir at CREATE time (delete is fenced separately).
_dr_vps_safe_id() {
  case "${1:-}" in
    ''|.|..|-*|*[!A-Za-z0-9_.-]*) dr_vps_die "$DR_VPS_E_USAGE" "unsafe id (need [A-Za-z0-9_.-], no '.'/'..'/leading-dash): ${1:-}"; return $? ;;
  esac
}

# Resolve <path> and require it to be a STRICT child of <prefix> (default pool), with
# .. normalized away; refuse the prefix root itself and any sibling-prefix path.
dr_vps_storage_path_fence() {  # <path> [allowed_prefix]
  local p="${1:-}" prefix="${2:-$DR_VPS_POOL_DIR}" real rprefix
  [ -n "$p" ] || { dr_vps_die "$DR_VPS_E_USAGE" "path_fence: empty path"; return $?; }
  rprefix=$(realpath -m "$prefix"); real=$(realpath -m "$p")
  [ "$real" != "$rprefix" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "refusing fence root itself: $p"; return $?; }
  case "$real" in
    "$rprefix"/*) printf '%s\n' "$real" ;;
    *) dr_vps_die "$DR_VPS_E_GENERIC" "path outside fence ($rprefix): $p"; return $? ;;
  esac
}

# Prepare a FRESH, non-symlink destination before the rig writes an overlay/seed/pubkey at a
# DETERMINISTIC path. Two attacks this closes, both of which would corrupt the target AFTER the
# preflight digest gate:
#   - a squatted SYMLINK (-> a registered golden): the writer (qemu-img/cloud-localds/cp) would FOLLOW
#     it and clobber the link target. We REFUSE a symlink destination outright (never write through it).
#   - a HARDLINK to a golden (shares the inode): writing in place would mutate the golden. We UNLINK any
#     pre-existing REGULAR file first, so the new write lands on a FRESH inode (the golden's other link
#     survives). This also lets recreate legitimately rebuild its own prior seed/overlay at the path.
_dr_vps_publish_guard() {  # <final_path>
  local f="${1:-}"
  [ -n "$f" ] || { dr_vps_die "$DR_VPS_E_USAGE" "publish_guard: empty path"; return $?; }
  [ ! -L "$f" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "refusing to publish THROUGH a symlink (golden-protection): $f"; return $?; }
  [ ! -e "$f" ] || rm -f "$f"   # rip out the rig's own prior regular artifact -> the new write is a fresh inode
}

# Create a per-VM COW overlay backed by the pinned golden, under the pool prefix.
dr_vps_storage_overlay_create() {  # <vm_id> <artifact_id> -> overlay path
  local vm_id="$1" aid="$2" golden overlay
  _dr_vps_safe_id "$vm_id" || return $?
  golden=$(dr_vps_store_image_get "$aid")
  { [ -n "$golden" ] && [ -f "$golden" ]; } || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no golden for $aid"; return $?; }
  mkdir -p "$DR_VPS_POOL_DIR"
  overlay="${DR_VPS_POOL_DIR}/${vm_id}.qcow2"
  _dr_vps_publish_guard "$overlay" || return $?     # never qemu-img create THROUGH a squatted symlink (golden-protection)
  "$DR_QEMU_IMG" create -f qcow2 -b "$golden" -F qcow2 "$overlay" >/dev/null 2>&1 \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "overlay create failed for $vm_id"; return $?; }
  # qemu (the VM) reads+writes the overlay; libvirt chowns owner->qemu but preserves
  # group+mode, so group=qemu + 0660 keeps BOTH the VM and the rig (drvps) able to use it
  # (recreate deletes it). Fail-closed: an inaccessible overlay breaks VM boot.
  chgrp "$DR_VPS_SEED_GROUP" "$overlay" || { rm -f "$overlay"; dr_vps_die "$DR_VPS_E_GENERIC" "chgrp overlay to '$DR_VPS_SEED_GROUP' failed"; return $?; }
  chmod 0660 "$overlay"                 || { rm -f "$overlay"; dr_vps_die "$DR_VPS_E_GENERIC" "chmod overlay failed"; return $?; }
  printf '%s\n' "$overlay"
}

# Path-fenced overlay deletion (refuses anything outside the pool).
dr_vps_storage_overlay_delete() {  # <overlay_path>
  local p="$1" real
  real=$(dr_vps_storage_path_fence "$p") || return $?      # must resolve UNDER the pool
  # NEVER follow a symlink to delete. The caller's golden-guard sees the LINK name (not its target),
  # so an overlay path that is a SYMLINK to a registered golden would pass the guard while `realpath`
  # resolves to the golden -> deleting it. A legitimate overlay is a REGULAR FILE; refuse a symlink
  # and unlink only the ORIGINAL directory entry (never the resolved/followed path).
  if [ -L "$p" ]; then
    dr_vps_die "$DR_VPS_E_GENERIC" "refusing to delete a SYMLINK overlay (golden-protection): $p"; return $?
  fi
  rm -f "$p"
}

# ---- Observability: persistent serial-console log lifecycle (CONCEPT-OBSERVABILITY) ----------
# virtlogd persists each VM's <serial><log file> at dr_vps_console_log_path <id>; console-dump reads the
# bounded tail. The guestexec GATE allows EXACTLY that one canonical path. These helpers mirror the
# overlay/seed discipline: fenced under DR_VPS_CONSOLE_LOG_DIR, symlink-refusing, fresh-inode.

# Prepare a FRESH-INODE console-log slot BEFORE `virsh define`. A symlink OR any non-regular type at the
# path is a tamper signal -> FAIL CLOSED (do NOT unlink an anomaly). Unlink only a stale REGULAR log + its
# fenced rotated siblings so virtlogd writes a fresh inode (no hardlink/stale-inode reuse across generations).
dr_vps_console_log_prepare() {  # <id>
  local id="$1" f r
  _dr_vps_safe_id "$id" || return $?
  f=$(dr_vps_console_log_path "$id")
  dr_vps_storage_path_fence "$f" "$DR_VPS_CONSOLE_LOG_DIR" >/dev/null || return $?
  mkdir -p "$DR_VPS_CONSOLE_LOG_DIR"     # no-op in production (installer made it labeled); convenience for seams
  if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then
    dr_vps_die "$DR_VPS_E_GENERIC" "refusing non-regular/symlink console log (tamper): $f"; return $?
  fi
  [ ! -e "$f" ] || rm -f "$f"           # drop any stale inode from a prior generation first
  # LIVE-FIX: pre-create the log as a drvps-OWNED regular file so virtlogd (root) O_APPENDs to THIS inode
  # rather than creating its own root:root 0600 -- which the unprivileged console-dump (drvps) could not read
  # (confirmed live: a drvps-owned virt_log_t console log IS readable by the drvps watcher, and virtlogd
  # appends to it). New file inherits the dir's virt_log_t label (SELinux parent-type default); restorecon is
  # best-effort insurance so virtlogd may still write it. 0640: drvps reads as owner; group read is harmless.
  : >"$f" || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot create console log slot: $f"; return $?; }
  chmod 0640 "$f" 2>/dev/null || true
  command -v restorecon >/dev/null 2>&1 && restorecon "$f" >/dev/null 2>&1 || true  # stdout too: create captures stdout as the id
  for r in "$f".[0-9]*; do              # rotated backups (<log>.N) from a prior generation
    [ -e "$r" ] || continue
    dr_vps_storage_path_fence "$r" "$DR_VPS_CONSOLE_LOG_DIR" >/dev/null || return $?
    [ ! -L "$r" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "refusing symlink rotated console log: $r"; return $?; }
    [ -f "$r" ] && rm -f "$r"
  done
  dr_vps_diag "prepare: id=$id fresh-inode console-log slot ready"   # metadata-only (SPEC-DIAG)
  return 0
}

# Bounded tail of the persisted console log. FAIL CLOSED on symlink; explicit not-found (-> the caller's
# "recreate to enable" message) when there is no persistent log (pre-change VM).
dr_vps_console_log_tail() {  # <id> <cap_bytes>
  local id="$1" cap="${2:-$DR_VPS_CONSOLE_TAIL_MAX_BYTES}" f
  _dr_vps_safe_id "$id" || return $?
  # convergence r4 (self-defending primitive): the cap MUST be a strict base-10 POSITIVE byte count -- reject
  # '+N' (tail -c +N reads the WHOLE file), leading-zero octal, and non-numeric, regardless of the caller.
  case "$cap" in ''|0|*[!0-9]*|0?*) dr_vps_die "$DR_VPS_E_USAGE" "console tail: byte cap must be a positive base-10 integer: $cap"; return $?;; esac
  f=$(dr_vps_console_log_path "$id")
  dr_vps_storage_path_fence "$f" "$DR_VPS_CONSOLE_LOG_DIR" >/dev/null || return $?
  [ ! -L "$f" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "refusing symlink console log: $f"; return $?; }
  [ -f "$f" ]   || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no persistent console log for $id (recreate to enable)"; return $?; }
  # Stage-1: an EXISTING but unreadable log = a pre-change VM whose log is root-owned (virtlogd created/rotated it
  # before the append='on' + drvps-pre-create fix). Sharpen the message: recreate rebuilds it drvps-readable.
  [ -r "$f" ]   || { dr_vps_die "$DR_VPS_E_CAP" "console log not readable (root-owned pre-change VM?) -- recreate to enable READABLE console: $f"; return $?; }
  tail -c "$cap" -- "$f"
}

# Path-fenced console-log removal (log + rotated .N). REFUSE (never follow) a symlink anomaly.
dr_vps_console_log_cleanup() {  # <id>
  local id="$1" f r
  _dr_vps_safe_id "$id" || return $?
  f=$(dr_vps_console_log_path "$id")
  dr_vps_storage_path_fence "$f" "$DR_VPS_CONSOLE_LOG_DIR" >/dev/null || return $?
  if [ -L "$f" ]; then dr_vps_die "$DR_VPS_E_GENERIC" "refusing to remove a SYMLINK console log: $f"; return $?; fi
  rm -f "$f"
  for r in "$f".[0-9]*; do
    [ -e "$r" ] || continue
    [ -L "$r" ] && continue            # never follow/unlink a symlink anomaly
    dr_vps_storage_path_fence "$r" "$DR_VPS_CONSOLE_LOG_DIR" >/dev/null || return $?
    rm -f "$r"
  done
  return 0
}

# Validate the overlay's backing file is exactly the expected golden.
dr_vps_storage_backing_check() {  # <overlay> <expected_golden>
  local overlay="$1" expected="$2" actual gback ovinfo ovdf
  [ -f "$overlay" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no overlay: $overlay"; return $?; }
  ovinfo=$("$DR_QEMU_IMG" info --output=json "$overlay" 2>/dev/null)
  actual=$(printf '%s' "$ovinfo" | jq -r '."backing-filename" // ""')
  [ "$actual" = "$expected" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "backing chain mismatch: $actual != $expected"; return $?; }
  # the overlay must have NO external qcow2 data-file (a host-file channel that reports the expected
  # backing-filename while backing guest I/O with a host path) -- same invariant as the golden_digest.
  ovdf=$(printf '%s' "$ovinfo" | jq -r '."format-specific".data."data-file" // ""')
  [ -z "$ovdf" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "overlay has an external data-file ($ovdf) -- hidden host storage channel"; return $?; }
  # the golden must itself be standalone, so overlay -> golden is the COMPLETE chain
  gback=$("$DR_QEMU_IMG" info --output=json "$expected" 2>/dev/null | jq -r '."backing-filename" // ""')
  [ -z "$gback" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden is not standalone (backs $gback): $expected"; return $?; }
}

# ---- per-distro-FAMILY cloud-init repo/proxy emitters (Phase 3) -------------------------
# Each emits the write_files:/runcmd: cloud-config for one package-manager family: pin the
# repo to the allowlisted official master + route the package manager through the cache proxy.
# \$ is cloud-init's ($releasever/$basearch); ${...} is our config.
_dr_vps_default_fedora_repo() {   # the proven Fedora .repo body (default when a recipe pins none)
  cat <<EOF
[fedora-drvps]
name=Fedora \$releasever (drvps pinned)
baseurl=${DR_VPS_REPO_SCHEME}://${DR_VPS_REPO_HOST}/pub/fedora/linux/releases/\$releasever/Everything/\$basearch/os/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-\$releasever-\$basearch
[updates-drvps]
name=Fedora \$releasever updates (drvps pinned)
baseurl=${DR_VPS_REPO_SCHEME}://${DR_VPS_REPO_HOST}/pub/fedora/linux/updates/\$releasever/Everything/\$basearch/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-\$releasever-\$basearch
EOF
}
_dr_vps_seed_repos_dnf() {   # Fedora / RHEL / Rocky / Alma / CentOS -- RECIPE-DRIVEN .repo (default Fedora)
  local content="${DR_VPS_REPO_CONTENT:-}" rrm="${DR_VPS_REPO_REMOVE:-}" removecmd
  if [ -n "$content" ]; then
    # A PINNED repo (non-default-Fedora, e.g. Rocky/Alma/CentOS). If the recipe NAMED the stock repos
    # to drop, use them; OTHERWISE disable ALL stock repos generically (keeping only drvps.repo) -- the
    # Fedora-specific default list would miss a RHEL-family guest's stock mirrorlists, which then
    # resolve to NON-allowlisted hosts and break `dnf install` behind the fence.
    # shellcheck disable=SC2016  # $f below is the GUEST shell's loop var (cloud-init runcmd) -- no local expand
    if [ -n "$rrm" ]; then
      removecmd="rm -f ${rrm} 2>/dev/null; true"
    else
      removecmd='cd /etc/yum.repos.d && for f in *.repo; do [ "$f" = drvps.repo ] || rm -f "$f"; done; true'
    fi
  else
    content=$(_dr_vps_default_fedora_repo)
    removecmd="rm -f ${rrm:-/etc/yum.repos.d/fedora.repo /etc/yum.repos.d/fedora-updates.repo /etc/yum.repos.d/fedora-cisco-openh264.repo /etc/yum.repos.d/fedora-updates-testing.repo /etc/yum.repos.d/fedora-updates-archive.repo} 2>/dev/null; true"
  fi
  printf 'write_files:\n  - path: /etc/yum.repos.d/drvps.repo\n    content: |\n'
  printf '%s\n' "$content" | sed 's/^/      /'
  cat <<YAML
runcmd:
  - [ sh, -c, "printf 'proxy=${DR_VPS_GUEST_PROXY}\\\\nfastestmirror=0\\\\n' >> /etc/dnf/dnf.conf" ]
  - [ sh, -c, "${removecmd}" ]
YAML
}
_dr_vps_seed_repos_zypper() {   # openSUSE -- pin a repo (download.opensuse.org sprawls) + system proxy
  local content="${DR_VPS_REPO_CONTENT:-}"
  [ -n "$content" ] || { dr_vps_die "$DR_VPS_E_USAGE" "zypper family needs repo_content in the recipe"; return $?; }
  printf 'write_files:\n  - path: /etc/zypp/repos.d/drvps.repo\n    content: |\n'
  printf '%s\n' "$content" | sed 's/^/      /'
  printf '  - path: /etc/sysconfig/proxy\n    content: |\n'
  printf '      PROXY_ENABLED="yes"\n      HTTP_PROXY="%s"\n      HTTPS_PROXY="%s"\n' "${DR_VPS_GUEST_PROXY%/}/" "${DR_VPS_GUEST_PROXY%/}/"
  # M12: DISABLE the stock openSUSE repos (download.opensuse.org redirects to un-allowlisted
  # mirrors -> installs fail behind the fence). Keep only the pinned drvps.repo.
  cat <<'YAML'
runcmd:
  - [ sh, -c, "cd /etc/zypp/repos.d && for f in *.repo; do [ \"$f\" = drvps.repo ] || rm -f \"$f\"; done; true" ]
YAML
}
_dr_vps_seed_repos_apk() {   # Alpine -- single CDN master; persist the proxy env (apk reads http_proxy).
  # CAVEAT: ssh non-interactive exec does NOT source profile.d, so agent `exec apk add` may need
  # http_proxy set in the command; /etc/environment is the best-effort persistent setting.
  cat <<YAML
write_files:
  - path: /etc/profile.d/drvps-proxy.sh
    permissions: '0644'
    content: |
      export http_proxy=${DR_VPS_GUEST_PROXY%/}/
      export https_proxy=${DR_VPS_GUEST_PROXY%/}/
  - path: /etc/environment
    content: |
      http_proxy=${DR_VPS_GUEST_PROXY%/}/
      https_proxy=${DR_VPS_GUEST_PROXY%/}/
YAML
}
_dr_vps_seed_repos_apt() {   # Debian / Ubuntu -- the image's official sources are fine; just
  # route apt through the cache proxy (the allowlist must include deb.debian.org/archive.ubuntu.com).
  # apt's documented proxy form has a trailing slash; normalize to exactly one.
  cat <<YAML
write_files:
  - path: /etc/apt/apt.conf.d/99drvps-proxy
    content: |
      Acquire::http::Proxy "${DR_VPS_GUEST_PROXY%/}/";
      Acquire::https::Proxy "${DR_VPS_GUEST_PROXY%/}/";
YAML
}

# Build a NoCloud seed: ssh-key-only (NO root password), unique instance-id so cloud-init
# re-runs on recreate. The key is written to a 0600 file and passed by PATH; never argv.
dr_vps_storage_seed_build() {  # <vm_id> <ssh_pubkey_file> [instance_seq] -> seed path
  local vm_id="$1" keyfile="$2" seq="${3:-$(date -u +%s)-${RANDOM}}" seed ud md d
  _dr_vps_safe_id "$vm_id" || return $?
  [ -f "$keyfile" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "ssh key file not found: $keyfile"; return $?; }
  mkdir -p "$DR_VPS_SEED_DIR"
  d=$(mktemp -d --tmpdir="$DR_VPS_SEED_DIR" seed.XXXXXX) || { dr_vps_die "$DR_VPS_E_GENERIC" "mktemp seed dir"; return $?; }
  ud="$d/user-data"; md="$d/meta-data"
  : >"$ud"; chmod 0600 "$ud"
  # cat the key by PATH (its argv is the file path, not the key bytes) so the key never
  # appears on a command line / set -x trace -- only inside the 0600 user-data file.
  # Emit the user-data in a SUBSHELL and CHECK it. The old `{ ... } >>"$ud"` group ran
  # `|| return $?` INSIDE the group, so an emitter failure (or a vanished keyfile -- cat's rc was
  # unchecked, yielding a KEYLESS seed -> an unreachable VM) returned from the function WITHOUT the
  # `rm -rf "$d"` cleanup, leaking the 0600 key-bearing temp dir. `exit` (not `return`) inside `( )`
  # ends the subshell; the outer `if !` then cleans up and propagates the code.
  (
    printf '#cloud-config\n'
    printf 'disable_root: false\nssh_pwauth: false\n'
    printf 'users:\n  - name: root\n    ssh_authorized_keys:\n      - '
    cat "$keyfile" || { echo "dr-vps: seed: ssh key unreadable/vanished mid-build: $keyfile" >&2; exit "$DR_VPS_E_NOTFOUND"; }
    printf '\n'
    # Guest repo/proxy plumbing per the distro FAMILY (Phase 3). dnf is the proven default;
    # apt/zypper/apk are profile emitters (s below). The golden's baked CA already trusts the
    # cache, so the family just wires the proxy + an allowlist-pinned repo.
    case "${DR_VPS_DISTRO_FAMILY:-dnf}" in
      dnf)    _dr_vps_seed_repos_dnf    || exit $? ;;
      apt)    _dr_vps_seed_repos_apt    || exit $? ;;
      zypper) _dr_vps_seed_repos_zypper || exit $? ;;
      apk)    _dr_vps_seed_repos_apk    || exit $? ;;
      *)      echo "dr-vps: unsupported distro family '${DR_VPS_DISTRO_FAMILY:-?}' -- no seed plumbing (add an emitter); FAIL-CLOSED" >&2; exit "$DR_VPS_E_USAGE" ;;
    esac
  ) >>"$ud"
  # CAPTURE the subshell rc DIRECTLY (an `if ! (...); then` would clobber $? to the negation's 0).
  local _emit_rc=$?
  [ "$_emit_rc" -eq 0 ] || { rm -rf "$d"; return "$_emit_rc"; }   # cleanup key-bearing temp; propagate
  printf 'instance-id: %s\nlocal-hostname: %s\n' "${vm_id}-${seq}" "$vm_id" >"$md"
  seed="${DR_VPS_SEED_DIR}/${vm_id}-seed.iso"
  _dr_vps_publish_guard "$seed" || { rm -rf "$d"; return 1; }   # no-follow/no-clobber (golden-protection)
  # BUILD the NoCloud seed ISO. Prefer cloud-localds; fall back to genisoimage when it is absent
  # (EPEL9 packages NO cloud-utils/cloud-localds -- live centos9 finding). cloud-localds IS just
  # `genisoimage -output SEED -volid cidata -joliet -rock user-data meta-data`, so the fallback is
  # byte-contract-equivalent. -graft-points pins the in-ISO names to user-data/meta-data regardless
  # of the temp paths (cloud-init keys off those exact names + the 'cidata' volume label). Both tools
  # get the files by PATH, never the key on argv. Fail CLOSED if neither tool is present.
  if dr_vps_have "$DR_CLOUDLOCALDS"; then
    "$DR_CLOUDLOCALDS" "$seed" "$ud" "$md" >/dev/null 2>&1 \
      || { rm -rf "$d"; dr_vps_die "$DR_VPS_E_GENERIC" "cloud-localds failed for $vm_id"; return $?; }
  elif dr_vps_have "$DR_GENISOIMAGE"; then
    "$DR_GENISOIMAGE" -output "$seed" -volid cidata -joliet -rock \
      -graft-points "user-data=$ud" "meta-data=$md" >/dev/null 2>&1 \
      || { rm -rf "$d"; dr_vps_die "$DR_VPS_E_GENERIC" "genisoimage (cloud-localds fallback) failed for $vm_id"; return $?; }
  else
    rm -rf "$d"; dr_vps_die "$DR_VPS_E_CAP" "no NoCloud seed builder: neither cloud-localds nor genisoimage found (install cloud-utils or genisoimage)"; return $?
  fi
  rm -rf "$d"                                  # remove the 0600 user-data with the key
  # FAIL-CLOSED on perms/group: a seed qemu cannot read => the VM won't boot. Better to
  # refuse here than hand out an unreadable seed. (Installer guarantees the qemu group.)
  chmod 0640 "$seed" || { rm -f "$seed"; dr_vps_die "$DR_VPS_E_GENERIC" "chmod seed failed"; return $?; }
  chgrp "$DR_VPS_SEED_GROUP" "$seed" \
    || { rm -f "$seed"; dr_vps_die "$DR_VPS_E_GENERIC" "chgrp seed to '$DR_VPS_SEED_GROUP' failed (installer must create it + add ${DR_VPS_SERVICE_USER})"; return $?; }
  [ "$(stat -c '%a:%G' "$seed")" = "640:$DR_VPS_SEED_GROUP" ] \
    || { rm -f "$seed"; dr_vps_die "$DR_VPS_E_GENERIC" "seed perms/group != 640:$DR_VPS_SEED_GROUP"; return $?; }
  printf '%s\n' "$seed"
}

# Remove a VM's seed (path-fenced under the seed dir).
dr_vps_storage_seed_cleanup() {  # <vm_id>
  _dr_vps_safe_id "${1:-}" || return $?
  local seed="${DR_VPS_SEED_DIR}/${1}-seed.iso"
  [ -e "$seed" ] || [ -L "$seed" ] || return 0
  # fence VALIDATES no-escape; then REFUSE a symlink and remove the LITERAL deterministic path (id is
  # charset-fenced, so it cannot escape the seed dir) -- NOT the canonical target. rm on a symlink would unlink
  # the LINK, but refusing outright surfaces the anomaly instead of silently touching another VM's seed target.
  dr_vps_storage_path_fence "$seed" "$DR_VPS_SEED_DIR" >/dev/null || return $?
  [ ! -L "$seed" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "refusing to clean a SYMLINK seed: $seed"; return $?; }
  rm -f -- "$seed"
}
