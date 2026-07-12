#!/usr/bin/env bash
# dr_vps_identity.sh -- canonicalization + hashing (Stage 1).
# Layering: recipe_hash (build intent) -> artifact_id (= golden CONTENT digest,
# drvps-raw-v1, D-P4) ; an instance pins exactly one artifact ; the COW overlay is
# runtime state and is NEVER an identity input. ASCII only; bins run set -uo pipefail (code is also -e-safe).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"

# sha256 hex of a file (first field only).
dr_vps_sha256() {
  [ -f "${1:-}" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "sha256: no file: ${1:-}"; return $?; }
  sha256sum "$1" | awk '{print $1}'
}

# Canonical JSON: sorted object keys, compact. Reads a file arg or stdin.
# Fail-closed: empty/invalid JSON is an error, never a silent empty hash input.
dr_vps_canon() {
  local out
  if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then
    out=$(jq -S -c '.' <"$1") || { dr_vps_die "$DR_VPS_E_GENERIC" "canon: invalid JSON: $1"; return $?; }
  else
    out=$(jq -S -c '.') || { dr_vps_die "$DR_VPS_E_GENERIC" "canon: invalid JSON (stdin)"; return $?; }
  fi
  [ -n "$out" ] && [ "$out" != "null" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "canon: empty/null JSON"; return $?; }
  printf '%s\n' "$out"
}

# recipe_hash: hash of the canonicalized build-intent recipe (key order irrelevant).
dr_vps_recipe_hash() {
  local recipe="${1:-}" canon
  [ -f "$recipe" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "recipe not found: $recipe"; return $?; }
  canon=$(dr_vps_canon "$recipe") || return $?
  printf '%s' "$canon" | sha256sum | awk '{print $1}'
}

# golden_digest (artifact_id) -- the blessed drvps-raw-v1 algorithm (D-P4).
# Digest is over the LOGICAL raw virtual-disk byte stream: metadata-free, so two
# qcow2 files with identical guest content but different qcow2 metadata hash equal.
# Input: a verified, INACTIVE golden qcow2.
dr_vps_golden_digest() {
  local golden="${1:-}" vsize tmp_raw actual hash rc=0
  [ -f "$golden" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "golden not found: $golden"; return $?; }
  # -U (force-share, read-only): the golden is an IMMUTABLE read-only artifact, so its digest
  # must be computable even while a running VM holds a shared lock on it as a backing file
  # (e.g. during `recreate`). -U avoids the exclusive lock `qemu-img check` would otherwise
  # take; it changes only locking, never the bytes read -> identical digest.
  local _ckout                                   # SURFACE qemu-img's real stderr (lock vs
  if ! _ckout=$("$DR_QEMU_IMG" check -U -f qcow2 "$golden" 2>&1); then   # EACCES vs SELinux avc)
    dr_vps_die "$DR_VPS_E_VERIFY" "qcow2 check failed: $golden -- ${_ckout}"; return $?
  fi
  vsize=$("$DR_QEMU_IMG" info -U --output=json -f qcow2 "$golden" | jq -r '."virtual-size"') \
    || { dr_vps_die "$DR_VPS_E_VERIFY" "cannot read virtual-size: $golden"; return $?; }
  case "$vsize" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_VERIFY" "bad virtual-size: $vsize"; return $?;; esac
  # Upper-bound the virtual-size: the digest streams the full LOGICAL size via `convert -O raw`, so a
  # tampered golden with an absurd virtual-size is a time/space DoS on every create/recreate. Cap it.
  [ "$vsize" -le "$(( ${DR_VPS_MAX_GOLDEN_GIB:-512} * 1073741824 ))" ] \
    || { dr_vps_die "$DR_VPS_E_VERIFY" "golden virtual-size ${vsize}B exceeds the ${DR_VPS_MAX_GOLDEN_GIB:-512}GiB cap: $golden"; return $?; }
  # M10: a golden MUST be standalone. `convert -O raw` FLATTENS a backing chain OR an external
  # data-file, so a non-self-contained substitute could reproduce the same digest (PASS) while qemu
  # boots a MUTABLE external store (TOCTOU). Assert HERE -- the chokepoint every identity path uses --
  # that BOTH the backing-filename AND the qcow2 external data-file are empty. (data-file lives under
  # format-specific.data.data-file and is NOT reported as backing-filename, so the old check missed it.)
  local _qinfo _gback _gdf
  _qinfo=$("$DR_QEMU_IMG" info -U --output=json -f qcow2 "$golden" 2>/dev/null)
  _gback=$(printf '%s' "$_qinfo" | jq -r '."backing-filename" // ""')
  _gdf=$(printf '%s' "$_qinfo" | jq -r '."format-specific".data."data-file" // ""')
  [ -z "$_gback" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "golden is not standalone (backs $_gback): $golden"; return $?; }
  [ -z "$_gdf" ]   || { dr_vps_die "$DR_VPS_E_VERIFY" "golden has an external data-file ($_gdf) -- not self-contained: $golden"; return $?; }
  mkdir -p "$DR_VPS_TMP_DIR"
  tmp_raw=$(mktemp --tmpdir="$DR_VPS_TMP_DIR" golden.XXXXXX.raw) \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "mktemp failed in $DR_VPS_TMP_DIR"; return $?; }
  # NB: this GB-scale raw temp is removed straight-line below AND by the reaper's TMP_DIR age-sweep
  # No RETURN/EXIT trap here on purpose: the watcher kills verbs with SIGKILL (no
  # trap can run), so the age-sweep -- not a trap -- is the real safety net for interrupt/SIGKILL.
  if "$DR_QEMU_IMG" convert -U -f qcow2 -O raw -t none -T none "$golden" "$tmp_raw"; then
    actual=$(stat -c '%s' "$tmp_raw")
    if [ "$actual" = "$vsize" ]; then
      hash=$(dr_vps_sha256 "$tmp_raw")
      printf 'drvps-raw-v1-%s-%s\n' "$vsize" "$hash"
    else
      dr_vps_die "$DR_VPS_E_VERIFY" "raw size mismatch: $actual != $vsize"; rc=$?
    fi
  else
    dr_vps_die "$DR_VPS_E_VERIFY" "qemu-img convert failed: $golden"; rc=$?
  fi
  rm -f "$tmp_raw"
  return "$rc"
}

# instance_id: deterministic id for a named VM instance (pins one artifact in the store). Inputs:
# name + project (+ owner_uid, S2). The overlay/lease/ttl never feed it.
dr_vps_instance_id() {  # <name> [project] [owner_uid]
  local name="${1:-}" project="${2:-default}" owner="${3:-}"
  [ -n "$name" ] || { dr_vps_die "$DR_VPS_E_USAGE" "instance_id: empty name"; return $?; }
  case "$name" in *[!A-Za-z0-9_.-]*) dr_vps_die "$DR_VPS_E_USAGE" "instance name not [A-Za-z0-9_.-]: $name"; return $?;; esac
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "instance_id: owner_uid must be numeric: $owner"; return $?; };; esac
  # S2 (owner-namespaced identity): the same name+project owned by DIFFERENT accounts hash to
  # DISTINCT ids, so a co-tenant cannot pre-create/squat another owner's name (post-S1a they also could not
  # destroy the squatter -- a durable namespace-denial). The direct OPERATOR (no owner) keeps the historical
  # 2-field derivation, so existing operator VM ids are UNCHANGED (no migration).
  local h
  if [ -n "$owner" ]; then
    h=$(printf '%s\037%s\037%s' "$name" "$project" "$owner" | sha256sum | awk '{print substr($1,1,16)}')
  else
    h=$(printf '%s\037%s' "$name" "$project" | sha256sum | awk '{print substr($1,1,16)}')
  fi
  printf 'drvps-vm-%s' "$h"
}
