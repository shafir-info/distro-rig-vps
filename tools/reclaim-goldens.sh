#!/usr/bin/env bash
# reclaim-goldens.sh -- INTERIM maintainer tool: remove specific GOLDEN artifacts (store row + pool
# file) to reclaim disk, e.g. old duplicates left after an in-place upgrade + rebuild. Refcount-gated:
# a golden any VM still backs is SKIPPED (never deleted). Superseded by a future `dr-vps rm-golden`
# verb (see TODO.md). Run as the drvps service user on an installed host; DRY-RUN unless --commit:
#
#     sudo -u drvps -H /opt/distro-rig-vps/tools/reclaim-goldens.sh <artifact_id> [<artifact_id> ...]
#     sudo -u drvps -H /opt/distro-rig-vps/tools/reclaim-goldens.sh --commit <artifact_id> ...
#
# Each id must be a GOLDEN (drvps-raw-v1-*); snapshots are refused here (use `dr-vps snap-rm`). The row
# delete goes through the store's atomic refcount-gated dr_vps_store_image_delete, so a golden with any
# live referrer is refused even if it slips in after the pre-check. ASCII only.
set -uo pipefail

COMMIT=0
args=()
for a in "$@"; do
  case "$a" in
    --commit)  COMMIT=1 ;;
    --dry-run) COMMIT=0 ;;
    --*)       echo "unknown flag: $a" >&2; exit 2 ;;
    *)         args+=("$a") ;;
  esac
done
[ "${#args[@]}" -ge 1 ] || { echo "usage: reclaim-goldens.sh [--commit] <artifact_id> [<artifact_id>...]" >&2; exit 2; }

set -a
[ "${DR_VPS_TEST_SEAMS:-}" = 1 ] || { [ -r /etc/distro-rig-vps/env ] && . /etc/distro-rig-vps/env; }
set +a
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
# shellcheck source=/dev/null
. "$HERE/dr_vps_api.sh"
# shellcheck source=/dev/null
. "$HERE/dr_vps_store.sh"
dr_vps_store_init >/dev/null 2>&1 || true

hsz() { numfmt --to=iec "$1" 2>/dev/null || echo "$1"; }

deleted=0; skipped=0; freed=0
for aid in "${args[@]}"; do
  case "$aid" in
    drvps-raw-v1-*) ;;
    *) echo "SKIP $aid -- not a golden id (drvps-raw-v1-*); use 'dr-vps snap-rm' for snapshots"; skipped=$((skipped + 1)); continue ;;
  esac
  path="$(dr_vps_store_image_get "$aid" 2>/dev/null)"
  [ -n "$path" ] || { echo "SKIP $aid -- not registered"; skipped=$((skipped + 1)); continue; }
  refs="$(dr_vps_store_image_refcount "$aid" 2>/dev/null)"
  case "$refs" in ''|*[!0-9]*) echo "SKIP $aid -- refcount read failed (db error)"; skipped=$((skipped + 1)); continue ;; esac
  sz=0; [ -f "$path" ] && sz="$(stat -c%s "$path" 2>/dev/null || echo 0)"
  if [ "$refs" -gt 0 ]; then
    echo "SKIP $aid -- $refs referrer(s): a VM still backs it; path=$path"; skipped=$((skipped + 1)); continue
  fi
  if [ "$COMMIT" -ne 1 ]; then
    echo "WOULD DELETE $aid ($(hsz "$sz")B) path=$path"; deleted=$((deleted + 1)); freed=$((freed + sz)); continue
  fi
  if dr_vps_store_image_delete "$aid"; then
    rm -f -- "$path"
    echo "DELETED $aid ($(hsz "$sz")B) + removed $path"; deleted=$((deleted + 1)); freed=$((freed + sz))
  else
    echo "REFUSED $aid -- store refused the delete (referenced / db error); file kept"; skipped=$((skipped + 1))
  fi
done
echo "---"
echo "$([ "$COMMIT" = 1 ] && echo deleted || echo would-delete): $deleted, skipped: $skipped, reclaim: $(hsz "$freed")B"
[ "$COMMIT" = 1 ] || echo "(dry-run -- re-run with --commit to apply)"
