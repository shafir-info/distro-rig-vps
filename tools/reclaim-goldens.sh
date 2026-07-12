#!/usr/bin/env bash
# reclaim-goldens.sh -- INTERIM maintainer tool: remove OLDER duplicate GOLDEN artifacts (store row +
# pool qcow2) to reclaim disk after an in-place upgrade + rebuild. Superseded by a future `dr-vps
# rm-golden` verb (see TODO.md). Run as the drvps service user on an installed host; DRY-RUN unless
# --commit:
#
#     sudo -u drvps -H /opt/distro-rig-vps/tools/reclaim-goldens.sh <artifact_id> [<artifact_id> ...]
#     sudo -u drvps -H /opt/distro-rig-vps/tools/reclaim-goldens.sh --commit <artifact_id> ...
#
# SAFETY (each id is checked before it is touched; any failing/uncertain check SKIPS it, FAIL CLOSED):
#   - must be a golden id (drvps-raw-v1-*) registered kind='golden' (snapshots refused).
#   - NEWEST-PER-DISTRO GUARD: reads the id's distro from provenance and the newest golden for that distro
#     (same query as the resolver); REFUSES if the id IS the newest, OR if that lookup errors/returns empty
#     (fail closed). So only OLDER duplicates are removed -- the resolvable (newest) golden, and the LAST
#     golden of a distro, always survive.
#   - ZERO references: referrers ledger AND direct vms AND direct overlays rows (belt-and-suspenders).
#   - PATH FENCE: golden_path is a REGULAR file (not symlink/dir), its realpath is UNDER the pool dir, and
#     NO OTHER image row resolves (by realpath, not string) to the same file.
#   - on --commit: the atomic refcount-gated dr_vps_store_image_delete drops the row; then the id is
#     re-verified ABSENT + still unreferenced (guards a concurrent re-register/create) before a CHECKED rm.
#     A row-deleted-but-file-kept case is reported as a WARNING and the tool exits non-zero (3).
# Run on a QUIESCENT rig (no concurrent build/create/destroy). Byte figures are disk-usage estimates
# (du; sparse-aware) and ignore hardlinks. ASCII only.
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
# shellcheck disable=SC1091  # /etc/distro-rig-vps/env is created by the installer; absent in CI/dev
[ "${DR_VPS_TEST_SEAMS:-}" = 1 ] || { [ -r /etc/distro-rig-vps/env ] && . /etc/distro-rig-vps/env; }
set +a
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
# shellcheck source=/dev/null
. "$HERE/dr_vps_api.sh"
# shellcheck source=/dev/null
. "$HERE/dr_vps_store.sh"
# FAIL CLOSED: refuse if the store cannot init/migrate (a half-migrated or corrupt store must not be
# operated on by a destructive tool).
dr_vps_store_init >/dev/null || { echo "FATAL: store init/migration failed -- refusing to reclaim" >&2; exit 1; }

POOL="$(cd "${DR_VPS_POOL_DIR:?}" 2>/dev/null && pwd -P)" || { echo "FATAL: pool dir '${DR_VPS_POOL_DIR:-}' unreadable" >&2; exit 1; }
hsz() { numfmt --to=iec "$1" 2>/dev/null || echo "$1"; }

deleted=0; skipped=0; warned=0; freed=0
for aid in "${args[@]}"; do
  case "$aid" in
    drvps-raw-v1-*) ;;
    *) echo "SKIP $aid -- not a golden id (drvps-raw-v1-*); use 'dr-vps snap-rm' for snapshots"; skipped=$((skipped + 1)); continue ;;
  esac
  qa="$(dr_vps_sql_str "$aid")"
  kind="$(dr_vps_sql "SELECT kind FROM images WHERE artifact_id=$qa;")"; krc=$?
  [ "$krc" -eq 0 ] || { echo "SKIP $aid -- kind read failed (db error, fail closed)"; skipped=$((skipped + 1)); continue; }
  [ "$kind" = golden ] || { echo "SKIP $aid -- $([ -z "$kind" ] && echo 'not registered' || echo "kind=$kind (not a golden)")"; skipped=$((skipped + 1)); continue; }
  path="$(dr_vps_store_image_get "$aid")"
  [ -n "$path" ] || { echo "SKIP $aid -- no golden_path"; skipped=$((skipped + 1)); continue; }
  distro="$(dr_vps_sql "SELECT json_extract(provenance,'\$.distro') FROM images WHERE artifact_id=$qa AND kind='golden';")"; drc=$?
  { [ "$drc" -eq 0 ] && [ -n "$distro" ]; } || { echo "SKIP $aid -- distro unreadable from provenance (fail closed)"; skipped=$((skipped + 1)); continue; }
  # distro names are recipe identifiers; anything with a newline/space/control/other char is unexpected
  # (a malformed row) -> fail closed rather than let it perturb the newest lookup.
  case "$distro" in *[!A-Za-z0-9._+:-]*) echo "SKIP $aid -- distro '$distro' has unexpected characters (fail closed)"; skipped=$((skipped + 1)); continue ;; esac
  # NEWEST guard, FAIL CLOSED: an errored or empty newest lookup must not authorize deletion.
  newest="$(dr_vps_sql "SELECT artifact_id FROM images WHERE json_extract(provenance,'\$.distro')=$(dr_vps_sql_str "$distro") AND kind='golden' ORDER BY created_at DESC LIMIT 1;")"; nrc=$?
  { [ "$nrc" -eq 0 ] && [ -n "$newest" ]; } || { echo "SKIP $aid -- cannot determine newest golden for '$distro' (fail closed)"; skipped=$((skipped + 1)); continue; }
  case "$newest" in drvps-raw-v1-*) ;; *) echo "SKIP $aid -- newest lookup returned a non-golden id (fail closed)"; skipped=$((skipped + 1)); continue ;; esac
  [ "$newest" != "$aid" ] || { echo "SKIP $aid -- it is the NEWEST golden for '$distro' (this tool removes only older duplicates)"; skipped=$((skipped + 1)); continue; }
  # references: referrers + direct vms + direct overlays
  refs="$(dr_vps_sql "SELECT (SELECT COUNT(*) FROM referrers WHERE artifact_id=$qa)+(SELECT COUNT(*) FROM vms WHERE artifact_id=$qa)+(SELECT COUNT(*) FROM overlays WHERE artifact_id=$qa);")"
  case "$refs" in ''|*[!0-9]*) echo "SKIP $aid -- reference read failed (fail closed)"; skipped=$((skipped + 1)); continue ;; esac
  [ "$refs" -eq 0 ] || { echo "SKIP $aid -- $refs reference(s) (referrer/vm/overlay): a VM still backs it"; skipped=$((skipped + 1)); continue; }
  # path fence: regular file, real path under the pool
  if [ ! -f "$path" ] || [ -L "$path" ]; then echo "SKIP $aid -- golden_path is not a regular file (symlink/dir/missing): $path"; skipped=$((skipped + 1)); continue; fi
  rp="$(realpath -- "$path" 2>/dev/null)"
  [ -n "$rp" ] || { echo "SKIP $aid -- golden_path does not resolve: $path"; skipped=$((skipped + 1)); continue; }
  case "$rp/" in "$POOL"/*) ;; *) echo "SKIP $aid -- golden_path escapes the pool dir: $path -> $rp"; skipped=$((skipped + 1)); continue ;; esac
  # no OTHER image row points at the SAME FILE. Compare inode:device (file IDENTITY), so a symlink,
  # hardlink, or lexically-different path to the same file is caught; a dangling other path stats-fail and
  # is correctly NOT the same file. Fail closed if the candidate itself cannot be stat'd.
  cid="$(stat -c '%i:%d' -- "$path" 2>/dev/null)"
  [ -n "$cid" ] || { echo "SKIP $aid -- cannot stat golden_path (fail closed): $path"; skipped=$((skipped + 1)); continue; }
  others="$(dr_vps_sql "SELECT golden_path FROM images WHERE artifact_id != $qa;")"; orc=$?
  [ "$orc" -eq 0 ] || { echo "SKIP $aid -- shared-path read failed (fail closed)"; skipped=$((skipped + 1)); continue; }
  shared=0
  while IFS= read -r op; do
    [ -n "$op" ] || continue
    oid="$(stat -c '%i:%d' -- "$op" 2>/dev/null)" || continue
    [ "$oid" = "$cid" ] && { shared=1; break; }
  done <<< "$others"
  [ "$shared" -eq 0 ] || { echo "SKIP $aid -- its file is shared with another image row (same inode): $path"; skipped=$((skipped + 1)); continue; }

  sz="$(du -B1 -- "$path" 2>/dev/null | cut -f1)"; case "$sz" in ''|*[!0-9]*) sz=0 ;; esac
  if [ "$COMMIT" -ne 1 ]; then
    echo "WOULD DELETE $aid  distro=$distro  (~$(hsz "$sz")B)  path=$path"; deleted=$((deleted + 1)); freed=$((freed + sz)); continue
  fi
  if ! dr_vps_store_image_delete "$aid"; then
    echo "REFUSED $aid -- store refused the row delete (referenced / db error); file kept"; skipped=$((skipped + 1)); continue
  fi
  # TOCTOU guard: row is gone; only unlink if the id did NOT reappear and is still unreferenced.
  back="$(dr_vps_sql "SELECT COUNT(*) FROM images WHERE artifact_id=$qa;")"
  again="$(dr_vps_sql "SELECT (SELECT COUNT(*) FROM referrers WHERE artifact_id=$qa)+(SELECT COUNT(*) FROM vms WHERE artifact_id=$qa)+(SELECT COUNT(*) FROM overlays WHERE artifact_id=$qa);")"
  if [ "$back" != 0 ] || [ "$again" != 0 ]; then
    echo "WARN $aid -- re-registered/referenced during delete; file KEPT (concurrent build/create?): $path"; warned=$((warned + 1)); continue
  fi
  if rm -f -- "$path" && [ ! -e "$path" ]; then
    echo "DELETED $aid (~$(hsz "$sz")B) + removed $path"; deleted=$((deleted + 1)); freed=$((freed + sz))
  else
    echo "WARN $aid -- row deleted but FILE NOT removed (rm failed): orphan at $path"; warned=$((warned + 1))
  fi
done
echo "---"
echo "$([ "$COMMIT" = 1 ] && echo deleted || echo would-delete): $deleted, skipped: $skipped, warnings: $warned, reclaim (est): $(hsz "$freed")B"
[ "$COMMIT" = 1 ] || echo "(dry-run -- re-run with --commit to apply)"
[ "$warned" -eq 0 ] || exit 3
