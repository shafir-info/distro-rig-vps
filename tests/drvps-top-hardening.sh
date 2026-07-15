#!/usr/bin/env bash
# Pins the drvps-top operator-TUI hardening from the code review:
#  MAJOR-1  schema_probe reproduces store_init's FULL refusal set (a missing UNIQUE index / CHECK trigger
#           -- not just a column -- makes a store store_init would refuse show as SCHEMA, never OK).
#  MAJOR-2  acquisition FAILURE is surfaced, NEVER shown as an empty rig: a failed virsh -> SRC_LV=down and
#           tracked rows labeled `livedown`/`live?` (not `absent`); a failed store read -> SRC_DB=down.
#  MAJOR-3  run_bounded kills the WHOLE process GROUP on timeout (a TERM-ignoring grandchild does not survive).
# Sources tools/drvps-top (main() is guarded, so no loop runs). ASCII only.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0; ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
command -v sqlite3 >/dev/null 2>&1 || { echo "drvps-top hardening: SKIP (no sqlite3)"; exit 0; }

DRVPS_TOP_NO_ENV=1 DR_SQLITE=sqlite3
# shellcheck source=/dev/null
. "$REPO/tools/drvps-top"                             # defs only (main() is guarded); functions run in THIS shell

_schema() {   # $1=which-to-drop ('' none) $2=tag -> echoes a store db path
  local db="$T/$2.db" idx=1 trg=1
  [ "$1" = drop_index ] && idx=0; [ "$1" = drop_trigger ] && trg=0
  sqlite3 "$db" <<SQL
CREATE TABLE images(artifact_id TEXT PRIMARY KEY, kind TEXT, name TEXT, provenance TEXT, created_at TEXT);
CREATE TABLE vms(id TEXT PRIMARY KEY, owner_uid TEXT, class TEXT, domain_uuid TEXT, artifact_id TEXT, state TEXT, name TEXT, created_at TEXT, net TEXT, contract TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, name TEXT, parent_golden_id TEXT, secret_bearing INT, validation_status TEXT, created_at TEXT, bundle_relpath TEXT);
$([ "$idx" = 1 ] && printf 'CREATE UNIQUE INDEX images_kind_name_uq ON images(kind,name); CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);')
$([ "$trg" = 1 ] && printf 'CREATE TRIGGER images_kind_ins BEFORE INSERT ON images BEGIN SELECT 1; END; CREATE TRIGGER images_kind_upd BEFORE UPDATE OF kind ON images BEGIN SELECT 1; END; CREATE TRIGGER snapshots_ins BEFORE INSERT ON snapshots BEGIN SELECT 1; END; CREATE TRIGGER snapshots_upd BEFORE UPDATE ON snapshots BEGIN SELECT 1; END;')
SQL
  echo "$db"
}

# MAJOR-1: complete store -> OK; a missing index or trigger -> SCHEMA:... (refused, not OK)
DR_VPS_DB="$(_schema '' full)";        ok "schema gate: complete store -> OK"          '[ "$(schema_probe)" = OK ]'
DR_VPS_DB="$(_schema drop_index i)";   ok "schema gate: missing UNIQUE index -> SCHEMA" 'case "$(schema_probe)" in SCHEMA:*index*) true;; *) false;; esac'
DR_VPS_DB="$(_schema drop_trigger tr)";ok "schema gate: missing CHECK trigger -> SCHEMA" 'case "$(schema_probe)" in SCHEMA:*trigger*) true;; *) false;; esac'

# MAJOR-2: a FAILING virsh -> SRC_LV=down + the tracked row is `livedown/live?`, NOT `absent`
DR_VPS_DB="$(_schema '' full2)"
sqlite3 "$DR_VPS_DB" "INSERT INTO vms VALUES('drvps-vm-0000000000000001','1008','throwaway','11111111-1111-4111-8111-111111111111','x','running','n','1',NULL,NULL);"
VFAIL="$T/vfail"; printf '#!/usr/bin/env bash\nexit 1\n' > "$VFAIL"; chmod +x "$VFAIL"
DR_VIRSH="$VFAIL" acquire_top > "$T/rows"             # redirect (NOT a subshell) so SRC_LV/SRC_DB propagate
ok "never-empty: failed virsh -> SRC_LV=down"                '[ "$SRC_LV" = down ]'
ok "never-empty: tracked row is livedown/live? (not absent)" 'grep -q "^livedown|.*|live?|" "$T/rows"'
ok "never-empty: not mislabeled absent"                      '! grep -q "|absent|" "$T/rows"'
SFAIL="$T/sfail"; printf '#!/usr/bin/env bash\nexit 1\n' > "$SFAIL"; chmod +x "$SFAIL"
DR_SQLITE="$SFAIL" acquire_top >/dev/null 2>&1 || true
ok "never-empty: failed store read -> SRC_DB=down" '[ "$SRC_DB" = down ]'
DR_SQLITE=sqlite3

# MAJOR-3: run_bounded kills the WHOLE group -- a TERM-ignoring grandchild that outlives its parent is reaped
GC="$T/gc.pid"; STUB="$T/stub"
printf '#!/usr/bin/env bash\n( trap "" TERM; exec sleep 30 ) &\necho $! > %s\nsleep 30\n' "$GC" > "$STUB"; chmod +x "$STUB"
run_bounded 1 bash "$STUB" >/dev/null 2>&1
sleep 3                                               # allow the escalated group KILL to land
gcpid="$(cat "$GC" 2>/dev/null || echo 0)"
ok "process-group kill: TERM-ignoring grandchild reaped" '[ "$gcpid" = 0 ] || ! kill -0 "$gcpid" 2>/dev/null'

echo "-------------------------------------------"
echo "drvps-top hardening: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
