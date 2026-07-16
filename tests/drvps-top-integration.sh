#!/usr/bin/env bash
# Integration tests for drvps-top's read-only SQLite adapter against a REAL-schema temp DB,
# plus the ~1s hard-kill on a TERM-ignoring reader. No live rig / no libvirt.
# Run: bash tests/drvps-top-integration.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v sqlite3 >/dev/null || { echo "SKIP: sqlite3 not installed"; exit 0; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
DB="$TMP/store.db"

# Real-schema-representative tables (columns drvps-top reads; mirrors dr_vps_store.sh).
sqlite3 "$DB" <<'SQL'
CREATE TABLE images(artifact_id TEXT PRIMARY KEY, golden_path TEXT, kind TEXT NOT NULL DEFAULT 'golden',
  name TEXT, provenance TEXT, created_at TEXT);
CREATE TABLE vms(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
  name TEXT, project TEXT, domain_uuid TEXT, net TEXT, contract TEXT, owner_uid TEXT,
  class TEXT NOT NULL DEFAULT 'throwaway', created_at TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, vm_id TEXT, artifact_id TEXT, source_vm_id TEXT,
  secret_bearing INTEGER DEFAULT 0, name TEXT, parent_golden_id TEXT, scrub_profile TEXT,
  shutdown_mode TEXT, validation_status TEXT, notes TEXT, owner_uid TEXT, created_at TEXT);
-- store_init ENFORCEMENT objects: schema_probe (hardened to reproduce store_init's full refusal set) requires
-- these to exist WITH the right SEMANTICS -- UNIQUE indexes + triggers whose body RAISEs -- so the fixture must
-- create real ones (a WHEN guard keeps the RAISE triggers from firing on the valid rows below). The negative
-- test further down proves a same-named NON-unique index / no-op trigger is REJECTED, not blessed.
CREATE UNIQUE INDEX images_kind_name_uq ON images(kind,name);
CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);
CREATE TRIGGER images_kind_ins BEFORE INSERT ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'invalid images.kind'); END;
CREATE TRIGGER images_kind_upd BEFORE UPDATE OF kind ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'invalid images.kind'); END;
CREATE TRIGGER snapshots_ins BEFORE INSERT ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'invalid snapshots row'); END;
CREATE TRIGGER snapshots_upd BEFORE UPDATE ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'invalid snapshots row'); END;
INSERT INTO images VALUES('drvps-raw-v1-99-bc07c9f78db03574','/g/f','golden','fed','{"distro":"fedora44"}','2026-07-12T12:58:02Z');
INSERT INTO images VALUES('drvps-snap-v1-99-a9f0e966caafc7e4','/g/s','snapshot','u26snap','{"distro":"ubuntu26"}','2026-07-12T13:01:39Z');
INSERT INTO vms VALUES('drvps-vm-b71deae19298de23','drvps-snap-v1-99-a9f0e966caafc7e4','running','n1','p','b71deae1-9298-de23-4a5b-0011deadbeef','net','c','1007','throwaway','2026-07-12T20:00:00Z');
INSERT INTO vms VALUES('drvps-vm-000000000000dead','drvps-raw-v1-MISSING','broken','n2','p',NULL,'net','c',NULL,'throwaway','2026-07-12T20:01:00Z');
INSERT INTO snapshots VALUES('drvps-snap-v1-99-a9f0e966caafc7e4','vm','a','svm',0,'u26snap','drvps-raw-v1-99-bc07c9f78db03574','sp','sm','passed','n','1007','2026-07-12T13:01:39Z');
SQL

export DRVPS_TOP_NO_ENV=1 DR_VPS_DB="$DB" DR_SQLITE=sqlite3 DR_VIRSH=/bin/true DR_GETENT=/bin/true
# shellcheck disable=SC1090
source "$HERE/../tools/drvps-top"

pass=0; fail=0
eq() { if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); printf 'FAIL: %s\n  got : [%s]\n  want: [%s]\n' "$1" "$2" "$3"; fi; }

# ---- schema_probe on a good schema ----
eq "schema OK"        "$(schema_probe)"            "OK"
# ---- q_ledger clean ----
eq "ledger clean"     "$(q_ledger)"                "0"
# ---- q_vms: normal row (join to snapshot -> ubuntu26@snap) + orphan row ----
eq "q_vms normal"     "$(q_vms | grep b71deae1)"   "VM|drvps-vm-b71deae19298de23|1007|running|throwaway|b71deae1-9298-de23-4a5b-0011deadbeef|n1|2026-07-12T20:00:00Z|snapshot|ubuntu26|drvps-snap-v1-99-a9f0e966caafc7e4"
eq "q_vms orphan"     "$(q_vms | grep 000000 | cut -d'|' -f9-10)"  "|"   # kind+distro empty (no images row)
# ---- inventory ----
eq "q_goldens"        "$(q_goldens)"               "G|drvps-raw-v1-99-bc07c9f78db03574|fedora44|2026-07-12T12:58:02Z"
eq "q_snaps"          "$(q_snaps | cut -d'|' -f1-6)" "S|drvps-snap-v1-99-a9f0e966caafc7e4|u26snap|drvps-raw-v1-99-bc07c9f78db03574|0|passed"

# ---- NEGATIVE: same-named but WRONG-SEMANTICS enforcement objects must be REJECTED (not blessed by name) ----
# All required columns present, but images_kind_name_uq is NON-unique and images_kind_ins is a no-op (no RAISE).
DBn="$TMP/noenforce.db"; sqlite3 "$DBn" <<'SQL'
CREATE TABLE vms(owner_uid TEXT, class TEXT, domain_uuid TEXT, artifact_id TEXT, state TEXT, name TEXT, created_at TEXT);
CREATE TABLE images(kind TEXT, name TEXT, provenance TEXT, artifact_id TEXT);
CREATE TABLE snapshots(parent_golden_id TEXT, secret_bearing INT, validation_status TEXT, created_at TEXT, name TEXT);
CREATE INDEX images_kind_name_uq ON images(kind,name);                         -- NON-unique (wrong semantics)
CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);
CREATE TRIGGER images_kind_ins BEFORE INSERT ON images BEGIN SELECT 1; END;    -- no-op (no RAISE)
CREATE TRIGGER images_kind_upd BEFORE UPDATE OF kind ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'x'); END;
CREATE TRIGGER snapshots_ins BEFORE INSERT ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'x'); END;
CREATE TRIGGER snapshots_upd BEFORE UPDATE ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'x'); END;
SQL
outn="$(DR_VPS_DB=$DBn schema_probe)"
eq "no-enforce schema REJECTED (not OK)"  "$([ "$outn" != OK ] && echo yes || echo no)"        "yes"
eq "non-unique index flagged"             "$(printf '%s' "$outn" | grep -c 'index:images_kind_name_uq')"  "1"
eq "no-op trigger flagged"                "$(printf '%s' "$outn" | grep -c 'trigger:images_kind_ins')"    "1"

# ---- schema_probe on an OLD schema (drop a required column) ----
DB2="$TMP/old.db"; sqlite3 "$DB2" "CREATE TABLE vms(id TEXT, artifact_id TEXT, state TEXT, name TEXT, created_at TEXT); CREATE TABLE images(artifact_id TEXT, kind TEXT, name TEXT, provenance TEXT); CREATE TABLE snapshots(id TEXT, name TEXT);"
eq "schema old"       "$(DR_VPS_DB=$DB2 schema_probe | grep -o '^SCHEMA')"  "SCHEMA"

# ---- ledger DIRTY (bad kind + snapshot with no bijection) ----
DB3="$TMP/dirty.db"; sqlite3 "$DB3" <<'SQL'
CREATE TABLE images(artifact_id TEXT PRIMARY KEY, kind TEXT, name TEXT, provenance TEXT, created_at TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, parent_golden_id TEXT, secret_bearing INT, validation_status TEXT, name TEXT, created_at TEXT);
INSERT INTO images VALUES('x','boguskind','n','{}','t');
INSERT INTO snapshots VALUES('drvps-snap-orphan',NULL,0,'passed','n','t');
SQL
eq "ledger dirty>=2"  "$([ "$(DR_VPS_DB=$DB3 q_ledger)" -ge 2 ] && echo yes || echo no)"  "yes"

# ---- HARD KILL: a TERM-ignoring reader must be SIGKILLed within ~1s ----
STUB="$TMP/slow-sqlite"; cat > "$STUB" <<'EOF'
#!/usr/bin/env bash
trap '' TERM        # ignore TERM (only SIGKILL stops us)
sleep 10
EOF
chmod +x "$STUB"
t0=$(date +%s.%N)
DR_SQLITE="$STUB" q_db "SELECT 1;" >/dev/null 2>&1; rc=$?
t1=$(date +%s.%N)
elapsed=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
eq "hardkill fired"   "$(awk -v e="$elapsed" 'BEGIN{print (e<2.0)?"yes":"no"}')"  "yes"
eq "hardkill nonzero" "$([ "$rc" -ne 0 ] && echo yes || echo no)"                 "yes"
echo "  (TERM-ignoring reader killed in ${elapsed}s, rc=$rc)"

echo "-------------------------------------------"
echo "drvps-top integration: PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
