#!/usr/bin/env bash
# End-to-end --once golden for drvps-top: seamed DB + virsh (list + domstats) + getent.
# Verifies the full acquire -> reconcile -> render path with NO live rig.
# Run: bash tests/drvps-top-once.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v sqlite3 >/dev/null || { echo "SKIP: sqlite3 not installed"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
DB="$TMP/store.db"

sqlite3 "$DB" <<'SQL'
CREATE TABLE images(artifact_id TEXT PRIMARY KEY, golden_path TEXT, kind TEXT NOT NULL DEFAULT 'golden', name TEXT, provenance TEXT, created_at TEXT);
CREATE TABLE vms(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, state TEXT, name TEXT, project TEXT, domain_uuid TEXT, net TEXT, contract TEXT, owner_uid TEXT, class TEXT DEFAULT 'throwaway', created_at TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, vm_id TEXT, artifact_id TEXT, source_vm_id TEXT, secret_bearing INT DEFAULT 0, name TEXT, parent_golden_id TEXT, scrub_profile TEXT, shutdown_mode TEXT, validation_status TEXT, notes TEXT, owner_uid TEXT, created_at TEXT);
-- the store_init enforcement objects the schema gate reproduces (unique indexes + check triggers); a real
-- store always has them (no-op trigger bodies here -- the gate checks existence + type, not the body).
CREATE UNIQUE INDEX images_kind_name_uq ON images(kind,name);
CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);
CREATE TRIGGER images_kind_ins BEFORE INSERT ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'invalid images.kind'); END;
CREATE TRIGGER images_kind_upd BEFORE UPDATE OF kind ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'invalid images.kind'); END;
CREATE TRIGGER snapshots_ins BEFORE INSERT ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'invalid snapshots row'); END;
CREATE TRIGGER snapshots_upd BEFORE UPDATE ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'invalid snapshots row'); END;
INSERT INTO images VALUES('drvps-snap-v1-99-a9f0e966caafc7e4','/g/s','snapshot','u26','{"distro":"ubuntu26"}','2026-07-12T13:01:39Z');
INSERT INTO vms VALUES('drvps-vm-b71deae19298de23','drvps-snap-v1-99-a9f0e966caafc7e4','running','weftg-20260712T195935Z-fC4Ted-P05','p','b71deae1-9298-de23-4a5b-0011deadbeef','net','c','1007','throwaway','2026-07-12T20:00:00Z');
SQL

# virsh stub: dispatch on subcommand
VSTUB="$TMP/virsh"; cat > "$VSTUB" <<'EOF'
#!/usr/bin/env bash
op=""; for a in "$@"; do case "$a" in list) op=list;; domstats) op=domstats;; esac; done
if [ "$op" = list ]; then
  printf ' Id   Name                          UUID\n'
  printf ' 3    drvps-vm-b71deae19298de23     b71deae1-9298-de23-4a5b-0011deadbeef\n'
elif [ "$op" = domstats ]; then
  printf 'Domain: drvps-vm-b71deae19298de23\n  state.state=1\n  cpu.time=123456789\n  vcpu.current=4\n  balloon.current=1572864\n  balloon.maximum=1572864\n'
fi
EOF
chmod +x "$VSTUB"
# getent stub
GSTUB="$TMP/getent"; cat > "$GSTUB" <<'EOF'
#!/usr/bin/env bash
[ "$1" = passwd ] && printf 'alice:x:%s:%s::/home/alice:/bin/bash\n' "$2" "$2"
EOF
chmod +x "$GSTUB"

OUT="$(DRVPS_TOP_NO_ENV=1 DR_VPS_DB="$DB" DR_SQLITE=sqlite3 DR_VIRSH="$VSTUB" DR_GETENT="$GSTUB" \
       bash "$HERE/../tools/drvps-top" --once --no-color 2>&1)"

pass=0; fail=0
has() { if printf '%s' "$OUT" | grep -qF -- "$2"; then pass=$((pass+1)); else fail=$((fail+1)); printf 'FAIL: %s (missing [%s])\n' "$1" "$2"; fi; }

echo "----- rendered --once frame -----"; printf '%s\n' "$OUT"; echo "---------------------------------"
has "owner label"  "alice(1007)"
has "vm shortname" "weftg*P05"
has "short id"     "b71deae1"
has "state"        "running"
has "base"         "ubuntu26@snap:a9f0e966"
has "ram"          "1.5G/1.5G"
has "cpu first --" "--"
has "header"       "drvps-top"
has "anomalies"    "anomalies:"

echo "drvps-top --once: PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
