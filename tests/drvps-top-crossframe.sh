#!/usr/bin/env bash
# Cross-frame test: proves acquire_top's global state (CPU baseline _STCACHE, A_* counters)
# PERSISTS across frames -- i.e. frame_top does NOT lose it to a subshell.
# Run: bash tests/drvps-top-crossframe.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v sqlite3 >/dev/null || { echo "SKIP: sqlite3 not installed"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
DB="$TMP/store.db"

sqlite3 "$DB" <<'SQL'
CREATE TABLE images(artifact_id TEXT PRIMARY KEY, golden_path TEXT, kind TEXT DEFAULT 'golden', name TEXT, provenance TEXT, created_at TEXT);
CREATE TABLE vms(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, state TEXT, name TEXT, project TEXT, domain_uuid TEXT, net TEXT, contract TEXT, owner_uid TEXT, class TEXT DEFAULT 'throwaway', created_at TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, vm_id TEXT, artifact_id TEXT, source_vm_id TEXT, secret_bearing INT, name TEXT, parent_golden_id TEXT, scrub_profile TEXT, shutdown_mode TEXT, validation_status TEXT, notes TEXT, owner_uid TEXT, created_at TEXT);
INSERT INTO images VALUES('drvps-snap-v1-99-a9f0e966caafc7e4','/g','snapshot','u26','{"distro":"ubuntu26"}','t');
INSERT INTO vms VALUES('drvps-vm-b71deae19298de23','drvps-snap-v1-99-a9f0e966caafc7e4','running','vm1','p','b71deae1-9298-de23-4a5b-0011deadbeef','n','c','1007','throwaway','2026-07-12T20:00:00Z');
-- a VM with an invalid (NULL) domain_uuid -> bumps the ledger/anomaly counter
INSERT INTO vms VALUES('drvps-vm-000000000000dead','drvps-snap-v1-99-a9f0e966caafc7e4','broken','vm2','p',NULL,'n','c','1007','throwaway','2026-07-12T20:01:00Z');
SQL

# stateful virsh stub: domstats returns an INCREASING cpu.time each call
CNT="$TMP/cnt"; echo 0 > "$CNT"
VSTUB="$TMP/virsh"; cat > "$VSTUB" <<EOF
#!/usr/bin/env bash
op=""; for a in "\$@"; do case "\$a" in list) op=list;; domstats) op=domstats;; esac; done
if [ "\$op" = list ]; then
  printf ' Id Name UUID\n 3 drvps-vm-b71deae19298de23 b71deae1-9298-de23-4a5b-0011deadbeef\n'
elif [ "\$op" = domstats ]; then
  n=\$(cat "$CNT"); n=\$((n+1)); echo "\$n" > "$CNT"
  cpu=\$((n*1000000000))
  printf 'Domain: drvps-vm-b71deae19298de23\n  state.state=1\n  cpu.time=%s\n  vcpu.current=4\n  balloon.current=1572864\n  balloon.maximum=1572864\n' "\$cpu" 2>/dev/null || printf 'Domain: x\n  state.state=1\n  cpu.time=%s\n  vcpu.current=4\n  balloon.current=1572864\n  balloon.maximum=1572864\n' "\$cpu"
fi
EOF
# (fix var name in stub)
sed -i 's/%s" "\$cpu"/%s" "\$cpu"/' "$VSTUB"
chmod +x "$VSTUB"
GSTUB="$TMP/getent"; printf '#!/usr/bin/env bash\n[ "$1" = passwd ] && printf "alice:x:%%s:%%s::/h:/b\\n" "$2" "$2"\n' > "$GSTUB"; chmod +x "$GSTUB"

export DRVPS_TOP_NO_ENV=1 DR_VPS_DB="$DB" DR_SQLITE=sqlite3 DR_VIRSH="$VSTUB" DR_GETENT="$GSTUB" DRVPS_TOP_COLOR=0
# shellcheck disable=SC1090
source "$HERE/../tools/drvps-top"

# two frames in THIS shell, redirection (NOT $()), stepped monotonic clock
DRVPS_TOP_NOW_MONO_NS=0          frame_top > "$TMP/f1.txt"
DRVPS_TOP_NOW_MONO_NS=1000000000 frame_top > "$TMP/f2.txt"

pass=0; fail=0
eqc() { if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); printf 'FAIL: %s\n  got:[%s] want:[%s]\n' "$1" "$2" "$3"; fi; }

echo "----- frame1 -----"; cat "$TMP/f1.txt"; echo "----- frame2 -----"; cat "$TMP/f2.txt"; echo "------------------"
# frame1: CPU is -- (no baseline yet)
eqc "f1 cpu is --"    "$(grep vm1 "$TMP/f1.txt" | awk '{print $(NF-1)}')" "--"
# frame2: CPU baseline PERSISTED -> real % (1e9 ns cpu over 1e9 ns wall = 100.0)
eqc "f2 cpu persisted" "$(grep vm1 "$TMP/f2.txt" | awk '{print $(NF-1)}')" "100.0"
# anomaly counter reached the header (the NULL-uuid VM bumped ledger) -> not zero
eqc "counter in header" "$(grep -oE 'ledger [0-9]+' "$TMP/f1.txt" | awk '{print ($2>=1)?"ge1":"zero"}')" "ge1"

echo "drvps-top crossframe: PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
