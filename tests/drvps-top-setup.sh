#!/usr/bin/env bash
# drvps-top INSTALL WIRING (S3): dr-vps-setup must install the viewer trust anchor + the publisher service +
# the three bin entry points, and remove them on uninstall. Plus a real end-to-end through the WRAPPERS:
# the publisher wrapper emits a valid feed, and the viewer wrapper renders it via the hostile-file protocol.
# ASCII only.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; SETUP="$REPO/bin/dr-vps-setup"; fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

# --- wiring (grep the installer source) ---
ok "step_top is in the install &&-chain"        'grep -qE "step_units && step_top && step_verify" "$SETUP"'
ok "installs the viewer trust anchor root:root 0644" 'grep -qE "install -m 0644 -o root -g root .* /etc/drvps-top/viewer.conf" "$SETUP"'
ok "viewer.conf pins feed_dir/mode/dir_mode/cap" 'grep -q "feed_dir=/run/drvps-top" "$SETUP" && grep -q "feed_mode=0640" "$SETUP" && grep -q "dir_mode=0710" "$SETUP" && grep -q "max_bytes=262144" "$SETUP"'
ok "viewer.conf feed_uid/gid come from drvps/drvpsctl numeric ids" 'grep -q "feed_uid=\$_uid" "$SETUP" && grep -q "feed_gid=\$_gid" "$SETUP"'
ok "publisher unit: User=drvps Group=drvpsctl RuntimeDirectory 0710" 'grep -q "User=\$DR_VPS_SERVICE_USER" "$SETUP" && grep -q "Group=\$DR_VPS_CTL_GROUP" "$SETUP" && grep -q "RuntimeDirectory=drvps-top" "$SETUP" && grep -q "RuntimeDirectoryMode=0710" "$SETUP"'
ok "publisher unit ExecStart -> the drvps-top-publish wrapper" 'grep -qE "ExecStart=\\\$root/bin/drvps-top-publish" "$SETUP"'
ok "publisher start failure is NON-FATAL (ancillary dashboard)" 'grep -q "non-fatal -- the viewer shows an absent/stale feed" "$SETUP"'
ok "uninstall disables + removes the publisher unit"  'grep -q "drvps-top-publish.service" "$SETUP" && grep -qE "rm -f .*drvps-top-publish.service" "$SETUP"'
ok "uninstall removes the viewer trust config dir"    'grep -qE "rm -rf /etc/drvps-top" "$SETUP"'

# --- the three bin entry points exist, are executable, resolve to the right tool ---
for b in drvps-top drvps-top-operator drvps-top-publish; do
  ok "bin/$b exists + executable" "[ -x \"$REPO/bin/$b\" ]"
done
ok "bin/drvps-top wraps the VIEWER"        'grep -q "tools/drvps_top_view.py" "$REPO/bin/drvps-top"'
ok "bin/drvps-top-operator wraps the bash TUI" 'grep -q "tools/drvps-top" "$REPO/bin/drvps-top-operator"'
ok "bin/drvps-top-publish wraps the PUBLISHER" 'grep -q "tools/drvps_top_publish.py" "$REPO/bin/drvps-top-publish"'

# --- end-to-end through the WRAPPERS (single-UID; the config is the numeric trust anchor) ---
if command -v sqlite3 >/dev/null 2>&1; then
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  DB="$T/store.db"
  sqlite3 "$DB" <<SQL
CREATE TABLE images(artifact_id TEXT PRIMARY KEY, kind TEXT, name TEXT, provenance TEXT, created_at TEXT);
CREATE TABLE vms(id TEXT PRIMARY KEY, owner_uid TEXT, class TEXT, domain_uuid TEXT, artifact_id TEXT, state TEXT, name TEXT, created_at TEXT, net TEXT, contract TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, name TEXT, parent_golden_id TEXT, secret_bearing INT, validation_status TEXT, created_at TEXT, bundle_relpath TEXT);
CREATE UNIQUE INDEX images_kind_name_uq ON images(kind,name); CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);
CREATE TRIGGER images_kind_ins BEFORE INSERT ON images BEGIN SELECT 1; END; CREATE TRIGGER images_kind_upd BEFORE UPDATE OF kind ON images BEGIN SELECT 1; END;
CREATE TRIGGER snapshots_ins BEFORE INSERT ON snapshots BEGIN SELECT 1; END; CREATE TRIGGER snapshots_upd BEFORE UPDATE ON snapshots BEGIN SELECT 1; END;
SQL
  VS="$T/virsh"; printf '#!/usr/bin/env bash\nfor a in "$@"; do case "$a" in list) exit 0;; domstats) exit 0;; esac; done\nexit 0\n' > "$VS"; chmod +x "$VS"
  FDIR="$T/run"; mkdir -p "$FDIR"; chmod 0710 "$FDIR"
  DRVPS_TOP_NO_ENV=1 DR_VPS_DB="$DB" DR_VIRSH="$VS" "$REPO/bin/drvps-top-publish" --once > "$FDIR/feed" 2>/dev/null; prc=$?
  chmod 0640 "$FDIR/feed"
  ok "drvps-top-publish wrapper --once -> a feed (rc 0)" '[ "$prc" = 0 ] && [ -s "$FDIR/feed" ]'
  CONF="$T/viewer.conf"
  printf 'feed_dir=%s\nfeed_name=feed\nfeed_uid=%d\nfeed_gid=%d\nfeed_mode=0640\ndir_mode=0710\nmax_bytes=262144\n' "$FDIR" "$(id -u)" "$(id -g)" > "$CONF"; chmod 0644 "$CONF"
  vout="$(DRVPS_TOP_CONFIG="$CONF" DR_TOP_CFG_UID="$(id -u)" DR_TOP_CFG_GID="$(id -g)" "$REPO/bin/drvps-top" --once 2>&1)"; vrc=$?
  ok "drvps-top viewer wrapper --once renders the published feed" '[ "$vrc" = 0 ] && printf "%s" "$vout" | grep -q "^drvps-top  seq="'
else
  echo "SKIP e2e (no sqlite3)"
fi

echo "-------------------------------------------"
echo "drvps-top setup wiring: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
