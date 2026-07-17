#!/usr/bin/env bash
# dr_vps_store.sh -- SQLite state store + referrer ledger + CAS (Stage 1).
# The store is the source of truth. Phase-1 tables: images, referrers (the GC
# invariant's basis), vms, overlays, networks, snapshots(schema-only).
# SQLite discipline: one quoting path (dr_vps_sql_str/int), BEGIN..COMMIT for
# multi-statement, never interpolate caller names into raw SQL by hand.
# ASCII only; bins run set -uo pipefail (code is also -e-safe).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"

# ---- quoting (the single safe path) ----------------------------------------------
dr_vps_sql_str() { local s="${1-}"; s="${s//\'/\'\'}"; printf "'%s'" "$s"; }
dr_vps_sql_int() {
  [[ "${1-}" =~ ^-?[0-9]+$ ]] || { dr_vps_die "$DR_VPS_E_USAGE" "not an integer: ${1-}"; return $?; }
  printf '%s' "$1"
}

# Run SQL (arg) against the store with a busy timeout (silent .timeout, not PRAGMA).
dr_vps_sql() { printf '.bail on\n.timeout 5000\n%s' "$1" | "$DR_SQLITE" -batch "$DR_VPS_DB"; }   # .bail: a statement error ABORTS (atomic), never falls to autocommit

# Run a single-row UPDATE and PROVE exactly one row changed. sqlite returns success even when the
# WHERE matches ZERO rows (the row was deleted/lost), so an unchecked UPDATE can silently no-op; this
# appends SELECT changes() and fails unless it is 1. Use for every must-affect-one-row mutation.
dr_vps_sql_update1() {  # <update-statement-with-trailing-semicolon>
  local n; n=$(dr_vps_sql "$1 SELECT changes();") || return 1
  [ "$n" = 1 ]
}

dr_vps_store_init() {
  mkdir -p "$(dirname "$DR_VPS_DB")"
  dr_vps_sql "
CREATE TABLE IF NOT EXISTS images(
  artifact_id TEXT PRIMARY KEY,
  provenance  TEXT NOT NULL,
  golden_path TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'golden' CHECK(kind IN ('golden','snapshot')),  -- SNAPSHOT feature: a
                                             -- KIND-tagged artifact ledger; 'row in images' is NOT proof of
                                             -- golden trust. Typed resolvers gate golden-vs-snapshot use.
  name        TEXT,                          -- human handle (goldens optional; snapshots required)
  created_at  TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS referrers(
  artifact_id TEXT NOT NULL,
  kind        TEXT NOT NULL,
  ref_id      TEXT NOT NULL,
  PRIMARY KEY(artifact_id,kind,ref_id));
CREATE TABLE IF NOT EXISTS vms(
  id          TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  overlay     TEXT,
  egress_gen  TEXT NOT NULL DEFAULT '0',   -- INFORMATIONAL only (H-1): the ENFORCED egress-freshness
                                           -- authority is the root-owned /run marker vs the fleet
                                           -- hash (dr_vps_net_create_guard), NOT this per-VM column;
                                           -- the guestexec gate does not read it. Do not trust it
                                           -- as policy state. See CONCEPT s4 / dr_vps_net.sh.
  ttl_hours   INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL DEFAULT 'pending',
  generation  INTEGER NOT NULL DEFAULT 0,
  name        TEXT, project TEXT,
  domain_uuid TEXT,                                    -- libvirt UUID (Phase-2 gate identity)
  net         TEXT,                                    -- the create-time simnet; recreate re-renders
                                                       -- on THIS, not a hardcoded default
  contract    TEXT,                                    -- Stage-0: resolved VM-contract snapshot (canonical
                                                       -- k=v lines; set_contract validates); legacy NULL
  owner_uid   TEXT,                                    -- S0 (service plane): client OS uid from SO_PEERCRED at
                                                       -- ingress; NULL = direct operator (admin), SAME convention
                                                       -- as snapshots.owner_uid. S1a owner-scoping + the S5
                                                       -- result ACL read and enforce it.
  class       TEXT NOT NULL DEFAULT 'throwaway',       -- S0 (service plane): throwaway = default reaped VM;
                                                       -- service = long-lived (S1b). NOT NULL + a literal default
                                                       -- (owner_uid instead stays NULL = operator): class carries no
                                                       -- second meaning, and a NULL row would be EXCLUDED by the
                                                       -- reaper inequality compare on class (a SQL NULL footgun),
                                                       -- silently never-reaping it. UNREAD until S1b.
  created_at  TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS overlays(
  path TEXT PRIMARY KEY, vm_id TEXT NOT NULL, artifact_id TEXT NOT NULL);
-- RESERVED (H-1): the networks table + dr_vps_store_net_record/_egress_gen have no runtime callers;
-- the enforced egress authority is the /run marker (dr_vps_net_create_guard), not this table. Kept
-- (schema-stable) for a future per-network policy-staleness feature; do not treat as live state.
CREATE TABLE IF NOT EXISTS networks(
  name TEXT PRIMARY KEY, egress_gen TEXT NOT NULL DEFAULT '0');
-- DR-6 (per-run network modes): the per-group net record. ISOLATED/ROUTED ONLY -- shared/simnet NEVER
-- appears here, so the shared marker + path stay store-INDEPENDENT (concept s5.2 / s7.1). Owner-namespaced by
-- the authenticated principal; group_id is a sanitized caller LABEL, not an authority. state = the s5.1 lifecycle
-- machine; generation = the per-group canonical marker; nonce = bridge-name re-salt on collision.
CREATE TABLE IF NOT EXISTS net_groups(
  owner       TEXT NOT NULL,
  group_id    TEXT NOT NULL,
  mode        TEXT NOT NULL CHECK(mode IN ('isolated','routed')),
  bridge      TEXT,                                   -- drb-<hex(owner,group)> (NULL until allocated)
  subnet      TEXT,                                   -- e.g. 10.124.<h>.0/24 (locked-allocated; concept s5)
  gw_ip       TEXT,                                   -- host IP on the group bridge = the group dnsmasq endpoint
  dhcp_range  TEXT,                                   -- must prove-inside subnet at gate (concept s5.3)
  lan_cidrs   TEXT NOT NULL DEFAULT '[]',             -- JSON array: routed declared-LAN CIDRs (schema-validated)
  state       TEXT NOT NULL DEFAULT 'allocating'
              CHECK(state IN ('allocating','pending','live','destroying','gone')),
  generation  TEXT NOT NULL DEFAULT '0',              -- per-group canonical marker generation (concept s5.2)
  nonce       INTEGER NOT NULL DEFAULT 0,             -- deterministic bridge-name re-salt on collision (s5.1)
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(owner, group_id));
CREATE TABLE IF NOT EXISTS snapshots(
  id TEXT PRIMARY KEY,                        -- = the snapshot content id (== images.artifact_id, drvps-snap-v1-*)
  vm_id TEXT NOT NULL, artifact_id TEXT NOT NULL,  -- LEGACY stub cols (mirror source_vm_id/parent_golden_id);
                                             -- kept NOT NULL so a FRESH db has the SAME shape a MIGRATED stub
                                             -- reaches after ALTER -> one INSERT path works on both.
  secret_bearing INTEGER NOT NULL DEFAULT 0 CHECK(secret_bearing IN (0,1)),
  name TEXT,                                 -- human handle (drvps-snap-<distro>-<UTC>-<short8>)
  source_vm_id TEXT,                         -- the VM snapshotted (provenance, not an FK)
  parent_golden_id TEXT,                     -- the golden it was installed on (provenance, NOT a disk dep/FK)
  bundle_relpath TEXT,                       -- relative '<id>' under DR_VPS_SNAP_DIR (fence on read)
  scrub_profile TEXT, shutdown_mode TEXT, validation_status TEXT, notes TEXT,
  owner_uid TEXT,                            -- OWNER SCOPING: the client OS uid (from SO_PEERCRED at ingress);
                                             -- NULL = created by the direct operator (admin). Enforced at the
                                             -- verb layer (a client op carries --owner; the operator does not).
  created_at TEXT NOT NULL DEFAULT (datetime('now')));"
  # MIGRATION: add domain_uuid to a pre-Phase-2 vms table (idempotent; ignore "duplicate column").
  if [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('vms') WHERE name='domain_uuid';")" ]; then
    dr_vps_sql "ALTER TABLE vms ADD COLUMN domain_uuid TEXT;" 2>/dev/null || true
  fi
  # MIGRATION: add `net` to a pre-existing vms table so recreate can re-render on the VM's
  # own create-time network instead of a hardcoded default. Legacy rows get NULL -> recreate falls
  # back to DR_VPS_RECREATE_NET (simnet), preserving old behavior for VMs created before this column.
  if [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('vms') WHERE name='net';")" ]; then
    dr_vps_sql "ALTER TABLE vms ADD COLUMN net TEXT;" 2>/dev/null || true
  fi
  # MIGRATION (Stage-0): add `contract` -- the resolved VM-contract snapshot. Legacy rows get NULL ->
  # inspect reports "unrecorded" (not an error); canonical k=v is enforced by set_contract, not the column.
  if [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('vms') WHERE name='contract';")" ]; then
    dr_vps_sql "ALTER TABLE vms ADD COLUMN contract TEXT;" 2>/dev/null || true
  fi
  # MIGRATION (S0 service plane): add owner_uid + class to a pre-existing vms table. Legacy rows get NULL:
  # owner_uid NULL = operator-owned (S1a treats a client op as not-found on it -- NOT a wildcard); class
  # NULL = throwaway. Both are UNREAD until S1a/S1b, so this is a behavioral no-op on an existing host.
  if [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('vms') WHERE name='owner_uid';")" ]; then
    dr_vps_sql "ALTER TABLE vms ADD COLUMN owner_uid TEXT;" 2>/dev/null || true
  fi
  if [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('vms') WHERE name='class';")" ]; then
    # NOT NULL + constant default: SQLite backfills EVERY existing row to 'throwaway' (a NULL class would be
    # excluded by the reaper's `class != 'service'` compare -> silently never-reaped). owner_uid stays NULL.
    dr_vps_sql "ALTER TABLE vms ADD COLUMN class TEXT NOT NULL DEFAULT 'throwaway';" 2>/dev/null || true
  fi
  # POST-MIGRATION INVARIANT: the Phase-2 + S0 columns MUST exist now. The ALTERs swallow errors
  # (to tolerate the benign "duplicate column"), so a REAL failure (disk/corruption) would otherwise
  # pass silently -- and get_net reading a MISSING column as empty would be mistaken for a legacy
  # NULL net, driving recreate down the simnet fallback instead of failing. FAIL CLOSED here instead.
  local _c
  for _c in domain_uuid net contract owner_uid class; do
    [ -n "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('vms') WHERE name='$_c';")" ] \
      || { dr_vps_die "$DR_VPS_E_GENERIC" "store: vms.$_c missing after migration -- schema failure"; return $?; }
  done

  # ---- SNAPSHOT feature migration (idempotent; a FRESH db already has these from the CREATEs above) ----
  # images: add kind (constant default -> ALTER-safe) + name. snapshots: add the snapshot-bundle columns, all
  # NULLABLE (SQLite ALTER cannot add NOT NULL / UNIQUE / a non-constant default) -- the triggers below
  # enforce NOT-NULL + value ranges on both the fresh and the migrated shapes.
  # CONCURRENCY: the ADD COLUMN statements are the only non-idempotent-under-race part; guard
  # them with a MIGRATION FLOCK so two concurrent first-inits can't see a half-added column set. Gated on
  # migration-needed so the post-migration hot path stays lock-free; BEST-EFFORT (a flock hiccup degrades to
  # the prior behavior -- the IF-NOT-EXISTS + fail-closed post-checks still protect).
  local _mfd=""
  if [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('images') WHERE name='kind';")" ] \
     || [ -z "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('snapshots') WHERE name='bundle_relpath';")" ]; then
    if exec {_mfd}>"${DR_VPS_DB}.migrate.lock" 2>/dev/null; then
      # CLOSE the fd if the lock ACQUIRE fails (else _mfd="" would skip the close below -> fd leak).
      "${DR_FLOCK:-flock}" -w 10 "$_mfd" 2>/dev/null || { exec {_mfd}>&-; _mfd=""; }
    else
      _mfd=""
    fi
  fi
  [ -n "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('images') WHERE name='kind';")" ] \
    || dr_vps_sql "ALTER TABLE images ADD COLUMN kind TEXT NOT NULL DEFAULT 'golden';" 2>/dev/null || true
  [ -n "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('images') WHERE name='name';")" ] \
    || dr_vps_sql "ALTER TABLE images ADD COLUMN name TEXT;" 2>/dev/null || true
  for _c in name source_vm_id parent_golden_id bundle_relpath scrub_profile shutdown_mode validation_status notes owner_uid created_at; do
    [ -n "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('snapshots') WHERE name='$_c';")" ] \
      || dr_vps_sql "ALTER TABLE snapshots ADD COLUMN $_c TEXT;" 2>/dev/null || true
  done
  [ -n "$_mfd" ] && { exec {_mfd}>&-; } || true   # release the migration lock (if held)
  # Unique-name indexes + CHECK/NOT-NULL triggers AFTER the ALTERs (they reference post-migration columns).
  dr_vps_sql "
CREATE UNIQUE INDEX IF NOT EXISTS images_kind_name_uq ON images(kind,name) WHERE name IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS snapshots_name_uq   ON snapshots(name)    WHERE name IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS images_kind_ins BEFORE INSERT ON images
  WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'invalid images.kind'); END;
CREATE TRIGGER IF NOT EXISTS images_kind_upd BEFORE UPDATE OF kind ON images
  WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'invalid images.kind'); END;
CREATE TRIGGER IF NOT EXISTS snapshots_ins BEFORE INSERT ON snapshots
  WHEN NEW.name IS NULL OR NEW.source_vm_id IS NULL OR NEW.parent_golden_id IS NULL
    OR NEW.bundle_relpath IS NULL OR NEW.scrub_profile IS NULL OR NEW.created_at IS NULL
    OR NEW.shutdown_mode NOT IN ('clean','forced')
    OR NEW.validation_status NOT IN ('passed','skipped','failed')
    OR NEW.secret_bearing NOT IN (0,1)
  BEGIN SELECT RAISE(ABORT,'invalid snapshots row'); END;
CREATE TRIGGER IF NOT EXISTS snapshots_upd BEFORE UPDATE ON snapshots
  WHEN NEW.name IS NULL OR NEW.source_vm_id IS NULL OR NEW.parent_golden_id IS NULL
    OR NEW.bundle_relpath IS NULL OR NEW.scrub_profile IS NULL OR NEW.created_at IS NULL
    OR NEW.shutdown_mode NOT IN ('clean','forced')
    OR NEW.validation_status NOT IN ('passed','skipped','failed')
    OR NEW.secret_bearing NOT IN (0,1)
  BEGIN SELECT RAISE(ABORT,'invalid snapshots row'); END;" 2>/dev/null || true
  # POST-MIGRATION column-existence (fail-closed, like the vms loop above).
  for _c in kind name; do
    [ -n "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('images') WHERE name='$_c';")" ] \
      || { dr_vps_die "$DR_VPS_E_GENERIC" "store: images.$_c missing after migration -- schema failure"; return $?; }
  done
  for _c in name source_vm_id parent_golden_id bundle_relpath scrub_profile shutdown_mode validation_status notes owner_uid created_at; do
    [ -n "$(dr_vps_sql "SELECT 1 FROM pragma_table_info('snapshots') WHERE name='$_c';")" ] \
      || { dr_vps_die "$DR_VPS_E_GENERIC" "store: snapshots.$_c missing after migration -- schema failure"; return $?; }
  done
  # POST-MIGRATION ENFORCEMENT verification : the UNIQUE indexes + CHECK triggers MUST exist. A CREATE
  # that hit a pre-existing duplicate-name (or was swallowed) would leave the store running WITHOUT the promised
  # uniqueness/NULL/range enforcement -- fail CLOSED here. Runs even under LENIENT (schema, not a data invariant).
  # check TYPE too, not just name : a pre-planted TABLE named e.g. `snapshots_name_uq` would let the
  # CREATE UNIQUE INDEX fail (name taken) + a name-only check pass -> enforcement silently absent.
  local _obj
  for _obj in images_kind_name_uq snapshots_name_uq; do
    [ -n "$(dr_vps_sql "SELECT 1 FROM sqlite_master WHERE type='index' AND name='$_obj';")" ] \
      || { dr_vps_die "$DR_VPS_E_GENERIC" "store: required UNIQUE index '$_obj' missing (migration/enforcement failure)"; return $?; }
  done
  for _obj in images_kind_ins images_kind_upd snapshots_ins snapshots_upd; do
    [ -n "$(dr_vps_sql "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='$_obj';")" ] \
      || { dr_vps_die "$DR_VPS_E_GENERIC" "store: required CHECK trigger '$_obj' missing (migration/enforcement failure)"; return $?; }
  done
  # POST-MIGRATION data invariants (fail-closed): kind valid; NO prefix/kind crossing; snapshot<->images
  # bijection. A nonzero total => refuse to operate on an inconsistent store. LENIENT mode
  # (DR_VPS_STORE_LENIENT_INIT=1) does the migration + column checks but SKIPS this abort, so a DIAGNOSTIC
  # verb (snap-fsck) can actually RUN and REPORT the corruption instead of being blocked by it .
  [ "${DR_VPS_STORE_LENIENT_INIT:-0}" = 1 ] && return 0
  local _inv
  _inv=$(dr_vps_sql "SELECT
      (SELECT COUNT(*) FROM images WHERE kind NOT IN ('golden','snapshot'))
    + (SELECT COUNT(*) FROM images WHERE (kind='golden'   AND artifact_id NOT GLOB 'drvps-raw-v1-*')
                                      OR (kind='snapshot' AND artifact_id NOT GLOB 'drvps-snap-v1-*'))
    + (SELECT COUNT(*) FROM images i WHERE i.kind='snapshot'
         AND NOT EXISTS(SELECT 1 FROM snapshots s WHERE s.id=i.artifact_id))
    + (SELECT COUNT(*) FROM snapshots s
         WHERE NOT EXISTS(SELECT 1 FROM images i WHERE i.artifact_id=s.id AND i.kind='snapshot'));")
  case "$_inv" in
    0) : ;;
    ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "store: post-migration invariant query failed"; return $? ;;
    *) dr_vps_die "$DR_VPS_E_GENERIC" "store: $_inv snapshot/kind invariant violation(s) -- refusing an inconsistent store"; return $? ;;
  esac
}

# Set the libvirt UUID for a VM (captured at create, used by the Phase-2 gate).
dr_vps_store_vm_set_uuid() {  # <id> <uuid>
  dr_vps_sql_update1 "UPDATE vms SET domain_uuid=$(dr_vps_sql_str "$2") WHERE id=$(dr_vps_sql_str "$1");"
}

# Set / read the VM's create-time network: recreate re-renders on this, not a fixed default.
dr_vps_store_vm_set_net() {  # <id> <net>
  dr_vps_sql_update1 "UPDATE vms SET net=$(dr_vps_sql_str "$2") WHERE id=$(dr_vps_sql_str "$1");"
}
dr_vps_store_vm_get_net() {  # <id> -> net (empty for a genuine legacy NULL); NONZERO rc on a read error
  # No 2>/dev/null: a SQL/DB error must surface (to the journal) AND propagate its nonzero rc, so the
  # caller can tell a genuine empty (legacy NULL, rc 0) from a failed read (rc!=0) -- recreate fails
  # CLOSED on the latter instead of mistaking it for "legacy -> default net".
  dr_vps_sql "SELECT IFNULL(net,'') FROM vms WHERE id=$(dr_vps_sql_str "$1");"
}

# Stage-0 R0: the resolved VM-contract snapshot. CANONICAL + LINE-SAFE format so set/get cannot round-trip a
# string a later consumer reparses differently: newline-separated `key=value` lines, keys sorted + UNIQUE,
# key matches [a-z][a-z0-9_.]*, value is one-or-more of [A-Za-z0-9_.:+/-] (NO whitespace/newline in a value, so
# a value can never smuggle a fake line). Rejects blank lines, malformed k=v, empty key/value, dup/unsorted keys.
_dr_vps_contract_canonical() {  # <contract> -> rc 0 valid; nonzero invalid (no output)
  local c="${1-}" line k v keys=""
  [ -n "$c" ] || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || return 1                                   # no blank lines
    case "$line" in *=*) ;; *) return 1 ;; esac                  # must contain '='
    k=${line%%=*}; v=${line#*=}
    [ -n "$k" ] && [ -n "$v" ] || return 1                       # non-empty key AND value
    case "$k" in [!a-z]* | *[!a-z0-9_.]*) return 1 ;; esac        # key: [a-z][a-z0-9_.]*
    case "$v" in *[!A-Za-z0-9_.:+/-]*) return 1 ;; esac           # value charset (no ws/newline)
    keys="${keys}${k}
"
  done <<< "$c"
  # sorted + unique: the keys as-emitted must equal an LC_ALL=C sort -u of themselves. Both sides through
  # $(...) so the trailing newline is stripped consistently (else the compare never matches).
  [ "$(printf '%s' "$keys")" = "$(printf '%s' "$keys" | LC_ALL=C sort -u)" ] || return 1
  return 0
}

dr_vps_store_vm_set_contract() {  # <id> <contract> -- validate canonical, then persist (fails on a missing id)
  _dr_vps_contract_canonical "${2-}" \
    || { dr_vps_die "$DR_VPS_E_USAGE" "store: non-canonical/unsafe contract for '$1'"; return $?; }
  dr_vps_sql_update1 "UPDATE vms SET contract=$(dr_vps_sql_str "$2") WHERE id=$(dr_vps_sql_str "$1");"
}

dr_vps_store_vm_get_contract() {  # <id> -> contract (empty for a legacy NULL); NONZERO rc on a read error
  # Same read-error discipline as get_net: no 2>/dev/null, so a genuine empty (legacy NULL, rc 0) is
  # distinguishable from a failed read (rc!=0) and the caller can fail closed.
  dr_vps_sql "SELECT IFNULL(contract,'') FROM vms WHERE id=$(dr_vps_sql_str "$1");"
}

# Full row the Phase-2 gate needs: "overlay|artifact_id|egress_gen|domain_uuid|state|net" (empty if none).
# `net` is last (appended) so the gate validates the VM's RECORDED net -- consistent with recreate --
# not the watcher's env DR_VPS_RIG_NET. Legacy rows read empty net -> gate env-fallback.
dr_vps_store_vm_gaterow() {  # <id>
  dr_vps_sql "SELECT IFNULL(overlay,'')||'|'||artifact_id||'|'||egress_gen||'|'||IFNULL(domain_uuid,'')||'|'||state||'|'||IFNULL(net,'')
    FROM vms WHERE id=$(dr_vps_sql_str "$1");" 2>/dev/null
}

# ---- referrer ledger -------------------------------------------------------------
# NOTE: ref_add/ref_del are INTERNAL primitives (no FK enforcement on the schema).
# Public callers use the typed flows (vm_create / overlay_add) which insert the row and
# its referrer in ONE transaction. Do not add arbitrary referrers from outside the lib.
dr_vps_store_ref_add() {  # <artifact_id> <kind> <ref_id>
  dr_vps_sql "INSERT OR IGNORE INTO referrers(artifact_id,kind,ref_id)
    VALUES($(dr_vps_sql_str "$1"),$(dr_vps_sql_str "$2"),$(dr_vps_sql_str "$3"));"
}
dr_vps_store_ref_del() {  # <artifact_id> <kind> <ref_id>
  dr_vps_sql "DELETE FROM referrers WHERE artifact_id=$(dr_vps_sql_str "$1")
    AND kind=$(dr_vps_sql_str "$2") AND ref_id=$(dr_vps_sql_str "$3");"
}
dr_vps_store_image_refcount() {  # -> integer (number of referrers)
  dr_vps_sql "SELECT COUNT(*) FROM referrers WHERE artifact_id=$(dr_vps_sql_str "$1");"
}

# ---- images ----------------------------------------------------------------------
dr_vps_store_image_register() {  # <artifact_id> <provenance_json> <golden_path>
  local aid="$1" prov="$2" path="$3" out cnt epath qa
  printf '%s' "$prov" | jq -e . >/dev/null 2>&1 || { dr_vps_die "$DR_VPS_E_GENERIC" "provenance not JSON"; return $?; }
  qa=$(dr_vps_sql_str "$aid")
  # One transaction: read pre-state, insert iff new. Idempotent on identical (artifact,
  # path); a same-id re-register at a DIFFERENT golden_path is a conflict (15), never a
  # silent ignore. (provenance.built_at legitimately varies on rebuild of identical
  # content -- the content-addressed path is the stable invariant, so we compare path.)
  out=$(dr_vps_sql "BEGIN IMMEDIATE;
    SELECT COUNT(*)||'|'||COALESCE((SELECT golden_path FROM images WHERE artifact_id=$qa),'') FROM images WHERE artifact_id=$qa;
    INSERT INTO images(artifact_id,provenance,golden_path)
      SELECT $qa,$(dr_vps_sql_str "$prov"),$(dr_vps_sql_str "$path")
      WHERE (SELECT COUNT(*) FROM images WHERE artifact_id=$qa)=0;
    COMMIT;") || { dr_vps_die "$DR_VPS_E_GENERIC" "image register db write failed: $aid"; return $?; }
  cnt=${out%%|*}; epath=${out#*|}
  case "$cnt" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "image register: unreadable db result for $aid"; return $?;; esac
  if [ "$cnt" -eq 1 ] && [ "$epath" != "$path" ]; then
    dr_vps_die "$DR_VPS_E_CONFLICT" "image $aid already registered at a different path"; return $?
  fi
}
dr_vps_store_image_get() {  # <artifact_id> -> golden_path|provenance  (empty if none)
  dr_vps_sql "SELECT golden_path FROM images WHERE artifact_id=$(dr_vps_sql_str "$1");"
}
dr_vps_store_image_ls() {
  dr_vps_sql "SELECT artifact_id FROM images ORDER BY created_at;"
}
# Refcount-gated delete -- ATOMIC: count-check and delete in one BEGIN IMMEDIATE txn so
# no referrer can slip in between. Refuse (19) while any referrer exists.
dr_vps_store_image_delete() {  # <artifact_id>  -- GOLDEN-only; refuses a snapshot (use snap-rm) so a
                               # generic unreferenced-image sweep can NEVER prune a snapshot or orphan its
                               # authoritative snapshots row (CONCEPT R3.1 kind-dispatched GC).
  local qa refs _k _krc; qa=$(dr_vps_sql_str "$1")
  # FAIL CLOSED on a DB read error: an errored kind read must NOT pass the "not a snapshot"
  # guard (empty != snapshot) and let the generic GC delete a snapshot's images row (orphaning its authoritative
  # snapshots row -- violating "generic GC can never prune a snapshot"). rc-check the guard; AND scope the DELETE
  # itself to kind='golden' (belt-and-suspenders -- the delete can never touch a snapshot row even if reached).
  _k=$(dr_vps_sql "SELECT kind FROM images WHERE artifact_id=$qa;"); _krc=$?
  [ "$_krc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "image_delete: kind lookup failed (db read error): $1"; return $?; }
  [ "$_k" != snapshot ] || { dr_vps_die "$DR_VPS_E_USAGE" "image_delete refuses a snapshot artifact ($1) -- use snap-rm"; return $?; }
  refs=$(dr_vps_sql "BEGIN IMMEDIATE;
    SELECT COUNT(*) FROM referrers WHERE artifact_id=$qa;
    DELETE FROM images WHERE artifact_id=$qa AND kind='golden'
      AND (SELECT COUNT(*) FROM referrers WHERE artifact_id=$qa)=0;
    COMMIT;") || { dr_vps_die "$DR_VPS_E_GENERIC" "image delete db write failed: $1"; return $?; }
  case "$refs" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "image delete: unreadable db result for $1"; return $?;; esac
  [ "$refs" -eq 0 ] || { dr_vps_die "$DR_VPS_E_REFERENCED" "image $1 still has $refs referrer(s)"; return $?; }
}

# ---- vms -------------------------------------------------------------------------
dr_vps_store_vm_create() {  # <id> <artifact_id> <overlay> <egress_gen> <ttl> [name] [project] [expected_kind=golden] [owner_uid] [class]
  local id="$1" aid="$2" overlay="$3" egen="$4" ttl="$5" name="${6:-}" proj="${7:-default}" expkind="${8:-golden}"
  local owner="${9:-}" class="${10:-throwaway}"  # owner: '' -> SQL NULL = operator. class: '' -> 'throwaway' (NOT NULL col)
  [ -n "$class" ] || class=throwaway             # an explicit empty string also means the default
  local qid qaid qkind out img dup qowner qclass
  case "$expkind" in golden|snapshot) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "vm_create: bad expected_kind '$expkind'"; return $?;; esac
  # owner is a numeric OS uid or empty (empty = direct operator). Same guard as the snapshot store, so a
  # malformed owner FAILS instead of silently storing garbage that a later owner check would compare against.
  case "$owner" in ''|*[!0-9]*) [ -z "$owner" ] || { dr_vps_die "$DR_VPS_E_USAGE" "vm_create: owner_uid must be a numeric uid: $owner"; return $?; };; esac
  dr_vps_sql_int "$ttl"  >/dev/null || return $?          # egress_gen is TEXT (content hash)
  qid=$(dr_vps_sql_str "$id"); qaid=$(dr_vps_sql_str "$aid"); qkind=$(dr_vps_sql_str "$expkind")
  if [ -n "$owner" ]; then qowner=$(dr_vps_sql_str "$owner"); else qowner=NULL; fi   # omitted -> SQL NULL, never ''
  qclass=$(dr_vps_sql_str "$class")                        # always a value (NOT NULL): 'throwaway' or the given class
  # ONE transaction: read pre-state (image-exists-OF-THE-EXPECTED-KIND, id-dup), then insert the vm AND its
  # referrer together iff image exists and id is new. Closes the crash/interleave gap where a vm row could
  # outlive a missing referrer and let its golden be deleted. The `AND kind=$qkind` makes creation TYPED --
  # a golden create refuses a snapshot artifact and vice-versa (snapshot segregation, CONCEPT R3.1).
  out=$(dr_vps_sql "BEGIN IMMEDIATE;
    SELECT (SELECT COUNT(*) FROM images WHERE artifact_id=$qaid AND kind=$qkind)||'|'||(SELECT COUNT(*) FROM vms WHERE id=$qid);
    INSERT INTO vms(id,artifact_id,overlay,egress_gen,ttl_hours,name,project,owner_uid,class)
      SELECT $qid,$qaid,$(dr_vps_sql_str "$overlay"),$(dr_vps_sql_str "$egen"),$ttl,$(dr_vps_sql_str "$name"),$(dr_vps_sql_str "$proj"),$qowner,$qclass
      WHERE (SELECT COUNT(*) FROM images WHERE artifact_id=$qaid AND kind=$qkind)=1
        AND (SELECT COUNT(*) FROM vms WHERE id=$qid)=0;
    INSERT OR IGNORE INTO referrers(artifact_id,kind,ref_id)
      SELECT $qaid,'vm',$qid
      WHERE (SELECT COUNT(*) FROM vms WHERE id=$qid AND artifact_id=$qaid)=1;
    COMMIT;") || { dr_vps_die "$DR_VPS_E_GENERIC" "vm_create db write failed: $id"; return $?; }
  img=${out%%|*}; dup=${out##*|}
  case "$img$dup" in *[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "vm_create: unreadable db result for $id"; return $?;; esac
  [ "$img" -eq 1 ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such image (kind=$expkind): $aid"; return $?; }
  [ "$dup" -eq 0 ] || { dr_vps_die "$DR_VPS_E_CONFLICT" "vm id already exists: $id"; return $?; }
}
# Typed create wrappers (CONCEPT R3.1): callers should use these, not the kind-defaulted core.
dr_vps_store_vm_create_from_golden()   { dr_vps_store_vm_create "$1" "$2" "$3" "$4" "$5" "${6:-}" "${7:-default}" golden   "${8:-}" "${9:-}"; }   # [owner] [class]
dr_vps_store_vm_create_from_snapshot() { dr_vps_store_vm_create "$1" "$2" "$3" "$4" "$5" "${6:-}" "${7:-default}" snapshot "${8:-}" "${9:-}"; }   # [owner] [class]
dr_vps_store_vm_get() {  # <id> -> "state|generation|artifact_id|egress_gen"  (empty if none)
  dr_vps_sql "SELECT state||'|'||generation||'|'||artifact_id||'|'||egress_gen
    FROM vms WHERE id=$(dr_vps_sql_str "$1");"
}
# S1a: owner-scoped VM existence check. If [owner_uid] is given, resolve ONLY a row owned by that uid, so a
# non-owner CLIENT resolves NOTHING (caller sees not-found, no existence leak). NULL owner_uid = operator:
# a client never matches it (owner_uid=$own is false/NULL for a NULL row). The direct operator passes NO
# owner -> matches any row (admin). FAIL CLOSED on a DB read error (nonzero rc + empty output) so a transient
# error can never be mistaken for "owner matched". Mirrors dr_vps_store_snapshot_id.
dr_vps_store_vm_id_owned() {  # <id> [owner_uid] -> echoes id if it exists (owner-scoped); nonzero+empty on db error
  local q own oc r rc; q=$(dr_vps_sql_str "$1"); own="${2:-}"; oc=""
  [ -n "$own" ] && oc=" AND owner_uid=$(dr_vps_sql_str "$own")"
  r=$(dr_vps_sql "SELECT id FROM vms WHERE id=$q$oc LIMIT 1;"); rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  [ -n "$r" ] && printf '%s\n' "$r"
  return 0
}
# S1a: run a per-VM verb owner-scoped + serialized. Resolve <vm> for [owner] (a foreign uid -- or a NULL-owner
# operator row for a client -- resolves to NOTHING -> E_NOTFOUND, no existence leak); take the per-VM lock;
# REVALIDATE ownership UNDER the lock (a concurrent operator destroy+recreate must not swap the id between the
# caller's resolve and its action -- the watcher's single request queue does NOT serialize a DIRECT dr-vps
# invocation); then run "$@" holding the lock, releasing it whatever the action returns. owner '' = direct
# operator (matches any row). Mirrors the resolve->lock->revalidate idiom of dr_vps_snapshot.sh use/rm.
dr_vps_vm_do_owned() {  # <vm> <owner_uid|''> <cmd> [args...]
  local vm="$1" own="$2"; shift 2
  local id lockdir="${DR_VPS_STATE_DIR}/locks" fd rc
  id=$(dr_vps_store_vm_id_owned "$vm" "$own") || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such vm: $vm"; return $?; }
  [ -n "$id" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such vm: $vm"; return $?; }
  mkdir -p "$lockdir"
  exec {fd}>"${lockdir}/vm-${id}.lock" || { dr_vps_die "$DR_VPS_E_GENERIC" "vm lock open failed: $id"; return $?; }
  if ! flock "$fd"; then exec {fd}>&-; dr_vps_die "$DR_VPS_E_GENERIC" "vm lock acquire failed: $id"; return $?; fi
  if [ -z "$(dr_vps_store_vm_id_owned "$id" "$own")" ]; then
    exec {fd}>&-; dr_vps_die "$DR_VPS_E_NOTFOUND" "vm $vm changed under lock (no longer resolves for this owner)"; return $?
  fi
  "$@"; rc=$?
  exec {fd}>&-
  return "$rc"
}
# S1a: lightweight owner GUARD for the guest verbs (exec/pull/push/console-dump/exec-detach). If an owner was
# stamped (the agent path -- the watcher passes --owner), the VM MUST resolve for that owner or this DIES
# E_NOTFOUND (a co-tenant, or a NULL-owner operator row seen by a client, resolves to nothing). Owner '' =
# the direct OPERATOR *or an INTERNAL call* (the job machinery calls dr_vps_exec/pull/push with no --owner) ->
# no check, unchanged. Unlike the lifecycle verbs, these do NOT hold the per-VM lock across the action: they
# are serialized by the single request queue and re-validated by the guestexec gate at the SSH, and wrapping
# them would deadlock the many INTERNAL exec/pull/push calls in the detached-job state machine. (The residual
# operator-race TOCTOU is the one item to revisit with a lock under a future CODE review gate.)
dr_vps_vm_assert_owned() {  # <vm> <owner_uid|''>
  [ -z "$2" ] && return 0
  [ -n "$(dr_vps_store_vm_id_owned "$1" "$2")" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "no such vm: $1"; return $?; }
}
dr_vps_store_vm_ls() {  # all vms: "id  state  name  artifact_id"
  dr_vps_sql "SELECT id||'  '||state||'  '||COALESCE(name,'')||'  '||artifact_id FROM vms ORDER BY created_at;"
}
dr_vps_store_vm_set_state() {  # <id> <state>
  dr_vps_sql_update1 "UPDATE vms SET state=$(dr_vps_sql_str "$2") WHERE id=$(dr_vps_sql_str "$1");"
}
# CAS on generation: succeeds only if current==expected; else 15 (stale writer).
# RESERVED (H-1): no runtime caller today -- recreate bumps generation inline in its own checked
# UPDATE. Kept as a tested primitive for a future optimistic-concurrency writer; not dead-strip it.
dr_vps_store_vm_cas_generation() {  # <id> <expected> <new>
  dr_vps_sql_int "$2" >/dev/null || return $?; dr_vps_sql_int "$3" >/dev/null || return $?
  local out
  out=$(dr_vps_sql "BEGIN IMMEDIATE;
    UPDATE vms SET generation=$3 WHERE id=$(dr_vps_sql_str "$1") AND generation=$2;
    SELECT changes();
    COMMIT;") \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "generation CAS db error for $1"; return $?; }   # distinguish DB error from CONFLICT
  case "$out" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "generation CAS unreadable result for $1"; return $?;; esac
  [ "$out" -eq 1 ] || { dr_vps_die "$DR_VPS_E_CONFLICT" "generation CAS failed for $1 (expected $2)"; return $?; }
}
dr_vps_store_vm_delete() {  # <id>  -- drops vm + its referrer + overlays + overlay referrers
  local q; q=$(dr_vps_sql_str "$1")
  dr_vps_sql "BEGIN IMMEDIATE;
    DELETE FROM referrers WHERE kind='overlay' AND ref_id IN (SELECT path FROM overlays WHERE vm_id=$q);
    DELETE FROM overlays WHERE vm_id=$q;
    DELETE FROM referrers WHERE kind='vm' AND ref_id=$q;
    DELETE FROM vms WHERE id=$q;
    COMMIT;"
}

# ---- overlays / networks ---------------------------------------------------------
dr_vps_store_overlay_add() {  # <vm_id> <overlay_path> <artifact_id>
  # ONE transaction: clear any prior overlay row + its (possibly different-artifact)
  # referrer for this path, then insert the new overlay row + referrer together. Avoids
  # the OR REPLACE stale-referrer leak.
  local vm p aid; vm=$(dr_vps_sql_str "$1"); p=$(dr_vps_sql_str "$2"); aid=$(dr_vps_sql_str "$3")
  dr_vps_sql "BEGIN IMMEDIATE;
    DELETE FROM referrers WHERE kind='overlay' AND ref_id=$p;
    DELETE FROM overlays WHERE path=$p;
    INSERT INTO overlays(path,vm_id,artifact_id) VALUES($p,$vm,$aid);
    INSERT INTO referrers(artifact_id,kind,ref_id) VALUES($aid,'overlay',$p);
    COMMIT;"
}
# RESERVED (H-1): net_record/egress_gen back the unused `networks` table (see its schema note); no
# runtime path records or reads per-network egress state -- the /run marker is the enforced authority.
dr_vps_store_net_record() {  # <name> <egress_gen>  (egress_gen is TEXT, a content hash)
  dr_vps_sql "INSERT OR REPLACE INTO networks(name,egress_gen)
    VALUES($(dr_vps_sql_str "$1"),$(dr_vps_sql_str "$2"));"
}
dr_vps_store_egress_gen() {  # <name> -> egress_gen TEXT content-hash (empty if none)
  dr_vps_sql "SELECT egress_gen FROM networks WHERE name=$(dr_vps_sql_str "$1");"
}

# ---- snapshots (SNAPSHOT feature; CONCEPT R3.1-R3.3) -------------------------------
# Register a snapshot: ONE txn inserts BOTH the images(kind='snapshot') ledger row AND the authoritative
# snapshots row. kind='snapshot' is HARDCODED here (an unprivileged caller can never register a golden --
# only dr-vps build/promote register kind='golden'). Idempotent on identical (id, golden_path); a same-id
# re-register at a DIFFERENT path is a CONFLICT (15) -- the content-addressed path is the stable invariant
# (mirrors dr_vps_store_image_register). golden_path MUST be the canonical <SNAP_DIR>/<id>/image.qcow2.
dr_vps_store_snapshot_register() {  # <id> <name> <prov_json> <golden_path> <source_vm> <parent_golden> <bundle_relpath> <secret 0|1> <scrub_profile> <shutdown clean|forced> <validation passed|skipped|failed> <notes> [owner_uid]
  local id="$1" nm="$2" prov="$3" gpath="$4" svm="$5" pgold="$6" brel="$7" sec="$8" prof="$9" sd="${10}" val="${11}" notes="${12:-}" owner="${13:-}"
  local qowner=NULL; [ -n "$owner" ] && qowner=$(dr_vps_sql_str "$owner")   # empty owner (direct operator) -> NULL
  printf '%s' "$prov" | jq -e . >/dev/null 2>&1 || { dr_vps_die "$DR_VPS_E_GENERIC" "snapshot provenance not JSON"; return $?; }
  case "$sec" in 0|1) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "snapshot secret_bearing must be 0|1: $sec"; return $?;; esac
  case "$sd"  in clean|forced) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "snapshot shutdown_mode must be clean|forced: $sd"; return $?;; esac
  case "$val" in passed|skipped|failed) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "snapshot validation_status invalid: $val"; return $?;; esac
  local qid; qid=$(dr_vps_sql_str "$id")
  # NAME collision with a DIFFERENT snapshot -> E_CONFLICT (not a generic DB abort from the UNIQUE index).
  # The id (content) is new here; only the human NAME collides -- astronomically rare (same UTC-min + distro
  # + 8hex short), but the conflict SHAPE must be honest so create surfaces it as a conflict.
  if [ -n "$(dr_vps_sql "SELECT 1 FROM snapshots WHERE name=$(dr_vps_sql_str "$nm") AND id<>$qid;")" ]; then
    dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot name '$nm' already in use by another snapshot"; return $?
  fi
  local out cnt epath
  out=$(dr_vps_sql "BEGIN IMMEDIATE;
    SELECT COUNT(*)||'|'||COALESCE((SELECT golden_path FROM images WHERE artifact_id=$qid),'') FROM images WHERE artifact_id=$qid;
    INSERT INTO images(artifact_id,provenance,golden_path,kind,name)
      SELECT $qid,$(dr_vps_sql_str "$prov"),$(dr_vps_sql_str "$gpath"),'snapshot',$(dr_vps_sql_str "$nm")
      WHERE (SELECT COUNT(*) FROM images WHERE artifact_id=$qid)=0;
    INSERT INTO snapshots(id,vm_id,artifact_id,secret_bearing,name,source_vm_id,parent_golden_id,bundle_relpath,scrub_profile,shutdown_mode,validation_status,notes,owner_uid,created_at)
      SELECT $qid,$(dr_vps_sql_str "$svm"),$(dr_vps_sql_str "$pgold"),$sec,$(dr_vps_sql_str "$nm"),$(dr_vps_sql_str "$svm"),$(dr_vps_sql_str "$pgold"),$(dr_vps_sql_str "$brel"),$(dr_vps_sql_str "$prof"),$(dr_vps_sql_str "$sd"),$(dr_vps_sql_str "$val"),$(dr_vps_sql_str "$notes"),$qowner,datetime('now')
      WHERE (SELECT COUNT(*) FROM snapshots WHERE id=$qid)=0;
    COMMIT;") || { dr_vps_die "$DR_VPS_E_GENERIC" "snapshot register db write failed: $id"; return $?; }
  cnt=${out%%|*}; epath=${out#*|}
  case "$cnt" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "snapshot register: unreadable db result for $id"; return $?;; esac
  if [ "$cnt" -eq 1 ] && [ "$epath" != "$gpath" ]; then
    dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot $id already registered at a different path (content id exists w/ different provenance)"; return $?
  fi
}
# id-or-name -> the canonical snapshot id (empty if none). Name lookup is scoped to kind='snapshot'.
dr_vps_store_snapshot_id() {  # <id_or_name> [owner_uid]  -- EXACT ID WINS before name . If [owner_uid]
  # is given, SCOPE the lookup to that owner so a non-owner client resolves NOTHING (-> caller sees not-found,
  # no existence leak). The direct operator passes no owner -> sees all (admin).
  local q r rc own oc; q=$(dr_vps_sql_str "$1"); own="${2:-}"; oc=""
  [ -n "$own" ] && oc=" AND owner_uid=$(dr_vps_sql_str "$own")"
  # FAIL CLOSED on a DB read error : an errored exact-ID read must NOT fall through to the name
  # lookup -- an EMPTY result there is indistinguishable from "no exact id", so a transient error could resolve
  # <id> via a name collision and act on the WRONG snapshot. Capture rc; a nonzero read returns nonzero + empty
  # (the caller, dr_vps_resolve_snapshot, then treats it as not-found -> refuses the op).
  r=$(dr_vps_sql "SELECT id FROM snapshots WHERE id=$q$oc LIMIT 1;"); rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  [ -n "$r" ] && { printf '%s\n' "$r"; return 0; }
  r=$(dr_vps_sql "SELECT id FROM snapshots WHERE name=$q$oc LIMIT 1;"); rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  [ -n "$r" ] && printf '%s\n' "$r"
  return 0
}
dr_vps_store_snapshot_get() {  # <id> -> name|parent_golden_id|bundle_relpath|secret_bearing|scrub_profile|shutdown_mode|validation_status|source_vm_id|created_at (empty if none)
  dr_vps_sql "SELECT name||'|'||parent_golden_id||'|'||bundle_relpath||'|'||secret_bearing||'|'||scrub_profile||'|'||shutdown_mode||'|'||validation_status||'|'||source_vm_id||'|'||created_at
    FROM snapshots WHERE id=$(dr_vps_sql_str "$1");"
}
dr_vps_store_snapshot_golden_path() {  # <id> -> the registered images.golden_path for this snapshot (empty if none)
  dr_vps_sql "SELECT golden_path FROM images WHERE artifact_id=$(dr_vps_sql_str "$1") AND kind='snapshot';"
}
dr_vps_store_snapshot_ls() {  # [owner_uid] -> "id  name  parent_golden  secret  validation  created". If
  # [owner_uid] is given, list ONLY that owner's snapshots (a client sees only its own; the operator sees all).
  local own="${1:-}" wc=""
  [ -n "$own" ] && wc=" WHERE owner_uid=$(dr_vps_sql_str "$own")"
  dr_vps_sql "SELECT id||'  '||name||'  '||parent_golden_id||'  '||secret_bearing||'  '||validation_status||'  '||created_at
    FROM snapshots${wc} ORDER BY created_at;"
}
dr_vps_store_snapshot_secret_bearing() {  # <id> -> 0|1|''
  dr_vps_sql "SELECT secret_bearing FROM snapshots WHERE id=$(dr_vps_sql_str "$1");"
}
# Refcount-gated delete -- ATOMIC: refuse (19) while ANY blocker exists; else drop BOTH the snapshots row
# and its images(kind='snapshot') ledger row in one txn (no orphan). BLOCKER = referrers ledger OR a DIRECT
# vms/overlays row on this artifact (belt-and-suspenders vs a corrupted/missing referrer:
# a hand-deleted referrer must NOT let snap-rm delete an image a live VM still backs).
dr_vps_store_snapshot_delete() {  # <id>
  local qa refs; qa=$(dr_vps_sql_str "$1")
  local blk="((SELECT COUNT(*) FROM referrers WHERE artifact_id=$qa)+(SELECT COUNT(*) FROM vms WHERE artifact_id=$qa)+(SELECT COUNT(*) FROM overlays WHERE artifact_id=$qa))"
  refs=$(dr_vps_sql "BEGIN IMMEDIATE;
    SELECT $blk;
    DELETE FROM snapshots WHERE id=$qa AND $blk=0;
    DELETE FROM images    WHERE artifact_id=$qa AND kind='snapshot' AND $blk=0;
    COMMIT;") || { dr_vps_die "$DR_VPS_E_GENERIC" "snapshot delete db write failed: $1"; return $?; }
  case "$refs" in ''|*[!0-9]*) dr_vps_die "$DR_VPS_E_GENERIC" "snapshot delete: unreadable db result for $1"; return $?;; esac
  [ "$refs" -eq 0 ] || { dr_vps_die "$DR_VPS_E_REFERENCED" "snapshot $1 still referenced (vm/overlay/referrer x$refs)"; return $?; }
}
# Rename (human handle only; content id unchanged). Updates BOTH tables; the UNIQUE index rejects a dup name.
dr_vps_store_snapshot_rename() {  # <id> <new_name> [owner_uid]  -- ATOMIC across snapshots + images :
  # ONE txn so a crash can't leave the name mirrors divergent; assert exactly one snapshots row moved.
  # OWNER-SCOPED + COLLISION-GUARDED atomically (TOCTOU race): the snapshots UPDATE fires ONLY when the
  # row is still owned by this caller (a client [owner given]; the operator [empty] matches any) AND no artifact
  # id equals the new name -- so a delete+re-register under a DIFFERENT owner, or a concurrent registration of
  # artifact_id==new_name, in the resolve..rename window yields changes()=0 (refused), never a cross-owner rename
  # or a name==id ambiguity. BEGIN IMMEDIATE serializes writers, so the check + write are one critical section.
  local qa qn out own oc; qa=$(dr_vps_sql_str "$1"); qn=$(dr_vps_sql_str "$2"); own="${3:-}"; oc=""
  [ -n "$own" ] && oc=" AND owner_uid=$(dr_vps_sql_str "$own")"
  out=$(dr_vps_sql "BEGIN IMMEDIATE;
    UPDATE snapshots SET name=$qn WHERE id=$qa$oc
      AND NOT EXISTS (SELECT 1 FROM images WHERE artifact_id=$qn);
    SELECT changes();
    UPDATE images SET name=$qn WHERE artifact_id=$qa AND kind='snapshot'
      AND EXISTS (SELECT 1 FROM snapshots WHERE id=$qa AND name=$qn);
    COMMIT;") \
    || { dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot rename failed (no such id for this owner, or name in use): $1"; return $?; }
  [ "$out" = 1 ] || { dr_vps_die "$DR_VPS_E_CONFLICT" "snapshot rename affected $out rows (expected 1 -- changed owner / name in use / gone): $1"; return $?; }
}
