# CONCEPT: drvps-top shared publisher / viewer (design v5, 2026-07-13)

Status: architecture converged and implemented. The shared feed CONTRACT
(tools/drvps_top_feed.py + tools/drvps_top_config.py + docs/drvps-top-share-fixtures/) is frozen: the
reconcile_class<->live_state matrix (sec 5.1) and the anomaly-counter semantics (sec 5.1) are enforced
IN the shared validator, and the publisher + viewer are implemented and unit-tested against it. ASCII only.

## 1. Goal + THREAT MODEL (authorization statement)
Let `drvpsctl` members (rig consumers; NO store.db/libvirt access) SEE a rig VM view READ-ONLY.
AUTHORIZATION (document for operators): drvpsctl membership authorizes visibility, per VM, of:
id, sanitized name, store+live state, class, age, coarse CPU%/RAM-alloc, plus host
load/memavail/cpu-count. NOT: owner identity (default off), snapshot identity/metadata (only an
opaque golden-vs-snapshot flag), guest data, paths, secrets, inventory. Too broad => needs a
per-viewer authenticated relay (out of scope).

## 2. THREE separate, ROOT-OWNED programs (no name collision; no mode switch)
- `drvps-top-publish` (PYTHON; runs AS drvps / the unit). ONLY privileged program: sqlite3 ROW
  API + `virsh -r`, CPU baseline, serialize snapshot. Also `--once` -> emit one snapshot to
  stdout (operator/feed bootstrap).
- `drvps-top` (PYTHON; the VIEWER; unprivileged; any drvpsctl member). Opens+validates the feed
  with the hostile-file protocol (sec 7 -- needs os.open O_NOFOLLOW + os.fstat on the SAME fd +
  capped raw-byte read + NUL detection, which bash CANNOT do), keeps parsed rows as TYPED
  OBJECTS (never re-serialized into a delimiter string -> no `|`/TAB re-injection), renders the
  TUI (in-place redraw, local sort, quit). Does NO sqlite/virsh/NSS; the ONLY local syscall it
  makes for display is sampling CLOCK_BOOTTIME for FRESHNESS (sec 4) -- permitted, not telemetry.
- `drvps-top-operator` = the EXISTING bash drvps-top (operator's direct live tool incl.
  inventory), UNCHANGED. Renamed on install so the member `drvps-top` never shadows it.
Install: all root-owned 0755, not writable by drvps/drvpsctl; viewer never setuid/caps.
Publisher and viewer SHARE ONE parser/serializer module (tools/drvps_top_feed.py) + the config parser (tools/drvps_top_config.py) + the byte-exact fixtures -- no reimplementation.

## 3. PUBLISH POLICY (security core)
Per VM (the only fields): reconcile_class, vm_id, sanitized vm_name, store_state, live_state,
class, base_flag, created_epoch, cpu, ram_cur_kib, ram_max_kib, and owner_display iff enabled.
- base_flag: `golden:<distro>@<8hex>` (golden catalogue is global) | the OPAQUE literal
  `snapshot` (NO id/short-id/distro -- snapshot identity is owner-scoped) | `orphan` | `unknown`.
  base_flag is STRUCTURED, not free text: a golden flag is emitted ONLY when the distro
  canonicalizes to `[a-z0-9]{1,16}` AND the short-id is exactly `[0-9a-f]{8}`. If EITHER component
  is malformed/canonicalized-away, the producer emits the WHOLE field as `unknown` (never a partial
  or garbled `golden:...`). `make_base_flag()` (tools/drvps_top_feed.py) is the single normative
  producer. All three inputs (kind, distro, short-id) may arrive as raw sqlite bytes OR str;
  make_base_flag ASCII-decodes each, and a non-ASCII component yields `unknown` (never a decoder crash).
- owner_display: OMITTED by default. Root-only unit `PublishOwner=no|uid|name-and-uid`; unit
  REFUSES to start on any other value; viewers cannot select it. `no` => the field is ABSENT
  (not a placeholder). The V field count DEPENDS on PublishOwner (sec 5 table).
- Inventory NEVER in the feed. (Operator uses drvps-top-operator.)
- NOTED OUT OF SCOPE: the pre-existing global `dr-vps list` artifact_id leak (dr_vps_store list)
  is not widened here; fixing it is a separate drvps policy decision.

## 4. FRESHNESS
Independent RETAINED source frames; per-source status + boottime sample stamp in H; the viewer
samples LOCAL CLOCK_BOOTTIME only to compute publisher staleness.
- H carries: db_status,db_boottime_ns ; libvirt_status,libvirt_boottime_ns ;
  stats_status,stats_boottime_ns (stats_boottime_ns ADDED).
- STATUS enums (normative): db,libvirt in {ok, stale, down} (NO `partial` for db/libvirt);
  stats in {ok, partial, down}. ok = a freshly-acquired COMPLETE frame this tick; stale =
  retained complete frame, OLD boottime; down = no retained valid frame, boottime sentinel 0.
- A new publish NEVER refreshes a RETAINED source's boottime. A malformed/timed-out/partial
  db or libvirt acquisition NEVER replaces its retained complete frame (frames are all-or-
  nothing). stats `partial` = some per-VM samples missing; each missing CPU/RAM is `--` in its V
  row (a retained old CPU/RAM value is NEVER emitted; a per-row stale value would need per-row
  stats stamps, which v1 avoids by emitting `--`).
- PUBLISHER-STALE (viewer): let dt = now_boottime_ns - H.boottime_ns. Publisher is STALE if
  dt > STALE_MULT * interval_ms*1e6 (STALE_MULT = 3), or dt < 0 (clock/future -> STALE), or
  H.boottime_ns == 0. On stale -> banner + keep last valid frame. Overflow-safe integer math.
- The viewer distinguishes: publisher-stale ; db-stale/down ; libvirt-stale/down ; stats-partial.
- FRAME MERGE (normative): DB frame drives the tracked V rows. A current libvirt frame is
  joined to a (possibly stale) DB frame by uuid per CONCEPT-DRVPS-TOP sec 5.2. If libvirt is
  down with NO retained frame, live_state = `unknown` and NO VM is classified `absent`/
  `untracked` (those require a live frame). If DB never succeeded (down, no retained) -> H
  row_count=0, db_status=down, publish a status-only feed. Each anomaly counter is meaningful
  only when BOTH db and libvirt are `ok`; otherwise the counters are 0 and the header flags the
  stale source (the viewer must not present stale-derived anomalies as fact).

## 5. NORMATIVE SCHEMA (frozen)
> NORMATIVE = `tools/drvps_top_feed.py` (the validator+serializer BOTH sides import; neither
> reimplements parsing) + `docs/drvps-top-share-fixtures/*.feed` + `MANIFEST.txt` (byte-exact
> accept/reject fixtures, one condition per file). The prose in 5 + 5.1 is the informative
> summary; where it and the code differ, THE CODE WINS. All counts below INCLUDE the record tag
> (H=24, V=12/13, E=4). The reconcile_class token is lowercase `unreconciled`.
Framing: LF-only; the file is exactly one H line, then row_count V lines, then one E line, each
terminated by a single `\n`; final newline REQUIRED; no CR, no blank lines, no trailing bytes.
Field separator: a single TAB (0x09) between fields; fields contain ONLY bytes 0x20..0x7e MINUS
TAB (already excluded) -- and, for text fields, MINUS the field separator handling below.
CAPS (frozen): feed <= 262144 bytes; <= 4096 V rows; vm_name <= 64 bytes; base_flag <= 48;
owner_display <= 64; vm_id <= 40; any status/enum token <= 16; each numeric <= 20 digits.
Numeric grammar: `0` or `[1-9][0-9]*` (NO leading `+`/`-` except where a signed delta is defined;
NO whitespace, NO leading zeros, NO exponent), within the declared range; sentinel `0` where
noted; `--` (two hyphens) is the ONLY non-numeric allowed in cpu/ram_* and means "unavailable".

    H  <ver=1> <instance:[A-Za-z0-9_-]{1,32}> <seq:0..2^63-1> <realtime_s:0..2^63-1>
       <boottime_ns:0..2^63-1> <interval_ms:100..3600000>
       <db_status> <db_boottime_ns:0..2^63-1> <libvirt_status> <libvirt_boottime_ns:0..2^63-1>
       <stats_status> <stats_boottime_ns:0..2^63-1> <row_count:0..4096>
       <c_absent> <c_uuid> <c_name> <c_untracked> <c_other> <c_ledger>   (each 0..65535)
       <load1_milli:0..1000000> <memavail_kib:0..2^63-1> <host_cpu_count:1..4096>
       <ownerpolicy: no|uid|name-and-uid>
       -> 24 TAB-separated fields, exactly.
    V  <reconcile_class: normal|absent|uuid|name|untracked|uuidbad|unreconciled>
       <vm_id> <vm_name> <store_state> <live_state: nostate|running|paused|shutoff|crashed|blocked|
         shutdown|pmsuspended|unknown|-->  <class: throwaway|service|-->
       <base_flag>  <created_epoch:0..2^63-1>
       <cpu_tenths: 0..1000000 | -->  <ram_cur_kib: 0..2^63-1 | -->  <ram_max_kib: 0..2^63-1 | -->
       [<owner_display>]   -> 12 fields incl the V tag (13 with owner). NORMATIVE: drvps_top_feed.py.
    E  <instance> <seq> <row_count>   -> 4 fields incl the E tag; instance+seq MUST equal H.s; row_count MUST
       equal the parsed V count (else the whole feed is rejected).
- store_state/live_state/class/reconcile_class use FROZEN enum sets above; an unknown token
  rejects the feed. vm_name empty -> the publisher emits the placeholder `-` (names are never
  empty in the feed). base_flag matches `^(golden:[a-z0-9]{1,16}@[0-9a-f]{8}|snapshot|orphan|
  unknown)$` (distro component is itself sanitized+capped).
- cpu is TENTHS of an aggregate percent (e.g. 3123 = 312.3%). AGE is computed BY THE VIEWER from
  (H.realtime_s - V.created_epoch); the publisher does not pre-compute age. load is shown by the
  viewer as `load1_milli/1000` over `host_cpu_count` (host_cpu_count ADDED so the header matches
  the operator tool's `load/ncpu`).
Publisher and viewer BOTH validate against this table; shared golden fixtures encode it.

## 6. SANITIZATION -- one producer-side canonicalizer for EVERY external string
- ONE function canonicalizes ALL producer-side strings: SQLite text (Python sqlite3
  `text_factory=bytes` -> operate on raw bytes so invalid DB encoding is sanitizable input, not
  a decoder crash), libvirt domain names, NSS usernames, provenance/distro, config-derived text.
- Policy: keep bytes 0x20..0x7e except the separator; replace every other byte with `?`; enforce
  the per-field cap; then VALIDATE the enum/grammar. A value that cannot be made a valid enum/
  number -> governed by the per-field FAILURE MATRIX in section 6.1 (NORMATIVE), NOT this prose:
  free TEXT is canonicalized; a bad IDENTITY key / controlled ENUM / store NUMBER FAILS the whole
  DB acquisition (retain the prior complete frame) -- a corrupt DB row is never silently dropped or
  mutated; stats numbers -> `--`. (Rows are typed objects; no re-delimiting -> no field shift.)
- NSS: hard per-lookup timeout + positive/negative TTL + size cap (only if PublishOwner!=no).

## 7. FILE PROTOCOLS
### 7.1 Publisher WRITE
1. open the runtime dir (dir_fd); acquire a non-blocking EXCLUSIVE flock in it (2nd publisher
   exits with a dedicated code). 2. remove abandoned temp files at start. 3. create a UNIQUE temp
   RELATIVE to dir_fd with O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, mode 0600. 4. write the
   whole snapshot; CHECK every write + the close. 5. fchown drvps:drvpsctl + fchmod 0640 on the
   temp inode. 6. `renameat(dir_fd, tmp, dir_fd, "feed")` -- atomic same-dir replace (this
   REPLACES a pre-existing `feed` even if it is a symlink, WITHOUT following it; O_NOFOLLOW
   applied to the TEMP open, not the rename target -- r2-#9). fsync not required for /run.
### 7.2 Viewer OPEN/READ
Each poll (no fd reuse; no stat-then-open): open dir_fd (O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK),
then openat(dir_fd,"feed",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK) -- O_NONBLOCK so a hostile
FIFO/device planted at the path cannot BLOCK the open before fstat rejects it; os.fstat THAT fd: require regular file,
st_uid == drvps (numeric, from the validated runtime dir / root config -- no per-frame NSS),
st_gid == drvpsctl, perm mask exactly 0640, st_nlink == 1, st_size <= cap; read in capped chunks
enforcing the byte cap WHILE reading (not only st_size); reject any NUL/out-of-range byte; parse
+ fully validate (sec 5); ONLY then replace the last valid frame. On any failure: keep last valid
frame, show a fixed locally-generated error (never echo feed bytes).

## 8. ACQUISITION HARDENING (publisher)
Capture stdout AND status separately per source; empty-success != failure. DB and libvirt frames
are ATOMIC (all-or-nothing); a malformed/timed-out/partial acquisition NEVER replaces a retained
complete frame. Whole-stats-pass deadline + bounded fan-out (CONCEPT-DRVPS-TOP sec 5.1); a stats
timeout -> that uuid `--`, never a stall. Never publish an empty VM set because a read failed; if
NO frame ever acquired, publish a status-only feed (row_count=0, statuses=down).

## 9. SUPERVISION (frozen)
`drvps-top-publish.service`: User=drvps, Group=drvpsctl (RuntimeDirectory takes the service
Group), SupplementaryGroups=<libvirt-access-group>, RuntimeDirectory=drvps-top,
RuntimeDirectoryMode=0710, RuntimeDirectoryPreserve=no (an old owner-bearing feed must NOT
survive a policy change), UMask=0027. Restart=on-failure, RestartSec=2s, StartLimitIntervalSec+
StartLimitBurst. A PERMANENT config/schema error -> exit code 78 (EX_CONFIG);
RestartPreventExitStatus=78 (no tight loop). Transient DB/libvirt failures are handled INSIDE the
loop (publish stale/down status), NOT by exiting. Hardening: NoNewPrivileges, empty Capability
BoundingSet/AmbientCapabilities, ProtectSystem=strict, ProtectHome, PrivateTmp, PrivateDevices,
ProtectKernelTunables/Modules, ProtectControlGroups, ProtectClock, RestrictSUIDSGID,
LockPersonality, MemoryDenyWriteExecute, RestrictRealtime, SystemCallArchitectures=native,
RestrictAddressFamilies=AF_UNIX (if NSS/libvirt strictly local; else document the exception),
TasksMax, MemoryMax, low CPU/IO weight. On the FIRST publication under a new policy failing:
publish a status-only tombstone (down) before members can read a mismatched policy.

## 10. TESTING (offline; shared fixtures from sec 5)
PUBLISHER: publish cycle writes temp(0600 relative to dir_fd)->renameat; a store value with
TAB/newline/`|`/ESC/NUL/non-ASCII cannot inject a field/row (typed objects); owner omitted by
default + honored; a source failure -> retained rows + stale status (never empty) + status-only
when nothing acquired; 2nd publisher refused by flock; a pre-existing `feed` SYMLINK is atomically
REPLACED (not followed); every H/V/E field count + enum + numeric range enforced.
VIEWER: renders TOP from a valid feed (columns/values, sort on TYPED rows); rejects malformed/
oversized/dup-id/bad-enum/short-field/NUL/CR feeds -> keep last frame + fixed error; refuses a
non-regular / wrong uid|gid / wrong-mode / nlink!=1 / oversized feed; a hostile feed with ESC/
newline in a name cannot move the cursor or fabricate a row; distinguishes publisher-stale vs
db-stale/down vs libvirt-down vs stats-partial (fixed CLOCK_BOOTTIME seam). END-TO-END: publisher
(fixture store+virsh) -> feed -> viewer renders -> halves agree.

## 5.1 schema completeness (FROZEN)
- V FIELD COUNT: exactly 12 fields INCLUDING the leading `V` tag; 13 when ownerpolicy != no
  (r3: counts are inclusive of the tag). H = 24 incl. the `H` tag; E = 4 incl. the `E` tag.
- store_state: NOT an enum (the store column has no CHECK; the setter takes free text). It is
  BOUNDED OPAQUE TEXT: producer-canonicalized (sec 6), <=16 bytes, printable-ASCII only; the
  token `unknown` = store state absent. The VIEWER treats it as opaque display text (charset +
  length validated, NOT enum-checked). live_state REMAINS a frozen enum (from domstats).
- vm_id: FROZEN grammar `^drvps-vm-[0-9a-f]{16}$` (dr_vps_identity.sh), NON-EMPTY, FRAME-UNIQUE
  (a duplicate vm_id REJECTS the whole feed -- normative). vm_id is NEVER canonicalized/truncated;
  a store id not matching the grammar is a store ANOMALY -> FAIL the DB acquisition + retain the
  prior DB frame (never emit a mangled id).
- reconcile_class ENUM (frozen): normal|absent|uuid|name|untracked|uuidbad|unreconciled
  (base CONCEPT-DRVPS-TOP sec 5.2: normal=(name,uuid) pair matches; name=uuid maps to a different
  name; uuid=id maps to a different uuid; absent=neither map has the expected uuid/name; untracked=a
  drvps-shaped LIVE domain with no store row; uuidbad=store uuid NULL/malformed, uncheckable).
- MASKING is in the SHARED VALIDATOR, an EQUIVALENCE: `unreconciled` is emitted iff a
  source is masked. Whenever db_status OR libvirt_status != `ok`, EVERY V row's reconcile_class MUST
  be `unreconciled` (-> `mask-reconcile`); when BOTH are `ok`, `unreconciled` is FORBIDDEN
  (-> `unmasked-unreconciled`). When libvirt is down, live_state MUST be `unknown` (-> `mask-livestate`).
- live_state values: the 8 REAL virDomainState members
  `nostate|running|paused|shutoff|crashed|blocked|shutdown|pmsuspended` (nostate=VIR_DOMAIN_NOSTATE, an
  OBSERVED state -- NOT a sentinel), plus two SENTINELS: `unknown` = libvirt unobservable, emitted IFF
  libvirt is down (up + `unknown` -> `livestate-unknown`); `--` = no live domain attributed to the row.
  A future/unlisted libvirt state fails closed at the enum.
- reconcile_class <-> live_state MATRIX (enforced when unmasked; `_validate_frame`): live-backed
  classes normal|untracked => one of the 8 REAL states; absent|uuid|name|uuidbad => `--` (no
  attributed live domain). Violation -> `reconcile-livestate`. So the producer NEVER emits, and the
  viewer NEVER sees, a contradictory row.
- HEADER ANOMALY COUNTERS (frozen semantics; cross-checked in `_validate_frame`). The
  feed enumerates EVERY tracked VM as a V row (the 4096-row cap FAILS the DB acquisition and retains
  the prior frame -- it NEVER truncates), so FIVE of the six counters are EXACT row derivations and
  MUST equal the emitted rows (else `counter-<name>`): `c_absent`==#absent, `c_uuid`==#uuid,
  `c_name`==#name, `c_untracked`==#untracked, and `c_ledger`==#uuidbad rows. (v1 rule: a DB/schema
  INTEGRITY failure sets db_status!=ok, which forces every counter to 0 -- so the ONLY ledger anomaly
  that coexists with db_status==ok is the per-row store-uuid-invalid `uuidbad`; other integrity
  failures are carried by db_status + logs, NOT a counter. So c_ledger is exactly row-derivable.)
- `c_other` is the ONE non-row-derivable counter. Its producer rule is NORMATIVE (this paragraph binds
  despite the sec-5 "prose is informative" rule) and has a single implementation, `count_other()` in
  tools/drvps_top_feed.py: the number of LIVE libvirt domains (from the live-identity frame, active AND
  inactive) whose NAME does NOT match the VM grammar `^drvps-vm-[0-9a-f]{16}$` AND whose live-domain
  UUID is not already claimed by a normal/name/uuid/untracked reconcile row (base CONCEPT sec 5.2: "a
  domain already claimed by a name!=/uuid!= row is NOT also counted in other"). A malformed/None domain
  name is not drvps-shaped -> counted. It is a TRUSTED producer count (single root publisher): bounded
  0..65535; a true count > 65535 FAILS the libvirt acquisition (retain prior frame), never saturates;
  and it is 0 when masked.
- ALL six counters are 0 whenever a source is masked (the `anomaly-while-stale` rule).
- UNTRACKED ROW PROJECTION (frozen; enforced in `_validate_frame`). An `untracked` row is
  a LIVE-only domain with NO store row, so every store-derived field MUST be its unavailable sentinel
  -- a publisher can NEVER attribute store metadata or an owner to a live-only domain: vm_name==`--`,
  store_state==`unknown` (store state absent), class==`--`, base_flag==`unknown`, created_epoch==0, and
  (owner-enabled feeds) owner_display==`-`. Violations -> `untracked-vm_name`/`-store_state`/`-class`/
  `-base`/`-created`/`-owner`. The `-` owner value is the OWNER-UNAVAILABLE sentinel, accepted under
  BOTH the `uid` and `name-and-uid` policies (also the NSS-failure value); it is the ONLY owner an
  untracked row may carry.

## 4.1 v4 -- freshness completeness (r3)
- STATS are CURRENT-PASS-ONLY (never retained). Exhaustive:
  ok = a complete pass this tick sampled every eligible NORMAL uuid (zero eligible = trivially
  ok); stats_boottime_ns = this tick's pass-start boottime. partial = the pass ran but some
  eligible uuids were missing/timed-out (their V rows carry `--`); stats_boottime_ns = this tick.
  down = the pass could not run OR failed entirely, incl. total-failure-after-prior-success -> ALL
  cpu/ram `--`; stats_boottime_ns = 0. A retained CPU/RAM value is NEVER emitted; missing -> `--`.
- HOST telemetry (load1_milli, memavail_kib, host_cpu_count) is an ALL-OR-NOTHING PUBLISH
  PREREQUISITE: read /proc/loadavg + /proc/meminfo + the cpu count each tick; if ANY read fails,
  DO NOT advance H (skip this tick's publish; the prior feed stands) -- never falsely freshen.

## 6.1 v4 -- producer per-field failure matrix (r3)
- IDENTITY key (vm_id): grammar + frame-unique; mismatch/duplicate FAILS the whole DB acquisition
  -> retain the prior DB frame. NEVER canonicalize/truncate an identity key into a different id.
- CONTROLLED enums (class, reconcile_class, live_state): a value outside the frozen set is a
  producer BUG -> fail the DB/live acquisition (fail-closed), retain the prior frame.
- FREE text (vm_name, store_state): canonicalize (sec 6); empty -> `-`.
- STRUCTURED base_flag (NOT free text): built by `make_base_flag()` (sec 4). A golden needs a
  distro matching `[a-z0-9]{1,16}` AND an `[0-9a-f]{8}` short-id; malformed EITHER -> whole field
  `unknown`. Snapshot -> opaque `snapshot`. This is a total function: it NEVER fails acquisition.
- STORE numbers (created_epoch): out of range -> fail the DB acquisition. STATS numbers (cpu,
  ram_*): bad/missing -> `--` (does not fail the tick).
So a "complete DB frame" is all-or-nothing: a corrupt DB row NEVER silently drops or mutates.

## 7.3 v4 -- viewer trust anchor (frozen; r3)
The viewer's expected feed identity comes ONLY from a ROOT-INSTALLED NUMERIC CONFIG -- never NSS,
never the runtime dir's current owner: `/etc/drvps-top/viewer.conf` (root:root 0644), keys
`feed_dir=/run/drvps-top`, `feed_name=feed`, `feed_uid=<numeric>`, `feed_gid=<numeric>`,
`feed_mode=0640`, `dir_mode=0710`, `max_bytes=262144`. Each poll: fstat(dir_fd) and require dir
owner==feed_uid, group==feed_gid, mode==dir_mode BEFORE openat("feed"); then the sec-7.2 fstat on
the feed fd uses feed_uid/gid/mode/max_bytes. A missing/malformed config -> refuse to run with a
fixed message. Seams/fixtures cover a wrong-owner dir + a wrong-mode feed.
`load_config()` opens the config with O_NOFOLLOW|O_NONBLOCK and ENFORCES the security invariant of
the trust anchor: a REGULAR file owned by root:root, with NO group/world WRITE bit and NO
set-uid/set-gid/sticky bit (`config-not-regular` / `config-not-root-owned` /
`config-group-world-writable` / `config-setid`). The shipped file is 0644; group/world READ bits are
harmless on a root-owned world-readable config, so the loader constrains the write/set-id bits, not
the exact octal. Tests cover symlink, FIFO/non-regular, wrong owner, writable, set-id, oversize,
short read, and non-ASCII.

## 11. Out of scope (v1)
Multi-host; history; per-viewer filtering / individual owner views; inventory in the feed; a
socket/push transport; fixing the pre-existing global-list artifact_id leak (separate policy).
