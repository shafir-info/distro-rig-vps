# CONCEPT: drvps-top -- operator rig-wide live TUI (design v5, 2026-07-12)

Status: design v5, architecture converged and implemented (bash operator TUI + the shared
publisher/viewer of CONCEPT-DRVPS-TOP-SHARE). The precision items (process-group kill, the exact
store_init check set) are implemented and unit-tested; live on-host verification is the operator's
isolated-env step, still pending. ASCII only.

## 1. Purpose
A read-only, operator terminal dashboard for the WHOLE drvps rig: reconciled store-vs-libvirt
VMs, owner (uid), live CPU/RAM, plus the golden + snapshot inventory.

`rigctl list` VM reads are GLOBAL host-wide already (drvps_rigctl.py:120-122 "Reads
(list/status/inspect/wait/distros/version) stay GLOBAL"; NOT owner-scoped -- only the
SNAPSHOT verbs are). What it LACKS: owner labels, live CPU/RAM, store-vs-libvirt
reconciliation, and inventory richness. `dr-vps list` is a bare `id state name artifact`
line. drvps-top adds those. weft's monitor.sh is scoped to one weft RUN, not the rig.

## 2. System facts (verified in source 2026-07-12)
- Host-wide store visibility is OPERATOR-ONLY: store.db is 0750 drvps:qemu. drvps-top RUNS
  AS `drvps` (`sudo -u drvps ...`).
- VM id grammar: `drvps-vm-<16 hex>` (dr_vps_identity.sh:105-109 = sha256(name\37project\37
  owner)[:16]). Goldens `drvps-raw-v1-<vsize>-<64hex>`; snapshots `drvps-snap-v1-...`
  (snapshots.id == images.artifact_id for kind=snapshot). This grammar drives untracked-
  domain detection and short-id.
- libvirt DOMAIN NAME == vms.id (dr_vps_domain.sh:120 `<name>${id}</name>`); the row is
  committed state='broken' with a pre-generated domain_uuid BEFORE define (L281-320); a
  foreign same-name domain is refused (L267). So store presence != live presence and
  identity MUST be verified by uuid.
- The store uses SQLite's DEFAULT journal (dr_vps_store.sh:20-21 has no journal_mode pragma)
  BUT that only proves this wrapper does not SET a mode; the file's ACTUAL mode (DELETE vs a
  persisted WAL) is queried at runtime (section 3.1). `_dr_virsh` (dr_vps_domain.sh:23) opens
  an ORDINARY RW connection -- read-only there is convention, not a boundary.
- The rig serves live campaigns; the tool MUST be low-interference.

## 3. Acquisition layer
NOT claimed anywhere: a guarantee that a daemon write can never be delayed. CLAIMED:
best-effort, low-interference, hard-deadline-bounded. (The hard-guarantee alternative --
a daemon-exported snapshot -- is section 12, out of v1.)

### 3.1 SQLite (store.db) -- best-effort, hard-bounded reader
- Open read-only + private cache: `file:${DR_VPS_DB}?mode=ro&cache=private`. NEVER
  immutable=1 on the live file.
- `PRAGMA query_only=ON` (defense-in-depth) and `PRAGMA busy_timeout=0` (fail-fast: do not
  WAIT on a lock).
- Read ALL database-backed frame data (vms + images + snapshots) in ONE sqlite3 invocation,
  ONE short snapshot transaction (`BEGIN; SELECT...; COMMIT`), then close BEFORE any virsh/
  NSS/keyread/render -> an internally consistent DB frame.
- HARD DEADLINE: the whole sqlite3 read is wrapped in `timeout --signal=TERM --kill-after=
  0.25 0.75` -- TERM at 750ms, KILL at ~1000ms -> a TRUE wall-clock lifetime cap of ~1s
  (`-k 1s 1s` would be ~2s = TERM at 1s + KILL 1s later; that arithmetic is fixed
  here). Even a TERM-ignoring read is KILLed by ~1s, well below the writer's 5s `.timeout`
  (dr_vps_store.sh:21). Honest bound: busy_timeout=0 = never WAIT to ACQUIRE; the ~1s kill =
  never HOLD a shared lock beyond ~1s. In the normal single-reader case the writer is not
  failed -- but this is BEST-EFFORT, not a formal guarantee (pathological host stress;
  concurrent dashboards add load). The integration test (section 10) MUST exercise a
  TERM-ignoring reader requiring SIGKILL (verifying the ~1s wall-clock kill actually fires),
  not a sqlite that exits on TERM. The
  hard-guarantee path is section 12.
- Runtime journal-mode probe: during the capability probe read `PRAGMA main.journal_mode`
  (never SET it). Report the actual mode in the header; the interference note differs
  (DELETE: reader can delay a writer's commit; WAL: reader pins a snapshot / may impede a
  checkpoint). Define/test both.
- Store INTEGRITY (read-only): reproduce dr_vps_store_init's FULL refusal set
  (dr_vps_store.sh:202-242) as read-only checks, enumerated (match it exactly,
  do not vaguely gesture at "referrer/overlay invariants" the cited range does not assert):
  (a) all REQUIRED columns present (the pragma_table_info set already in section 3.2);
  (b) the required INDEXES exist AND are of type index; (c) the required TRIGGERS exist AND
  are of type trigger (the exact object set store_init asserts at L202-224); (d) the DATA
  invariants (L225-242): valid image kinds, artifact-prefix/kind agreement, and the
  images(kind=snapshot) <-> snapshots bijection (snapshots.id == images.artifact_id). Each is
  a SELECT against sqlite_master / the tables. On ANY failure, render a distinct `ledger: N
  anomalies` status and SUPPRESS normal inventory totals for the affected set rather than
  presenting a state store_init itself would refuse.
- On SQLITE_BUSY / timeout-kill: keep the last COMPLETE db frame, render it flagged `db:busy
  (stale <age>)`, retry next tick. Adapter failure is NEVER reinterpreted as "empty rig".

### 3.2 Schema capability probe (must COMPLETE before diagnosing)
Before the first frame, probe with `pragma_table_info` (read-only): vms.{owner_uid,class,
domain_uuid}, images.{kind,name,provenance}, snapshots.{parent_golden_id,secret_bearing,
validation_status,created_at}. A BUSY/killed probe is TRANSIENT -> retry / show `store busy`;
only a SUCCESSFUL probe proving a column ABSENT -> refuse "store schema too old/incomplete;
run the operator upgrade path" (exit 3). NEVER migrate.

### 3.3 libvirt -- own read-only wrapper, minimal sourcing
- `rvirsh() { LC_ALL=C timeout --signal=TERM --kill-after=2s "${DR_VIRSH_TIMEOUT:-4}" \
   "$DR_VIRSH" -r --no-pkttyagent -c "$DR_LIBVIRT_URI" "$@"; }` -- `-r` = read-only
  connection (capability boundary); `--no-pkttyagent` avoids a polkit prompt; LC_ALL=C
  (virsh output is gettext-translated); a HARD per-call wall-clock timeout (TERM then KILL).
- Source ONLY dr_vps_api.sh (DR_VIRSH, DR_LIBVIRT_URI, DR_VPS_DB, DR_SQLITE seams). Do NOT
  source dr_vps_domain.sh (it pulls 7 modules).

## 4. Views (switchable, htop-style)
### 4.1 TOP view (hot; `--interval`, default 3s, min 1s; polls only while shown)
    OWNER          VM         ID        STATE           CLASS      BASE                AGE    CPU%    RAM
    alice(1007)    weftg*P05  b71deae1  running         throwaway  ubuntu26@snap:a9f0  4m12s  312.4  1.5G/1.5G
    operator       kcgold     15685c94  running         throwaway  fedora44@raw:bc07   9m1s     0.0  2.0G/2.0G
    1099(gone)     bare       702420fc  broken/absent   throwaway  ubuntu26@snap:a9f0   2m1s     --   --

- OWNER: `username(uid)` via cached, timeout-bounded getent; `uid` if lookup fails;
  `operator` for NULL. UID ALWAYS visible (reused/absent account must not be hidden).
- VM: name prefix, hash/timestamp elided.
- ID: short_id = first 8 chars of `${id##*-}` (final hash component; VM=drvps-vm-<16hex>,
  golden/snapshot=...-<64hex>). On a collision WITHIN a frame, expand both prefixes until
  unique.
- STATE: composite STORE/LIVE (single value when equal). STORE=vms.state; LIVE=domstats
  `state.state` for the SAME uuid (running/paused/shutoff/crashed); absent domain -> `absent`;
  uuid mismatch -> `uuid!=`.
- CLASS: throwaway | service (service highlighted).
- BASE: LEFT JOIN vms.artifact_id -> images: `json_extract(provenance,'$.distro')` guarded
  by `json_valid(provenance)` + images.kind -> `distro@raw:8hex` | `distro@snap:8hex`; no
  image row -> `orphan:<8hex>`; invalid provenance -> `distro?`.
- AGE: now - created_at (future/malformed -> `?`).
- CPU%: TOP-STYLE AGGREGATE across vcpus = `100 * dCPU_ns / dWALL_ns` (monotonic clock); a
  busy 4-vcpu VM reads ~400%; NOT divided by nvcpu, NOT clamped; `--` until valid (section 5).
- RAM: `alloc/max` = balloon.current/maximum (ALLOCATION, not guest-used); absent -> `--`.

Sort: default CPU% desc; `s` cycles cpu -> ram -> age -> owner.

### 4.2 INVENTORY view (cold; on switch + ~30s)
- GOLDENS (images.kind='golden'): short-id  distro(json_extract provenance)  built(created_at)
- SNAPSHOTS (the snapshots TABLE): short-id  name  parent(short parent_golden_id)  secret
  (secret_bearing)  validation(validation_status)  created
- Totals: VMs by class+live-state; golden/snapshot counts; anomaly + ledger counts.

### 4.3 Header
`UTC | load1/ncpu | MemAvailable | VMs N(by class) | anomalies: absent A uuid! U untracked T
other O | db:<ok|busy stale Ns|journal=delete|wal> | libvirt:<ok|stale Ns|down> | ledger:K`

### 4.4 Footer
`Tab view | s sort | r refresh | q quit | interval=Ns`

## 5. Reconciliation + CPU/RAM (freshness-gated; TOCTOU-safe)
### 5.1 Frames (each independently timestamped with a monotonic clock)
- DB frame: one sqlite txn (vms+images+snapshots).
- LIVE-IDENTITY frame: `rvirsh list --all --uuid --name` -> TWO independent reverse maps
  `uuid_to_name` and `name_to_uuid`, covering ALL domains (active AND inactive). Timestamped.
- UUID VALIDATION: before ANY libvirt stats call, validate each vms.domain_uuid
  against the canonical form `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
  (case-normalized). The schema permits domain_uuid NULL, and create commits the row BEFORE
  the uuid UPDATE (dr_vps_domain.sh:281-297) -- so a row can legitimately have NULL/absent
  uuid. NULL/empty/malformed -> do NOT call domstats (an empty arg would make domstats gather
  ALL domains), render `uuid?` / store-uuid-invalid, count a LEDGER anomaly; never classify
  as ordinary absent/uuid!=.
- ORDER: CLASSIFY FIRST. After the two identity maps are built, run the section
  5.2 pair classification, THEN enqueue domstats ONLY for class-1 NORMAL uuids. Anomalous
  rows (name!=/uuid!=/absent) and invalid uuids never consume a fan-out slot or deadline
  budget, so they cannot starve NORMAL rows.
- STATS pass (bounded, NORMAL-only): for each class-1 NORMAL uuid, a PER-UUID `rvirsh
  domstats --raw --nowait --state --cpu-total --vcpu --balloon <uuid>`; the record is
  attributed to the REQUESTED uuid (never a returned name) -- removes the name-reuse TOCTOU.
  Explicit uuid returns state for inactive domains too (cpu/balloon absent -> `--`). NO
  `--enforce`. Require EXACTLY ONE complete record from the call before it is usable.
- WHOLE-PASS BUDGET (R3/R4-major): the NORMAL-only per-uuid calls run as a BOUNDED PARALLEL
  fan-out (concurrency cap, e.g. 4) under a SINGLE monotonic pass deadline. If the identity
  call FAILED, SKIP the stats pass entirely (do not hammer a failing libvirt with N calls).
  PROCESS-TREE GUARANTEE: each worker runs in its OWN process group/session (`setsid`), so at
  the deadline the supervisor TERMs then KILLs the whole GROUP (not just the visible child --
  each worker nests a `timeout`+`virsh` subtree), reaps every worker, and accepts output ONLY
  from workers PROVEN complete before the deadline. The TERM->KILL termination + reaping grace
  is counted INSIDE the stated pass bound (deadline <= display interval; any overrun is only
  this bounded grace). NEVER update a CPU baseline from a late/cancelled/killed result;
  timestamp each accepted sample at its ACTUAL acquisition. (Very large N -> round-robin a
  subset of NORMAL uuids per tick.)

### 5.2 Reconciliation -- reconcile the exact (name,uuid) PAIR
The identity invariant is BOTH: domain name == vms.id AND domain uuid == vms.domain_uuid.
Using the two reverse maps (uuid_to_name, name_to_uuid), classify each row by its expected
pair (id, domain_uuid):
  1. domain_uuid maps to name == vms.id            -> NORMAL (attach that uuid's stats).
  2. domain_uuid maps to a DIFFERENT name          -> `name!=` (anomaly; do NOT treat as
     normal even though the uuid's stats are valid -- a renamed-domain drift).
  3. vms.id maps to a DIFFERENT uuid               -> `uuid!=` (anomaly).
  4. neither map has the expected uuid or name     -> `absent`.
  5. both mismatch (a name swap)                   -> report BOTH dimensions, count each
     DOMAIN once (no double-counting).
  6. a live domain whose name matches the VM grammar `^drvps-vm-[0-9a-f]{16}$` (dr_vps_
     identity.sh:105-109) and is consumed by NO store row -> `untracked` (anomaly).
Non-drvps-shaped domains -> `other:N` count only. A domain already claimed by a name!=/uuid!=
row is NOT also counted in other. Only class-1 NORMAL rows get per-uuid stats attached.
FRESHNESS GATE (wording): a cross-source class is a CURRENT-CYCLE OBSERVATION, not
proof -- the DB and libvirt reads are not atomic (a domain can be defined/removed/renamed
between them, and create legitimately commits a row before define -> a one-cycle broken/absent
is normal). So: (a) if EITHER frame is stale, render `live=?/stale`, SUPPRESS the affected
counters, flag `db:stale`/`libvirt:stale`; (b) an attention counter (absent/uuid!=/name!=/
untracked) is only PROMOTED after the SAME anomaly appears in TWO consecutive fully-fresh
cycles; a single-cycle anomaly renders as `transient?`.

### 5.3 CPU baseline STATE MACHINE (uuid-keyed; monotonic)
Baseline {uuid -> (cpu.time, mono_ns)} retained ONLY after a fully-parsed per-uuid record
from a VALIDATED uuid (section 5.1); mono_ns is the ACTUAL per-uuid acquisition timestamp
(not the tick start), and a late/cancelled/deadline-killed result NEVER updates a baseline.
Given prior + current for the SAME uuid:
- current.cpu_time < prior -> reset/wrap: reseed, show `--`.
- current.cpu_time == prior -> valid `0.0` (idle/paused) IF two valid same-uuid samples.
- current.cpu_time > prior AND dWALL_ns > 0 -> `100 * dCPU_ns / dWALL_ns`.
- new uuid / missing field / timed-out-or-partial record / dWALL<=0 -> `--`.
nvcpu (vcpu.current) is display/validation only, NOT a divisor in the aggregate. On timeout/
malformed output for a uuid, DISCARD that record (never merge partial). RAM = balloon.current/
maximum; absent -> `--`; never enable a balloon stats period (that would mutate the domain).

## 6. Rendering
- ANSI flicker-free redraw (home, per-line clear-to-eol, clear trailing lines, hide cursor
  in loop). Non-blocking keyread `read -t <remaining>`.
- Idempotent EXIT trap restores cursor/terminal on ANY exit (+ INT/TERM/HUP). `--once` and
  non-TTY NEVER enter cursor/key modes. Do NOT swallow render failures.
- Cadence: next poll scheduled against a MONOTONIC DEADLINE (tick_start + interval); enforce
  min interval; never busy-catch-up.
- ASCII-only source; separators `=`/`-`/`|`. Color via ANSI SGR (skip for --no-color/non-tty):
  bold header; CPU% ramp green(<100)/yellow(<300)/red(>=300) aggregate scale; service class
  highlighted; near-full RAM bold; anomaly/stale rows dim/red. Recompute widths each frame;
  drop ID then BASE on a narrow terminal.

## 7. Flags
`--interval N`(>=1) `--once`(single frame, exit; offline/CI/watch entry) `--sort cpu|ram|age|
owner` `--view top|inventory` `--no-color` `--help`. `q`/Ctrl-C -> restore + exit 0.

## 8. Structure + seams (four layers)
1. PURE reducers (I/O-free; now/inputs injected): short_id(+collision expand), vm_shortname,
   owner_label, base_label, cpu_pct(t1,t2,w1,w2), ram_fmt, fmt_age(created_at,now),
   state_label, color_ramp, fit_cols.
2. RAW PARSERS (string->records): parse per-uuid `domstats --raw`, parse `list --uuid --name`,
   parse the sqlite rows. Unit-tested against captured fixtures (missing/reordered/partial/
   paused/inactive/malformed).
3. SUBPROCESS ADAPTERS (seamed): q_db (one sqlite3 -readonly txn, timeout-wrapped), q_ident
   (rvirsh list), q_stats (per-uuid rvirsh domstats), owner_name (DR_GETENT). Seams:
   DR_SQLITE, DR_VIRSH, DR_GETENT, CLOCK (monotonic+wall).
4. RENDER + main loop (arg parse, deadline scheduler, keyread, view dispatch, traps).

## 9. Failure modes / races (explicit)
DB: SQLITE_BUSY/timeout-kill (stale frame, never "empty"); missing column (probe refusal
only after a SUCCESSFUL probe); malformed/NULL provenance (json_valid -> orphan/`?`);
integrity-invariant break (ledger anomaly, suppress totals); corrupt/absent DB (clear error);
actual WAL vs DELETE (probe + mode-specific note).
Reconciliation: domain added/removed/paused/resumed/recreated between DB and identity frames
(freshness gate); uuid mismatch; untracked; broken pre-define rows (absent); name-reuse
(killed by per-uuid stats).
Stats: unsupported/omitted fields; another domain job (--nowait); partial/timeout -> discard
that uuid's record; counter reset/wrap/zero-delta (5.3); nvcpu change.
Env: slow/failing NSS (timeout+cache; show uid); libvirt down/stale (header flag, rows from
store); non-TTY; SIGWINCH/HUP; broken pipe; invalid/zero interval (clamp to min); multiple
dashboards (additive but each bounded; documented).

## 10. Testing
- UNIT: every pure reducer + every raw parser vs fixtures (malformed/partial/paused/inactive/
  reordered domstats; counter wrap/zero/decrease; owner resolved/uid/NULL; provenance valid/
  invalid/missing; short_id collisions -> expansion).
- INTEGRATION: temp DB built from the REAL schema in BOTH journal modes (DELETE and WAL),
  incl. a concurrent-writer case asserting the reader is killed at the deadline and degrades
  to stale (best-effort behavior, not a false "never blocks" claim); integrity-invariant
  violation surfaces as ledger anomaly.
- `--once` GOLDEN via seams (DR_SQLITE=temp db, DR_VIRSH=canned per-uuid domstats + list,
  DR_GETENT=canned, CLOCK=fixed): render one frame, strip SGR, assert columns/values.
- LIVE smoke (operator): `sudo -u drvps drvps-top --once`, then interactive.

## 11. Placement & git
`tools/drvps-top`. Do NOT reuse `dr-vps list/distros/snap-ls` (they call dr_vps_store_init ->
dirs/tables/ALTER migrations/index/trigger/lock). Raw read-only adapters; share ONLY
dr_vps_api.sh config. Git DEFERRED until operator on-host test; then commit with repo
discipline

## 12. Out of scope (YAGNI v1) / hardening paths
No VM/snapshot actions; no mouse; no config file; no history/graphs; no multi-host; no
install integration. HARD-GUARANTEE DB non-interference (a drvps-side periodic
`VACUUM INTO`/`.backup` snapshot the TUI reads instead of the live file -- slightly stale,
writer-owned) and GUEST-USED memory (guest agent / RSS) are noted future paths, NOT built.
