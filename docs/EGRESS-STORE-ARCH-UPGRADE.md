# Egress-store architecture upgrade — root-cause fix for the recurring root↔drvps hazards

**Status:** IMPLEMENTED (the v2 store shipped in 0.3.0). Supersedes the incremental hardening in
`EGRESS-HARDENING-BACKLOG.md`. Design validated by a focused external **architecture** review — its
mandatory corrections are folded in below (topology, claim leases, snapshot-first, root session lock,
pending-aware GC, exact schemas). `dr-vps-setup` (`step_proxy`) provisions this store at install time.

## 1. The pattern — a recurring MAJOR class, all one shape

The member-facing surface is clean; the recurring MAJORs all landed on the same
**root↔drvps store-access boundary**, each patched in isolation:

| Hazard on the boundary | Per-instance patch (each insufficient) |
|------------------------|----------------------------------------|
| drvps-planted namespace **symlink** splits the lock / redirects root | `O_NOFOLLOW` on every open |
| swapped-ancestor **TOCTOU**; path-based scans; uncapped sweeps | `open_base_fd`+`open_sub_fd`; `list_names` cap |
| **post-open rename race**: drvps renames a held dir between root's open and `mkdirat` → privileged mkdir escapes | root stops creating (`provisioned()`) |
| **cross-UID perms**: root writes `0600 root:root`; drvps can't read | `0644` + umask-independent `fchmod` |

`O_NOFOLLOW` validates a *name at open time*, not that a held inode stays beneath the base, so it can never
close the rename-race; and while root and drvps both write the same directories there is always another
symlink / rename / mode / TOCTOU vector. Patching per-instance is a losing game.

## 2. Modules on the hazard surface

- **`tools/drvps_egress_req.py`** — store primitive layer (fd ops, atomic writes, modes, sweeps, claim
  recovery, GC). *Most-affected.*
- **`bin/drvps-egress-approve`** — the **root** consumer (reads store, applies to squid, writes decisions,
  clears pending, commit-recovery). The privileged sink.
- **`tools/drvps_egress_member.py`** — the **drvps** consumer (member submit/list/status via the socket
  watcher; reaper `expire` sweep).
- **`bin/dr-vps-setup` `step_proxy`** — provisions the shared lock AND the root-owned v2 store namespaces
  (this resolved the "who creates the namespaces" question: the root installer is the single provisioner).

## 3. Root cause — shared-write directories across a privilege boundary

Both root (approve) **and** drvps (member + reaper) create/delete/rename/chmod entries in the **same**
directories. The trust boundary is drawn *through the middle of shared mutable directories*, so every
privileged filesystem op root performs inside a drvps-mutable directory is a standing hazard.

### Evidence — who-mutates-what (grep-verified)

| Namespace | mutated by **drvps** | mutated by **root** |
|---|---|---|
| `pending/` | submit, `_clear`, `_quarantine_invalid` | `_clear_pending`(unlink), pre-scan quarantine |
| `owner/` | submit, `_clear`, `_quarantine_invalid` | `_clear_pending`(unlink), pre-scan quarantine |
| `review/{claimed,copy,manifest}` | `recover_claims`(release) | `claim_batch`, `release_batch` |
| `review/journal` | — | `_fd_install`, `_jclear` |
| `decisions/root` | `gc_terminals`(unlink) | `write_root_decision` |
| `decisions/expiry` | `write_expiry_decision`, `gc_terminals` | (read only) |

**Every namespace except `review/journal` has two writers straddling the boundary.** `review/journal` — the
one single-writer namespace — has produced *zero* MAJORs. That is the whole disease.

## 4. The fix — one writer per namespace, under a ROOT-OWNED anchor

Re-partition so each namespace has exactly one writer/owner and the other side only **reads** it (hardened
hostile-inbox opener). The critical correction from the architecture review:

> **Rename/unlink of a child is authorized by the *parent* directory's permissions, not the child's
> ownership.** A root-owned `review/` under a **drvps-owned** base is still renameable/removable by drvps —
> the post-open rename hazard one level up. Therefore the anchor **and every intermediate parent** of a root-owned
> namespace must be **root-owned and non-writable by drvps**; only drvps *leaf* directories are drvps-owned.

### Target topology (installer-created; nothing created at runtime)

The anchor is a **root-owned sibling** `/var/lib/distro-rig-vps-egress` (NOT `/var/lib/distro-rig-vps/egress`
— that base is drvps-owned `0750` for the VM pool, so drvps could rename an `egress` child under it). Its
ancestors (`/var/lib`, `/`) are root-owned, so no drvps-writable directory sits above any root namespace.

```
/var/lib/distro-rig-vps-egress/         root:drvps  0710   # anchor: root-owned -> drvps cannot rename/replace children
├── pending/                            drvps:drvps 0700   # drvps writes requests; root READS (hostile inbox)
├── expiry/                             drvps:drvps 0700   # drvps writes expiry terminals; root READS
├── root-private/                       root:root   0700   # invisible to drvps
│   ├── batches/                        root:root   0700   #   immutable request SNAPSHOTS + manifests
│   └── journals/                       root:root   0700   #   commit journals
└── published/                         root:drvps  0750   # root writes, drvps READS (group drvps)
    ├── decisions/                      root:drvps  2750   #   applied/rejected terminals   (files 0640 root:drvps)
    └── claims/                         root:drvps  2750   #   read-only claim LEASES        (files 0640 root:drvps)
```

- The **anchor** is `root:drvps 0710`: drvps may traverse (x) but not write (no rename/replace of children).
  If `/var/lib/distro-rig-vps` is itself drvps-writable, the anchor is placed under a **root-controlled
  sibling** (or that parent's ownership is corrected) so no drvps-writable directory sits above a root
  namespace.
- **drvps leaves** (`pending/`, `expiry/`): drvps writes entries *inside*; cannot rename the leaf itself
  (parent is root-owned). Root only READS them.
- **root-private** (`batches/`, `journals/`): `root:root 0700`, drvps cannot even see them. The authoritative
  snapshot + journals live here (§5).
- **published** (`decisions/`, `claims/`): `root:drvps` with setgid `2750` dirs and `0640 root:drvps` files
  — a dedicated **group** (drvps) read interface, umask-independent via explicit `fchown`+`fchmod`, instead of
  a world-readable `0644`. This is the *only* root→drvps read edge that carries root-written data.

### Snapshot-first — the frozen copy is the ONE authoritative source

Today root validates + builds the operator display + candidate fleet from the **pre-scan** read of `pending/`,
then `claim_batch` **re-reads** `pending/`. A drvps process ignoring the advisory lock can change a pending
file between those reads, so the displayed/committed op can differ from the frozen copy. Corrected flow:

```
drvps pending/  --bounded hostile read-->  root-private/batches/<id>/ (immutable snapshot + manifest)
                                                     |
                          validate + operator display + dry-run + journal + COMMIT  (all from the snapshot ONLY)
                                                     |
                                          published/decisions/<reqid>  (terminal, 0640 root:drvps)
```

There is **no second semantically-authoritative read from `pending/`**. The batch digest binds {batch id,
reqids, exact canonical request bytes, owner uid, policy/fleet version}. After the snapshot is published, no
privileged step depends on inbox mutability.

### Duty reassignment (each side maintains only its own zone)

1. **root stops mutating drvps leaves.** No `_clear_pending`, no pending pre-scan quarantine. After writing
   `published/decisions/<reqid>`, root does nothing in `pending/`/`expiry/`.
2. **drvps reaper stops mutating root zones.** No `recover_claims`/`release_batch`/root-decision GC. Claim
   recovery + stale-batch release + root-decision retention-GC move **entirely into the root approve tool**.
3. **The reaper keeps** its own zone: expire past-TTL `pending/` (write `expiry/`), sweep orphan pending,
   GC `expiry/`. To preserve the *under-review* guarantee across the operator's YES pause it **reads**
   root-published **claim leases** (`published/claims/<reqid>`, root-written, drvps-read): a fresh lease ⇒
   skip expiry; it never writes/deletes the lease.
4. **The drvps reaper clears decided pending** (it already does: "decided but pending not cleared → drop it")
   — so `pending/` clearing is drvps-sole-writer with no new code.
5. **Collapse `owner/` into the request record.** The pending request already carries the peer-cred-stamped
   `owner_uid`; the sidecar adds a mutable two-file join, an orphan sweep, and display-mismatch risk for no
   added authority (both are written by the same drvps domain). Root snapshots the single request record.
6. **Installer provisions the whole tree** (root anchor + intermediate parents + leaves, correct owners/modes/
   setgid/group) at install, writing a **root-owned schema/installation marker last**. Runtime tools
   **verify** owner+group+mode+type+schema-version (not mere existence) and **fail closed hard** on a
   root-zone failure; a missing marker ⇒ "not installed"; a present-but-damaged tree ⇒ hard failure (never
   silently "no work").

### Root session lock (separate from the global data lock)

The global data lock is deliberately released across the YES prompt, so a second root approval can start
concurrently. Add a **root-only approval-session lock** in a root-controlled dir, held for the *entire*
command including the YES pause. Then any **unjournaled** root-private batch present at startup is provably
abandoned by a dead process and can be released immediately — no wall-clock TTL guessing, no risk of releasing
a live claim. The global data lock still releases during the prompt so member submit + reaper continue.

Root startup recovery (under the session lock) is **two-phase**: (a) finish-or-retain **journaled** commit
batches (existing `_recover_journals`); (b) release every **non-journaled** abandoned batch + its published
claim leases. `_recover_journals` alone is insufficient — it misses crashes during claim construction, after
claim before journal, during the prompt, and during clean-abort release.

**Journal completion is STATE-SPECIFIC — the *expected* applied terminal, not merely *any* terminal.** The
design accepts that a fully-compromised drvps can publish a rival `expiry` terminal ignoring the data lock
(§5). So an `applied` journal entry is "complete" **only** when an exact, schema-valid **root** decision says
`applied` AND is bound to the expected `{reqid, batch id, batch digest, op, resulting-state hash}`. An
`expiry` or `rejected` terminal for that reqid is a **conflict, never completion**: retain the journal, batch,
and leases and enter **hard-degraded** recovery (surfaced to the operator) — do **not** clean up merely
because "a terminal exists". The identical rule applies immediately **after** a successful commit: root must
**not** skip publishing its own `applied` decision because a rival `expiry` record appeared (today's
`read_terminal`-guarded "skip if any terminal" at both the recovery and post-commit loops is unsafe under
this threat and must become state-specific).

### Pending-aware terminal GC — BOTH terminal namespaces

Root now writes a terminal but no longer clears pending; the drvps reaper clears decided pending. Both crash
windows are identical: publish `terminal`, crash before deleting `pending/<reqid>`, later GC removes the
terminal, the surviving pending resurrects as undecided. The invariant therefore binds **both** GC owners
(root over `published/decisions/`, drvps over `expiry/`):

> Neither root-decision GC nor expiry-decision GC may remove a terminal unless a **complete, bounded pending
> scan under the global data lock** proves the corresponding `pending/<reqid>` absent. If the inbox is missing
> unexpectedly, unreadable, malformed at the directory level, or overflows, that GC pass removes **zero**
> terminals. A two-terminal (degraded) pair is **never** independently collected. GC is retention cleanup,
> **not** corruption repair — malformed terminals and degraded pairs are **retained for diagnosis**.

Because root-decision GC moves out of the reaper, it needs an explicit execution path so retention is not
merely operator-activity-dependent: a documented `drvps-egress-approve gc` maintenance subcommand (operator-
or root-cron-invoked; no new `User=root` daemon).

### Exact schema enforcement on every cross-domain read

`read_terminal` currently accepts *any* JSON dict; `read_request` validates most but not all fields. Under the
new boundary, enforce exact schemas so a malformed record fails closed instead of driving state:
- **root decision** (drvps reads to clear pending): reqid==filename, `state ∈ {applied,rejected}`, required
  fields+types, valid state/reason combo, size+ownership per the publication contract. A malformed root
  decision must **not** clear pending.
- **inbox request** (root reads → privileged action): regular file, size cap, no set-id, `st_uid==drvps_uid`,
  preferably `st_nlink==1` (blocks a DAC-override confused-reader onto an unexpected root-owned hardlink),
  exact reqid↔body binding, strict schema + primitive types.
- **expiry terminal** (root reads): filename==reqid, `state=="expired"`, valid ts/attribution, no unknown
  fields.

## 5. What each hazard class becomes (after the corrections)

- **Symlink redirect / rename / unlink TOCTOU on a root MUTATION** → *impossible by construction*: root mutates
  only root-owned dirs whose parents are root-owned; drvps has no write there.
- **Privileged namespace creation** → removed from runtime (installer-only).
- **Attacker chmod/chown of root records** → closed by DAC ownership.
- **Cross-UID mode ambiguity** → reduced to one explicit `published/` group interface (`0640 root:drvps`).
- **Snapshot race (displayed ≠ committed)** → closed by copy-out-first authoritative snapshot.
- **Residual (accepted, bounded):**
  - *Hostile inbox content* — a well-formed request still proposes a squid allowlist change; the boundary is
    the existing strict schema + exact canonicalization + fixed op/port set + no path/command construction +
    human YES + fleet revalidation before commit. (A read cannot escalate *by itself*, but it feeds policy —
    so the validation gate, not the read, is the control.)
  - *DoS* — a compromised drvps can delete/replace pending before root reads, fill the inbox to the fail-closed
    cap, or exhaust space/inodes. Mitigations: quota, a low `list_names` cap (kept), disable unprivileged
    mounts for the account, optional `RESOLVE_NO_XDEV`. These are availability-only; no approval bypass.
  - *Competing expiry terminal* — a fully-compromised drvps ignoring the lock can write a rival `expiry`
    terminal → a degraded/`status`-confusing state, but **not** a sink-open (root validation + YES gate hold).
    A single root terminal-arbiter would close it but needs a root daemon (rejected — violates never-root).

## 6. Alternatives considered

- **`openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)` while keeping shared
  writers** — *not preferred*. It constrains one path resolution but does **not** establish durable ownership
  of a dir inode nor stop relocating an already-open mutable dir before a later `mkdirat`/`renameat`. Use it
  **opportunistically to harden the inbox reads after the split**, not instead of it.
- **Copy-out to root-owned staging** — not an alternative; it *is* the strongest form of the split and is
  incorporated (§4 snapshot-first).
- **Single root terminal arbiter (daemon)** — true first-terminal serialization, but a continuously
  privileged service + IPC + parse surface; departs from the never-root-daemon model. Rejected; the
  cooperative lock + ownership split is the better trade-off.
- **Socket-only request transport** — removes filesystem traversal but not untrusted-content or snapshot
  concerns (a compromised service can equivocate across reads); complicates operator tooling/recovery.

## 7. Implementation invariants (normative — must not miss while coding)

- **Lease protocol.** Exact claim-lease schema: version, filename-bound reqid, batch id, batch digest,
  expiry/renewal time. The approve tool **renews** the lease periodically throughout the *unbounded* YES
  pause. A malformed / wrongly-owned / unreadable / ambiguously-stale root claim must **suppress expiry AND
  surface a root-zone failure** — it must never be treated as "no claim".
- **Ordering (write-before-visible, terminal-before-cleanup).** Under the data lock: durable snapshot +
  manifest first, then claims, then release the lock for the YES pause. Before any sink mutation: durable
  journal first. After a successful commit: exact root `applied` decisions first, *then* remove claims, then
  journal, then batch. **Never remove a lease before its terminal is durable.**
- **Lock discipline.** Two lock files at **fixed root-owned paths outside the cutover subtree**. One
  acquisition order everywhere: **session lock, then data lock.** Every two-phase-recovery mutation holds
  both.
- **Snapshot authority.** After snapshot publication, owner uid, op, host, port, operator display, dry-run,
  decision attribution, journal entries, and recovery all come from the **snapshot**. `pending/` may be
  consulted afterward **only** for lifecycle facts (GC existence) — never for semantic content.
- **Cross-domain metadata checks (mandatory, all four record kinds).** `st_nlink == 1` is **mandatory** (not
  "preferably") — it blocks a DAC-override confused-reader onto an unexpected root-owned hardlink. Apply
  bounded regular-file, no-set-id, uid/gid, mode, link-count, filename↔body, canonical-byte, and exact-field
  checks to **requests, expiry terminals, root decisions, and claim leases** alike.
- **Migration handoff.** Build the Stage-3 fresh tree under a **root-only, non-traversable staging parent**;
  complete every root write + `fsync` before exposing the final anchor; chown the intended leaves while the
  staging parent is still inaccessible to drvps; after exposure root **never** populates those leaves. Do
  **not** reuse the Stage-2 adversarial test tree.

## 8. Staged plan (corrected — build inactive v2, test split-UID FIRST, migrate by copy-out)

Ownership can't flip while old duties remain (that breaks the running store), and the split-UID e2e must gate
*every* ownership/mode change — so it cannot be the last stage.

- **Stage 0 — invariants + tests, NO live filesystem change.** Define the v2 layout, UID/GID/mode/setgid
  contract, schema marker, version detection. Add split-UID tests + adversarial tests (parent rename,
  namespace replacement, mutable pending content, wrong owner/group/mode, `st_nlink>1` hardlink, overflow)
  immediately. Live store untouched.
- **Stage 1 — implement v2 semantics behind an inactive layout.** Root never mutates inbox leaves; reaper
  never mutates root zones. Snapshot-first (validate/display/journal/commit from the snapshot only). Add
  root-private batches + published claim leases. Add the root session lock. Move claim recovery + decision GC
  into approve; make decision GC pending-aware. Exact-schema + owner/`nlink` verification, fatal on root-zone
  failure. Collapse `owner/` into the request record.
- **Stage 2 — provision a parallel v2 tree** under a root-controlled anchor: root-owned common parents, only
  the intended leaves chowned to drvps, dedicated read group, (SELinux/AppArmor labels if relevant), fsync
  dirs, root schema marker written **last**. Run the full split-UID e2e against it.
- **Stage 3 — quiesced live migration + atomic cutover.** Acquire the root session lock; stop watcher/reaper;
  acquire the global data lock; ensure no other root approval active; run journal recovery (abort if any
  journal unresolved or fleet/squid degraded); require no live pre-journal batch (else classify abandoned).
  **Build a FRESH v2 tree and copy only validated, bounded, regular records via fd-relative no-follow reads**
  (do not re-chown the hostile old tree in place; do not migrate untrusted review artifacts blindly —
  reconstruct or require a clean review state). Cross-check pending/owner/terminal conflicts. Publish the v2
  activation marker last. Switch via a **fixed root-controlled path / rename within a root-owned parent**
  (never a symlink in a drvps-writable dir). Start runtime; smoke submit/status. Fail closed on any race.
- **Stage 4 — retire legacy.** Keep the old tree read-only/quarantined for a bounded diagnostic window; remove
  legacy runtime + creation paths; keep the split-UID + adversarial tests permanently. No auto-rollback once
  v2 decisions are published (unless reverse migration is explicitly designed).

**Migration test states** (each migrated or explicitly rejected): ordinary pending; owner orphans (if
retained); expiry decisions; root decisions with pending not yet cleared; two-terminal degraded; partial
claim before manifest; published claim without journal; journal before / after fleet install; malformed/
non-regular; overflow; wrong uid/gid/mode; a drvps attempt to rename/replace every root namespace.

## 9. Test-gate blind spot this closes

The offline suites run under **one UID**, so they structurally cannot see a root↔drvps ownership/permission
failure (the class the cross-UID perms hazard belonged to). The split-UID container e2e (run as root, real `drvps` user) is the standing
regression for the whole boundary and gates every ownership stage; the offline suite keeps the mode/owner
invariant assertions as a fast proxy.

## 10. Scope + recommendation

This is a **v2 store** (new topology + snapshot-first + root session lock + claim leases + a live migration),
not a patch. It is larger than any single prior round, but it **ends the class** — after it, a compromised/
buggy drvps has only bounded DoS, never an approval bypass or a privileged-mutation escape, and future
operations inherit the safety by *placement* rather than by remembering to add `O_NOFOLLOW`. Recommendation:
**adopt the corrected ownership split (this document) as the drvps 2.1 egress architecture**, implemented via
Stages 0→4, replacing the incremental hardening loop.
