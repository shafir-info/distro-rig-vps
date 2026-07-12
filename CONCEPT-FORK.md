# CONCEPT — VM SNAPSHOT (installed-state bundle) + companion metadata (.md)

## STATUS: design converged and SHIPPED (v1 live-validated; see STATUS.md / CHANGELOG.md)
The spec below is the authoritative design of the snapshot feature as built. Operator decisions baked in:
verb name is `snapshot` (not `fork`); snapshots are an UNPRIVILEGED, user-owned artifact class, hard-
segregated from goldens; `--keep-secrets` is a first-class mode; a snapshot is a self-contained bundle
DIRECTORY.

======================================================================================================
## DESIGN (v1, authoritative)
======================================================================================================

### R3.0 v1 SCOPE (surgical first cut) + NON-GOALS
- v1 VERBS: `snapshot <vm> [--keep-secrets] [--notes STR]` (create), `use <name> --from-snap <snap-id>`
  (VM from a snapshot), `snap-rm <snap-id>`, `snap-ls`, `snap-show <snap-id>`, `snap-rename <snap-id> <name>`.
- v1 NON-GOALS (DEFER; specify only where noted): snap-export/snap-import (tar security surface);
  `promote` snapshot->golden (SPECIFY the trust-transition contract now, DEFER the code); restore/rollback
  (reserved daemon verbs, not needed to ship snapshot/use/delete); golden human-name BACKFILL (only if the
  typed-resolver work forces it -- avoid broad test churn); auto TTL pruning; rich install-path
  reconstruction from arbitrary shell history (prefer deterministic package/provision metadata + opt-in cmdlog).

### R3.1 TYPED ARTIFACT LEDGER (resolves the s5 tension + decision-6c). images = a KIND-TAGGED ledger,
###      never "row in images == trusted golden". Snapshots keep AUTHORITATIVE metadata in `snapshots`.
- `images` gains `kind TEXT NOT NULL DEFAULT 'golden' CHECK(kind IN ('golden','snapshot'))`. PREFIX-KIND
  invariant: kind='golden' => id GLOB 'drvps-raw-v1-*'; kind='snapshot' => id GLOB 'drvps-snap-v1-*'.
- TYPED RESOLVERS (no lifecycle/build/list path may call an untyped "resolve image" except one private
  low-level helper): `dr_vps_resolve_golden(id|name)` requires kind='golden' + raw prefix + POOL_DIR fence +
  no matching snapshots.id; `dr_vps_resolve_snapshot(id|name)` requires kind='snapshot' + snap prefix +
  EXISTS snapshots(id) + SNAP_DIR fence + bundle image == <SNAP_DIR>/<id>/image.qcow2. Typed vm_create:
  `vm_create_from_golden` / `vm_create_from_snapshot` (or a required kind arg).
- CLASSIFY every existing `images` query as golden-only | snapshot-only | generic-internal. `distros`,
  build output, golden selection ("latest distro"), golden delete, provenance lookup => FILTER kind='golden'
  + raw prefix (prefix-only is NOT enough; future code forgets). `snap-ls/show/rm`, `use --from-snap` =>
  FILTER kind='snapshot' + snapshots membership.
- GC DISPATCHES BY KIND: golden delete touches only POOL_DIR; snapshot delete touches only its bundle dir;
  the refcount refusal stays shared; the generic "unreferenced images" GC must NEVER prune a snapshot just
  because no VM currently backs it (a snapshot is an intentional artifact, not disposable state).

### R3.2 STORAGE + NAMING (unchanged core; fenced)
- `DR_VPS_SNAP_DIR := ${DR_VPS_STATE_DIR}/snapshots` (drvps-owned, distinct from POOL_DIR). Bundle dir per
  snapshot = <SNAP_DIR>/<snap-id>/ : image.qcow2 (0640 drvps:qemu), provenance.json (0640, NEVER world-read),
  snapshot.md (0640), secrets/ (0700, ONLY under --keep-secrets). realpath-fence EVERY path under SNAP_DIR;
  reject symlink/hardlink/traversal/preexisting-final-dir.
- CONTENT id = `drvps-snap-v1-<vsize>-<sha256>` (same raw-stream digest algo; prefix chosen BY THE IMPL, NOT
  user argv -> a dedicated `dr_vps_snapshot_digest` wrapper, so an unprivileged caller can NEVER mint a
  drvps-raw-v1-* golden). HUMAN name = `drvps-snap-<distro>-<UTC>-<short8>`; grammar [A-Za-z0-9._:-]+,
  bounded length, UNIQUE per kind.

### R3.3 SCHEMA (extend `snapshots`; add `images.kind`+`name`; idempotent ALTER + fail-closed post-migration)
  images(id PK[was artifact_id], name, kind DEFAULT 'golden' CHECK(golden|snapshot), provenance, golden_path, created_at)
  snapshots(
    id PK,                      -- = images.id, drvps-snap-v1-...
    name TEXT NOT NULL UNIQUE,
    source_vm_id TEXT NOT NULL, -- provenance string (NOT necessarily an FK)
    parent_golden_id TEXT NOT NULL,   -- RENAMED from the trap `artifact_id`; PROVENANCE, not a disk dep,
                                      -- NOT a hard FK (snapshot is flattened+standalone; parent may be GC'd
                                      -- -> store parent provenance in provenance.json to survive that)
    bundle_relpath TEXT NOT NULL,     -- RELATIVE "<id>", not absolute (state-dir moves/imports); fence on read
    secret_bearing INTEGER NOT NULL DEFAULT 0 CHECK(0,1),
    scrub_profile TEXT NOT NULL,
    shutdown_mode TEXT NOT NULL CHECK('clean'|'forced'),
    validation_status TEXT NOT NULL CHECK('passed'|'skipped'|'failed'),
    notes TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))
- POST-MIGRATION INVARIANTS (fail-closed like domain_uuid/net): kind='snapshot' <=> exactly one snapshots.id;
  no snapshots.id starts drvps-raw-v1-; no kind='golden' starts drvps-snap-v1-; every bundle fenced + contains
  image.qcow2+provenance.json+snapshot.md; secret_bearing=1 iff provenance says so.
- DUPLICATE-CONTENT (content-addressed collision): if id exists AND provenance-equivalent -> return existing id
  idempotently; if id exists with DIFFERENT provenance -> FAIL CLOSED (tell the user the content artifact
  already exists); never overwrite sidecars.

### R3.4 CREATE SEQUENCE (s7, hardened). `dr_vps_snapshot_create <vm> [--keep-secrets] [--notes] [--profile]`:
  1. ACQUIRE a per-VM lifecycle LOCK (+ per-artifact lock) -- the gate proves identity, it does NOT serialize;
     block concurrent exec/destroy/recreate/snapshot/use/source-disk-mutation.
  2. GATE host-side: `dr_vps_gate_vm lifecycle <vm>` (refuse tampered/ambiguous). Host-side only; NOT guestexec.
  3. CAPTURE PROVENANCE BEFORE SCRUB: source golden id/name, overlay path, domain UUID, shutdown mode, scrub
     profile, dnf txn shape (NEVRs/repo-ids/`dnf history` ids), app pack hash, service/firewall/SELinux state,
     `status` warning set, + (opt-in) shell-history/cmdlog. (If the VM is up + guestexec-openable, pull
     /root/.bash_history NOW; a kept-failed VM = cmdlog-only + a note.)
  4. SHUTDOWN: ACPI `virsh shutdown` + bounded wait to domstate 'shut off'; on timeout -> force-off, record
     shutdown_mode='forced' (then validation boot is MANDATORY, not skippable). NEW helper dr_vps_domain_shutdown.
  5. FLATTEN only while OFF, into a TEMP bundle: mktemp -d under SNAP_DIR (realpath-fenced), `qemu-img convert
     -O qcow2 <overlay> image.qcow2.tmp`. Assert standalone (no backing, no external data-file, vsize<=cap).
  6. SCRUB (default) via an EXPLICIT-ALLOW-LIST virt-sysprep (`--operations machine-id,ssh-hostkeys,cloud-init,
     logfiles,tmp-files,bash-history,udev-persistent-net,...` -- PRESERVE rpm-db/package-state/selinux-modules/
     enabled-units; run `--no-rpm-db` OR follow with rpm --rebuilddb). SEAM it for offline bats. App-
     specific scrub (an app's /opt tree, its deploy logs) lives in a PROFILE HOOK, not
     generic core. Skipped under --keep-secrets (secret_bearing=1, LOUD md; secrets also bundled 0700).
  7. Assert standalone AGAIN (post-sysprep). DIGEST the scrubbed base -> drvps-snap-v1-<vsize>-<sha>.
  8. VALIDATION BOOT via a DISPOSABLE OVERLAY (CRITICAL: booting the candidate DIRECTLY regenerates machine-id/
     logs -> CHANGES THE DIGEST). Create a temp overlay backed by the scrubbed base, boot it, health-check
     (getenforce; expected SELinux modules present; no unexpected AVC; app healthcheck), DISCARD the overlay. Digest/
     register the ORIGINAL unbooted scrubbed base. validation_status = passed|skipped|failed; forced-shutdown
     REQUIRES passed. (Live step -> flag-gated so offline bats skips the boot but the code path exists.)
  9. REGISTER LAST, TRANSACTIONALLY: atomic-rename temp bundle -> <SNAP_DIR>/<id>/; one DB txn INSERT
     images(kind='snapshot') + INSERT snapshots(...); commit. On DB fail -> remove temp bundle. On FS-delete
     fail after rollback -> leave a fenced orphan + provide `snap-fsck`. STDOUT = the bare snap id.
 10. Source VM LEFT POWERED OFF (document; add `--restart-source` later, do not surprise operators).

### SECURITY
- Unprivileged create cannot: mint drvps-raw-v1-* (impl-chosen prefix), write into POOL_DIR (SNAP_DIR fence),
  or register kind='golden' (kind-constrained: drvps-user may register ONLY kind='snapshot'; golden stays
  privileged build/promote). The lifecycle gate protects OPERATIONS on a VM; artifact TRUST is protected by
  typed resolvers + store invariants, not the gate.
- SECRET-BEARING: secrets live INSIDE image.qcow2 too, not just secrets/. image.qcow2 0640 drvps:qemu => the
  qemu trust boundary can read it -> DOCUMENT qemu as inside the TCB (or store secret bases 0600 + grant qemu
  only at VM-create). `use --from-snap` on a secret_bearing snapshot REQUIRES `--allow-secret-bearing`; a
  secret-bearing base is DENIED as a multi-clone base by default (machine-id/host-key collisions). Sidecars
  0600/0640 never world-readable; snap-show goes through the daemon, not direct FS.
- CMDLOG is high-risk (argv = tokens/passwords/cred-URLs/heredocs) -> raw cmdlog is OPT-IN
  (`--record-install-path`) or structured-known-safe only; default install-path = package/dnf-history/repo-id/
  txn-id + status snapshot; raw logs stored sensitive, only REDACTED summaries rendered into md. Redacting
  `--flag VALUE` alone is NOT sufficient.
- PROMOTE (specify, defer code) = a PRIVILEGED trust transition: re-scrub + revalidate + re-digest as
  drvps-raw-v1-* + copy into POOL_DIR + register kind='golden'; REFUSE secret_bearing=1 + refuse status
  warnings unless --allow-warnings. Never a rename.

### R3.6 bats/testability + surgical footprint (v1)
- NEW src/dr_vps_snapshot.sh (create/rm/ls/show/rename + digest wrapper + the create sequence; reuses
  identity/store/image/gate/storage/domain). Seams: DR_VIRSH (fake shutdown/domstate), DR_QEMU_IMG (real on
  tiny fixtures), DR_VIRT_SYSPREP (:=virt-sysprep; `true` no-op in bats), validation-boot flag off in bats.
- store: images.kind+name migration + typed resolvers + snapshot_add/get/ls/delete/rename + invariant checks.
- daemon (drvps_rigctl.py): wire the reserved "snapshot" op (+ snap-rm/snap-ls/snap-show) into build_action +
  VM_VERBS(lifecycle) + the submit validator; opt-in cmdlog hook. bin/rigctl + bin/dr-vps: the v1 verbs.
- NEW tests: snapshot.bats (create->standalone x2->sysprep-seam->digest->register->md; secret_bearing;
  gate-mismatch refusal; refcount-gated rm; use-from-snap typed; duplicate-digest; hostile-name/traversal/
  prefix-mismatch/kind-mismatch; generic-GC-does-not-delete-snapshot; forced-shutdown-requires-validation).
  Keep the full suite green. NEW snap-fsck consistency checker (images/snapshots/bundles/sidecars/referrers).

