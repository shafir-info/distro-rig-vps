# Egress-splice loop — hardening backlog (drvps→root defense-in-depth)

The egress member↔operator loop converged through an extended external code review. The
member-facing security surface (owner-scoping, admit gate, argv/FQDN validation, no cross-owner/leak) has
been clean throughout and is **container-verified** end-to-end on every supported host family
(fedora44 + rocky9 dnf/RHEL, ubuntu + debian apt) — real squid, splice tunnels end-to-end, no MITM —
with the bare-metal on-host run still pending (see STATUS.md).

The root approve tool's crash-recovery + shared lock were hardened against an **already-compromised
or buggy `drvps` service account** (a drvps→root escalation/DoS boundary). The review explicitly confirmed
the items below are **NOT reachable by an ordinary `drvpsvc` member** — the egress store
(`/var/lib/distro-rig-vps/egress`, drvps-owned `0700`) is reachable by a member only through the socket
(the watcher, as drvps, writes). They are the correct bar for a root sink-opener but are strictly
defense-in-depth beyond the member threat model.

> SUPERSEDED (0.3.0): the v2 egress store (`EGRESS-STORE-ARCH-UPGRADE.md`, shipped) is exactly the
> fd-relative, root-owned store-access refactor the residuals below asked for. They are retained here for
> history; the v2 store's access model addresses this drvps→root defense-in-depth class.

## Closed
- reqid identity / retry / add-remove-add cycle; status-by-reqid outcomes + reasons; max_active at commit;
  per-owner outcome; expiry sweep + retention GC; claim crash-recovery + abandoned-batch release; the
  commit journal (finish-or-repair, health-gated, single fleet snapshot, retained-journal gates cmd_apply);
  the shared **root-owned fixed lock** (`/etc/distro-rig-vps/egress.lock`, no chown-of-symlink, bound to the
  store base, O_NOFOLLOW); FIFO/symlink/directory/over-long-name/malformed-content quarantine; a bounded
  `_names` sweep; the journal-dir O_NOFOLLOW guard.

## Residual (v1-era; addressed by the v2 store refactor above)
These all require WRITE access to the drvps-owned store (i.e. the drvps service account or root), so they
are NOT member-reachable. Fixing them well means opening the store base ONCE with `O_DIRECTORY|O_NOFOLLOW`
and deriving EVERY namespace fd via `openat` from it (no path-based `os.listdir`/`os.unlink`/`_read_bytes`
on `base/<ns>`), plus a canonical-base handle held across the whole op:

1. **Swapped-ancestor realpath TOCTOU** — `_lock_path` canonicalizes `base` once; a symlink swapped on an
   ancestor between lock-selection and the later `_dfd(base/<ns>)` opens could reach the production store
   under a non-production lock. `_dfd` is O_NOFOLLOW on the FINAL component only. Fix: resolve + open the
   base to a single held dir-fd, derive the lock + all namespaces from it.
2. **Path-based journal/pending scans** — `_recover_journals` now O_NOFOLLOW-guards the journal dir, but its
   per-entry `_read_bytes(base/journal/<bid>)` + `_unlink(base/journal,<bid>)` remain path-based (a
   check-then-use TOCTOU on the journal dir). Fix: do them dir-fd-relative from the guarded journal fd.
3. **Uncapped sweeps under the exclusive lock** — `gc_terminals`, `recover_claims`, root `_recover_journals`,
   and the root pending pre-scan still `os.listdir()`/`sorted()` the full namespace; a drvps/root-planted
   mass namespace could exhaust memory / hold the lock. `_names` is capped but these bypass it. Fix: apply
   the same scandir + budget to every namespace enumeration.
4. **Capped-sweep continuation cursor** — `_names`' cap has no cursor, so a permanently-oversized live
   namespace may re-process the same first `_MAX_SWEEP` entries. Fix: process-then-advance, or quarantine
   forward.

Severity: defense-in-depth (drvps→root). Recommend scheduling the fd-relative store-access refactor as a
single follow-up that closes 1–4 together; not a member-facing blocker for the 2.1 egress feature.
