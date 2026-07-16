# Releasing distro-rig-vps

One script gates a release: `tests/release-gate.sh`. It has three tiers so you can go from a code change to a
verified, committable release with a predictable sequence. Everything a release must pass lives in that script
(single source of truth) -- CI runs its offline tier, so a green CI means the whole offline suite passed, not
just the bats subset.

## The three tiers

```
tests/release-gate.sh              # TIER 1  offline: bats + python + sh + shellcheck + ast + residue
tests/release-gate.sh --container  # + TIER 2  disposable rootless-podman e2e (real squid, split-UID, atomic-install)
tests/release-gate.sh --live       # + TIER 3  the nested "really works" run (needs KVM)
tests/release-gate.sh --all        # tiers 1+2+3
```

- Tier 1 needs no podman and no KVM; run it on any dev box before every commit.
- Tier 2 needs rootless `podman`; it builds/uses disposable containers (no host-network / bridge touch), so it
  is safe on a machine that is also running the live rig.
- Tier 3 needs `/dev/kvm` and touches a real rig: it boots a small, self-cleaning L1 VM, installs the rig inside
  it, and drives the real egress + drvps-top wiring. Run it on a KVM host. Via the gate, `--live` is all you
  pass (the gate exports `DRVPS_LIVE=1` for the nested run); running `tests/dogfood/nested-selftest.sh` directly
  needs `DRVPS_LIVE=1` yourself. It is gated so it never runs by accident.

An UNREQUESTED tier SKIPs; a tier you EXPLICITLY request (`--container`/`--live`) whose prerequisite is missing
is a FAILURE, not a skip -- you asked to run it and it did not. The final line is `RELEASE-GATE: PASS` or `FAIL`
with a per-suite tally. Run tier 1 as a NON-root user -- the
seam suite asserts `0700`/`0600` refusals a root process would bypass.

## What each tier is protecting

The tiers exist because real wiring bugs slipped past a green offline suite: the installer-to-consumer seam (the
installer persisting the egress render inputs that `drvps-egress-approve` reads) was only ever exercised with a
`test_root` seam, so no test ran the real installer through to the real consumer on real paths. Tier 3 closes
that -- it runs the real `dr-vps-setup` and then the real egress + drvps-top flows. Tier 2's `setup-atomic-install`
unit test (with a positive control) pins the atomic-publish helper behind that persistence. Keep new features
honest by adding their live assertions to `tests/dogfood/nested-selftest.sh` (tier 3), not just an offline seam.

The gate also guards against a test being silently unrun: every `tests/*.sh` must be classified and still exist,
and every container-inner test must ACTUALLY EXECUTE -- verified at runtime by a `RELEASE-GATE-RAN: <name>`
marker each inner test emits, which tier 2 asserts is present (a static "is it invoked" grep is only a
best-effort pre-filter, since no grep can prove a line runs). Settled review decisions and areas still worth
scrutiny are recorded in `docs/REVIEW-NOTES.md` -- paste its "Accepted" list into a review prompt so a fresh
review does not re-litigate them.

## Cut a release

1. `tests/release-gate.sh --container` on your dev box -> `RELEASE-GATE: PASS`.
2. `tests/release-gate.sh --live` on a KVM host (the gate exports DRVPS_LIVE=1 for the nested run). Collect
   its log; every `PASS` line should be present and no `FAIL`.
3. Bump `VERSION`; add a `CHANGELOG.md` section (features + a "deferred" list of known gaps); reconcile
   `STATUS.md` (verification status per subsystem). Flip any "in development / no push" wording to released.
4. Back up: `tools/backup.sh <name>` (lands in `~/BACKUPS`).
5. Commit in logical chunks. Push only after the live run passes on the target host(s).

## Notes

- The residue gate keeps internal review-process handles out of the published tree. `tests/release-gate.sh` is
  the only file that legitimately contains those tokens (its own patterns) and is excluded from the scan; do not
  spell them in docs or comments.
- `DR_VPS_DRIVER_VERSION` (image/artifact format) is a SEPARATE axis from the product `VERSION`; bump it only
  when the golden/snapshot/store on-disk format actually changes.
