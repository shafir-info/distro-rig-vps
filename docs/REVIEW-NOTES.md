# Review notes -- accepted design decisions + where to look next

This records design decisions that external reviews have already converged on, so a fresh review does not
re-litigate them, plus the areas most worth scrutiny. When commissioning a review, paste the "Accepted" list
into the prompt (ask the reviewer NOT to re-flag these) and point it at the "Still worth reviewing" list.

## Accepted -- do NOT re-flag as blockers (each was reviewed and settled)

- **release-gate CONTAINER_INNER coverage is guaranteed at RUNTIME, not by static analysis.** The offline
  "is it invoked" check in `tests/release-gate.sh` is an explicit BEST-EFFORT static pre-filter -- no grep of
  source can prove a line actually executes (this is the halting-problem tail: for any pattern, an input like
  `false && bash t.sh` or `echo bash t.sh` matches without running). The AUTHORITATIVE guarantee is TIER-2
  RUNTIME coverage: every CONTAINER_INNER test emits `RELEASE-GATE-RAN: <name>` on stderr WHEN IT EXECUTES, and
  tier 2 FAILS if any marker is absent from the captured run. That checks what happened, not what the source
  looks like, so a disabled invocation (comment, `false &&`, `echo`, deletion from a runner) is caught. Do NOT
  propose further static-grep hardening of the pre-filter -- it cannot be made complete and does not need to be.

- **The nested "really works" test is OPERATOR-run by design.** The full `dr-vps-setup` requires `/dev/kvm`;
  the rig's automation identity (a `drvpsctl`/`drvpsvc` member) is deliberately NOT in the `kvm` group, so it
  cannot run the full installer. That is the intended trust boundary, not a coverage gap. Tier 3
  (`tests/release-gate.sh --live`, `tests/dogfood/nested-selftest.sh`) is the operator's step; the automated
  tiers (1 offline, 2 disposable-container) cover everything reachable without KVM.

- **`DR_VPS_DRIVER_VERSION` stays `0.2.0` while the product `VERSION` is `0.3.0`.** They are separate axes: the
  driver version is the golden/snapshot/store on-disk format, which did not change in 0.3.0.

- **The pre-existing "dirty" test scripts are not shellchecked in the gate.** ~16 `tests/*.sh` have shellcheck
  findings that are mostly intentional (SC2016 deferred-eval in `eval`/SSH command strings). This is tracked
  debt; every shell file still gets `bash -n`, and the shipped `bin/`/`src/`/`tools/` bash is shellcheck-clean.

## Accepted: development-process residue in the published git history

A public-readiness audit of the full pushed history (2026-07-17) found **no secrets, credentials,
personal data, key material, or reachable-infrastructure identifiers** in any commit. Commits from
before the pre-release scrub (and the scrub commit's own message) do retain internal
development-process references -- a development-machine nickname, reviewer attributions, and
process labels. This is ACCEPTED as-is: the exposed items are process trivia consistent with the
project's openly documented external-review method, and rewriting published history would break
every public clone and all recorded commit references. The in-tree residue gate keeps the CHECKOUT
clean going forward (its patterns are deliberately literal -- a transparent gate was preferred over
an obfuscated one); commit MESSAGES sit outside that gate, so keep them free of the same residue
classes by habit.

## Still worth reviewing -- focus here

- `tests/dogfood/nested-selftest.sh`: do the egress and drvps-top assertions actually exercise the real code
  paths on a real install (e.g. the egress bar requires a clean `apply` rc=0, reaching `_render_params`)?
- `tools/drvps_top_view.py`: the viewer's hostile-file open protocol (O_PATH dir + fstat trust anchor + capped
  NUL-checked read) and `tools/drvps_top_feed.py`'s validator.
- `tools/drvps_egress_*.py` + `bin/drvps-egress-approve`: the store DAC, the approve tool's crash-recovery,
  the shared lock, and the render/apply transaction.
- Any subsystem not yet examined in depth in earlier rounds.
