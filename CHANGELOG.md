# Changelog

## [0.3.0] — rig observability + egress self-service (in development)

Three subsystems land on top of 0.2.0, plus a self-documentation install path. Everything new is
offline-green (the full bats + python + shellcheck + ast gate) and wired into the installer; the
live on-host verification of each is the operator's isolated-env step, still pending (see STATUS.md
and the Deferred list below). No push until that passes.

### Added

- **drvps-top — read-only rig-wide live dashboard.** Two deliverables over one frozen feed contract
  (`tools/drvps_top_feed.py` + byte-exact fixtures): (a) `drvps-top-operator`, the operator's direct
  bash TUI (reconciled store-vs-libvirt VMs, owner uid, live CPU/RAM, golden+snapshot inventory),
  hardened to a strict read-only, process-group-killed, output-capped acquisition; (b) a
  publisher/viewer pair (`drvps-top-publish` unit + unprivileged `drvps-top` viewer) that lets any
  `drvpsctl` member see a sanitized rig view through a hostile-file-safe `/run/drvps-top/feed`
  (O_PATH dir + fstat trust anchor + capped NUL-checked read; the viewer does no sqlite/virsh/NSS).
  Owner identity is off by default (`PublishOwner=no|uid|name-and-uid`; the unit refuses any other
  value). Installer: `step_top`.
- **Egress SPLICE self-service — wired end to end.** The drvpsvc splice-destination path is now a
  first-class verb: `rigctl egress add-splice|remove-splice|status|list`, dispatched owner-scoped
  (SO_PEERCRED-stamped) through the watcher to an owner-scoped, journaled v2 request store; the root
  `drvps-egress-approve` tool stages → dry-run → YES-gated atomic commit + full restart + health,
  with the outcome published back for `egress status`. `dr-vps-setup` provisions the root-owned store
  + shared egress lock under the fixed `drvps` identity (refuses a mismatched service user) and
  persists the reproducible render inputs so `approve` can re-render to open a splice on a real host.
  A splice tunnels the origin cert end to end (never MITM'd by the rig CA). Off until an operator
  opens a destination.
- **Skills self-documentation.** `bin/drvps-skill-install` installs the drvps agent skills pack
  (copy-default) so an operating agent can self-document the rig's verbs and contracts.
- **DR-2 firewalld interop.** On firewalld-active hosts the zone REJECT outranked the rig's nft
  ACCEPT, leaving the package cache unreachable from guests. `dr-vps-setup` now installs scoped
  permanent rich-rules (guest /24 → cache_cidr:cache_port + mock ports, read from fleet.json), binds
  drvps0 to its zone, and reloads — idempotent, query-before-add, a no-op when firewalld is inactive
  (`step_firewalld`). Replaces the manual two-rule workaround from 0.2.0's runbook.

### Security

- Egress internal-destination SSRF guard hardened (external review). The `drvps_internal_dst` deny is
  now rendered UNCONDITIONALLY — it guards the always-on mirror allowlist too, not only splices, so a
  compromised/DNS-rebound allowlisted mirror name cannot be tunnelled to an internal host. The deny set
  covers the special-purpose / non-global ranges plus the host's own IPs/subnets; prefixes that ENCODE
  IPv4 (`::ffff:0:0/96`, well-known NAT64 `64:ff9b::/96`) are deliberately excluded because squid maps
  every IPv4 destination to its v4-mapped form, so denying them would deny all/public IPv4 (a total
  outage the container gate caught). `step_proxy` derives + persists the real host-facts (fail-closed)
  and publishes squid.conf + both render inputs atomically with a fail-closed, non-deleting rollback.

### Fixed (multi-distro nested sweep, 2026-07-16 — el9 portability + install robustness)

Driven by running the nested mandatory bar across all 5 goldens (agent over rigctl). **fedora44 and
centos9 (CentOS Stream 9, el9) now both pass the full bar end to end**; the el9 path surfaced and
fixed three real blockers plus two transient install faults:

- el9 EPEL: `cloud-utils` + `inotify-tools` are not in el9 BaseOS/AppStream, so `dnf install` died
  "Unable to find a match". `step_deps` ensures EPEL on el9 first (prefer `epel-release`, else pin
  the official EPEL repo by a single-host `dl.fedoraproject.org` baseurl — not the mirror metalink an
  egress-fenced host can't reach — with gpgcheck). No-op on Fedora.
- **cloud-localds fallback:** EPEL9 packages no cloud-utils at all, so cloud-localds is simply absent
  on el9. `dr_vps_storage_seed_build` now builds the identical NoCloud seed ISO with `genisoimage
  -volid cidata -graft-points …` when cloud-localds is missing (new `DR_GENISOIMAGE` seam), and fails
  closed if neither exists. `genisoimage` is now a mandatory dep; `cloud-utils` dropped to best-effort
  (present on Fedora, absent everywhere on el9 where genisoimage covers the build). `doctor`'s
  `cloud_localds` fact reads true when either builder is present.
- Fresh-boot reaper heartbeat: the rigreaper timer's first tick is `OnBootSec=10min`, so a host
  installed within 10 min of boot (every nested/cloud provision) failed its first `dr-vps doctor`
  ("reaper heartbeat stale/missing"). `step_units` now kicks one real reaper run so the heartbeat
  exists immediately.
- squid Type=notify readiness timeout under install load ("Failed with result 'protocol'" though
  `squid -k parse` passed): added one generic safe retry (the prior recovery only handled the
  SysV-shm case) — idempotent, a genuine config fault still fails the retry.

**Not fixed here (operator-side):** ubuntu22/24/26 nested fail at the package step because the
golden's ~2.3 GB root fs cannot hold the ~900 MB install — a golden rebuild with a larger disk
(`dr-vps build`), not a code change.

### Fixed (whole-tree consistency review, 2026-07-16 — every finding closed RED-first)

- **CRITICAL — snapshot owner-scopes its SOURCE VM.** `snapshot <vm>` parsed `--owner` but stamped
  only the RESULT: a member who learned a peer's VM id could shut it down, flatten its disk, and
  register the copy under their own uid. `dr_vps_vm_assert_owned` now guards the create flow before
  lock/gate/shutdown (not-found, no existence leak), the same contract as every other VM-acting verb.
- **`rigctl exec-errors <job>` — a detached job's stderr is finally reachable.** The launcher always
  captured `2>${tag}.err` but no verb served it, so a failed detached install showed an empty
  `exec-output` with the FATAL line stranded in the guest. Owner-scoped, symmetric with
  `exec-output`; wired through the client, watcher allow-list, CLI, and AGENT-GUIDE.
- rigctl submit taxonomy: a send failure AFTER the stream started is now INDETERMINATE (exit 4,
  reconcile first) — it was mislabeled "not submitted, safe to retry", inviting double-applied
  mutations. Exit 3 is connect/setup-only.
- Shared env parsing (`drvps_common.cap_int/cap_float`): the accepter/watcher spool caps and the
  accepter read-timeout no longer crash-loop the Restart=always daemons on a malformed override, and
  a zero/negative cap can no longer unbound the request read or wedge the flood cap.
- `snap-show` propagates a failed sidecar read/render (it returned the fd-close 0, masking garbage).
- The egress generation marker publishes atomically (same-dir temp + `mv -Tf`, 0644 before
  visibility) — the unlocked reader could see an empty/partial/0600 marker mid-rewrite and falsely
  refuse creates as "stale".
- `write_result`'s last-resort trim now emits a minimal VALID truncated envelope instead of byte-cut
  (invalid) JSON; fixed-argv `dr-vps` verbs reject surplus argv (`status vm1 --typo` no longer
  silently succeeds); `dr-vps doctor` initializes the store, so a VIRGIN install's first doctor no
  longer dies "no such table: vms" (found live in the 2026-07-16 nested run).
- Docs reconciled to the enforced isolation model (see STATUS "Trust model" — the canonical
  statement): VM mutations + guest content are owner-scoped per SO_PEERCRED NOW; the old "any member
  can act on every rig VM / per-VM ownership is v2" prose is gone from STATUS/USAGE/ORCHESTRATOR-GUIDE.

### Changed

- Egress request store migrated to the seam-free v2 layout (`drvps-egress-migrate`, an operator-run
  idempotent one-shot). The approve tool and member path hardcode the fixed store anchor + service
  identity (no runtime path/command seam — a root CLI must not take a path-or-command door).
- `VERSION` → 0.3.0.

### Tests

- New offline suites: drvps-top feed contract / publisher / viewer / config / acquire (real sqlite +
  canned virsh e2e), operator-TUI hardening, drvps-top installer wiring, firewalld DR-2 (mock seam),
  and egress shell-wiring (store-free admit-gate + reaper-wiring, replacing the retired v1 store-seam
  tests); plus the shared-caps and write_result unit suites from the consistency review. The full
  offline gate stays green (774 bats + python at umask 0077 and 0022 + shellcheck + ast).
- **The nested dogfood is now honest and was executed (2026-07-16, agent-driven over rigctl on a
  fresh fedora44 L1).** `tests/dogfood/nested-selftest.sh` previously ran every check as root@L1 and
  gated on a doctor bar a 4GB L1 could never meet, while its committed form omitted the renumber the
  real run needed and printed a "define" claim it never tested. It now: stages root-owned under
  `/opt` with the nested renumber baked in (`DR_VPS_BRIDGE_IP=10.199.0.1` + fleet `cache_cidr` patch
  + `--force-squid`); runs doctor AS drvps with the capacity policy scoped to the small L1; REALLY
  defines a rendered domain XML (`virsh define --validate` + undefine); drives the member surface as
  a NON-root drvpsctl+drvpsvc account (egress add-splice with SO_PEERCRED/socket-DAC/result-ACL on
  the path; the drvps-top viewer); and its PASS line claims exactly the mandatory bar (L2 boot +
  firewalld stay labeled best-effort; one distro per run — an ubuntu L1 is a second invocation).
  Every step of that bar passed on the live L1; the verbatim operator invocation is
  `tests/release-gate.sh --live`.
- `tests/release-gate.sh` inventories `tests/dogfood/` + `tests/acceptance/` (an unclassified or
  removed nested/acceptance script now fails the gate) and states that its live tier covers the
  fedora44 L1 only.
- Container e2e (disposable rootless podman): the egress-splice matrix on 4 host families
  (fedora/rocky9/ubuntu/debian) — config parse, the behavioral splice tunnel (origin cert end to end,
  squid CA proves no MITM, non-allowlisted terminated), the full stage → approve → restart → tunnel
  workflow, and a production-path check that `approve` reads the installer-persisted render inputs
  (no test_root seam), all verified against a REAL squid; plus the split-UID v2-store DAC boundary.

### Deferred (operator/live — tracked in STATUS.md)

- A verbatim OPERATOR run of the nested tier (`tests/release-gate.sh --live`) on the rig host — the
  2026-07-16 execution of the same bar was agent-driven step-by-step over rigctl — and the
  second-family L1 (`DRVPS_LIVE=1 tests/dogfood/nested-selftest.sh ubuntu26`).
- Bare-metal on-host verification of every 0.3.0 subsystem in a disposable systemd/KVM env: the
  drvps-top publisher unit + member viewer end to end; the egress-splice on-host run; the firewalld
  rich-rules on a real firewalld host (the nested L1 ships firewalld inactive, so DR-2 stayed a
  correctly-labeled no-op there).
- Egress-splice: the squid-capability gate + audit line and the release-gate integration harness
  (egress-splice tasks 1.8 / 1.10) land with that on-host run.

## [0.2.0] — first public release (2026-07-12)

distro-rig-vps: a local, host-simulated KVM/libvirt VM test rig — golden-image build plane,
disposable per-VM overlays, an unprivileged owner-scoped agent control loop (socket ingress →
never-root watcher → fixed verb whitelist), an egress fence (nft) with an SSL-bump package cache
(squid + name-constrained CA), snapshots with owner scoping and gated secrets-restore, and a
portable installer (Fedora/RHEL + Debian/Ubuntu families). Everything privileged is fail-closed;
the guest-exec gate proves a positive closed shape of the domain XML rather than denylisting.

### Development method

Every phase ran CONCEPT → PLAN → code, each stage adversarially reviewed by external LLM
reviewers before proceeding, then live-verified on real KVM (a nested-guest harness for the
installer/network surface). All fixes ship with red-green regression tests. The engineering
lessons distilled from this process are in LESSONS-LEARNED.md; the per-round review narratives
were folded into this summary at release time.

### External review convergence — summary

~70+ external review rounds across the development cycle (a ChatGPT-backed external reviewer pool, plus Grok as a
second provider on the owner-scoping cycle). Per cycle:

| Cycle (scope) | Rounds | Result |
|---|---|---|
| Guest-exec gate hardening | 7 | converged on a positive closed-shape proof (device whitelist + host-reference sweep) |
| Generic installer (portability/coexistence/fail-closed) | 6 | 27 findings folded, GO |
| Snapshot + per-client owner-scoping | 19 (16 review + 3 dedicated race audits) | ~20 real defects folded incl. a full resolve-then-act TOCTOU class; two consecutive clean rounds |
| Snapshot-migration + live deploy | 11 + 1 scoped | terminated by behavior (non-monotone loop); scoped standalone review GO; live deploy surfaced + fixed 3 pre-existing bugs |
| Console-log observability (concept + Stage 0/1) | concept pivot + 2 code reviews | shipped with DoS bound |
| Observability/SSH-reliability bundle | concept r3 GO, plan r3 GO, code | 2 consecutive clean |
| Ubuntu 26.04 cross-distro installer | 7 | 6 findings folded, GO (2 pre-existing gaps deferred, see below) |
| Build-net (appliance-network robustness) | concept 5 revisions + impl | converged |
| Service plane S0–S6 | S4: 2, S6: 1 | findings triaged fix/reject-with-reasoning/log; S6 gate fail-closed defects fixed |
| End-of-cycle installer/net-ownership convergence | 15 | ~41 findings (3 BLOCKER, ~20 MAJOR) folded; collision surface made fully structural (ElementTree ownership/shape/foreign-scan), policy-table-aware, ARG_MAX-safe, live-address-complete; accepted at heavily-hardened state (see LESSONS-LEARNED #22–24) |
| Nested-guest live harness (fedora44, renumbered bridge) | — | 10 harness findings resolved; S0–S6 live behavior matrix 26 checks PASS; S6 identity two-arm probe resolved the keep-secrets contract |

Offline suite growth across the cycle: 96 → 741 bats tests (22 suites), plus shellcheck
(documented per-file suppressions) and live smokes on every convergence fix.

### Release verification (maintainer-reported; no public CI yet)

Offline: `for f in tests/*.bats; do bats "$f"; done` -> 741 ok / 0 failed (22 suites);
shellcheck -> clean except documented per-file suppressions (SC2163+SC2012 in dr-vps-setup,
SC2034 in dr_vps_domain.sh, SC2016 in dr_vps_snapshot.sh + dr_vps_image.sh -- the exact per-file
commands are in README "Testing" and .github/workflows/ci.yml);
`bash -n` + python `ast.parse` clean (2026-07-12, Fedora 44). Live: end-to-end installs + behavior
matrices on a Fedora 44 bare-metal host and a nested-KVM fedora44 guest (renumbered bridge), plus
an ubuntu26 outer guest for the apt installer path. A GitHub Actions workflow
(.github/workflows/ci.yml: syntax gates, shellcheck with the documented per-file exceptions, and
the full offline suite as an unprivileged user in a Fedora container) ships with the release; its
first public run is the independent check of the numbers above.

### Licensing

Licensed **GPL-3.0-or-later** (decision 2026-07-12: derivatives stay open, attribution
preserved). Clean-room provenance audit: docs/PROVENANCE.md.

### Deferred / known gaps (tracked, not hidden)

- **Installer path-hardening pass** (pre-existing, operator-deferred): confine `DR_VPS_NET_STATE`
  to a fixed root-owned /run namespace; reject `DR_VPS_SYS_STATE`/`DR_VPS_SPOOL_BASE` under /run.
- **S6 identity contract sign-off**: ssh-host-key preservation is out of scope by design
  (machine-id is the preserved device identity; keys regenerate per new cloud-init instance-id).
  Needs explicit operator confirmation; if ever required, the restore seed would preserve the
  instance-id or set `ssh_deletekeys: false`.
- **Distro widening**: fedora44 proven nested end-to-end; ubuntu26 installer proven on an outer
  guest. centos9/ubuntu22/ubuntu24 inner goldens blocked on a mirror-allowlist edit
  (`cloud.centos.org`, `cloud-images.ubuntu.com`) or fetch-on-host + `file://` upstream.
- **Held service-plane stages** (S2 stable-IP/service-ports #3a/#3b/#3c, S3 egress profiles /
  `--egress`): NOT BUILT -- design PROPOSED; held pending their own implementation + live-dev run.
- **Bake-through-cache**: recipes with `packages` need mirror egress during the bake; nested
  hosts use a package-less variant until the bake path goes through the cache.
- **DR-6 per-net / per-tenant isolation**: open design issue (docs/ISSUE-per-net-isolation.md);
  the current model is a single shared trust domain per CONCEPT.md.
- UX/quality backlog: TODO.md. Feature-level deferrals and the verification-status table: STATUS.md.
