# Changelog

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
