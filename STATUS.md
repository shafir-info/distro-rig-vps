# distro-rig-vps — STATUS

Current verification state of every subsystem, the load-bearing trust boundaries, and the open
deferrals. History and per-cycle review narratives live in CHANGELOG.md; engineering lessons in
LESSONS-LEARNED.md. Last updated: 2026-07-17 (0.3.0 in development).

## Verification status

Legend: **LIVE** = proven on real KVM (bare-metal and/or the nested-guest harness);
**SEAM** = offline bats suite only (deterministic seams, no /dev/kvm); **GATED** = built,
wired, and tested but disabled by default pending an operator decision.

| Subsystem | Status | Evidence |
|---|---|---|
| Core rig (identity, store, doctor, image, storage, net, domain, CLI) | LIVE | end-to-end acceptance on real KVM: build → create → boot/cloud-init/ssh → recreate → destroy |
| Agent control loop (socket ingress → never-root watcher → verb whitelist) | LIVE | full loop driven by the agent over the socket on a real host |
| Guest-exec gate (positive closed-shape proof of the domain XML) | LIVE | live guestexec + `--gate-selftest` positive control; faithful seam fixtures |
| Egress fence (deny-by-default nft + periodic root re-apply timer) | LIVE | guest reach-controls (internet/DNS/IPv6/gateway blocked); timer re-asserts + refreshes the marker |
| SSL-bump package cache (squid + name-constrained rig CA) | LIVE | guest dnf through the cache with DNS off; CA nameConstraints track the mirror allowlist |
| Egress SPLICE destinations (CRM callback path: drvpsvc self-service register + root YES-gated open; end-to-end tunnel, never MITM'd) | WIRED, CONTAINER-VERIFIED (bare-metal pending) | Wired end to end: `rigctl egress add-splice/remove-splice/status/list` -> owner-scoped (SO_PEERCRED-stamped) dispatch in `drvps_rigctl.py` -> `dr-vps egress` -> the seam-free **v2** request store (`drvps_egress_member.py`); the root `drvps-egress-approve` stages -> dry-run -> YES-gated atomic commit + full restart + health, with the outcome published back for `egress status`. `dr-vps-setup` provisions the root-owned store + shared egress lock under the FIXED `drvps` identity (validate_env refuses a mismatched service user) AND persists the reproducible render inputs (`egress-render-params.json` + `egress-host-facts.json`) so `approve` can re-render to open a splice on a real host (egress-splice task 1.9). Renderer/store/req/approve converged to an external-review GO; store v2 reached two consecutive clean rounds. **Disposable rootless-podman e2e on 4 host families (fedora/rocky9/ubuntu/debian): parse + behavioral splice-tunnel (origin cert end-to-end, squid CA proves NO MITM, non-allowlisted terminated) + the full stage->approve->restart->tunnel workflow + a PRODUCTION-path check that approve reads the installer-persisted render inputs (no test_root seam), ALL-VERIFIED; the split-UID v2-store DAC boundary passes in a container.** NOT yet built: the squid-capability gate + audit line and the release-gate integration harness (egress-splice tasks 1.8/1.10). Bare-metal on-host run remains (Deferred). Feature stays OFF until an operator opens a destination. |
| drvps-top rig dashboard (operator TUI + member publisher/viewer over one frozen feed contract) | SEAM (live pending) | Operator `drvps-top-operator` (hardened read-only bash TUI: process-group kill, ~1s sqlite deadline, output caps) + the `drvps-top-publish` unit / unprivileged `drvps-top` viewer, sharing `tools/drvps_top_feed.py` (validator+serializer, byte-exact fixtures). Viewer opens the feed hostile-file-safe (O_PATH dir + fstat trust anchor + capped NUL-checked read; no sqlite/virsh/NSS). Owner identity OFF by default. Installer: `step_top` (viewer.conf root:root 0644 + the publisher unit User=drvps Group=drvpsctl). Offline: feed contract 291, publisher 36, viewer 26, config 33, acquire 27 (real sqlite + canned virsh e2e), hardening 8, setup-wiring 17. Live publisher-unit + member-viewer run pending. |
| DR-2 firewalld interop (guest->cache path on firewalld-active hosts) | SEAM (live pending) | `dr-vps-setup` `step_firewalld`: scoped permanent rich-rules (guest /24 -> cache_cidr:cache_port + mock ports from fleet.json), binds drvps0 to its zone, reloads; idempotent query-before-add; no-op when firewalld inactive. Offline: 10-check mock-seam suite. Replaces 0.2.0's manual two-rule runbook workaround. Real firewalld-host verification pending. |
| Skills self-documentation (`drvps-skill-install`, copy-default) | SEAM | Installs the drvps agent skills pack so an operating agent can self-document the rig's verbs/contracts; offline-tested, converged to an external-review GO. |
| Snapshots + per-client owner-scoping (SO_PEERCRED-stamped) | LIVE | owner-scoped snapshot built over the socket on a real host; TOCTOU re-checks under per-content locks |
| S6 keep-secrets restore (secret-bearing snapshot → 1:1 restore) | LIVE + GATED | two-arm identity probe (machine-id preserved; app data both arms; host keys regenerate); `DR_VPS_ALLOW_SECRET_RESTORE` default OFF |
| Service plane: landed stages (S0/S1 service-class+quota, S4 idempotency, S5 private result ACLs, S6 gated secrets-restore) | LIVE + GATED | 26-check nested matrix PASS; **0.2.0 live-deployed on bare-metal (Fedora 44); the class=service + drvpsvc-membership + per-account quota gate verified end-to-end** (`tests/acceptance/live-service-quota.sh`) |
| Service plane: held stages (S2 stable-IP/service-ports, S3 egress profiles incl. `--egress`) | NOT BUILT (design PROPOSED) | held pending their own build + live-dev run (see Deferred) |
| Installer (Fedora/RHEL + Debian/Ubuntu families) | LIVE nested: ALL FIVE goldens (fedora44, centos9/el9, ubuntu22/24/26) | **What is actually proven, by tier:** container tier (real squid, 4 host families) GREEN; **0.3.0 nested L1 (2026-07-16, agent-driven over rigctl, full mandatory bar):** for a fresh L1 -> tree staged root-owned under `/opt` -> installer with the renumbered bridge (`DR_VPS_BRIDGE_IP=10.199.0.1` + fleet `cache_cidr` patch + `--force-squid`) rc=0 -> `doctor` PASS **as the drvps user** (capacity knobs scoped for the small L1) -> a rendered domain XML **really defined** (`virsh define --validate`) as drvps -> **MEMBER-level isolation exercised** (a non-root drvpsctl+drvpsvc account staged an egress splice over the socket: SO_PEERCRED/DAC/result-ACL on the path) -> root YES-gated approve applied the SPECIFIC host into the live squid policy -> drvps-top publisher (drvps, live, advancing seq) + MEMBER viewer PASS. **All five goldens pass this full bar:** fedora44; centos9 (el9 -- exercising the genisoimage seed-builder fallback with no cloud-localds, the pinned EPEL repo, and the fresh-boot reaper + squid-notify-retry hardenings, all found live in this sweep and fixed); and ubuntu22/24/26 on 12GB goldens built via the new recipe `disk_size` field (the stock ~2-3.5GB ubuntu cloud goldens had no room for the ~900MB install; `disk_size` grows the golden's virtual disk and cloud-init growpart expands root on first boot). The committed `tests/dogfood/nested-selftest.sh` encodes this bar; a verbatim operator `tests/release-gate.sh --live` run remains an operator step. |
| Collision/net-ownership preflight (structural, live-address-complete) | LIVE | non-dry-run positive + planted-drift negative controls (widened /16, deleted /24, foreign net XML) |
| Multi-distro golden builds (dnf/apt/zypper/apk profiles) | dnf (fedora44/centos9) + apt (ubuntu22/24/26) LIVE; zypper/apk SEAM | fedora44/centos9/ubuntu22/24/26 goldens built AND driven through the full nested bar (2026-07-16); ubuntu built with recipe `disk_size:"12G"`. zypper (opensuse-leap) / apk (alpine) family profiles remain seam-tested (live acceptance pending). |
| Console-log observability (drvps-readable, DoS-bounded) | LIVE | reaper tail-compaction bound; readability decoupled from virtlogd |
| Offline suite | GREEN | **784 bats tests / 23 suites**, plus offline python at umask 0077 AND 0022 (egress: layout/model/req/approve/migrate/verb; drvps-top: feed 291 / publisher / viewer / config / acquire) and offline sh (egress wiring + lock + render-noop; drvps-top unit/once/crossframe/hardening/setup; firewalld DR-2; image-bake guards) all green; shellcheck 0 errors (documented per-file suppressions: SC2163/SC2012 dr-vps-setup, SC2034 dr_vps_domain.sh + tools/drvps-top, SC2016 dr_vps_snapshot.sh + dr_vps_image.sh); python ast clean |

**0.2.0 live-deploy smoke (bare-metal Fedora 44, 2026-07-12) -- all PASS:** clean-install upgrade
from 0.1.0; goldens rebuilt (fedora44, ubuntu22/24/26, centos9); basic agent loop
(create -> boot -> root exec -> **egress fence blocks internet** -> **package cache reachable through
the SSL-bump proxy** -> destroy); and the drvpsvc service-plane gate (a member creates class=service;
the per-account quota refuses the 4th at 3/3, fail-closed E_CAP). No leaked VMs.

## Trust model and load-bearing boundaries (current, by design)

- **Owner-scoped VM plane (S1a) -- CANONICAL statement of the isolation model** (USAGE §11 and
  the ORCHESTRATOR/AGENT guides defer here): every VM MUTATION and guest-content verb on the
  agent path -- create/destroy/recreate/exec, detached jobs (exec-detach/-status/-output/-errors),
  push/pull/console-dump, snapshot (incl. the SOURCE-VM check) and use -- is scoped to the
  requesting account. The ingress accepter stamps the client's OS uid UNFORGEABLY from
  SO_PEERCRED; the watcher refuses an unstamped owner-scoped request (fail closed); and the
  dr-vps layer re-asserts ownership (a foreign or operator-owned VM resolves to not-found -- no
  existence leak; the offline suites REQUIRE the rejection). The READS stay rig-global by
  design (`list`/`status`/`inspect`/`wait`: VM ids/names are non-secrets; note `wait` probes a
  VM's SSH readiness -- it reaches the guest yet is not owner-filtered; guest content and
  lifecycle are what is protected), the direct operator CLI (no `--owner`) is admin, and the
  preempt path is same-owner-only. At the NETWORK/hypervisor layer the rig remains ONE
  confinement domain (one sim subnet, L2-isolated ports; per-tenant nets = DR-6). Result payloads
  are PRIVATE by default (`DR_VPS_RESULT_PRIVATE=1`: each result `0600` + a POSIX ACL for the
  requesting account only; the watcher launcher fails closed without spool ACL support). The
  legacy opt-out (`=0`) makes results `0640` group-readable for a single-tenant rig -- in that
  mode a co-tenant CAN read another member's result envelopes.
- **The watcher is trusted infrastructure**: gates (incl. the S6 secret-restore gate) are
  authoritative against the AGENT-controlled request JSON. A hostile watcher is outside the
  model — it owns the state (0700 drvps) and needs no argv door. Distrusting the invoker would
  require an unforgeable operator credential — a rig-wide architecture change, explicitly not
  claimed.
- **Direct-op concurrency boundary**: the agent/socket path is serialized (one op at a time
  under the spool lock). Concurrent DIRECT `dr-vps` lifecycle ops on the SAME VM
  (create/recreate/destroy/snapshot interleavings) do not share a lifecycle lock — operator
  discipline or the v2 lifecycle-locking refactor. The S6 1:1 restore invariant likewise relies
  on the watcher's single queue against a racing destroy (documented residual).
- **Async-exec job containment = the original process group**: a guest command that `setsid`s a
  descendant escapes the job's kill scope. Accepted for disposable rig VMs running test
  commands; a guest cgroup/systemd scope is the follow-on. (Job lifecycle is otherwise
  fail-closed: rc-first completion-aware kill, reaper as authoritative terminalizer, atomic
  reservations.)
- **Crash-orphan snapshots** (SIGKILL between bundle mv and register): operator re-snapshot
  adopts identical content or `snap-fsck --prune` removes it; a CLIENT claiming it is refused
  (true owner unknowable).
- **nft-flush window**: the egress marker + 120s root re-apply timer bound (not eliminate) the
  gap; a non-root rig cannot detect a flush between ticks.
- **libvirt dynamic-ownership dependency**: disk access relies on owner-only chown + qemu-group
  perms; a libvirt that chmods to 0600 would need per-disk `<seclabel relabel='no'/>`.
- **Goldens are not byte-reproducible** (`virt-customize --install` bakes non-deterministically);
  each build yields a new artifact id.
- **Console-log bound is two-tier and best-effort**: the reaper tail-compacts each log to
  `DR_VPS_CONSOLE_FILE_CAP` (eventual, drvps-readable); virtlogd's `MAX_SIZE` is the synchronous
  host-DoS backstop (fires into a root-owned rotation, degrading `console-dump` until recreate).
  Compaction racing a live writer may drop the newest bytes (never corrupts). Reaper health is a
  `doctor` signal, not a create precondition (the admission floor reserves worst-case disk).
  Design: CONCEPT-VM-CONTRACT.md.
- **At-most-once replay protection is retention-bounded**: `.claimed` tombstones are GC'd with
  their results (TTL/count caps), so an ancient reqid can re-execute after eviction — intentional;
  the guard targets accidental duplication (client retry, watcher crash), which the retention
  window covers under the single-agent model.

## Deferred / open (tracked)

- **Post-S5 dev-side follow-ups** (2026-07-17 review passes; each its own change): owner-scoping
  the global reads (`wait` included) and auditing the guest exec command line; installer
  persistence for `DR_VPS_RESULT_PRIVATE=0` (a hand-edited env line survives neither re-setup nor
  `--reapply-egress`; an ACL-less spool cannot complete a documented install without a unit
  drop-in); results/ stray temp-file GC; make-pack exclusion of untracked files; a results-dir
  fsync on result publish; client reqid entropy; headroom between `wait`'s in-child deadline and
  the supervisor kill; the accepter `.reqid.tmp` age-sweep race; optional doctor surfacing of the
  result-ACL probe; watcher publish-path consolidation; bounding the golden-fetch curl (https-only
  proto pinning + a size cap); a per-tier drift guard for the CONCEPT whitelist.
- **Installer path-hardening pass** (pre-existing): confine `DR_VPS_NET_STATE` to a fixed
  root-owned /run namespace; reject `DR_VPS_SYS_STATE`/`DR_VPS_SPOOL_BASE` under /run.
- **S6 identity contract sign-off**: host-key preservation is OUT of scope (machine-id is the
  preserved device identity). If ever required: preserve the instance-id or set
  `ssh_deletekeys: false` on the restore seed.
- **Held fence stages** (S2 stable-IP/service-ports #3a/#3b/#3c, S3 egress profiles / `--egress`):
  NOT built; the consumer guide marks them PROPOSED. Need their own build + live-dev run.
- **Egress SPLICE — bare-metal run + two integration pieces.** The path is WIRED (verb 1.4, outcome
  publication 1.6, and the `dr-vps-setup` store/lock 1.9 all landed) and CONTAINER-VERIFIED on 4 host
  families (see the status row above). Still open: the squid-capability gate + audit line (1.8), the
  release-gate integration harness (1.10), the doctor-side egress fleet<->config generation-mismatch
  check (1.9 L -- the approver already re-verifies baseline drift; only the `doctor` surfacing is
  missing), and the on-host bare-metal live-dev run. The feature stays OFF until an operator opens a destination.
- **Egress SPLICE — proxy-publish crash-atomicity + host-IP freshness (both self-healing, no WAL).**
  `step_proxy` publishes squid.conf and its two render inputs (`egress-render-params.json` +
  `egress-host-facts.json`) as per-file atomic renames, rolled back as a unit on any single failure.
  It is NOT journal-transactional: a crash BETWEEN the render inputs and squid.conf can leave them
  momentarily divergent. This is self-healing — `drvps-egress-approve` re-renders squid.conf FROM the
  persisted inputs and drift-checks all three before any splice change (`_reconcile_squid` +
  the under-lock re-verify), so the next approve reconciles a torn publish. A write-ahead journal
  for the three-file set is deferred. Separately, `egress-host-facts.json` pins the host's routable
  IPs (the SSRF deny set) at install/reapply time; if the host renumbers afterward the deny set is
  stale until `dr-vps-setup --reapply-egress` re-derives it (the light path runs `step_proxy`).
  A doctor-side "host IP changed since last egress apply" surfacing is deferred.
- **DR-2 firewalld (installer-automated; live + self-test pending)**: firewalld's zone REJECT
  outranks the rig's nft ACCEPT for guest->cache traffic. `step_firewalld` now adds the scoped rich
  rules + persists the drvps0 zone binding automatically (seam-tested, `tests/firewalld-dr2.sh`);
  remaining OPEN is only a real firewalld-host run and the https-through-proxy self-test probe
  (TODO.md DR-2). The 0.2.0 cache/fence LIVE rows were verified on hosts with the (then-manual)
  workaround applied or firewalld inactive.
- **Distro widening**: centos9/ubuntu22/ubuntu24 inner goldens need a mirror-allowlist edit or
  fetch-on-host + `file://` upstream; per-family live acceptance for zypper/apk.
- **Bake-through-cache**: recipes with `packages` need mirror egress during the bake.
- **DR-6 per-net / per-tenant isolation**: open design issue (docs/ISSUE-per-net-isolation.md).
- **Live-only test gaps** (need a disposable systemd env): S6 enable→watcher-restart→disable env
  lifecycle; concurrent create/destroy; an `--idem` replay around an S6 refusal.
- **Nested tier, operator-verbatim**: the 0.3.0 nested bar passed agent-driven over rigctl
  (2026-07-16, see the Installer row); the verbatim `tests/release-gate.sh --live` run on the rig
  host and the second-family L1 (`nested-selftest.sh ubuntu26`) are the operator's remaining steps.
- **M8 wording**: host `owner_uid` appears in agent-visible quota/admission error text; reword
  to "requesting account" (uid stays in daemon-private diagnostics).
- **v2 features** (specified, not coded): snap export/import, promote-to-golden, restore/
  rollback UX, multi-owner refcount snapshots; `proxied-real`/`open` egress
  profiles; broker/tenants/quotas (P3); remote provider (P4); crash reconciliation walk;
  per-VM anti-spoof nft rule (mitigated by `<port isolated='yes'/>`; request-layer owner
  scoping shipped in 0.3.0, network-layer spoofing is the residual this rule would close);
  live-memory checkpoint UX.
- UX/quality backlog: TODO.md.

## Operator quickstart

Stage the tree root-owned under `/opt/distro-rig-vps` (see README "One-time setup"), then
`sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes`, re-login (group change), then see
docs/INSTALL-RUNBOOK.md. The rig runs as `drvps`; the agent drives it via `bin/rigctl`
(see docs/AGENT-GUIDE.md).
