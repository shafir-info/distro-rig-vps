# distro-rig-vps — STATUS

Current verification state of every subsystem, the load-bearing trust boundaries, and the open
deferrals. History and per-cycle review narratives live in CHANGELOG.md; engineering lessons in
LESSONS-LEARNED.md. Last updated: 2026-07-12.

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
| Snapshots + per-client owner-scoping (SO_PEERCRED-stamped) | LIVE | owner-scoped snapshot built over the socket on a real host; TOCTOU re-checks under per-content locks |
| S6 keep-secrets restore (secret-bearing snapshot → 1:1 restore) | LIVE + GATED | two-arm identity probe (machine-id preserved; app data both arms; host keys regenerate); `DR_VPS_ALLOW_SECRET_RESTORE` default OFF |
| Service plane: landed stages (S0/S1 service-class+quota, S4 idempotency, S5 private result ACLs, S6 gated secrets-restore) | LIVE + GATED | 26-check live behavior matrix PASS on the nested harness; undeployed |
| Service plane: held stages (S2 stable-IP/service-ports, S3 egress profiles incl. `--egress`) | NOT BUILT (design PROPOSED) | held pending their own build + live-dev run (see Deferred) |
| Installer (Fedora/RHEL + Debian/Ubuntu families) | LIVE | fedora44 nested end-to-end incl. renumbered bridge (`DR_VPS_BRIDGE_IP`); ubuntu26 proven on an outer guest |
| Collision/net-ownership preflight (structural, live-address-complete) | LIVE | non-dry-run positive + planted-drift negative controls (widened /16, deleted /24, foreign net XML) |
| Multi-distro golden builds (dnf/apt/zypper/apk profiles) | fedora44 LIVE; others SEAM | family profiles seam-tested; per-family live acceptance is the remaining step (see Deferred) |
| Console-log observability (drvps-readable, DoS-bounded) | LIVE | reaper tail-compaction bound; readability decoupled from virtlogd |
| Offline suite | GREEN | **741 bats tests / 22 suites**; shellcheck clean except 4 documented per-file exceptions (SC2163/SC2012 dr-vps-setup, SC2034 dr_vps_domain.sh, SC2016 dr_vps_snapshot.sh); python ast clean |

## Trust model and load-bearing boundaries (current, by design)

- **Single trust domain per rig**: all `drvpsctl` members are one tenant at the VM plane (any
  member can act on every rig VM). Owner-scoping is STORE + ACTION isolation (a client can act on
  and enumerate only its own snapshots; the preempt path is same-owner-only). Result payloads are
  PRIVATE by default (`DR_VPS_RESULT_PRIVATE=1`: each result `0600` + a POSIX ACL for the
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

- **Installer path-hardening pass** (pre-existing): confine `DR_VPS_NET_STATE` to a fixed
  root-owned /run namespace; reject `DR_VPS_SYS_STATE`/`DR_VPS_SPOOL_BASE` under /run.
- **S6 identity contract sign-off**: host-key preservation is OUT of scope (machine-id is the
  preserved device identity). If ever required: preserve the instance-id or set
  `ssh_deletekeys: false` on the restore seed.
- **Held fence stages** (S2 stable-IP/service-ports #3a/#3b/#3c, S3 egress profiles / `--egress`):
  NOT built; the consumer guide marks them PROPOSED. Need their own build + live-dev run.
- **DR-2 firewalld (open, affects firewalld-active hosts)**: firewalld's zone REJECT outranks the
  rig's nft ACCEPT for guest->cache traffic, so the package cache is unreachable from guests until
  the operator adds two scoped rich rules + persists the drvps0 zone binding (workaround commands:
  docs/INSTALL-RUNBOOK.md "firewalld hosts"; installer automation: TODO.md DR-2). The cache/fence
  LIVE rows above were verified on hosts with the workaround applied or firewalld inactive.
- **Distro widening**: centos9/ubuntu22/ubuntu24 inner goldens need a mirror-allowlist edit or
  fetch-on-host + `file://` upstream; per-family live acceptance for zypper/apk.
- **Bake-through-cache**: recipes with `packages` need mirror egress during the bake.
- **DR-6 per-net / per-tenant isolation**: open design issue (docs/ISSUE-per-net-isolation.md).
- **Live-only test gaps** (need a disposable systemd env): S6 enable→watcher-restart→disable env
  lifecycle; concurrent create/destroy; an `--idem` replay around an S6 refusal.
- **M8 wording**: host `owner_uid` appears in agent-visible quota/admission error text; reword
  to "requesting account" (uid stays in daemon-private diagnostics).
- **v2 features** (specified, not coded): snap export/import, promote-to-golden, restore/
  rollback UX, multi-owner refcount snapshots, per-VM ownership; `proxied-real`/`open` egress
  profiles; broker/tenants/quotas (P3); remote provider (P4); crash reconciliation walk;
  per-VM anti-spoof nft rule (mitigated by `<port isolated='yes'/>` + single trust domain);
  live-memory checkpoint UX.
- UX/quality backlog: TODO.md.

## Operator quickstart

Stage the tree root-owned under `/opt/distro-rig-vps` (see README "One-time setup"), then
`sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes`, re-login (group change), then see
docs/INSTALL-RUNBOOK.md. The rig runs as `drvps`; the agent drives it via `bin/rigctl`
(see docs/AGENT-GUIDE.md).
