# CONCEPT: build-plane libguestfs appliance-network robustness (passt/slirp)

Status: IMPLEMENTED (rev5 design; 2026-07-11). Architecture externally converged. CODE
externally reviewed to convergence. Seam suite green + shellcheck clean;
the live-only integration (real libguestfs->shim->qemu/passt; real cgroup scope-kill) is pending a
first-live-run on an Ubuntu host (slirp path) + a Fedora host (passt path).
Full-rigor design (operator fork 2). Replaces the manual `dpkg-divert` workaround with an in-code,
observed, transactional mechanism. BUILD plane only (`dr-vps build` -> `dr_vps_image_bake`);
vendor-verified images are TRUSTED inputs (the existing bake already runs guest binaries -- no new
trust boundary).

## Problem

`dr-vps build` bakes packages + the cache CA into a cloud image via libguestfs `virt-customize`.
libguestfs gives the throwaway appliance usermode networking, PREFERS passt, and falls back to slirp
only if no `passt` binary returns exit 0/1 from `--help` -- it NEVER network-tests passt. Where passt
is broken the appliance has no network and the bake dies at `dnf`/`apt` with "Could not resolve host"
AFTER a multi-minute download. Proven on an Ubuntu 26.04 cloud VM (old passt: no DHCP lease, NAT dead
even as root; newer passt: exits status 1 -- AppArmor/userns breaking passt's namespaces); slirp works
there. The only current fix is a host-wide `dpkg-divert` -- invasive, undocumented, easy to misapply.

## Goals

- G1 Scoped per-build backend selection, NO host change: `DR_VPS_LIBGUESTFS_NET=auto|passt|slirp`.
- G2 `auto` (default) = a TRANSACTIONAL bake: attempt passt, and on a backend-specific failure discard
  the overlay and retry slirp; no separate probe boot.
- G3 Fail FAST + LEGIBLY with an OBSERVED, differential classification that blames a backend ONLY when
  the OTHER backend demonstrably worked, and never masks a real (non-network) failure.
- G4 Healthy Fedora host: the first (passt) attempt succeeds -> golden bakes on passt, one boot.
- G5 Runbook carries the passt-broken -> slirp lesson + the knob.
- G6 Live bake PROGRESS on a TTY, preserving the full log + the real exit status.

## Non-goals (deferred, in runbook Known-limitations)

- Fixing passt on Ubuntu 26.04 (host/upstream). Routing installs through the squid cache by numeric IP.

## Design

### 0. Preconditions + network scope

- Knob applies ONLY to `LIBGUESTFS_BACKEND=direct`; non-direct + knob active -> FAIL CLOSED.
- Network is needed ONLY when the bake has `--install` packages. A CA-ONLY bake (no packages) runs
  ONCE with `virt-customize --no-network` and NO passt/qemu interception and NO probe/fallback (v3:
  virt-customize enables networking BY DEFAULT, so CA-only MUST pass `--no-network` or an unrelated
  network fault could still break a purely offline CA injection).

### 1. Backend selection -- OBSERVED + ENFORCED (final-launch only)

A per-invocation PATH-prepended private dir carries a `passt` shim; `LIBGUESTFS_HV` points at a qemu
wrapper. Both write machine-readable marker files the bake reads (no log-scraping).

- passt/auto attempt -- passt shim = OBSERVER: it resolves the REAL absolute passt path FIRST (BEFORE
  the dir is on PATH, so it cannot recurse into itself), then RUNS real passt as a CHILD, WAITs,
  atomically records the invocation kind (`--help` vs the real `--one-off` launch) + exit status, and
  EXITs with the same status. (v3: "record then exec" is impossible -- a successful exec never returns.)
- slirp attempt -- passt shim = REFUSER: `exit 2` (NOT 1) so libguestfs picks slirp.
- qemu wrapper (`LIBGUESTFS_HV`): libguestfs calls the HV for FEATURE PROBES (`-version`, KVM detect,
  etc.) BEFORE the final appliance command. The wrapper PASSES THROUGH any invocation lacking the final
  networked-appliance signature, unchanged. ONLY on the final appliance launch does it record `-netdev`
  (`stream`=passt / `user`=slirp) and REFUSE (coded) if it != EXPECTED, else `exec` real qemu.

Guarantees: explicit `passt` FAILS CLOSED if libguestfs would silently use slirp (mismatch at final
launch); explicit `slirp` fails closed if qemu did not get `user`. `BACKEND_START_ERROR` is proven by
TWO observable facts only: (a) the passt shim recorded a real `--one-off` NONZERO exit, or (b) the qemu
wrapper recorded a backend MISMATCH. It does NOT include "qemu rejected the netdev" -- once the wrapper
execs qemu it cannot observe a later qemu exit, and an early qemu exit may be KVM/disk/firmware/etc, so
that is a NEUTRAL launch error, never backend-blamed (v3). Version-gate the libguestfs range; unknown
semantics fail closed. The shim/wrapper dir must be EXECUTABLE: the setup step actually EXECUTES the
shim once; if exec fails (noexec tmpfs) that is a SETUP error, not "backend unavailable".

### 2. Transactional bake (immutable base, promote-only-success)

Verified base image is IMMUTABLE and NEVER the writable target. Each attempt = a FRESH external qcow2
OVERLAY (backing format recorded explicitly; only the overlay writable). ONE `virt-customize` per
attempt, actions ORDERED:

  1. OFFLINE cache-CA copy-in + trust-store update FIRST (v3: if repos are reached through the
     SSL-bumping proxy the CA exists for, a pre-CA probe/install would fail cert validation; `--run-command`
     is chrooted in the guest, so the trust store updated here is exactly what the probe/install use);
  2. the network PROBE (see 3) as the FIRST NETWORK-BEARING action -- fails BEFORE the slow `--install`;
  3. then the existing `--install <pkgs>`.

virt-customize aborts on the first failing action. `auto`: run passt; on a BACKEND-specific failure
(`BACKEND_START_ERROR` / `REPO_PROBE_FAILED`) discard the overlay and run a FRESH slirp attempt. If the
probe PASSES but `--install` later fails -> ORDINARY bake failure (network worked), NO backend retry.
PROMOTION is non-destructive + atomic: convert the successful overlay to a NEW unique STANDALONE temp
image (`qemu-img convert`), verify it has NO backing file, then RENAME it into the build-work position
-- never flatten into the base, never over a final/existing path. DIGEST note: the PM refresh writes
repo metadata/caches into the promoted overlay, so it DOES affect content -- accepted as part of the
EXISTING online-install nondeterminism (the golden digest is already not reproducible across time via
`--install`); an optional final PM-cache clean is a separate hygiene item, out of scope here.

### 3. Probe -- family PM refresh, strict, bounded (portable, binary-free)

FIRST network-bearing action: a STRICT package-manager refresh against the REAL repos the `--install`
uses (no non-portable `getent`/`/dev/tcp`/`curl`; higher fidelity than a synthetic URL). Family
commands, each in STRICT-fail mode; NO reliance on a `timeout` binary (bounded by the outer deadline,
sec 7):

  dnf     : `dnf makecache --refresh --setopt=skip_if_unavailable=false` (v3: defaults may DISABLE an
            unreachable repo and still succeed)
  yum(3)  : `yum clean expire-cache && yum -y makecache` (v4: legacy Yum 3 has NO `makecache --refresh`;
            branch on DNF-vs-legacy-Yum, not merely "a command named dnf/yum exists". ALL shipped
            recipes are DNF-family, so Yum-3 is a forward-compat branch)
  apt     : `apt-get update` with `-o APT::Update::Error-Mode=any` (v3: retries=0 alone does NOT turn
            transient repo warnings into a nonzero exit)
  apk     : `apk update` (all configured repos required)
  zypper  : `zypper --non-interactive refresh` (all enabled repos)

Result is REPO_PROBE_OK vs REPO_PROBE_FAILED (see taxonomy). No `probe_url` override (v3: no
binary-free execution contract for an arbitrary URL; the PM-vs-real-repos probe is the contract).

### 4. Failure taxonomy (only what is OBSERVABLE)

- `PROBE_INFRA_ERROR`  -- appliance/qemu/KVM/disk/supermin launch failed BEFORE any backend process, OR
  a neutral qemu early-exit after the wrapper confirmed correct args; FATAL, NO backend blame (keeps the
  existing kernel-unreadable path).
- `BACKEND_START_ERROR`-- passt shim recorded a real `--one-off` nonzero exit, OR qemu wrapper recorded
  a backend MISMATCH; backend-specific + observable.
- `PROBE_TOOL_ERROR`   -- the probe tool/output contract itself failed inside the guest; FATAL, no
  fallback, no backend blame.
- `REPO_PROBE_FAILED`  -- appliance up, but this backend's strict PM refresh failed (LINK/DNS/TLS/repo
  are NOT split -- a PM return code cannot distinguish them portably).
- `BOTH_REPO_PROBES_FAILED` -- BOTH backends `REPO_PROBE_FAILED`: neither recorded attempt reached
  usable repos. This does NOT prove a shared cause or exclude two independent backend faults (v4) --
  report LIKELY shared causes (repo/DNS/egress/appliance) WITHOUT asserting "not a backend fault" or
  "the endpoint is down"; still do NOT quarantine passt.
- `PASST_OK` / `SLIRP_OK`.

`auto` matrix:
- passt `*_OK` -> bake passt.
- passt `BACKEND_START_ERROR` | `REPO_PROBE_FAILED` -> discard, try slirp:
  - slirp `*_OK` -> bake slirp; report passt as `PASST_PATH_FAILED` (a transient outage that recovers
    before the slirp attempt is possible; per-build, conservative slirp choice is fine; message stays
    path-scoped, never "passt is broken").
  - both `REPO_PROBE_FAILED` -> `BOTH_REPO_PROBES_FAILED` (fatal). MIXED (e.g. passt `REPO_PROBE_FAILED` +
    slirp `PROBE_INFRA_ERROR`/`BACKEND_START_ERROR`) -> FATAL.
- `PROBE_INFRA_ERROR` / `PROBE_TOOL_ERROR` at any point -> FATAL immediately, no fallback.
Separate logs retained per attempt.

### 5. Failure message -- HARD remedy invariant

Classified `dr_vps_die`. HARD INVARIANT: the message mentions/offers `DR_VPS_LIBGUESTFS_NET=slirp` ONLY
when the recorded slirp attempt was `SLIRP_OK` (v3: never advise forcing slirp on a run where slirp
itself failed or was never tried). In explicit `passt`/`slirp` mode a single REPO failure is reported
as the attempt failing WITHOUT backend-causal language or switch advice (one failure cannot prove the
backend caused it). `PROBE_INFRA_ERROR` keeps the existing kernel-readability hint.

### 6. Bake progress (G6)

TTY-gated (`[ -t 2 ]`):

    virt-customize ... 2>&1 | tee "$bakelog" | progress_filter
    st=("${PIPESTATUS[@]}")            # ATOMIC array capture FIRST -- before any other command
    vc_rc=${st[0]}; tee_rc=${st[1]}; filter_rc=${st[2]}

`vc_rc != 0` -> existing hint + log tail (fatal). `tee_rc != 0` -> fatal (log not preserved / SIGPIPE).
`filter_rc != 0` -> WARNING only, golden still promoted; the filter MUST consume to EOF even after a
stderr write fails. Never the old `if ! virt-customize ...; then` shape. Non-TTY keeps quiet-to-log.

### 7. Isolation, cleanup, concurrency

The per-attempt sequence runs in a SUBSHELL with its own `trap` (preserves the caller's traps/env/PATH/
shell-opts). BUT an outer SUPERVISOR (in the parent) owns EMERGENCY cleanup independent of the subshell
trap, because a SIGKILL escalation BYPASSES subshell traps (v3). Killing the virt-customize PROCESS
GROUP is INSUFFICIENT (v4): passt double-forks into a daemon with a NEW pid, libguestfs may place qemu +
its recovery process in separate groups, and process-name matching is unsafe under concurrency. So each
attempt runs inside a PER-ATTEMPT cgroup/transient scope, and emergency cleanup KILLS THE SCOPE (every
descendant incl. the daemonized passt + qemu), then confirms the scope is empty BEFORE deleting the
overlay. NOTE: the COMMON (non-timeout) path relies on libguestfs's OWN passt/qemu teardown on
virt-customize exit -- the emergency scope-kill only matters on the rare HARD-TIMEOUT path. Where a
transient scope cannot be created (e.g. a sessionless `sudo -u drvps` build with no user manager), fall
back to a best-effort reap of the libguestfs run-dir pidfiles + LOG any residual for the reaper, with a
documented residual-leak caveat bounded to that hard-timeout case. Unique `mktemp -d` overlay/wrapper/
marker dirs (dir 0700; shim/wrapper 0500); concurrent builds get distinct dirs/scopes; probe/overlay
never touch the promoted golden beyond sec-2's accepted PM metadata.

## Testing

bats (image.bats + a new backend/probe suite), seaming the passt shim, qemu wrapper, probe, overlay.
Assertions:
- qemu wrapper PASSES THROUGH feature probes (`-version`/KVM) and enforces ONLY the final launch;
- explicit `passt` when libguestfs would fall to slirp -> FAILS CLOSED (final-launch mismatch);
- explicit `slirp` proves qemu got `-netdev user`;
- passt shim runs real passt as a child + records `--one-off` nonzero -> `BACKEND_START_ERROR`,
  distinguished from a neutral qemu early-exit (`PROBE_INFRA_ERROR`);
- `PROBE_INFRA_ERROR`/`PROBE_TOOL_ERROR` do NOT trigger fallback;
- `REPO_PROBE_FAILED` on passt + `SLIRP_OK` -> bake slirp, `PASST_PATH_FAILED`; both fail ->
  `BOTH_REPO_PROBES_FAILED`; MIXED -> fatal; remedy offers slirp ONLY when `SLIRP_OK`;
- CA-only bake -> `--no-network`, no interception, no probe;
- CA-injection is ordered BEFORE the probe/install;
- non-direct backend + knob -> fail closed;
- promotion = convert-to-standalone + verify-no-backing + atomic rename (never over base/final);
- `vc_rc`/`tee_rc` fatal, `filter_rc` warning; `PIPESTATUS` atomic under set -u;
- outer supervisor scope-kills the per-attempt cgroup/scope (reaping daemonized passt + qemu) and
  confirms it empty before overlay removal; sessionless-fallback logs a residual for the reaper;
- dnf uses `makecache --refresh`, legacy Yum-3 uses `clean expire-cache && makecache` (family branch);
- noexec-tmp: the shim setup EXECUTES the shim and reports a SETUP error, not backend-unavailable;
- existing 20 image.bats stay green; the fedora/centos passt bake path is unchanged on a passt host.
Real: an Ubuntu host (slirp, proven) + a Fedora host (passt) -- first-live-run of BOTH paths.

## Review gates

- ARCH: converged by behavior (remaining risk judged implementation-level, owned by the CODE gate).
- CODE (MUST) pre-release, multiple varied clean rounds.

## Decisions (operator 2026-07-10)

- D1 probe = family PM refresh vs real repos (fork-2 rigor, binary-free; no `probe_url`).
- D2 default `auto` (transactional passt -> slirp). D3 single-boot transactional. D4 TTY progress.
- D5 converge ARCH + CODE to clean before ship.
- D6 (ARCH v1-v3) observed/enforced backend via `LIBGUESTFS_HV` qemu wrapper (final-launch only) +
  passt observer/refuser shim (resolve-run-wait-record); require `direct`; CA-first ordering; CA-only
  `--no-network`; collapse LINK/HTTP -> `REPO_PROBE_FAILED`; neutral qemu launch errors (no netdev-
  rejection claim); `BOTH_REPO_PROBES_FAILED`/MIXED; slirp offered only when `SLIRP_OK`; atomic promotion;
  outer-supervisor emergency reap (SIGKILL-safe); executed noexec test; atomic PIPESTATUS + filter warn.

## Related doc drift (this pack)

- USAGE.md sec.4 stale recipe list -> point at `dr-vps distros`; add passt/slirp build-host note.
  Consumer-pack split tracked separately, after this fix lands.
