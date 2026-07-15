# distro-rig-vps (`dr-vps`) — a disposable-VM test rig for KVM/libvirt

**Boot real Linux VMs, hand an untrusted process root inside them, let it wreck them, reset them
in seconds — while the host stays safe and the VMs stay off the internet.**

distro-rig-vps is a **self-hosted KVM/libvirt virtual-machine test rig** for **root-heavy,
systemd-heavy, real-system testing** that containers cannot reach (real boot, PID-1 systemd,
kernel isolation, SELinux, firewall daemons). It builds **digest-pinned golden images** of real
distros (Fedora, Debian/Ubuntu, Rocky, openSUSE, Alpine), boots **disposable copy-on-write VMs**
from them, and gives an **unprivileged client** (a CI job, a test harness, an **AI coding agent**)
a full root VM it can drive into any state and **reset from the pinned golden** — through a
mediated socket API, with **no sudo, no /dev/kvm, and no privileged host control beyond that
socket** (guests reach only explicitly allowlisted host endpoints, e.g. the package cache).

**Use it for:** installer/deploy testing, systemd service testing, destructive-recovery drills,
sandboxing AI agents that need root on a real OS, multi-distro compatibility matrices, and any
workload where "docker is not a real machine" bites.

**Scope — what it is / is not:**
- IS: a single-host, operator-installed test rig; a privilege gateway (never-root watcher, fixed
  verb whitelist, per-VM identity gate); a deny-by-default **egress fence** (nftables) with an
  **SSL-bump squid package cache** so guests install packages fast without open internet;
  **snapshots** of installed VM state (owner-scoped, content-addressed) with gated restore.
- IS NOT: a cloud / multi-tenant hosting platform (one rig = one agent trust domain), a container
  runtime, a network security boundary against a root attacker on the host, or a public-facing
  service (nothing listens beyond the host).

> **Docs:** [`CONCEPT.md`](CONCEPT.md) — design + security model. [`USAGE.md`](USAGE.md) — install /
> operate / drive-as-agent / troubleshoot. [`STATUS.md`](STATUS.md) — per-subsystem verification
> status, trust boundaries, deferrals. [`CHANGELOG.md`](CHANGELOG.md) — release summary + the
> external-review record. This README is the quickstart.

## Status
The core rig, the agent control loop, the guest-exec gate, the egress fence + cache, and snapshots
with owner-scoping are **live-validated on real KVM**; the offline suite is **767 bats tests across
23 suites**, green. Some features ship **gated off** pending operator decisions. The authoritative
per-subsystem table (LIVE / seam-tested / GATED), the trust-model boundaries, and every known
limitation live in [STATUS.md](STATUS.md) — read it before relying on a specific guarantee.

## The four identities
- **operator** — a human sudoer. Runs the one-time installer, pre-builds goldens, drives live runs.
- **agent** — an unprivileged host user (no sudo, no `/dev/kvm`). Its only rig capability is the
  ingress socket + reading its own results via `rigctl`; no other host control.
- **`drvps`** — the dedicated service account the rig runs *as* (in `kvm`/`libvirt`/`qemu`, **not
  root**). Owns the state; the watcher + reaper run as it.
- **guest VMs** — disposable COW overlays on the immutable golden, on the egress-fenced `simnet`.

## Requirements (host)
```
qemu-kvm  libvirt  virt-install  virt-customize (guestfs-tools)  qemu-img
cloud-image-utils (cloud-localds)  genisoimage  nftables  squid  openssl
xmllint (libxml2)  jq  sqlite3  flock  inotify-tools  python3  bash (4.4+)  ssh
```
For the test suite: `bats` and `shellcheck`.

## One-time setup (operator)
1. Stage the tree into a root-owned prefix (the installer refuses to run from a user-owned
   checkout, by design -- root executes these files):
```
git clone <this-repository-url> distro-rig-vps   # fill in the canonical URL at release
sudo install -d -o root -g root -m 0755 /opt/distro-rig-vps
sudo cp -a distro-rig-vps/. /opt/distro-rig-vps/
sudo chown -R root:root /opt/distro-rig-vps
sudo chmod -R u=rwX,go=rX /opt/distro-rig-vps
sudo restorecon -RF /opt/distro-rig-vps 2>/dev/null || true   # SELinux hosts
```
2. Install (creates the `drvps` user, the `simnet` net, the deny-by-default nft + squid cache with
   SSL-bump, the spool + `drvpsctl` group, and the ingress-socket (`drvps-rigsubmit.socket`) +
   watcher + reaper units):
```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes
```
3. Re-login (group changes need a fresh session), then build a golden (the agent cannot build —
   `build` runs on the host BUILD plane, by design):
```
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps build /opt/distro-rig-vps/etc/recipes/fedora44.json
```
4. Let the agent drive the loop with no sudo: add the agent user to `drvpsctl`, then re-login as it:
```
sudo usermod -aG drvpsctl <agent-user>
```

## Operating

### As the agent (no sudo, no KVM) — the normal path
`rigctl` submits one validated request over the `drvps` ingress socket (the agent has no
filesystem write to the spool); the `drvps` watcher executes it; the result comes back. The agent can drive any guest into any state and reset it within a **bounded host-facing
surface** (the confinement still relies on libvirt/qemu, a root egress unit + periodic nft re-assert,
and the privileged installer -- not a zero-trust boundary):
`create` takes a human NAME but returns the VM **id** (`drvps-vm-...`) -- every other verb takes
the id (the name is a label; see `docs/AGENT-GUIDE.md`):
```
vmid=$(rigctl create myvm fedora44 | jq -r 'select(.status=="ok" and .exit_code==0).stdout' | tr -d '[:space:]')
rigctl wait "$vmid"
rigctl exec "$vmid" 'dnf -y install httpd && systemctl enable --now httpd'
rigctl exec "$vmid" 'rm -rf /var/lib/* ; echo c > /proc/sysrq-trigger'
rigctl recreate "$vmid"
rigctl exec "$vmid" 'getent passwd marker || echo CLEAN'
rigctl push "$vmid" ./local-file /tmp/remote-file
rigctl pull "$vmid" /etc/os-release
rigctl console-dump "$vmid"
rigctl destroy "$vmid"
```

### As the operator / `drvps` (the underlying CLI)
```
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps doctor
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps build <recipe.json>
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps verify <file> <sha256> [sig]
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps distros
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps create <name> <distro> [--net simnet] [--ttl H] [--mem M] [--cpus N]
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps list
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps recreate <id>
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps destroy <id>
```

## Multi-distro
The core is distro-agnostic; per-distro specifics live in a **recipe** (`etc/recipes/`) keyed by a
package-manager **family**. Nine recipes ship: `fedora44`, `centos9`, `rocky9` (dnf);
`debian13`, `ubuntu22`, `ubuntu24`, `ubuntu26` (apt); `opensuse-leap` (zypper); `alpine` (apk).
Each references a minimal cloud image + an `upstream_sha256` (fail-closed): some carry `PIN_ME`
placeholders -- the **operator must pin** the vendor sha before building (the build refuses until
`sha256sum` matches).

To add a distro: drop a recipe with its `family`, minimal image URL + sha, and (for dnf/zypper
mirrorlist distros) a `repo_content` pinning the official master; then add that master to
`etc/fleet.json` `mirror_allowlist` and re-apply the egress (below). No code change.

## The cache (compact base + warm cache, not a TB mirror)
The guest reaches **only** the squid proxy. squid runs the rig's own **cache CA** (baked into every
golden's trust) and **SSL-bumps** the allowlisted HTTPS mirrors, so package files are **cached and
reused across VMs**. Integrity is unaffected — the guest's package manager still GPG-verifies the
cached bytes (cache = speed, never trust). `dr-vps verify` validates any binary (sha256 + optional
GPG), fail-closed.

## Egress allowlist (and not re-running the full installer)
The deny-by-default allowlist lives in `etc/fleet.json` (`mirror_allowlist`). To add a distro
master or an external host (e.g. an npm registry) **without a full reinstall**:
```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --reapply-egress
```
That regenerates the squid allowlist + nft and reloads the units. **Caveat:** if the change adds an
HTTPS mirror, the cache CA's nameConstraints must widen, so the CA is **rotated** — existing goldens
trust the *old* CA, so HTTPS-through-squid will fail for them until they are **rebuilt**. A change that
only touches nft/non-HTTPS allowlisting leaves goldens unaffected.

## Security model (brief)
- **SINGLE-AGENT trust domain (deployment contract).** `drvpsctl` is ONE trust domain: add exactly
  **one** agent principal to it. The rig does **not** isolate between `drvpsctl` members — any member
  can `list` and act (`exec`/`destroy`/…) on **every** rig VM. Result payloads default to a
  **private result store** (each result `0600` + a POSIX ACL granting only the requesting account;
  `DR_VPS_RESULT_PRIVATE=0` is the legacy group-readable opt-out for a single-tenant rig or a spool
  fs without ACLs). This is by design (see `CONCEPT.md` §6/§8): all rig VMs are the single
  agent's disposable playground; goldens are operator-only and gate-protected. Do **not** place
  mutually-distrusting agents in `drvpsctl` expecting per-agent isolation — that would need per-agent
  authorization (peer-uid ownership + owner-filtered verbs), which is out of Phase-2 scope.
- The agent's only host capability is submitting a validated request over the drvps ingress
  socket (`drvps-rigsubmit`, `SocketGroup=drvpsctl`). It has **no filesystem write to the spool**:
  `requests/` is `drvps`-only `0700`, so it can never plant a poison entry a never-root watcher
  couldn't reclaim; it only **reads back its own result** from `results/` (private ACL by default).
- The watcher runs **as `drvps`, never root**, executes only a **fixed verb whitelist**, and **gates
  every VM verb**. The gate has two tiers: **every** gated verb gets the **live-domain identity bind**
  (UUID + primary disk + backing golden — so a verb can never hit an unrelated libvirt domain);
  **guest-I/O verbs** (`exec`/`push`/`pull`/`wait`/`console-dump`) get an **additional closed-shape
  proof** (on *only* `simnet`, no non-allowlisted device or host channel, fresh egress). `console-dump`
  is **guest-exec-gated**, not merely lifecycle: it returns the guest's serial output to the agent (a
  guest→host data channel), so it must pass the full closed-shape proof. `exec`'s command is unrestricted
  because it is confined to the disposable, egress-fenced VM, and `recreate` resets it from the
  verified golden.

## Recovery / troubleshooting
- **Watcher:** `systemctl status drvps-rigctl` · `journalctl -u drvps-rigctl` · the audit trail at
  `…/spool/audit.log` (a processed request is `received` then `ok`/`rejected`/`preempted`/`duplicate`,
  timestamped; size-rotated to `.1`. A request too malformed to yield a reqid leaves no audit line.).
- **`rigctl` timed out:** it now says whether the request was *claimed* (watcher running it / died
  mid-op) or *never claimed* (watcher down).
- **Cache:** `squid -k parse` · `squid -z` (re-init cache_dir) · `du -sh /var/spool/squid`.
- **Broken VMs:** `dr-vps list` shows `broken`; clear with `dr-vps destroy <id>` (the reaper also
  reaps expired broken VMs). **Stuck egress after reboot:** `systemctl status drvps-egress`.
- **Failed build:** re-run `dr-vps build <recipe>` (idempotent; fail-closed on a bad/unpinned sha).

## Known limitations / deferrals (honest)
Every limitation, trust boundary, and deferral is maintained in **one place**:
[STATUS.md](STATUS.md). Headline items to know before installing:
- **One rig = one agent trust domain.** `drvpsctl` members are not isolated from each other
  at the VM plane (owner-scoping isolates snapshots/actions; results are per-owner-ACL private by
  default, group-readable only under the legacy `DR_VPS_RESULT_PRIVATE=0` opt-out).
- **firewalld hosts are configured automatically (DR-2):** firewalld's REJECT outranks the rig's
  nft ACCEPT for guest->cache traffic, so on a firewalld-active host the package cache would be
  unreachable from guests. The installer's `step_firewalld` adds the scoped rich rules + persists
  the bridge's zone binding for you (idempotent; a no-op when firewalld is inactive). Verified by a
  mock-seam suite; a real firewalld-host run is still pending (STATUS.md). Fallback/manual commands
  and the one remaining open item (a real https-through-proxy self-test) are in docs/INSTALL-RUNBOOK.md.
- **The egress fence is a test-confinement tool, not a security boundary against a host root.**
  A root re-apply timer bounds (not eliminates) the nft-flush window.
- **SSL-bump** means the rig's squid sees guest TLS to the allowlisted mirrors (accepted for a
  test rig; the guest's package manager still GPG-verifies everything).
- **openSUSE/zypper needs a non-redirecting mirror pinned**; zypper/apk paths are seam-tested,
  not yet live-validated.

## Testing
```
bats tests/
sudo -u drvps -H env DRVPS_LIVE=1 /opt/distro-rig-vps/tests/acceptance/live-fedora44.sh --smoke
DRVPS_LIVE=1 /opt/distro-rig-vps/tests/acceptance/live-rigctl.sh
# shellcheck: documented per-file suppressions (same commands CI runs). SC2016 (single-quoted
# templates emitted for the guest shell) is intentional in snapshot.sh + image.sh.
shellcheck -x -s bash --exclude=SC2163,SC2012 bin/dr-vps-setup
shellcheck -x -s bash --exclude=SC2034 src/dr_vps_domain.sh
shellcheck -x -s bash --exclude=SC2016 src/dr_vps_snapshot.sh
shellcheck -x -s bash --exclude=SC2016 src/dr_vps_image.sh
shellcheck -x -s bash bin/dr-vps bin/rigctl bin/drvps-rigctl bin/drvps-rigreaper bin/drvps-rigsubmit bin/drvps-top bin/drvps-top-operator bin/drvps-top-publish bin/make-pack.sh tools/backup.sh tools/reclaim-goldens.sh src/dr_vps_api.sh src/dr_vps_doctor.sh src/dr_vps_egress.sh src/dr_vps_gate.sh src/dr_vps_identity.sh src/dr_vps_net.sh src/dr_vps_netgroup.sh src/dr_vps_reaper.sh src/dr_vps_remote.sh src/dr_vps_storage.sh src/dr_vps_store.sh
shellcheck -x -s bash --exclude=SC2034 tools/drvps-top   # read-target field vars (bash TUI)
# the bin/ python entry points (drvps-egress-approve, drvps-egress-migrate, drvps-skill-install) are ast-checked, not shellchecked
```
(`live-fedora44.sh` runs as the service user — the `-H` matters, the VM ssh key is found via HOME;
`live-rigctl.sh` runs as a `drvpsctl` member. See USAGE §8.)
The agent runs the seamed suite (no KVM). Live acceptances are operator-run.

## Layout
```
bin/dr-vps           operator/drvps CLI
bin/dr-vps-setup     privileged one-time installer (+ --reapply-egress, --uninstall)
bin/rigctl           agent-side client (socket submit + result read; no sudo/KVM)
bin/drvps-rigsubmit  the ingress-accepter launcher (socket-activated, runs as drvps)
bin/drvps-rigctl     the watcher launcher (systemd, runs as drvps)
bin/drvps-rigreaper  the TTL reaper (timer, runs as drvps)
bin/drvps-top        read-only rig dashboard: member viewer / -operator (bash TUI) / -publish (unit)
bin/drvps-egress-approve   root operator: review + YES-gated open of a splice destination
bin/drvps-egress-migrate   operator one-shot: egress request store v1 -> v2 migration
bin/drvps-skill-install     install the drvps agent skills pack (self-documentation)
src/dr_vps_api.sh    the LOCKED dr_vps_* signature + seam contract
src/dr_vps_*.sh      identity store doctor image storage net domain gate remote reaper egress
src/drvps_rigctl.py  the python watcher (privilege gateway: decide() + event loop; egress dispatch)
src/drvps_rigsubmit.py  the ingress accepter (the ONLY agent write path into the spool)
etc/recipes/         per-distro golden recipes (family-keyed)
etc/fleet.json       egress inventory + mirror/splice allowlist (config)
tests/               seamed suite (767 tests / 23 suites) + acceptance/ + dogfood/ + container e2e
tools/               drvps-top feed/publish/view + egress model/req/member/layout + maintainer utils
.github/workflows/   CI (offline suite + shellcheck, no KVM needed)
docs/                runbooks, agent/orchestrator guides, concept docs, provenance
CONCEPT*.md STATUS.md CHANGELOG.md LESSONS-LEARNED.md
```

## License, author, provenance

Copyright (c) 2026 **Alexander Shafir** <<alexander@shafir.info>> — <https://www.shafir.info>.
Licensed under the **GNU GPL v3 or later** ([LICENSE](LICENSE)): you may use, study, modify, and
redistribute this software; if you distribute it (modified or not) you must keep the copyright
notices and provide the source under the same license — derivatives stay open.

Vibe-coded with **Claude (Anthropic)** through a documented CONCEPT → PLAN → implement →
external-adversarial-review workflow (~70+ review rounds; see [CHANGELOG.md](CHANGELOG.md)). The
tree is clean-room first-party work — no vendored third-party code; the derivation audit is in
[docs/PROVENANCE.md](docs/PROVENANCE.md).

## Sponsor

Development of this project is sponsored by **[Soroban™](https://soroban.ua/)** — the Soroban
school of mental arithmetic (Ukraine, with international branches).
