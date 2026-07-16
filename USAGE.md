# distro-rig-vps -- USAGE

How to install, operate, and drive the rig. For the design and security model, see
[`CONCEPT.md`](CONCEPT.md).

Two roles:

- **Operator** -- installs the rig (once, with sudo), builds goldens (controlled host egress), and can
  drive VMs directly with `dr-vps`.
- **Agent** -- an unprivileged, untrusted user (no sudo, no `/dev/kvm`) that drives VMs only through
  `rigctl` over the ingress socket.

Throughout, `<INSTALL>` is the checkout path. Deploy it under a plain, root-owned path -- e.g.
`/opt/distro-rig-vps` (the installer refuses install paths with shell-unsafe characters).

---

## 1. Prerequisites

- A Linux host with **KVM** (`/dev/kvm`), **libvirt** (`qemu:///system`), and nested virt if the host
  is itself a VM.
- Root (sudo) for the one-time install.
- The installer pulls the needed packages (libvirt, qemu, guestfs tools, cloud-image-utils, nftables,
  squid, sqlite, jq, xmllint, ...). Fedora and Debian-family hosts are auto-detected.

---

## 2. Install (operator, once)

Preview with no changes (no root needed):

```
/opt/distro-rig-vps/bin/dr-vps-setup --dry-run
```

Install for real (`--yes` is required because it creates the OS service user):

```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes
```

Then **re-login** the service user (and any interactive user) so the new group memberships take
effect (like the `kvm` group) -- `/dev/kvm` access is captured at login.

The installer is idempotent and re-entrant: re-running it is safe and only reconciles what changed.

### Upgrading an installed rig (state-preserving)

To redeploy a new build over an existing install **without losing your goldens/snapshots**, re-run the
installer in state-preserving mode:

```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes --adopt-simnet --force-squid
```

`--adopt-simnet` adopts an older rig network that predates the `<drvps:owner>` ownership marker and
**re-marks it once** (after that, normal re-runs reconcile it as drvps-owned -- there is no perpetual
re-collision). `--force-squid` re-applies the rig's squid policy over a pre-existing squid config. Both are
deliberate overrides: neither ever auto-takes-over a genuinely foreign network or proxy (an unmarked,
non-drvps resource is refused unless you pass the flag). Your goldens and snapshots live under the pool/
state dirs and are untouched by the network/squid reconcile.

### What the install creates

- **Service user** `drvps` (never root) -- runs the whole runtime.
- **Groups** `drvpsctl` (agent + drvps share it: the spool + ingress socket) and membership in the
  host's `qemu` group (disk access after libvirt's dynamic-ownership chown).
- **A throwaway VM ssh key** at `~drvps/.ssh/drvps_vm_ed25519` (its `.pub` is seeded into every VM).
- **System paths**
  - `/var/lib/distro-rig-vps/` -- `pool/` (goldens + overlays), `seed/` (NoCloud seeds), `store.db`
    (`0750 drvps:qemu`).
  - `/var/spool/distro-rig-vps/` -- `requests/` (`0700 drvps`, agent has no write), `processing/`
    (`0700 drvps`), `results/` (`2750` dir; result files `0600` + per-owner ACL by default, `DR_VPS_RESULT_PRIVATE=0` = legacy group-readable), `audit.log`.
  - `/etc/distro-rig-vps/` -- `env` (the CLI/runtime sources this for the installed paths),
    `fleet.json` (the egress inventory), `cache-ca.crt` (the cache CA baked into goldens).
  - `/run/drvps-submit.sock` -- the agent ingress socket (`0660 drvps:drvpsctl`).
  - `/run/distro-rig-vps/nft.applied` -- the egress generation marker (tmpfs, root-owned).
- **systemd units** (all `User=drvps`, except the egress oneshot which must be root)
  - `drvps-egress.service` + `.timer` -- re-apply the nft fence + re-stamp the marker each boot and
    every ~120s. Runs as **root** (loading nft rules cannot be done unprivileged).
  - `drvps-rigsubmit.socket` + `drvps-rigsubmit@.service` -- the agent request ingress.
  - `drvps-rigctl.service` -- the watcher (`Restart=always`).
  - `drvps-rigreaper.service` + `.timer` -- TTL reap + result GC + orphaned build/digest temp GC
    (~every 15 min).

---

## 3. Verify capability (anyone)

```
dr-vps doctor            # or: dr-vps doctor --json
```

Gates on KVM, libvirt, RAM, disk, tools. Exit `12` (capability) or `13` (libvirt) on a miss. If you
are in the right groups but `/dev/kvm` isn't open, it tells you to re-login.

---

## 4. Build a golden (operator, BUILD plane)

Goldens are built once, from a **recipe** in `<INSTALL>/etc/recipes/`. You must **pin**
`upstream_sha256` to the current vendor checksum -- the build **fails closed** (exit 18) until it
matches.

```
# 1. pin the checksum in the recipe (edit upstream_sha256 to the vendor's value)
$EDITOR /opt/distro-rig-vps/etc/recipes/fedora44.json

# 2. build: fetch + verify(sha256[+gpg]) + bake(virt-customize) + digest + register
dr-vps build /opt/distro-rig-vps/etc/recipes/fedora44.json
# -> prints the artifact_id: drvps-raw-v1-<vsize>-<sha256>

dr-vps distros           # list registered goldens (id  distro  built_at)
```

Recipe fields: `distro`, `family` (`dnf`/`apt`/`zypper`/`apk`), `upstream_url`, `upstream_sha256`,
`packages` (baked in at build time). The bake injects the rig cache CA so the guest trusts the
SSL-bumping cache. The shipped recipes are whatever lives in `<INSTALL>/etc/recipes/*.json` -- list them with
`ls /opt/distro-rig-vps/etc/recipes/` (and registered goldens with `dr-vps distros`); they span the
dnf/apt/apk/zypper families (Fedora, CentOS Stream, Rocky, Debian, Ubuntu, Alpine, openSUSE Leap).
Non-Fedora `upstream_sha256` values may be `PIN_ME` placeholders -- pin them to the vendor checksum
first. If the bake appliance has no network on your build host (e.g. Ubuntu 26.04's older passt), the
build auto-falls-back passt->slirp; see `docs/INSTALL-RUNBOOK.md` (Appliance networking).

`dr-vps verify <file> <sha256> [sig]` is the standalone fail-closed checksum(+GPG) helper.

---

## 5. Operate directly (operator, `dr-vps`)

```
dr-vps create web fedora44 --ttl 24 --mem 4096 --cpus 2   # clone a VM from the fedora44 golden
dr-vps wait web                                            # wait for boot + cloud-init + ssh
dr-vps list                                               # id  state  name  artifact_id
dr-vps status web                                         # state|generation|artifact_id|egress_gen
dr-vps exec web 'systemctl status; uname -a'              # run a command INSIDE the guest (gated)
dr-vps push web ./local.conf /etc/app/app.conf            # scp a file into the guest (gated)
dr-vps pull web /var/log/messages                         # read a guest file, bounded (gated)
dr-vps console-dump web 4096                              # bounded serial snapshot (gated)
dr-vps recreate web                                       # drop overlay, re-clone the pinned golden
dr-vps destroy web                                        # stop + undefine + drop overlay (golden kept)
dr-vps console web                                        # attach serial console (break-glass)

# --- snapshots: save a VM's INSTALLED state as a reusable, segregated artifact ---
dr-vps snapshot web --notes 'nginx+tg-dispatcher'        # shut down -> flatten -> scrub -> register; prints a snap id
dr-vps snapshot web --keep-secrets                       # KEEP identity/secrets (secret_bearing; LOUD md; image 0640 in a 0750 bundle)
dr-vps snap-ls                                           # list snapshots (id  name  parent  secret  validation  created)
dr-vps snap-show <id|name>                               # render the .md (golden provenance -> installation path)
dr-vps use dev --from-snap <id|name> --ttl 4             # create a VM FROM a snapshot (still gate-governed)
dr-vps snap-rename <id|name> my-baseline                 # human handle (content id unchanged)
dr-vps snap-rm <id|name>                                 # delete (refused while a VM backs it)
dr-vps snap-fsck                                         # read-only consistency check (reports orphan bundles)
dr-vps snap-fsck --prune                                 # operator cleanup: remove crash-orphan bundle dirs
```
Snapshots are HARD-SEGREGATED from goldens (kind-tagged ledger + `drvps-snap-v1-*` prefix + separate storage)
so one can never be used as a golden; a secret-bearing snapshot is refused as a `use` base without
`--allow-secret-bearing`. Snapshot create/delete are also drivable UNPRIVILEGED via `rigctl` (see below).

Every VM verb is authorization-gated (see CONCEPT §5). `create` flags: `--net`, `--ttl` (hours),
`--mem` (MB), `--cpus`, `--ssh-key` (public key seeded in), `--project`. Every VM has a mandatory TTL;
the reaper destroys expired VMs (gating each first).

---

## 6. Drive as the agent (`rigctl`)

Give the agent user access, once (operator):

```
sudo usermod -aG drvpsctl <agent-user>       # then the agent user must re-login
```

The agent then uses only `rigctl` -- no sudo, no `/dev/kvm`, no filesystem write to the spool. It
submits a request over the ingress socket and bounded-waits on the result:

```
rigctl create web fedora44 [ttl] [mem] [cpus]
rigctl list
rigctl status <id>
rigctl wait <id>
rigctl exec <id> 'reboot -f'                  # runs INSIDE the fenced guest
rigctl push <id> <localfile> <remote>         # file is base64'd into the request (no host path leaks)
rigctl pull <id> <remote>                     # writes the guest file's RAW bytes to stdout (binary-safe)
rigctl console-dump <id>
rigctl recreate <id>                          # reset from the pinned golden
rigctl destroy <id>
rigctl snapshot <id> [--keep-secrets] [--notes STR]   # UNPRIVILEGED: freeze installed state (daemon runs it as drvps)
rigctl snap-ls                                # list snapshots
rigctl snap-show <snap-id|name>               # render a snapshot's .md
rigctl snap-rm <snap-id|name>                 # UNPRIVILEGED delete (refcount-gated)
```

Each call prints the watcher's JSON result envelope, EXCEPT `pull`: on success it decodes the
size-capped base64 transfer and writes the guest file's **raw bytes** to stdout (binary-safe, like
`cat`); on error (over the transfer cap, gate refused, no such file) it prints the envelope and exits
non-zero. Notes:

- The agent cannot set `--net`/`--ssh-key`/`--project` -- those are fixed by the watcher; numeric caps
  (ttl/mem/cpus) are range-checked.
- `rigctl` waits up to `RIGCTL_TIMEOUT` seconds (default 360). On timeout it tells you whether the
  request was *claimed* (running / watcher died mid-op) or *never claimed* (watcher down).
- `exec` is intentionally unrestricted **inside the box**: break the guest however you like, then
  `recreate` to reset it.

---

## 7. The egress model in practice

The fence is driven by `/etc/distro-rig-vps/fleet.json` (operator-owned; nothing is hardcoded):
`simulated_allow` (cache CIDR/port + mock ports) and `mirror_allowlist` (the hostnames the squid
cache may reach). The `block_cidrs`/`block_ipv6_all` keys are **reserved** for the deferred
non-default profiles -- the `simulated` profile is deny-by-default, so no code consumes them yet.
Note that editing *any* key (reserved ones included) changes the egress generation, so always
re-apply afterwards or VM creation/guest-exec fail closed (exit 24) on staleness. To change it:

```
sudo $EDITOR /etc/distro-rig-vps/fleet.json
sudo /opt/distro-rig-vps/bin/dr-vps-setup --reapply-egress
```

**Caveat:** adding an **HTTPS** mirror widens the cache CA's `nameConstraints`, so the CA is
**rotated** -- existing goldens trust the old CA and must be **rebuilt** to use HTTPS-through-cache.
A change that only touches nft / non-HTTPS allowlisting leaves goldens unaffected.

Guests reach package mirrors only through the cache proxy (`http://10.123.0.1:3128`), with repos
pinned to allowlisted hosts (so Fedora's metalink mirror-sprawl can't bypass the allowlist). Non-HTTPS
package integrity still relies on the distro's own GPG/Release signing end-to-end.

### The guest subnet & addressing

All guests attach to ONE shared simulated network `simnet` -> bridge `drvps0` -> subnet `10.123.0.0/24`:

- **Gateway / cache proxy:** `10.123.0.1` (`:3128`). DNS is off on the net (`<dns enable="no"/>`).
- **DHCP:** each guest gets a **dynamic** lease from the pool `10.123.0.10`-`10.123.0.250` (dnsmasq; **no**
  static/MAC reservations). `dhclient -r && dhclient` on the **same MAC** re-leases the **same** address --
  release/renew does NOT change a guest's IP.
- **Guest<->guest is blocked** at L2 by libvirt `<port isolated='yes'/>`; a guest reaches only the host (`.1`)
  and the mock ports. This is **one shared subnet + one DHCP scope for all tenants** (a single trust domain --
  see Security notes), **not** per-tenant network isolation. A per-net/per-tenant-isolation upgrade is tracked
  as **DR-6** (`docs/ISSUE-per-net-isolation.md`).
- **Adding a secondary/extra IP to a guest** (e.g. simulating an IP change): use an address **OUTSIDE** the DHCP
  pool so it can never collide with another guest's future lease -- `10.123.0.2`-`10.123.0.9` or
  `10.123.0.251`-`10.123.0.254` (avoid `.1`, `.0`, `.255`; pick a unique one). Do **not** static-squat an
  in-pool address -- dnsmasq's conflict ping-check is best-effort and dynamic-only, so an in-pool static can
  still be handed to another guest.

---

## 8. Live acceptance tests

The bats suite is seam-driven (no real KVM). To exercise the real stack on a KVM host, run the
acceptance scripts as the service user in a **fresh** session (so the new groups are present; `-H`
sets `HOME` so the VM ssh key is found):

```
# Phase-1 end-to-end (build/create/boot/ssh/root-op/egress-fence/recreate/destroy):
sudo -u drvps -H env DRVPS_LIVE=1 /opt/distro-rig-vps/tests/acceptance/live-fedora44.sh --smoke

# Phase-2 agent loop over the real spool + socket (run as a drvpsctl member):
DRVPS_LIVE=1 /opt/distro-rig-vps/tests/acceptance/live-rigctl.sh
```

The seam suite: `bats /opt/distro-rig-vps/tests/` and
`shellcheck -x -s bash bin/* src/dr_vps_*.sh`.

---

## 9. Troubleshooting

- **Watcher:** `systemctl status drvps-rigctl` - `journalctl -u drvps-rigctl` - the audit trail at
  `/var/spool/distro-rig-vps/audit.log` (a processed request is `received` then
  `ok`/`rejected`/`preempted`/`duplicate`, timestamped; size-rotates to `.1`; a request too malformed
  to yield a reqid leaves no audit line).
- **Ingress socket:** `systemctl status drvps-rigsubmit.socket`. `rigctl` fails fast with "could not
  reach the submit socket" if the socket is down or the caller isn't in `drvpsctl`.
- **`rigctl` timed out:** it reports whether the request was *claimed* or *never claimed*.
- **Egress / create refused (exit 24):** the fence marker is missing or stale. Check
  `systemctl status drvps-egress`; it re-applies each boot and every ~120s.
- **Cache:** `squid -k parse` - `squid -z` (re-init cache_dir) - `du -sh /var/spool/squid`.
- **Broken VMs:** `dr-vps list` shows `broken`; clear with `dr-vps destroy <id>` (the reaper also
  reaps expired broken VMs).
- **Build fails (exit 18):** the upstream checksum doesn't match the pinned `upstream_sha256`, or the
  golden isn't standalone. Re-pin and rebuild.

---

## 10. Uninstall

```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --uninstall          # (--dry-run to preview)
```

Removes the network, nft rules, systemd units, spool, and state, and destroys only libvirt domains
**proven store-owned** (by UUID). It leaves the installed OS packages in place.

---

## 11. Security notes

- **Owner-scoped VM plane (request layer).** VM **mutations and guest-content** verbs over the agent
  socket -- `create`/`destroy`/`recreate`/`exec` (incl. detached jobs), `push`/`pull`/`console-dump`,
  `snapshot` (source-VM checked) and `use` -- are scoped to the requesting account via `SO_PEERCRED`:
  another account's VM resolves to **not-found**. Metadata reads (`list`/`status`/`inspect`) stay
  rig-global by design -- treat VM ids/names as visible to co-tenants (non-secrets). At the
  network/hypervisor layer the rig remains **one** confinement domain (CONCEPT §6/§8; shared subnet,
  L2-isolated ports -- see §7): do **not** host mutually-hostile workloads expecting network-level
  tenant isolation. (Result PAYLOADS are per-owner-ACL private by default -- see the boundary note
  below. Canonical statement of the model: STATUS.md "Trust model".)
- **Snapshots are per-owner scoped (action + store isolation).** Unlike the VM plane, **snapshots** are
  owner-isolated: the ingress accepter reads the connecting client's OS uid **unforgeably** via `SO_PEERCRED`
  and stamps it as the snapshot's `owner_uid` (the watcher **fails closed** if a snapshot verb ever arrives
  unstamped). The client-reachable snapshot verbs -- `snap-ls`, `snap-show`, `snap-rm`, and `snapshot`
  (create) -- are scoped to the caller: a client can **act on only its own** snapshots and its own
  `snap-ls`/`snap-show` **enumerate only its own** (another client's reference resolves to *not-found*, no
  existence leak). `use --from-snap` IS available to agents over the socket, owner-scoped so a client can
  clone a new VM only from **its own** snapshots. (`snap-rename` and `snap-fsck` are the operator-only
  management verbs, not exposed over the socket.) Ownership is bound to the OS uid
  and **persists** across sessions. The **operator** running `dr-vps` directly on the host (bypassing the
  socket, so no `--owner`) is admin: it sees all snapshots and can always **recover/remove any** client's
  snapshot.
  - **Boundary:** with the DEFAULT private result store (`DR_VPS_RESULT_PRIVATE=1`), each result file is
    `0600` with a POSIX ACL granting only the requesting account -- a co-tenant cannot read your result
    envelopes (the watcher launcher fails closed if the spool fs lacks ACL support). Under the legacy
    opt-out (`DR_VPS_RESULT_PRIVATE=0`, single-tenant/no-ACL-fs rigs) results are `0640` group-readable
    and a co-`drvpsctl` member CAN read another's result file (incl. `snap-ls`/`snap-show` output) --
    in that mode rely on snapshot **action isolation**, not secrecy.
  - **Crash-orphan cleanup is operator-only.** A snapshot create killed between publishing its bundle and
    registering the DB row leaves a bundle with no recorded owner. A **client is refused** (E_CONFLICT) from
    adopting it (it could be another client's in-flight content); only the **operator** self-heals it (re-
    snapshot to adopt) or removes it with `dr-vps snap-fsck --prune`.
- **Goldens are operator-only** and gate-protected; the agent can never build, alter, or delete one.
- The agent-facing runtime (watcher, ingress accepter, reaper) is **never root**. Root is confined
  to the one-time `dr-vps-setup` and the recurring `drvps-egress` fence re-apply (each boot +
  ~120s), which must load nft rules.

---

## 12. Path + env reference

| Path | What |
|------|------|
| `/opt/distro-rig-vps` | the code checkout (`<INSTALL>`; unit `ExecStart` points here) |
| `/var/lib/distro-rig-vps/{pool,seed}`, `store.db` | goldens, overlays, seeds, the store DB |
| `/var/spool/distro-rig-vps/{requests,processing,results}`, `audit.log` | the control-loop spool |
| `/etc/distro-rig-vps/{env,fleet.json,cache-ca.crt}` | installed config |
| `/run/drvps-submit.sock` | agent ingress socket |
| `/run/distro-rig-vps/nft.applied` | egress generation marker (tmpfs) |
| `~drvps/.ssh/drvps_vm_ed25519` | the throwaway-VM ssh key |

Every operational value is overridable via `DR_VPS_*` env (see `src/dr_vps_api.sh` for the full list
and defaults); the installed `/etc/distro-rig-vps/env` uses conditional `:=` so an explicit env still
wins. Key ones: `DR_VPS_STATE_DIR`, `DR_VPS_POOL_DIR`, `DR_VPS_SPOOL_DIR`, `DR_VPS_FLEET_JSON`,
`DR_VPS_SSH_KEY`, `DR_VPS_RIG_NET`, `DR_VPS_TTL_DEFAULT`, `DR_VPS_REQ_MAX_BYTES`,
`DR_VPS_TRANSFER_MAX_BYTES`, `RIGCTL_TIMEOUT`. Two of those live outside api.sh: `DR_VPS_RIG_NET`
defaults in the installed env (fallbacks in `dr_vps_gate.sh` / the watcher), and `RIGCTL_TIMEOUT`
is client-local in `bin/rigctl` (default 360).
