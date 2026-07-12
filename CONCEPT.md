# distro-rig-vps -- CONCEPT (design + security model)

**A local, host-simulated KVM/libvirt VM test rig.** It builds pinned "golden" VM images, clones
throwaway VMs from them over copy-on-write overlays, and lets an *untrusted agent* drive those VMs
into any state (kernel panic, fs corruption, package installs, reboots) and reset them -- all inside
a deny-by-default egress fence, with the agent-facing runtime running **unprivileged (never root)**
(root stays in the one-time installer and the recurring egress-fence oneshot -- see section 7).

It is the full-fidelity VM sibling of `distro-rig` (the container fixture rig): use it for root-heavy,
systemd, kernel, or boot-level deploy testing that containers can't reach.

> This document supersedes the phased design sketches (folded and removed at release); where any
> older record
> disagree with this file or the code, the code wins. For how to install and use the system, see
> [`USAGE.md`](USAGE.md).

---

## 1. The three planes

The system is split into planes with different privilege and network posture:

| Plane | Who runs it | Host egress | What it does |
|-------|-------------|-------------|--------------|
| **BUILD** | operator (`dr-vps build`) | controlled (fetch upstream image) | fetch + verify + bake + digest + register a golden |
| **RUN** | operator or watcher (`dr-vps create/...`) | none (fenced) | clone an overlay off a pinned golden, boot a throwaway VM |
| **CONTROL** | the untrusted agent (`rigctl`) | none (fenced) | submit gated verbs to a never-root watcher |

Test VMs never touch the BUILD plane. The agent never touches the BUILD plane -- goldens are
operator-supplied and immutable; the agent only ever works with what is already registered.

---

## 2. Components (files)

```
bin/dr-vps            operator CLI: doctor build verify distros create wait list status
                      console console-dump exec push pull recreate destroy
                      gate (internal: the watcher's authorization probe, read-only)
bin/dr-vps-setup      privileged one-time installer (operator sudo; idempotent, re-entrant)
bin/rigctl            AGENT client: submit one verb over the ingress socket, poll the result
bin/drvps-rigsubmit   ingress-accepter launcher (sources env, execs the python accepter)
bin/drvps-rigctl      watcher launcher (sources env, execs the python watcher)
bin/drvps-rigreaper   TTL-reap + result-GC launcher

src/dr_vps_api.sh       LOCKED contract: exit codes, env defaults, command seams, signatures
src/dr_vps_identity.sh  canonical JSON, recipe hash, content-addressed golden digest
src/dr_vps_store.sh     SQLite store + referrer ledger (goldens, VMs, overlays, egress gen)
src/dr_vps_storage.sh   pool path-fence + overlay/seed lifecycle
src/dr_vps_image.sh     BUILD plane: fetch/verify/bake/provenance/register
src/dr_vps_net.sh       egress fence: nft ruleset render/apply, create-guard, SSRF allowlist
src/dr_vps_doctor.sh    capability gate (KVM/libvirt/RAM/disk/tools) + golden-tamper gate
src/dr_vps_domain.sh    domain XML render (templated+escaped) + create/wait/recreate/destroy
src/dr_vps_gate.sh      the SINGLE authorization choke point (identity bind + closed-shape proof)
src/dr_vps_remote.sh    guest-only exec/push/pull/console-dump (gate-first, safe argv)
src/drvps_rigctl.py     the watcher: validate -> gate -> run, serial + preempt + audit
src/drvps_rigsubmit.py  the ingress accepter: validate + atomically write one request
src/dr_vps_reaper.sh    TTL reaper (gate before destroy) + result/claimed GC

etc/fleet.json          the egress inventory (operator-edited; nothing hardcoded in code)
etc/recipes/*.json      golden recipes (distro, family, upstream_url, upstream_sha256, packages)
```

---

## 3. Identity: content-addressed goldens + a referrer ledger

- A **golden** is an immutable, standalone qcow2. Its `artifact_id` is
  `drvps-raw-v1-<virtual_size>-<sha256>`, where the sha256 is taken over the **raw virtual-disk
  stream** (`qemu-img convert` to raw, metadata-free) -- so two qcow2 files with identical guest
  content but different container metadata (cluster size, etc.) get the **same** id, and any content
  change gets a different id. A golden with an external qcow2 *data-file* or a backing chain is
  **refused** (a hidden host-storage channel).
- Each **VM** is a copy-on-write **overlay** over exactly one pinned golden. `recreate` drops the
  overlay and re-clones the *same* pinned golden (deterministic reset).
- The **store** is a SQLite DB (`store.db`) with a **referrer ledger**: a golden cannot be deleted
  while any VM/overlay/snapshot references it (refcount-gated, exit 19). All mutations go through one
  safe-quoting SQL path and are transactional; every must-affect-one-row UPDATE asserts `changes()==1`.

---

## 4. The egress fence (`simulated` deny-by-default)

A test VM must not reach the host, the rest of the fleet, or the internet -- except a curated package
cache. Four layers, all driven by the operator-owned `etc/fleet.json` (nothing is hardcoded):

1. **Isolated libvirt network `simnet`** -- its own bridge (`drvps0`), DHCP on, internal DNS off
   (`<dns enable='no'/>`).
2. **nft deny-by-default** -- `guest_in` + `forward` hooks generated from `fleet.json`
   (only the `simulated_allow` cache CIDR/port + mock ports are opened; everything else, IPv6
   included, is dropped by the default policy). The `block_cidrs`/`block_ipv6_all` keys are
   **reserved** for the deferred non-default profiles -- no code consumes them today, and editing
   *any* fleet.json key (reserved ones included) bumps the egress **generation** (recorded as a real
   rule comment), staleness-blocking VM creation/guest-exec until the fence is re-applied.
3. **A squid cache** that **owns the whole `squid.conf`** (Fedora's stock file has no `conf.d`
   include) with a mirror allowlist (method + port + dstdomain constrained, SSRF-checked). It
   **SSL-bumps** allowlisted HTTPS mirrors so package traffic is cached; the guest still GPG/Release-
   verifies (cache != trust). The rig's cache CA is `nameConstraints`-bounded and baked into goldens.
4. **VM<->VM L2 isolation** via `<port isolated='yes'/>` on the NIC (nft is L3-only; guest-to-guest on
   the shared bridge is blocked by libvirt bridge port isolation).

The fence is **re-applied every boot and re-verified every ~120s** by a root `drvps-egress` oneshot +
timer, which re-stamps a world-readable **generation marker** on tmpfs (`/run/distro-rig-vps/
nft.applied`). The non-root rig can read but not forge it; if the marker is missing/stale, VM creation
and guest-exec **fail closed** (exit 24) until the fence is re-applied.

---

## 5. The gate: the single authorization choke point

`dr_vps_gate_vm <mode> <id>` (`src/dr_vps_gate.sh`) is called before **any** `virsh`/`ssh`/`scp` on an
agent-named VM. It has two tiers:

**`lifecycle` (identity bind)** -- proves the live libvirt domain *is* the store row, not a stale or
same-named impostor:
- `id` is a safe filename component (no leading `-`), and a **registered** rig VM;
- the overlay is **pool-fenced** and the registered golden exists;
- the live domain's **primary disk** (first `<disk device='disk'>` element, `type='file'`) is exactly
  the fenced overlay;
- the overlay's **backing** is exactly the registered golden, with **no external data-file**;
- the live **UUID** equals the stored UUID (a VM with no recorded UUID must be recreated before
  guest-exec).

**`guestexec` (adds a closed live-domain shape proof)** -- before any guest->host data channel
(`exec`/`push`/`pull`/`wait`/`console-dump`), proves a *positive bound* on every channel the domain
could use to reach the host/fleet/net:
- XML parses (`count(/domain)==1`, so the proof fails **closed** on malformed XML);
- every interface is `type='network'` on `simnet` **and** carries `<port isolated='yes'/>`;
- a **positive device whitelist** over every `/domain/devices/*` (only the template classes + benign
  libvirt auto-defaults); **no** `qemu:` namespace (raw QEMU args);
- the `<emulator>` path canonicalizes under `/usr/`; `<watchdog>` action is guest-only (no host-write
  `dump`); no disk `<mirror>`/network-source/`@path` host channel;
- `/domain/os` contains only `type`+`boot`(+`bootmenu`) -- no direct-boot/firmware host path;
- a **closed top-level `/domain`** shape (only template + benign auto-added children; no
  `seclabel type='none'`, no `cpu host-passthrough`);
- a **broad host-reference sweep** (no host connection/backend/path/dev beyond overlay+seed+golden);
- storage shape closed (all disks file-backed; exactly one overlay disk; every cdrom is the seed iso);
- every serial/console is a `pty`;
- the egress generation is **fresh**.

`destroy` and `status` are deliberately **not** pre-gated by the watcher. `destroy`: `dr-vps destroy`
is itself the authoritative gate (store-row required + conditional identity gate + path-fence) and
can also clear a no-domain "broken" VM, which a raw lifecycle gate would wrongly reject and wedge the
agent's reset path. `status`: `dr-vps status` is an ungated pure store **read** (no virsh/ssh/scp),
and the raw lifecycle gate (which requires a live domain) would refuse it exactly on a broken or
undefined VM -- the state the agent most needs to inspect (the same wedge class as `destroy`).

---

## 6. The Phase-2 control loop (agent -> watcher)

**Trust model: a SINGLE untrusted agent.** The `drvpsctl` group is one trust domain -- the operator
adds exactly **one** agent principal to it. The rig does **not** isolate between `drvpsctl` members
(all rig VMs are the single agent's disposable playground; result payloads are per-owner-ACL private by default -- files created 0600, a named-owner ACL grant, `getfacl` shows `group::---`; the watcher launcher FAILS CLOSED if the spool fs lacks ACL support; `DR_VPS_RESULT_PRIVATE=0` = legacy group-readable opt-out). Multi-agent
isolation is explicitly out of scope (see [`USAGE.md`](USAGE.md) "Security notes").

Flow:

```
agent: rigctl exec myvm 'reboot -f'
  -> connect /run/drvps-submit.sock (SocketGroup=drvpsctl)
  -> drvps-rigsubmit (User=drvps) validates reqid+size+JSON, atomically writes
     requests/<reqid>.json  (requests/ is drvps-ONLY 0700; the agent has NO spool write)
  -> drvps-rigctl watcher (User=drvps, never root):
       claim (unlink) the request  ->  validate against the fixed verb whitelist
       ->  GATE the VM verb  ->  run `dr-vps <verb>` (guest op runs INSIDE the fenced VM)
       ->  write results/<reqid>.json  (results/ is 2750; the agent group-READS it)
  -> rigctl bounded-waits on results/<reqid>.json, prints the envelope
```

Key properties:

- **Ingress is a socket, not a shared dir.** The agent cannot write the spool at all, so it can never
  plant a non-regular "poison" entry that a never-root watcher couldn't reclaim. The accepter is
  deliberately thin (validate reqid/size/JSON + flood cap + atomic `O_EXCL|O_NOFOLLOW` temp +
  no-clobber `renameat2` publish); the **watcher** is the sole authoritative verb/semantic validator.
- **Fixed verb whitelist.** Global: `create`, `list`. Per-VM `lifecycle`: `recreate`, `destroy`,
  `status`. Per-VM `guestexec`: `exec`, `push`, `pull`, `wait`, `console-dump`. Anything else is
  rejected. `create` fixes `--net`/`--ssh-key`/`--project` (agent-set values are ignored); numeric
  caps (ttl/mem/cpus) are range-checked.
- **`exec` is unrestricted *inside the box*** -- the command is one trailing ssh arg (never `bash -c`
  on the host; the IP is resolved from libvirt by the watcher, not the agent), and it runs only in the
  disposable, egress-fenced VM. `recreate` resets the VM from the verified golden.
- **Serial + preemption.** One watcher owns a single work-lock and runs each op in its own process
  group with a hard per-verb timeout; a same-VM `destroy`/`recreate` **preempts** an in-flight `exec`.
- **At-most-once.** A claimed request drops a durable `results/<reqid>.claimed` marker; a re-submitted
  reqid whose result **or** claimed marker exists is treated as a duplicate and not re-run.
- **Bounded spool.** Request/result byte caps, a pending-count flood cap (with mid-pass re-cap), an
  audit log that size-rotates, and a reaper that GCs result pairs (`.json` + `.claimed`) by TTL and by
  count. Non-regular entries that somehow appear in `requests/` are deleted in place (defense in depth).

---

## 7. Never-root + a hardened install-time root path

The agent-facing **runtime** -- watcher, ingress accepter, reaper -- runs as the unprivileged
`drvps` service user (`User=drvps`, never UID 0, by explicit design). Root appears in exactly two
places: the recurring `drvps-egress` oneshot + timer (re-applies the nft fence every boot and ~120s;
loading nft rules cannot be done unprivileged -- see section 4), and the one-time `dr-vps-setup`,
whose root-exec surface is hardened on every axis a root installer can be attacked through:

- eval-free argv (`run`/`run_sh`; values are literal args, never re-parsed);
- a validated privileged env (rig-namespace paths judged lexically with `realpath -ms`, non-root
  service user, simnet-only net, non-wildcard proxy, strict-int numerics, `NET_STATE` under `/run`);
- a **physical** install path (`cd -P`/`pwd -P`) with a charset guard and a root pre-source preflight
  (so a symlink-swapped or attacker-owned tree can't be sourced/exec'd as root);
- inherited tool-binary seams (`DR_*`) and `DR_LIBVIRT_URI` dropped when root; `#!/bin/bash -p` + a
  pinned PATH + a one-time `env -i` re-exec (NUL-parsed allowlist) to defeat `BASH_ENV`/`BASH_FUNC_*`
  and PATH/interpreter seams;
- **fd-based** race-free create/own (`openat O_NOFOLLOW` + `fchown`/`fchmod`) for every service-owned
  target, including the generated ssh key;
- uninstall destroys only domains proven store-owned (by UUID).

---

## 8. What is and isn't claimed

**Claimed (the security goals):**
1. The single agent cannot escape the egress fence (reach host/fleet/internet from a guest).
2. A verb can never hit an unrelated libvirt domain or a non-rig store row; goldens are operator-only
   and gate-protected.
3. The agent cannot drive the never-root watcher into a root-exec, an out-of-tree write, or an
   un-reclaimable disk/inode DoS.
4. The agent cannot forge or replay a request, nor desync the accepter from the watcher.
5. The install-time root path cannot be subverted.

**Not claimed / out of scope:**
- **Per-agent isolation.** `drvpsctl` is a single trust domain; there is one agent. No per-peer result
  privacy. A multi-agent rig would need per-agent authorization (peer-uid ownership via `SO_PEERCRED`
  + owner-filtered verbs) -- a Phase-3/4 feature.
- **A zero-trust confinement of the guest.** Confinement still relies on libvirt/qemu + the root
  egress unit + the privileged installer; the honest host-facing surface is documented, not eliminated.
- Broker / tenants / quotas / remote provider (deferred Phase 3/4).

---

## 9. Exit codes (authoritative; `src/dr_vps_api.sh`)

```
0  ok            2  usage           10 unknown-distro   11 ungreened
12 capability    13 libvirt-unusable 14 not-found       15 conflict/lease
16 ip/port-collision  17 timeout     18 golden-verify-failed  19 referenced (gc-gated)
20 quarantined   24 egress-policy-refused   25 secret-policy-refused
```

---

## 10. Historical records

- CHANGELOG.md -- the original phased
  design sketches (rationale and threat tables). Historical.
- `STATUS.md` -- the running implementation/validation history, including live-KVM first-contact fixes
  and CHANGELOG.md.
