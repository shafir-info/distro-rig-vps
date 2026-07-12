# CONCEPT -- drvps minimal distro VM compatibility contract + console observability (STAGED) [rev4]

Status: rev4, externally converged (correctness, architecture, and security all GO; every finding folded in).
Re-scoped from "expose all qemu options" to a TYPED, RESOLVED, gate-bounded, STAGED contract. Part A
(console-log) is proven and ships FIRST. An interactive console is a separate parked idea (TODO.md).

## Reframe
NOT "N independent knobs for all qemu/libvirt options" (combinatorial test + security surface). Instead:
a recipe declares REQUIREMENTS -> a resolver selects a named safe hardware profile + small typed overrides ->
the renderer emits ONE OF A FEW known XML shapes -> the GATE validates the LIVE normalized XML. Shipped in
SAFE INDEPENDENT STAGES. libvirt domain-capabilities are INPUT to preflight, never a replacement for the gate.
REJECTED: per-recipe raw XML fragments (they make recipes mini-domain-authors + explode the security surface).

## The resolver (the missing seam -- build FIRST, no-op)
One function `resolve_vm_contract(id, distro, create_args) -> contract`, precedence
`env-default <- recipe-requirement <- operator-create-arg (escape hatch ONLY)`. render_xml AND preflight AND
inspect ALL consume the SAME `contract` object -- no ad-hoc env/JSON/arg scraping in render. Recipe fields are
REQUIREMENTS (`requires_cpu_baseline`, `requires_firmware`, `disk_driver`, `nic_driver`, `guest_boot.*`),
a VERSIONED JSON schema, UNKNOWN KEYS FAIL CLOSED. create-args are operator escape hatches, not the normal
recipe language ("declare a requirement + add one reviewed shape", never "try random knobs").

## Invariants (apply to every stage)
- UNMET requirement FAILS CLOSED: a recipe requirement whose stage/gate/host-support is not yet
  built -- `requires_firmware=uefi` before Stage 6, or a host that cannot provide `requires_cpu_baseline` --
  REFUSES create with a precise "requirement understood, not satisfiable by this build/host" message. NEVER a
  silent fallback (never render BIOS for a uefi requirement). The resolver/schema may KNOW a requirement before
  its stage ships; render must never silently ignore it.
- Every gate exception ships BOTH an inactive-defined-XML fixture AND a live-running-dumpxml fixture (authored
  != live -- the console-mirror bug proved render-only fixtures miss real shapes).
- The GATE never trusts render: each knob's emitted shape gets a POSITIVE gate predicate; the pre-start gate
  (Stage 0) checks the live XML before boot. Backward-compat: pre-change VMs still pass the gate.

## Staging (ORDER + safety only -- NOTHING is dropped; every listed feature stays in scope)
Staging decides WHEN each feature is built (Part A first because it is proven), never WHETHER. All features
below -- console-log, CPU, seed, RNG, disk/nic bus, machine/features, UEFI, and the separate interactive
console -- remain PLANNED. "Later stage" == built when its stage comes (or when a recipe
first needs it), NOT removed. Removing any feature requires explicit operator approval; adding is welcome.
- **Stage 0 (FOUNDATION -- resolver + persistence + pre-start gate; NO XML behavior change):**
  1. `resolve_vm_contract(id,distro,args) -> contract` returning TODAY's fixed template values; render +
     preflight + inspect route through it. NO render-time env scraping after this (env is an INPUT to the
     resolver, e.g. today's `DR_VPS_CPU_MODE` read in render moves behind it).
  2. STORE the resolved contract snapshot in the vm row at create/recreate (so inspect DRIFT compares live-vs-
     stored, and rollback/migration are real, not guesswork).
  3. POST-DEFINE, PRE-START **`closedshape` gate**: a DISTINCT gate mode sharing the closed-shape device
     predicates with `guestexec` but semantically "is this domain SAFE TO BOOT" (not "safe for guestexec"),
     called after define+uuid-check+autostart-off, BEFORE `start`. Rollback on refusal: identity(lifecycle)-
     gated undefine when provably row-owned (destroy||true; undefine; prove absent; scrub overlay/seed/pubkey/
     console; drop row); else leave row+files marked broken and touch NO domain by name. Create + recreate get
     SEPARATE tested rollback paths. (This turns render from trusted-output into gate-checked; the security-r1 fix.)
  4. Fixtures: BOTH inactive-defined-XML and live-running-dumpxml (they differ -- console-mirror history).
- **Stage 1 (Part A, console-log):** SHIP NOW -- append='on' + drvps pre-create (PROVEN) + the BOUND fix +
  rewrite `console_admission`. Not held hostage to B/C/UEFI.
- **Stage 2 (CPU):** host-model default + `requires_cpu_baseline` + preflight via libvirt DOMCAPABILITIES +
  inspect reports resolved CPU. Fixes the el9 panic class.
- **Stage 3 (seed boot):** network-optional + `console=ttyS0` baked in the golden. Fixes the u26 stall + empty-
  console class.
- **Stage 4 (RNG):** fixed `<rng model='virtio'>` /dev/urandom + an EXACT gate predicate + a LIVE-dumpxml
  fixture. Separate boot-quality knob (NOT the u26 cause).
- **Stage 5+ (disk_bus / nic_model):** ONLY when a real image needs it, one at a time (disk_bus is NOT "attr
  only": controller + target-dev + cdrom interactions + a gate update).
- **Stage 6 (UEFI -- IN SCOPE, later):** recipe field `requires_firmware` accepted from Stage 2; the
  `<loader>/<nvram>` security-core gate exception is built in Stage 6 (its own converge->plan->code), ideally
  once a UEFI-only distro is baked so it can be live-tested. Planned, not dropped.
- **Stage 7+ (machine / features / vcpu-topology / memoryBacking -- IN SCOPE, later):** each built as a typed
  knob with the same gate predicate + tests. Deprioritized only because no distro has needed them YET.
- **Interactive console:** a separate parked idea (agent/operator socket attach; see TODO.md).
- **Cross-cutting hardening (fold into Stage 0/2):** a POST-DEFINE, PRE-START closed-shape gate.

## Part A (Stage 1) -- console-log readable, with the BOUND fixed
- Mechanism (SOURCE + LIVE proven): `<serial type='pty'><log file=EXPECTED append='on'/>` + `console_log_prepare`
  pre-creates EXPECTED drvps-owned+writable. virtlogd (`virrotatingfile.c`, trunc=false) OPENS the drvps inode
  (no unlink, mode not re-applied). Live: `console-dump` read the boot log, no sudo, file `drvps:qemu 0640`.
- **BOUND (the real gap):** disabling virtlogd rotation removes the SYNCHRONOUS cap; a periodic
  reaper is only EVENTUAL (a guest can spam between sweeps) and truncate-rewrite is lossy vs the live writer. FIX:
  1. Keep a virtlogd **EMERGENCY `max_size`** (>> the drvps cap) as the synchronous host-DoS fail-safe. If it
     fires the log degrades to root-owned/unreadable, but the HOST is protected (accepted + documented).
  2. The drvps reaper enforces the NORMAL cap by **truncate-in-place via a NO-FOLLOW fd**:
     `open(O_NOFOLLOW)` + `fstat` (regular, expected owner/mode, link-count==1) + `ftruncate` the FD; NEVER
     unlink/rename an active log (closes the path-swap race on the service-owned dir). Accept the diagnostic
     tail MAY lose a few bytes during a concurrent sweep -- documented + tested, not a silent guarantee.
  3. `console_admission` asserts **BOTH floors**: `normal_floor = MAX_VMS*(FILE_CAP+overshoot)+
     reserve` (overshoot = max serial write-rate x max sweep interval) AND `emergency_floor =
     MAX_VMS*EMERGENCY_MAX_SIZE*(EMERGENCY_MAX_BACKUPS+1)+reserve` -- OR the console dir sits on a dedicated
     fs/project-quota whose hard limit is below the host-danger threshold. `doctor` asserts the reaper is
     enabled+running+RECENT (not just installed) + the emergency virtlogd config; NOT "virtlogd bounded".
     `_dr_vps_console_per_vm_cap` REWRITTEN (current code computes from virtlogd max_size + rejects max_size=0).
- Pre-change VMs: `console-dump` on an append-off/root-owned log returns "recreate to enable READABLE console"
  (sharpen the message), not a generic read failure. Gate UNCHANGED (append transparent to `log[@file=EXPECTED]`).

## Part B -- the contract knobs (Stages 2,4,5; each with a GATE predicate)
Every knob is a typed ENUM, never XML. render emits a known shape; the GATE gets a POSITIVE predicate for that
shape (defense-in-depth -- the gate does NOT trust render):
- **CPU (Stage 2):** gate exact `<cpu>` mode/model, reject host-passthrough (DONE). `requires_cpu_baseline`
  preflight checks the CPU **libvirt/QEMU will actually expose** (domcapabilities / `virsh hypervisor-cpu-compare`
  / a generated host-model definition), NOT raw `/proc/cpuinfo` (host-model is derived from domcapabilities).
- **RNG (Stage 4):** an EXACT POSITIVE shape anchored under `/domain/devices/rng`, not a class
  whitelist: `count(/domain/devices/rng)<=1` AND `count(/domain/devices/rng[not(CANONICAL)])=0`, where
  CANONICAL = `@model='virtio'` + `count(rng/*[not(self::backend or self::rate)])=0` (NO `<driver>`/other rng
  children) + `count(backend)=1` + `backend/@model='random'` + `count(backend/@*)=1` + `count(backend/*)=0` +
  `normalize-space(backend)='/dev/urandom'` + `count(rate)=1` + `count(rate/*)=0` + `not(normalize-space(rate))`
  + rate/@bytes,@period strict positive ints in bounds (NO other rate attrs). Contract enables RNG -> require
  exactly 1; disables -> require 0. (Closes the `<backend model='random'>/etc/shadow</backend>` text-node path,
  the egd/udp form, AND unconstrained `<driver>`/rate shapes.)
- **disk_bus / nic_model (Stage 5+):** gate the exact bus/model AND preserve the single-file-overlay disk +
  optional-seed-cdrom + isolated-network-nic shape. disk_bus implies controller/target-dev/cdrom changes.
- **PRE-START GATE (normative order -- specified in Stage 0):** the CURRENT flow's `define -> start` (with only
  guestexec gating LATER) is the bug being fixed. The NORMATIVE order for create AND recreate is
  **define -> uuid-check -> autostart-off -> `closedshape` gate -> start** (never start before the gate), so a
  render bug/smuggle cannot create a host channel before the first gate. Turns render from trusted-input to
  gate-checked. (See Stage 0 for the mode + rollback.)
- **inspect** reports the RESOLVED live hardware (cpu level, firmware, buses, rng, seed/console readiness) +
  drift vs the resolved-at-create object stored in the row. **preflight/create-guard** explains UNMET
  requirements precisely ("centos9 requires x86-64-v2; the host/selected CPU exposes v1").

## Part C (Stage 3) -- guest-boot seed (guest-side, no gate impact)
- **network-optional:** netplan `optional: true` / networkd `RequiredForOnline=no` (NOT masking wait-online --
  the NIC still requests DHCP). drvps readiness stays "lease + ssh reachable": `wait` keeps polling
  `virsh domifaddr --source lease` and times out no-ip if no lease appears. Test on the target systemd version
  (all-links-optional edge behavior).
- **console=ttyS0 BAKED in the golden** kernel cmdline (cloud-init is too late for first-boot early lines).
  Verify: `/proc/cmdline`, `serial-getty@ttyS0`, and `console-dump` showing early kernel/systemd lines across
  Ubuntu / Fedora / el9 / (UEFI later).

## Part D -- observability (SEPARATE track), except two obligations pulled into B:
preflight explains unmet requirements; inspect shows resolved live hardware. The full structured-`wait` +
error-taxonomy (`rpc_status`/`drvps_status`/typed reason) is an accelerant, not a blocker for these stages.

## Testing (per stage) -- promoted to a contract
resolver precedence; schema UNKNOWN-KEY rejection; allowlist rejection; render +/-; GATE +/- with a LIVE-
DUMPXML fixture (authored != live -- proven by the console-mirror history); preflight fail-fast; live per-distro
(recreate centos9 v2, u26 no-stall + non-empty console); old-VM compat; console reaper race/loss + DoS/quota
behavior; inspect drift; recreate/rollback/migration.

## Migration / rollback (per knob)
applies-to-new-only vs recreate-required; old-VM gate compat; default-change behavior; store the resolved-
hardware object in the vm row at create; a rollback path if a knob breaks a distro. "Defaults to today" is the
baseline; recipe requirements are opt-in.

## Resolved in rev3 (were open in r2)
1. Part A bound -> BOTH floors admitted (normal + emergency), OR a dedicated fs/project-quota; no-follow ftruncate.
2. Pre-start gate -> a DISTINCT `closedshape` gate mode (shared predicates, "safe to boot" semantics) in Stage 0,
   with identity(lifecycle)-gated create/recreate rollback specified.
3. Stage independence: can Stage 1 (console-log) ship with ZERO dependency on the resolver seam, or does the
   admission rewrite couple them?
