# CONCEPT -- per-run network modes for drvps (DR-6)

Status: **design converged under adversarial architecture review (2026-07-09)**; the review closed real
confinement holes now folded into the body (locked subnet allocation §5, lifecycle/allocation races §5.1,
per-group host-plane INPUT deny §3.4, DNS destination+source binding with non-forwarding dnsmasq §3.4) and
verified the **shared/simnet legacy path intact** (§7.1). Implementation status: Stage 0 (the net-group
record layer, `dr_vps_netgroup.sh`) is landed and inert; allocation and the lifecycle state machine are NOT
implemented. Because this touches the CREATE-GATE (the confinement boundary), the remaining stages require
the full external-review bar again before code ships. §8 carries the test requirements the design review
mandated. Supersedes the problem statement in `docs/ISSUE-per-net-isolation.md`. Companion to `CONCEPT.md`
/ `dr_vps_net.sh`.

## 1. Why
Today every guest lands on ONE shared `simnet` (bridge `drvps0`, subnet `10.123.0.0/24`, one dnsmasq DHCP scope).
Guest<->guest is port-isolated, but the DHCP scope is SHARED across all tenants -> a tenant's in-pool address (a
lease or a static) can collide with another tenant's guest (surfaced live between two co-tenant harnesses). And
there is no way to run a guest that (a) is isolated as its own scope, or (b) is reachable from the local LAN as a
"server under test". DR-6.

## 2. Model: a per-RUN net-group + a per-group MODE
Isolation is keyed on a **net-group id** the CALLER supplies (`rigctl create/use --net-group <id>`); all VMs
sharing an id land on ONE network. This is more correct than keying on the snapshot/base image, because the
caller (harness or consumer) knows the true scenario boundary.

- **Per RUN** = the recommended usage: the matrix `run.sh` (and a consumer's batch) passes its RUN id as the
  net-group -> the whole run gets its own network. This alone de-conflicts co-tenant harnesses (DR-6).
- **Defaults when no `--net-group`:** `--from-snap` -> the snapshot id (auto-group by base); a bare `create` ->
  the VM id (per-VM).
- **The net-group id is a LABEL inside an OWNER-AUTHENTICATED namespace, NOT an authority**. The
  namespace key is derived from the AUTHENTICATED drvpsctl principal (the effective owner the rig already
  authenticates), never from a caller-supplied `--owner` string. Two owners can reuse the same human-readable id
  without colliding, and one owner cannot address another owner's group. Trust boundary: **one owner == one trust
  domain** (matches "same owner + same run" in §7); within an owner, jobs may join each other's group by id.
  Where a single Unix owner fronts MUTUALLY-DISTRUSTING tenants, that is NOT this deployment -- if it ever is, the
  id must become control-plane-generated capability-grade randomness, not caller input (recorded in §6 as an
  assumption, flagged for the operator).
- Each net-group has a **MODE** (`--net-mode`, default `shared`): the network shape it gets. Mode/subnet/bridge/
  DHCP-range/declared-LAN-CIDRs are **PINNED on first creation** and immutable for the group's life; a later
  `use`/join MUST match the pinned mode exactly or is refused.

## 3. The three modes
| Mode | bridge / subnet / DHCP | guest<->guest (same group) | reaches | gate posture |
|---|---|---|---|---|
| **`shared`** *(today = simnet)* | shared `drvps0` / `10.123.0.0/24` / one drvps dnsmasq | blocked (port-isolated) | squid cache (allowlisted mirrors) | isolated + `<dhcp>` + no `<forward>` (as today) |
| **`isolated`** | per-group bridge / per-group subnet / per-group drvps dnsmasq | **allowed** (one trust domain) | nothing (airgapped) | isolated + `<dhcp>` + no `<forward>`, per-group bridge |
| **`routed`** | per-group bridge / per-group subnet / **per-group drvps dnsmasq (own IP range)** | allowed | ONLY the operator-declared LAN CIDR(s), both ways (no internet) | **`<forward mode='route'>`** -- a GATE CARVE-OUT, nft is the authority |

### 3.1 `isolated` -- the clean collision fix (cheapest)
Per-group dedicated bridge + subnet + drvps dnsmasq; NO `<forward>`, NO squid, NO external. Airgapped. Within a
group, guest<->guest is ALLOWED (same owner + same run = one trust domain) -- a capability the all-port-isolated
model can't offer, useful for multi-VM scenarios. Fence: per-group INPUT policing (§3.4 -- DHCP + DNS to the group
dnsmasq only, then drop) and NO forward path at all -- simpler than simnet's (no squid exception). **IPv6 dropped**
(§5.3) even though airgapped, so a guest can't leak via v6. (No FORWARD anti-spoof needed -- there is no forward
path; §3.3.)

### 3.2 `routed` -- a guest "server" reachable from the local LAN
The scenario: test a drvps guest acting as a VPS **server** FROM a rig/tester on the local network.
- The guest keeps its OWN subnet + OWN drvps dnsmasq (its own IP range serves the guest distro) -- NOT the LAN's
  DHCP. drvps owns the addressing so the gate can validate the scope.
- libvirt `<forward mode='route'/>` (routed, **NO NAT**): the host routes between the guest subnet and the LAN.
- **libvirt's route mode is NOT a LAN-only primitive**: libvirt documents routed networks as
  UNRESTRICTED in/out unless further filtered. So **the drvps nft fence -- not the route table, not "drop the
  default route" -- is the sole authority.** The fence is a POSITIVE allowlist bound to the observed
  interface + source + destination, default-drop for the group bridge:
  ```
  # egress (guest -> LAN): only the group's own source, only declared LAN CIDRs
  iifname <group-bridge> ip saddr <group-subnet> ip daddr { <declared_lan_cidrs> } accept
  iifname <group-bridge> drop
  # ingress (LAN -> guest): only to the group's own subnet, only from declared LAN CIDRs
  oifname <group-bridge> ip daddr <group-subnet> ip saddr { <declared_lan_cidrs> } accept
  oifname <group-bridge> drop
  # anti-spoof + v6 (see 3.3 / 5.3) apply first
  ```
  A guest setting its own default route, static routes, or spoofed saddr changes nothing: the host drops by
  ACTUAL observed `iifname`/`oifname`/`saddr`/`daddr`. No **direct IP internet egress** is reachable because
  `0.0.0.0/0` is never in the allowlist and the default-drop catches everything else. (Application-layer relay
  THROUGH an allowed LAN host/proxy is an L7 concern outside drvps's L3 fence -- the guarantee is "no direct IP
  internet egress".) These four are FORWARD-hook rules; **no
  `ct state established,related` is needed** because BOTH directions are explicitly accepted (a LAN-initiated
  session matches the `oifname` accept, its guest replies match the `iifname` accept). DHCP
  never traverses the forward hook -- it is guest<->host dnsmasq on the INPUT hook, handled before anti-spoof
  (§3.3).
- **LAN->guest routing is ASSUMED PROVIDED** (out of drvps scope): the operator supplies the LAN-side static
  route. drvps PRINTS it in standard iproute2 form (§7) and the fence still polices the ingress direction.

### 3.3 Anti-spoof (MANDATORY for every non-shared mode)
- **Anti-spoof is a FORWARD-path rule, applied to ROUTED traffic only.** A FORWARDED packet whose ingress iif is
  `br-dr-<group>` MUST have `ip saddr <group-subnet>`; otherwise drop. This makes cross-group source-spoof
  impossible even if two groups are both routed.
- **DHCP is NOT subject to the saddr check.** A DHCP discover
  legitimately sources `0.0.0.0`. DHCP is guest<->host dnsmasq on the INPUT hook, accepted FIRST by
  `iifname <group-bridge> udp dport { 67, 68 } accept` -- exactly as simnet's `guest_in` does -- and never reaches
  the forward-path anti-spoof. The ordering is: input-hook DHCP accept -> forward-hook anti-spoof -> forward-hook
  §3.2 allowlist -> default drop.
- **Per-VM (hardening target):** the tap/vnet + MAC + assigned lease/static IP must match exactly (built + tested;
  if a live-only proof is out of scope for the landing cycle it ships gated per the standard rule, but per-bridge
  anti-spoof is never gated).
- Ingress (LAN->guest, forwarded) to any group bridge MUST have `ip daddr <group-subnet>`.
- **Scope:** per-bridge FORWARD anti-spoof is mandatory wherever a forward path exists
  (`routed`). `isolated` has no forward path, so its anti-spoof reduces to the §3.4 INPUT policing; WITHIN a bridge
  (same group = one trust domain) L2/source spoofing is out of scope by design.

## 3.4 Host-plane INPUT policing -- a per-group `guest_in` (BLOCKING)
The FORWARD rules (§3.2) say nothing about traffic aimed at the drvps HOST itself. Today simnet's `chain guest_in`
polices guest->host on the INPUT hook (IPv6 drop, established/related, DHCP, cache only, then drop). **Every
non-shared group bridge MUST get the SAME shape**, else a `routed`/`isolated` guest can reach the group gateway,
the host's dnsmasq (DNS/TFTP), squid, or any host daemon bound to `0.0.0.0`. For each group bridge, the drvps
INPUT base chain (§4) jumps to a per-group input subchain. **DNS is bound on BOTH axes -- source
`ip saddr <group-subnet>` AND destination `ip daddr <group-gw-ip>`**: the daddr bind
stops the guest reaching any OTHER host resolver; the saddr bind stops a SPOOFED-source query whose reply would
otherwise exit via host OUTPUT toward the spoofed address (a reflection/exfil channel out of an airgapped guest).
**DHCP stays UNBOUND** (`udp dport {67,68}`) because a DHCP discover/renew is broadcast (`255.255.255.255`) from
`0.0.0.0` -- a daddr/saddr bind would break lease acquisition; DHCP cannot widen the L3 boundary, so
unbound is safe, exactly as simnet's `guest_in`:
```
iifname <group-bridge> meta nfproto ipv6 drop
iifname <group-bridge> ct state established,related accept
iifname <group-bridge> udp dport { 67, 68 } accept                                          # DHCP: broadcast/0.0.0.0 -> UNBOUND (as simnet)
iifname <group-bridge> ip saddr <group-subnet> ip daddr <group-gw-ip> udp dport 53 accept   # DNS: src AND dst bound
iifname <group-bridge> ip saddr <group-subnet> ip daddr <group-gw-ip> tcp dport 53 accept
# NO squid, NO other host daemon, NO resolver other than THIS group's dnsmasq
iifname <group-bridge> drop
```
`shared`/simnet keeps its EXISTING `guest_in` verbatim (§7.1); this is the ADDITIVE per-group equivalent. Any host
service a mode legitimately needs must be EXPLICITLY declared + daddr-bound here -- never reachable by omission.

**The group dnsmasq MUST be non-forwarding.** Accepting
DNS to the host dnsmasq is only safe if that dnsmasq cannot itself reach outside:
- **`isolated` (airgapped):** the per-group dnsmasq is LOCAL-ONLY -- `no-resolv`, `no-poll`, ZERO upstream
  servers, no recursion/forwarding, no TFTP or other dnsmasq features. It answers only from its own leases/local
  data. A forwarding resolver would give an airgapped guest an indirect internet path -- forbidden.
- **`routed`:** DNS forwarding is DISABLED by default; if a scenario needs upstream resolution it must be
  EXPLICITLY declared and constrained to the declared LAN CIDR resolver(s) -- the host's default resolvers must
  never silently become a bypass.

## 4. Security -- the gate is the load-bearing change
`dr_vps_net.sh` create-guard today HARD-REFUSES any net that isn't isolated + `<dhcp>` + `<forward>`-free +
bridge==`drvps0`. The change is additive but the gate/fence are shared code, so the rules are:

**Per-mode gate branches**
- `shared`: UNCHANGED -- retains the exact `drvps0` / `10.123.0.0/24` / `simnet` literals and the existing
  create-guard body (§7.1); it is NOT per-group.
- `isolated`: the same *invariant shape* (isolated + `<dhcp>` + no `<forward>`) but on a per-group bridge/subnet
  instead of the drvps0 literals, plus §3.4 INPUT policing. `simulated_networks` stays an allowlist; a new-mode net
  is NEVER admitted through the shared branch.
- `routed`: a NEW, tightly-scoped branch -- a net-group may be `routed` ONLY if (a) it is on the operator
  allowlist keyed by **owner+group** (§5.5), (b) its net has the EXACT routed shape (`<forward mode='route'>` +
  own `<dhcp>` whose range is proven inside the stored subnet + per-group bridge), (c) the fence is the §3.2
  positive allowlist + §3.3 anti-spoof + §5.3 v6 drop, and (d) every artifact (libvirt XML, stored subnet, bridge
  name, dnsmasq range, nft rules, marker generation, gate proof) agrees on ONE immutable group record. A single
  parameterization drift = the fence may not cover the guest -> fail closed.

**No generic drop; ONE base chain per hook at a pinned priority.** The current forward
chain is `policy accept` + explicit `drvps0` drops SPECIFICALLY so it does not clobber podman/libvirt-NAT/firewalld
traffic on the same `forward` hook. DR-6 MUST NOT introduce a generic `forward policy drop` or a
same-priority-ordering assumption. Structure: **exactly ONE drvps base chain per hook** (input/forward)
in `table inet drvps_sim`, at an EXPLICIT pinned numeric priority, that `jump`s to per-concern REGULAR subchains
(anti-spoof, per-group allowlist) -- never multiple unordered same-hook base chains. All drops stay
interface/subnet-scoped to drvps group bridges. Coexistence must be PROVEN in test in BOTH directions: (a)
CONFINEMENT -- a drvps `drop` is terminal, so no third-party higher-priority `accept` can bypass it; (b) LIVENESS
-- a third-party `drop` (podman/firewalld) can still kill traffic drvps intends to ALLOW for `routed`, which
would silently break LAN reachability; the bring-up test asserts routed LAN reachability actually works on a host
carrying podman/libvirt/firewalld rules.

**Weakest link (arch): rule binding + lifecycle correctness**, not NAT-vs-route. §5 (allocation), §5.1
(lifecycle), and §5.2 (marker) exist to keep the one-record invariant.

## 5. Address allocation -- locked probe/validate/reserve
Hash-only allocation is REJECTED: `10.124.<hash>.0/24` is only 256 buckets (~52% collision at 20 groups) and is
blind to future VPNs/routes/container nets. The invariant instead:

**At network create/start, under an exclusive allocation LOCK:**
1. Pick a candidate subnet (deterministic candidate ORDER from a reserved pool, e.g. `10.124.0.0/16` walked
   `/24` by `/24`) -- candidate order only, not the final answer.
2. REJECT the candidate if it OVERLAPS any of: an existing drvps group subnet (incl. stopped-but-reserved);
   a LIVE host route (`ip route`); a host interface address/prefix; an active OR inactive libvirt network subnet;
   an inspectable container network range (podman/docker); `drvps0`'s `10.123.0.0/24`; any declared routed LAN
   CIDR; the DHCP range of any drvps/libvirt dnsmasq.
3. On overlap, advance to the next candidate; if the pool is exhausted, FAIL CLOSED (do not start).
4. RESERVE the chosen subnet in the drvps store (transactional) BEFORE rendering libvirt/nft from it.
5. **Close the external TOCTOU:** a non-drvps route/interface/container-net can appear AFTER the probe
   and BEFORE libvirt starts the bridge. So: revalidate IMMEDIATELY pre-start (still under the lock), then, AFTER
   libvirt brings the bridge up, VERIFY the ACTUAL live bridge/subnet/routes match the stored reservation; on any
   mismatch or newly-appeared overlap, tear the half-started net DOWN, RELEASE the reservation, and FAIL CLOSED --
   never leave a colliding or half-configured bridge live.
6. At every reassert/start, RE-VALIDATE the stored allocation against live host routes (same fail-closed rule).

## 5.1 Net-group lifecycle -- transactional, state-machine'd, quota'd
The group's libvirt net (bridge + dnsmasq) is created on the first VM and destroyed when the last VM is gone. To
make that safe:
- **Explicit state machine in the store, not a bare refcount:** a group record is
  `allocating -> pending -> live -> destroying(tombstone) -> gone`. A VM that has been DEFINED/ATTACHED but is not
  yet running counts as `pending` and BLOCKS destroy -- closing the "concurrent create attached but not-yet-live"
  race. Refcount is DERIVED from actual live+pending domains (virsh), never trusted as the sole truth; underflow
  is FATAL.
- **One exclusive lifecycle lock** serialises create/join/destroy AND is shared with the reassert timer, the
  reaper, and allocation-reuse: the timer will not re-render a group in
  `destroying`, and a name/subnet is reused only after a `gone` tombstone is verified.
- **Exact lock boundaries:** the lock is
  held for the SHORT store transitions only -- (i) `allocating -> pending` (reserve subnet + name + record the
  domain as pending) and (ii) `pending|... -> live` and `-> destroying` -- each a bounded critical section. The
  actual libvirt `net-start`/domain `create` runs OUTSIDE the lock but is BRACKETED by the pending tombstone (so a
  concurrent destroy sees `pending` and refuses) and by the §5-step-5 post-start verify (re-acquire lock, verify
  actual bridge, then commit `live` or roll back to `destroying`). Every `virsh`/`ip`/`podman` call is TIME-BOUNDED
  regardless. Net: no external call is held under the lock, yet destroy can never interleave a half-attached VM.
- **Destroy only after proving no live OR pending domain** is attached; then tombstone -> teardown (§5.4) -> gone.
- **Reaper** compares store <-> virsh <-> nft under the lock and removes orphans (stale libvirt nets, stale nft
  rules/table entries, stale store records).
- **QUOTAS (config-driven, `fleet.json`; DoS bound):** max net-groups per owner, max `routed` groups per
  owner, max bridges, max leases per group, max stale/stopped (tombstone) groups retained. Stale/stopped groups
  DO count toward their own cap; on a quota refusal the reaper RUNS FIRST (so reclaimable garbage never denies
  service permanently), and only a genuinely-at-limit state is a clean refusal.
- **Bridge name is deterministic, IFNAMSIZ-safe, collision-checked:** `drb-<N hex of
  sha256(owner,group)>` sized to fit the 15-char `IFNAMSIZ` limit (prefix `drb-` = 4 chars -> 11 hex). On store
  insert, if that truncated name collides with a DIFFERENT `(owner,group)`, deterministically re-salt (store a
  per-record nonce, re-hash) and record the final name IN the store; if re-salt space is exhausted, FAIL CLOSED.
  The candidate is ALSO checked against LIVE non-drvps interfaces before define/start; a live-name
  collision re-salts or fails closed too. All rendering (libvirt/nft/dnsmasq) reads the STORED name, never
  recomputes it.
- **Group ids are SANITIZED and length-limited** before they build any filesystem / libvirt / nft name.

## 5.2 Marker / reassert -- PER-GROUP canonical generation
Today one marker records "some egress was applied" and the `drvps-egress.timer` re-asserts it (the rig user can't
read nft, so the unprivileged create-guard trusts the marker). For multi-net:
- **PER-GROUP generation, canonically serialized:** each group has its OWN marker/generation, computed
  from a CANONICAL serialization of ONLY that group's record (bridge/subnet/mode/LAN-CIDRs) plus `fleet.json`:
  sorted object keys, fixed encoding, and the **LAN-CIDR list SORTED** (canonical order) so a semantically-equal
  reordering does not churn the generation. Hashing the WHOLE store into one generation is REJECTED -- it would
  stale every group on any unrelated group change.
- **The `shared`/simnet marker is INDEPENDENT of the group store:** it is computed exactly as
  today (fleet inventory only) and is NEVER a function of any group record, so creating/tearing down a group can
  never stale or alter the shared marker.
- **Atomic update under the §5.1 lifecycle lock:** a marker is written atomically (temp + rename) so a reader
  never sees a half-written generation; the timer takes the same lock while re-rendering.
- The timer RE-RENDERS and LIVE-VERIFIES **every active group fence** (skipping `destroying` tombstones), not just
  simnet.
- The unprivileged create-guard REFUSES to start a VM if the marker does not cover the SPECIFIC group + mode being
  started (a `shared`-covering marker never satisfies a `routed` group, and vice versa).

## 5.3 IPv6 + DHCP proof
- **IPv6:** every non-shared group bridge DROPS IPv6 (`meta nfproto ipv6 drop`) exactly as simnet's `guest_in`
  does, AND IPv6 is disabled in the group's libvirt/dnsmasq/domain config. Route-mode v6 is especially unsafe
  (no NAT assumption) -- no v6 egress path is created.
- **DHCP proof:** the gate proves `/network/ip` address + prefix AND `/network/ip/dhcp/range` are INSIDE the
  stored group subnet and overlap no other scope. "Has `<dhcp>`" is insufficient for multi-net.

## 5.4 Teardown -- tombstoned, safe + idempotent under lock
Destroy first moves the group to the `destroying` TOMBSTONE state (§5.1) under the shared lifecycle lock, so the
reassert timer, the reaper, and allocation-reuse all SKIP it and cannot race a half-torn-down group. It then
removes, idempotently: the nft rules/table entries, the libvirt network, the dnsmasq state, and the store record;
only after teardown is VERIFIED does the record become `gone`. Bridge names / subnets are REUSED only after `gone`
(else a stale routed rule could keep unintended LAN reachability, or block a future unrelated bridge that reuses
the name).

## 5.5 Operator allowlist for `routed` -- schema-validated
The `routed` allowlist (in `fleet.json`) is keyed by **owner+group** and each entry's declared LAN CIDR(s) are
schema-validated at load: valid CIDR syntax; NO `0.0.0.0/0`; NO `::/0`; no overlap with any group subnet or other
drvps subnet; no multicast/link-local; no broad RFC1918 or host-management network unless the entry is explicitly
flagged intentional. A `routed` start with no matching allowlist entry is refused.
- **Absent keys FAIL CLOSED:** a MISSING `routed` allowlist key means EMPTY -> every `routed` start is
  refused (never "unrestricted"). MISSING quota keys (§5.1) resolve to explicit conservative DEFAULTS, never
  unlimited. No omission in `fleet.json` may widen access.

## 6. Out of scope / assumptions
- LAN->guest routing (the route table) is **operator-provided** for `routed`; drvps does not touch the LAN gateway.
- No internet egress in any new mode (no NAT). `shared` keeps the squid cache path.
- Not creating OS users / not changing the golden/build plane.
- **Trust model:** one drvpsctl owner == one trust domain (§2). If a single owner ever fronts mutually-distrusting
  tenants, net-group ids must become control-plane-issued capability-grade tokens -- flagged for the operator, not
  assumed here.

## 7. Resolved decisions (operator, 2026-07-09)
- **Default net-mode = `shared`.** A bare `create`/`use` with no `--net-mode` gets today's simnet path exactly.
  The new modes are strictly ADDITIVE, selected by `--net-mode`; a run with no net-mode is indistinguishable from
  today.
- **Intra-group guest<->guest = ALLOWED for `isolated`/`routed`** (a net-group is one owner + one run = one trust
  domain); **`shared` keeps today's `<port isolated='yes'>` unchanged.**
- **`routed` uses STANDARD formats, no custom syntax:** libvirt `<forward mode='route'/>` (the standard routed
  net); the reachable local subnet is a plain CIDR; and drvps PRINTS the exact LAN-side route the operator applies,
  in standard iproute2 form -- `ip route add <guest-subnet> via <drvps-host-ip> dev <lan-if>` (and its
  `ip route del` inverse for teardown). LAN->guest is operator-applied, out of drvps scope.
- **`run.sh` adopts per-run `isolated` only AFTER the feature lands + is tested** (not now); the matrix stays on
  `shared` until then.

## 7.1 HARD REQUIREMENT: the current (`shared`/simnet) mode stays INTACT
The existing simnet path -- the create-gate invariant, the nft fence, the dnsmasq scope, the squid egress, the
`drvps0` / `10.123.0.0/24` literals, `<port isolated='yes'>` -- must stay behaviourally IDENTICAL. Enforced by:
- **A LEGACY path, not a generalized function.** The no-`--net-mode` code calls the EXISTING shared create-guard /
  render / domain-XML unchanged; new modes are added as NEW functions. The shared confinement function is NOT
  parameterized-away first. (e.g. keep `dr_vps_net_render simulated` and the create-guard body producing
  byte-identical output for the shared path.)
- **GOLDEN-DIFF tests:** `dr_vps_net_render simulated`, the create-gate XML fixture, and the no-net-mode domain
  XML must be diff-IDENTICAL to today. Any diff fails CI unless the operator explicitly approves a separate shared
  bugfix.
- **CALL-PATH assertion:** identical OUTPUT does not prove the
  shared path is unchanged if it now routes through new code. A test must PROVE the no-`--net-mode` path does NOT
  invoke allocation, the group-store, per-group marker code, or marker-generation-v2 -- e.g. via seam counters /
  spies asserting those functions are never called on the shared path. The `shared` marker independence (§5.2) is
  part of this guarantee.
- **No literal drift:** shared keeps exact `simnet` / `drvps0` / `10.123.0.0/24` / no-`<forward>` / DHCP-present /
  `simulated_networks` membership / squid-cache nft exceptions / `iifname`+`oifname "drvps0"` drops / `<port
  isolated='yes'>`.
- If the review finds a MAJOR pre-existing bug in `shared`, it is REPORTED separately (not silently changed) and
  the operator decides.

## 8. Process
CONCEPT (this, converged) -> PLAN -> external plan review -> implement in cycles (dr_vps_net.sh gate +
fence, dr-vps-setup multi-net, dr_vps_domain net-group, store/reaper lifecycle) with an external CODE gate +
bug-sweep + bats each cycle -> a real multi-mode bring-up test. A confinement-boundary change holds to the
multiple-varied-clean-rounds review bar.

**PLAN-phase test requirements (mandated by the design review, carried forward so they are not lost):**
- §7.1 golden-diff + call-path spies (shared unchanged).
- §3.2/§3.3 confinement: DHCP bootstrap WITH anti-spoof enabled (proves lease acquisition survives); routed
  positive-allowlist accept + default-drop.
- Live routed sessions: LAN->guest initiated AND guest->LAN replies both reachable on a host carrying
  podman/libvirt/firewalld rules (the §4 liveness proof).
- Negative routed allowlist: reject `0.0.0.0/0`, `::/0`, overlap with any drvps subnet, broad RFC1918 without the
  intentional flag.
- One drvps base chain per hook with regular subchains (§4); pinned numeric priority asserted.
- **Host-plane negatives:** `routed` guest -> drvps HOST's LAN IP on ssh/3128/etc MUST drop, while
  guest -> a DIFFERENT declared-LAN host works; guest -> `<group-gw-ip>:53` (its own dnsmasq) works, guest ->
  `<group-gw-ip>`:any-other-port drops; `isolated` guest DNS query for an external name gets NO answer (dnsmasq
  non-forwarding).
- **Lifecycle race:** a destroy issued between `net-start` and commit-`live` must REFUSE (pending
  bracket); reassert ignores pending-not-live groups.
- **Absent `fleet.json` keys:** missing routed allowlist => routed refused; missing quota keys =>
  the exact conservative DEFAULTS (pin the numbers in PLAN), never unlimited.
- **Spoofed-source DNS:** a UDP/TCP DNS query to `<group-gw-ip>:53` from a source OUTSIDE
  `<group-subnet>` MUST drop and produce NO host OUTPUT (reflection/exfil closed).
- **IPv6 RA/SLAAC:** assert no RA/SLAAC is emitted on group bridges and guest RS/any-v6 is dropped.
- **Other host responders:** NTP/TFTP/mDNS/other UDP responders on the host are unreachable from group
  bridges (covered by the §3.4 final drop -- test it).
- **dnsmasq flags:** pin per-group dnsmasq -- `isolated`: no upstream, no TFTP, no RA, no implicit
  `/etc/resolv.conf` import, `no-resolv`/`no-poll`; `routed`: forwarding only to declared-LAN resolvers when
  explicitly enabled, else off.

