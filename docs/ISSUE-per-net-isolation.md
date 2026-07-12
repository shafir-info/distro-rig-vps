# OPEN ISSUE -- per-net / per-tenant network isolation (drvps creates isolated nets)

Status: **OPEN -- design not started. Tracked as DR-6.** Surfaced 2026-07-09 (a co-tenant's same-MAC / new-IP
device-recovery test on the shared `10.123.0.0/24`). This is a design note, NOT an approved plan; if pursued it
goes CONCEPT -> PLAN -> external review before code (the create-guard is the confinement boundary).

## Problem
The rig runs ONE shared simulated network: `simnet` -> bridge `drvps0` -> subnet `10.123.0.0/24` -> a SINGLE
dnsmasq DHCP scope (range `10.123.0.10`-`10.123.0.250`) for ALL guests of ALL tenants. Guest<->guest L2 is
blocked by `<port isolated='yes'/>`, but the DHCP scope is shared, so a tenant's in-pool address (a dynamic
lease OR a static squat) can collide with ANOTHER tenant's guest -> breaks that other guest. Matches
`CONCEPT.md`: `drvpsctl` is a single trust domain; per-agent / per-tenant isolation is explicitly out of scope.

## Proposal (operator ask 2026-07-09)
Upgrade drvps so it can create ISOLATED networks (each with its OWN bridge + subnet + DHCP scope), two variants:
- **(a) Airgapped, NO external access -- the clean, smaller win.** New net profile: own bridge/subnet/DHCP,
  `<forward>` absent, NO squid, NO nft egress fence (nothing to fence -- no egress). Gives true per-net/per-tenant
  isolation and eliminates the shared-pool collision (separate scopes). Guests get zero package downloads /
  external mocks -- fine for self-contained tests.
- **(b) Isolated + a bridge for external access -- harder.** Re-solve egress per net: the nft fence and squid
  bind must become per-bridge/per-net. Bigger surface; security-critical path -> heavier review.

## Blast radius (everything hardcoded to the single net today)
- `src/dr_vps_net.sh` create-guard: REFUSES a guest unless the net's real bridge is literally `drvps0`, has no
  `<forward>`, has `<dhcp>`. **This is the hard blocker** -- no guest can attach to any other net today.
- `src/dr_vps_net.sh` nft egress fence: interface-scoped on the LITERAL `drvps0`.
- `bin/dr-vps-setup`: `DR_VPS_NET_NAME` must be `simnet`; bridge/IP/range are hardcoded literals
  (net-define `10.123.0.1/24` + range `.10`-`.250`); comment already anticipates "if the bridge ever becomes
  configurable, update in lockstep".
- Squid cache proxy bound at `10.123.0.1:3128`; guest->host policing keyed to it.
All must become per-net / parameterized (for (b), per-net egress too).

## Security note
Separate bridges are STRONGER isolation than today's port-isolated shared bridge (no shared L2, no shared DHCP
scope, no cross-tenant collision). The create-guard IS the confinement boundary, so any change to it needs the
same external-review rigor as the rest of drvps.

## Recommendation
Do **(a)** first (airgapped isolated-net profile); keep `simnet` as the "needs-controlled-egress" profile. Add
**(b)** only when a real isolated-but-online need appears.

## Interim workaround (co-tenant discipline -- no code change)
Static-alias an address OUTSIDE the DHCP pool so DHCP never hands it out:
`10.123.0.2`-`10.123.0.9` or `10.123.0.251`-`10.123.0.254` (avoid `.1` bridge, `.0` net, `.255` bcast; pick a
unique one). Do NOT rely on dnsmasq's ping-check (best-effort, dynamic-only, zero protection for a static
squat). `dhclient -r && dhclient` on the SAME MAC re-leases the SAME IP (DHCP is dynamic, no reservations), so it
will NOT change the IP -- the static alias is the way.
