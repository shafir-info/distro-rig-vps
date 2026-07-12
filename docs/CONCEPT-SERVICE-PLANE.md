# CONCEPT -- service plane for long-lived driver VMs

Status: **APPROVED by operator (2026-07-11)** including the no-TTL service-class mechanism; the
architecture passed its external design gate with every finding folded in (see "Design review
resolutions"). Source: the operator change request of 2026-07-11.
Consumer contract (external view): `docs/ORCHESTRATOR-GUIDE.md` -- that file is what the orchestrator developer sees;
THIS file owns every internal design decision. Facts live in exactly one of the two.

## Decisions already taken with the operator (2026-07-11)

1. **Hybrid privilege model.** A second group (working name `drvpsvc`) gates WHO may use the service
   plane at all; WHAT a member may actually reach (egress profiles, service ports, quota) stays
   operator-registered per account. Group membership alone opens nothing outward.
2. **Multi-user, owner-scoped.** The service plane reuses the existing `owner_uid` grain (snapshots
   already work this way). No shared/team ownership of a VM -- DEFERRED until a real consumer needs it.
3. **One orchestrator account.** The orchestrator runs all its workers under one dedicated service
   account; how many processes share it is the orchestrator's concern, invisible to drvps.
4. Two-instance documentation: internal (this) vs consumer (`ORCHESTRATOR-GUIDE.md`), like the agent pack.

## Design review resolutions

The design gate found 5 real architectural gaps; all are folded into this document. Two carry an operator decision the
concept records but does not pre-empt: (1) egress is honestly an **IP-equivalence** fence in v1 -- true
domain granularity needs the SNI gate, chosen at the S3 ARCH gate (build-now vs accept-IP-equivalence);
(2) the **owner-aware runtime boundary (#3c)** is new required scope (HIGH) -- direct guest_ip HTTP
cannot be a supported private interface until it lands. The identity-squatting (owner-namespaced id, S2), no-TTL account-retirement/quota-occupancy, and
idempotency (honest INDETERMINATE; reconcile-by-type stays required) gaps are folded as hard
requirements with no open choice.

## Identity invariants (what makes this NOT docker/rooted-podman)

KVM isolation, never-root watcher, deny-all egress by default, no host filesystem in guests, no
agent-side network/sudo/policy control, operator-owned goldens/profiles/ports/quotas, single-queue
provisioning-only watcher, mandatory-TTL throwaway default. Every item below is opt-in and must leave
these intact; any item that cannot is rejected or redesigned.

## Items (from the change request), mapped to the tree

### 1. Service-class VMs -- reaper exemption + quota          [Required; MEDIUM risk]
- **DECIDED (operator, 2026-07-11): no-TTL, not renewable-TTL.** A missed renewal would kill exactly the asset the
  class protects (a logged-in messenger session). Reaper skips `class=service`; the per-account quota
  (default 3, fleet.json) bounds leak risk; owner `destroy` (or operator administrative destroy) is the
  only exit.
- **Hard requirement -- no-TTL needs an account-retirement invariant + quota-occupancy rule.** Ownership
  is a numeric OS uid; a no-TTL VM outlives everything. The architecture MUST define:
  (a) **Retirement:** removing an OS account does NOT stop its running service VMs or their egress, and a
  reused uid would INHERIT authority over those VMs and their owner-scoped snapshots. So account teardown
  is an **operator procedure** (INSTALL-RUNBOOK): destroy or explicitly transfer all `class=service` rows
  + dependent artifacts BEFORE deleting/reusing the uid. Removing `drvpsvc` membership blocks NEW service
  creates but does NOT reap existing ones -- state this.
  (b) **Quota occupancy:** the quota counts **every persisted `class=service` row until successful
  destroy -- including `pending` and `broken`** -- else repeated failed creates accumulate resources
  under the cap. (Broken service VMs are the operator/owner's to destroy; they still occupy a slot.)
  (c) The absolute consumer promise "ends only on YOUR destroy" becomes "ends on owner destroy OR
  operator administrative destroy (account teardown / policy)".
- Touches: store schema (new `class` column, default `throwaway`), `dr_vps_reaper.sh` +
  `bin/drvps-rigreaper` (skip service), watcher (`--class` validation: requires `drvpsvc` membership +
  quota check at create/use), `bin/rigctl` (flag plumb), `list/status/inspect` output.
- **S1 hard requirement surfaced by review: owner-scope VM MUTATIONS.** Today only snapshots + detached
  jobs are owner-scoped; VM verbs act by id with NO ownership check (a co-tenant could `destroy` the
  orchestrator's driver VM), and `list` is global. Multiuser service plane is unsafe without it: stamp `owner_uid`
  on VM rows (store schema, part of S0) and enforce owner==caller on destroy/recreate/exec/exec-detach/
  push/pull/snapshot/console-dump for ALL VMs (not just service class -- same grain as snapshots).
  Reads (`list`/`status`/`inspect`) may stay global (ids/names are not secrets); decide at plan time.
  Severity note: foreign `exec`/`pull` on a driver VM = reading a logged-in messenger session -- worse
  than destroy. Id secrecy is NO mitigation: `list` is global AND ids are deterministic
  (sha256(name+project), dr_vps_identity.sh). **Operational gate: S1 ships BEFORE the orchestrator account is
  onboarded** -- until then the only mitigation is "drvpsctl stays small and trusted".
- **Sized (2026-07-11): small-to-medium -- a PORT of the proven snapshot mechanism, not new design.**
  The plumbing already exists end-to-end: the ingress stamps the kernel-verified (SO_PEERCRED) uid on
  every request, the watcher computes `owner_args`, `dr_vps_resolve_snapshot` is the enforcement
  template, and two VM verbs (`snapshot`, `exec-detach`) already parse `--owner`. ~130-160 production
  LOC across 4 files; tests are the bulk (~12-15 bats cases, templates in snapshot.bats). Enforcement
  lives in dr-vps itself -- below the watcher's destroy/status/inspect gate bypass, so no gate rework.
  Legacy rows (`owner_uid` NULL): **NULL = operator-only (matches snapshots), NOT a client wildcard**
  (the plan review caught grandfather-as-wildcard as a real hole). Cutover DRAINS agent throwaway VMs
  (mandatory TTL -> reap in hours) before enabling enforcement, so no agent loses a wanted VM and every
  post-cutover NULL row is operator-created. Execution shape: prove on `destroy`, then sweep the
  remaining verbs in one fold with a full callsite grep; each verb resolves -> per-VM lock -> revalidate
  owner under lock (TOCTOU). Step-level detail incl. fail-closed set + `--owner` plumbing +
  fleet-hash-safe S0: implemented (the stage plan was folded and removed at release).
- Schema change ships as its OWN no-op stage first (rename-as-its-own-stage): column + default backfill,
  zero behavior change, then the feature stage.

### 2. Per-VM egress profiles -- dnsmasq -> nftables set      [Required; HIGH risk -- ARCH MUST-gate]
- The confinement boundary changes: from "deny-all, one static allow-list" to "per-VM, per-profile
  dynamic sets". Design core: guests already use rig DNS; dnsmasq `--nftset` writes resolved A/AAAA of
  allow-listed domains into a per-VM nft set; forward chain allows guest -> set on tcp/443 ONLY;
  udp/443 (QUIC) blocked by default with per-profile override. No `--egress` = today's behavior,
  byte-identical.
- **Design constraint -- the boundary this delivers is IP-EQUIVALENCE, not hostname.** dnsmasq/nftset
  authorizes destination IPs, so (a) a guest can hardcode any IP currently in its set (DNS is not on the
  authorization path), and (b) a shared-CDN IP transitively authorizes EVERY TLS vhost at that IP. The
  IP-equivalence boundary is still a strong, useful fence (no arbitrary internet, no other guests, 443
  only) and is what S3 ships FIRST -- but the external contract must state it honestly as
  IP-equivalence, NOT "these domains and no other host". **True domain granularity requires the SNI gate
  (sniproxy in front of the profile's 443, matching TLS SNI); that is now a NAMED S3 sub-decision the
  operator makes at the S3 ARCH gate (build-now vs accept-IP-equivalence-for-v1), not a deferred
  optional.** The nft hook is reserved so SNI can slot in with zero guest changes.
- **Hard requirement -- unspoofable per-VM selector.** Today there is no per-VM source-IP
  anti-spoof rule (`dr_vps_net.sh:27-31`) and a DHCP reservation is NOT enforcement -- an untrusted guest
  can set another source address and borrow a co-tenant VM's egress set. S3 MUST pin per-VM identity to a
  trusted property: a libvirt `nwfilter` (clean-traffic / MAC+ARP+IP anti-spoof) per NIC, and dispatch
  the per-VM chain on the tap interface / verified source, never on a guest-settable field.
- **Hard requirement -- expiry + revocation + reassert model.** `--nftset` only INSERTS; the
  design must (a) use timeout-capable sets so an element expires with DNS TTL (no stale-IP authorization
  after reassignment), and (b) define how a LIVE VM loses reach when the operator removes a domain /
  profile / account registration. The existing per-VM `egress_gen` column is INFORMATIONAL only
  (`dr_vps_store.sh:52-56`) -- it is NOT the authority and does not revoke; the enforced authority is the
  root `/run` marker vs fleet-hash (`dr_vps_net_create_guard`). AND: the root reassert timer atomically
  deletes+recreates `table inet drvps_sim` (`dr_vps_net.sh:56-60,121-123`); putting learned sets in that
  table would wipe them each reassert. S3 MUST specify the reconciliation: either learned sets live in a
  separate, reassert-surviving table with their own repopulation, or the reassert repopulates from a
  durable per-VM profile binding. Revocation = drop the VM's set membership on profile/registration
  removal, enforced at the next reassert AND pushed immediately.
- Profile registry lives in `etc/fleet.json` (already the operator-owned inventory; extend, don't fork):
  `egress_profiles: { name: { domains: [...], quic: false, users: [...] } }`. Per-ACCOUNT binding is part
  of registration (hybrid model). A live binding change must trigger the revocation/repopulation path above.
- Touches: `dr_vps_net.sh` (dnsmasq conf + nft sets + anti-spoof nwfilter + reassert reconciliation),
  `dr_vps_netgroup.sh`/`dr_vps_gate.sh` (per-VM chain on trusted selector), watcher (profile validation),
  fleet.json schema, doctor checks.
- **Prove-core-first:** implement ONE profile (an example messenger backend) end-to-end on dev, live-verify
  reach/deny/QUIC-block/mirror-proxy-unaffected AND the three r1 additions (spoofed-source blocked;
  set element expires on DNS TTL; live revocation cuts a running VM), THEN generalize. Live testing on
  dev is part of the stage (net/kernel code -- offline-green is not evidence).

### 3a. Stable guest IP across recreate                        [Required; MEDIUM risk]
- Identity is already derived from name+project only (`dr_vps_identity.sh` -- lease/overlay/ttl never
  feed it), so the substrate exists: pin a DHCP host-reservation (MAC or client-id -> IP) to the VM id at
  create; recreate reuses it; destroy releases it. Expose `guest_ip` in `inspect` (machine-readable).
- Touches: `dr_vps_identity.sh`, `dr_vps_net.sh` (dnsmasq host reservations), `dr_vps_domain.sh`
  (recreate path), inspect output, doctor.
- **Hard requirement -- VM identity is globally squattable; owner-scoping does NOT fix it.** id =
  sha256(name+project), project fixed to `agent` (`drvps_rigctl.py:153-154,212-213`), owner_uid NOT in
  the namespace. A co-tenant can pre-create a predictable name (`ch-<id>`), occupy the global VM id, and
  make the orchestrator's create/use fail with a conflict -- and post-S1a it cannot destroy the squatter,
  turning authz hardening into a durable name-denial primitive. **S2 MUST namespace VM identity by owner:
  fold owner_uid into `dr_vps_instance_id` (or an operator-registered name-prefix per account), so
  `ch-<id>` owned by A and by B are distinct ids and neither can claim the other's.** Decide
  owner-in-hash vs prefix-allocation at the S2 plan; the architecture commits to "no cross-owner name
  claim". Note this makes id owner-dependent -- inspect must still return the actual id for the caller.

### 3c. Owner-aware RUNTIME-plane boundary                     [Required; HIGH risk -- ARCH-relevant]
- **Design constraint -- S1a scopes only the CONTROL plane; the runtime plane stays cross-tenant.** The
  nft fence has input+forward hooks but NO output hook (`dr_vps_net.sh:60-77`), so host-initiated traffic
  is unfenced: another unprivileged rig account can connect DIRECTLY to another owner's driver
  `http://guest_ip:PORT` / noVNC without ever touching the watcher. Global `inspect` makes discovery
  easy, but hiding ids would not stop subnet scanning. This directly undermines the S1a "guest-read
  protected" claim the consumer contract makes.
- **Requirement: an owner-aware runtime boundary MUST land before S2 exposes direct guest_ip HTTP as a
  supported interface AND before orchestrator onboarding.** Options to decide at plan time: (a) an nft OUTPUT
  hook that permits host->guest_ip:PORT only from the owning uid (packet owner match), (b) a per-owner
  reverse proxy / unix-socket front so the orchestrator never dials guest_ip directly, or (c) mandatory
  app-layer auth on the guest listener, stated in the external contract. Until one lands, the consumer guide
  must NOT present direct guest_ip HTTP as a private/supported interface.
- Touches: `dr_vps_net.sh` (output hook / owner match), possibly a small proxy; inspect/contract wording.

### 3b. Registered service ports (guest->host callbacks)      [Required; MEDIUM risk]
- Generalize `simulated_allow.mock_ports` into named, operator-registered entries (e.g.
  `service_ports: { svc-callback: { port: 443, users: [...] } }`); keep `mock_ports` as a
  validate-and-keep legacy alias for one release. Guest default remains proxy + registered ports only.
- Touches: fleet.json schema, `dr_vps_net.sh` rules, doctor, docs.

### 4. Idempotency keys on mutations                           [Required; MEDIUM risk]
- Watcher-side journal keyed `(owner_uid, idem_key) -> reqid + recorded result | in-progress`; on hit,
  replay the recorded envelope instead of executing. Applies to create/use/recreate/destroy/snapshot/
  snap-rm. Journal is spool-resident, GC'd with results; keys are a crash-recovery window, not a ledger.
- Touches: watcher (journal + lookup before dispatch), `bin/rigctl` (`--idem` flag on the six verbs),
  spool GC, AGENT-GUIDE/ORCHESTRATOR-GUIDE (retire the reconcile-by-type dance to "fallback" status).
- **Hard requirement -- ordering alone CANNOT recover an execute-before-record crash.** A watcher-side
  journal cannot infer a result after the side effect already happened: today the shape is
  received/claimed -> execute -> record result (`drvps_rigctl.py:768-774`); a crash between execute and
  record leaves only "in-progress", and replay risks a DUPLICATE mutation while refusal leaves it
  permanently indeterminate. No write-ordering removes that. So the honest contract is: an idem hit
  returns the recorded result if one exists, else an explicit **INDETERMINATE** (not a blind "in-progress
  that will resolve") -- and for INDETERMINATE the caller MUST fall back to reconcile-by-type. `--idem`
  collapses the COMMON ambiguity (lost ack / queue timeout / duplicate submit of a not-yet-run op) into
  "safe to retry with the same key"; it does NOT promise every retry reaches a definitive recorded
  outcome. Reconcile-by-type therefore stays a REQUIRED fallback, not a deprecated path. (A stronger
  per-verb recoverable-state design -- e.g. create keyed on the deterministic VM id so replay is a lookup,
  not a re-create -- can upgrade specific verbs later; not required for S4 GO.) The consumer contract
  wording is corrected to match.

### 5. Same-user keep-secrets restore for service VMs         [Optional; HIGH risk -- ARCH MUST-gate]
- Relaxes a deliberate refusal (secret-bearing snapshot as a base). Conditions: snapshot owner == caller
  AND target class == service AND explicit `--restore-secrets` ack. Throwaway restore stays refused.
- Operator has pre-accepted the fallback: if the design review finds it against the tool's grain,
  DEFER -- disaster recovery = re-QR. (Originally sequenced LAST, after 1-4; the operator later
  approved landing it GATED ahead of the held S2/S3 -- the live identity probe removed the isolation
  prerequisite's force. Decision record: docs/CONCEPT-S6-SECRETS-RESTORE.md.)

### 6. Private result store                                    [Optional; LOW risk]
- Per-owner 0700 subdirs under results/ (or owner-only 0600 files + group-listable dir), watcher fchmod
  change + rigctl path change + GC. Removes the co-tenant caveat from both guides (sync both, same pass).
- Cheap, contained; schedule early-ish since a production orchestrator execs routinely.

## Staging (top-down: cross-cutting first)

| Stage | Content | Gate |
|---|---|---|
| S0 | fleet.json schema extensions + store `class` + `owner_uid` columns + `drvpsvc` group plumbing -- all NO-OP (nothing reads them yet) | plan review |
| S1a | VM owner-scoping enforcement on mutations + guest-reads (port of the snapshot mechanism) | code gate; **ships BEFORE orchestrator onboarding** |
| S1b | #1 service class + quota + reaper exemption | code gate + reaper live smoke |
| S2 | #3a stable IP + **owner-namespaced identity**; #3b service ports; **#3c owner-aware runtime boundary** (HIGH) | **ARCH-relevant** (3c) + code gate + live smoke; 3c + identity land BEFORE orchestrator onboarding |
| S3 | #2 egress profiles: IP-equivalence fence + anti-spoof nwfilter + expiry/revocation/reassert, ONE profile end-to-end, then generalize; **SNI-vs-IP-equivalence operator decision at this gate** | **ARCH MUST** + code gate + live dev verify |
| S4 | #4 idem keys | code gate |
| S5 | #6 private result store | code gate |
| S6 | #5 secrets-restore (or documented deferral) | **ARCH MUST** |

Landed stages: S0/S1 (service class + quota), S4 (idempotency), S5 (private result ACLs), S6 (gated secrets-restore) -- live-verified on the nested harness. S2 (stable IP/service ports) and S3 (egress profiles) remain HELD/PROPOSED (STATUS.md). The stage plans were folded and removed at release.

Rationale: S1/S2 unblock the orchestrator's biggest integration surface (long-lived VM + stable address +
callbacks) while S3's ARCH review runs; #4 kills the retry dance before production load; #5 was
sequenced last as a security relaxation (later landed gated ahead of the held S2/S3 -- see its
decision record). Operator account creation (the service account, groups) is an
operator-side runbook step, never installer-automated (no-account-provisioning).

## Documentation rules for this plane

- The consumer guide stays PROPOSED-marked until each feature lands; on landing, flip its table row, and
  extend `tests/agent-guide.bats`-style drift guards to the new flags (guide fenced-block <-> rigctl
  case labels <-> watcher allowlist) so docs are code-checked from day one.
- Single source of truth: verb reference = AGENT-GUIDE; service-plane contract = ORCHESTRATOR-GUIDE;
  internal design = this file; operator runbook additions = INSTALL-RUNBOOK. No fact in two places.

## Deferred (visible, deliberate)

- Team/shared ownership of a VM across OS users.
- SNI gate (sniproxy) behind a profile -- insertion point reserved in S3, not built.
- Renewable-TTL service variant -- rejected in favor of no-TTL+quota (revisit only on quota pressure).
- Discovery verb for "what am I registered for" (profiles/ports/quota) -- nice-to-have, post-S4.
