# CONCEPT: operator-approved SPLICE egress destinations (drvpsvc self-service, squid-only apply)

Status: IMPLEMENTED in 0.3.0. This records the SECURITY DESIGN + threat model; the shipped code is
authoritative and differs in named mechanics from the original v1 sketch below: the control verbs are
`add-splice|remove-splice|list|status` (not `list-splice`); staging uses the root-owned **v2 egress
store** (EGRESS-STORE-ARCH-UPGRADE.md), not a drvps spool dir; and apply does a **full squid restart**
(fresh ssl_db -- ssl_bump changes need a real restart), not `squid -k reconfigure`. Where this concept
and the code/STATUS disagree, the CODE wins. ASCII only.

## 1. Goal + threat model
Let a drvps guest reach ONE additional egress destination that must NOT be MITM'd -- e.g. a CRM
callback host whose real TLS cert + application HMAC must stay END-TO-END. The primitive is Squid
`ssl_bump splice` (tunnel, never decrypt), distinct from the BUMPED distro mirrors.

Two trust boundaries, kept separate:
- WHO MAY REGISTER a destination = the drvps CONTROL PLANE. This capability belongs to the SERVICE
  group `drvpsvc` (not the broader VM-plane `drvpsctl`). It is a control-API authorization, NOT a
  guest-network property (Squid cannot distinguish groups on the one shared simnet).
- WHAT ACTUALLY OPENS = a ROOT, human-approved step. A drvpsvc member can only STAGE a request; a
  sudoer must REVIEW it (dry-run) and type YES before anything is spliced.

Threat model. Guests run untrusted build/agent code. A spliced host is an OPAQUE egress sink Squid
cannot inspect, reachable by EVERY guest on simnet (data-exfil surface bounded only by the
destination's own auth). Therefore: rig-wide by construction (documented, warned); registration
gated to drvpsvc; opening gated behind an operator dry-run + explicit YES; and the destination set
is hardened (canonical FQDN only, no overlap with mirrors, no internal/RFC1918 targets).

Out of scope (deferred): limiting WHICH guests reach the sink to drvpsvc-owned VMs -- that needs an
enforceable per-guest identity (Stage-2 per-group bridge/subnet, not yet wired). v1 sink is rig-wide.

## 2. Architecture (surgical: reuse, do not rebuild)
Four pieces, each reusing an existing drvps mechanism:

1. DATA -- `fleet.json` gains `splice_allowlist` (structured, additive), STRICTLY DISJOINT from
   `mirror_allowlist`. fleet.json stays the single source of truth (root:root).
2. RENDER -- `dr-vps-setup step_proxy` (the ONLY squid.conf generator) gains a splice branch. One
   renderer; the approve script reuses it, never reimplements squid.conf.
3. STAGE -- a new control-API verb `egress add-splice|remove-splice|list|status` over the EXISTING
   submit socket; SO_PEERCRED uid -> `drvpsvc` gate (mirrors `_dr_vps_service_admit`). The watcher
   (User=drvps) writes a PENDING request to a drvps-writable inbox. Self-service, opens nothing.
4. APPLY -- a NEW SIMPLE, squid-ONLY review-approve script (root/sudoer). Reads the pending inbox,
   validates, prints the allowed list DRY-RUN style, requires an explicit YES, merges approved hosts
   into `fleet.json.splice_allowlist`, regenerates squid.conf (reusing #2), `squid -k parse` then a
   FULL squid restart (fresh ssl_db; squid only; NOT nft, NOT the CA). The reaper later clears decided pending.

Privilege boundary: #3 is drvps and NEVER writes root files / squid / fleet.json. #4 is the ONLY
component that opens a sink, and only after a human YES. #4 touches squid ONLY.

## 3. Data model -- fleet.json `splice_allowlist`
```
"splice_allowlist": [
  { "host": "callback.crm.example", "port": 443 }
]
```
- `host`: exact FQDN (see sec 6 validation). `port`: integer (v1: 443 only; schema leaves room).
- Absent key / empty array => byte-identical old squid.conf (no-op). Wrong type => fail closed.
- INVARIANT: `splice_allowlist.host` and `mirror_allowlist` are DISJOINT sets (a host cannot be
  both bumped and spliced). Non-empty intersection => fail closed at render AND at approve time.

## 4. Squid policy (rendered by step_proxy when splice_allowlist non-empty)
Added lines (exact ordering matters -- ssl_bump + http_access are first-match). Each bump/splice
action binds the CONNECT DESTINATION *and* the SNI conjunctively (SNI-only lets a
mirror CONNECT with a splice SNI be spliced, and vice versa):
```
acl splice_sni ssl::server_name --client-requested callback.crm.example
acl splice_dst dstdomain -n callback.crm.example
acl mirror_sni ssl::server_name --client-requested <mirrors>   # CHANGED: add --client-requested
acl mirror_dst dstdomain -n <mirrors>                          # CHANGED: add -n (see bugfix note)
acl step2 at_step SslBump2
# internal-destination deny (SSRF / DNS-rebinding): loopback/link-local/RFC1918/CGNAT/host-mgmt/
# drvps subnets/IPv6-local -- see sec 6.3 (the LITERAL set is derived, not hardcoded)
acl drvps_internal_dst dst 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 ::1/128 fe80::/10 fc00::/7
ssl_bump peek step1
ssl_bump splice step2 splice_dst splice_sni     # splice ONLY when BOTH dst AND sni are the splice host
ssl_bump bump   step2 mirror_dst mirror_sni     # bump   ONLY when BOTH dst AND sni are a mirror
ssl_bump terminate all                          # any cross-class / bad SNI -> terminate
http_access deny !drvps_guests
http_access deny drvps_internal_dst
http_access allow drvps_connect splice_dst drvps_https
http_access allow drvps_connect mirror_dst drvps_https
http_access allow mirror_methods mirror_dst drvps_http
http_access deny all
```
Invariants this makes true: splice-dst + splice-SNI => splice; mirror-dst + mirror-SNI => bump;
any cross-class or bad SNI => terminate; a splice dst is NEVER bumped; a mirror dst is NEVER spliced.
- `dstdomain -n` = do NOT reverse-resolve an IP-literal CONNECT target; the CONNECT authority must
  itself be an allowlisted hostname. NOTE (separate approved BUGFIX): the EXISTING mirror rules lack
  `-n`, an adjacent reverse-DNS defect. Adding `-n`+`--client-requested` to the mirror ACLs is a
  flagged, tested change to current behavior -- NOT silently bundled into the splice feature.
- NON-TLS after CONNECT: emit `on_unsupported_protocol respond all` explicitly (this IS Squid's
  current default, but emitting it pins the security contract package-independently -- non-TLS bytes on
  a spliced/mirror CONNECT get a fixed response, never a fall-through). Tested (sec 9a.N).
- `http_access` AUTHORIZES on `dstdomain` (real destination), never the guest-controlled SNI (an
  existing drvps invariant); SNI is only the bump/splice selector.
- Spliced hosts are NEVER bumped => they are EXCLUDED from the CA nameConstraints hash. Adding one
  causes NO CA rotation and NO golden rebuild (a real advantage over adding a mirror).

## 5. Control verb + staging (drvpsvc)
- Transport: the EXISTING submit socket (`/run/drvps-submit.sock`, 0660 drvps:drvpsctl). Every
  drvpsvc member is also in drvpsctl, so socket access holds; the verb ADDS a drvpsvc check.
- `_dr_vps_egress_admit <uid>`: the uid is ALWAYS the SO_PEERCRED value (every socket request has one
  -- the service gate's "empty owner = operator" is NOT copied here, sec 9a.F). uid 0 = admin; else
  require `drvpsvc` membership (same `_dr_vps_groups_of` seam). Reject a missing/negative/non-integer
  uid. Fail closed.
- `add-splice <fqdn>`: validate (sec 6) -> write a pending request file to the root-owned v2 egress store's pending namespace (one immutable record per request; a REQID + the
  SO_PEERCRED uid recorded; see EGRESS-STORE-ARCH-UPGRADE.md).
  Returns the reqid. Idempotency (privacy-safe -- fleet.json stores NO owner, so never return a foreign
  reqid): a same-owner already-PENDING request returns THAT owner's reqid; adding an already-ACTIVE host
  returns an immediate caller-owned `already-active` outcome with NO reqid; likewise `remove` of an
  absent host -> `already-absent`.
- `remove-splice <fqdn>`: stage a removal request (applied by the approve script).
- `list` / `status <reqid>`: read-only, `drvpsvc`-gated (same group that may register);
  shows ACTIVE (fleet.json.splice_allowlist) + the caller's own PENDING/decided requests with their
  OUTCOME (sec 5.1).
- Staging opens NOTHING: a request sits until an operator approves it.

### 5.1 Approval OUTCOME channel (the requester learns the result)
Every request has a lifecycle the submitting drvpsvc member can observe: `pending` -> `applied` OR
`rejected:<reason>` OR `expired`. PUBLICATION SPLIT (sec 9a.C): the root approve script records a
durable DECISION keyed by REQID only (it cannot prove an inbox uid came from SO_PEERCRED); the WATCHER
-- which holds the original SO_PEERCRED-stamped ownership -- matches reqid -> owner and PUBLISHES the
outcome as an S5 private result (`0600`, drvps-owned, POSIX ACL granting ONLY that owner read; ACL set
on the temp BEFORE the no-clobber publish; retryable from the durable decision ledger). The member
reads it via `status <reqid>` / `list`; the watcher owner-scopes the read on the RECORDED owner
uid (not reqid possession). So an operator YES or a rejection (reason: bad-fqdn / mirror-overlap /
internal-dst / operator-declined / expired) is always reported back -- no silent drops.

## 6. Hardening contract -- ONE canonicalizer, shared by verb + render + approve + SSRF guard
Divergent normalization is an authorization bypass, so sec 6.1/6.2/6.3 live in ONE function reused
everywhere.

6.1 Canonical FQDN validation (replaces the current char-only mirror check):
- lowercase canonical; total length <= 253; labels 1-63; labels start/end alphanumeric, interior
  may contain hyphens; reject leading/trailing dot, consecutive dots, single-label names.
- REJECT tokens beginning with `-` (a value like `-i` could be parsed by Squid as an ACL option).
- REJECT IPv4/IPv6 literals, URL syntax, embedded ports, `*`/leading-dot parents (a wildcard turns
  one reviewed sink into an uncontrolled family), and duplicates. IDNs only in pre-converted xn--.

6.2 Set invariants: `splice_allowlist` disjoint from `mirror_allowlist` (fail closed on overlap);
no duplicate splice hosts.

6.3 Internal-destination deny (sec 4 ACL): `dstdomain` constrains the NAME, not where DNS resolves
it, so a compromised/rebinding public name could point at host/LAN. Deny loopback/link-local/
RFC1918/CGNAT/host-mgmt/drvps subnets/IPv6-local at the dst layer (belt: an nft OUTPUT fence on the
squid process is a follow-on if we want defense in depth).

6.4 SNI caveat (documented, not claimed away): `ssl::server_name` at step2 prefers client SNI but
FALLS BACK to the CONNECT target when SNI is absent. We do NOT claim "missing SNI is rejected".

6.5 Squid capability gate (DESIGN; the build-capability probe + audit line, task 1.8, is NOT yet built --
see STATUS.md): ssl_bump is documented through Squid 7; render/approve should refuse (fail closed, clear
message) on an unverified major or a build lacking ssl_bump.

## 7. Operator apply -- the SIMPLE squid-only review-approve script
`bin/drvps-egress-approve` (PYTHON; root). Squid ONLY -- it never touches nft, the CA, or VMs.
Python for structured fleet.json editing (atomic rewrite), clean tests, and to match the py
control-plane tooling (drvps_rigctl.py).
Flow:
```
drvps-egress-approve list       # dry-run: print ACTIVE + PENDING, and the exact squid ACL diff
drvps-egress-approve apply      # same review, then prompt: type YES to open the listed sinks
```
1. Read the v2 store's pending namespace; validate every entry (sec 6); durably reject any invalid (fail closed).
2. Print, DRY-RUN style: the currently-active splice hosts, the PENDING add/remove requests (with
   the submitting uid), and the exact squid.conf lines that WOULD change. Opens nothing.
   An INVALID pending entry is not silently dropped: it becomes a durable `rejected:<reason>` decision
   (step 5). A non-YES answer ABORTS and leaves every request PENDING (never a silent reject). No
   generic `--yes` in v1 (it contradicts the human-approval invariant, sec 9a.E).
3. `apply`: after re-printing the CLAIMED batch (sec 9a.B), require an explicit `YES` on stdin.
4. On YES, under the global egress lock (sec 9a.B), re-verify the baseline fleet+squid hashes, then:
   merge approved adds/removes into `fleet.json.splice_allowlist` (atomic same-FS temp+rename);
   regenerate squid.conf via the sec-2 renderer (squid-only); `squid -f <tmp> -k parse` BEFORE
   clobbering; install; then a FULL squid restart (fresh ssl_db; NOT disruption-free -- sec 9a.H -- then verify
   process health + listener). The commit spans two files + a live daemon, so it is NOT atomic: a mid-commit
   death recovers from the transaction JOURNAL, a failed step triggers compensating rollback, and a
   failed rollback surfaces an explicit DEGRADED state (sec 9a.B) -- never a silent half-apply.
5. Record a durable per-request DECISION keyed by REQID (`applied` per opened host, `rejected:<reason>`
   per declined/invalid one) into the root decision ledger; the WATCHER publishes the owner-private
   outcome (sec 5.1/9a.C). The reaper clears a decided pending entry once its decision is DURABLE. Idempotent.

## 8. Offline test plan (no internet, no live rig)
- Config-text (bats): for one splice entry assert peek<splice<bump<terminate; `dstdomain -n`; the
  splice allow carries CONNECT + exact dst + 443; internal-dst deny precedes the allows; the splice
  host is ABSENT from mirror ACLs AND the CA-hash input is byte-identical; missing/empty key =>
  byte-identical old config; wrong type / overlap / wildcard / leading-dot / IP / URL / option-like
  => fail; a parse failure leaves live squid.conf + fleet.json unchanged.
- Integration (offline) -- a RELEASE GATE, not just a unit test: a local squid on the PINNED build +
  local TLS endpoints proving splice / bump / terminate and the CONNECT-vs-SNI mismatch matrix
  (allowed CONNECT+SNI=splice; bad CONNECT=deny; bad SNI=terminate; IP-literal CONNECT=deny;
  splice-host+mirror-SNI creates no alternate path; missing-SNI falls back to CONNECT target as Squid
  documents). Config-text asserts alone cannot prove Squid's runtime CONNECT/SNI behavior.
- Verb: SO_PEERCRED uid -> drvpsvc admit (allow member, refuse non-member, admin operator); staging
  writes a pending file and opens nothing.
- Approve script: dry-run opens nothing; a non-YES answer aborts; YES applies; parse-fail rolls back;
  idempotent re-run.

## 9. Deferrals / limits (operator-visible)
- The splice sink is RIG-WIDE: every guest can tunnel to an approved host. Per-guest/owner scoping
  needs Stage-2 per-group nets (not wired) -- do NOT describe this as owner/group-scoped egress.
- Belt-and-suspenders nft OUTPUT fence on the squid process (sec 6.3) is a follow-on, not v1.
- Multi-port splice is schema-ready but v1 renders 443 only.

## 9a. Architecture hardening (folded into the shipped design)
Direction approved ("conditionally yes"); these must be IN the design before a PLAN. [v1] = build
now, [DEFER] = named follow-on.

A. SELECTOR (done, sec 4): bind dst AND sni per action; `-n`+`--client-requested` on mirror ACLs too
   (flagged bugfix). [v1]
B. APPROVAL TRANSACTION (crash/TOCTOU-safe). [v1]
   - Root-owned non-writable parent; pending dir drvps:drvps 0700, no default ACLs.
   - Watcher publishes IMMUTABLE request files atomically: reqid filename, same-FS temp, bounded
     canonical JSON, fsync, no-clobber rename/link, dir fsync.
   - Root reader: dir-relative safe opens (openat, O_NOFOLLOW), fstat regular/owner/mode/size/nlink,
     EXACT schema (reject unknown fields), fixed absolute paths, SANITIZED root env (ignore DR_VPS_*/
     PYTHONPATH/PATH/test seams under sudo).
   - `apply` CLAIMS an immutable BATCH into a root-owned review dir BEFORE printing: the bytes shown
     before YES == the bytes applied after; later requests fall to the next batch.
   - ONE global egress LOCK shared by approver AND dr-vps-setup; verify baseline fleet + managed
     squid.conf HASHES immediately before commit; a durable transaction JOURNAL for recovery if the
     process dies mid-commit; an explicit DEGRADED state when rollback itself fails (drop sec-7's
     absolute "nothing changes" -- two files + a live daemon are not atomic).
C. OWNER ATTRIBUTION: root must NOT trust the inbox owner_uid for the result ACL. Root records a
   durable decision keyed by REQID; the WATCHER (which holds the SO_PEERCRED-stamped ownership)
   matches reqid -> owner and publishes the S5 private result. [v1]
D. PURE RENDERER SEAM: step_proxy is NOT pure (CA lifecycle, ssl_db, ownership/SELinux, backup/
   takeover, service orchestration). Extract ONE root-owned side-effect-free egress model/renderer
   (Python module + CLI): load+validate the model, THE canonical FQDN fn, mirror/splice disjoint,
   deterministic squid emit, CA-hash input, SSRF host/port/method classification -- NO writes/CA/
   service/env-discovery. step_proxy calls it + keeps its orchestration; the approver calls it + only
   parse/install/restart; shell calls the CLI (no reimpl). Single source of truth for the render. [v1]
E. DECISION MODEL: approve selected reqids OR a named immutable batch; explicit REJECT + reason; a
   non-YES ABORTS and leaves requests PENDING (never silently rejected); opposing add/remove for one
   host is a surfaced CONFLICT (never fs-order/last-wins); idempotency (add active -> already-active;
   remove absent -> already-absent). Drop generic `--yes` for v1 (it contradicts human-approval) OR
   classify it procedural + audit every non-interactive invocation. [v1]
F. SUBMISSION GATE: every socket request HAS a SO_PEERCRED uid -- do NOT copy the service gate's
   "empty owner = operator" to the socket path. Reject missing/bool/string/negative owner_uid; root
   over socket = uid 0 explicit. Add per-owner + global PENDING limits, request-size, rate, expiry,
   max-active-splice count (a member must not flood the store or the operator's review). [v1]
G. ACTIVE VISIBILITY: operator sees all (ACTIVE + PENDING + submitter uids); a member sees only their
   OWN requests/outcomes + whether their exact submitted host is already active -- no enumeration of
   other owners' reqids/hosts/reasons/uids (splice hostnames are not classified rig-public). [v1]
H. APPLY RESTARTS SQUID (NOT disruption-free): the shipped approve does a FULL squid restart (fresh
   ssl_db -- ssl_bump changes need a real restart, not `-k reconfigure`), so a transient port close /
   in-flight effect. Runbook says so; approver verifies process health + listener after. [v1]
I. VERSION/CAPABILITY GATE: check the ssl_bump BUILD capability, not just the major (ssl_bump docs
   cover Squid <=7, absent in 8). [v1]
J. BASELINE-DRIFT ABORT: the approver renders the CURRENT fleet and compares to the managed live
   squid.conf; an UNRELATED drift (e.g. the observed cloud-images.ubuntu.com / cloud.centos.org
   fleet-vs-live gap) ABORTS with a SEPARATE diagnostic -- never folded into a splice YES. [v1]
K. INTERNAL-DST SET is DERIVED (block_cidrs + host_ips + fleet_public_ips + every drvps subnet +
   reserved/non-global ranges), not the literal example; test mixed public/internal A+AAAA, CNAME,
   DNS change on the pinned Squid build. [v1 derive; DEFER the belt nft OUTPUT fence]
L. REVISION INVARIANT: generated squid.conf carries a hash/generation of the canonical egress model;
   approver/setup/doctor detect a fleet<->config generation mismatch. [v1]
M. AUDIT: durable operator uid, submitter uid, reqids, batch digest, before/after model hashes,
   decision, failure/rollback status. [v1]
N. NON-TLS-AFTER-CONNECT: pin + test the behavior for non-TLS bytes after an approved CONNECT
   (don't depend on package defaults). [v1]

## 10. Decisions (operator sign-off 2026-07-13)
- DEPTH: FULL-ROBUST v1 -- build ALL of sec 9a (transaction journal, batch-claim, pure-renderer,
  full decision model, submission limits, drift-abort, revision hash, audit). No corner-cutting.
- SEQUENCING (top-down, no-op-first): Stage 0 EXTRACTS the pure renderer/canonicalizer out of
  step_proxy and proves it byte-identical (the live managed squid.conf is unchanged; a golden/parse
  test pins it) -- a pure refactor, NO behavior change, its own reviewed stage. "No-op" means it
  preserves the complete ACCEPTED-INPUT behavior, not just today's rendered file: if the new canonical
  FQDN validator (sec 6.1) is STRICTER than the old char-only check, that stricter policy is an
  EXPLICIT, separately-announced stage (with a fleet-preflight that flags any now-rejected existing
  mirror), NOT smuggled into the "no-op". Stage 1 then adds splice render + verb + approve + outcome on
  top. The mirror `-n`/`--client-requested` bugfix (sec 4) is its OWN small flagged stage between them
  (it DOES change mirror behavior -> test + announce).
- NORMATIVE PRECEDENCE: where the earlier prose (sec 5/7) and sec 9a/10 differ, SEC 9a + 10 WIN
  (they carry the converged architecture); the earlier sections are informative narrative.
- `list`/`status` is `drvpsvc`-gated (same group that may register). [sec 5]
- The approve script is PYTHON. [sec 7]
- Ship a short INSTALL-RUNBOOK.md operator+client section: the client must be proxy-aware and connect
  by the allowlisted hostname (splice keys on SNI); HTTPS_PROXY set + NO_PROXY clear; payload/HMAC stay
  END-TO-END; no CA/golden impact; the add-splice -> operator dry-run + YES -> approve flow.
