# distro-rig-vps -- service orchestrator guide

**Status: DRAFT v0.5 (2026-07-11) -- a PROPOSED contract.** Rows marked SHIPPED work today exactly as
written. Rows marked BUILT are implemented and offline-tested with FINAL syntax/shapes, but not yet
deployed to the rig (and, where noted, gated behind an operator policy that ships OFF). Rows marked
PROPOSED are the agreed target you may build against, but flag syntax/field names can still shift until
each lands.

Audience: the developer of a long-lived service orchestrator (e.g. a messenger-bot fleet manager). This is the complete external contract; you never
need drvps internals, and nothing here depends on them.

| Feature | Status |
|---|---|
| Throwaway VM provisioning (full `rigctl` verb set) | SHIPPED |
| Result envelope + exit-code contract (below) | SHIPPED |
| Timeout/INDETERMINATE reconcile rules (interim) | SHIPPED |
| Service-class VMs (`--class service`, no auto-reap, quota) | BUILT (pending rig deploy) |
| Owner-scoping of VM operations (see Identity) | BUILT (pending rig deploy) |
| Per-VM egress profiles (`--egress <profile>`) | PROPOSED |
| Stable guest IP (survives `recreate`) + `inspect` field | PROPOSED |
| Guest->host registered service ports (callbacks) | PROPOSED |
| Idempotency keys (`--idem <key>` on mutations) | BUILT (pending rig deploy; syntax + response shape FINAL) |
| Private per-account result store | DEFAULT (cross-uid deny live-verified on the project harness; `dr-vps doctor` re-probes ACL support per host) |
| Same-user secrets-restore for service VMs (`--restore-secrets`) | BUILT (GATED: ships OFF; operator opt-in after live verify) |

## Identity and access

The orchestrator runs as ONE dedicated OS service account on the rig host. Run every worker process
under this one account; drvps never sees your internal process structure.

**Owner-scoping -- what is private to your account:**
- SHIPPED today: your **snapshots** and **detached exec jobs** are account-scoped -- other accounts
  cannot list, read, or act on them (theirs resolve to not-found for you, and vice versa).
- NOT yet: **VM records are not private today.** `list` shows every account's VMs, and VM operations
  address a VM by id without an ownership check. On the current rig, do not treat co-tenants as
  untrusted for VM lifecycle.
- BUILT, pending rig deploy (part of the service plane): ownership checks extend to VM **mutations and
  guest-reads** (destroy/recreate/exec/push/pull/console-dump/snapshot) -- another account's attempt on
  your VM resolves to not-found. Listing/metadata reads (`list`/`status`/`inspect`) stay global: treat VM
  ids and names as visible to co-tenants (non-secrets); it is the guest CONTENT and lifecycle that get
  protected. **Sequencing promise: this lands before your account is onboarded to the rig** -- by the
  time you integrate, your driver VMs are owner-protected.

Access is two-layered (both required; the service-group + quota layer is BUILT pending rig deploy,
per-capability registration ships with each capability):
1. **Group** -- your account joins the base rig group (all provisioning) plus a higher service group that
   unlocks the ABILITY to request service-class VMs and opt into egress/ports.
2. **Registration** -- each concrete capability (a named egress profile, a callback port, your service-VM
   quota) must additionally be registered for you by the operator. Group membership alone opens nothing
   outward.

You have NO sudo, no hypervisor device, no host filesystem inside guests, and no way to change network
policy yourself. Anything not listed here is the operator's job -- ask, don't work around.

## The two planes (the one rule that shapes your design)

- **Provisioning plane** = `rigctl` (create/use/destroy/snapshot/exec/push/...). Requests are processed
  ONE AT A TIME rig-wide; a lifecycle op can take minutes and yours can queue behind another. Use it to
  build, reset, checkpoint, and tear down driver VMs.
- **Runtime plane** = plain HTTP on the rig bridge: your api talks to a driver at
  `http://<guest_ip>:<port>` directly, and the guest calls back to host-registered service ports
  (PROPOSED). This path involves no rigctl and does not queue.

**Never put rigctl on the message path.** If a design needs a rigctl call per chat message, the design is
wrong; rigctl is management-only.

## SHIPPED: the provisioning surface

The full verb reference (arguments, per-verb notes, snapshot semantics) is the agent guide,
`AGENT-GUIDE.md`, which ships alongside this document -- it is the single source of truth for verbs and
is drift-tested against the implementation. Contract points that matter for orchestrator CODE:

### Result envelope -- parse it, never trust exit 0

Most verbs print a JSON result envelope and exit **0 even when the operation failed**. Branch on the
envelope, not the exit status:

| Envelope | Meaning | Retry rule (mutations) |
|---|---|---|
| `status:"ok"`, `exit_code:0` | success | -- |
| `status:"ok"`, `exit_code:` nonzero | op ran and failed (message in `stderr`) | fix cause, then retry is safe only if the op didn't partially apply -- treat like timeout below unless the error clearly precedes execution |
| `status:"rejected"`, `reason:...` (no `exit_code`) | refused BEFORE execution | safe: fix and re-issue |
| `status:"timeout"`, `exit_code:124` | op started, killed at the server-side limit | may be PARTIALLY applied -> reconcile first |
| `status:"preempted"`, `exit_code:130` | op started, cancelled by a newer request | may be PARTIALLY applied -> reconcile first |
| `status:"error"`, nonzero `exit_code` | rig-side failure while handling the op | may be PARTIALLY applied -> reconcile first |
| `status:"indeterminate"`, `exit_code:1` | `--idem` only: the prior attempt with this key was interrupted mid-execution; outcome unknown | reconcile by type, then retry with a FRESH key |
| anything else / unparseable | unknown | FAIL CLOSED: treat as indeterminate, reconcile first |

Catch-all rule: any envelope other than `ok`/`rejected` may mean the operation partially ran --
reconcile before retrying a mutation. Only `rejected` (and `ok`) are conclusive.

Exceptions to "exit 0 + envelope": `pull` streams raw file bytes (exit 0 only on a genuine transfer,
1 on failure), `console-dump` prints sanitized text (same rule). Client exit **2** = usage error or
submit failure (below); **17** = the client gave up waiting for the result.

On success, `create` returns the new **VM id** in the envelope's `stdout` field -- capture it; every
later verb (`exec`, `push`, `snapshot`, `destroy`, ...) takes the id, NOT the name you passed to create.

### Submit failures (exit 2) -- three different retry rules

| Message | Meaning | Retry |
|---|---|---|
| `could not reach the submit socket` | NOT submitted | safe to re-issue once access/service is fixed |
| `submit refused: <reason>` | validated and REFUSED before enqueue | safe: fix the reason, re-issue |
| `submit acknowledgment lost after sending` / `unexpected submit response` / `submit failed (rc=N)` | INDETERMINATE -- may be enqueued | reconcile before re-running a mutation |

### Timeouts (exit 17)

The client waits `RIGCTL_TIMEOUT` seconds (default 360; lifecycle ops can legitimately run ~15 min, so
raise it or poll). Exit 17's stderr says whether processing had *begun* -- but BOTH variants are
indeterminate for mutations. Reconcile by type: lifecycle via `list`/`status`, snapshots via `snap-ls`,
exec/push by checking the effect in-guest. `--idem` (BUILT, pending deploy) SHRINKS this dance -- it makes the common
ambiguous cases safe to retry -- but does NOT remove it: an execute-before-record crash still resolves to
INDETERMINATE and needs reconcile-by-type. Keep the reconcile path in your retry wrapper; idem-keys layer
on top of it, they do not replace it.

### Limits and privacy

- **Numeric limits** (current fixed values): ttl 1-8760 h, mem 256-16384 MB, cpus 1-8. Over-limit = a
  clear pre-execution refusal.
- **Result privacy:** the rig's DEFAULT is the private result store (below) -- your result payloads
  are readable by your account only. If the operator runs the legacy opt-out
  (`DR_VPS_RESULT_PRIVATE=0`), result payloads are readable by other rig accounts for a retention
  window -- confirm the mode before moving secrets through `exec`/`pull` output.

## BUILT (pending rig deploy): service-class VMs

```
rigctl create <name> <distro> --class service [mem] [cpus]
rigctl use <name> --from-snap <snap-id> --class service [--mem M] [--cpus N]
```

- **Contract: a service VM is never auto-reaped; it ends on your explicit `destroy` OR an operator
  administrative destroy** (account teardown or a policy action -- rare, operator-initiated). (How the
  rig implements non-reaping internally is not part of the contract and needs no action from you.)
  A `pending` or `broken` service VM still occupies a quota slot until destroyed. Everything else
  (exec, push/pull, snapshot, recreate, destroy) behaves identically to a throwaway VM.
- Per-account service-VM **quota** (operator-set; default 3). Over-quota create/use fails with a clear
  pre-execution refusal and creates nothing -- treat quota-full as a capacity signal, not a retry case.
- `list` / `status` / `inspect` expose the class machine-readably.
- Omitting `--class` keeps today's behavior exactly: throwaway, mandatory TTL, auto-reaped. Design your
  fleet so anything disposable stays throwaway -- service slots are scarce by design.

## PROPOSED: egress profiles

```
rigctl create ... --egress <profile-name>     # e.g. --egress example-messenger
```

- A profile is an operator-registered, named domain allow-list. You can only select profiles the operator
  registered for your account; you cannot define, edit, or widen one.
- Semantics with a profile: the guest can reach the allow-listed domains on **tcp/443 only** (QUIC/udp-443
  blocked by default -- browsers fall back to TCP; a per-profile operator override exists), PLUS the
  standard package-mirror proxy and registered service ports. No arbitrary internet, no other guests, no
  other ports. Without `--egress`, today's deny-all stands.
- **Boundary granularity (v1): IP-equivalence, not strict hostname.** The fence authorizes the resolved
  IPs of the allow-listed domains. Consequence to design around: if an allow-listed domain shares a CDN
  IP with other TLS sites, those sites become reachable at that IP too. Strict per-hostname enforcement
  (SNI gating) is a planned operator upgrade. Do not rely on domain-exact isolation for security-critical
  separation in v1; treat the profile as "this domain set's CDNs and whatever else lives on their IPs".
- `status` exposes `egress_gen`, a generation counter that bumps when the operator edits policy. If you
  see it change for a live driver VM, re-run your connectivity health check.
- Ask the operator for a profile per messenger platform (domains + CDN domains). Expect first-contact
  failures to be missing CDN domains -- report the blocked domain, don't retry-loop.

## PROPOSED: stable addressing + callbacks

- **Host->guest:** every VM gets a stable IP tied to the VM id, exposed machine-readably in
  `rigctl inspect` (field: `guest_ip`). It SURVIVES `recreate` -- reset a wedged driver and your channel
  config keeps working. It is NOT guaranteed across destroy+create (with `--idem`, a retried create is
  the SAME request, so the address holds).
- Direct HTTP from your api to `http://<guest_ip>:<port>` on the rig bridge becomes a **supported
  interface** (today it happens to work but is unspecified -- do not ship against it until this lands).
  It becomes supported only once the owner-aware runtime boundary lands (until then, a co-tenant on the
  rig could reach your driver's guest_ip directly -- the operator keeps untrusted accounts off the rig
  until that boundary + owner-scoping are in place, which is guaranteed before your onboarding).
- **Guest->host:** the operator registers named host-side service ports (e.g. the host nginx that fronts
  your callback endpoint). Guests reach ONLY the proxy + registered ports; your api port itself is never
  directly reachable from guests -- callbacks go guest -> host nginx -> api.

## BUILT (pending rig deploy): idempotency keys

```
rigctl create ... --idem <key>      # also: use, recreate, destroy, snapshot, snap-rm
```

- Re-submitting a mutation with the SAME key + the IDENTICAL command returns the recorded outcome of the
  first execution instead of executing again. Keys are scoped to your account (another account's
  identical key never collides with yours). Key charset: 1-64 chars of `[A-Za-z0-9_.-]`.
- **Machine-readable shapes (final):**
  - *Replay*: the first execution's recorded envelope, re-addressed to your retry's reqid, plus
    `idem_replayed:true` and `orig_reqid:"<first reqid>"`. Branch on `idem_replayed` if you need to
    tell a replay from a fresh run.
  - *Crash window*: `status:"indeterminate"`, `exit_code:1`, explanation in `stderr` -- the prior attempt
    was durably accepted but left no completion record, so it may or may not have started, and its outcome
    is unknown. Reconcile by type (above), then retry with a FRESH key. A queued retry never sees this for
    a merely slow first attempt -- requests are processed one at a time, so your retry waits and then
    replays; `indeterminate` specifically means a prior attempt with no recorded completion.
  - *Key misuse*: the same key with a DIFFERENT command body is `status:"rejected"` (reason names the
    body mismatch). A retry must resend the byte-identical request; never reuse a key for a NEW intent.
- **Retention:** a key survives for the 24 h TTL (operator-tunable); after expiry a re-submitted old key
  re-EXECUTES rather than replaying. Keep retry windows short (minutes, not hours). Your account also has
  a generous per-account key quota (keys are scoped and counted per account, so another account's churn
  can never evict yours); if you ever exceed it, a NEW keyed mutation gets a clear `status:"error"`
  naming the quota -- retire old keys, wait for TTL, or retry that one command without `--idem`.
- Intended use: on ANY ambiguous outcome (timeout, lost ack, crashed worker) re-issue the identical
  command with the identical key. This makes the COMMON case safe (the op had not yet run, or its result
  was recorded) -- you get the recorded result or a clean re-run. It does NOT guarantee every retry
  reaches a definitive recorded outcome: if the rig crashed AFTER executing but BEFORE recording, the key
  resolves to the explicit **indeterminate** above, and you MUST fall back to reconcile-by-type for that
  case. So keep the reconcile-by-type path -- `--idem` shrinks it, doesn't remove it. Use a durable
  per-intent key, e.g. `create-<channel-id>-<epoch>`.

## Private result store (the DEFAULT)

Result payloads are private to the issuing account. Each result file (and its claimed marker) is
written `0600` owned by the driver, with a POSIX ACL granting ONLY your account read -- a co-tenant in
the shared spool group cannot read your `exec`/`pull` output. This needs the spool filesystem mounted
with `acl` support (the watcher's launcher and `dr-vps doctor` verify it, fail-closed). No
orchestrator-side change. A rig may run the legacy group-readable opt-out (`DR_VPS_RESULT_PRIVATE=0`);
confirm with the operator.

## BUILT (GATED -- ships OFF; operator opt-in): secrets-restore for service VMs

```
rigctl use <name> --from-snap <secret-snap-id> --class service --restore-secrets [--idem KEY]
```

Restores YOUR OWN `--keep-secrets` snapshot (a logged-in session) into a NEW service-class VM -- the one
exception to the standing "secret-bearing snapshot is refused as a base" rule. ALL of the following must
hold, or the request is refused with a clear pre-execution error (nothing is created):

- the **operator has enabled the rig policy** (it ships OFF; until the operator turns it on -- after the
  live verification -- every secrets-restore is refused, and that refusal is correct behavior, not a bug);
- the snapshot is **yours** (owner == caller; a co-tenant's snapshot resolves to not-found as usual);
- the target is **`--class service`** (throwaway restores stay refused);
- the command carries the **explicit `--restore-secrets` ack**;
- **1:1 replace rule:** NO VM record of yours -- in ANY state (running, pending, broken, mid-destroy)
  -- still derives from that same snapshot; restore is a REPLACE, not a clone fan-out. The old VM's
  `destroy` must have COMPLETED (the record removed), not merely been issued, before the restore is
  admitted. At most ONE VM per secret-bearing snapshot is what contains machine-id / host-key
  duplication on the network.

Disaster-recovery flow (destroy-then-restore -- the intended use):

```
rigctl destroy <old-vm-id>                        # the wedged/lost driver: frees the 1:1 slot + a quota slot
out=$(rigctl use ch-<id> --from-snap <secret-snap> --class service --restore-secrets --idem restore-<id>-<epoch>)
vmid=$(printf '%s' "$out" | jq -r 'select(.status=="ok" and .exit_code==0).stdout' | tr -d '[:space:]')
rigctl wait "$vmid"
# health-check the driver session; if the platform invalidated it anyway, fall back to re-QR
```

Until the operator enables the policy, plan for disaster recovery = re-login (re-QR). What a restore
actually preserves (live-verified 2026-07-12): the guest's **device identity (machine-id)** and all
**on-disk state** -- i.e. a device-bound logged-in session survives. The guest's **ssh host keys are
regenerated** on restore (a new cloud-init instance), so restored VMs never share a host key; the only
reused identity is machine-id, which is exactly why the restore is **1:1** -- never design around
restoring one secret snapshot into two live VMs (the rig refuses the second, and two live VMs would
then share a machine-id). If a rebuilt session still fails to resume, fall back to re-QR.

## Recommended channel lifecycle (reference)

```
# once per driver version: build a LOGIN-FREE template (no secrets -> valid base for any restore)
out=$(rigctl create tpl fedora44 24)              # throwaway is fine for template builds
tid=$(printf '%s' "$out" | jq -r 'select(.status=="ok" and .exit_code==0).stdout' | tr -d '[:space:]')
rigctl wait "$tid"
rigctl push "$tid" driver.tar /opt/driver.tar
rigctl exec "$tid" 'tar -C /opt -xf /opt/driver.tar && /opt/driver/install.sh'
rigctl snapshot "$tid" --notes "driver vX.Y pre-login"    # snapshot BEFORE any login
rigctl destroy "$tid"

# per channel (snap id from snap-ls). NOTE: `--egress` is PROPOSED (S3) -- omit it until that ships,
# or the client dies with "unknown flag". `--class service` is BUILT-pending-deploy; `--idem` is final.
out=$(rigctl use ch-<id> --from-snap <tpl-snap> --class service --idem create-<id>-<epoch>)   # (+ --egress <profile> once S3 ships)
vmid=$(printf '%s' "$out" | jq -r 'select(.status=="ok" and .exit_code==0).stdout' | tr -d '[:space:]')
rigctl wait "$vmid"
rigctl inspect "$vmid"                            # -> guest_ip
# QR login via noVNC at guest_ip through an operator-provided tunnel; then health-check + message
# traffic = direct HTTP api <-> guest_ip; callbacks via the registered host nginx port.
# driver wedged?           -> rigctl recreate "$vmid"   (same guest_ip; session lost -> re-QR)
#   ... unless you kept a --keep-secrets session snapshot AND the operator enabled the secrets-restore
#   policy: then destroy + secrets-restore keeps the session (BUILT-gated section above).
# channel decommissioned?  -> rigctl destroy "$vmid"    (frees a service-quota slot)
```

## Invariants (never changing -- do not design around them)

- Throwaway default stays: mandatory TTL, auto-reap, deny-all egress.
- You can never grant yourself network reach, ports, quota, or privileges; only the operator registers
  capabilities. No sudo, no host filesystem in guests, no direct inbound to your api from guests.
- Goldens (base images) are operator-built; you consume them via `distros`.
- One rig-wide provisioning queue: rigctl latency is unbounded-ish; runtime traffic must not depend on it.
