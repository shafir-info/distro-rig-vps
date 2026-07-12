# S6 concept -- same-user keep-secrets restore for service VMs (ARCH-MUST, HIGH risk)

Status: design converged, BUILT, and LIVE-PROVEN (see the live resolution below); ships GATED
(`DR_VPS_ALLOW_SECRET_RESTORE` default OFF). The identity-contract sign-off is the remaining operator
decision (STATUS.md).

**Decision record.** The parent plan (`docs/CONCEPT-SERVICE-PLANE.md` #5) originally sequenced S6
LAST, "only after 1-4 are live". The operator later approved landing S6 gated AHEAD of the held
S2/S3 stages, because the live probe removed the argument for that prerequisite: the 1:1
restore=replace is enforced fail-closed (Q1), and ssh host keys regenerate on restore so the
host-key half of the collision cannot occur (Q3) -- per-owner net isolation is no longer load-bearing
for S6's risk. The sections below are the DESIGN RECORD as written before implementation (kept for
the reasoning); the "LIVE-RESOLVED" section is what actually shipped.

## The pre-S6 baseline (the refusal S6 relaxes)
- `dr-vps snapshot <vm> --keep-secrets` skips the virt-sysprep scrub, so the snapshot's `image.qcow2`
  BAKES IN identity + secrets (machine-id, SSH host keys, app creds). The store row is
  `secret_bearing=1` (`dr_vps_snapshot.sh:303,395`); the rendered `.md` LOUDLY marks it.
- `dr-vps use --from-snap <sid>` refuses a secret-bearing base unless `--allow-secret-bearing`
  (`dr_vps_snapshot.sh:634-637`), fail-closed on any non-`0` flag value.
- **Before S6 the agent could never clone a secret-bearing base:** the watcher's `use` decider did not
  thread `--allow-secret-bearing`; only the OPERATOR could, on the direct `dr-vps use` path. S6 adds
  exactly one NARROW, gated agent way in (the decider threads the flag ONLY for an explicitly-acked
  `--class service` restore; the authoritative gate stays dr-vps-side).

## Why an orchestrator wants it
A messenger-channel driver VM's whole value is a logged-in session (e.g. QR-authenticated). A `--keep-secrets`
snapshot is the ONLY way to preserve that session across a rebuild. Disaster recovery = restore the
driver's snapshot INTO THE SAME service slot so the channel keeps working without re-scanning a QR.
Today the agent can't, so the fallback is re-QR (operator-accepted).

## The relaxation (as designed and built -- narrow)
Agent path `use --from-snap <sid> --restore-secrets` succeeds ONLY when ALL hold:
1. `snapshot.owner_uid == caller` (already owner-scoped; re-verified under the per-content lock).
2. `--class service` (throwaway restore stays REFUSED -- a throwaway has no session worth the risk).
3. Explicit `--restore-secrets` ack on the request (distinct from the operator's `--allow-secret-bearing`).
4. The doctor/live-verify + external-review gates for the whole service plane are in force.

## The HARD risk (the crux for the ARCH gate)
Secret restore reintroduces IDENTITY COLLISION: two live VMs off the same secret-bearing base share
machine-id + SSH host key -> host-key warnings, machine-id reuse, and (worse) two drivers claiming the
same channel session. A `use` that can run MORE THAN ONCE is a collision FAN-OUT, not a restore.

**ARCH questions raised at design time (resolutions in the LIVE-RESOLVED section):**
- **Q1 -- how is 1:1 enforced?** Options: (a) require the prior VM of that service slot be DESTROYED
  first (restore = replace, checked under lock); (b) a per-snapshot "consumed/restored-once" marker that
  blocks a second restore; (c) bind the restore to a service-slot identity so a second restore into the
  same slot is idempotent and into a different slot is refused. Which matches the tool's grain?
- **Q2 -- is `--restore-secrets` on the AGENT path acceptable given the decider strips
  `--allow-secret-bearing` today by design?** i.e. does routing a secret-bearing clone through the
  never-root watcher (vs operator-only) cross a line the confinement model drew on purpose?
- **Q3 -- does the collision even matter for a SERVICE VM on the isolated rig net?** If a restored
  driver REPLACES the original (original destroyed) and the rig net is per-owner isolated (S2/S3), is a
  shared host key a real exposure or a non-issue within one owner's own confinement?
- **Q4 -- interaction with S1a/S2 ownership + S5 privacy:** the restored VM must be owner-stamped (like
  `use` already does) and its results ACL'd (S5); confirm no new cross-owner leak via a restored identity.
- **Q5 -- DEFER test:** if Q1-Q3 don't yield a clean 1:1 story, the operator-accepted fallback is
  re-QR. Is the orchestrator's operational cost of re-login high enough to justify the risk, or defer S6?

## Design-time recommendation (historical; superseded by the decision record above)
Build ONLY if Q1 lands on a provable 1:1 restore=replace (option (a): require the prior slot VM
destroyed, enforced under the per-content lock), AND S1-S3 are live so collisions are contained to one
owner's isolated net. Otherwise DEFER (re-QR) -- a fan-out-capable secret restore is against the grain.
Sequencing unchanged: S6 is LAST, after S1-S5 are gated + deployed + live-verified.

## LIVE-RESOLVED (two-arm identity probe on the nested harness, 2026-07-12)
The crux questions were answered by a controlled marker probe on a real `dr-vps-setup` install (fedora44,
nested KVM, real socket path):
- **Q1 (1:1) -- CONFIRMED.** Option (a) as built: restore=replace, prior VM must be destroyed. Live: a
  second live restore off the same secret snapshot is REFUSED (exit 25); the refcount is fail-closed.
- **Q3 (does the collision matter) -- LARGELY MOOT.** ssh HOST KEYS are REGENERATED on restore
  (cloud-init runs its per-instance ssh module against the seed's always-unique `instance-id`), so
  restored VMs do NOT share a host key at all -- the host-key half of the collision does not occur.
  The only shared identity is **machine-id** (keep-secrets preserves it verbatim), which the 1:1 rule
  contains to one live VM -- on the CURRENT shared rig net too (guest-to-guest L2 is port-isolated;
  the held S2/S3 per-owner isolation is NOT load-bearing for this containment).
- **What keep-secrets actually preserves:** machine-id (device identity) + all on-disk state. Note
  arbitrary app FILES survive even a SCRUBBED snapshot (virt-sysprep targets identity artifacts, not
  user data); keep-secrets' distinguishing effect is the DEVICE IDENTITY (machine-id) a messenger
  session binds its device-registration to. So "keep-secrets is the only way to preserve the session"
  holds for a DEVICE-BOUND session, which is the messenger-driver case.
- **Q4 (ownership/privacy) -- HELD as built:** restore is owner-stamped and results ACL'd (S5 verified
  cross-uid DENY live). No new cross-owner path (cross-owner secret restore refused, exit 14).
- **Q2 (agent-path secret restore) + the contract wording (is host-key preservation OUT of scope?)**
  remain an operator sign-off FORK -- the BEHAVIOR is correct and safer as-is; if host-key preservation
  were ever required it needs instance-id preservation / `ssh_deletekeys:false` on the restore seed.

## Implementation status
Built, live-verified on the nested harness, and shipped GATED default-OFF; enable/disable procedure
in docs/INSTALL-RUNBOOK.md (Step 8), current verification state in STATUS.md.
