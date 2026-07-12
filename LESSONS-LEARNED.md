# distro-rig-vps — Lessons Learned

Engineering lessons from building the rig (Phase 1), the agent control loop (Phase 2), the
SSL-bump cache, multi-distro support (Phase 3), and the snapshot feature + per-client owner-scoping.
Specific to this project; each is something that cost real time or changed a decision.

Sections 12–17 are the retrospective on the owner-scoping **convergence flow** (16 general ChatGPT+Grok
review rounds + 3 dedicated race audits, ~20 real defects folded before two consecutive clean rounds),
focused on the multi-angle review method and the concurrency/race class.

## 1. Seam tests prove logic; only a real-environment run proves integration
Phase 1 was 96 seamed bats green and shellcheck-clean — and the first real-KVM run surfaced **~13
genuine issues none of the tests could reach**: squid's stock conf had no `conf.d` include (the
policy never loaded), `nft forward policy drop` killed podman/libvirt traffic, the installed
`/etc/.../env` clobbered explicit env, the recipe URL 404'd, dnf couldn't resolve under the egress
fence, `virt-customize` needed `LIBGUESTFS_BACKEND=direct` under `sudo -u`, the non-root rig
couldn't read live nft, and libvirt's dynamic-ownership chowned the golden out from under `drvps`.
**Lesson:** budget for a live shakeout as a first-class phase. "Isolated env passes, host
integration breaks" is the default, not the exception.

## 2. Measure, don't guess — un-suppress the error first
The `recreate` failure got **two blind fixes** (`qemu-img -U`, then reorder-after-destroy) on the
theory it was a file lock — because the real `qemu-img check` stderr was swallowed by `>/dev/null
2>&1`. Un-suppressing it + one 30-second diagnostic on the live (still-running) VM showed the truth:
**`Permission denied`** — libvirt dynamic-ownership had chowned the golden to `0600 qemu:qemu`. Not
a lock at all. **Lesson:** before fixing, read the actual failure; capture stderr; diagnose the live
fixture instead of re-running blind. Two wrong fixes cost more than one measurement.

## 3. A security-gate "find any bypass" review is unbounded — close the class, terminate by behavior
The guest-exec gate took **7 external review rounds**, each finding a more exotic libvirt device sub-shape:
a 2nd NIC → `<hostdev>` → `<qemu:commandline>` (a NIC invisible to `/domain/devices`) → an extra
disk → a network-backed disk → a 2nd cdrom → a non-pty serial → `<rng>` egd/udp and `<video>`
vhostuser backends. A per-device denylist is whack-a-mole against an enormous attack surface (the
domain XML). **Lesson:** switch to a **positive closed-shape proof** (a device whitelist + a broad
"no host path/connection/accel reference beyond overlay+seed" sweep) that closes the whole class at
once, and **terminate the loop by a behavior rule** — a competent reviewer never returns zero on a
big surface, so "reviewer-clean" is the wrong stop condition.

## 4. Invert the threat intuition — scrutiny belongs where input reaches the HOST
The instinct was to lock down `exec` (it runs arbitrary code — scary). The advisor inverted it:
`exec` is the **safe** verb (confined to the disposable, egress-fenced guest); `build` is the real
danger (it runs on the host BUILD plane); and the boring fields — `reqid` used as a *filename*, `vm`
flowing into `virsh` — are the host-touching holes. **Lesson:** the unrestricted-looking thing can
be safe by confinement; the mundane fields can be the real attack surface. Scrutinize by "does this
reach the host," not "does this look dangerous."

## 5. Concurrency + TOCTOU live where bash runs out — change the tool, not just the code
The watcher's security primitives — `O_NOFOLLOW`/`O_NONBLOCK` opens, `O_EXCL` atomic writes, killing
a child *process group* while *concurrently* scanning for a preempt — are not expressible in bash
(`[ -h ]`-then-open IS a TOCTOU). It had to be python. And the first preemption design killed the
in-flight op *before* claiming/validating the rescue (a peek/claim TOCTOU). **Lesson:** a concurrent
privilege daemon is a different kind of component than the pure-function shell libs around it; plan
it as one, and let the security requirement pick the language.

## 6. A "simple" requirement can surface a real infrastructure decision — validate the assumption
"Cache the official distro packages" assumed the official master served cacheable HTTP. It doesn't —
`dl.fedoraproject.org` forces `http → https`, so caching it requires **SSL-bump** (squid terminating
the guest's TLS with a CA baked into the golden), not a one-line http pin. **Lesson:** probe the
assumption (does the host serve cacheable http? does the mirror redirect?) *before* building; a
modest-sounding feature can imply MITM-ing the guest's TLS.

## 7. Build the hard core on one concrete case; generalize after it works
Fedora-only was deliberately the "mock-up" that built and proved the core (identity, overlays, gate,
agent loop, egress, cache) on a real distro. The multi-distro **family profile** model (dnf/apt/
zypper/apk) came *after*, and was bounded **because the core turned out genuinely distro-agnostic** —
a golden is a golden; the gate proves overlay/UUID/backing regardless of distro. **Lesson:** don't
build generic before the cross-cutting core works on one instance; prove it, then factor the variation
into a profile.

## 8. CONCEPT → PLAN → code, each converged externally, catches blockers before they're expensive
Every phase ran design-doc → plan-doc → code, each adversarially reviewed (two independent external reviewers) before
proceeding. It caught REAL blockers at the cheapest possible stage: at CONCEPT ("build is the host-
plane danger; drop it from the agent"); at PLAN (the watcher must be python; bind the live domain by
UUID, not name); at code (8 gateway blockers incl. only-simnet, the preemption TOCTOU, a NUL-byte
DoS). **Lesson:** an adversarial second opinion *before* committing to an approach is far cheaper
than discovering the same blocker in finished code.

## 9. Let an untrusted actor drive privilege through a fixed-verb gateway, not by granting privilege
The agent never acts on the host — it submits a validated request over a group-accessible ingress
SOCKET to a `drvps`-owned (unprivileged, never-root) watcher that executes it against a fixed verb
whitelist. Maximum freedom *inside* the disposable box (run anything in the guest, reset it), zero
host reach. **Lesson:** the clean way to give an untrusted actor power over privileged ops is a
mediated, whitelisted gateway — not adding the actor to a privileged group. (The gateway's INGRESS
matters too — see lesson 11 for why the original group-shared spool dir had to go.)

## 11. A never-root daemon cannot reclaim everything an untrusted writer can plant — take away the write
The original ingress was a group-writable spool dir the agent wrote request files into. A reviewer
proved the fatal class: the agent `mkdir`s a `x.json/` directory, fills it, `chmod 000`s it — and a
never-root watcher can neither traverse nor chmod what it doesn't own, so the poison is
un-reclaimable without root: a permanent disk/inode DoS no watcher-side code can fix. The fix was
structural, not defensive: `requests/` became `drvps`-only 0700 and submission moved to a systemd
socket (`Accept=yes` -> a thin per-connection accepter that is the ONLY writer). **Lesson:** if an
untrusted principal can create filesystem objects in a directory a never-root service must manage,
you have a design bug, not a hardening gap — remove the untrusted write path entirely (socket/pipe
ingress) instead of enumerating poison shapes.

## 10. Surface deferrals where the operator looks — and name the accumulating-unvalidated-surface risk
Phase 2, the cache/SSL-bump, and the non-Fedora distros are all built and seam-tested but **never
run on real KVM** — and each unvalidated layer stacked on the last compounds the first-contact risk.
That, plus the dynamic-ownership dependency and the Alpine `apk`-via-`exec` caveat, are stated in the
README + STATUS, not buried. **Lesson:** put limitations where the operator will see them, and when
unvalidated layers accumulate, say so loudly and push for a live run before stacking more.

## 12. Multi-angle review: the LENS is the tool — rotate it, because each angle finds a different class
Owner-scoping ran ~19 review passes, and every distinct LENS surfaced a class the others read past: a
**security/authorization** lens (r1) found the owner-forge / fail-open / idempotent cross-owner-leak gaps;
a **correctness/edge** lens (r2) found the "A's DB row exists but bundle is missing → register no-ops → B
gets A's id"; a **portability** lens (r4) caught `SO_PEERCRED` unpacked SIGNED (`3i`), so a real uid ≥ 2³¹
stamps negative and locks that client out of every verb; a **red-team / operator-readiness** lens (r7)
found a client could adopt another client's crash-orphan bundle AND that the operator had no cleanup path
for one; a **test-adversary** lens (r11–12) found real coverage gaps in code it agreed was correct; and a
**dedicated race** lens found TOCTOUs a correctness read went straight past. Tellingly, a same-bundle "do
one more final review" prompt returned GO — twice (r10, and again r11's code verdict) — while a re-framed
prompt found blockers. **Lesson:** "review it again" is not an angle; the prompt's stated THREAT MODEL is
what does the work. Enumerate the angles up front (security, correctness, failure/recovery, portability,
concurrency, test-adversary) and rotate ONE per round; "clean" means "clean under THIS lens," not "clean."

## 13. Concurrency needs a DEDICATED race angle — a general review passes straight over it
The feature reached GO from BOTH reviewers (r10) and stayed "code-clean" through r11–r12 — yet r13 found an
entire TOCTOU class: every owner-scoped verb resolved ownership BEFORE taking the per-content lock, then
acted on the content id UNSCOPED, so a delete+re-register under a different owner in the resolve→act window
let a caller delete/read/rename/clone ANOTHER owner's snapshot by (content) id. The operator then asked for
a standing **dedicated race angle**; it immediately found three MORE (rename TOCTOU, use resolve-then-act, and
a rename collision read-decide-write). Concurrency defects hide from a correctness lens because each line is
correct in isolation — the bug is in the INTERLEAVING, which only shows if you deliberately trace two threads
through every shared critical section. **Lesson:** for any code with locks / a shared DB / a shared spool /
files touched by multiple ops, run a DEDICATED race angle whose prompt enumerates every shared resource and
asks, per critical section: is the lock taken BEFORE the first read of the state it guards, and is every
decision RE-VALIDATED after acquiring it? Is every `flock` fd released on every exit path? Demand a concrete
A-does-X1,X2 / B-interleaves-Y interleaving for each finding. (Extends lesson 5: TOCTOU lives where you don't
look for it.)

## 14. Fix the CLASS, not the instance — one fail-open finding means you have several
The single most wasteful pattern in the loop: the "empty command-substitution read as no-row" fail-open
(`[ -z "$(db_read)" ]` treating an ERRORED read the same as "no row") was fixed in `create` (r5), then
RE-INTRODUCED — by me — in new code written to fold LATER findings: `snap-fsck --prune` (r8), the resolver +
`rename` (r9), and `image_delete` (r14). Four rounds, one class; the reviewer finally had to demand an
exhaustive audit of it before it was actually closed. **Lesson:** on the first finding of a recognizable
class, `grep` the whole tree for the pattern, classify each hit (safe read-only/diagnostic vs. real
fail-open), and fold them ALL at once — and when you WRITE new code during a later fold, re-check it against
every class already closed. New code is the single most common place a closed class reappears. Prefer
`x=$(cmd); rc=$?; [ "$rc" -eq 0 ] || fail` over `[ -z "$(cmd)" ]` whenever an empty read gates a destructive act.

## 15. Structured severity (MUST-FIX vs NICE-TO-HAVE) sharpens signal AND lets the loop terminate
A relentless reviewer never returns zero on a real surface — it will always suggest another test dimension
or a theoretical edge, so the "clean rounds" counter never advances (r11–r12 were exactly this: true-but-
incremental test-coverage gaps on code both reviewers agreed was correct). The fix was to make the reviewer
bucket every finding: **[MUST-FIX]** (a real code defect, or a test so vacuous a plausible regression of a
CORE invariant ships undetected) vs **[NICE-TO-HAVE]** (peripheral / already guarded), and to GO iff there is
no MUST-FIX. The very round that framing was introduced (r13), the reviewer surfaced the real TOCTOU class as
a clean [MUST-FIX], separated from the noise. **Lesson:** ask the reviewer to classify findings by severity
against a stated invariant set; it both sharpens what matters and gives an honest, non-infinite stop
condition. (Complements lesson 3's "terminate by behavior, not by reviewer-silence.")

## 16. State REACHABILITY per finding — it keeps the fold proportionate
The dedicated race audit rated create/recreate/destroy/snapshot lifecycle races and the rename/use races as
MUST-FIX — but every one was **DIRECT-OP-ONLY**: the watcher serializes all socket-client requests (one op at
a time under a global spool lock), so a co-tenant client can never interleave two ops, and rename/use/
image_delete aren't even routed to clients. Those races were reachable only via concurrent DIRECT `dr-vps`
invocations — the already-documented shared-lifecycle-lock v1 boundary. Requiring each finding to declare
"[CLIENT-REACHABLE] vs [DIRECT-OP-ONLY]" let me fix the client-reachable ones fully (rm/show under-lock
re-check) and DOCUMENT the direct-op-only ones as the accepted boundary — instead of over-building locks the
threat model never needed. **Lesson:** a race (or any defect) is only a must-fix if it's reachable under the
ACTUAL threat model; make the reviewer prove reachability, and separate "fix now" from "documented boundary,
surface to the operator" (as with the vm-lock). Note this cuts both ways — you still folded the direct-op
ones here for correctness + to reach a clean GO, but knowing the reachability made the fixes proportionate
(atomic SQL guard, not a heavyweight lock, for the not-client-reachable rename).

## 17. The two TOCTOU fix patterns: re-verify under the lock, OR make the mutation atomic
Every owner-scoped verb had the same shape — resolve-under-owner, then act-by-id — and each took one of two
fixes. For the file-touching verbs (`snap-rm`, `snap-show`, `use --from-snap`) the fix was to take the
per-content `snap-<id>.lock`, RE-RESOLVE ownership under it (fail closed on a read error or an id mismatch),
then act while STILL holding it. For the pure-DB verb (`snap-rename`) the fix was to push the guards INTO one
`BEGIN IMMEDIATE` statement: the UPDATE fires only `WHERE id=? AND owner_uid=? AND NOT EXISTS(<name==artifact
id>)`, so a cross-owner rename or a name==id collision yields `changes()=0` and is refused — no verb-level
lock needed. **Lesson:** close a resolve-then-act race either by re-validating under the same lock the
mutator holds, or by collapsing the check and the write into ONE atomic statement whose affected-row count
you verify. A lock-free "re-check just before acting" only NARROWS the window; it does not close it — and the
daemon's serialization protecting the socket path is not a license to skip the guard on the direct path.

## 18. Two-provider review survives one provider's outage — and each provider plays a different role
Across the loop, ChatGPT was the relentless discriminator (it found a real issue in nearly every round and was
the one that surfaced the TOCTOU class), while Grok was the thorough confirmer (exhaustive "here is why every
invariant holds" GOs when it ran). Grok's backend flaked often (`the turn failed`, several rounds), but that
never blocked progress: ChatGPT carried the discriminating load and Grok confirmed the design + the race angle on
the rounds it completed. Every finding was validated against the current code before folding, and every fold
was locked with a fault-injection/scenario regression test proving the fix BITES (would fail if reverted) —
which the test-adversary round then re-checked for vacuity. **Lesson:** run two independent strong reviewers
(they play complementary roles and one's outage doesn't stall you), validate every finding against the code
before folding, and pin every fix with a test that fails on the un-fixed code.

## 19. Snapshot-migration convergence + deploy (2026-07-05)

**Stateless-reviewer loops never converge -- judge by BEHAVIOR.** Chasing "2 consecutive all-GO rounds" over a
Grok+ChatGPT bundle ran 11 rounds going 5->4->4->2->4->4->2 GO (NON-MONOTONE). The reviewer is stateless: each round
re-reads the whole tree and samples a DIFFERENT subset of the many latent findings, so a GO never accumulates and
"K consecutive all-GO" is not a reachable fixed point on a large tree (same dynamic as "find any blocker"). STOP
at the first non-monotone round; terminate by a behavior fixed point -- the specific properties of the CHANGE
verified + tested + smoked. One clean STANDALONE review (scoped to the change, pre-existing hardening explicitly
=backlog) then gives a crisp verdict (Grok GO; ChatGPT one finding, fixed).

**Sweep a finding-CLASS at the SOURCE, not per-callsite.** The reviewers kept surfacing NEW instances of the same
two classes (fail-open DB reads; client-timeout/kill-mid-birth VM orphans) at sites I hadn't touched, round after
round. It stopped only when I fixed the CLASS at its source: rc-check EVERY `$(dr_vps_sql/dr_vps_store_* ...)`
decision read + check the RETURN of fail-closed helpers at every caller (export_family's callers ignored E_VERIFY
under set -uo!); and bake `DRVPS_BIRTH_TIMEOUT` into `rig_create`/`rig_use_from_snap` + in-flight markers at ALL
birth sites (scenario, on_sig, bases, preflight). Grep every callsite of the class BEFORE declaring it swept.

**Deploy gotchas (fresh uninstall+install of a code change):**
- umask-0077 checkout -> pack with `tar --mode='u=rwX,go=rX'` so dirs/bin=0755, files=0644; else after root
  extract + chown root:root the `drvps` SERVICE USER cannot traverse/exec the tree -> watcher 203/EXEC. Also add
  a dr-vps-setup mode-normalise + `runuser -u drvps test -x/-r` postcondition (twin of the SELinux relabel guard).
- `dr-vps-setup --uninstall` `rm -rf`s /var/lib/distro-rig-vps -> GOLDENS + snapshots wiped; rebuild after.
- Fresh install after uninstall hits the squid coexistence guard (uninstall restored stock squid.conf) -> re-run
  `--yes --force-squid`. The install is reentrant (user-exists ok, net redefine, state dir exists-ok).
- Build goldens AFTER the fresh install: `dr-vps build` before /etc/env exists uses DEFAULT paths -> golden
  registers into a store the installed rig never reads -> `create <distro>` fails "no greened golden" (rc 10)
  even though build returned rc=0.

**Version identity must be queryable from the control API.** A static VERSION/DR_VPS_DRIVER_VERSION ("0.1.0-dev")
in provenance does NOT distinguish old vs new builds, and rigctl has no `version` verb -- so the agent can't ask
the running watcher which build it is. That ambiguity directly caused old/new-build confusion. Add a `version`
verb returning the running version + a per-build fingerprint (sha of src/+bin/).

## 20. Snapshot scrub broke under systemd hardening -- `RestrictSUIDSGID` vs libguestfs (DR-4, 2026-07-08)

**A hardening directive on the watcher unit silently broke a whole feature, and the error pointed nowhere near the
cause.** `rigctl snapshot` failed with `supermin exited with error status 1` -- a generic libguestfs "file a bug"
message. Two dead-end hypotheses (stale appliance cache; centos9-specific image) cost time; both wrong. ROOT
CAUSE: the watcher (`drvps-rigctl.service`) set `RestrictSUIDSGID=yes`, and supermin MUST create setuid binaries
(mount, etc.) inside the appliance it builds -> seccomp EPERM -> exit 1. It failed on EVERY distro; fedora44
worked earlier only because its snapshot predated the restriction / the kernel churn that forced a runtime
appliance rebuild inside the sandbox.
- Isolation is the fast path: `libguestfs-test-tool` under `systemd-run -p RestrictSUIDSGID=yes` (fail) vs the
  other two directives only (pass) pinned the single culprit in two commands -- faster than reading logs.
- Reproduce IN THE REAL CONTEXT: the tool passed in a login shell, failed only inside the service sandbox. A
  diagnosis as root/login would have "worked" and hidden the bug.
- Hardening a service that shells out to libguestfs/qemu needs a carve-out: `RestrictSUIDSGID` (and likely
  `MemoryDenyWriteExecute`/`PrivateDevices`) is incompatible with an appliance build. Keep it on siblings that do
  NOT build one (rigsubmit/rigreaper); add a regression test asserting the watcher unit omits it.

## 21. drvps logs are MANDATORY + must be diagnosable-by-the-agent (2026-07-09)

**A performance regression was undiagnosable because the agent cannot see the watcher's own logs.** The matrix
oracle phase ran ~10x slow; from the agent side only wall-time is visible (~2.75s/exec), so the cause -- SSH
handshake vs mux-not-reused vs watcher per-job overhead -- could not be told apart without the watcher journal +
the ctrl/ mux sockets, both locked (drvps:qemu 0750 / systemd-journal). STANDING RULES:
- The AGENT gets permanent R/O to drvps logs: `systemd-journal` group (watcher journal) + R/O ACL on the state
  dir's log/ctrl paths. Diagnosis must not require an operator to hand-paste logs.
- When drvps code is touched, ENRICH the logs -- especially the hard-to-diagnose paths: per-guest-exec timing +
  ssh mux HIT/MISS (reused vs fresh), snapshot/scrub phase timings, job pickup->dispatch->return spans. Log the
  FACTS a future diagnosis needs, structured (op, vm, ms, mux=hit/miss).
- Logs are a MUST: never strip logging to save disk. If volume is a concern, add ROTATION (size/time-capped +
  logrotate), not silence.

## 22. A dry-run that PRINTS the refusal but RETURNS 0 masks refusal regressions (2026-07-12)
The collision preflight's dry-run branch prints "would refuse; nothing changed" and returns 0 by design
(preview, not enforcement). Live-verifying a collision fix via `--dry-run` therefore proves NOTHING about
the refusal path -- a route-parsing regression shipped past exactly such a check and was only caught one
review round later. **Lesson:** verify a fail-closed change by driving the REAL enforcement path
(`DRY_RUN=0`, read the rc), never the preview. If a check has a preview mode, write down that the preview
is a known blind spot of your gate.

## 23. Exemptions are the fail-open surface: bound EVERY dimension, on EVERY path (2026-07-12)
Three consecutive review rounds were one class. A scanner's exemption keyed on identity-but-not-value lets
drift evade it: "skip all addresses on our bridge" passed a widened live /16; "skip our kernel routes"
(dev+proto+src) passed a widened route destination; and the fixed check guarded only the install path
while `--reapply-egress` skipped it -- where `ip_nonlocal_bind=1` let squid bind a DELETED address, so
even the late bind-poll lied. Each fix was live-verified by PLANTING the drift (add/delete the address,
read the rc) and removing it. **Lesson:** for every exemption in a fail-closed scanner ask (a) does it
pin ALL dimensions of the exempted object (name AND expected value AND bounds), and (b) does the check run
on EVERY entry path that depends on the invariant? An exemption is an allowlist entry; treat it with
allowlist rigor. Related: absence is invisible to overlap/collision scans -- also assert the REQUIRED
state is present, not merely that no conflicting state exists.

## 24. argv is a bounded channel: big data through it fails E2BIG and can read as "clean" (2026-07-12)
Passing foreign XML to a python helper via argv hit MAX_ARG_STRLEN on a >128K document; python failed with
a rc the caller did not treat as fatal, so an unevaluable (possibly hostile) network read as "no
collision" -- fail-open by size. Fix: pass bulk data via a temp FILE (a path is tiny) and refuse on ANY
nonzero helper rc, not just the "known" error codes. **Lesson:** when a verifier shells out, enumerate the
channel limits (argv/env size, pipe buffering) and make the caller fail CLOSED on every nonzero rc -- an
exec-layer failure is indistinguishable from "not verified", never from "verified clean".

## 25. Triage the DETECTOR before the product: discriminate on the real contract (2026-07-12)
The first S0-S6 live matrix scored 6 failures; 5 were the probe's own bug -- it grepped `"status":"ok"`
as "accepted", but the envelope contract is success == `status:ok AND exit_code==0` (a REFUSAL is
`ok` + nonzero exit: ran and declined). The product's deny behavior was correct the whole time. A 6th
"failure" (empty machine-id) was a boot-timing artifact of the golden image, not an identity bug.
**Lesson:** a failing detector is not a product bug until the discriminator is validated against the
interface contract -- and an all-green detector is equally suspect without a positive control (plant one
real violation and watch it fire). Applies doubly to test harnesses written quickly during a live session.

## 26. Prove what a "preserve" feature preserves with a controlled two-arm probe (2026-07-12)
S6 keep-secrets was assumed to preserve "the session identity". A two-arm live probe (marker file +
machine-id + ssh-host-key fingerprint, keep-secrets restore vs default scrubbed restore) showed: on-disk
app data survives BOTH paths; machine-id survives only keep-secrets; ssh host keys survive NEITHER (the
restore seed mints a new cloud-init instance-id, and the guest's `ssh_deletekeys` default regenerates
them). That turned a suspected defect into a documented, benign contract (device-bound sessions need
keep-secrets; host-key preservation is out of scope; no host-key collision exists to contain).
**Lesson:** for any preserve/migrate/restore feature, enumerate the concrete identity artifacts and probe
each arm live -- "what actually survives" routinely differs from the design's mental model, in both
directions.
