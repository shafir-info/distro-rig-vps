# CONCEPT — drvps observability + SSH-reliability (BUNDLED)

Status: SHIPPED — console-log observability is LIVE (see STATUS.md). BUNDLED (console capture IN
scope). Single-agent trust domain unchanged; NO schema/ownership/trust-model change. It touches the
guestexec GATE (security core), so the structural live-XML rule carried a dedicated race/tamper
review and was confirmed bypass-free, with every review finding folded in (review record:
CHANGELOG.md).

## 1. Problem (evidence, 2026-07-06)
Golden acceptance: centos9 booted `running` but never SSH-ready in 365s (agent can't see guest IP or boot
console); ubuntu26 intermittent `exec rc=255` (SSH `known_hosts` collision). Fix = the DRIVER returns richer
read-only facts in its own envelopes; the agent stays walled off the host journal/state (correct).

## 2. Goal / non-goals
GOAL: any `drvpsctl` member gets read-only, drvps-scoped (never whole-root) facts about a VM incl. its boot
console; SSH stops flaking. NON-GOALS: per-user VM ownership (Phase-4), historical driver-log slice (Part B),
any write/control, any raw privileged passthrough.

## 3. API / CONFIG CONTRACT (r2 MAJOR-2 — one source of truth)
- New knob in `dr_vps_api.sh`: `: "${DR_VPS_CONSOLE_LOG_DIR:=/var/log/distro-rig-vps/console}"` (or a
  state-dir child if SELinux policy prefers). Under `set -u`, an unset var fails closed.
- ONE shared path helper `dr_vps_console_log_path <id>` -> `${DR_VPS_CONSOLE_LOG_DIR}/<id>.log`, used by the
  renderer, the gate, tail, and cleanup so no two callers can diverge.
- Add to the locked signature manifest: `dr_vps_console_log_path`, `dr_vps_console_log_prepare`,
  `dr_vps_console_log_tail`, `dr_vps_console_log_cleanup`, `dr_vps_domain_inspect`. `dr_vps_domain_render_xml`
  signature UNCHANGED (path derived from id inside it).

## 4. Parts (ONE redeploy)

### A — `inspect <vm>` (read-only, all-visible, HOST-ONLY) — r2 confirmed
`rigctl/dr-vps inspect <vm>` -> `dr_vps_domain_inspect`. FIXED host-side fields, NO SSH: `state`/`generation`/
`artifact_id`, `dominfo` summary, `guest_ip` via `virsh domifaddr --source lease` (empty -> `null`),
`console_available`. Gate = LIFECYCLE-identity (must NOT call `dr_vps_domain_ready`, which SSHes — r1 B-1). No
owner-scoping. CLOSED query set; normalized fields; `status` contract untouched.

### B — `wait`/ready why-failed (host-side) — r2 confirmed
`dr_vps_domain_ready` captures `virsh domifaddr` rc+stderr separately -> `domifaddr-error` (FAIL CLOSED) |
`no-ip` | `ssh-probe-failed` | `ready`; `wait` surfaces the last reason in E_TIMEOUT. ssh-probe leg stays in
wait (guestexec-gated); inspect never gets it.

### C — `known_hosts` SSH fix (centralized) — r2 confirmed
ONE shared SSH-opts array at all 3 sites (both remote.sh ssh/scp helpers + the domain.sh console path):
`-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no
 -o StrictHostKeyChecking=no -o LogLevel=ERROR`. Kills recycled-IP CHANGED-key rc=255.

### D — console capture: GATE CHANGE (r1 B-2; r2 confirmed no-bypass with the STRUCTURAL rule)
Renderer adds `<log file='$(dr_vps_console_log_path id)'/>` to the `<serial>` pty device (XML-escaped).
Replace the gate's blanket `count(//log)` reject with a STRUCTURAL live-dumpxml exception:
  `count(//log)=0`  OR
  `count(//log)=1 AND the sole log is
     /domain/devices/serial[@type='pty'][target/@type='isa-serial'][target/@port='0']/log[@file=EXPECTED]`
where EXPECTED = `dr_vps_console_log_path <resolved-id>` (gate computes it the SAME way; the id is
`_dr_vps_safe_id`-fenced, storage.sh, re-validated gate.sh + watcher rigctl.py). The zero-log case
is EXPLICIT so PRE-change/old VMs still PASS the gate (their console-dump then returns the Part-G "recreate to
enable" error, NOT a gate refusal). Keep the existing "all serial/console MUST be pty" invariant (gate.sh:
217) + device whitelist (gate.sh) + host-path char-dev sweep (gate.sh) so file/dev/pipe/tcp/udp/
unix backends and any 2nd/misplaced `<log>` still FAIL CLOSED. Gate validates the LIVE dumpxml (gate.sh)
-> a redefine swapping `<log file=/etc/x>` is refused (TOCTOU closed). Symlink-at-path is ALSO refused at
prepare + tail time (Part F), not gate alone.

### E — console capture: DoS BOUND (r1 B-3; r2 MAJOR-1 — prove active + aggregate)
Per-VM cap = virtlogd's `max_size` * (`max_backups`+1) (virtlogd rotates `<log file>` char-dev logs). But
per-log rotation is NOT an aggregate cap. So BOTH:
- Installer sets virtlogd `max_size` (bounded, e.g. few MB) + small `max_backups` in `/etc/libvirt/
  virtlogd.conf` (or verified include), and RESTARTS/re-execs virtlogd so the running daemon uses it.
- `doctor`/setup ASSERTS: virtlogd is the ACTIVE log manager, its running config has nonzero bounded
  `max_size` + bounded `max_backups` (fail closed otherwise — no silent "logging unbounded").
- AGGREGATE bound: `DR_VPS_CONSOLE_LOG_DIR` sits on a bounded location (dedicated/quota'd fs) OR the design
  budgets `max_active_vms * per_vm_cap + orphan_cap <= disk_budget`; setup documents + verifies the budget so
  a full console-log dir can never exhaust the host root fs.

### F — console lifecycle + fresh-inode prepare + runtime assertion (r2 MAJOR-3/4/5)
Helpers mirror `_dr_vps_publish_guard`/overlay-seed discipline (storage.sh, 75-87, 245-255):
- `console_log_prepare <id>`: path-fence, REFUSE symlink, UNLINK any pre-existing regular `<id>.log` +
  fenced rotated `<id>.log.N` (fresh-inode — no hardlink/stale-inode reuse), then leave absent for virtlogd
  OR create fresh 0640 drvps:qemu + restorecon.
- `console_log_tail <id> <cap>`: RE-check regular/not-symlink/readable, bounded read.
- `console_log_cleanup <id>`: path-fenced, REFUSE symlink (don't blindly unlink anomalies), remove `<id>.log`
  + fenced rotated `.N`.
WIRE: `prepare` before `define` on create AND recreate (recreate does NOT call destroy, domain.sh — so
stale gen output can't bleed in); `cleanup` in `_dr_vps_domain_scrub_files` (domain.sh), create rollback
(domain.sh), recreate rollback (domain.sh), destroy (domain.sh). ORPHAN GC (no VM
reaper exists in-tree — only job GC, remote.sh): add a bounded `console_log_gc` on watcher startup/setup
that removes ONLY fenced console logs whose `<id>` has NO store row AND NO live domain (safe-id parser).
RUNTIME FAIL-CLOSED ASSERTION (r2 MAJOR-5): before render/define in create+recreate (and in doctor/setup) —
console dir exists, owner/mode EXACT + not group/world-writable, SELinux label expected, virtlogd active+
bounded, target path not a symlink. Not installer-only.

### G — `console-dump` read path + edges (r2 MINOR-7)
`console-dump` (guestexec-gated, remote.sh) reads the bounded TAIL of the console log via
`console_log_tail`. No-log/pre-change VM -> explicit "no persistent console; recreate to enable" error, NEVER
empty-as-success. UNTRUSTED bytes -> follow the PULL binary path in the watcher (rigctl.py pull branch, not
the UTF-8-replace generic path ~596): return base64 + own cap; `rigctl` decodes+sanitizes for display.

## 5. Error handling
All reads FAIL CLOSED (virsh/read/label/config error -> explicit error, never empty-as-success).
`inspect`/`console-dump` on missing/foreign/gate-refused -> not-found / E_EGRESS, never partial leak.
`guest_ip: null` ONLY on a SUCCESSFUL empty lease.

## 6. Testing
Seam bats: inspect fields + fail-closed + gate-refusal + `guest_ip null`; 3 SSH sites use the shared array;
ready 4 reasons + wait timeout carries last reason; render XML has exactly the canonical `<log file>`; GATE
accepts (i) zero-log old VM and (ii) the one canonical serial log, and REFUSES (a) 2nd `<log>`, (b) wrong
path, (c) `<log>` on non-serial/non-pty device, (d) symlink at path, (e) any other host-path char dev, (f) a
redefined swapped path in live dumpxml; console_log_prepare fresh-inode (unlinks stale, refuses symlink);
console_log_cleanup path-fenced; console_log_gc removes only rowless+domainless orphans; console-dump returns
base64 tail + explicit no-console error; doctor asserts virtlogd active+bounded; runtime assertion fails
closed on bad dir/label/symlink. LIVE smoke: 4-golden acceptance -> inspect shows centos9 domifaddr
present/absent (closes centos9 diagnosis), console-dump shows real boot, no rc=255 across many births.

## 7. Deploy (ordering matters)
Code + XML + INSTALLER (virtlogd bounded config + console-log dir owned drvps:qemu, non-group-writable,
`virt_log_t` label + restorecon). ORDER: installer (dir+label+virtlogd+restart) BEFORE the code that renders
`<log file>`/widens the gate; but the create/recreate RUNTIME ASSERTION (Part F) is the real fail-closed
guard, so a half-applied deploy refuses to create rather than fail open. Redeploy `src/`+`bin/`, re-run the
`dr-vps-setup` console step, restart watcher (the deploy's mode-normalize step preserves the Part-A private file modes).
`<log file>` applies to VMs created AFTER; `inspect` additive; old VMs still pass the gate. No schema.

## 8. Deferred (Part B)
Historical driver-log slice. YAGNI until these live facts prove insufficient.
