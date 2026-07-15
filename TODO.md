# TODO / backlog (open items only)

UX/quality backlog + operator-pending deploy steps. Feature-level deferrals and design
boundaries live in STATUS.md ("Deferred"); DR-6 has its own design note
(docs/ISSUE-per-net-isolation.md). Completed items are removed (history: CHANGELOG.md).

Priority order: 1) DR-2 firewalld self-test (installer automation LANDED; a real proxy probe remains),
2) DR-3 operator tail (CA regen + golden re-bake), 3) upgrade helper, 4) DR-4/DR-5 deploy tails, 5) the rest.

## DR-2 (firewalld hosts): installer automation LANDED; one self-test item + a live run remain
On a firewalld-active host NO guest can reach the squid cache at `<bridge-ip>:3128` (or mock
ports): nftables runs EVERY base chain on a hook, so `drvps_sim.guest_in`'s ACCEPT (prio 0)
cannot override firewalld's REJECT (prio 10; drvps0 lands in a libvirt-style zone).
- DONE (INSTALLER FIX, `step_firewalld`): detect firewalld (`firewall-cmd --state`); derive the zone
  (`--get-zone-of-interface=drvps0`); install PERMANENT scoped rich-rule allows for
  `simulated_allow.cache_port` + `mock_ports` from the guest subnet to `cache_cidr` (all from
  fleet.json), never a blanket service open; idempotent query-before-add; `--permanent
  --add-interface=drvps0` so `--reload` cannot drop the binding. Offline: `tests/firewalld-dr2.sh`
  (10 checks, mock seam). A real firewalld-host verification is still pending (STATUS.md).
- DONE (DOC FIX): the base-chain composition note is next to `dr_vps_net_render`'s fence comment.
- OPEN (SELF-TEST FIX): extend `--gate-selftest` (or the egress apply) with a guest->cache
  reachability probe that does a REAL https-through-proxy fetch (`dnf makecache`), not a bare
  TCP connect -- a bare connect would pass while a real fetch still broke.

*(The "deploy tail" items below are operations for an already-deployed instance -- not source
defects; they matter to anyone upgrading a running rig in place.)*

## DR-3 (deploy tail): CA regen + golden re-bake on an already-deployed host
The nameConstraints fix (parent-domain permitted subtrees derived from mirror_allowlist) is in
the installer and regression-tested; the DEPLOYED host still needs: run `dr-vps-setup` (it
auto-detects the constraint change and announces "REBUILD goldens"), then `dr-vps build
<distro>` per golden so the new trust anchor ships in each image. Note: the standard install
path needs NO non-distro allowlist entries (audited: all deps are base distro packages; no
pip/npm/EPEL fetches).

## DR-4 (deploy tail): RestrictSUIDSGID fix
The installer source now omits `RestrictSUIDSGID` from the watcher unit (supermin must create
setuid appliance files; kept on rigsubmit/rigreaper which never build one). Remaining:
1. Deploy the source fix to the running /opt (host currently relies on a drop-in override).
2. Bats regression test: the generated `drvps-rigctl.service` must NOT contain
   `RestrictSUIDSGID` (guards reintroduction; the snapshot feature is unusable with it).
3. Optional: `dr-vps doctor` / setup-time WARN if the running watcher has it set.

## DR-5 (deploy tail): default the guest-exec SSH mux ON
`DR_VPS_SSH_MUX` ships 0 (off) -> every guest exec pays a full SSH handshake (~2.75s measured;
~32x overhead vs a pooled connection). The mux implementation is code-complete and converged
(per-VM ControlMaster socket under the state dir, 0700 + length-guard + destroy/reaper
cleanup); flip the default to 1 (installer unit env or the api.sh default) after a soak run,
plus a bats/doctor check. Until then it can be enabled per-host via a watcher drop-in.

## Logging: enrich + rotate (standing rule; see LESSONS-LEARNED #21)
When touching drvps code:
1. Instrument the guest-exec path: log per-exec `op=exec vm=<id> ms=<n> mux=hit|miss`.
2. Time snapshot/scrub phases + job pickup->dispatch->return spans.
3. Add log ROTATION (size/time caps) -- logs are mandatory; silence is not a disk strategy.
4. Grant + document the agent's standing R/O log access (systemd-journal group + scoped
   state-dir ACL) in INSTALL-RUNBOOK so it survives reinstalls.

## rigctl UX: VM name is a LABEL, not a handle
`rigctl create <name>` returns the id; wait/exec/destroy accept ONLY the id, yet the name is
shown in `list`. A by-name call is gate-refused, and a failed destroy-by-name leaks the VM (a
first-time consumer hit exactly this). Either resolve name->id inside the id-taking verbs
(mapping already in the store; dedup ambiguity per owner), or keep id-only with an explicit
error ("'<name>' is a label; use its id drvps-vm-..."). Add a bats case either way.

## Installer: tested upgrade helper (`dr-vps-setup --upgrade`)
The manual redeploy is a 15-step ordeal and unsafe as written (moving live /opt aside before
verifying the staged tree once broke /opt mid-deploy). The helper must: (a) extract the pack to
staging, (b) VERIFY key files exist BEFORE touching live /opt, (c) atomically swap (root:root
0755 + restorecon), (d) run `dr-vps-setup` (with `--adopt-simnet`/`--force-squid` when
appropriate), (e) RESTART `drvps-rigctl` (enable --now does not restart a running watcher),
(f) verify + keep a `.old` rollback. Guard discipline: coexistence/marker refusals are
deliberate security -- improve adoption ergonomics, never auto-takeover of a foreign resource.

## Installer: finish the verify-class sweep
Three race-prone post-mutation reads (net-ACTIVE, net-autostart, squid port-bind) already go
through the shared bounded-poll `_dr_vps_verify_poll`. Sweep the REMAINING read-once
postconditions that immediately follow a socket-activated libvirt/systemd mutation (net dumpxml
shape checks, nft apply live-verify) through the same primitive -- a slower host trips the next
instance (fix the class, cf. LESSONS-LEARNED #14).

## Parked idea: interactive out-of-band recovery console
An agent/operator interactive console attach over an INTERNAL socket (beyond the operator
break-glass `dr-vps console` = virsh console). Never approved or started; revisit on demand.

## Golden lifecycle: a `dr-vps rm-golden` verb (GC)
There is no first-class way to remove a golden -- `snap-rm` deletes snapshots, but goldens accumulate
(esp. old duplicates after an in-place upgrade + rebuild, since `create` uses the newest per distro and
the older ones just sit on disk). The store already has the safe primitive: `dr_vps_store_image_delete`
is golden-only and atomically **refcount-gated** (refuses while any VM backs it). Wire a proper verb:
`dr-vps rm-golden <artifact_id>` -> resolve `golden_path`, call `dr_vps_store_image_delete`, then `rm`
the pool file; refuse a snapshot id (point at `snap-rm`); add a red-green bats test (refcount-refusal,
successful delete removes row + file, snapshot refused). Interim tool that does exactly this over the
existing primitive: `tools/reclaim-goldens.sh` (dry-run default, `--commit` to apply) -- fold its logic
into the verb, then retire it.

## Housekeeping
- **/opt vs checkout reconcile** on the deployed host: verify `/opt` matches the current pack
  (past deploys used single-file patches); clean full redeploy if it drifts.
