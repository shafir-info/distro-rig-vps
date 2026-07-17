# SPEC — DR_VPS_DIAG: flag-gated metadata-only diagnostic trace (observability add-on)

Purpose: post-run analysis of the observability RUNTIME acts that offline/seamed tests cannot see (gate
accept/refuse reasoning, admission math, console_assert results, prepare/gc actions, console-dump served
bytes, inspect probe decisions, ready-reason) — the exact live-path decisions that the "converged but not
proven-live" gap makes hard to diagnose. Design locked 2026-07-06.

## Design (locked)
- **Enable**: env flag `DR_VPS_DIAG` (default UNSET -> OFF). Only-by-flag, NOT permanent: with it unset,
  NOTHING is created and NOTHING is logged (gc reap included -- no always-on trail). Zero prod cost/noise.
- **Banner**: when ON, the FIRST emission in a process writes (a) a loud one-line stderr banner
  `drvps: DIAG logging ENABLED (debug, metadata-only) -> <path>` and (b) a header line in the diag file, so
  it is obvious debug is on + where it goes.
- **Sink**: `${DR_VPS_SPOOL_DIR}/diag/drvps-diag.log`. Under the SPOOL (drvps:drvpsctl) because that is the
  one tree the watcher (drvps) writes AND the agent (drvpsctl) can traverse+read; `/var/log/distro-rig-vps`
  is `drvps:qemu 0750` (agent cannot even traverse it). Dir lazy-created `drvps:drvpsctl 2750` (setgid ->
  files inherit drvpsctl; drvps is `usermod -aG drvpsctl`); file explicitly `chmod 0640` on create (the
  environment umask 0077 would otherwise strip group-read). A `diag/` sibling of `requests/` is NOT touched
  by the watcher's request-scan / non-regular purge. The agent has NO spool write -> no plant-race on the dir.
- **Write safety**: refuse a symlink at the diag path (`[ ! -L ]`) before append (belt-and-suspenders -- the
  dir is drvps-write-only, no attacker can plant there). Pure best-effort (`… || true`): a diag failure NEVER
  fails a real op.
- **Content**: METADATA ONLY -- ids, counts, decisions, byte-counts, the console path (agent-derivable),
  ready-reason. NEVER console content / guest bytes / secrets / golden|overlay host paths.
- **Rotation**: the reaper sweep size-rotates the diag file to `.1` above `DR_VPS_DIAG_MAX_BYTES` (default
  16 MiB) so a long debug session cannot fill disk. Gated on the FILE (existence+size), NOT the flag -- the
  flag may live only in the watcher's env while the reaper's lacks it, so a flag-gated rotation could leave a
  growing diag unbounded. Consequence (accepted trade-off): default-off with no prior session =
  ZERO filesystem mutation; but a leftover OVERSIZE diag from a past session may be tidied once (a harmless
  `mv`). "Default-off = no logging"; the reaper may clean up a pre-existing debug log.
- **Helper**: one `dr_vps_diag()` in api.sh (all shell modules get it); the tricky acts live in the shell
  CLI the watcher runs as drvps, so no Python/bin-rigctl twin is needed (the agent-side bin/rigctl cannot
  write the spool anyway). Instrumented: gate.sh (console-log check + overall accept), doctor.sh (admission
  math, assert), storage.sh (prepare fresh-inode), domain.sh (gc reap, inspect probe-decision), remote.sh
  (console-dump log-size, NOT content). NOTE: `ready` is NOT instrumented -- its reason is already surfaced
  in the `dr_vps_domain_wait` E_TIMEOUT message, so a diag line would be redundant.
- **Cost when OFF**: every diag arg is a cheap variable expansion (no forks); the one arg needing `stat`
  (console-dump) is guarded by `[ -z "$DR_VPS_DIAG" ] ||`. So DR_VPS_DIAG unset = truly zero cost.

## Trust trade-off (deliberate)
The diag makes the gate/admission/assert INTERNAL reasoning agent-readable (drvpsctl, not world). Judged
acceptable: metadata-only; the agent already sees refusal reasons + can derive its own console path; scoped
to the trust group (not world); flag-gated OFF by default. It is NOT an audit/authorization surface -- the
enforcing decisions and their fail-closed dies are unchanged; this only ADDS a debug trace.

## Test plan
- diag OFF (default): dr_vps_diag is a no-op; no file created; ops unaffected.
- diag ON: banner emitted once; a metadata line lands in the file; file is 0640 + group drvpsctl.
- NO-LEAK: feed a console log containing a fake "secret"/binary; assert the diag file contains the byte
  COUNT but NOT the content.
- symlink at the diag path -> refused (no write through it).
- reaper rotation above the cap.
