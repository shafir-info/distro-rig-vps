# distro-rig-vps -- AGENT guide (for `drvpsctl` members)

You are a rig **agent**: an unprivileged user in the `drvpsctl` group. You drive throwaway VMs entirely
through one command -- **`rigctl`** -- with NO sudo and NO `/dev/kvm`. The operator installs and maintains
the rig (the goldens, the host, the network); you just use it via `rigctl`. This page is everything you
need to do that -- you do not need the project source or internals (even if the installed tree happens to
be group-readable, you never have to look at it).

If a `rigctl` call says **"could not reach the submit socket"**, either you are not in `drvpsctl` yet
(ask the operator to `usermod -aG drvpsctl <you>`, then log out and back in) or the service is down.

## For AI agents: install the skill once

If you are an AI agent (Claude Code), run this ONE command once so every future session auto-discovers how
to drive the rig -- no re-reading this guide after a context clear:

```
drvps-skill-install                 # copies the drvps skill (this guide + the orchestrator guide) into ~/.claude/skills/drvps
```

It writes only your own `~/.claude`, needs no sudo, and is idempotent (re-run after a rig update to refresh).
`drvps-skill-install --status` shows what is installed; `--uninstall` removes it. Start a new session to load
the skill.

## The commands

Discover the rig and what you can create from:

```
rigctl distros                                      # id  distro  built_at  -- the goldens the operator built
rigctl version                                      # rig version + which build is live; include it when reporting a problem
```

Lifecycle + access:

```
rigctl create <name> <distro> [ttl] [mem] [cpus] [--class service] [--idem KEY]   # clone a VM from a golden distro (e.g. fedora44)
rigctl use <name> --from-snap <snap-id> [--ttl H] [--mem M] [--cpus N] [--class service] [--idem KEY] [--restore-secrets]   # clone from one of YOUR snapshots
rigctl list                                         # id  state  name  artifact_id
rigctl status <id>                                  # state | generation | artifact_id | egress_gen
rigctl inspect <id>                                 # fuller detail on one VM
rigctl wait <id>                                    # wait for boot + cloud-init + ssh ready
rigctl recreate <id> [--idem KEY]                   # reset the VM from its pinned base (golden OR snapshot); wipes changes
rigctl destroy <id> [--idem KEY]                    # stop + remove the VM
rigctl console-dump <id>                            # bounded serial-console snapshot
```

Run things inside the guest / move files:

```
rigctl exec <id> 'cmd'                              # run a command INSIDE the guest, wait for it (in-box unrestricted)
rigctl exec-detach <id> 'cmd'                       # start a LONG command detached -> prints a <job>
rigctl exec-status <job>                            # poll a detached job
rigctl exec-output <job>                            # fetch a detached job's captured STDOUT
rigctl exec-errors <job>                            # fetch its captured STDERR (where a failed install's FATAL line lands)
rigctl push <id> <localfile> <remote>              # copy a local file into the guest (no host path leaks)
rigctl pull <id> <remote>                           # write the guest file's RAW bytes to stdout (binary-safe)
```

Snapshots (yours only):

```
rigctl snapshot <id> [--keep-secrets] [--notes STR] [--idem KEY]   # freeze the VM's installed state as a reusable snapshot
rigctl snap-ls                                      # list YOUR snapshots
rigctl snap-show <snap-id|name>                     # render a snapshot's provenance
rigctl snap-rm <snap-id|name> [--idem KEY]          # delete YOUR snapshot
```

Egress splice destinations (drvpsvc members only -- register a CRM/callback host the operator opens end-to-end, never MITM'd):

```
rigctl egress add-splice <host> [port]              # request an end-to-end splice to <host> (default 443); a root operator opens it after a dry-run + YES
rigctl egress remove-splice <host> [port]           # request removal of a splice you no longer need
rigctl egress list                                  # list YOUR splice requests + each one's state
rigctl egress status <reqid>                        # that request's outcome: pending | under-review | applied | rejected | expired (reqid printed by add/remove-splice)
```

- Egress verbs require membership in the `drvpsvc` group (a non-member is refused, exit 12). The submit
  result is the request outcome (`pending`+reqid / `already-active` / `already-absent` / `refused`); the
  operator's later decision (`applied` | `rejected` | `expired`) is learned by polling `egress status <reqid>`.

- Every call prints the watcher's JSON result envelope, EXCEPT `pull` and `console-dump`: on success
  `pull` streams the guest file's raw bytes to stdout (like `cat`) and `console-dump` prints the decoded,
  sanitized console text; on error either one prints the envelope and exits non-zero.
- **Result privacy.** By DEFAULT the rig runs the private result store: each result -- including a
  `pull`'s file contents and an `exec`'s stdout/stderr -- is written `0600` with a POSIX ACL granting
  read to YOUR account only, so a co-tenant cannot read it (the watcher refuses to start if the spool
  fs lacks ACL support; note `ls -l` shows `0640` on an ACL'd file -- the mask -- while `getfacl`
  shows `group::---` + your named grant, which is the real check). A rig may run the legacy opt-out
  (`DR_VPS_RESULT_PRIVATE=0`: results group-readable until garbage-collected) -- ask your operator
  which mode is active before moving anything sensitive through `exec`/`pull` output; under the legacy
  mode, do NOT `pull` or `exec 'cat ...'` a secret you would not share with a co-tenant.
- You CANNOT set the network, ssh key, or project -- those are fixed by the watcher. The numeric caps
  (ttl hours / mem MB / cpus) are range-checked. Every VM has a mandatory TTL and is auto-reaped when it
  expires -- snapshot anything you want to keep.
- `exec` is intentionally unrestricted INSIDE the box: break the guest however you like, then `recreate`
  to reset it to its pinned base.
- `rigctl` waits up to `RIGCTL_TIMEOUT` seconds (default 360). The watcher runs requests **one at a time**
  and a lifecycle op (create/use/recreate/destroy/snapshot) can run up to ~900s, so a request can time out on the
  client while still QUEUED behind another or still running. On timeout `rigctl` says whether it was
  *claimed* (a worker picked it up -- it may still be finishing, or the watcher died mid-op) or *never
  claimed* (no claim marker recorded -- usually still queued or the watcher stalled, but treat it as
  INDETERMINATE for mutations). See "When something is wrong" for what is safe to retry.

## What your VM can reach (egress)

Guests sit on one shared, isolated network. A guest can reach ONLY the host's caching proxy (for package
installs from allow-listed mirrors) and the configured mock ports -- NOT the open internet, and NOT other
guests (guest-to-guest traffic is blocked). If a package mirror you need isn't allow-listed, ask the
operator to add it (that's an operator action).

## Snapshots are yours

Snapshots you create are scoped to your OS user: `snap-ls`/`snap-show` enumerate only your own, and you
can act on only your own (another user's snapshot resolves to not-found). This is action/store isolation,
**not** transport privacy -- do not rely on snapshot *secrecy* between co-tenants. `snapshot` without
`--keep-secrets` scrubs identity/secrets; a secret-bearing snapshot is refused as a base for a new VM.
The ONE exception is `use ... --restore-secrets`: restoring your OWN secret-bearing snapshot into a
service-class VM, and only when the operator has enabled that policy on the rig (it ships disabled) --
see the orchestrator guide (`ORCHESTRATOR-GUIDE.md`) for the conditions. Without all of them the restore is
refused exactly as before.

## When something is wrong

- **"could not reach the submit socket"** -> you're not in `drvpsctl`, or the ingress socket/service is
  down (an operator checks `systemctl status drvps-rigsubmit.socket drvps-rigctl`). The request was NOT
  submitted -- safe to re-issue once you're in the group / the service is back.
- **"submit acknowledgment lost after sending"** / **"unexpected submit response"** -> the request reached
  the ingress but the reply was lost, so it MAY already be enqueued. Treat it as INDETERMINATE: for a
  MUTATING op do NOT blindly re-run -- reconcile with `list` / `status` / `snap-ls` first, exactly as for a
  timeout (below).
- **`rigctl` timed out** -> the ingress already accepted the request (the wait starts after that), so a
  timeout does NOT mean it was rejected. *claimed* = a worker took it (still finishing, or the watcher died
  mid-op). *never claimed* = no claim marker was recorded -- usually still queued behind a long op or the
  watcher stalled, but a claim-marker write can itself fail while the op still runs, so treat this as
  INDETERMINATE too. Re-issuing a READ (`list`/`status`/`inspect`/`snap-ls`/`snap-show`) is always safe.
  For MUTATIONS, pass `--idem <key>` (1-64 chars of `[A-Za-z0-9_.-]`, scoped to your account) on the
  FIRST attempt: then re-issuing the byte-identical command with the same key either replays the recorded
  result (`idem_replayed:true`, `orig_reqid` set) or answers `status:"indeterminate"` if the first attempt
  was durably accepted but left no completion record (it may or may not have started) -- it never silently
  double-executes. The same key with a DIFFERENT command is rejected (body mismatch): keys name one intent,
  once. Keys are retained for a 24 h TTL (operator-tunable); after expiry an old key re-executes. Your
  account also has a generous per-account key quota -- an over-quota NEW key is refused with a clear
  error (another account's churn never evicts your keys).
  On `indeterminate` -- or when the original attempt had no `--idem` -- reconcile by TYPE, and never let
  an inconclusive check justify a blind retry:
  - **VM lifecycle** (create/use/recreate/destroy): `rigctl list` / `rigctl status <id>` DO reflect the
    outcome -- a new or vanished id, or a bumped generation. Reconcile against those before retrying.
  - **snapshot / snap-rm**: check `rigctl snap-ls` (NOT `list`/`status`, which never show snapshots) for
    whether the snapshot now exists / is gone.
  - **exec / exec-detach / push**: `list`/`status` reveal NOTHING about these -- the effect is inside the
    guest. Confirm the actual effect yourself (e.g. `rigctl exec <id> '...'` to test the file or result, or
    `rigctl pull`); if you cannot confirm, do NOT blindly re-run -- a non-idempotent command may have
    completed after the client exited. For a timed-out `exec-detach` whose `<job>` was never printed, the
    output is unrecoverable: treat the box as possibly-modified and `recreate` if you need a known-clean base.
- **A VM shows `broken`** -> `rigctl destroy <id>` (the reaper also clears expired broken VMs).
- **create refused with an egress error** -> the operator needs to re-apply the egress fence.

Anything that needs sudo -- installing the rig, building golden distros, allow-listing a mirror,
changing the caps -- is the **operator's** job. You cannot and should not do it from the agent seat.
