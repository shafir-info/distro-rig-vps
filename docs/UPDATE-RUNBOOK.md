# UPDATE-RUNBOOK -- replacing a running distro-rig-vps install

How to update an already-installed rig to a newer build with no data loss. Verified live on 2026-07-08
(e.g. 0.1.0 -> 0.2.0). For a first-time install see INSTALL-RUNBOOK.md.

## Roles and assumptions

Two identities, ALWAYS treated as distinct:

- OPERATOR -- a separate user with `sudo`. Owns every privileged step: the root-owned `/opt/distro-rig-vps`
  code tree, systemd units, and `dr-vps-setup`. The operator is NOT the agent.
- AGENT -- an unprivileged user in the `drvpsctl` group. Builds the pack and drives the live rig via
  `rigctl` (submits over `/run/drvps-submit.sock`; the watcher, running as the service user, does the KVM
  work). The agent NEVER runs `sudo`.

Baseline: the agent's home is umask 0077 (files 0600 / dirs 0700), so the operator cannot read the agent's
artifacts as themselves. This runbook still works if the two identities coincide or umask is looser, because
every privileged step uses `sudo` (root bypasses DAC) and integrity is checked with a piped absolute-path
checksum (independent of cwd and permissions).

What survives an update: state (DB, pool, overlays) lives in `/var/lib/distro-rig-vps`, NOT in `/opt`, so a
code swap never touches it. The store schema migrates additively and backward-compatibly on first use, so a
rollback to the previous code is safe without a DB rollback.

## File modes (least privilege)

Default restrictive (0600 files / 0700 dirs); loosen ONLY where a specific user or group must have access, and
only that far:

- pack tarball 0600 in the agent's 0700 `~/tmp` -- the operator reads it via `sudo`.
- `/root/drvps-backups` 0700 (root only).
- state + logs (`/var/lib/distro-rig-vps`, `/var/log/distro-rig-vps`) 0750 `drvps:qemu` -- group access for the
  virtlogd/qemu side, NO world bit. The config env `/etc/distro-rig-vps/env` is 0644 (non-secret, paths only;
  it MUST stay readable by the agent and drvps -- rigctl and the acceptance script source it with a
  readability guard and silently fall back to defaults if it is not). Secrets stay tighter: the VM ssh key
  under `~drvps/.ssh` 0700.
- NO world-readable trees. The code at `/opt/distro-rig-vps` is `root:drvpsctl`, top dir `0750`, files `g=rX,o=`
  (group-only, no world bit): `make-pack.sh` normalises archive modes to `u=rwX,g=rX,o=`, and Steps 3/Rollback
  `chown -R root:drvpsctl` + `chmod 0750` the top dir. BOTH the `drvps` service user and the agent are members of
  `drvpsctl` (established by `dr-vps-setup`), so both can traverse/read/exec the tree -- and no other local user
  can. This is why the group MUST be `drvpsctl` specifically: any group that omits either identity breaks exec
  (the watcher dies `203/EXEC`, or the agent's `rigctl` gets EACCES).

## Step 0 -- AGENT: build and stage the verified pack (no sudo)

Build with the committed bundler (normalises in-archive modes as above -- do NOT hand-roll a `tar`, which under
umask 0077 would ship 0600 files the service user cannot read):

```
"$HOME/distro-rig-vps/bin/make-pack.sh"
```

It writes `~/tmp/distro-rig-vps-<UTC>.tar.gz` (mode 0600). Print the path + checksum to hand the operator:

```
PACK=$(ls -t "$HOME/tmp"/distro-rig-vps-*.tar.gz | head -1); echo "$PACK"; sha256sum "$PACK"
```

Give the operator the printed PACK path and the 64-hex hash.

## Step 1 -- OPERATOR: verify the pack (sudo; cwd- and permission-independent)

Substitute the agent's PACK path and HASH:

```
echo "<HASH>  <PACK>" | sudo sha256sum -c -
```

Expected: `<PACK>: OK`. Do not proceed on a mismatch.

## Step 2 -- OPERATOR: back up the current install (rollback point)

Timestamped so repeated updates never overwrite an earlier rollback point:

```
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps list
TS=$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 /root/drvps-backups
sudo tar -C /opt -czf "/root/drvps-backups/opt-$TS.tar.gz" distro-rig-vps
sudo cp -a /var/lib/distro-rig-vps/store.db "/root/drvps-backups/store.db-$TS"
sudo ls -l /root/drvps-backups
```

`dr-vps list` printing nothing just means no active VMs. If the `store.db` copy reports "No such file", find
the real path with `sudo -u drvps -H bash -lc 'echo "$DR_VPS_DB"'` and back that up instead (the DB backup is a
safety net, not a hard dependency -- the migration is additive).

## Step 3 -- OPERATOR: stop the watcher, swap the code, relabel

The watcher is down from here until Step 5. Running VMs are libvirt domains and are unaffected.

```
sudo systemctl stop drvps-rigctl.service drvps-rigsubmit.socket
sudo rm -rf /opt/drvps-stage
sudo mkdir -p /opt/drvps-stage
sudo tar -xzf <PACK> -C /opt/drvps-stage
sudo test -x /opt/drvps-stage/distro-rig-vps/bin/dr-vps-setup
sudo rsync -a --delete /opt/drvps-stage/distro-rig-vps/ /opt/distro-rig-vps/
sudo rm -rf /opt/drvps-stage
sudo chown -R root:drvpsctl /opt/distro-rig-vps
sudo chmod 0750 /opt/distro-rig-vps
if command -v restorecon >/dev/null 2>&1; then sudo restorecon -RvF /opt/distro-rig-vps; fi   # SELinux only (no-op on Ubuntu/Debian)
```

The `test -x ...dr-vps-setup` line ABORTS (non-zero) before the `rsync --delete` if the pack extracted wrong,
so a bad pack can never wipe `/opt`. `rsync -a --delete` makes `/opt/distro-rig-vps` exactly match the pack --
it refreshes every file (code + `README.md`/`VERSION`/`CONCEPT.md`/`STATUS.md`/`LICENSE`), removes any
file the new build dropped, and cleans out stray leftovers from earlier deploys. `make-pack.sh` already
normalised the file modes (group-only); the explicit `chmod 0750` fixes the one thing it can't -- the top directory, which
`tar`/`rsync` create under root's umask 0077 (0700) and which `drvps` must be able to traverse. `restorecon` is
MANDATORY: code in `/opt` can inherit a docker `container_file_t` SELinux label a confined systemd service
cannot exec (the watcher crash-loops `203/EXEC`); the relabel fixes it.

Confirm the new code landed:

```
grep -m1 DR_VPS_DRIVER_VERSION /opt/distro-rig-vps/src/dr_vps_image.sh
```

## Step 4 -- OPERATOR: re-run the idempotent setup

Provisions any new host config (e.g. the console-log dir with its `virt_log_t` label, virtlogd bounds),
refreshes `/etc/distro-rig-vps/env`, and reinstalls units. It reload-or-restarts squid + virtlogd briefly but
does NOT rebuild goldens or disturb running VMs.

```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes
```

It ends with `[setup] DONE`. Its "sanity (informational, non-gating): dr-vps doctor" line may report the reaper
heartbeat stale/missing -- that is EXPECTED before the first reaper sweep (Step 5) and does not gate anything.
Stop and investigate only on `FATAL`, an SELinux `AVC`/`denied`, or a non-zero exit.

## Step 5 -- OPERATOR: restart the services and prime the reaper

```
sudo systemctl daemon-reload
sudo systemctl restart drvps-rigctl.service
sudo systemctl start drvps-rigsubmit.socket
sudo systemctl start drvps-rigreaper.service
```

The last line runs one reaper sweep so the console-reaper heartbeat exists; otherwise `dr-vps doctor` reports
the reaper stale until the timer first fires. Creates are NOT blocked by a missing heartbeat -- that check is a
doctor health signal only, and the console DoS bound is guaranteed by the virtlogd emergency cap regardless.

## Step 6 -- verify (the first live run is the real test)

Operator health check:

```
sudo systemctl is-active drvps-rigctl.service drvps-rigsubmit.socket
sudo test -f /var/lib/distro-rig-vps/console-reaper.last && echo "reaper heartbeat: OK" || echo "MISSING"
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps doctor && echo "DOCTOR: PASS"
```

Then a full round-trip smoke. The AGENT can do this without sudo via rigctl (positional args; net is fixed to
simnet):

```
/opt/distro-rig-vps/bin/rigctl create smoke fedora44 1
/opt/distro-rig-vps/bin/rigctl list
/opt/distro-rig-vps/bin/rigctl exec <vm-id> id
/opt/distro-rig-vps/bin/rigctl console-dump <vm-id>
/opt/distro-rig-vps/bin/rigctl destroy <vm-id>
```

`create` returns the `<vm-id>` in its JSON `stdout`. Success: `exec` prints `uid=0(root) ...`, `console-dump`
prints real kernel/boot text (the readable, drvps-owned console log), `destroy` leaves `list` empty. If `exec`
returns `gate refused`, the guest-exec closed-shape proof hit a host/qemu-version-specific benign device --
paste the refusal (it names the element) so it can be allowlisted narrowly.

## Step 7 -- (optional) enable the closed-shape pre-start gate

The gate ships default OFF (`DR_VPS_PRESTART_GATE=off`, behaviour-preserving). Once the smoke proves the live
path, raise it one notch at a time in `/etc/distro-rig-vps/env`. The installer defaults this knob in CODE and
does NOT seed an env line, so first make sure the line exists (guarded append -- idempotent, a no-op when the
line is already there). Each later `sed` is followed by a `grep -qx` that FAILS loudly if the line did not
change (drifted spacing, already-set, commented) so you never restart on a silent no-op:

```
grep -q 'DR_VPS_PRESTART_GATE' /etc/distro-rig-vps/env || printf '%s\n' ': "${DR_VPS_PRESTART_GATE:=off}"' | sudo tee -a /etc/distro-rig-vps/env
sudo sed -i 's/^: "${DR_VPS_PRESTART_GATE:=off}"/: "${DR_VPS_PRESTART_GATE:=warn}"/' /etc/distro-rig-vps/env
sudo grep -qx ': "${DR_VPS_PRESTART_GATE:=warn}"' /etc/distro-rig-vps/env
sudo systemctl restart drvps-rigctl.service
```

Run several creates in `warn` (it runs the sweep on the live inactive `dumpxml` and logs a DIAG on what it
would refuse, without blocking). When clean across your distros, go to `enforce`:

```
sudo sed -i 's/^: "${DR_VPS_PRESTART_GATE:=warn}"/: "${DR_VPS_PRESTART_GATE:=enforce}"/' /etc/distro-rig-vps/env
sudo grep -qx ': "${DR_VPS_PRESTART_GATE:=enforce}"' /etc/distro-rig-vps/env
sudo systemctl restart drvps-rigctl.service
```

## Rollback

If Step 6 misbehaves. Extract the backup to a scratch dir and VERIFY it before removing the live tree, so a
bad/missing backup can never leave the host without code:

```
BK=$(sudo sh -c 'ls -t /root/drvps-backups/opt-*.tar.gz | head -1'); test -n "$BK"; echo "restoring $BK"
sudo rm -rf /opt/drvps-rollback
sudo mkdir -p /opt/drvps-rollback
sudo tar -C /opt/drvps-rollback -xzf "$BK"
sudo test -x /opt/drvps-rollback/distro-rig-vps/bin/dr-vps-setup
sudo systemctl stop drvps-rigctl.service drvps-rigsubmit.socket
sudo rm -rf /opt/distro-rig-vps
sudo mv /opt/drvps-rollback/distro-rig-vps /opt/distro-rig-vps
sudo rm -rf /opt/drvps-rollback
sudo chown -R root:drvpsctl /opt/distro-rig-vps
sudo chmod -R u=rwX,g=rX,o= /opt/distro-rig-vps
sudo chmod 0750 /opt/distro-rig-vps
if command -v restorecon >/dev/null 2>&1; then sudo restorecon -RvF /opt/distro-rig-vps; fi   # SELinux only (no-op on Ubuntu/Debian)
sudo systemctl daemon-reload
sudo systemctl restart drvps-rigctl.service
sudo systemctl start drvps-rigsubmit.socket
```

## Gotchas (why the non-obvious steps exist)

- top-directory mode -- `make-pack` normalises the files it lists, but `tar`/`rsync` create the top
  `/opt/distro-rig-vps` dir under root's umask 0077 (0700). `chmod 0750` (root:drvpsctl) lets `drvps` + the agent
  traverse; without it the watcher dies `203/EXEC`.
- restorecon after placing code -- code in `/opt` can inherit a docker `container_file_t` label the confined
  watcher cannot exec (`203/EXEC`). Always relabel.
- prime the reaper -- `dr-vps doctor` (and setup's sanity line) reports the reaper stale until the first sweep
  writes `/var/lib/distro-rig-vps/console-reaper.last`; `systemctl start drvps-rigreaper.service` primes it.
- reaper does NOT gate creates -- the heartbeat freshness window (`DR_VPS_CONSOLE_SWEEP_MAX_AGE_S`) must exceed
  the `drvps-rigreaper.timer` interval, or the operator doctor false-alarms between sweeps.
- verify-before-delete -- both the swap and the rollback `test -x .../dr-vps-setup` the staged tree BEFORE any
  `rm -rf`, so a bad pack/backup can never wipe `/opt`.
- S5 private result store (ACL) -- on a pre-S5 rig the FIRST fail-closed moment is Step 4:
  `dr-vps-setup --yes` starts the watcher (`enable --now`), whose launcher hard-requires POSIX-ACL
  support on the spool fs (the setup's own service-start check aborts with the journal tail; see
  INSTALL-RUNBOOK "POSIX ACL support"). For a no-ACL spool the opt-out is `DR_VPS_RESULT_PRIVATE=0`,
  BUT setup rewrites `/etc/distro-rig-vps/env` on every run: add the line AFTER Step 4 (and re-add it
  after any future setup re-run), then start the services per Step 5 -- or use a systemd drop-in
  (`Environment=DR_VPS_RESULT_PRIVATE=0` on drvps-rigctl.service), which survives setup re-runs.
- S5 legacy-results tail -- results written 0640 BEFORE the update stay group-readable until the
  reaper's result GC AGES them out (`DR_VPS_RESULT_TTL_MIN`, default 24h); a manual reaper start does
  NOT shorten that, it only sweeps what is already past the TTL. To close the tail immediately, run
  the reaper once with a lowered TTL (this also ages out duplicate-reqid replay tombstones early --
  acceptable right after an update, when no pre-update reqid should ever be re-submitted):

```
sudo runuser -u drvps -- env DR_VPS_RESULT_TTL_MIN=1 /opt/distro-rig-vps/bin/drvps-rigreaper
```
