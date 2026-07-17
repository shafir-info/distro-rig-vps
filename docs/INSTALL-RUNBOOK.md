# INSTALL-RUNBOOK -- first-time install of distro-rig-vps

Fresh install on a Linux KVM host. To update an existing install instead, use UPDATE-RUNBOOK.md.
The first live install on a real host informed this runbook; it is the distilled, repeatable
procedure. The "Roles and assumptions" and "File modes" sections in UPDATE-RUNBOOK.md apply here
too and are not repeated.

## Roles

- OPERATOR -- a separate user with `sudo`; owns every privileged step (placing code under root-owned
  `/opt/distro-rig-vps`, `dr-vps-setup`, group changes, systemd). NOT the agent.
- AGENT -- an unprivileged user that will drive the rig via `rigctl` after install; builds the pack and, once
  in the `drvpsctl` group, submits to the watcher. NEVER runs `sudo`.

Baseline: independent operator + agent home umask 0077, but it works even if not -- every privileged step uses
`sudo`, and integrity is a piped absolute-path checksum (cwd/permission-independent).

## Prerequisites (host)

- Linux with KVM (`/dev/kvm`), libvirt + `virtlogd`, and the tools `nft`, `qemu-img`, a NoCloud
  seed builder (`cloud-localds` OR `genisoimage` -- genisoimage is the packaged mandatory dep, so
  el9 hosts without a cloud-utils package are covered), `xmllint`, `squid`. SELinux enforcing is
  supported (and expected).
- `dr-vps-setup` installs missing OS packages, so a clean host mainly needs KVM + libvirt + a package manager
  it recognises (dnf/apt). It will NOT create OS accounts without `--yes`.
- **Subnet-colliding hosts (e.g. a nested rig guest that itself sits on 10.123.0.0/24):** set
  `DR_VPS_BRIDGE_IP=<a.b.c.1>` in Step 2's environment to renumber the WHOLE guest-subnet endpoint set
  (simnet bridge + dhcp range, squid bind/ACL, persisted guest-proxy URL) in lockstep. The value must be
  the `.1` of its /24. `fleet.json`'s `simulated_allow.cache_cidr` must match `<bridge-ip>/32` --
  pre-create `/etc/distro-rig-vps/fleet.json` accordingly (setup installs the packaged 10.123 default
  only when the file is missing, then FAILS CLOSED on the mismatch, naming the fix). Stock hosts: leave
  unset; behavior is byte-identical to the historical literals.
- **POSIX ACL support on the spool filesystem (S5 private result store).** With the private result store on
  (`DR_VPS_RESULT_PRIVATE=1`, the default), the watcher grants each requesting account read on its own
  `0600` result via a POSIX ACL, so the spool fs must be mounted with `acl` and the `acl` package
  (`setfacl`/`getfacl`) installed. `dr-vps-setup` installs the `acl` package, and the watcher launcher
  probes ACL support on `results/` at startup and FAILS CLOSED (the service won't start; `dr-vps-setup`'s
  service-start check surfaces it) -- so a misconfigured host is caught at install, not by silently writing
  results no agent can read. This is enforced at the WATCHER boundary, NOT the generic VM-create gate (a
  direct operator `dr-vps create` is unaffected). ext4/xfs enable ACLs by default. For a trusted
  single-tenant rig (or a spool fs without ACL support) set `DR_VPS_RESULT_PRIVATE=0` to keep the legacy
  `0640` group-readable results (co-tenant-trusting). NOTE: setup does not yet persist that line --
  `dr-vps-setup` rewrites `/etc/distro-rig-vps/env` on every run, so re-add it after any re-run, or use
  a systemd drop-in (`Environment=DR_VPS_RESULT_PRIVATE=0` on drvps-rigctl.service), which survives
  re-runs (tracked in CHANGELOG Deferred).

## Ubuntu 26.04 (apt family) specifics -- READ THIS if the target is Ubuntu/Debian

The steps below are the same on Ubuntu 26.04; `dr-vps-setup` detects the apt family and adapts. What it
does differently (all AUTOMATIC -- no operator action) versus the Fedora path:

- Packages: `apt` installs `qemu-system-x86` (NOT `qemu-kvm`, which is a virtual package with no install
  candidate on 26.04), `libvirt-daemon-system`, `squid-openssl` (base `squid` lacks SSL-bump), and the
  rest of the apt dep set. The libvirt control unit is `libvirtd.service`; the squid runtime user is
  `proxy`; the cert helper is `/usr/lib/squid/security_file_certgen`.
- SELinux is OFF on a stock Ubuntu host, so the installer SKIPS all `semanage`/`restorecon`/`virt_log_t`
  labeling. The `restorecon` lines in Steps 1 and 5 are guarded (`command -v restorecon`) and become a
  no-op here -- run them as written; they just do nothing.
- Console-log dir: Debian/Ubuntu ship `/var/log` as `root:syslog 2775` (group-writable), which is unsafe
  as a root-created log ancestor, so the installer RELOCATES the console-log default to
  `/var/lib/distro-rig-vps/console` (root:root ancestors). Ownership stays `drvps:<qemu-group>` `0750`, so
  `console-dump` reads it exactly as on Fedora. Transparent -- nothing to configure.
- `/dev/kvm` must be present (bare-metal, or a nested-virt-enabled VM). `dr-vps-setup` fails closed in the
  preflight if it is absent.

Only two things change in the operator commands below: in **Step 4** build the Ubuntu golden recipe, and in
**Step 6** create from it:

```
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps build /opt/distro-rig-vps/etc/recipes/ubuntu26.json
/opt/distro-rig-vps/bin/rigctl create smoke ubuntu26 1
```

`etc/recipes/ubuntu26.json` PINS `upstream_sha256` and fetches the cloud image from
`cloud-images.ubuntu.com` (allowlisted in `fleet.json`). If `dr-vps build` FATALs on a sha256 mismatch,
Ubuntu re-published the 26.04 image -- re-pin `upstream_sha256` from
`https://cloud-images.ubuntu.com/releases/26.04/release/SHA256SUMS` (GPG-verify SHA256SUMS.gpg first) and
rebuild. Base packages only -- consumer installers pull their own deps.

Kernel readability (Debian/Ubuntu build-plane prereq): `dr-vps build` runs `virt-customize`/libguestfs,
which COPIES the host kernel to build its appliance, so the `drvps` build user must be able to READ
`/boot/vmlinuz-*`. Ubuntu ships the kernel mode `0600` (root-only), Fedora `0644`. On Ubuntu the build fails
inside libguestfs (`supermin exited nonzero`); every bake failure now carries a common-cause hint naming
this + the fix, and re-running with `DR_VPS_LIBGUESTFS_DEBUG=1 dr-vps build ...` shows the full libguestfs
diagnostics (the `cp: cannot open '/boot/vmlinuz-...': Permission denied` line). Fix it and re-run:

```
sudo chmod 0644 /boot/vmlinuz-*
```

`chmod` persists across reboot but NOT across a kernel UPGRADE (a new kernel installs `0600`) -- re-apply
after each upgrade (a per-kernel `dpkg-statoverride` covers only that exact filename; add a
`/etc/kernel/postinst.d` hook if you build often). Fedora hosts are unaffected.

Appliance DNS (build-plane prereq -- ANY host on a loopback-stub resolver, INCLUDING Fedora, not just
Ubuntu): the bake's in-appliance package install must resolve the distro mirrors. When `systemd-resolved`
is active, `/etc/resolv.conf` is TYPICALLY its loopback STUB (`nameserver 127.0.0.53`); libguestfs copies
that stub into its appliance where `127.0.0.53` is useless, so the bake fails with `Could not resolve host
...`. The fix below applies ONLY to that stub arrangement -- if `/etc/resolv.conf` already lists a real
upstream server, DNS is fine and you skip this entirely.

Run these THREE checks first and READ the output; do the repoint only if ALL hold:

```
grep -E '^nameserver' /etc/resolv.conf                          # (a) must be the loopback STUB (127.x); a REAL server here -> SKIP, DNS already works
systemctl is-active systemd-resolved                            # (b) must print: active
grep -E '^nameserver' /run/systemd/resolve/resolv.conf          # (c) uplink must list a NON-loopback server (not 127.x / ::1)
```

If all three checks hold, back up the current
`/etc/resolv.conf` (once) and repoint it at that uplink. `cp -a` faithfully preserves a symlink OR a
regular file; the `test -e ... ||` keeps a re-run from overwriting your saved original:

```
sudo test -e /etc/resolv.conf.drvps-bak || sudo cp -a /etc/resolv.conf /etc/resolv.conf.drvps-bak
sudo ls -l /etc/resolv.conf.drvps-bak                           # CONFIRM the backup exists before the next line
sudo ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

Restore the original afterward (a **split-DNS / VPN / corporate** host cannot express per-interface routing
through the flattened uplink, so restore if resolution misbehaves) -- confirm the backup first, then swap:

```
sudo ls -l /etc/resolv.conf.drvps-bak                           # CONFIRM the backup before restoring
sudo cp -a --remove-destination /etc/resolv.conf.drvps-bak /etc/resolv.conf
```

If any of the three checks does NOT hold -- `/etc/resolv.conf` already lists a real (non-loopback) server,
systemd-resolved is not running, or the uplink is absent / loopback-only -- do NOT run the `ln`; configure a
reachable non-loopback resolver another way. Fedora build hosts that use the systemd-resolved stub need this
same fix; a Fedora host that already has real upstream nameservers works as-is. This one fix serves BOTH the
Fedora `dnf` and the Ubuntu `apt` bakes -- the appliance DNS path is identical.

### Appliance networking

Modern libguestfs gives the throwaway bake appliance usermode networking via **passt**, and only falls
back to **slirp** if no `passt` binary answers `--help` with exit 0/1 -- it never network-TESTS passt. On
some hosts passt is broken even though the host network is fine. Proven on an Ubuntu 26.04 cloud VM: the
distro passt (`git20260120`) never leases the appliance (it falls back to a zeroconf `169.254.x` address
with an empty `resolv.conf`), and a newer passt built from source exits status 1 (Ubuntu's AppArmor +
unprivileged-userns restriction breaks passt's `pivot_root`/namespaces). slirp works there.

`dr-vps build` handles this automatically: the default `DR_VPS_LIBGUESTFS_NET=auto` bakes on passt first
and, on a passt-specific failure, **transparently retries on slirp** (a fresh overlay per attempt; only a
fully-successful bake is promoted -- never a partial). You normally do nothing. To pin the backend:

```
DR_VPS_LIBGUESTFS_NET=auto  dr-vps build ...     # default: passt, then slirp on a passt failure
DR_VPS_LIBGUESTFS_NET=slirp dr-vps build ...     # force slirp (skip passt)
DR_VPS_LIBGUESTFS_NET=passt dr-vps build ...     # force passt, fail closed if unusable
```

A build that reports "no usable appliance backend" with BOTH passt and slirp failing to reach the repos
is almost certainly a host repo/DNS/egress problem (see the DNS fix above), not the backend. The knob
needs the `direct` libguestfs backend (the default) and makes NO host change -- it selects the backend
per bake via a private, per-invocation shim. Emergency host-wide alternative, if ever needed:
`sudo dpkg-divert --divert /usr/bin/passt.distro --rename /usr/bin/passt` forces libguestfs onto slirp
system-wide (reverse with `sudo dpkg-divert --rename --remove /usr/bin/passt`). Newer passt also adds a
`--chroot-fallback` flag for the Ubuntu `pivot_root` failure if you prefer to fix passt itself.

Scope note (first real export): the network-dependent tail (simnet ACTIVE -> squid on 10.123.0.1:3128 ->
nft egress fence -> `dr-vps doctor` PASS -> a real guest boot) is exactly what a bare-metal/nested-enabled
Ubuntu host proves that a drvps-in-drvps guest could not (the guest sits on the rig's own 10.123.0.0/24, so
its inner simnet cannot activate). Watch Step 5's `doctor` and Step 6's `console-dump` closely.

## Step 0 -- AGENT: build and stage the pack (no sudo)

```
"$HOME/distro-rig-vps/bin/make-pack.sh"
PACK=$(ls -t "$HOME/tmp"/distro-rig-vps-*.tar.gz | head -1); echo "$PACK"; sha256sum "$PACK"
```

`make-pack.sh` normalises in-archive modes to `u=rwX,g=rX,o=` (group-only, no world) so that after root extracts
and chowns to `root:drvpsctl`, the service user + agent can traverse/read/exec the tree (without this the
watcher dies `203/EXEC`). Give the
operator the printed PACK path and hash.

## Step 1 -- OPERATOR: verify and place the code

Refuses to run over an existing install (use UPDATE-RUNBOOK.md for that), and verifies the staged tree BEFORE
removing anything, so a wrong pack can never delete a live tree:

```
echo "<HASH>  <PACK>" | sudo sha256sum -c -
sudo rm -rf /opt/drvps-stage
sudo mkdir -p /opt/drvps-stage
sudo tar -xzf <PACK> -C /opt/drvps-stage
sudo test -x /opt/drvps-stage/distro-rig-vps/bin/dr-vps-setup
if [ -e /opt/distro-rig-vps ]; then echo "REFUSED: existing install -- use UPDATE-RUNBOOK.md (or remove /opt/distro-rig-vps first)"; else sudo mv /opt/drvps-stage/distro-rig-vps /opt/distro-rig-vps; fi
sudo rm -rf /opt/drvps-stage
sudo chown -R root:root /opt/distro-rig-vps
sudo chmod -R u=rwX,go=rX /opt/distro-rig-vps
if command -v restorecon >/dev/null 2>&1; then sudo restorecon -RvF /opt/distro-rig-vps; fi   # SELinux only (no-op on Ubuntu/Debian)
```

The `if [ -e /opt/distro-rig-vps ]` gate MECHANICALLY prevents the `mv` when an install already exists (the
`mv` runs only in the `else`): if it prints `REFUSED`, the code was NOT moved -- use UPDATE-RUNBOOK.md instead.
The `chmod -R u=rwX,go=rX` makes the tree traversable/readable/execable through setup -- this is a TEMPORARY
world-read, because the target `drvpsctl` group does not exist yet (it is created by `dr-vps-setup` in Step 2);
Step 5 tightens the tree to `root:drvpsctl` group-only. `restorecon` is MANDATORY: code placed in `/opt` can
inherit a docker `container_file_t` SELinux label a confined systemd service cannot exec (`203/EXEC`).

## Step 2 -- OPERATOR: run the installer

Creates the `drvps` service user (system account, no login shell), adds it to `kvm,libvirt,qemu`, defines the
isolated `simnet` network + nft egress fence, configures the caching squid, bounds `virtlogd`, provisions the
console-log dir with its `virt_log_t` label, and installs the Phase-2 units.

```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes
```

On a host with NO prior squid use, `dr-vps-setup` itself installs the squid package, whose stock
distro `/etc/squid/squid.conf` then trips the FOREIGN-config coexistence guard (the installer cannot
tell a never-used package default from an operator's config -- it refuses either way, verified live
2026-07-12). If nothing else on the host uses squid, re-run with `--force-squid` (the original is
saved to `squid.conf.drvps-orig` and restored on uninstall):

```
sudo /opt/distro-rig-vps/bin/dr-vps-setup --yes --force-squid
```

Watch for `[setup] DONE`. Stop and investigate on any `FATAL`, SELinux `AVC`/`denied`, or non-zero exit. On an
SELinux host the first install historically surfaced squid pidfile/ssl_db label issues -- those fixes are in
this code, but keep `sudo journalctl -u squid -n 30 --no-pager` and `sudo ausearch -m avc -ts recent` handy.

## Step 3 -- OPERATOR: enrol the agent, refresh group membership

Let the agent drive the rig without sudo (Phase-2 loop). Group changes need a fresh login for interactive
users; the unit restart applies the service user's groups.

```
sudo usermod -aG drvpsctl <agent-user>
sudo systemctl restart drvps-rigctl.service
```

The `<agent-user>` must start a fresh login session (or `newgrp drvpsctl`) before `rigctl` works.

## Step 4 -- OPERATOR: build at least one golden

No VM can be created until a distro golden is registered. Build the one(s) you need (each is a few GiB and
takes minutes):

```
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps build /opt/distro-rig-vps/etc/recipes/fedora44.json
```

## Step 5 -- OPERATOR: tighten /opt to group-only, finalize services + health check

Now that `dr-vps-setup` has created `drvpsctl` and added `drvps` to it, drop the temporary world-read to
group-only, then finalize (mirrors UPDATE-RUNBOOK.md) including priming the reaper heartbeat:

```
sudo chown -R root:drvpsctl /opt/distro-rig-vps
sudo chmod -R u=rwX,g=rX,o= /opt/distro-rig-vps
sudo chmod 0750 /opt/distro-rig-vps
if command -v restorecon >/dev/null 2>&1; then sudo restorecon -RvF /opt/distro-rig-vps; fi   # SELinux only (no-op on Ubuntu/Debian)
sudo systemctl daemon-reload
sudo systemctl restart drvps-rigctl.service
sudo systemctl start drvps-rigsubmit.socket
sudo systemctl start drvps-rigreaper.service
sudo systemctl is-active drvps-rigctl.service drvps-rigsubmit.socket
sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps doctor && echo "DOCTOR: PASS"
```

The restart re-execs the watcher under the tightened perms; `drvps` reads `/opt` via its `drvpsctl`
membership, and no other local user can.

## Step 6 -- smoke (the real test)

As the AGENT (no sudo; rigctl args are positional, net fixed to simnet):

```
/opt/distro-rig-vps/bin/rigctl create smoke fedora44 1
/opt/distro-rig-vps/bin/rigctl list
/opt/distro-rig-vps/bin/rigctl exec <vm-id> id
/opt/distro-rig-vps/bin/rigctl console-dump <vm-id>
/opt/distro-rig-vps/bin/rigctl destroy <vm-id>
```

`create` returns `<vm-id>` in its JSON `stdout`. Success: `exec` prints `uid=0(root) ...`; `console-dump`
prints real kernel/boot text; `destroy` leaves `list` empty. A `gate refused` on `exec` means the guest-exec
closed-shape proof hit a host/qemu-version-specific benign device -- paste the refusal (it names the element)
to allowlist it narrowly.

## Step 7 -- (optional) enable the closed-shape pre-start gate

Ships default OFF (`DR_VPS_PRESTART_GATE=off`). After the smoke proves the live path, raise it one notch at a
time (`off` -> `warn` -> `enforce`). Use the exact `sed` + `grep -qx` verify + restart commands in
UPDATE-RUNBOOK.md Step 7.

## Step 8 -- (optional, KEEP OFF until live-verified) same-user secrets-restore for service VMs

`DR_VPS_ALLOW_SECRET_RESTORE` ships **OFF**: an agent's `rigctl use --restore-secrets` (restoring that
agent's own `--keep-secrets` snapshot into a service-class VM, 1:1 replace) is refused with a clear
pre-execution error until the operator enables the policy. The operator's own direct
`dr-vps use --allow-secret-bearing` path is unaffected either way. Do NOT enable it until the
secrets-restore path has passed its live verification (restored guest identity contained by the
per-owner isolation) -- the refusal IS the intended shipped behavior until then.

To enable (the guarded append is idempotent -- safe to re-run; the `:=` form lets an explicit env
override still win, matching the rest of the file):

```
grep -qxF ': "${DR_VPS_ALLOW_SECRET_RESTORE:=1}"' /etc/distro-rig-vps/env || printf '%s\n' ': "${DR_VPS_ALLOW_SECRET_RESTORE:=1}"' | sudo tee -a /etc/distro-rig-vps/env
grep -qxF ': "${DR_VPS_ALLOW_SECRET_RESTORE:=1}"' /etc/distro-rig-vps/env && echo "SECRET-RESTORE: ENABLED"
```

Enabling needs no service restart: `dr-vps` sources `/etc/distro-rig-vps/env` on every invocation, so
the policy applies from the next request.

**Disabling DOES need a watcher restart.** The watcher launcher exports the env file into the
long-lived watcher process at startup (`set -a`), and every `dr-vps` child inherits that environment;
the env file's `:=` lines never UNSET an inherited value. So if the watcher (re)started while the flag
line was present, deleting the line alone leaves the policy silently ENABLED in the running watcher --
the kill-switch must remove the line AND restart (pick an idle moment; a restart mid-operation kills
the in-flight request):

```
sudo sed -i '/DR_VPS_ALLOW_SECRET_RESTORE/d' /etc/distro-rig-vps/env
sudo systemctl restart drvps-rigctl.service
! grep -q DR_VPS_ALLOW_SECRET_RESTORE /etc/distro-rig-vps/env && systemctl is-active --quiet drvps-rigctl.service && echo "SECRET-RESTORE: DISABLED"
```

## firewalld hosts (DR-2): handled automatically by the installer

On a firewalld-active host (Fedora/RHEL default), firewalld's zone REJECT (nft prio 10) outranks
the rig's `drvps_sim` ACCEPT (prio 0) for guest->cache traffic -- nftables runs EVERY base chain on
a hook, and an accept in one table does not compose past a reject in another. Symptom (if unhandled):
guest `dnf install` fails with "proxy connect refused"; the cache/SSL-bump path is inert.

The installer's `step_firewalld` now does this FOR YOU: when firewalld is active it adds the scoped
rich rules + the permanent `drvps0` zone binding and reloads (idempotent; a no-op when firewalld is
inactive). The commands below are the equivalent MANUAL fallback -- run them only if you disabled
that step, or to adjust after a non-default `DR_VPS_BRIDGE_IP`. They allow the guest subnet to reach
ONLY the cache endpoints and persist the bridge's zone binding so a firewalld reload does not drop it:

```
sudo firewall-cmd --permanent --zone=libvirt --add-rich-rule='rule family="ipv4" source address="10.123.0.0/24" destination address="10.123.0.1/32" port port="3128" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone=libvirt --add-rich-rule='rule family="ipv4" source address="10.123.0.0/24" destination address="10.123.0.1/32" port port="8443" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone=libvirt --add-interface=drvps0
sudo firewall-cmd --reload
```

Adjust the zone (`firewall-cmd --get-zone-of-interface=drvps0`) and the subnet/bridge-ip if you
installed with a non-default `DR_VPS_BRIDGE_IP`. GOTCHA: `--reload` drops drvps0's RUNTIME
interface->zone binding -- that is why the `--add-interface` line above must be `--permanent`
(`step_firewalld` already does this). The one remaining open DR-2 item is a real
https-through-proxy self-test probe (TODO.md DR-2); the rule installation itself is automated.

## Gotchas (why the non-obvious steps exist)

- top-directory mode + group-only -- `tar` creates `/opt/distro-rig-vps` under root's umask 0077 (0700); Step 1
  makes it world-read TEMPORARILY (the `drvpsctl` group does not exist until setup), Step 5 tightens to
  `root:drvpsctl` `0750` group-only. Both `drvps` and the agent are in `drvpsctl` so both exec the tree; the
  wrong owner/mode dies `203/EXEC` (watcher) or EACCES (agent's rigctl).
- restorecon after placing code -- avoids the `container_file_t` -> `203/EXEC` crash-loop.
- verify-before-delete -- `test -x .../dr-vps-setup` on the staged tree before any `rm -rf`/`mv`.
- group changes need a fresh login -- the agent must re-login (or `newgrp drvpsctl`); the unit restart covers
  the service user's groups.
- golden before create -- `dr-vps build` must run at least once; a create with no registered golden fails.
- make-pack.sh, not a raw tar -- normalised in-archive modes make the tree readable/execable by the
  unprivileged service user after `chown root:root`.

## Known issue: snapshot scrub vs systemd hardening -- the watcher must NOT set `RestrictSUIDSGID` (DR-4)

Root-caused 2026-07-08. Symptom: `rigctl snapshot <vm>` (default scrub) fails `status ok exit 1`, and
`/var/lib/distro-rig-vps/tmp/sysprep.*.log` shows
`virt-sysprep: error: libguestfs error: /usr/bin/supermin exited with error status 1`
(base builds report "snapshot produced no id").

Root cause: the scrub runs inside `drvps-rigctl.service` (the watcher). libguestfs/supermin builds an appliance
that MUST contain setuid binaries (mount, etc.); `RestrictSUIDSGID=yes` seccomp-blocks setuid/setgid file
creation, so supermin exits 1. It is NOT the appliance cache, NOT a kernel/permission issue, and NOT
distro-specific -- it fails identically on every guest under that restriction. Proof: `libguestfs-test-tool` as
the service user passes in a plain shell but fails under `systemd-run -p RestrictSUIDSGID=yes` (and passes with
`NoNewPrivileges`+`LockPersonality` only). `drvps-rigsubmit` and `drvps-rigreaper` keep `RestrictSUIDSGID` -- they
never build an appliance.

Fix: the installer (`dr-vps-setup`) now OMITS `RestrictSUIDSGID` from the watcher unit. On a host installed
BEFORE that fix, apply a drop-in (idempotent):

```
sudo mkdir -p /etc/systemd/system/drvps-rigctl.service.d
printf '[Service]\nRestrictSUIDSGID=no\n' | sudo tee /etc/systemd/system/drvps-rigctl.service.d/10-libguestfs.conf
sudo systemctl daemon-reload
sudo systemctl restart drvps-rigctl.service
```

Verify: `rigctl snapshot <a-ready-vm>` returns `status ok exit 0` with a snapshot id.
