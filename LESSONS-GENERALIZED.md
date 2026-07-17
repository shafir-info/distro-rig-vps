# distro-rig-vps — Generalized Engineering Lessons (transferable)

Portable, **project-independent** lessons distilled from building, reviewing, deploying, and
consuming this rig. Each item is a rule plus the mechanism that makes it true — stated so it
applies to any KVM/libvirt system, any privilege-separated service, any unprivileged-agent +
human-sudoer workflow, or any bash/shell codebase, not just drvps.

**Relationship to the other lessons docs.** [`LESSONS-LEARNED.md`](LESSONS-LEARNED.md) is the
*project-specific* retro (what cost time here, with the concrete fix). This file is the
*generalized* layer curated from it plus the project's wider development history. Concrete drvps
details appear only as illustrations.

**Provenance.** Curated from this project's build, review, deployment, and live-verification
history — its development records, the deploy/consumer retrospective, and this repo's own
`LESSONS-LEARNED.md` and CONCEPT docs.

**Status.** A living, project-independent reference — refined as the codebase and its lessons
evolve.

---

## 1. Verification and epistemology — how a finding earns the word "verified"

- **Seam/mock tests prove logic; only a real-environment run proves integration.** A fully green
  seamed suite (here: 96 bats + shellcheck-clean) still met ~13 genuine issues on first live
  contact. Budget a live shakeout as a first-class phase; "isolated env passes, host integration
  breaks" is the default, not the exception.
- **A mock suite is bounded by fixture fidelity.** 188 green tests + 23 external review rounds
  missed a would-refuse-ALL-real-input blocker because the fake was structurally unlike real tool
  output. Build fakes from *captured* real output, refresh them whenever reality is consulted, and
  prove each test bites via fault injection.
- **Live testing reclassifies findings in BOTH directions.** The same live pass proved a
  statically-"correct" code path wrong (a default-ACL leak) and a scary-looking finding harmless
  (a read-only ProtectHome). A test environment faithful to the real deploy target converts
  "reasoned on paper" into fact — and paper reasoning is wrong in both directions often enough to
  matter.
- **Two wrongs can mask each other; isolation exposes what end-to-end hides.** A leak was invisible
  in the full-install test because a *different* bug incidentally cleaned it up. Never conclude "the
  reversal works" from an end-to-end pass alone — an isolated round-trip is what surfaces
  compensating defects.
- **A detector tuned only on failure paths false-fires on the first real success**, and an
  all-green detector is equally suspect without a positive control. First-green is a distinct test
  event. The inverse trap: a negative assertion passing *vacuously* because the harness could not
  host the subject at all (a daemon that refuses to run as uid 0, tested inside a rootless userns
  where everything is uid 0 — the "no-MITM PASS" was a dead tunnel). A negative result is meaningful
  only beside a passing positive control in the same run.
- **Un-suppress the real error before theorizing, then design ONE discriminating measurement on the
  live failing state.** Two blind fixes were spent on a `>/dev/null 2>&1`-swallowed error that
  turned out to be `Permission denied`, not the assumed lock. Helper wrappers that swallow error
  envelopes turn designed refusals (fail-closed capacity checks) into silent no-ops and multiply
  misdiagnosis.
- **Ground truth beats recollection — and you can buy certainty by running both in parallel.** On a
  contested semantics question, consult an independent reviewer AND run a definitive local experiment in parallel;
  agreement settles it as fact, not opinion. Prove artifact integrity by checksum/mtime, never by
  "I didn't touch it."
- **State the identity a live test ran as, and every manual deviation from the committed
  procedure.** A "nested really works — GREEN" claim collapsed under review: it ran entirely as
  root (bypassing the very DAC boundaries the system enforces) with five manual workarounds absent
  from the committed script. A root-driven pass cannot substantiate an isolation/authorization
  claim; encode the workarounds into the test or downgrade the claim to "functional wiring."
- **Skip an expensive test tier only with cryptographic proof nothing in scope changed
  ("blast-radius proof").** `diff -q` the sudo-path files, or sha256 the changed class, before
  deciding a tier is unnecessary — and grep the cheap tests for assertions touching the changed
  lines to choose which tiers run at all. Map each change to the suites it can plausibly break; run
  the full suite at batch boundaries, not per one-line fix.
- **Version-stamp BOTH the suite and the code under test; the code sha *changing* after a patch is
  the proof the green run exercised the fix.** Every run header printing suite-version + tree-sha +
  code `__version__` + code-sha makes stale suites obvious and makes "did green actually test the
  new code?" answerable at a glance. (Corollary: every component carrying a version string a drift
  check compares must bump in the same diff, or healthy deploys warn forever.)
- **Red-first / green-after, at suite scale — the suite becomes an executable finding ledger.** A
  privileged suite whose baseline on unfixed code is deliberately RED, flipping GREEN as each fix
  lands, is both the acceptance signal and the living record of what was found.
- **Mutation-test your gates, and make liveness observe CHANGE.** "The output file exists and
  parses" is satisfied forever by the last good write; a health gate for anything periodic must see
  an advancing sequence/timestamp within the period plus per-dependency status — then kill the
  producer and confirm the gate fails.
- **Idempotency/drift fingerprints must cover only inputs the service itself cannot write.** Hashing
  runtime-regenerated caches (`__pycache__`, `ld.so.cache`, a first-start-rewritten conf) guarantees
  false drift; compute at a stable lifecycle point and prove immunity empirically. Before/after
  system-state diffs likewise catch ambient daemons (identical residue across independent runs is
  the fingerprint of ambient churn, not your change) and formatting noise — whitelist by exact
  path+attribute, normalize in the capture layer.
- **A `--dry-run` pass is not a live pass** — dry-run suppresses exactly the enforcement exits under
  test. Verify refusal behavior with the real command on a disposable target.
- **Follow existing conventions before building.** Reading the pre-existing acceptance suite fully
  first meant the new privileged suite *extended* rather than duplicated it, and the old suite
  became an independent regression guard.

## 2. Gating, trust, and privilege boundaries

- **Fail-closed gates deserve respect, not overrides.** When a capacity or integrity gate says no,
  the cheap path (tune the gate) is almost always wrong — fix the world instead. A RAM-reserve gate
  refusing to launch a 4 GB VM on a 29-user box at load 15 is doing its job; free real memory. An
  integrity gate refusing a checksum mismatch is doing its job; re-pin deliberately.
- **A destructive operation should require two independent "yes, this is a throwaway" proofs.**
  Two-level gating everywhere: a host-side runner that gates on environment markers + group
  membership (skips inert, exits 0, safe to invoke anywhere) AND an in-target gate that requires
  root + the service manager + a disposable-environment marker AND refuses where a real install
  exists. Neither alone should be able to authorize destruction.
- **The vetted hash is the trust anchor — never rebuild the artifact it blesses.** If a human vetted
  a sha256, regenerating the tarball only re-stamps the name and invalidates the vetting. Ship and
  verify the exact bytes that were blessed.
- **Invert the threat intuition: scrutinize by "does this reach the host," not "does this look
  dangerous."** The unrestricted-looking verb (run arbitrary code in a fenced, disposable,
  egress-limited guest) is the *safe* one; the boring host-touching fields (an id used as a
  filename, a name flowing into a privileged command, the build plane that runs on the host) are
  the real attack surface. Confinement, not appearance, decides risk.
- **Identity across a unix socket comes from `SO_PEERCRED`, never from request fields.** Read the
  unforgeable caller uid at the accept boundary, STAMP it into the request overwriting anything
  client-supplied, fail closed on unstamped requests, and return not-found (not forbidden) to
  non-owners so existence doesn't leak.
- **When an untrusted principal can create filesystem objects a never-root service must manage, that
  is a design bug, not a hardening gap.** A group-writable request spool lets the untrusted writer
  plant a `chmod 000` inode the never-root watcher can neither traverse nor delete — a permanent
  DoS. Move ingress to a socket so the trusted side owns every object, and publish with no-clobber
  atomic renames (`renameat2(RENAME_NOREPLACE)`).
- **Directories writable by two trust levels are finding factories.** When successive security
  reviews keep minting same-flavored findings (symlink swaps, TOCTOU, marker claims) in one
  subsystem, stop patching instances: build a who-writes-what matrix across the privilege boundary
  and fix the ownership model once (single writer per namespace).
- **For a sudo-invokable tool, argv is exactly as attacker-controlled as the environment.** Moving
  an override from env to command line changes nothing; the fix is NO runtime path/command seam at
  all — fixed constants, with test seams at import/API level. Everything the invoker controls (env,
  argv, cwd, fds) is attack surface.
- **Unprivileged code that must gate on privileged state trusts a verified generation marker.** The
  privileged actor live-verifies reality (e.g. the loaded firewall ruleset) then writes a
  world-readable monotonic marker under `/run`; unprivileged consumers gate on its freshness.
  Volatile storage means a reboot invalidates it automatically.
- **Close observability gaps with a closed, audited, read-only query set run by the privileged
  side** — per-resource, owner-scoped facts only. Never a generic privileged passthrough (an
  escalation proxy) and never per-tenant filtering of a global log firehose (one parse bug =
  cross-tenant leak). For read-only group visibility across a boundary, publish an atomically-renamed
  group-readable snapshot with a seq counter and give consumers a dumb renderer — don't widen the
  control channel.
- **Privileged processes must never write predictable names in shared sticky dirs** (classic
  CWE-59: a pre-planted symlink turns a privileged append into an arbitrary-file clobber). Opt-in
  diagnostics live under service-owned trees, group-readable to the narrowest real group (chmod'd
  explicitly against the process umask), off by default, metadata-only, with a banner when enabled.
- **Provenance markers keyed by path alone are replayable against a lookalike created later** — bind
  "this object is mine" markers to filesystem identity `(st_dev, st_ino)`.
- **A concurrent privilege daemon is a different kind of component than the pure-function libraries
  around it — let the security requirement pick the language.** `O_NOFOLLOW`/`O_EXCL` atomic opens
  and killing a child *process group* while concurrently scanning for a preempt are not expressible
  in bash (`[ -h ]`-then-open is itself a TOCTOU); that part had to be Python. Plan the privileged
  core as its own component from the start.

## 3. Unprivileged agent ⇄ human-sudoer operations

- **Cross-user handoffs fail on directory TRAVERSAL, not on the file's own mode.** A 0755 script
  under a 0700 home is unreachable by any other user — the x bit on every ancestor is what counts.
  Files another identity must read/execute go in a world-traversable place (`/tmp`, `/opt`,
  `/var/tmp`) with modes set explicitly (under `umask 0077` every new file starts 0600).
- **umask-0077 artifacts poison every downstream copy.** `cp -a`/`tar` preserve 0700/0600; after
  `chown root:root` nothing else can read or exec them (cause of a live 203/EXEC crash-loop);
  `make install` under a global 0077 produced a root-only `-rwx------` binary that looked like a
  program failure. Normalize modes explicitly in the deploy path (`install -m`,
  `tar --mode='u=rwX,go=rX'`, `find ... chmod u=rwX,go=rX`); a manual runbook that bypasses the
  installer must replicate every normalization the installer does; diagnose "command not working" by
  checking mode bits before behavior.
- **Root extracting a tar applies the archive's recorded ownership** (unlike non-root extraction) —
  a tree tarred by an unprivileged uid stays that uid after root untars it, and a hardened installer
  correctly refuses the non-root source. Normalize with `--owner=root --group=root` at creation, or
  `chown -R root:root` after extraction; stage packs under root's space, never a third user's home.
- **The sudo-handoff grammar that worked:** do everything unprivileged yourself first; hand ONE
  copy-pasteable step at a time and read the pasted output before deciding the next (a multi-command
  batch died on drifted state assumptions); absolute paths only — `~` expands in the *other* user's
  context; keep lines short enough not to wrap; state the expected output including "prints nothing"
  and the expected duration; build destructive steps as `check && act && echo OK || echo ABORTED` so
  a human can't carry a failure forward; when a sequence outgrows paste-lines, hand one
  self-contained, syntax-checked, idempotent script at a world-readable path; wrap long
  interactive-sudo jobs in tmux (a sudo password prompt forbids `nohup`).
- **Cross-user integrity handoff = a piped absolute-path checksum:**
  `echo "<sha>  /abs/path" | sudo sha256sum -c -` — immune to cwd and umask, and sudo lets root read
  the agent's 0700 home. Produce checksum files in exact `sha256sum -c` grammar; a *format* error
  from the other side actually proves permissions were fine.
- **Group membership is frozen at process start, and the freeze points are bigger than shells.**
  `usermod -aG` never affects running processes; the `systemd --user` manager (kept alive across all
  relogins by `Linger=yes`) re-attaches every new login to the stale set. Remedies: `sg <group> -c`
  per command (surgical), restart `user@<uid>.service` + relogin (inventory and stage recovery for
  whatever tmux/user services that kills first), `newgrp`, or reboot. Corollary: a phased tool that
  starts a daemon and *then* adds groups will observe its own "stale groups" and can self-escalate a
  safe repair into a session-killing relogin — order identity mutations before starting the reader.
  Installers granting groups must print the relogin requirement.
- **Schedule wide-then-narrow permission windows, with the tighten as an explicit step.** When early
  install stages need a directory world-readable before the intended group exists, widen
  deliberately and add the "now tighten to `root:group`, `o=`" as its own scheduled step — never an
  afterthought.
- **Verify claimed system config through the resolved view, not the config directory.** "I already
  added the rule" was false; `systemctl show -p` + live cgroup/interface files show what actually
  took effect. A config file on disk is an intention, not a fact.
- **Grant the debugging agent durable read access to the system's own telemetry** —
  `usermod -aG systemd-journal` + `setfacl -R -m u:<agent>:rX` on state dirs beats pasting excerpts
  through a human. Pair log enrichment with rotation from day one; copy a huge journal to a file
  before analysis.
- **Own your failures in the report.** "The two mid-run hiccups were mine, not the rig's"; a leaked
  resource reported, found, and destroyed, then turned into a documented caveat — beats a quiet
  cleanup. And update the source of truth when reality outruns it (flag doc/README drift the moment
  a live run invalidates a claim).

## 4. Shared-host operations judgment

- **Soft caps for humans, hard caps for machines.** On a shared interactive host use `MemoryHigh`
  (throttle) without `MemoryMax` (kill); watch `memory.events` before ever adding a hard cap.
  A hard cap + `daemon-reload` applies to *running* sessions and can freeze logged-in users.
- **A full swap turns throttling into killing.** With swap exhausted the kernel can't spill, so a
  cap goes straight to hard-throttle/OOM-kill. Judge memory health by `MemAvailable` and swap
  in/out *rates*, not swap fill — a full swap of idle pages is a high-water mark, not an emergency,
  and `swapoff` drags those cold pages back into RAM and makes it worse.
- **Know what the memory IS before killing anything.** Dead junk vs live work present identically as
  "cgroup over limit." tmpfs `/tmp` is RAM wearing a filesystem costume: it survives `pkill -9`,
  charges the owner's cgroup, and can freeze their next login — the remedy is to delete the files,
  not kill processes. The opposite case (a slice full of a user's live work) has the opposite
  remedy: relax the cap, never kill. Read `memory.stat` / `findmnt -t tmpfs` before acting.
- **Unexplained kills under memory pressure are often `systemd-oomd`, invisible to the kernel OOM
  log.** The userspace OOM daemon SIGKILLs the highest-pressure cgroup and logs to the journal, so
  `journalctl -k` comes up empty. Also: measure actual per-VM RSS before estimating fleet footprint
  (demand-allocated is far below configured).
- **Size concurrency by measured host reality, not a RAM formula.** A formula reading only
  `MemAvailable` is blind to co-tenants, swap pressure, CPU/IO contention, and the
  configured-vs-demand-allocated gap. Run a small load-sampler during a pilot; treat swap collapse
  or capacity refusals as automatic no-go; remember a timeout-based harness converts host contention
  into *fake product failures*.
- **A monitor must not query the system it monitors in the hot path.** A status view that called the
  control plane under a 4 s timeout showed 0 live resources while several ran, because the busy
  plane answered in 4.7 s. Have the workload emit cheap state files at phase boundaries and render
  from those; treat any unavoidable live query's timeout as "unknown," never "none."
- **Legibility is a feature worth preserving deliberately.** A busy root-privileged service on a
  shared host will keep landing on other investigations' suspect lists (here: an empty `/etc/hosts`
  pointed straight at the rig). Readable units, sources, and configs made exoneration take minutes
  instead of days — that transparency is an asset, not just a nicety.
- **An agent living inside a session manager must assume env-based isolation can silently fall back
  to the real one.** With `$TMUX` set, tmux ignores `TMUX_TMPDIR`, so a "throwaway" server is the
  operator's real one — and `kill-server` in cleanup destroyed live sessions (including the one
  hosting the agent). Bind an explicit private socket (`tmux -L <unique>`), only ever
  `kill-session -t <name>`, and before killing any session/service check whether it hosts your own
  process. Standing rule: tests that exercise a real service manager (tmux/systemd/dbus) run ONLY in
  disposable containers/VMs with their own PID 1; the shared host gets fully-seamed offline tests.

## 5. KVM / libvirt / qemu / nested virtualization

- **Always emit an explicit `<cpu>` element (host-model/host-passthrough).** Without one, qemu's
  default CPU predates x86-64-v2 and EL9-family userspace panics at init (`Fatal glibc error: CPU
  does not support x86-64-v2`) — presenting as an SSH/DHCP timeout. Adding it took ssh-ready from a
  300 s timeout to 8 s.
- **The XML you define is not the XML you get back.** Live `virsh dumpxml` normalizes and mirrors
  devices (a serial `<log>` duplicated onto the paired `<console>`). Any count/shape validator of
  live XML must be written against observed live output, never the submitted template.
- **libvirt dynamic ownership chowns every disk a domain touches — including read-only shared
  backing files — to `qemu:qemu`, and does not reliably restore them.** Combined with umask-0077
  0600 artifacts, the management layer loses read access to its own base images. libvirt rewrites
  the OWNER but preserves group+mode, so the surgical immunity is group ownership + group perms
  (backing 0640, overlays 0660, group `qemu`); `dynamic_ownership=0` is a host-wide hammer. Note
  `qemu-img check -U` addresses locks, not permissions — read the real errno before choosing.
- **When a privileged daemon hard-codes restrictive file modes, pre-create the inode and have it
  append.** virtlogd creates console logs 0600 root:root (hard-coded in source — no config knob);
  pre-creating a service-owned file plus `<log ... append='on'>` keeps ownership. Reading the
  daemon's source is the cheapest way to answer "is this configurable?" before burning live
  experiments.
- **PTY consoles persist nothing** — a post-mortem "dump console" over a pty is structurally empty.
  Configure `<serial><log file=.../>` and bake `console=ttyS0` into the image (cloud-init applies too
  late to capture first boot). Build console capture BEFORE running a VM matrix: "ssh never came up"
  is a catch-all symptom, and a serial transcript root-causes it in minutes.
- **libguestfs as a non-login service identity needs `LIBGUESTFS_BACKEND=direct`** (no
  session/dbus/XDG under `sudo -u` → the default backend tries `qemu:///session` and dies
  generically). Know `libguestfs-test-tool` — it bisects environment-vs-code in seconds. The
  `libvirt` backend runs the appliance qemu as a *different* uid, so 0700 temp trees break it:
  switching backends changes the security principal, not just the launch mechanics. And the
  appliance is not a chroot — it substitutes/read-only-mounts the guest's `/etc/resolv.conf`
  (scripting it fails EROFS and can abort the bake); configure network facts at first boot instead.
- **The same generic error string has distro-specific root causes — never cache "the" cause.**
  `supermin exited with error status 1` was, on one distro, `RestrictSUIDSGID=yes` on the calling
  systemd unit blocking supermin's setuid appliance files (bisected in two commands with
  `systemd-run -p RestrictSUIDSGID=yes/no ... libguestfs-test-tool`); on another, `/boot/vmlinuz-*`
  shipped 0600 so the non-root builder couldn't read the kernel (fix:
  `dpkg-statoverride --add root root 0644 /boot/vmlinuz-$(uname -r)`, re-applied per kernel).
  `LIBGUESTFS_DEBUG=1 LIBGUESTFS_TRACE=1` gets the real error past the generic footer.
- **When a library selects a helper binary by probing PATH + exit codes, override it with a scoped
  PATH shim speaking the probe protocol.** A tiny shim exiting the "unavailable" code forces the
  fallback per-process, reversibly and upgrade-safe — better than renaming/diverting system binaries
  (still the right one-shot *diagnostic* lever). Shim gotcha: "record then exec" never returns — run
  the real binary as a child and wait.
- **The first SSH connection to a freshly booted VM can be accept-then-reset** — a capability probe
  must retry the transport and distinguish "couldn't ask" from "asked and got no."
- **Self-similar nesting guarantees address-space collisions.** A system installed inside its own
  guest collides with the outer layer's hardcoded subnet; every layer needs a distinct subnet, and a
  renumber must sweep every value *derived from* the old address (a pinned CIDR stopped an install
  after the bridge itself was renumbered). Provide a parameter or documented collision override, or
  the installer can never be tested inside its own guests. Dogfood guests built by the product are
  pre-contaminated with its own dependencies, so coexistence/refuse-to-clobber guards fire where a
  clean host's wouldn't — use the designed force paths, and remember service users can't exec from
  0550 `/root` (use root-owned, world-traversable `/opt`).
- **No `/dev/kvm` for the automation identity? A rootful container with the real userspace toolchain
  is the cheap dogfood** — real qemu-img/nft/squid/cloud-localds caught integration bugs invisible
  statically. Define the hardware-dependent acceptance bar honestly (e.g. "installer + service
  manager + doctor + can-define-domain proven; actually booting the nested guest best-effort").
  `/dev/kvm` is deliberately 0666 on some distros (so rootless virt works); tighten with a udev rule
  + group only if your threat model needs it, knowing it breaks other rootless-virt users.

## 6. Cloud images and golden-image pipelines

- **Vendor cloud images ship near-full, tiny virtual disks** (~2 GB, 94% used). Make disk size a
  first-class build parameter; `qemu-img resize` the download AFTER checksum verification (the
  upstream pin still validates the original bytes — no re-pinning) and BEFORE any bake/content-digest
  step; cloud-init growpart expands root on FIRST boot only, so create+boot flows can't grow later.
- **A content pin on a rolling URL is a time bomb, and a later mismatch is usually a vendor respin,
  not corruption** — the integrity gate refusing is the system working. Prefer dated immutable URLs;
  otherwise re-pin from the vendor's live `SHA256SUMS` (GPG-verify when a keyring exists) and word
  errors to distinguish tampering from republish. Per-vendor reality bites: filenames lie (a `.img`
  that is qcow2), Debian publishes only SHA512SUMS (convert locally), formats differ, `-latest`
  endpoints are flaky — a stable same-family release is a valid stand-in when consumers key on the
  family.
- **Digest disk images over the logical raw byte stream, not the container file.** qcow2 bytes vary
  with metadata/compression/allocation; `qemu-img convert -O raw -t none -T none` to stdout gives a
  stable, pure-userspace identity. And never boot an integrity-hashed image directly to validate it
  — direct boot mutates the digest; health-check via a disposable overlay, and capture any in-guest
  provenance BEFORE the sysprep scrub deletes it.
- **Forking a provisioned VM into a template is an identity problem, not a disk problem.** Scrub
  machine-id, SSH host keys, udev persistent-net, logs, history, AND `/var/lib/cloud` (or cloud-init
  never re-runs and clones share identity) — verified per distro family. But never run
  `virt-sysprep` with implicit defaults on an installed-state image: the default op set scrubs the
  rpm-db and corrupts the package database — use an explicit operation allow-list.
- **Baking packages into an image flips runtime-state assumptions.** Distro systemd presets enable
  services at install time and the image flow adds a reboot, so every clone boots with the service
  *running* where the old install-at-provision flow observed "inactive" by timing luck (blast radius
  once: 40/64 scenarios). Fixtures must construct the state they assert; sweep all assume-default
  checks whenever the base image changes; "package absent" fixtures need per-image verification
  (removal can cascade through protected deps and brick the guest).
- **Artifacts registered into a store are keyed by the build-time environment.** A golden built
  before the real install registered under dev paths and was invisible to the installed system. The
  runtime warned — but the warning was TTY-gated, invisible in scripts. Make load-bearing warnings
  unconditional or hard errors; gate builds on a preflight.
- **ENOSPC during a big build corrupts innocent bystanders** (a disk-full bake truncated a
  concurrent `/etc/hosts` rewrite — collateral that looks like someone else's bug). Pre-check a
  free-space floor on EVERY filesystem touched (temp and destination are often different mounts);
  stage promotions in the destination directory so the final `mv` is a same-FS atomic rename; a
  cloud-init NoCloud seed is just ISO-9660 labeled `cidata`, so `genisoimage -volid cidata`
  substitutes for `cloud-localds` where cloud-utils isn't packaged.
- **Rotating a baked-in trust anchor cascades into artifact rebuilds.** Adding an HTTPS mirror and
  re-applying egress can rotate the cache CA, and every golden built before the rotation stops
  trusting the proxy — so batch all allowlist edits + one reapply FIRST, then build all goldens.
  Any trust anchor embedded in immutable images makes every CA change a rebuild plan.

## 7. Networking under deny-by-default egress

- **A packet must survive EVERY base chain on an nftables hook.** Your `accept` at priority 0 can't
  override another manager's REJECT at higher priority; on firewalld hosts libvirt bridges join the
  `libvirt` zone with a trailing reject, so guest→host-service traffic needs explicit *permanent*
  rich rules. Fastest attribution: instant refusal = active REJECT somewhere; full timeout = silent
  drop. `firewall-cmd --reload` discards runtime-only interface-to-zone bindings — make bindings
  permanent and re-verify. Ship the exact verified rules in the runbook; never let docs claim LIVE
  for a path a common host firewall disables.
- **Own exactly one named nft table on shared hosts** — re-assert atomically via delete-table/re-add
  scoped to your own table, key rules to your own interfaces, keep foreign-traffic policy accept. A
  periodic re-assert that did `flush ruleset` would destroy every other subsystem's rules each tick.
- **Machine-readable state in a rule engine must live in constructs the engine round-trips.** nft
  `#` line comments are NOT preserved by `nft list ruleset`; a real `comment "..."` attribute is —
  prove round-tripping on the real engine, and when a probe later reports the marker "lost," suspect
  the probe first.
- **Deny/allow lists fail in both directions, and can be wrong at the engine's internal
  representation.** Squid stores IPv4 as IPv4-mapped IPv6, so a "completeness" deny of `::ffff:0:0/96`
  blocked ALL IPv4. Conversely allowlists drift too narrow (a shipped mirror allowlist omitted the
  image hosts the shipped recipes fetch from). Validate every list change behaviorally on the real
  engine WITH a positive legitimate-traffic test; add consistency checks that derive the required
  destination set from the consuming artifact; pin incidents with "this entry must stay out"
  regression tests; first-match engines mean allow entries must precede deny/terminate rules.
- **A drop-in config is worthless if the main config never includes it.** A stock `squid.conf` with
  no `conf.d` include left a security policy silently inactive while file-inspection tests passed —
  prove the engine LOADED your policy with live positive AND negative requests.
- **Constraining a MITM/ssl-bump CA with NameConstraints must account for the origin's cert shape.**
  The proxy mints leaves mimicking origin SANs; real mirrors use wildcard SANs that violate
  exact-FQDN permitted subtrees (OpenSSL error 47) for a whole mirror family. Constrain at the
  registrable-domain level or mint SNI-exact leaves.
- **Layered network failures unmask one at a time** — a CA bug was invisible until a firewall bug
  was fixed (no handshake → TLS never attempted). Plan serial fix-and-retest, and make reachability
  self-tests exercise the full application path consumers use (a real fetch through the real
  proxy/TLS), not a bare TCP connect.
- **Guests behind an allowlist proxy need their package plumbing rewritten.** Package managers
  default to metalink/mirrorlist indirection that returns arbitrary mirrors an allowlist blocks —
  and a MirrorBrain-style redirector's 302 escapes the allowlist entirely (an allowlist entry is
  useless if the mirror redirects off it). Pin concrete allowlisted mirror hosts, remove stock
  metalink repos, seed `proxy=` at first boot, disable DNS at the network definition when the fence
  is IP/proxy-based. Model build-time and run-time egress as separate planes. In proxy-only guests
  (no default route, no NAT) every client must be proxy-aware and SNI-gated splice means egress
  policy is hostname policy — IP literals fail by design.
- **Ephemeral VMs on a recycled DHCP pool poison TOFU known_hosts** — intermittent, target-random
  `REMOTE HOST IDENTIFICATION HAS CHANGED`. Use `-o UserKnownHostsFile=/dev/null -o CheckHostIP=no`
  for disposable targets, at every callsite.
- **On isolated / deny-by-default networks, "wait for network online" units stall boot for their
  full timeout** even though the lease arrived (newer releases enforce it harder). Declare
  interfaces `optional: true` / `RequiredForOnline=no` when "has a lease" suffices.
- **Shared-DHCP etiquette:** dnsmasq keys leases by MAC (release/renew re-leases the same IP — no
  "new IP" simulation); the ping conflict-check protects only dynamic allocations (an in-pool static
  squat eventually breaks someone else's box); L2 port isolation is not DHCP-scope isolation; static
  experiments go strictly outside the pool, coordinated. And route automated third-party-API traffic
  through a dedicated disposable egress IP — reputation penalties land on an address you can burn.

## 8. SELinux and cross-distro portability

- **Files carry the label of where they were staged, not where they land.** Trees authored in agent
  homes / container-mounted dirs carry `container_file_t` or `user_tmp_t`; copied into `/opt` they
  produce systemd `status=203/EXEC` crash-loops (exec denial by label — the file is present and
  executable). `ls -Z` is the first check on any post-deploy crash-loop; `restorecon -RF` (guarded
  with `command -v restorecon` for SELinux-less distros) belongs in EVERY deploy/update runbook.
- **SELinux denials can be invisible AND untestable as root.** A service failing to read pushed
  files may be a dontaudit'd denial (`ausearch` shows "no matches"), and root/unconfined validation
  proves nothing about the service domain. Diagnose with `ls -Z` plus the service's own start path;
  "passes as root, fails as the service" is its own failure class. The first-contact playbook:
  delete wrong-labeled runtime files so the domain's type-transition recreates them correctly;
  remember `restorecon` only applies labels the loaded policy maps (on an unmapped path it silently
  fixes nothing); discover real type names via `semanage fcontext -l | grep`, never guess; most
  durable is to place service data at paths the stock policy already labels correctly.
- **Filesystem-permission invariants are distro-specific.** Debian ships `/var/log` as
  `root:syslog 2775` on purpose; a guard asserting "ancestors root-owned, non-group-writable" blocks
  every Debian-family install. Refine a principled relaxation (group-write only for gid<1000 system
  groups with no human members, fail closed) or relocate to a path where the strict invariant holds
  — never silently weaken the guard.
- **Run platform detection before environment validation.** A validator that runs before the
  detection step that relocates paths encodes the home platform's layout and refuses every other
  distro — a bug that only surfaces on the second OS, so run installers on a second OS early.
- **Resolve a package list against a new release in ONE pass, expecting virtual/renamed packages.**
  `qemu-kvm` is virtual on newer Ubuntu (`qemu-system-x86`); pick substitutes that hold across the
  whole family. Family splits collected the hard way: Debian needs `squid-openssl`, `nologin` is in
  `/usr/sbin`, the qemu group is `libvirt-qemu`, EPEL needs a pinned baseurl, el9 has no cloud-utils
  at all. Split dependencies into mandatory-everywhere vs family-best-effort, verified against each
  family's real resolver.
- **`systemd Type=notify` readiness is time-bounded and load-sensitive** — a healthy daemon on a
  busy host can miss its window and fail with `result 'protocol'`. Retry on the failure *category*
  (unit start timeout, bounded count), not on one previously-seen error string.
- **`runuser -l` dies on nologin service accounts; `sudo -u user cmd` works and gets fresh groups.**
  Any command your tool prints for operators is product surface — execute it once as part of
  acceptance.
- **Installers must treat every named host resource as potentially foreign.** Detect ownership via
  explicit markers (bridge names, a daemon's single config file, state dirs); refuse by default with
  the exact remedy in the message; gate takeover behind an explicit flag that backs up the original
  and restores it on uninstall; fail closed on unreadable state during destructive teardown; offer a
  partial reapply mode; print residual operator obligations (fresh login for groups) in the DONE
  banner.

## 9. Bash and shell footguns (each cost real time)

- **RETURN traps are not function-scoped** — a `trap ... RETURN` fires on the return of every
  ancestor on the call stack, and single-quoted bodies re-evaluate in whatever scope is live then
  (→ `unbound variable` under `set -u` on healthy cold-start paths). Use explicit rc-preserving
  cleanup at each return, or a `flock <cmd>` wrapper process; verify subtle shell semantics with a
  NESTED-caller test, not just the sequential case.
- **`local a="$1" b="...${a}..."` is unbound under `set -u`** — bash expands all arguments of `local`
  before any assignment. Split declarations, then grep the tree for the whole class.
- **Verify what your `die()` does** — `x || die` is a fail-open no-op if the helper *returns* (or
  exits only a subshell). And `set -e` has transitive exemption zones: a command on the left of
  `||`/`&&`/`if` suspends errexit for it and everything it calls, and `local v=$(...)` masks the
  substitution's exit status. Audit these as classes.
- **`grep -q` under `pipefail` eats producers via SIGPIPE** (exits at first match → producer SIGPIPE
  → exit 141 → pipeline "fails" on a positive match). Probes must drain stdin
  (`awk '$0==x{f=1} END{exit !f}'`). And `grep -c` prints `0` AND exits 1 on no-match — `|| echo 0`
  doubles the output.
- **bash caches executable paths per shell** — after removing/reinstalling a binary mid-script,
  `command -v` lies until `hash -r`; fresh shells never reproduce it. Prefer package-manager or
  stat-based existence checks in long-lived provision shells.
- **bash ≥5.2: `&` in a `${var//pat/repl}` replacement means "the matched text"**
  (patsub_replacement, default on) — an entity escaper produced `<lt;` instead of `&lt;`. Write `\&`
  or `shopt -u patsub_replacement`.
- **`interpreter <<'EOF'` and "the program also reads data from stdin" are mutually exclusive** — the
  heredoc consumes stdin (a bridge dropped 100% of messages with no error). Pass code via file/fd/-c
  and reserve stdin for payload. Relatedly, anything that greps source for structural markers
  (heredoc openers, fence markers) matches them inside comments and strings — including the comment
  documenting the extractor itself; use unique per-block delimiters.
- **sqlite3 in shell:** double-quoted tokens are IDENTIFIERS (single-quote all string literals);
  value-returning PRAGMAs (`busy_timeout`) echo into stdout and corrupt parsed results — use the
  silent `.timeout` dot-command. When a CLI's stdout is your data plane, audit every setup statement
  for incidental output.
- **`mv -f tmp dest` silently moves INTO `dest` if it is a directory** (a "successful" corrupted
  publish) — atomic-publish helpers use `mv -Tf`. Command substitution and every pipeline stage fork
  subshells, so global state mutated there evaporates — accumulate in the main shell, pass bulk data
  via temp files/fds. Never edit a script a running bash is executing (it streams by byte offset —
  stage a `.next` and swap). Modern scp is SFTP-mode: embedded remote-path quotes become literal
  filename characters.
- **systemd Exec lines have their own `$` expansion** — bare `$name` expands (to empty if unset)
  before the shell sees it; digit-led `$1` survives literally. Never trust a unit's shell one-liner
  without running it under real systemd, and `systemctl start` on an already-active unit silently
  no-ops (updated code needs `restart`).
- **Env-knob precedence, done safely:** source a config file before `: "${VAR:=default}"` defaults so
  file beats code-default and explicit env beats file — but that makes ambient env authoritative (an
  injection surface for root-run tools), so provide a `TEST_SEAMS=1` escape that skips it (tests must
  not inhale system config) and inventory every var before wrapping the tool in `env -i`.
- **Canonical-JSON hashing needs a real spec:** jq `-S` sorts keys only at final serialization
  (key-sort recursively before deriving any array order key); argv-like arrays are order-semantic
  (sorting merges distinct commands); improvised numeric folding introduces IEEE collisions; and
  `2>/dev/null` on the left of a non-pipefail pipe can hash invalid/empty input to sha256-of-empty
  with exit 0 — fail closed on invalid AND empty, and test for the well-known empty hash explicitly.
- **In errtrace/bats frameworks, a bare command whose point is a nonzero exit aborts the test before
  the assertion** — capture via `rc=0; cmd || rc=$?` or the framework's `run`. Pipes return the
  FILTER's exit code (`cmd | tail` hides mid-run failures — redirect to a log and read the real
  code). Tools that resolve ids to names (getfacl, ls, ps) break numeric matching — force numeric
  (`getfacl -n`).

## 10. Session, harness, and review craft

- **`pkill -f <pattern>` in a wrapping harness matches its own and sibling wrappers.** The harness
  wraps every background command in an `eval`ing shell, so the pattern string is present in the argv
  of every sibling AND the cleanup's own shell — one `pkill` killed its parent and siblings mid-run
  while the detached children survived and kept spawning work. Stop process trees by recorded
  PID/PGID (kill the launcher first so no retry fires, then TERM the group), and never conclude an
  external culprit from timing correlation without a positive demonstration.
- **Cleanup must be ownership-scoped and layered, and SIGKILL is uncatchable.** Any foreground runner
  living under a supervisor with a hard timeout WILL be SIGKILLed mid-lifecycle — so run long
  create/run/destroy cycles in the background, scope destroy-on-interrupt to only resources *this
  run created* (never reused ones), fire on EXIT/INT/TERM/HUP, document that SIGKILL escapes all
  traps, and keep a list-audit + a server-side TTL reaper as the real backstop. (A trap firing on a
  timeout once destroyed a healthy resource under a retry; a kill no trap could catch leaked one —
  the reconciled answer is scoped + layered, not "traps good/bad.")
- **Chat is not storage: persist everything of value the moment it's confirmed.** Long campaigns
  survive context exhaustion only via durable files (findings logs, status/checkpoint docs,
  per-round review state) plus a continuation prompt written BEFORE decay that lists the files in
  read order and the literal next command. Background tasks do not survive a session boundary and may
  leave no completion record — redirect their output to files and check for partial results before
  assuming completion. At resume, treat a handoff doc as a cache of when-written claims: revalidate
  mutable live-system facts before acting.
- **Background-task discipline:** rely on harness notifications, never busy-poll tracked jobs; DO
  sample a long run's earliest complete artifact ("verify early rather than burn two hours"); arm
  bounded event-watches (fast exit on signal + realistic timeout) for specific milestones; enumerate
  running background work in every status report.
- **A control API returns structured envelopes on success but RAW text on pre-envelope errors** —
  naive `json.load` blows up on `no guest IP` / usage strings. Wrap with a tolerant unwrapper.
  "Readiness = network up" is not "exec up" — poll the actual channel you will use. A file-transfer
  primitive is often single-file — tar directories first (excluding unreadable caches), and watch
  for shared tar roots colliding on extract. Confirm a streaming pull actually delivered (magic bytes
  / digest), since extra args may be silently ignored.
- **Stateless adversarial review loops never return zero findings** — each round independently
  samples a large latent pool, so "iterate until clean" is unreachable and "reviewer-clean" is the
  wrong stop condition. Terminate behaviorally: K consecutive clean rounds after the last change,
  rotating a *stated threat-model lens* per round (races/TOCTOU deserve a dedicated angle — a full
  TOCTOU class survived two GO verdicts), findings validated against CURRENT code before acting
  (stateless reviewers re-derive stale complaints and read diff `-` lines as current code). Make
  reviewers bucket MUST-FIX vs NICE-TO-HAVE and prove *reachability* under the actual threat model.
  Refuted findings become regression tests. One confirmed finding of a CLASS triggers a same-fold
  grep-and-fix of every instance (a fail-open pattern was re-introduced three times in later folds
  precisely because the class wasn't swept).
- **Close the class, don't patch the instance — especially for security gates.** A "find any bypass"
  review of a large surface (a whole domain XML) is unbounded whack-a-mole against a denylist; switch
  to a positive closed-shape proof (a device whitelist + a broad "no host reference beyond the
  intended files" sweep) that closes the whole class at once.
- **Verify the review payload before trusting any verdict** — reviewers happily review nothing (an
  empty diff from a commitless repo got a confident verdict). Inspect the pack before dispatch; pass
  prompts as files (shell-quoting through `bash -c`/`sg -c` layers corrupts them); curate per-provider
  size caps (an over-cap attachment degrades into hallucinated partial review); never resend a
  byte-identical pack; cheapest fault isolation for a failing provider is sending the identical pack
  to a second one; keep an agreed degradation ladder for outages.
- **Metered-LLM hygiene:** never spend a call on tooling self-tests or dummy prompts; wrappers get a
  `--dry-run` showing the exact would-be submission, pre-flight size validation, and per-attempt logs
  of the raw provider envelope. **Large fan-outs:** one agent per angle with an explicit output JSON
  schema → a per-finding adversarial refuter (prompted to DISPROVE, default-invalid when uncertain) →
  a completeness critic; every stage persisted to disk so API failures lose nothing and runs are
  resumable; orchestrator argument plumbing treated as untrusted; findings re-validated in the main
  context before fixing. Confirm scope as 2-4 closed options with a recommendation before firing —
  scope dominates cost and actionability.
- **A "simple" requirement can surface a real infrastructure decision — probe the assumption before
  building.** "Cache the official packages" assumed the master served cacheable HTTP; it forced
  http→https, so caching it required SSL-bump (MITM-ing the guest's TLS with a baked-in CA), not a
  one-line pin.
- **Migrate through zero when a capture/replay invariant changes representation.** A clean
  uninstall + reinstall beats an in-place upgrade when semantics changed underneath (old code
  reverses its own grants with matching logic; the new version builds fresh baselines) — an in-place
  hop could strand state the new code can't undo.
- **De-narrate long-lived artifacts:** rewrite comments and test names that reference review
  rounds/chronology into the constraint + failure mode ("a doc-wide regex would count an ip planted
  inside metadata"), keeping provenance CLASS (tested / live-incident), dropping the history.
  **Operator ergonomics is a feature:** any step silent for minutes needs stage-numbered, timestamped
  progress lines with the slow phase annotated, or humans kill healthy jobs and re-run
  non-idempotent ones.

---

*Distilled from this project's build, review, and live-verification history and this repo's
`LESSONS-LEARNED.md`. Companion to the project-specific retro.*
