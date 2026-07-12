#!/usr/bin/env bash
# dr_vps_gate.sh -- Phase-2 store-gate: the SINGLE authorization choke point the watcher
# (and reaper) call before ANY virsh/ssh/scp on an agent-named VM. It binds the live libvirt
# domain to the store identity by UUID + disk + backing (not just name), so a stale/plausible
# row can never let an op hit an UNRELATED same-named domain. ASCII only; set -uo pipefail safe.
# See CONCEPT.md (agent control loop).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_storage.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_storage.sh"   # _dr_vps_safe_id, path_fence (+ store)
. "$(dirname "${BASH_SOURCE[0]}")/dr_vps_net.sh"       # dr_vps_net_create_guard

_dr_gate_virsh() { LC_ALL=C "$DR_VIRSH" -c "$DR_LIBVIRT_URI" "$@"; }   # locale-proof (translated output)
_dr_gate_xpath() { printf '%s' "$1" | "$DR_XMLLINT" --xpath "$2" - 2>/dev/null; }
# FAIL-CLOSED count(): xmllint prints a number on a compiled count() and NOTHING (nonzero rc) when
# the XPath fails to COMPILE (e.g. an apostrophe in a spliced path breaks the string literal).
# The raw helper + `${x:-0}` would turn that empty into 0 -> a closed-shape guard passes OPEN
# Here a non-numeric/empty result becomes the sentinel "ERR", which fails every
# downstream `= 0` / `-ge 1` / `-le 1` / numeric-equality guard closed.
_dr_gate_count() { local o; o=$(_dr_gate_xpath "$1" "$2"); case "$o" in ''|*[!0-9]*) printf 'ERR' ;; *) printf '%s' "$o" ;; esac; }

# dr_vps_gate_vm <mode> <id>  (mode = lifecycle | guestexec | closedshape)
#   closedshape = "SAFE TO BOOT" -- the guestexec structural sweep run on the DEFINED (--inactive) domain,
#   called post-define/pre-start (Stage-0.C). Shares the sweep with guestexec so they cannot drift.
# echoes a TRUSTED tuple "overlay|domain|uuid|net|aid" on success, or dies (14/15/18/24).
dr_vps_gate_vm() {
  local mode="${1:-}" id="${2:-}" net
  case "$mode" in lifecycle|guestexec|closedshape) ;; *) dr_vps_die "$DR_VPS_E_USAGE" "gate: bad mode '$mode'"; return $? ;; esac
  # 1. id is a safe filename component AND must not start with '-' (CLI-option-injection fence).
  _dr_vps_safe_id "$id" || return $?
  case "$id" in -*) dr_vps_die "$DR_VPS_E_USAGE" "gate: id must not start with '-': $id"; return $? ;; esac
  # 2. the id must be a registered rig VM.
  local row overlay aid egen uuid state rownet _grc
  row=$(dr_vps_store_vm_gaterow "$id"); _grc=$?
  # A transient store READ FAILURE is infra (retriable), NOT a permanent NOTFOUND. Reserve
  # NOTFOUND for a SUCCESSFUL empty read (genuinely-absent VM). Both fail closed; this just gives the agent the
  # right retry semantics instead of a permanent-looking "not a registered rig VM" on a transient SQLite fault.
  [ "$_grc" -eq 0 ] || { dr_vps_die "$DR_VPS_E_GENERIC" "gate: store read failed for '$id' (transient) -- refusing"; return $?; }
  [ -n "$row" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "gate: '$id' is not a registered rig VM"; return $?; }
  # shellcheck disable=SC2034  # egen/state parsed positionally; not all fields used downstream
  IFS='|' read -r overlay aid egen uuid state rownet <<<"$row"
  { [ -n "$overlay" ] && [ -n "$aid" ]; } || { dr_vps_die "$DR_VPS_E_GENERIC" "gate: incomplete store row for $id"; return $?; }
  # Validate against the VM's RECORDED net: the NIC/egress proofs below must key to the net
  # this VM was created on -- the same net recreate re-renders with -- NOT the watcher's current env
  # DR_VPS_RIG_NET, else a VM on a non-default net desyncs (gate refuses its own valid domain). Legacy
  # rows (NULL net) fall back to the env default, exactly as recreate does.
  net="${rownet:-${DR_VPS_RIG_NET:-simnet}}"
  case "$net" in ''|.|..|-*|*[!A-Za-z0-9_.-]*) dr_vps_die "$DR_VPS_E_USAGE" "gate: bad recorded net '$net' for $id"; return $? ;; esac
  # 3a. overlay must be pool-fenced; the registered golden must exist.
  local fov golden gback
  fov=$(dr_vps_storage_path_fence "$overlay") || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: overlay not pool-fenced: $overlay"; return $?; }
  golden=$(dr_vps_store_image_get "$aid")
  { [ -n "$golden" ] && [ -f "$golden" ]; } || { dr_vps_die "$DR_VPS_E_NOTFOUND" "gate: registered golden missing for $aid"; return $?; }
  # 3b. LIVE-DOMAIN IDENTITY: dump the live domain XML and bind it to the store row by parsing
  # it STRUCTURALLY (xmllint XPath, not grep-as-XML -- a substring match can be fooled by a
  # secondary disk or an extra device).
  dr_vps_have "$DR_XMLLINT" || { dr_vps_die "$DR_VPS_E_CAP" "gate: xmllint required for the structural XML checks"; return $?; }
  local xml lvuuid pdisk          # gback already declared above
  # closedshape (Stage-0.C) gates the DEFINED, not-yet-running domain -> dump the INACTIVE config (what will
  # boot); guestexec/lifecycle dump the running domain. The SAME structural sweep runs on both (shared helper).
  if [ "$mode" = closedshape ]; then xml=$(_dr_gate_virsh dumpxml --inactive "$id" 2>/dev/null)
  else                               xml=$(_dr_gate_virsh dumpxml "$id" 2>/dev/null); fi
  [ -n "$xml" ] || { dr_vps_die "$DR_VPS_E_LIBVIRT" "gate: no libvirt domain '$id'"; return $?; }
  #  - the PRIMARY disk (the FIRST <disk device='disk'> ELEMENT) must be file-backed AND its source
  #    MUST be the fenced overlay. NB: `(...disk/source/@file)[1]` picks the first @file across ALL
  #    disks -- a foreign primary (nbd/block, no @file) with the overlay attached SECOND would then
  #    bind. Anchor to the first disk ELEMENT's source, and require it be type='file'.
  local ptype
  ptype=$(_dr_gate_xpath "$xml" "string((/domain/devices/disk[@device='disk'])[1]/@type)")
  pdisk=$(_dr_gate_xpath "$xml" "string((/domain/devices/disk[@device='disk'])[1]/source/@file)")
  { [ "$ptype" = file ] && [ "$pdisk" = "$fov" ]; } \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: live primary disk (type=$ptype src=$pdisk) is not the file-backed store overlay"; return $?; }
  #  - the overlay's backing must be exactly the registered golden (-U: golden may be VM-locked) AND the
  #    overlay must have NO external qcow2 data-file. Same hidden host-file channel the golden_digest
  #    already rejects (dr_vps_identity.sh): an overlay built with `-o data_file=/host/...` reports the
  #    expected backing-filename but backs guest I/O with a host path INVISIBLE to the XML @file sweep.
  local _ovinfo _ovdf
  _ovinfo=$("$DR_QEMU_IMG" info --output=json -U "$fov" 2>/dev/null)
  gback=$(printf '%s' "$_ovinfo" | jq -r '."backing-filename" // ""')
  _ovdf=$(printf '%s' "$_ovinfo" | jq -r '."format-specific".data."data-file" // ""')
  [ "$gback" = "$golden" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "gate: overlay backing ($gback) != registered golden"; return $?; }
  [ -z "$_ovdf" ] || { dr_vps_die "$DR_VPS_E_VERIFY" "gate: overlay has an external data-file ($_ovdf) -- hidden host storage channel"; return $?; }
  #  - UUID identity, with the DETERMINISTIC legacy (NULL-uuid) policy:
  lvuuid=$(_dr_gate_xpath "$xml" "string(/domain/uuid)" | tr -d '[:space:]')
  if [ -n "$uuid" ]; then
    [ "$lvuuid" = "$uuid" ] || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: live UUID != stored UUID for '$id'"; return $?; }
  else
    [ "$mode" = lifecycle ] || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has no recorded UUID -- recreate before guest-exec"; return $?; }
  fi
  # 4. guestexec ADDS a CLOSED known-safe shape proof. The rig template is minimal (one overlay
  # disk[device=disk], one file cdrom seed, one simnet interface, pty serial+console). Rather
  # than chase device classes one at a time, prove a POSITIVE bound on every channel a guest
  # could use to reach the host/fleet/net or host data.
  if [ "$mode" = guestexec ] || [ "$mode" = closedshape ]; then
    local nics simnics nonallowed qns hostref hostconn alldisks nfile ndisk nother ncdrom badcdrom nonpty
    # PARSE-SUCCESS SENTINEL: the closed-shape counts use ${x:-0} (fail-OPEN on empty). An unparseable
    # dumpxml makes every count empty -> 0=0 -> the proof would pass. Require count(/domain)==1 FIRST so
    # the whole proof fails CLOSED on a malformed XML (defence-in-depth; pdisk extraction also catches it).
    [ "$(_dr_gate_count "$xml" "count(/domain)")" = 1 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: unparseable/empty domain XML for '$id'"; return $?; }
    # Observability (console-log observability, Step 5): the ONE canonical per-VM console-log path -- the gate
    # computes it the SAME way the renderer/tail/cleanup do (id is _dr_vps_safe_id-fenced above). Spliced
    # into the XPaths below as a STRING LITERAL: a quote in the path breaks XPath COMPILATION so
    # _dr_gate_count returns the ERR sentinel and every downstream numeric guard fails CLOSED.
    local EXPECTED; EXPECTED=$(dr_vps_console_log_path "$id")
    # (a) net: every interface is type='network' on $net (no non-simnet egress) AND carries exactly one
    # <port isolated='yes'/>. Guest-to-guest L2 on the rig bridge is NOT nft-filtered (nft is L3) -- it
    # is enforced ONLY by libvirt bridge port isolation (rendered by dr_vps_domain.sh). A redefined
    # domain that drops <port isolated='yes'/> keeps identity/overlay/simnet but regains VM<->VM
    # reachability, so the gate must REQUIRE it, not just trust the renderer.
    nics=$(_dr_gate_count "$xml" "count(/domain/devices/interface)")
    simnics=$(_dr_gate_count "$xml" "count(/domain/devices/interface[@type='network'][count(source)=1][source/@network='${net}'][count(port)=1][port/@isolated='yes'])")
    { [ "${nics:-0}" -ge 1 ] && [ "${nics:-0}" = "${simnics:-0}" ]; } \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' not EXCLUSIVELY on '$net' with port-isolation (nics=$nics sim=$simnics)"; return $?; }
    # (b) POSITIVE device WHITELIST over EVERY /domain/devices/* element: only the rig-template
    # classes + benign libvirt auto-defaults are permitted. Anything else -- graphics, hostdev,
    # filesystem, vsock, channel, redirdev, smartcard, tpm, shmem, memory, sound, hub, parallel,
    # or any FUTURE host-facing device -- is refused by exclusion, not by a chase-list. Plus: no
    # element in the libvirt qemu: namespace (raw QEMU args, invisible to /domain/devices).
    # <emulator> is allowlisted -- libvirt AUTO-ADDS it to EVERY running domain's dumpxml (the QEMU
    # binary path; the rig template never emits it) -- but its path is then constrained below so a
    # tampered emulator binary cannot slip through under the allowlist.
    # <audio type='none'> is likewise a benign libvirt AUTO-DEFAULT on modern Fedora/qemu (a no-op,
    # host-less sound backend the rig template never emits). Allowed ONLY when type='none'; any other
    # audio type (pulseaudio/spice/...) IS a host audio channel and stays refused by exclusion.
    nonallowed=$(_dr_gate_count "$xml" "count(/domain/devices/*[not(self::disk or self::interface or self::serial or self::console or self::controller or self::memballoon or self::input or self::watchdog or self::emulator or (self::audio and @type='none'))])")
    qns=$(_dr_gate_count "$xml" "count(//*[namespace-uri()='http://libvirt.org/schemas/domain/qemu/1.0'])")
    { [ "${nonallowed:-0}" = 0 ] && [ "${qns:-0}" = 0 ]; } \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has a non-allowlisted/raw-QEMU device (extra=$nonallowed qemu-ns=$qns)"; return $?; }
    # CONSTRAIN the emulator path: it is a HOST binary path. A raw '/usr/' PREFIX test is traversal-
    # spoofable ('/usr/../../tmp/evil' starts with /usr/ but resolves to /tmp/evil), so CANONICALIZE the
    # path (realpath -m, lexical -- the binary need not exist on the gate host) and require the canonical
    # result under /usr/. Also at-most-one emulator (the rig template has exactly one).
    local nemu emu emucanon
    nemu=$(_dr_gate_count "$xml" "count(/domain/devices/emulator)")
    [ "${nemu:-0}" -le 1 ] 2>/dev/null \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has more than one <emulator>"; return $?; }
    emu=$(_dr_gate_xpath "$xml" "string((/domain/devices/emulator)[1])")
    emu="${emu#"${emu%%[![:space:]]*}"}"; emu="${emu%"${emu##*[![:space:]]}"}"   # trim surrounding whitespace
    if [ -n "$emu" ]; then
      emucanon=$(realpath -m -- "$emu" 2>/dev/null)
      case "$emucanon" in
        /usr/*) ;;
        *) dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' emulator path '$emu' does not canonicalize under /usr (host binary?)"; return $?;;
      esac
    fi
    # CONSTRAIN the watchdog ACTION: <watchdog> is allowlisted (libvirt AUTO-ADDS an itco watchdog on
    # q35), but action='dump' makes it a GUEST-TRIGGERABLE HOST WRITE (a guest memory dump to qemu.conf
    # auto_dump_path). Allow only guest-only actions (or none); refuse 'dump' or any future non-listed
    # action. The host-ref sweep can't catch this (a watchdog has no @file/@dev).
    local badwd; badwd=$(_dr_gate_count "$xml" "count(/domain/devices/watchdog[@action][not(@action='reset' or @action='poweroff' or @action='shutdown' or @action='pause' or @action='none' or @action='inject-nmi')])")
    [ "${badwd:-0}" = 0 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' watchdog action is not guest-only (host-write 'dump'?)"; return $?; }
    # CLOSE <disk> SUB-element host channels that the @file sweep misses because they are NESTED inside
    # the SINGLE allowed file disk: a <mirror> (live block-copy/commit JOB streaming guest blocks to a
    # network/host target) or ANY nested <host> / network-protocol <source> under a disk. The rig's
    # disks are plain file overlays over the golden -- no block job, no network source.
    # ...also any @path under a disk (a <reservations><source type='unix' path=.../> PR-helper host
    # socket, or any future path-bearing disk sub-element). The rig's disks reference files via @file
    # ONLY -- never an @path -- so a disk-scoped @path is always a host channel.
    local diskchan; diskchan=$(_dr_gate_count "$xml" "count(/domain/devices/disk/mirror) + count(/domain/devices/disk//host) + count(/domain/devices/disk//source[@protocol]) + count(/domain/devices/disk//@path)")
    [ "${diskchan:-0}" = 0 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' disk has a mirror/network-source/reservations host channel"; return $?; }
    # (b3) CLOSE the /domain/os BOOT surface -- direct-boot + firmware host paths (<kernel> <initrd>
    # <cmdline> <loader> <nvram> <dtb> ...) are TEXT nodes OUTSIDE /domain/devices, so the device
    # whitelist + @file sweep never see them. A tampered domain could boot a host kernel/initrd while
    # otherwise template-shaped. Positive proof: /domain/os may contain ONLY <type>+<boot>(+<bootmenu>);
    # any other os child (every host-path boot channel) refuses guest-exec.
    local osextra; osextra=$(_dr_gate_count "$xml" "count(/domain/os/*[not(self::type or self::boot or self::bootmenu)])")
    [ "${osextra:-0}" = 0 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has non-template /domain/os boot elements (direct-boot/firmware host path?)"; return $?; }
    # (b4) CLOSED TOP-LEVEL /domain SHAPE: prove EVERY direct child of /domain is a template element or a
    # benign libvirt auto-default. This closes -- by EXCLUSION, not a chase-list -- host/guest-affecting
    # subtrees OUTSIDE /domain/devices + /domain/os: <sysinfo>/<smbios> (host serial/uuid injection),
    # <memoryBacking> (host hugepage paths), <idmap>, <launchSecurity>, <bootloader>, etc.
    # Allow-set = template children (name/uuid/memory/vcpu/os/features/on_reboot/devices) + the elements
    # libvirt adds on define (currentMemory/resource/seclabel/cpu/clock/pm/on_poweroff/on_crash/metadata).
    # LIVE-ACCEPTANCE NOTE: if a real `virsh dumpxml` emits a BENIGN top-level child not listed here this
    # refuses-all (same class as the <emulator> fix) -- validate this allow-set against live KVM.
    local domextra
    domextra=$(_dr_gate_count "$xml" "count(/domain/*[not(self::name or self::uuid or self::title or self::description or self::metadata or self::memory or self::currentMemory or self::vcpu or self::cputune or self::resource or self::os or self::features or self::cpu or self::clock or self::on_poweroff or self::on_reboot or self::on_crash or self::pm or self::perf or self::devices or self::seclabel)])")
    [ "${domextra:-0}" = 0 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has a non-template top-level /domain element (host/guest-affecting subtree?)"; return $?; }
    # CONSTRAIN the two dangerous auto-added subtrees: <seclabel type='none'> DISABLES QEMU MAC
    # confinement; <cpu mode='host-passthrough'> exposes the bare host CPU. The rig uses neither.
    local badconf
    badconf=$(_dr_gate_count "$xml" "count(/domain/seclabel[@type='none']) + count(/domain/cpu[@mode='host-passthrough'])")
    [ "${badconf:-0}" = 0 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' disables QEMU confinement (seclabel type=none) or passes through the host CPU"; return $?; }
    # (b2) BROAD host-reference sweep -- closes host-facing SUB-shapes of allowed classes at once
    # (a class whitelist is not enough: e.g. <rng> egd/udp backend = egress, an ARBITRARY <serial><log
    # file> = controlled host write, <video> vhostuser/accel3d = host device). Refuse ANYWHERE in the
    # domain: a host network connection, a host accel/vhostuser backend, or any host path/dev/dir reference
    # OTHER than the overlay, the seed iso, or the ONE canonical console log (EXPECTED, node-scoped exempt
    # here + structurally proven in b2b below).
    local hostref hostconn
    hostconn=$(_dr_gate_count "$xml" "count(//source[@mode='connect']) + count(//*[@type='tcp' or @type='udp']) + count(//@accel3d) + count(//backend[@type] | //driver[@name='vhostuser'])")
    # @file: a real running-domain dumpxml carries the overlay's backing-chain golden in
    # <backingStore><source file='GOLDEN'/> -- that golden is ALREADY identity-bound above (gback ==
    # registered golden), so it is exempt alongside the overlay + seed. @dev: count only HOST-facing
    # device SOURCES (a host block-device disk), NOT the guest-side names libvirt emits everywhere
    # (<target dev='vda'>, <boot dev='hd'>, the NIC's <target dev='vnet0'>) -- counting those made
    # hostref>=3 for EVERY real VM and refuse-all'd guest-exec. (See tests/gate.bats faithful fixture.)
    # @tap/@vhost: a <backend tap='/host/...' vhost='/host/...'> on an otherwise-allowed network
    # interface OVERRIDES the host tun/tap + vhost device paths -- a host-reach channel through a
    # legal NIC. @tty: a host tty path -- BUT libvirt AUTO-ADDS a benign, libvirt-ALLOCATED
    # `tty='/dev/pts/N'` attribute to a pty <console>/<serial> (identical to its <source path>, which
    # is already exempt; the attr is output-only, an attacker can't point it at a host device). So
    # @tty on a pty console/serial is exempt; a @tty ANYWHERE ELSE is still a real host-tty channel.
    # The rig template emits none of the counted forms (the pty's host pts is a benign <source path>).
    # NB (Observability): the blanket `count(//log)` reject moved OUT of this sweep into the STRUCTURAL
    # console-log check below (a canonical <serial><log file=EXPECTED> is now allowed). Correspondingly the
    # @file sweep NODE-SCOPE-EXEMPTS EXPECTED but ONLY on the serial-pty log node -- an EXPECTED @file on a
    # disk/cdrom/other source is NOT exempt (the exemption must not be "any element referencing EXPECTED").
    # LIVE-FIX: exempt EXPECTED on the serial-pty <log> AND on its libvirt CONSOLE MIRROR (running dumpxml
    # duplicates the serial <log file=EXPECTED> onto <console type='pty'> -- see b2b). Still node-scoped: an
    # EXPECTED @file on a disk/cdrom/other <source> is NOT exempt (the exemption is not "any elem = EXPECTED").
    hostref=$(_dr_gate_count "$xml" "count((//@file)[. != '${fov}' and . != '${DR_VPS_SEED_DIR}/${id}-seed.iso' and . != '${golden}' and not(. = '${EXPECTED}' and parent::log[parent::serial[@type='pty'] or parent::console[@type='pty']])]) + count(//source/@dev) + count(//@dir) + count(//@evdev) + count(//@socket) + count(//@tap) + count(//@vhost) + count(//@tty[not(parent::console[@type='pty']) and not(parent::serial[@type='pty'])])")
    { [ "${hostconn:-0}" = 0 ] && [ "${hostref:-0}" = 0 ]; } \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' references a host path/connection beyond overlay+seed (conn=$hostconn ref=$hostref)"; return $?; }
    # (b2b) CONSOLE <log> STRUCTURAL EXCEPTION (console-log observability, Step 5): either NO <log> (old/pre-
    # observability VMs pass -> console-dump then returns "recreate to enable"), OR every <log> is canonical:
    # @file=EXPECTED and parented by a pty serial or its pty-console mirror (nbadlog=0), AND the ONE canonical
    # serial log exists (a single serial[@type='pty'], single target@port=0, single <log>@EXPECTED; ncanon=1).
    # Closes: a wrong @file, a no-@file <log>, a <log> on any non-serial/non-console device, and the cross-
    # target spoof (2 targets splitting the attrs -> count(target)!=1).
    # TWO deviations from the plan's literal XPath, BOTH found by the FIRST live guestexec (offline fixtures
    # were not faithful): (1) the running-domain serial target drops @type='isa-serial' (shows <target
    # port='0'/>), so match @port='0'+count(target)=1, not @type; (2) libvirt MIRRORS the serial <log> onto
    # the <console> view of serial0 -> count(//log)=2 for every real console VM, so the invariant is "no
    # NON-canonical log", not "exactly one log". tests/gate.bats _add_canon_log now reproduces BOTH.
    local nlog nbadlog ncanon nmirror
    nlog=$(_dr_gate_count "$xml" "count(//log)")
    if [ "${nlog:-ERR}" != 0 ]; then
      # LIVE-FIX (first-real-run): real libvirt MIRRORS the serial <log file=EXPECTED> onto the <console>
      # view of serial0, so count(//log)=2 for EVERY console VM -- the old "exactly one <log>" refused them
      # all. Correct invariant: EVERY <log> must have @file=EXPECTED AND hang off a pty serial OR its pty-
      # console mirror (nbadlog=0). A <log> with any other @file, no @file, or on any other device is a
      # controlled host-WRITE channel -> refuse.
      nbadlog=$(_dr_gate_count "$xml" "count(//log[not(@file='${EXPECTED}') or not(parent::serial[@type='pty'] or parent::console[@type='pty'])])")
      # POSITIVE proof the CANONICAL serial log exists: a single pty serial, single target@port=0, single
      # <log>@EXPECTED. Closes the cross-target spoof (count(target)!=1) and a console-only log (no serial),
      # and guarantees console-dump has a real serial log to read.
      ncanon=$(_dr_gate_count "$xml" "count(/domain/devices/serial[@type='pty'][count(target)=1][target[@port='0']][count(log)=1][log[@file='${EXPECTED}']])")
      # The ONE legit console MIRROR libvirt makes of serial0 (pty console, single target@port=0, single
      # <log>@EXPECTED). @port matched WITHOUT @type='serial' -- like the serial-target isa-serial drop, the
      # console target type is a libvirt-version detail; keying on it would risk another live refuse-all.
      nmirror=$(_dr_gate_count "$xml" "count(/domain/devices/console[@type='pty'][count(target)=1][target[@port='0']][count(log)=1][log[@file='${EXPECTED}']])")
      # ACCEPT ONLY the canonical serial0 log plus AT MOST its single console mirror: total logs == 1 + nmirror,
      # nmirror in {0,1}. TIGHTER than "no bad log": rejects an EXTRA pty serial/console
      # log=EXPECTED -- a shape libvirt never emits -- so two virtlogd producers can't alias the one console file.
      { [ "${nbadlog:-ERR}" = 0 ] && [ "${ncanon:-0}" = 1 ] \
        && { [ "${nmirror:-ERR}" = 0 ] || [ "${nmirror:-ERR}" = 1 ]; } \
        && [ "$nlog" -eq "$(( 1 + nmirror ))" ]; } \
        || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has a non-canonical console <log> (bad=$nbadlog canon=$ncanon mirror=$nmirror nlog=$nlog)"; return $?; }
      # FS TAMPER: once EXPECTED is XML-exempt, XML alone can't catch a post-create SYMLINK SWAP of the path
      # (-> a host-write channel). Require it not be a symlink on disk (prepare/tail also refuse symlinks).
      [ ! -L "$EXPECTED" ] \
        || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' console log path is a SYMLINK (host-write channel): $EXPECTED"; return $?; }
      # convergence r1 (defense-in-depth): the leaf check does not cover a PARENT-component symlink that
      # could relocate the trusted console root out of tree. The agent (drvpsctl, not qemu) cannot write the
      # drvps:qemu 0750 console dir so this is trust-bounded, but assert the dir itself is not a symlink too.
      [ ! -L "$DR_VPS_CONSOLE_LOG_DIR" ] \
        || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' console log DIR is a SYMLINK (relocated log root): $DR_VPS_CONSOLE_LOG_DIR"; return $?; }
    fi
    dr_vps_diag "gate: $id $mode console-log OK (nlog=${nlog})"   # metadata-only (SPEC-DIAG)
    # (c) CLOSED storage: ALL disks file-backed; device only disk|cdrom; EXACTLY one overlay
    # disk; and EVERY cdrom (the SET, not just the first) must be the expected seed iso, at most
    # one -- so a second host-readable cdrom cannot slip in.
    alldisks=$(_dr_gate_count "$xml" "count(/domain/devices/disk)")
    nfile=$(_dr_gate_count "$xml" "count(/domain/devices/disk[@type='file'])")
    ndisk=$(_dr_gate_count "$xml" "count(/domain/devices/disk[@device='disk'])")
    nother=$(_dr_gate_count "$xml" "count(/domain/devices/disk[not(@device='disk' or @device='cdrom')])")
    ncdrom=$(_dr_gate_count "$xml" "count(/domain/devices/disk[@device='cdrom'])")
    badcdrom=$(_dr_gate_count "$xml" "count(/domain/devices/disk[@device='cdrom'][not(source/@file='${DR_VPS_SEED_DIR}/${id}-seed.iso')])")
    { [ "${alldisks:-0}" = "${nfile:-0}" ] && [ "${ndisk:-0}" = 1 ] && [ "${nother:-0}" = 0 ]; } \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' storage shape not closed (disks=$alldisks file=$nfile overlay=$ndisk other=$nother)"; return $?; }
    { [ "${ncdrom:-0}" -le 1 ] && [ "${badcdrom:-0}" = 0 ]; } \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' cdrom set not closed (cdroms=$ncdrom bad=$badcdrom; must be <=1 == seed)"; return $?; }
    # (d) char: every serial AND console MUST be a pty (no tcp/udp/file/pipe/unix host paths).
    nonpty=$(_dr_gate_count "$xml" "count(/domain/devices/serial[not(@type='pty')]) + count(/domain/devices/console[not(@type='pty')])")
    [ "${nonpty:-0}" = 0 ] \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: '$id' has a non-pty serial/console (host path)"; return $?; }
    dr_vps_net_create_guard "$net" >/dev/null \
      || { dr_vps_die "$DR_VPS_E_EGRESS" "gate: egress policy not fresh for guest-exec on '$id'"; return $?; }
  fi
  dr_vps_diag "gate: $mode $id ACCEPTED (net=$net)"   # metadata-only (SPEC-DIAG); refusals are dr_vps_die'd
  printf '%s|%s|%s|%s|%s\n' "$fov" "$id" "$lvuuid" "$net" "$aid"
}
