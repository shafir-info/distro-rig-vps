#!/usr/bin/env bash
# nested-selftest.sh -- OPERATOR-RUN dogfood (see STATUS.md deferrals). Validate the dr-vps-setup
# installer by running it INSIDE a fresh VM the rig itself boots. This host has nested
# virt enabled (kvm_intel nested=Y), so the L1 guest can run KVM.
#
#     DRVPS_LIVE=1 tests/dogfood/nested-selftest.sh [distro]
#
# MANDATORY pass bar -- each step is labeled with WHO runs it, because identity is the point:
#   1. INSTALL (root, the documented operator path): the tree staged root-owned under
#      /opt/distro-rig-vps and dr-vps-setup --yes completes -- with the NESTED RENUMBER baked in
#      (the L1's own NIC sits ON the outer rig's 10.123.0.0/24, so the inner bridge MUST move:
#      DR_VPS_BRIDGE_IP=10.199.0.1 + the matching fleet cache_cidr patch + --force-squid for the
#      distro-shipped squid.conf the coexistence guard would otherwise refuse).
#   2. SERVICE USER (drvps via runuser): libvirtd active + `dr-vps doctor` passes. The host
#      capacity POLICY knobs are scoped down for a small L1 (DR_VPS_HOST_RESERVE_MB/
#      DR_VPS_DEFAULT_MEM_MB) -- the dogfood proves doctor's tooling/wiring checks, not host sizing.
#   3. SERVICE USER (drvps): a freshly RENDERED domain XML actually DEFINES against the L1's
#      libvirt (virsh define --validate) and undefines -- the "can define" bar is really exercised.
#   4. MEMBER (a NON-root drvpsctl+drvpsvc account created in the disposable L1): egress
#      add-splice over the socket -- SO_PEERCRED stamping, socket DAC, and the result ACL are
#      actually on the path -- then ROOT YES-gated `drvps-egress-approve apply` CLEANLY opens the
#      SPECIFIC host into the live policy (fleet.json + live squid.conf + squid healthy).
#   5. drvps-top: the publisher as drvps (LIVE sources + advancing seq) and the viewer as the
#      NON-root MEMBER.
# BEST-EFFORT (non-fatal, labeled in the log): the firewalld rich-rule check; booting a nested L2
# guest (tests/acceptance/live-fedora44.sh as drvps). The PASS line claims only the mandatory bar.
# PORTABILITY: ONE L1 distro per run (arg 1, default fedora44). Another family is a SEPARATE
# operator-run invocation (`DRVPS_LIVE=1 tests/dogfood/nested-selftest.sh centos9`); a single PASS
# line never implies multi-distro coverage. PROVEN passing (2026-07-16): ALL FIVE goldens --
# fedora44, centos9 (el9, via the genisoimage seed fallback + pinned EPEL), and ubuntu22/24/26 (on
# 12GB goldens built via the recipe `disk_size` field -- the stock ~2-3.5GB ubuntu cloud golden is
# too small for the ~900MB rig install; `disk_size` grows it and cloud-init growpart expands root).
#
# SAFETY (finding: a leaked/hung run on the shared host): the L1 VM is owner-scoped and destroyed on ANY exit via
# a trap installed BEFORE creation; every remote/create/destroy step is time-bounded (SSH ConnectTimeout +
# ServerAlive + an outer `timeout`); the source archive is a per-run mktemp removed by the trap.
#
# NOTE: a cheaper proxy for the NON-KVM wiring is `tests/release-gate.sh --container`; this adds real-KVM.
set -uo pipefail
[ "${DRVPS_LIVE:-}" = 1 ] || { echo "set DRVPS_LIVE=1 to run the nested dogfood (needs KVM)"; exit 0; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DR="$ROOT/bin/dr-vps"
KEY="${DRVPS_TEST_KEY:-$HOME/.ssh/drvps_vm_ed25519}"        # PRIVATE key (ssh/scp -i)
PUBKEY="${DRVPS_TEST_PUBKEY:-${KEY}.pub}"             # PUBLIC key (cloud-init --ssh-key)
export DR_VPS_SSH_KEY="$KEY"
GUEST_DISTRO="${1:-fedora44}"
INNER_BRIDGE_IP="10.199.0.1"                          # the nested renumber (see pass-bar note 1)
MEMBER="dogfoodagent"                                 # the NON-root member fixture inside the disposable L1

fail() { echo "DOGFOOD FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }

# SAFETY trap installed BEFORE any resource is created: destroy the L1 (if created) + remove the archive on ANY
# exit. ID/ARCHIVE start empty so cleanup is a safe no-op if we fail before they are set.
ID=""; ARCHIVE=""
cleanup() {
  [ -n "$ID" ] && timeout 120 "$DR" destroy "$ID" >/dev/null 2>&1
  [ -n "$ARCHIVE" ] && rm -f "$ARCHIVE"
  return 0
}
trap cleanup EXIT INT TERM

step "boot an L1 guest ($GUEST_DISTRO) with nested virt"
ID=$(timeout 300 "$DR" create dogfood-l1 "$GUEST_DISTRO" --net simnet --cpus 2 --mem 4096 --ssh-key "$PUBKEY") || fail "L1 create"
timeout 320 "$DR" wait "$ID" 300 || fail "L1 not ready"
IP=$(timeout 30 virsh -c qemu:///system domifaddr "$ID" | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
[ -n "$IP" ] || fail "no L1 IP"
# ConnectTimeout + ServerAlive bound a wedged transport; each command is ALSO wrapped in an outer `timeout` so a
# STUCK remote command (installer/package manager) can never hang the run (ServerAlive only covers a dead link).
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no
     -o IdentitiesOnly=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -i "$KEY" "root@$IP")
timeout 30 "${SSH[@]}" 'test -e /dev/kvm' || fail "no nested /dev/kvm in the L1 guest (check kvm_intel nested=Y)"

step "stage the rig ROOT-OWNED under /opt + run the installer (nested renumber + --force-squid baked in)"
ARCHIVE=$(mktemp --suffix=.tgz)                                       # per-run (no fixed /tmp path -> no stale/races)
# --transform pins the archive's root dir to the CANONICAL install name, whatever this checkout is called,
# so the guest-side path is deterministic (/opt/distro-rig-vps -- the documented operator layout).
tar -czf "$ARCHIVE" -C "$ROOT/.." --transform "s,^$(basename "$ROOT"),distro-rig-vps," "$(basename "$ROOT")" || fail "archive build failed"
timeout 120 scp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no \
     -o IdentitiesOnly=yes -o ConnectTimeout=15 -i "$KEY" "$ARCHIVE" "root@$IP:/tmp/drvps.tgz" || fail "scp"
# The inner rig CANNOT reuse the default bridge subnet: the L1's own NIC lives on the OUTER rig's
# 10.123.0.0/24, and the installer refuses a bridge/fleet mismatch -- so renumber the bridge AND
# patch the fleet cache_cidr to match BEFORE setup (sed, not jq: jq is not installed until setup runs;
# the grep proves the patch landed, fail-closed). --force-squid: a fresh L1's distro squid.conf is
# foreign to the rig and the coexistence guard (B3) would refuse it.
timeout 900 "${SSH[@]}" 'set -e
  rm -rf /opt/distro-rig-vps
  tar xzf /tmp/drvps.tgz -C /opt
  chown -R root:root /opt/distro-rig-vps
  sed -i "s|10\.123\.0\.1/32|'"$INNER_BRIDGE_IP"'/32|" /opt/distro-rig-vps/etc/fleet.json
  grep -q "'"$INNER_BRIDGE_IP"'/32" /opt/distro-rig-vps/etc/fleet.json
  cd /opt/distro-rig-vps && DR_VPS_BRIDGE_IP='"$INNER_BRIDGE_IP"' ./bin/dr-vps-setup --yes --force-squid' \
  || fail "installer inside L1 (root-owned /opt + renumbered bridge + --force-squid)"

step "create the NON-root MEMBER fixture ($MEMBER: drvpsctl + drvpsvc) in the disposable L1"
# The TEST creates its own member account in the throwaway guest (the installer itself never
# provisions accounts). drvpsvc is the service group the egress member gate requires; the operator
# normally creates it when onboarding -- the dogfood plays that operator step.
timeout 60 "${SSH[@]}" 'getent group drvpsvc >/dev/null || groupadd --system drvpsvc
  id -u '"$MEMBER"' >/dev/null 2>&1 || useradd -m -G drvpsctl,drvpsvc '"$MEMBER" \
  || fail "member fixture (groupadd/useradd) in the L1"

step "PASS BAR (drvps): libvirtd up + doctor (capacity policy scoped for a small L1)"
timeout 60 "${SSH[@]}" 'systemctl is-active libvirtd' || fail "libvirtd not active in the L1"
# runuser (NOT the root ssh session) so the freshly-created drvps user's groups (kvm/libvirt) are
# initialized -- the same identity the watcher runs verbs under. The capacity knobs are scoped:
# a 4096MB/5GB-disk L1 can never satisfy the host-scale defaults (4096 default-vm + 8192 reserve
# RAM; 10240MB min disk); doctor's tool/observability/net checks are what this bar proves.
timeout 120 "${SSH[@]}" 'runuser -u drvps -- env DR_VPS_HOST_RESERVE_MB=512 DR_VPS_DEFAULT_MEM_MB=1024 DR_VPS_MIN_DISK_MB=1024 /opt/distro-rig-vps/bin/dr-vps doctor' \
  || fail "L1 doctor as drvps (scoped capacity knobs)"
echo "  L1 installer + doctor(drvps) PASS"

step "PASS BAR (drvps): a RENDERED domain XML really DEFINES (virsh define --validate) + undefines"
# The renderer is the exact code `create` feeds to `virsh define`; --validate schema-checks it against
# the L1's own libvirt. Dummy disk paths are fine at define time (libvirt resolves sources at start).
timeout 30 "${SSH[@]}" 'cat > /usr/local/lib/dogfood-define.sh && chmod 0755 /usr/local/lib/dogfood-define.sh' <<'EOS' || fail "staging define-bar script"
#!/usr/bin/env bash
set -euo pipefail
cd /opt/distro-rig-vps
. src/dr_vps_api.sh
. src/dr_vps_domain.sh
xml=$(dr_vps_domain_render_xml drvps-vm-dogfooddefine /var/lib/nonexistent/overlay.qcow2 /var/lib/nonexistent/seed.iso simnet 1024 1 11111111-2222-3333-4444-555555555555)
printf '%s' "$xml" | virsh -c qemu:///system define --validate /dev/stdin
virsh -c qemu:///system undefine drvps-vm-dogfooddefine
echo DEFINE-OK
EOS
timeout 120 "${SSH[@]}" 'runuser -u drvps -- /usr/local/lib/dogfood-define.sh | grep -q DEFINE-OK' \
  || fail "define bar: rendered XML did not define+undefine against the L1 libvirt (as drvps)"
echo "  render -> virsh define --validate -> undefine (drvps) PASS"

# ---- 0.3.0 wiring on a REAL install (the coverage the offline/seamed tests could not give) ----
step "PASS BAR (MEMBER -> root): egress add-splice as $MEMBER, YES-gated approve apply, live policy"
# INCIDENT: an earlier step_proxy rendered squid.conf from temp files and deleted them -> nothing wrote the /etc
# render inputs approve reads -> `apply` crashed on a real host (masked by test_root). MANDATORY: `apply` must
# reach _render_params (only `apply` does; `list` reads only fleet + the store) AND CLEANLY (rc=0 + healthy; a
# degraded rc 3/4 still prints "APPLIED") AND open the SPECIFIC host (not just "an" apply that restarted squid).
timeout 20 "${SSH[@]}" 'test -s /etc/distro-rig-vps/egress-render-params.json && test -s /etc/distro-rig-vps/egress-host-facts.json' \
  || fail "installer did NOT persist the egress render inputs -- approve apply would crash on this host"
# The MEMBER (not root) submits: SO_PEERCRED stamps a real non-zero uid, the submit socket's DAC and
# the drvpsvc member gate are on the path, and reading the synchronous result exercises the 0600+ACL
# result publication. stderr stays visible -- a refusal here must name itself in the log.
timeout 60 "${SSH[@]}" 'runuser -u '"$MEMBER"' -- /opt/distro-rig-vps/bin/rigctl egress add-splice callback.dogfood.example >/dev/null' \
  || fail "MEMBER rigctl egress add-splice failed (socket DAC / SO_PEERCRED / drvpsvc gate / result ACL)"
timeout 120 "${SSH[@]}" 'cd /opt/distro-rig-vps && out=$(printf "YES\n" | ./bin/drvps-egress-approve apply 2>&1); rc=$?; printf "%s\n" "$out"; [ "$rc" = 0 ] && printf "%s" "$out" | grep -q "squid restarted + healthy"' \
  || fail "drvps-egress-approve apply did not CLEANLY apply (rc=0 + 'squid restarted + healthy'); a degraded rc 3/4 is rejected"
timeout 20 "${SSH[@]}" 'grep -q "callback.dogfood.example" /etc/distro-rig-vps/fleet.json' \
  || fail "apply did not add callback.dogfood.example to fleet.json splice_allowlist -- the WRONG destination was approved?"
timeout 20 "${SSH[@]}" 'grep -q "callback.dogfood.example" /etc/squid/squid.conf' \
  || fail "the approved host is not in the LIVE squid.conf -- the running proxy would not splice it"
timeout 20 "${SSH[@]}" 'systemctl is-active --quiet squid' || fail "squid is not healthy after the approve restart"
echo "  MEMBER stage -> root approve apply (clean, specific host, live policy) -> squid healthy PASS"

step "PASS BAR (drvps + MEMBER): drvps-top publisher (active, LIVE sources, advancing seq) + member viewer"
# The publisher emits a VALID feed even when its sources are DOWN (db_status=down / libvirt_status=down) and the
# viewer renders a STALE feed successfully -- so "feed exists + viewer parses" does NOT prove the data path works.
timeout 30 "${SSH[@]}" 'runuser -u drvps -- /opt/distro-rig-vps/bin/drvps-top-publish --once 2>/dev/null | head -1 | grep -q "^H"' \
  || fail "drvps-top-publish --once (as drvps) did not emit a valid feed frame (H header)"
timeout 60 "${SSH[@]}" 'systemctl start drvps-top-publish' || fail "drvps-top-publish unit failed to start"
timeout 20 "${SSH[@]}" 'systemctl is-active --quiet drvps-top-publish' || fail "drvps-top-publish unit is not active (dead/wedged)"
timeout 30 "${SSH[@]}" 'for i in $(seq 1 20); do [ -s /run/drvps-top/feed ] && break; sleep 0.5; done; test -s /run/drvps-top/feed' \
  || fail "the drvps-top-publish unit did not write /run/drvps-top/feed"
# LIVE sources: H fields 8=db_status, 10=libvirt_status (per the serializer). A degraded feed reports 'down'.
timeout 20 "${SSH[@]}" 'h=$(head -1 /run/drvps-top/feed); db=$(printf "%s" "$h" | cut -f8); lv=$(printf "%s" "$h" | cut -f10); [ "$db" = ok ] && [ "$lv" = ok ]' \
  || fail "feed reports non-ok sources (db/libvirt down) -- the installed service is not reading its real data"
# ADVANCING seq (H field 4): a dead publisher that left one stale file keeps the same seq -> the unit is not live.
timeout 40 "${SSH[@]}" 's1=$(head -1 /run/drvps-top/feed | cut -f4); sleep 6; s2=$(head -1 /run/drvps-top/feed | cut -f4); [ "$s2" -gt "$s1" ]' \
  || fail "feed seq did not advance -- the publisher unit is not actively refreshing (dead/wedged)"
# The VIEWER runs as the NON-root member: the feed's 0644-in-0710-dir DAC + the hostile-file-safe
# open path are what a real co-tenant account actually hits.
timeout 30 "${SSH[@]}" 'runuser -u '"$MEMBER"' -- /opt/distro-rig-vps/bin/drvps-top --once >/tmp/topview.out 2>&1 || { cat /tmp/topview.out; exit 1; }' \
  || fail "the MEMBER viewer (drvps-top --once as $MEMBER) failed to validate/render the feed"
echo "  drvps-top publisher(drvps: active,live,advancing) + MEMBER viewer PASS"

step "BEST-EFFORT: DR-2 firewalld (a fedora L1 ships firewalld; non-fatal)"
if timeout 20 "${SSH[@]}" 'command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1'; then
  timeout 20 "${SSH[@]}" 'z=$(firewall-cmd --get-zone-of-interface=drvps0 2>/dev/null || echo libvirt); firewall-cmd --permanent --zone="$z" --list-rich-rules 2>/dev/null | grep -q "port=\"3128\""' \
    && echo "  firewalld scoped rich-rule for the cache port PASS" \
    || echo "  firewalld rich-rule check best-effort (zone/state varied) -- inspect manually if needed"
else
  echo "  firewalld inactive on this L1 -> step_firewalld correctly no-op"
fi

step "BEST-EFFORT: try to boot a nested L2 guest (non-fatal)"
# runuser -l: a fresh drvps login session picks up the installer-granted groups + HOME (the throwaway
# VM key lives in ~drvps/.ssh) -- the exact acceptance invocation the installer's DONE banner prints.
if timeout 300 "${SSH[@]}" 'runuser -l drvps -c "cd /opt/distro-rig-vps && DRVPS_TEST_KEY=/home/drvps/.ssh/drvps_vm_ed25519 DRVPS_LIVE=1 timeout 240 tests/acceptance/live-fedora44.sh"'; then
  echo "  nested L2 boot PASS (full self-hosting proven)"
else
  echo "  nested L2 boot skipped/failed (best-effort; the mandatory define bar already passed)"
fi

# L1 + archive are removed by the EXIT trap (cleanup) -- covers this success path AND every early fail().
echo "DOGFOOD PASS ($GUEST_DISTRO L1 -- mandatory bar: installer(/opt, renumbered bridge, --force-squid)"
echo "  + libvirtd + doctor(as drvps, scoped capacity) + REAL define(render->virsh --validate, as drvps)"
echo "  + MEMBER egress add-splice -> root approve apply -> live policy + drvps-top(publisher as drvps,"
echo "  viewer as MEMBER). L2 boot + firewalld were BEST-EFFORT (see log above)."
echo "  Portability: one distro per run -- repeat with 'ubuntu26' etc. for a second family."
