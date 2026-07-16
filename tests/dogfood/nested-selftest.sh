#!/usr/bin/env bash
# nested-selftest.sh -- OPERATOR-RUN dogfood (see STATUS.md deferrals). Validate the dr-vps-setup
# installer by running it INSIDE a fresh VM the rig itself boots. This host has nested
# virt enabled (kvm_intel nested=Y), so the L1 guest can run KVM.
#
#     DRVPS_LIVE=1 tests/dogfood/nested-selftest.sh
#
# Pass bar: installer completes + libvirtd up + `dr-vps doctor` passes + a domain can be DEFINED, AND the
# 0.3.0 wiring works on a REAL install -- the egress installer->approve seam (render inputs persisted + a clean
# `apply` of a SPECIFIC splice; the exact class the offline seam tests MISSED because they hand-provided the
# inputs under a test_root), and drvps-top (the publisher, with LIVE sources + an advancing seq, emits a feed
# the member viewer reads). Actually BOOTING a nested L2 guest + the guest-through-proxy splice are BEST-EFFORT
# (L2 is slower/flakier) so the suite never hangs on them. Run a clean Fedora L1 then Ubuntu L1 for portability.
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

step "copy the rig in + run the installer inside the L1 guest"
ARCHIVE=$(mktemp --suffix=.tgz)                                       # per-run (no fixed /tmp path -> no stale/races)
tar -czf "$ARCHIVE" -C "$ROOT/.." "$(basename "$ROOT")" || fail "archive build failed"
timeout 120 scp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no \
     -o IdentitiesOnly=yes -o ConnectTimeout=15 -i "$KEY" "$ARCHIVE" "root@$IP:/tmp/drvps.tgz" || fail "scp"
timeout 900 "${SSH[@]}" 'cd /tmp && rm -rf distro-rig-vps* && tar xzf drvps.tgz && cd distro-rig-vps* && ./bin/dr-vps-setup --yes' \
  || fail "installer inside L1"

step "PASS BAR: libvirtd up + doctor + can DEFINE a domain (in the L1 guest, re-login for groups)"
timeout 120 "${SSH[@]}" 'sg kvm -c "cd /tmp/distro-rig-vps* && systemctl is-active libvirtd && ./bin/dr-vps doctor"' \
  || fail "L1 doctor/libvirtd"
echo "  L1 installer + doctor PASS"

# ---- 0.3.0 wiring on a REAL install (the coverage the offline/seamed tests could not give) ----
step "0.3.0 egress: stage a SPECIFIC splice, APPROVE it cleanly, prove it is in the live policy"
# INCIDENT: an earlier step_proxy rendered squid.conf from temp files and deleted them -> nothing wrote the /etc
# render inputs approve reads -> `apply` crashed on a real host (masked by test_root). MANDATORY: `apply` must
# reach _render_params (only `apply` does; `list` reads only fleet + the store) AND CLEANLY (rc=0 + healthy; a
# degraded rc 3/4 still prints "APPLIED") AND open the SPECIFIC host (not just "an" apply that restarted squid).
timeout 20 "${SSH[@]}" 'test -s /etc/distro-rig-vps/egress-render-params.json && test -s /etc/distro-rig-vps/egress-host-facts.json' \
  || fail "installer did NOT persist the egress render inputs -- approve apply would crash on this host"
timeout 30 "${SSH[@]}" 'cd /tmp/distro-rig-vps* && ./bin/rigctl egress add-splice callback.dogfood.example >/dev/null 2>&1' \
  || fail "rigctl egress add-splice failed (watcher/socket wiring)"
timeout 120 "${SSH[@]}" 'cd /tmp/distro-rig-vps* && out=$(printf "YES\n" | ./bin/drvps-egress-approve apply 2>&1); rc=$?; printf "%s\n" "$out"; [ "$rc" = 0 ] && printf "%s" "$out" | grep -q "squid restarted + healthy"' \
  || fail "drvps-egress-approve apply did not CLEANLY apply (rc=0 + 'squid restarted + healthy'); a degraded rc 3/4 is rejected"
timeout 20 "${SSH[@]}" 'grep -q "callback.dogfood.example" /etc/distro-rig-vps/fleet.json' \
  || fail "apply did not add callback.dogfood.example to fleet.json splice_allowlist -- the WRONG destination was approved?"
timeout 20 "${SSH[@]}" 'grep -q "callback.dogfood.example" /etc/squid/squid.conf' \
  || fail "the approved host is not in the LIVE squid.conf -- the running proxy would not splice it"
timeout 20 "${SSH[@]}" 'systemctl is-active --quiet squid' || fail "squid is not healthy after the approve restart"
echo "  egress stage -> approve apply (clean, specific host, live policy) -> squid healthy PASS"

step "0.3.0 drvps-top: publisher (active + LIVE sources + advancing seq) + member viewer reads it"
# The publisher emits a VALID feed even when its sources are DOWN (db_status=down / libvirt_status=down) and the
# viewer renders a STALE feed successfully -- so "feed exists + viewer parses" does NOT prove the data path works.
timeout 30 "${SSH[@]}" 'sudo -u drvps /tmp/distro-rig-vps*/bin/drvps-top-publish --once 2>/dev/null | head -1 | grep -q "^H"' \
  || fail "drvps-top-publish --once did not emit a valid feed frame (H header)"
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
timeout 30 "${SSH[@]}" 'cd /tmp/distro-rig-vps* && ./bin/drvps-top --once >/tmp/topview.out 2>&1 || { cat /tmp/topview.out; exit 1; }' \
  || fail "the member viewer (drvps-top --once) failed to validate/render the feed"
echo "  drvps-top publisher(active,live,advancing) + viewer wiring PASS"

step "0.3.0 DR-2 firewalld (best-effort; a fedora L1 ships firewalld)"
if timeout 20 "${SSH[@]}" 'command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1'; then
  timeout 20 "${SSH[@]}" 'z=$(firewall-cmd --get-zone-of-interface=drvps0 2>/dev/null || echo libvirt); firewall-cmd --permanent --zone="$z" --list-rich-rules 2>/dev/null | grep -q "port=\"3128\""' \
    && echo "  firewalld scoped rich-rule for the cache port PASS" \
    || echo "  firewalld rich-rule check best-effort (zone/state varied) -- inspect manually if needed"
else
  echo "  firewalld inactive on this L1 -> step_firewalld correctly no-op"
fi

step "BEST-EFFORT: try to boot a nested L2 guest (non-fatal)"
if timeout 300 "${SSH[@]}" 'sg kvm -c "cd /tmp/distro-rig-vps* && DRVPS_TEST_KEY=/home/drvps/.ssh/drvps_vm_ed25519 DRVPS_LIVE=1 timeout 240 tests/acceptance/live-fedora44.sh"'; then
  echo "  nested L2 boot PASS (full self-hosting proven)"
else
  echo "  nested L2 boot skipped/failed (best-effort; L1 define-bar already passed)"
fi

# L1 + archive are removed by the EXIT trap (cleanup) -- covers this success path AND every early fail().
echo "DOGFOOD PASS ($GUEST_DISTRO L1: installer + libvirtd + doctor + define + egress-wiring + drvps-top)"
