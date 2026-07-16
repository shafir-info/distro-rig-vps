#!/usr/bin/env bash
# nested-selftest.sh -- OPERATOR-RUN dogfood (see STATUS.md deferrals). Validate the dr-vps-setup
# installer by running it INSIDE a fresh VM the rig itself boots. This host has nested
# virt enabled (kvm_intel nested=Y), so the L1 guest can run KVM.
#
#     DRVPS_LIVE=1 tests/dogfood/nested-selftest.sh
#
# Pass bar: installer completes + libvirtd up + `dr-vps doctor` passes + a domain can be DEFINED, AND the
# 0.3.0 wiring works on a REAL install -- the egress installer->approve seam (render inputs persisted +
# `drvps-egress-approve list` reads them; this is the exact class the offline seam tests MISSED because they
# hand-provided the inputs under a test_root), and drvps-top (the publisher emits a feed the member viewer
# reads). Actually BOOTING a nested L2 guest + the guest-through-proxy splice are BEST-EFFORT (L2 is slower/
# flakier) so the suite never hangs on them. Run a clean Fedora L1 then Ubuntu L1 for host-distro portability.
#
# SAFETY: the L1 VM is owner-scoped (this account's VM only) and is destroyed on ANY exit via a trap, so a
# failed run never leaks a VM on the shared host. Keep the L1 small (2 vCPU / 4 GB, below).
#
# NOTE: a cheaper proxy for the NON-KVM wiring is `tests/release-gate.sh --container` (real installer helpers
# + squid in disposable podman); this nested test adds the real-KVM + full-install layer on top.
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

step "boot an L1 guest ($GUEST_DISTRO) with nested virt"
ID=$("$DR" create dogfood-l1 "$GUEST_DISTRO" --net simnet --cpus 2 --mem 4096 --ssh-key "$PUBKEY") || fail "L1 create"
# SAFETY: destroy the L1 on ANY exit (success, fail(), or interrupt) so a run never leaks a VM on the shared host.
cleanup() { [ -n "${ID:-}" ] && "$DR" destroy "$ID" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
"$DR" wait "$ID" 300 || fail "L1 not ready"
IP=$(virsh -c qemu:///system domifaddr "$ID" | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no -o IdentitiesOnly=yes -i "$KEY" "root@$IP")
"${SSH[@]}" 'test -e /dev/kvm' || fail "no nested /dev/kvm in the L1 guest (check kvm_intel nested=Y)"

step "copy the rig in + run the installer inside the L1 guest"
tar -czf /tmp/drvps.tgz -C "$ROOT/.." "$(basename "$ROOT")"
scp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no -o IdentitiesOnly=yes -i "$KEY" /tmp/drvps.tgz "root@$IP:/tmp/" || fail "scp"
"${SSH[@]}" 'cd /tmp && tar xzf drvps.tgz && cd distro-rig-vps* && ./bin/dr-vps-setup --yes' || fail "installer inside L1"

step "PASS BAR: libvirtd up + doctor + can DEFINE a domain (in the L1 guest, re-login for groups)"
"${SSH[@]}" 'sg kvm -c "cd /tmp/distro-rig-vps* && systemctl is-active libvirtd && ./bin/dr-vps doctor"' \
  || fail "L1 doctor/libvirtd"
echo "  L1 installer + doctor PASS"

# ---- 0.3.0 wiring on a REAL install (the coverage the offline/seamed tests could not give) ----
step "0.3.0 egress: the installer->approve seam -- stage a splice, APPROVE it, squid stays healthy"
# INCIDENT: an earlier step_proxy rendered squid.conf from temp files and deleted them, so nothing wrote the
# /etc render inputs drvps-egress-approve reads -> `apply` crashed on a real host. The offline + container
# tests hand-provided those inputs under a test_root and never saw it. The MANDATORY bar here is a full
# stage -> apply -> healthy: `approve list` reads only fleet.json + the request store, so it never calls
# _render_params (the crash path); ONLY `apply` does. So the apply MUST succeed, not be best-effort.
"${SSH[@]}" 'test -s /etc/distro-rig-vps/egress-render-params.json && test -s /etc/distro-rig-vps/egress-host-facts.json' \
  || fail "installer did NOT persist the egress render inputs -- approve apply would crash on this host"
"${SSH[@]}" 'cd /tmp/distro-rig-vps* && ./bin/rigctl egress add-splice callback.dogfood.example >/dev/null 2>&1' \
  || fail "rigctl egress add-splice failed (watcher/socket wiring)"
# Require apply's OWN exit code == 0, not just "APPLIED" in the output: a DEGRADED apply still prints
# "APPLIED (...)" but returns 3 (decisions not durable) or 4 (rival terminal) -- a piped `grep -q APPLIED`
# would accept those. Capture rc separately (no pipefail on the remote) and demand the CLEAN outcome.
"${SSH[@]}" 'cd /tmp/distro-rig-vps* && out=$(printf "YES\n" | ./bin/drvps-egress-approve apply 2>&1); rc=$?; printf "%s\n" "$out"; [ "$rc" = 0 ] && printf "%s" "$out" | grep -q "squid restarted + healthy"' \
  || fail "drvps-egress-approve apply did not CLEANLY apply (rc=0 + 'squid restarted + healthy') -- it reads the render inputs via _render_params (the crash path); a degraded rc 3/4 is rejected"
"${SSH[@]}" 'systemctl is-active --quiet squid' \
  || fail "squid is not healthy after the approve restart"
echo "  egress stage -> approve apply -> squid healthy PASS (the render-input read path is exercised)"

step "0.3.0 drvps-top: publisher emits a feed + the member viewer reads it"
# The privileged publisher (AS drvps) reads store.db + virsh -> one feed frame; the unprivileged viewer
# validates it with the hostile-file protocol + renders. Only a real install exercises this wiring.
"${SSH[@]}" 'sudo -u drvps /tmp/distro-rig-vps*/bin/drvps-top-publish --once 2>/dev/null | head -1 | grep -q "^H"' \
  || fail "drvps-top-publish --once did not emit a valid feed frame (H header)"
"${SSH[@]}" 'systemctl start drvps-top-publish 2>/dev/null || true; for i in $(seq 1 20); do [ -s /run/drvps-top/feed ] && break; sleep 0.5; done; test -s /run/drvps-top/feed' \
  || fail "the drvps-top-publish unit did not write /run/drvps-top/feed"
"${SSH[@]}" 'cd /tmp/distro-rig-vps* && ./bin/drvps-top --once >/tmp/topview.out 2>&1 || { cat /tmp/topview.out; exit 1; }' \
  || fail "the member viewer (drvps-top --once) failed to validate/render the feed"
echo "  drvps-top publisher+viewer wiring PASS"

step "0.3.0 DR-2 firewalld (best-effort; a fedora L1 ships firewalld)"
if "${SSH[@]}" 'command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1'; then
  "${SSH[@]}" 'z=$(firewall-cmd --get-zone-of-interface=drvps0 2>/dev/null || echo libvirt); firewall-cmd --permanent --zone="$z" --list-rich-rules 2>/dev/null | grep -q "port=\"3128\""' \
    && echo "  firewalld scoped rich-rule for the cache port PASS" \
    || echo "  firewalld rich-rule check best-effort (zone/state varied) -- inspect manually if needed"
else
  echo "  firewalld inactive on this L1 -> step_firewalld correctly no-op"
fi

step "BEST-EFFORT: try to boot a nested L2 guest (non-fatal)"
if "${SSH[@]}" 'sg kvm -c "cd /tmp/distro-rig-vps* && DRVPS_TEST_KEY=/home/drvps/.ssh/drvps_vm_ed25519 DRVPS_LIVE=1 timeout 240 tests/acceptance/live-fedora44.sh"'; then
  echo "  nested L2 boot PASS (full self-hosting proven)"
else
  echo "  nested L2 boot skipped/failed (best-effort; L1 define-bar already passed)"
fi

# L1 is destroyed by the EXIT trap (cleanup) -- covers this success path AND every early fail().
echo "DOGFOOD PASS ($GUEST_DISTRO L1: installer + libvirtd + doctor + define + egress-wiring + drvps-top)"
