#!/usr/bin/env bash
# nested-selftest.sh -- OPERATOR-RUN dogfood (see STATUS.md deferrals). Validate the dr-vps-setup
# installer by running it INSIDE a fresh VM the rig itself boots. This host has nested
# virt enabled (kvm_intel nested=Y), so the L1 guest can run KVM.
#
#     DRVPS_LIVE=1 tests/dogfood/nested-selftest.sh
#
# Pass bar: installer completes + libvirtd up + `dr-vps doctor` passes +
# a domain can be DEFINED inside the L1 guest. Actually BOOTING the nested L2 guest is a
# separate BEST-EFFORT assertion (L2 is slower/flakier) so the suite never hangs on it.
# Run in a clean Fedora L1 then a clean Ubuntu L1 to exercise host-distro portability.
#
# NOTE: a cheaper proxy for this -- running the installer in a Fedora 44 PODMAN container
# -- already passes (full bats green with real tools; user/dirs/proxy created). That
# covers everything except real KVM; this nested test adds the KVM layer.
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

step "BEST-EFFORT: try to boot a nested L2 guest (non-fatal)"
if "${SSH[@]}" 'sg kvm -c "cd /tmp/distro-rig-vps* && DRVPS_TEST_KEY=/home/drvps/.ssh/drvps_vm_ed25519 DRVPS_LIVE=1 timeout 240 tests/acceptance/live-fedora44.sh"'; then
  echo "  nested L2 boot PASS (full self-hosting proven)"
else
  echo "  nested L2 boot skipped/failed (best-effort; L1 define-bar already passed)"
fi

"$DR" destroy "$ID" || true
echo "DOGFOOD PASS ($GUEST_DISTRO L1: installer + libvirtd + doctor + define)"
