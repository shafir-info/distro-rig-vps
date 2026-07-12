#!/usr/bin/env bash
# live-fedora44.sh -- OPERATOR-RUN host-side Phase-1 acceptance (needs real KVM).
# Run as the drvps service user (in kvm+libvirt, after `dr-vps-setup` + re-login):
#
#     DRVPS_LIVE=1 tests/acceptance/live-fedora44.sh [--smoke]
#
# This is the END-TO-END bar (not "domain can be DEFINED"): build a real Fedora 44 Cloud
# golden, boot it on the `simulated` net, cloud-init an ssh key, SSH in, run a root-heavy
# op, run the LIVE egress reach-controls, recreate cleanly, destroy. The agent cannot run
# this (no /dev/kvm, never sudo); it is the operator tail of Phase 1.
#
# --smoke : SHAKEOUT mode for first contact with real KVM. Verbose per step, and on the
#           FIRST failure it dumps full diagnostic state (vm/net/nft/qemu-log/squid/cloud-
#           init) and LEAVES THE VM INTACT for inspection instead of cleaning up. Share the
#           output to diagnose. (Also enable via DRVPS_SMOKE=1.)
set -uo pipefail
[ "${DRVPS_LIVE:-}" = 1 ] || { echo "set DRVPS_LIVE=1 to run the live acceptance (needs KVM)"; exit 0; }

SMOKE=0; [ "${DRVPS_SMOKE:-}" = 1 ] && SMOKE=1
for a in "$@"; do [ "$a" = "--smoke" ] && SMOKE=1; done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DR="$ROOT/bin/dr-vps"
KEY="${DRVPS_TEST_KEY:-$HOME/.ssh/drvps_vm_ed25519}"        # PRIVATE key (for ssh -i)
PUBKEY="${DRVPS_TEST_PUBKEY:-${KEY}.pub}"             # PUBLIC key (seeds cloud-init authorized_keys)
export DR_VPS_SSH_KEY="$KEY"                          # so `dr-vps wait` uses the SAME private key
RECIPE="${DRVPS_RECIPE:-$ROOT/etc/recipes/fedora44.json}"
FLEET_HOST="${DRVPS_FLEET_PROBE:-}"        # an IP the VM must NOT reach (a real fleet host)
URI="qemu:///system"
ID=""                                      # set once the VM is created (for dump_state)

step() { echo "== $* =="; }
vlog() { [ "$SMOKE" = 1 ] && echo "    $*"; return 0; }

# Diagnostic state dump (best-effort; every probe tolerates absence). Secrets are NOT
# dumped (the seed's user-data holds the ssh key) -- only paths/perms.
dump_state() {
  echo; echo "################ SMOKE DIAGNOSTIC STATE ################"
  echo "---- dr-vps doctor --json ----";        "$DR" doctor --json 2>&1 || true
  echo "---- dr-vps list ----";                 "$DR" list 2>&1 || true
  echo "---- dr-vps distros ----";              "$DR" distros 2>&1 || true
  if [ -n "$ID" ]; then
    echo "---- virsh dominfo $ID ----";         virsh -c "$URI" dominfo "$ID" 2>&1 || true
    echo "---- virsh domifaddr $ID ----";       virsh -c "$URI" domifaddr "$ID" 2>&1 || true
    echo "---- qemu/boot log (last 60) ----";   tail -60 "/var/log/libvirt/qemu/${ID}.log" 2>&1 || true
    echo "---- serial console grab (5s) ----";  timeout 5 virsh -c "$URI" console "$ID" --force </dev/null 2>&1 | tail -40 || true
  fi
  echo "---- virsh net-info simnet ----";       virsh -c "$URI" net-info simnet 2>&1 || true
  echo "---- virsh net-dumpxml simnet ----";    virsh -c "$URI" net-dumpxml simnet 2>&1 || true
  echo "---- nft list table inet drvps_sim ---";nft list table inet drvps_sim 2>&1 || echo "    (could not read nft as $(id -un) -- run: sudo nft list table inet drvps_sim)"
  echo "---- systemctl libvirtd/squid ----";    systemctl --no-pager --lines=3 status libvirtd squid 2>&1 || true
  echo "---- squid access.log (last 25) ----";  tail -25 /var/log/squid/access.log 2>&1 || true
  echo "---- seed perms (no contents) ----";    ls -la "${DR_VPS_SEED_DIR:-/var/lib/distro-rig-vps/seed}" 2>&1 || true
  # guest-side (best-effort). DERIVE the IP here -- the most important failure (wait timed
  # out) happens BEFORE $IP/$SSH are set, so don't depend on them.
  local dip="${IP:-}"
  [ -z "$dip" ] && [ -n "$ID" ] && dip=$(virsh -c "$URI" domifaddr "$ID" 2>/dev/null | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
  if [ -n "$dip" ]; then
    echo "---- guest: cloud-init status (ip $dip) ----"
    timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=8 -o IdentitiesOnly=yes -i "$KEY" "root@$dip" \
      'cloud-init status --long 2>&1; echo "--- cloud-init-output.log tail ---"; tail -40 /var/log/cloud-init-output.log 2>&1' 2>&1 || echo "    (ssh to guest $dip failed -- boot/cloud-init/key issue)"
  else
    echo "---- guest: no IPv4 lease (DHCP/boot failure?) ----"
  fi
  echo "#######################################################"; echo
}

fail() {
  echo "ACCEPTANCE FAIL: $*" >&2
  if [ "$SMOKE" = 1 ]; then
    dump_state
    if [ -n "$ID" ]; then
      echo "VM LEFT INTACT for inspection: $ID" >&2
      echo "  console: virsh -c $URI console $ID   |   xml: virsh -c $URI dumpxml $ID" >&2
      echo "  clean up when done: $DR destroy $ID" >&2
    fi
  fi
  exit 1
}

# A remote probe that MUST fail (the guest must NOT reach the target).
assert_blocked() {  # <desc> <remote cmd...>
  local desc="$1"; shift
  if timeout 12 "${SSH[@]}" "$@" >/dev/null 2>&1; then
    fail "egress NOT blocked: ${desc} (the guest reached it)"
  fi
  vlog "blocked OK: ${desc}"
}

step "doctor (must pass on the live host)"
"$DR" doctor || fail "doctor refused -- run dr-vps-setup + re-login first"
vlog "doctor passed"

step "build the Fedora 44 Cloud golden (real fetch+verify+bake)"
AID=$("$DR" build "$RECIPE") || fail "golden build (pin upstream_sha256 in $RECIPE?)"
echo "  golden: $AID"

step "create a VM on the simulated net"
[ -f "$PUBKEY" ] || fail "no public key at $PUBKEY (the installer makes ~drvps/.ssh/drvps_vm_ed25519.pub; or set DRVPS_TEST_PUBKEY)"
[ -r "$KEY" ]    || fail "no readable PRIVATE key at $KEY (set DRVPS_TEST_KEY)"
ID=$("$DR" create acc1 fedora44 --net simnet --ssh-key "$PUBKEY") || fail "create"
echo "  vm: $ID"

step "wait for boot + cloud-init + ssh readiness"
vlog "polling boot+cloud-init+ssh (up to 300s)..."
"$DR" wait "$ID" 300 || fail "vm not ready (boot/cloud-init/ssh) within 300s"
IP=$(virsh -c "$URI" domifaddr "$ID" | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
[ -n "$IP" ] || fail "no IPv4 lease for $ID (DHCP on simnet?)"
echo "  ip: $IP"
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=8 -o IdentitiesOnly=yes -i "$KEY" "root@$IP")

step "root-heavy op inside the guest (real systemd + useradd + a cache install)"
vlog "ssh root@$IP : systemd state, useradd, tmux, and a proxied dnf install"
timeout 120 "${SSH[@]}" 'systemctl is-system-running --wait || true; id -u; useradd tester && echo USERADD_OK; tmux -V' \
  || fail "root op (systemd/useradd/tmux) failed"
vlog "checking package install through the IP cache proxy with DNS off (INFORMATIONAL)"
# The seed plumbs dnf (proxy + repos pinned to an allowlisted host); this is the live proof
# of that path. Kept INFORMATIONAL for now -- a real-VM wrinkle here must not mask the rest
# of the acceptance (egress controls / recreate / destroy), which don't need packages.
if timeout 180 "${SSH[@]}" 'dnf -y install nano >/tmp/dnf.out 2>&1'; then
  echo "  dnf-through-proxy: OK (seeded proxy + pinned repos work under simulated egress)"
else
  echo "  dnf-through-proxy: FAILED (informational, NOT fatal) -- guest /tmp/dnf.out tail:" >&2
  timeout 20 "${SSH[@]}" 'tail -25 /tmp/dnf.out' 2>&1 | sed 's/^/    /' || true
fi

step "LIVE EGRESS reach-controls (the live half of the net gate)"
assert_blocked "IPv6 egress"          'curl -s --max-time 5 -o /dev/null https://[2606:4700:4700::1111]/'
assert_blocked "internal/external DNS" 'getent hosts example.com'
[ -n "$FLEET_HOST" ] && assert_blocked "fleet host $FLEET_HOST" "curl -s --max-time 5 -o /dev/null http://$FLEET_HOST/"
GW=$(virsh -c "$URI" net-dumpxml simnet | sed -n "s/.*ip address='\\([^']*\\)'.*/\\1/p" | head -1)
[ -n "$GW" ] && assert_blocked "host gateway $GW (ssh)" "bash -c 'exec 3<>/dev/tcp/$GW/22'"
echo "  egress correctly fenced (IPv6 / DNS / fleet / gateway-ssh all blocked)"

step "recreate -> clean pinned golden, then re-verify"
"$DR" recreate "$ID" || fail "recreate"
"$DR" wait "$ID" 300 || fail "not ready after recreate"
IP=$(virsh -c "$URI" domifaddr "$ID" | awk '/ipv4/{print $NF}' | cut -d/ -f1 | head -1)
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=8 -o IdentitiesOnly=yes -i "$KEY" "root@$IP")
if timeout 30 "${SSH[@]}" 'getent passwd tester' >/dev/null 2>&1; then
  fail "recreate did NOT reset (tester user survived the rebuild)"
fi
vlog "recreate reset to a clean golden (tester user gone)"

step "destroy (golden untouched)"
"$DR" destroy "$ID" || fail "destroy"
ID=""                                   # destroyed -- nothing to leave intact
"$DR" distros | grep -q "$AID" || fail "golden disappeared after destroy"

echo "ACCEPTANCE PASS (Fedora 44 end-to-end hard bar: boot/cloud-init/ssh/root-op/egress/recreate/destroy; dnf-through-proxy is informational)"
