#!/usr/bin/env bash
# Build (if needed) the disposable squid test images and run the egress live gates on BOTH package families
# the drvps installer supports: Fedora/RHEL (squid) and Debian/Ubuntu (squid-openssl -- the base `squid`
# there is --with-gnutls and REJECTS ssl-bump, so dr-vps-setup's apt path installs squid-openssl). Each
# family runs: parse (squid -k parse accepts every rendered directive), behavioral (real squid TUNNELS a
# splice end-to-end, no MITM, terminates others), and the end-to-end approve workflow. Fully isolated in a
# rootless container's netns. No sudo, no shared-rig touch.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v podman >/dev/null || { echo "SKIP: podman not available"; exit 0; }

# distro -> (image, Containerfile). Covers every host family drvps supports as a golden target:
# RHEL (fedora/rocky/centos/alma), Debian (debian/ubuntu), SUSE (opensuse), Alpine. Fedora image name is
# the historical one (referenced elsewhere). Set DRVPS_EGRESS_DISTROS to a space-separated subset to narrow.
ALL_FAMILIES=("fedora:drvps-squid-test:egress-squid.Containerfile"
              "ubuntu:drvps-squid-test-ubuntu:egress-squid-ubuntu.Containerfile"
              "debian:drvps-squid-test-debian:egress-squid-debian.Containerfile"
              "rocky9:drvps-squid-test-rocky9:egress-squid-rocky9.Containerfile"
              "opensuse:drvps-squid-test-opensuse:egress-squid-opensuse.Containerfile"
              "alpine:drvps-squid-test-alpine:egress-squid-alpine.Containerfile")
# DEFAULT = every SUPPORTED HOST family: dnf/RHEL (fedora, rocky9 -> also centos9/alma) + apt/Debian (ubuntu,
# debian). dr-vps-setup installs only via dnf + apt, so those are the only platforms the host-side egress
# tools run on. opensuse + alpine are GUEST-only goldens (not host platforms; opensuse-leap ships Python 3.6,
# below the tools' 3.7+ floor) -- opt in via DRVPS_EGRESS_DISTROS to run them informationally.
FAMILIES=()
for _f in "${ALL_FAMILIES[@]}"; do
  _d="${_f%%:*}"
  case " ${DRVPS_EGRESS_DISTROS:-fedora rocky9 ubuntu debian} " in *" $_d "*) FAMILIES+=("$_f");; esac
done
rc=0
for spec in "${FAMILIES[@]}"; do
  distro="${spec%%:*}"; rest="${spec#*:}"; name="${rest%%:*}"; cf="${rest#*:}"; IMG="localhost/$name"
  podman image exists "$IMG" || { echo "[build] $IMG ($distro) ..."; podman build -q -t "$IMG" -f "$REPO/tests/$cf" "$REPO/tests" >/dev/null || { echo "BUILD FAILED $IMG"; rc=1; continue; }; }
  echo "================ $distro  ($IMG) ================"
  echo "=== parse gate (squid -k parse) ==="
  podman run --rm -v "$REPO":/repo:ro,Z "$IMG" bash /repo/tests/egress-squid-live.sh || rc=1
  echo "=== behavioral gate (live squid splice tunnel) ==="
  podman run --rm --cap-add NET_ADMIN -v "$REPO":/repo:ro,Z "$IMG" bash /repo/tests/egress-squid-container.sh || rc=1
  echo "=== end-to-end workflow gate (stage -> approve -> live splice tunnel) ==="
  podman run --rm --cap-add NET_ADMIN -v "$REPO":/repo:ro,Z "$IMG" bash /repo/tests/egress-squid-approve-container.sh || rc=1
  echo "=== production-path gate (approve reads /etc/distro-rig-vps render inputs, no test_root) ==="
  podman run --rm -v "$REPO":/repo:ro,Z "$IMG" bash /repo/tests/egress-approve-prodpath.sh || rc=1
done
echo "==============================================="
echo "egress squid live gates (${FAMILIES[*]%%:*}): $([ $rc = 0 ] && echo ALL-VERIFIED || echo FAILURES)"
exit $rc
