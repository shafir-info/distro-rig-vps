#!/usr/bin/env bash
# Build a multi-family matrix of drvps goldens (debian/ubuntu/rhel families).
#   Already built (skipped here): fedora44, ubuntu24.
#   This script adds: debian13, ubuntu22, ubuntu26 (debian-family) + rocky9
#   (rhel9 family stand-in for centos:stream9).
#
# RUN AS THE SUDOER (your admin account), NOT as root:
#     bash tests/build-matrix-goldens.sh
# It sudo's for /opt writes and uses `sudo -u drvps` for the never-root builds.
# It is idempotent (re-runnable). ~20-40 min for 4 builds (multi-GB each) -- run
# it under tmux/screen so it survives a disconnect. Each sha is fetched fresh
# from the vendor's published checksum (that is the trust anchor); Debian is
# download+sha512-verify+sha256-compute because Debian publishes only sha512.
set -uo pipefail
REC=/opt/distro-rig-vps/etc/recipes
DRVPS=(sudo -u drvps -H /opt/distro-rig-vps/bin/dr-vps)

die() { echo "FATAL: $*" >&2; exit 1; }
pin() { sudo sed -i "s|$2|$3|" "$REC/$1" || die "pin $1"; }

[ -x /opt/distro-rig-vps/bin/dr-vps ] || die "dr-vps not found at /opt/distro-rig-vps (is drvps installed here?)"

echo "== creating the two NEW recipes in $REC (ubuntu22, ubuntu26) =="
sudo tee "$REC/ubuntu22.json" >/dev/null <<'EOF'
{
  "_comment": "Ubuntu 22.04 LTS (jammy) cloud image -- apt FAMILY (ubuntu:22.04). PIN upstream_sha256 (published SHA256SUMS). Guest apt via the SSL-bump cache proxy; archive/security.ubuntu.com allowlisted.",
  "distro": "ubuntu22",
  "family": "apt",
  "upstream_url": "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img",
  "upstream_sha256": "PIN_ME_ubuntu22",
  "packages": ["systemd", "openssh-server", "cloud-init", "tmux", "ca-certificates"]
}
EOF
sudo tee "$REC/ubuntu26.json" >/dev/null <<'EOF'
{
  "_comment": "Ubuntu 26.04 LTS cloud image -- apt FAMILY (ubuntu:26.04, newest LTS). PIN upstream_sha256 (published SHA256SUMS). Guest apt via the SSL-bump cache proxy; archive/security.ubuntu.com allowlisted.",
  "distro": "ubuntu26",
  "family": "apt",
  "upstream_url": "https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img",
  "upstream_sha256": "PIN_ME_ubuntu26",
  "packages": ["systemd", "openssh-server", "cloud-init", "tmux", "ca-certificates"]
}
EOF
sudo chmod 0644 "$REC/ubuntu22.json" "$REC/ubuntu26.json"

echo "== fetching vendor sha256 for the published-checksum distros =="
UB22=$(curl -fsSL https://cloud-images.ubuntu.com/releases/22.04/release/SHA256SUMS | awk '/ubuntu-22.04-server-cloudimg-amd64\.img$/{print $1}')
UB26=$(curl -fsSL https://cloud-images.ubuntu.com/releases/26.04/release/SHA256SUMS | awk '/ubuntu-26.04-server-cloudimg-amd64\.img$/{print $1}')
RK9=$(curl -fsSL https://dl.rockylinux.org/pub/rocky/9/images/x86_64/CHECKSUM | awk '/SHA256 \(Rocky-9-GenericCloud-Base.latest.x86_64.qcow2\)/{print $NF}')
echo "  ubuntu22=$UB22"; echo "  ubuntu26=$UB26"; echo "  rocky9=$RK9"
[ ${#UB22} -eq 64 ] || die "ubuntu22 sha fetch empty/bad"
[ ${#UB26} -eq 64 ] || die "ubuntu26 sha fetch empty/bad"
[ ${#RK9}  -eq 64 ] || die "rocky9 sha fetch empty/bad"
pin ubuntu22.json PIN_ME_ubuntu22 "$UB22"
pin ubuntu26.json PIN_ME_ubuntu26 "$UB26"
pin rocky9.json   PIN_ME_to_the_vendor_CHECKSUM_sha256 "$RK9"

echo "== debian13: download + verify sha512 + compute sha256 (Debian publishes only sha512) =="
D=/var/tmp/drvps-debian-pin; mkdir -p "$D"; cd "$D" || die "cd $D"
curl -fsSLO https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2 || die "debian image download"
curl -fsSLO https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS || die "debian SHA512SUMS download"
sha512sum --ignore-missing -c SHA512SUMS | grep -q 'debian-13-genericcloud-amd64.qcow2: OK' || die "debian image FAILED sha512 verify"
DEB=$(sha256sum debian-13-genericcloud-amd64.qcow2 | awk '{print $1}')
echo "  debian13=$DEB"
[ ${#DEB} -eq 64 ] || die "debian sha256 compute failed"
pin debian13.json PIN_ME_to_the_vendor_SHA512SUMS_value "$DEB"

echo "== building (debian13, ubuntu22, ubuntu26, rocky9) -- long; each prints an artifact id on success =="
declare -a FAILED=()
for r in debian13 ubuntu22 ubuntu26 rocky9; do
  echo "--- build $r ---"
  if "${DRVPS[@]}" build "$REC/$r.json"; then echo "  OK: $r"; else echo "  FAILED: $r"; FAILED+=("$r"); fi
done

echo "== registered goldens =="
"${DRVPS[@]}" distros
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "ALL BUILT. (Leftover Debian image in $D can be removed: rm -rf $D)"
else
  echo "SOME FAILED: ${FAILED[*]} -- see the error above each."
fi
