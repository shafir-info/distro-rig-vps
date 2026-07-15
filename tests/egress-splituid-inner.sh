#!/usr/bin/env bash
# Inner orchestration for the split-UID egress boundary gate (runs AS ROOT inside the container). Creates a
# real drvps user/group, copies the tools + check to a world-readable path (the repo tools are 0600), then
# runs the provision + assertions as root and the cross-UID assertions as the real drvps user.
set -uo pipefail
command -v python3 >/dev/null 2>&1 || dnf install -y python3 >/dev/null 2>&1 || true
command -v useradd >/dev/null 2>&1 || dnf install -y shadow-utils >/dev/null 2>&1 || true
command -v runuser >/dev/null 2>&1 || dnf install -y util-linux >/dev/null 2>&1 || true
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 unavailable in the container"; exit 0; }
command -v useradd >/dev/null 2>&1 || { echo "SKIP: useradd unavailable"; exit 0; }
command -v runuser >/dev/null 2>&1 || { echo "SKIP: runuser unavailable"; exit 0; }

# Create drvps with a NON-drvps PRIMARY group + drvps as a SUPPLEMENTAL group -- so the whole run exercises
# the supplemental-membership case (the store group != the process primary gid). Falls
# back to a default (primary drvps) if the base image lacks the alt group.
groupadd -r drvps >/dev/null 2>&1 || true
if ! id drvps >/dev/null 2>&1; then
  useradd -r -g nobody -G drvps -s /usr/sbin/nologin drvps >/dev/null 2>&1 \
    || useradd -r -G drvps -s /usr/sbin/nologin drvps >/dev/null 2>&1 \
    || useradd -r -s /usr/sbin/nologin drvps
fi

# The repo tools are 0600 (owned by the host user, root inside the container); drvps cannot read them from
# the ro mount. Stage a world-readable copy the drvps user can import.
# the real member cmd_submit takes the shared data lock at the fixed root-owned path -- create it root:drvps 0660
install -d -m 0755 /etc/distro-rig-vps
install -m 0660 -g drvps /dev/null /etc/distro-rig-vps/egress.lock 2>/dev/null \
  || { : > /etc/distro-rig-vps/egress.lock; chgrp drvps /etc/distro-rig-vps/egress.lock 2>/dev/null || true; chmod 0660 /etc/distro-rig-vps/egress.lock; }

T=/opt/drvps-splituid
mkdir -p "$T/tools"
cp /repo/tools/drvps_egress_layout.py /repo/tools/drvps_egress_req.py /repo/tools/drvps_egress_model.py \
   /repo/tools/drvps_egress_member.py "$T/tools/"
cp /repo/tests/egress-splituid-check.py "$T/"
chmod -R a+rX "$T"
CHK="$T/egress-splituid-check.py"

fail=0
echo "=== provision (root) ==="
python3 "$CHK" provision || fail=1
echo "=== root-check (ownership + modes + write a published decision) ==="
python3 "$CHK" root-check || fail=1
echo "=== drvps-check (B1 traverse 0710 + cross-UID DAC) ==="
runuser -u drvps -- python3 "$CHK" drvps-check || fail=1
echo "=== root-read (root reads the drvps-written inbox) ==="
python3 "$CHK" root-read || fail=1

echo "-------------------------------------------"
echo "egress split-UID boundary: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
