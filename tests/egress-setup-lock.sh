#!/usr/bin/env bash
# Guards the SHARED egress lock (PLAN 1.9): dr-vps-setup's step_proxy, the root
# approve tool, and the drvps member/reaper must all take an exclusive flock on the SAME FIXED, ROOT-owned
# path -- /etc/distro-rig-vps/egress.lock -- so a --reapply-egress can never race the approve's crash-
# recovery, and no service user can plant a symlink / replace the lock inode.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
LOCK="/etc/distro-rig-vps/egress.lock"

ok "step_proxy pins the FIXED root-owned lock path" 'grep -qF "_EGLOCK=\"$LOCK\"" "$REPO/bin/dr-vps-setup"'
ok "step_proxy acquires an EXCLUSIVE flock on it" 'grep -qE "flock -w .* -x .*_EGLOCKFD" "$REPO/bin/dr-vps-setup"'
ok "step_proxy releases the lock at the end (fd close)" 'grep -qE "exec \{_EGLOCKFD\}>&-" "$REPO/bin/dr-vps-setup"'
ok "step_proxy does NOT chown a service-user lock path (no chown-based lock-inode privesc)" \
   '! grep -qE "chown .*egress.lock|chmod .*_egbase/egress.lock" "$REPO/bin/dr-vps-setup"'
ok "the approve tool pins the SAME fixed lock path" \
   'grep -qF "EGRESS_LOCK_PATH = \"$LOCK\"" "$REPO/bin/drvps-egress-approve"'
ok "the member/reaper pin the SAME fixed lock path" \
   'grep -qF "LOCK_PATH = \"$LOCK\"" "$REPO/tools/drvps_egress_member.py"'
ok "member/approve open the lock O_NOFOLLOW (no symlink follow)" \
   'grep -q "O_NOFOLLOW" "$REPO/bin/drvps-egress-approve" && grep -q "O_NOFOLLOW" "$REPO/tools/drvps_egress_member.py"'

# v2: the store ANCHOR is a FIXED constant everywhere (the seam-free approve tool
# cannot honor a STATE_DIR-derived path). The shell defaults + setup provisioning + uninstall must all use
# the SAME literal, and it MUST equal drvps_egress_layout.ANCHOR + the approve tool's L.ANCHOR.
ANCHOR="$(python3 -c "import sys; sys.path.insert(0, '$REPO/tools'); import drvps_egress_layout as L; print(L.ANCHOR)")"
ok "layout ANCHOR resolved" '[ -n "$ANCHOR" ]'
ok "member wrapper default anchor == L.ANCHOR" 'grep -qF "DR_VPS_EGRESS_BASE:=$ANCHOR}" "$REPO/src/dr_vps_egress.sh"'
ok "reaper default anchor == L.ANCHOR" 'grep -qF "DR_VPS_EGRESS_BASE:-$ANCHOR}" "$REPO/src/dr_vps_reaper.sh"'
ok "setup provisions the anchor == L.ANCHOR" 'grep -qF "_EGANCHOR=\"$ANCHOR\"" "$REPO/bin/dr-vps-setup"'
ok "uninstall removes the anchor == L.ANCHOR" 'grep -qF " $ANCHOR " "$REPO/bin/dr-vps-setup"'
ok "the approve tool base == L.ANCHOR (no STATE_DIR/env seam)" \
   'grep -q "self.base = L.ANCHOR" "$REPO/bin/drvps-egress-approve"'

# v2: the shared data lock must be CREATED + enforced root:drvps 0660 BEFORE the store
# migration/provision runs (drvps-egress-migrate takes the lock; it must not create it umask-masked). The
# lock chgrp+chmod must precede the migrate invocation in step_proxy.
SETUP="$REPO/bin/dr-vps-setup"
ok "step_proxy fd-safe-enforces the data lock as root:drvps 0660 (owner+group+mode+type)" \
   'grep -qE "_fs_guard_py file .*_EGLOCK. root drvps 0660" "$SETUP"'
ok "step_proxy fd-safe-enforces the session lock as root:root 0600" \
   'grep -qE "_fs_guard_py file .*_EGSESS.* root root 0600" "$SETUP"'
ok "the data lock is enforced BEFORE the migration runs" \
   'awk "/_fs_guard_py file .*_EGLOCK/{l=NR} /drvps-egress-migrate/{m=NR} END{exit !(l>0 && m>0 && l<m)}" "$SETUP"'
ok "step_proxy enforces /etc/distro-rig-vps as root:root 0755 (fd-safe parent dir)" \
   'grep -qE "_fs_guard_py dir /etc/distro-rig-vps root root 0755" "$SETUP"'
ok "step_proxy QUIESCES the v1 watcher/reaper before migrating" \
   'awk "/systemctl stop/ && !s{s=NR} /python3.*drvps-egress-migrate/{m=NR} END{exit !(s>0 && m>0 && s<m)}" "$SETUP"'
ok "step_proxy VERIFIES the v1 writers inactive/failed FAIL-CLOSED before migrating" \
   'awk "/ActiveState --value/ && !a{a=NR} /cannot confirm/ && !f{f=NR} /python3.*drvps-egress-migrate/{m=NR} END{exit !(a>0 && f>0 && m>0 && a<m && f<m)}" "$SETUP"'
ok "step_proxy accepts ONLY positively-safe states (0:inactive|0:failed)" \
   'grep -qE "0:inactive\|0:failed" "$SETUP"'
ok "the migration self-checks quiescence fail-closed (a direct invocation cannot bypass it)" \
   'grep -q "v1-not-quiesced" "$REPO/bin/drvps-egress-migrate" && grep -q "ActiveState" "$REPO/bin/drvps-egress-migrate"'
ok "the drvps identity is enforced in validate_env BEFORE any egress lock/store mutation" \
   'awk "/DR_VPS_SERVICE_USER. = drvps/ && !i{i=NR} /_fs_guard_py file .*_EGLOCK/{g=NR} END{exit !(i>0 && g>0 && i<g)}" "$SETUP"'
ok "the egress lock group is the LITERAL fixed drvps (not the configurable identity)" \
   'grep -qE "_fs_guard_py file .*_EGLOCK. root drvps 0660" "$SETUP"'
ok "the migrator receives the (possibly custom) v1 STATE_DIR/egress base" \
   'grep -qE "drvps-egress-migrate. .\\\$_EGV1" "$SETUP"'
ok "the migration tool pins ONE v1 generation via a held base fd + intermediate dirs" \
   'grep -q "v1bfd = R.open_base_fd" "$REPO/bin/drvps-egress-migrate" && grep -q "open_sub_fd(v1bfd, \"review\")" "$REPO/bin/drvps-egress-migrate"'
ok "a MISSING v1 namespace aborts the migration (held-fd generation pin)" 'grep -q "v1-namespace-missing" "$REPO/bin/drvps-egress-migrate"'

echo "-------------------------------------------"
echo "egress setup lock (1.9) + v2 anchor: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
