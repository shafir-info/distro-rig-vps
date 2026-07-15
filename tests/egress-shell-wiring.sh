#!/usr/bin/env bash
# Offline guard for the egress SHELL wiring that the v2 module/container suites don't exercise directly:
#   (1) the `_dr_vps_egress_admit` gate -- it runs BEFORE any store access, so it is testable with NO store:
#       a `drvpsvc` member (or uid 0 / empty owner = the direct operator) is admitted; a NON-member is refused
#       fail-closed with E_CAP (12). Membership is injected via the DR_VPS_GROUPS_OF seam.
#   (2) a static anti-un-wiring guard: `dr_vps_reaper_sweep` must call `_dr_vps_egress_reap` (the reaper's
#       egress-maintenance hook).
# The member-op + reaper-expiry LOGIC is covered by tests/egress-verb-test.py; the REAL `dr-vps egress` CLI
# end-to-end (a real drvps user + a provisioned v2 store) is covered by the container e2e tests
# (egress-splituid.sh, egress-squid-approve-container.sh). The v2 store is seam-free (fixed root-owned anchor,
# real drvps group), so a single-UID offline shell test of the full member CLI is not representative -- hence
# this narrow gate-only guard rather than the retired v1 seamable-store tests. ASCII only.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0; ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

GS="$(mktemp)"; trap 'rm -f "$GS"' EXIT
cat > "$GS" <<'EOF'
#!/usr/bin/env bash
case "$1" in 1008|2000) echo "drvpsvc users";; *) echo "users";; esac
EOF
chmod +x "$GS"

# call _dr_vps_egress_admit in a subshell with the membership seam; PRINT its exit status (E_CAP on refusal).
admrc(){ DR_VPS_GROUPS_OF="$GS" bash -c '
    . "'"$REPO"'/src/dr_vps_api.sh"    >/dev/null 2>&1
    . "'"$REPO"'/src/dr_vps_domain.sh" >/dev/null 2>&1
    . "'"$REPO"'/src/dr_vps_egress.sh" >/dev/null 2>&1
    _dr_vps_egress_admit "'"$1"'"' >/dev/null 2>&1; echo "$?"; }

ok "admit: drvpsvc member (1008) allowed"            '[ "$(admrc 1008)" = 0 ]'
ok "admit: second member (2000) allowed"             '[ "$(admrc 2000)" = 0 ]'
ok "admit: uid 0 (direct operator) allowed"          '[ "$(admrc 0)" = 0 ]'
ok "admit: empty owner (direct operator) allowed"    '[ "$(admrc "")" = 0 ]'
ok "admit: NON-member (4000) refused fail-closed E_CAP(12)" '[ "$(admrc 4000)" = 12 ]'

ok "reaper wiring: dr_vps_reaper_sweep calls _dr_vps_egress_reap" \
   'awk "/^dr_vps_reaper_sweep\\(\\)/{s=1} s&&/_dr_vps_egress_reap/{f=1} END{exit !f}" "$REPO/src/dr_vps_reaper.sh"'

echo "-------------------------------------------"
echo "egress shell wiring (admit gate + reaper hook): $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
