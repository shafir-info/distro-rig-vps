#!/usr/bin/env bash
# Offline test of the pre-bake free-disk guard (src/dr_vps_image.sh _dr_vps_bake_disk_ok). Uses a
# DETERMINISTIC df stub (STUB_AVAIL / STUB_DF_FAIL) so outcomes don't depend on the box's real free
# space. The appliance-DNS auto-fix was withdrawn (needs a KVM/libguestfs test) so there is
# nothing else to test here offline.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dr_vps_die(){ echo "die: $2" >&2; return 1; }
DR_VPS_E_CAP=24
eval "$(sed -n '/^_dr_vps_bake_disk_ok() {/,/^}/p' "$REPO/src/dr_vps_image.sh")"
fail=0; ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

# deterministic df: emit STUB_AVAIL as the Available (MiB) column; STUB_DF_FAIL=1 -> df errors (no row)
df(){ [ "${STUB_DF_FAIL:-0}" = 1 ] && return 1; printf 'Filesystem 1M-blocks Used Available Capacity Mounted\n/dev/stub 100000 1 %s 1%% /\n' "${STUB_AVAIL:-}"; }

STUB_AVAIL=20000 _dr_vps_bake_disk_ok /x;         ok "20000 MiB >= 10240 default -> pass"        '[ $? = 0 ]'
STUB_AVAIL=500   _dr_vps_bake_disk_ok /x 2>/dev/null; ok "500 MiB < 10240 default -> fail closed" '[ $? != 0 ]'
STUB_AVAIL=20000 _dr_vps_bake_disk_ok /x 512;     ok "positional min 512, 20000 avail -> pass"    '[ $? = 0 ]'
STUB_AVAIL=300   _dr_vps_bake_disk_ok /x 512 2>/dev/null; ok "positional min 512, 300 avail -> fail" '[ $? != 0 ]'
# non-numeric min falls back to the 10240 floor (not 0) -- proven by an exact boundary pair
STUB_AVAIL=10240 _dr_vps_bake_disk_ok /x abc;     ok "bad min -> 10240 floor (10240 passes)"      '[ $? = 0 ]'
STUB_AVAIL=10239 _dr_vps_bake_disk_ok /x abc 2>/dev/null; ok "bad min -> 10240 floor (10239 fails)" '[ $? != 0 ]'
# unreadable/malformed df -> fail closed by default; explicit opt-out proceeds
STUB_DF_FAIL=1   _dr_vps_bake_disk_ok /x 1 2>/dev/null; ok "df failure -> fail closed"             '[ $? != 0 ]'
STUB_AVAIL=notanum _dr_vps_bake_disk_ok /x 1 2>/dev/null; ok "malformed avail -> fail closed"      '[ $? != 0 ]'
STUB_DF_FAIL=1 DR_VPS_ALLOW_UNKNOWN_FREE=1 _dr_vps_bake_disk_ok /x 1 2>/dev/null; ok "df failure + opt-out -> proceeds" '[ $? = 0 ]'

echo "-------------------------------------------"; echo "image bake guards: $([ $fail = 0 ] && echo PASS || echo FAIL)"; exit $fail
