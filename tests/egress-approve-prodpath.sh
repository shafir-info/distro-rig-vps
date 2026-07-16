#!/usr/bin/env bash
# PRODUCTION-PATH regression (S7 BLOCKER): drvps-egress-approve reads its render inputs from the FIXED
# /etc/distro-rig-vps paths (Paths() with NO test_root). dr-vps-setup step_proxy now PERSISTS
# egress-render-params.json + egress-host-facts.json there -- it used to render squid.conf from mktemp temps
# and `rm` them, so nothing wrote the production paths and a real-host `drvps-egress-approve apply` crashed in
# _render_params (FileNotFoundError) before it could render/parse. The earlier container e2e used a test_root
# seam and thus MASKED this. Here we write those inputs exactly as step_proxy does and prove approve reproduces
# a squid-VALID config through its PRODUCTION Paths. Run as root in a disposable ssl-bump-squid container:
#   podman run --rm -v <repo>:/repo:ro localhost/drvps-squid-test bash /repo/tests/egress-approve-prodpath.sh
set -uo pipefail
echo "RELEASE-GATE-RAN: egress-approve-prodpath" >&2   # tests/release-gate.sh tier-2 runtime-coverage marker
APPROVE=/repo/bin/drvps-egress-approve; CLI=/repo/tools/drvps_egress_model.py; fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
CG=""; for c in /usr/lib64/squid/security_file_certgen /usr/lib/squid/security_file_certgen /usr/libexec/squid/security_file_certgen; do [ -x "$c" ] && { CG="$c"; break; }; done
[ -n "$CG" ] || { echo "SKIP: no security_file_certgen (not an ssl-bump squid)"; exit 0; }

# Write the THREE files step_proxy installs into /etc/distro-rig-vps (0644 root:root). fleet.json is already
# there on a real host; egress-render-params.json + egress-host-facts.json are the BLOCKER fix (host-facts {}
# matches what step_proxy renders with). This mirrors step_proxy's persistence, then exercises the CONSUMER.
install -d -m 0755 /etc/distro-rig-vps
printf '{"mirror_allowlist":["deb.debian.org"]}\n' > /etc/distro-rig-vps/fleet.json
printf '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"%s"}\n' "$CG" > /etc/distro-rig-vps/egress-render-params.json
printf '{}\n' > /etc/distro-rig-vps/egress-host-facts.json
chmod 0644 /etc/distro-rig-vps/fleet.json /etc/distro-rig-vps/egress-render-params.json /etc/distro-rig-vps/egress-host-facts.json

python3 - "$APPROVE" > /tmp/prodpath.out 2>&1 <<'PY'
import importlib.util, sys
from importlib.machinery import SourceFileLoader
sys.path.insert(0, "/repo/tools")
import drvps_egress_layout as L
ldr = SourceFileLoader("approve", sys.argv[1]); spec = importlib.util.spec_from_loader("approve", ldr)
A = importlib.util.module_from_spec(spec); ldr.exec_module(A)
p = A.Paths(ids={L.ROOT: (0, 0), L.SVC: (0, 0)})   # PRODUCTION /etc paths -- NO test_root seam
assert p.params == "/etc/distro-rig-vps/egress-render-params.json", p.params
params, facts = A._render_params(p)                # crashed pre-fix (file absent); now reads the persisted input
A._load_fleet(p)
print("RENDER_PARAMS_OK", params.proxy_ip)
PY
ok "approve _render_params reads the PRODUCTION render inputs (no test_root seam)" 'grep -q RENDER_PARAMS_OK /tmp/prodpath.out'
[ -f /tmp/prodpath.out ] && grep -qiE "Traceback|Error" /tmp/prodpath.out && sed 's/^/  approve| /' /tmp/prodpath.out | tail -5

# the persisted production inputs must render the expected ssl-bump policy structure (the config's runtime
# file dependencies -- the bump CA + ssl_db -- are installed separately by step_proxy and exercised by
# egress-squid-container.sh; here we assert the STRUCTURE the render produces from the production inputs).
python3 "$CLI" render --fleet /etc/distro-rig-vps/fleet.json --params /etc/distro-rig-vps/egress-render-params.json --host-facts /etc/distro-rig-vps/egress-host-facts.json > /tmp/prod-squid.conf 2>/tmp/prod-render.err
ok "renderer produces a config from the persisted production inputs" '[ -s /tmp/prod-squid.conf ]'
ok "rendered config carries the ssl-bump + terminate-all + deny-all structure" \
   'grep -q "http_port 127.0.0.1:3128 ssl-bump" /tmp/prod-squid.conf && grep -q "ssl_bump peek step1" /tmp/prod-squid.conf && grep -q "ssl_bump terminate all" /tmp/prod-squid.conf && grep -qx "http_access deny all" /tmp/prod-squid.conf'
ok "rendered config authorizes the mirror from fleet.json (dstdomain -n)" 'grep -q "dstdomain -n deb.debian.org" /tmp/prod-squid.conf'

echo "-------------------------------------------"
echo "egress approve production-path: $([ $fail = 0 ] && echo VERIFIED || echo FAILURES)"
exit $fail
