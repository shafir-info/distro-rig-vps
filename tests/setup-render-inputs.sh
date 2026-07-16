#!/usr/bin/env bash
# OFFLINE contract guard for the installer->approve render-input seam -- the BLOCKER-2 class (the installer
# rendered squid.conf from temp files and deleted them, so nothing wrote the /etc render inputs
# drvps-egress-approve reads, and `apply` crashed on a real host). The offline + container tests never saw it
# because they hand-provided those inputs under a test_root. The FULL runtime proof is tier-3 (nested-selftest,
# a real install). Here we bind PRODUCER<->CONSUMER at the source level: the thing step_proxy renders AS the
# params (_rp) must be persisted to egress-render-params.json, and the thing it renders AS host-facts (_rhf) to
# egress-host-facts.json -- a mutation that persists the WRONG source to a dest (e.g. host-facts -> the
# render-params path) means approve cannot reproduce the installed policy, and it breaks the exact binding below.
# (Deep behavior is unit-tested by setup-atomic-install.sh + end-to-end by egress-approve-prodpath.sh /
# nested-selftest.sh; a source-level binding is the strongest a KVM-free offline check can assert.)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
S="$ROOT/bin/dr-vps-setup"; A="$ROOT/bin/drvps-egress-approve"

# CONSUMER: the approve tool reads the FIXED /etc paths in its production Paths.
for p in egress-render-params.json egress-host-facts.json; do
  ok "approve reads /etc/distro-rig-vps/$p (production Paths)" "grep -q '/etc/distro-rig-vps/$p' '$A'"
done

# PRODUCER binding: assert step_proxy's source<->dest wiring in one python pass (avoids brittle shell quoting).
ok "installer binds each render source to the CORRECT dest (_rp->render-params, _rhf->host-facts)" \
   "python3 - '$S' <<'PY'
import re, sys
s = open(sys.argv[1]).read()
checks = {
  'params dest var':   '_pp=/etc/distro-rig-vps/egress-render-params.json' in s,
  'hostfacts dest var':'_ph=/etc/distro-rig-vps/egress-host-facts.json' in s,
  'render uses _rp as params':      re.search(r'render .*--params \"\\\$_rp\"', s) is not None,
  'render uses _rhf as host-facts': re.search(r'render .*--host-facts \"\\\$_rhf\"', s) is not None,
  'params SOURCE _rp -> render-params dest _pp':   '_dr_atomic_install_root \"\$_rp\" \"\$_pp\"' in s,
  'hostfacts SOURCE _rhf -> host-facts dest _ph':  '_dr_atomic_install_root \"\$_rhf\" \"\$_ph\"' in s,
}
bad = [k for k, v in checks.items() if not v]
sys.exit('unbound: ' + '; '.join(bad) if bad else 0)
PY"
ok "host-facts are DERIVED (not the empty {} that omitted the SSRF deny set)" \
   "! grep -qE \"printf '[{]}\\\\\\\\n' >\\\"\\\$_rhf\\\"\" '$S'"
ok "_dr_atomic_install_root is a top-level helper" "grep -qE '^_dr_atomic_install_root\\(\\) \\{' '$S'"

echo "-------------------------------------------"
echo "setup render-inputs contract: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
