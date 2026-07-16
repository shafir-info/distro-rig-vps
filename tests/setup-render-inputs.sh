#!/usr/bin/env bash
# OFFLINE contract guard for the installer->approve render-input seam -- the BLOCKER-2 class (the installer
# rendered squid.conf from temp files and deleted them, so nothing wrote the /etc render inputs that
# drvps-egress-approve reads, and `apply` crashed on a real host). The offline + container tests never saw it
# because they hand-provided those inputs under a test_root. The FULL runtime proof is tier-3 (nested-selftest,
# a real install) which needs KVM; this catches a SOURCE-level regression -- someone dropping the persist calls
# or the two sides drifting on the path -- with no KVM, so it runs in the default (offline) gate. It is a
# deliberately shallow "producer writes what the consumer reads" check: the deep behavior is unit-tested
# (setup-atomic-install.sh) + end-to-end (egress-approve-prodpath.sh, nested-selftest.sh).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
S="$ROOT/bin/dr-vps-setup"; A="$ROOT/bin/drvps-egress-approve"

for p in egress-render-params.json egress-host-facts.json; do
  # PRODUCER: step_proxy must atomically persist this render input to the fixed /etc path.
  ok "installer persists /etc/distro-rig-vps/$p via _dr_atomic_install_root" \
     "grep -q \"_dr_atomic_install_root .*/etc/distro-rig-vps/$p\" '$S'"
  # CONSUMER: the approve tool must read the SAME fixed path in its production Paths.
  ok "approve reads /etc/distro-rig-vps/$p (production Paths)" \
     "grep -q \"/etc/distro-rig-vps/$p\" '$A'"
done

# the persist helper is top-level (so setup-atomic-install.sh can unit-test it directly, incl. its failure path)
ok "_dr_atomic_install_root is a top-level helper" "grep -qE '^_dr_atomic_install_root\\(\\) \\{' '$S'"

echo "-------------------------------------------"
echo "setup render-inputs contract: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
