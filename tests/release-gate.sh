#!/usr/bin/env bash
# shellcheck disable=SC2016   # many run1/subshell command strings are single-quoted ON PURPOSE (deferred eval)
# release-gate.sh -- THE single command that verifies a distro-rig-vps release. It exists because the pieces
# were previously scattered (CI ran only *.bats; the 11 offline python suites and ~10 offline .sh tests were
# run by hand, so a green CI did NOT mean the offline suite passed -- a gap that let real wiring bugs through).
# One runner, three tiers, an explicit PASS/SKIP/FAIL tally so releasing is reproducible:
#
#   tests/release-gate.sh              # TIER 1 offline only (bats + python + sh + shellcheck + ast + residue)
#   tests/release-gate.sh --container  # + TIER 2 disposable rootless-podman e2e (real squid, split-UID, atomic)
#   tests/release-gate.sh --live       # + TIER 3 the nested "really works" run (needs KVM; see dogfood/)
#   tests/release-gate.sh --all        # tiers 1+2+3
#
# A tier that is EXPLICITLY REQUESTED but whose prerequisite is missing (no podman / no /dev/kvm) is a FAILURE,
# not a skip -- you asked to run it and it did not. An UNREQUESTED tier just SKIPs. Run the OFFLINE tier as a
# NON-root user -- the bats suite asserts 0700/0600 refusals a root process would bypass (CI runs it as `ci`).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT" || exit 2
WANT_CONTAINER=0; WANT_LIVE=0
for a in "$@"; do case "$a" in
  --container) WANT_CONTAINER=1;;
  --live) WANT_LIVE=1;;
  --all) WANT_CONTAINER=1; WANT_LIVE=1;;
  -h|--help) sed -n '3,18p' "$0"; exit 0;;
  *) echo "unknown arg: $a (see --help)" >&2; exit 2;;
esac; done

# ---- test classification. The completeness check below FAILS on any tests/*.sh or tests/*test*.py NOT listed
# here, so a newly-added test can never be silently unrun -- the EXACT failure mode this gate exists to prevent.
OFFLINE_SH="egress-setup-lock egress-render-noop egress-shell-wiring setup-render-inputs drvps-top-once drvps-top-test drvps-top-crossframe drvps-top-hardening drvps-top-setup drvps-top-integration firewalld-dr2 image-bake-guards-test"
CONTAINER_SH="egress-splituid egress-squid-run"                              # run DIRECTLY; they spawn their own podman
CONTAINER_INNER_SH="egress-approve-prodpath egress-squid-approve-container egress-squid-container egress-squid-live egress-splituid-inner setup-atomic-install"  # invoked INSIDE a container by a runner below (verified)
NONTEST_SH="build-matrix-goldens mk-share-review-bundle release-gate"        # operator utilities + this runner, not tests
OFFLINE_PY="drvps-egress-layout-test drvps-egress-model-test drvps-egress-req-test egress-approve-test egress-migrate-test egress-verb-test drvps-top-config-test drvps-top-feed-test drvps-top-publish-test drvps-top-view-test drvps-top-acquire-test"

pass=0; failn=0; skip=0; FAILED=""
run1(){ # <label> <command...> : run a suite, tally, keep going on failure (collect ALL failures, not just the first)
  local label="$1"; shift
  if "$@" >"/tmp/rg.$$.out" 2>&1; then echo "  PASS  $label"; pass=$((pass+1))
  else echo "  FAIL  $label"; failn=$((failn+1)); FAILED="$FAILED\n    $label"; sed 's/^/      | /' "/tmp/rg.$$.out" | tail -8; fi
  rm -f "/tmp/rg.$$.out"
}
markfail(){ echo "  FAIL  $1"; failn=$((failn+1)); FAILED="$FAILED\n    $1"; }
py_ok(){ (umask "$1"; python3 "$2") >"/tmp/rg.$$.p" 2>&1; local r=$?; grep -qE "FAIL=[1-9]|Traceback" "/tmp/rg.$$.p" && r=1; [ "$r" = 0 ] || tail -6 "/tmp/rg.$$.p"; rm -f "/tmp/rg.$$.p"; return $r; }

echo "================ TIER 1: OFFLINE (no podman, no KVM) ================"
[ "$(id -u)" = 0 ] && echo "  WARNING: running as root -- the bats permission-refusal tests are unreliable as root."

echo "-- test-inventory completeness (no test silently unrun, dead, or removed) --"
# (a) every tests/*.sh is classified (a NEW test can't be silently ignored); (b) every classified name still
# EXISTS (a REMOVED test is detected, not silently dropped); (c) every CONTAINER_INNER is actually INVOKED by a
# runner (a classified-but-dead test like the old egress-squid-behavioral is detected). Same for *test*.py.
run1 "every tests/*.sh is classified" bash -c '
  known=" '"$OFFLINE_SH $CONTAINER_SH $CONTAINER_INNER_SH $NONTEST_SH"' "; bad=""
  for f in tests/*.sh; do b=$(basename "$f" .sh); case "$known" in *" $b "*) ;; *) bad="$bad $b";; esac; done
  [ -z "$bad" ] || { echo "UNCLASSIFIED tests/*.sh (classify in release-gate.sh):$bad"; exit 1; }'
run1 "every classified test still exists (removal detected)" bash -c '
  bad=""; for b in '"$OFFLINE_SH $CONTAINER_SH $CONTAINER_INNER_SH $NONTEST_SH"'; do [ -f "tests/$b.sh" ] || bad="$bad $b"; done
  [ -z "$bad" ] || { echo "classified but MISSING tests/*.sh (remove from release-gate.sh, or restore):$bad"; exit 1; }'
run1 "every CONTAINER_INNER test is INVOKED (non-comment) by a runner" bash -c '
  # verify an EXECUTABLE `tests/<b>.sh` invocation on a NON-comment line of a runner (egress-squid-run.sh,
  # egress-splituid.sh, or THIS gate for setup-atomic-install) -- a bare substring match would accept a
  # commented-out or disabled invocation, so drop comment lines first, then require the invocation path.
  # Anchor to COMMAND POSITION: the invocation must be the command at the START of a non-comment line
  # (`podman run ...` or `bash ...`), so `false && bash t.sh` / `echo bash t.sh` (test-name present but not
  # executed) do NOT satisfy it. This is best-effort static analysis -- no grep can prove a line truly executes
  # against deliberate obfuscation; tier 2 ACTUALLY RUNS these inner tests, which is the real coverage guarantee.
  bad=""; for b in '"$CONTAINER_INNER_SH"'; do
    grep -hE "tests/$b\.sh" tests/egress-squid-run.sh tests/egress-splituid.sh tests/release-gate.sh 2>/dev/null \
      | grep -qE "^[[:space:]]*(podman run|bash )[^#]*tests/$b\.sh" || bad="$bad $b"
  done
  [ -z "$bad" ] || { echo "CONTAINER_INNER classified but NOT invoked (command-position) by any runner:$bad"; exit 1; }'
run1 "every tests/*test*.py is in OFFLINE_PY" bash -c '
  known=" '"$OFFLINE_PY"' "; bad=""
  for f in tests/*test*.py; do b=$(basename "$f" .py); case "$known" in *" $b "*) ;; *) bad="$bad $b";; esac; done
  [ -z "$bad" ] || { echo "UNLISTED python test (add to OFFLINE_PY):$bad"; exit 1; }'

echo "-- bats (all suites) --"
run1 "bats (all *.bats)" bash -c 'rc=0; for f in tests/*.bats; do bats "$f" >/dev/null 2>&1 || { echo "not-ok: $f"; rc=1; }; done; exit $rc'

echo "-- offline python (both umask 0077 and 0022) --"
for b in $OFFLINE_PY; do
  t="tests/$b.py"; [ -f "$t" ] || { markfail "$b.py MISSING"; continue; }
  run1 "$b.py @umask0077" py_ok 0077 "$t"
  run1 "$b.py @umask0022" py_ok 0022 "$t"
done

echo "-- offline sh (no container/root needed) --"
for b in $OFFLINE_SH; do
  t="tests/$b.sh"; [ -f "$t" ] || { markfail "$b.sh MISSING"; continue; }
  run1 "$b.sh" bash "$t"
done

echo "-- shellcheck (documented per-file exceptions) --"
run1 "shellcheck (all shipped bash)" bash -c '
  set -e
  shellcheck -x -s bash --exclude=SC2163,SC2012 bin/dr-vps-setup
  shellcheck -x -s bash --exclude=SC2034 src/dr_vps_domain.sh
  shellcheck -x -s bash --exclude=SC2016 src/dr_vps_snapshot.sh
  shellcheck -x -s bash --exclude=SC2016 src/dr_vps_image.sh
  shellcheck -x -s bash --exclude=SC2034 tools/drvps-top
  for f in bin/dr-vps bin/rigctl bin/drvps-rigctl bin/drvps-rigreaper bin/drvps-rigsubmit bin/make-pack.sh \
           bin/drvps-top bin/drvps-top-operator bin/drvps-top-publish tools/*.sh; do shellcheck -x -s bash "$f"; done
  for f in src/dr_vps_*.sh; do case "$f" in */dr_vps_domain.sh|*/dr_vps_snapshot.sh|*/dr_vps_image.sh) continue;; esac
    shellcheck -x -s bash "$f"; done'

echo "-- python ast (every shipped python program) --"
run1 "python ast (bin+src+tools)" bash -c '
  set -e
  for f in src/*.py tools/*.py; do python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f"; done
  for f in bin/*; do case "$(head -1 "$f")" in *python*) python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f";; esac; done'

echo "-- no internal-review residue (published-state cleanliness) --"
# This checker and CI's residue gate are the ONLY files that legitimately contain these tokens (as search
# patterns), so both exclude release-gate.sh -- else the observer flags itself (self-reference). It runs the
# SAME three pattern classes CI does (reviewer handle + provider shorthand + review-label class) so a local
# RELEASE-GATE: PASS cannot diverge from CI's residue gate. Any OTHER file matching is a real violation.
run1 "residue gate (handle + provider shorthand + review-label class)" bash -c '
  X="--exclude-dir=.git --exclude-dir=.github --exclude=release-gate.sh"
  ! grep -rniE "winhelm" $X . &&
  ! grep -rnE "\bgpt\b|\bgrok\b" $X . &&
  ! grep -rnE "finding r?[0-9]+:|CODE review r[0-9]|FIX-r[0-9]|R[0-9]-N[0-9]|[A-Z][0-9]*-MUST-[0-9]|\b[A-Z]-N[0-9]\b|review #[0-9]|review-final|round-[0-9]+ review|winhelm conv r[0-9]|whole-drvps r[0-9]|6angle|ARCH r[0-9] f[0-9]|\bCOR-[0-9]+\b|\bMOCK-[0-9]\b|\br[0-9]+ [MBf][0-9]+\b" $X .'

echo "================ TIER 2: CONTAINER e2e (disposable rootless podman) ================"
if [ "$WANT_CONTAINER" = 1 ]; then
  if command -v podman >/dev/null 2>&1; then
    run1 "atomic-install unit (root-in-container + positive control)" \
      podman run --rm -v "$ROOT":/repo:ro,Z registry.fedoraproject.org/fedora:latest bash /repo/tests/setup-atomic-install.sh
    for b in $CONTAINER_SH; do run1 "$b.sh" bash "tests/$b.sh"; done
  else markfail "tier 2 REQUESTED but podman is not available"; fi
else echo "  SKIP  tier 2: pass --container to run it"; skip=$((skip+1)); fi

echo "================ TIER 3: NESTED live 'really works' (needs KVM) ================"
if [ "$WANT_LIVE" = 1 ]; then
  if [ -e /dev/kvm ]; then
    run1 "nested dogfood (real installer + egress + drvps-top in an L1 VM)" \
      env DRVPS_LIVE=1 bash tests/dogfood/nested-selftest.sh
  else markfail "tier 3 REQUESTED but /dev/kvm is absent (run on a KVM host)"; fi
else echo "  SKIP  tier 3: pass --live to run it (needs KVM; touches a real rig)"; skip=$((skip+1)); fi

echo "==============================================="
printf 'release-gate: PASS=%d FAIL=%d SKIP=%d\n' "$pass" "$failn" "$skip"
[ "$failn" = 0 ] || { printf 'FAILED suites:%b\n' "$FAILED"; echo "RELEASE-GATE: FAIL"; exit 1; }
echo "RELEASE-GATE: PASS"
