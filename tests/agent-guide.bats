#!/usr/bin/env bats
# Drift guard for the standalone agent handout: docs/AGENT-GUIDE.md must document EXACTLY the set of real
# agent verbs -- BOTH directions:
#   forward  -- every verb documented in the guide's fenced blocks is a real bin/rigctl main-dispatch CASE
#               LABEL *and* is in the watcher's REAL allowlist (GLOBAL_VERBS set-elements UNION VM_VERBS
#               dict-keys in src/drvps_rigctl.py); so the guide cannot claim a verb that isn't real+allowed
#               (as USAGE.md's `use --from-snap` claim once had).
#   reverse  -- every real agent verb (a rigctl case label that is ALSO allowlisted) is documented; so the
#               guide cannot silently fall BEHIND the shipped surface (as `version` once did -- a real agent
#               verb that was undocumented, which a one-way guard would miss).
# Operator-only labels (in rigctl but NOT allowlisted) are intentionally excluded from the reverse check --
# the agent guide must not document them.
#
# The extraction + comparison are FACTORED into shared functions (_rigctl_labels / _guide_verbs /
# _drift_check) used by BOTH the real-files test (must PASS) and a deliberately-drifted fixture (must FAIL).
# So breaking the real checker -- not a reimplementation of it -- is what the positive control catches.
# Also checks make-pack.sh --profile=agent and the bin/rigctl pull paired-status path.

load helpers

_root() { cd "$DR_VPS_SRC/.." && pwd; }

# The watcher's REAL agent allowlist, parsed via AST (no import side effects; NOT a naive grep, which would
# also match e.g. "restore" that appears only in the LIFECYCLE tuple, not the allowlist).
_watcher_allow() {
  python3 - "$1" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
verbs = set()
for n in ast.walk(tree):
    if isinstance(n, ast.Assign):
        for t in n.targets:
            if isinstance(t, ast.Name) and t.id in ("GLOBAL_VERBS", "VM_VERBS"):
                v = n.value
                if isinstance(v, ast.Set):
                    verbs |= {e.value for e in v.elts if isinstance(e, ast.Constant)}
                elif isinstance(v, ast.Dict):
                    verbs |= {k.value for k in v.keys if isinstance(k, ast.Constant)}
print("\n".join(sorted(verbs)))
PY
}

# --- Shared drift-check primitives (used by the real-files test AND the drifted-fixture positive control) ---
# rigctl main-dispatch case labels: `  <verb>)` (possibly alternation `  a|b|c)`). The char class allows
# lowercase + digits + '_' + '-' so a future label form (e.g. exec2, snap_x) cannot silently slip the guard.
_rigctl_labels() {  # <rigctl-file>
  grep -oE '^[[:space:]]+[a-z][a-z0-9_|-]*\)' "$1" | sed -E 's/[[:space:]]//g; s/\)//' | tr '|' '\n' | LC_ALL=C sort -u
}
# The verbs a guide documents: within ``` fences, lines whose FIRST token is `rigctl` (indent-tolerant, so an
# accidentally-indented fenced command cannot bypass the forward check). Inline prose `rigctl` is outside the
# fence and ignored. The fence marker is built from octal backticks (no literal backtick in this file).
_guide_verbs() {  # <guide-file>
  local fence; fence=$(printf '\140\140\140')
  awk -v F="$fence" 'index($0,F)==1{f=!f;next} f && $1=="rigctl"{print $2}' "$1" | LC_ALL=C sort -u
}
# Compare three newline-lists (labels, allow, gverbs). Prints a tagged line per drift; returns 1 on any drift.
_drift_check() {  # <labels> <allow> <gverbs>
  local labels="$1" allow="$2" gverbs="$3" v bad=0
  for v in $gverbs; do   # FORWARD: nothing documented that isn't a real, allowlisted verb.
    printf '%s\n' "$labels" | grep -qxF "$v" || { echo "DOC-NOT-LABEL $v"; bad=1; }
    printf '%s\n' "$allow"  | grep -qxF "$v" || { echo "DOC-NOT-ALLOWED $v"; bad=1; }
  done
  for v in $labels; do   # REVERSE: every real agent verb (label AND allowlisted) is documented.
    printf '%s\n' "$allow"  | grep -qxF "$v" || continue        # operator-only label -> not an agent verb, skip
    printf '%s\n' "$gverbs" | grep -qxF "$v" || { echo "AGENT-VERB-UNDOCUMENTED $v"; bad=1; }
  done
  return "$bad"
}

@test "AGENT-GUIDE.md documents EXACTLY the real agent verbs (bin/rigctl case labels INTERSECT watcher allowlist)" {
  local root guide rc watcher; root="$(_root)"
  guide="$root/docs/AGENT-GUIDE.md"; rc="$root/bin/rigctl"; watcher="$root/src/drvps_rigctl.py"
  [ -f "$guide" ]; [ -f "$rc" ]; [ -f "$watcher" ]
  local labels allow gverbs
  labels=$(_rigctl_labels "$rc");   [ -n "$labels" ]
  allow=$(_watcher_allow "$watcher"); [ -n "$allow" ]
  gverbs=$(_guide_verbs "$guide");  [ -n "$gverbs" ]
  run _drift_check "$labels" "$allow" "$gverbs"
  [ "$status" -eq 0 ] || { echo "guide drift:"; echo "$output"; false; }
}

@test "drift guard SELF-TEST: an agent-DISallowed verb ('restore', present only in LIFECYCLE) is not treated as allowed" {
  local watcher allow; watcher="$(_root)/src/drvps_rigctl.py"; allow=$(_watcher_allow "$watcher")
  ! printf '%s\n' "$allow" | grep -qxF restore || false     # NOT in the parsed allowlist ...
  grep -q '"restore"' "$watcher"                   # ... even though it IS quoted elsewhere (would fool a naive grep)
}

@test "drift guard POSITIVE CONTROL: the REAL shared checker independently pins EVERY branch on a drifted fixture" {
  # Runs the ACTUAL _rigctl_labels / _guide_verbs / _drift_check against a synthetic rigctl+guide, so breaking
  # any of those (not a copy of them) makes this test fail. Each fixture verb ISOLATES exactly one branch, so
  # deleting any single check in _drift_check fails a specific assertion (asserting only "nonzero" would let a
  # branch regress silently while other drifts keep the status nonzero):
  #   nolabel      allowlisted + documented, NOT a label  -> ONLY DOC-NOT-LABEL fires   (pins the label check)
  #   notallowed   a label + documented, NOT allowlisted  -> ONLY DOC-NOT-ALLOWED fires (pins the allow check)
  #   indentbogus  INDENTED fenced command                -> must be extracted at all   (pins indent-tolerance)
  #   snap-ls      a real label+allowlisted, UNdocumented  -> AGENT-VERB-UNDOCUMENTED    (pins the reverse loop)
  #   oponly       a label, NOT allowlisted, UNdocumented  -> must be SKIPPED, never flagged (operator-only)
  local fence r g; fence=$(printf '\140\140\140')
  r="$BATS_TEST_TMPDIR/fake-rigctl"; g="$BATS_TEST_TMPDIR/fake-guide.md"
  printf '  create)\n  snap-ls)\n  oponly)\n  notallowed)\n' > "$r"
  printf '%s\nrigctl create <n>\nrigctl nolabel <x>\nrigctl notallowed <y>\n  rigctl indentbogus <z>\n%s\nProse: `rigctl snap-ls` is not a doc entry.\n' "$fence" "$fence" > "$g"
  local labels gverbs allow; labels=$(_rigctl_labels "$r"); gverbs=$(_guide_verbs "$g"); allow=$'create\nsnap-ls\nnolabel'
  run _drift_check "$labels" "$allow" "$gverbs"
  [ "$status" -ne 0 ]                                        # the real checker fires on drift ...
  [[ "$output" == *"DOC-NOT-LABEL nolabel"* ]]              # ... label-membership check fires (nolabel is allowed, so ONLY this branch) ...
  [[ "$output" != *"DOC-NOT-ALLOWED nolabel"* ]]           # ...   (confirming the isolation: nolabel IS allowlisted) ...
  [[ "$output" == *"DOC-NOT-ALLOWED notallowed"* ]]        # ... allow-membership check fires (notallowed IS a label, so ONLY this branch) ...
  [[ "$output" != *"DOC-NOT-LABEL notallowed"* ]]          # ...   (confirming the isolation: notallowed IS a case label) ...
  [[ "$output" == *"indentbogus"* ]]                       # ... the indented fenced command WAS extracted+caught ...
  [[ "$output" == *"AGENT-VERB-UNDOCUMENTED snap-ls"* ]]   # ... the reverse direction fires on an undocumented real verb ...
  [[ "$output" != *oponly* ]]                              # ... but an operator-only (non-allowlisted, undocumented) label is NOT flagged.
  # The main test's verdict is the RETURN STATUS, not the printed diagnostics -- a branch that printed a
  # warning but failed to set bad=1 would let a lone real drift return 0 and be silently accepted. So pin
  # each branch's STATUS contribution with a fixture that drifts via ONLY that branch and asserts nonzero.
  run _drift_check "$(printf 'create')" "$(printf 'create\nnolabel')" "$(printf 'create\nnolabel')"
  [ "$status" -ne 0 ]                                       # DOC-NOT-LABEL alone -> nonzero (nolabel: allowed+documented, not a label)
  run _drift_check "$(printf 'create\nnotallowed')" "$(printf 'create')" "$(printf 'create\nnotallowed')"
  [ "$status" -ne 0 ]                                       # DOC-NOT-ALLOWED alone -> nonzero (notallowed: label+documented, not allowed)
  run _drift_check "$(printf 'create\nsnap-ls')" "$(printf 'create\nsnap-ls')" "$(printf 'create')"
  [ "$status" -ne 0 ]                                       # reverse alone -> nonzero (snap-ls: label+allowed, undocumented)
  # And the clean case: a fixture with no drift passes the SAME checker.
  local gclean; gclean=$(printf '%s\nrigctl create <n>\nrigctl snap-ls\n%s\n' "$fence" "$fence")
  run _drift_check "$(printf 'create\nsnap-ls')" "$(printf 'create\nsnap-ls')" "$(printf '%s' "$gclean" | _guide_verbs /dev/stdin)"
  [ "$status" -eq 0 ]
}

@test "make-pack.sh agent handout: byte-identical to the guide, mode 0644, ONLY output; both --profile spellings" {
  local root guide; root="$(_root)"; guide="$root/docs/AGENT-GUIDE.md"
  local h1="$BATS_TEST_TMPDIR/h1"; mkdir -p "$h1"
  HOME="$h1" run bash "$root/bin/make-pack.sh" --profile=agent
  [ "$status" -eq 0 ]
  [ "$(find "$h1/tmp" -type f | wc -l)" -eq 1 ]                 # exactly ONE output file (nothing else leaked)
  local o1; o1=$(find "$h1/tmp" -type f); [[ "$o1" == *drvps-agent-guide-*.md ]]
  cmp -s "$o1" "$guide"                                         # byte-identical to the guide
  [ "$(stat -c '%a' "$o1")" = 644 ]                            # mode 0644
  local h2="$BATS_TEST_TMPDIR/h2"; mkdir -p "$h2"
  HOME="$h2" run bash "$root/bin/make-pack.sh" --profile agent  # space spelling
  [ "$status" -eq 0 ]; [ "$(find "$h2/tmp" -type f | wc -l)" -eq 1 ]
}

@test "make-pack.sh publishes BOTH profiles atomically (temp staged in TMP_DIR + same-fs rename, never a partial canonical artifact)" {
  local root mp; root="$(_root)"; mp="$root/bin/make-pack.sh"
  # Both profiles must stage under TMP_DIR (same filesystem as OUT) and publish via `mv -fT`, so OUT can
  # never be a truncated/zero-byte artifact on ENOSPC (a direct install/write or a cross-fs mv could).
  grep -q 'mktemp "${TMP_DIR}/.drvps-agent-guide' "$mp"    # agent: temp handout in TMP_DIR ...
  grep -q 'mktemp "${TMP_DIR}/.make-pack'          "$mp"    # full:  temp archive in TMP_DIR ...
  [ "$(grep -c 'mv -fT "\$ARCH_TMP" "\$OUT"\|mv -fT "\$TMP_OUT" "\$OUT"' "$mp")" -eq 2 ]   # ... each published by rename
  ! grep -q 'mktemp "${TMPDIR:-/tmp}' "$mp" || false               # never stage the published artifact on a (possibly cross-fs) system temp
  ! grep -qE 'install -m 0644 -T "\$GUIDE" "\$OUT"' "$mp" || false  # agent must NOT install directly to the canonical OUT
}

@test "make-pack.sh full profile: excludes runtime/secret files and normalizes archive ownership to 0/0 (no packager identity, no stray secret)" {
  local root mp; root="$(_root)"; mp="$root/bin/make-pack.sh"
  # A fake checkout salted with the exact files a dirty tree could carry; make-pack derives SRC_DIR from its
  # own location, so the script must live at <fake>/distro-rig-vps/bin/make-pack.sh.
  local fake="$BATS_TEST_TMPDIR/fake"; mkdir -p "$fake/distro-rig-vps"
  install -D -m 0755 "$mp" "$fake/distro-rig-vps/bin/make-pack.sh"
  mkdir -p "$fake/distro-rig-vps/src" "$fake/distro-rig-vps/spool/results" "$fake/distro-rig-vps/logs" "$fake/distro-rig-vps/secrets"
  echo 'echo hi'      > "$fake/distro-rig-vps/src/keep.sh"          # a normal source file -> MUST ship
  echo '{"secret":1}' > "$fake/distro-rig-vps/spool/results/r1.json"  # runtime result payload -> excluded
  echo 'rotated'      > "$fake/distro-rig-vps/logs/audit.log.1"     # rotated log (not *.log) -> excluded
  echo 'TOKEN=x'      > "$fake/distro-rig-vps/.env"                 # stray credential -> excluded
  echo 'PRIVKEY'      > "$fake/distro-rig-vps/secrets/id_ed25519"   # private key -> excluded
  echo 'tok'          > "$fake/distro-rig-vps/secrets/token.txt"    # EXTENSIONLESS-dir secret -> excluded
  mkdir -p "$fake/distro-rig-vps/keys"
  echo 'cred'         > "$fake/distro-rig-vps/keys/credential"      # extensionless key file -> excluded
  local h="$BATS_TEST_TMPDIR/fh"; mkdir -p "$h"
  HOME="$h" run bash "$fake/distro-rig-vps/bin/make-pack.sh" --profile=full
  [ "$status" -eq 0 ]
  local o; o=$(find "$h/tmp" -name '*.tar.gz'); [ -n "$o" ]
  local members; members=$(tar tzf "$o")
  echo "$members" | grep -q 'distro-rig-vps/src/keep.sh'          # the normal source file IS shipped ...
  ! echo "$members" | grep -q 'spool/results/r1.json' || false            # ... runtime result payload is NOT ...
  ! echo "$members" | grep -q 'audit.log.1' || false                       # ... rotated log is NOT ...
  ! echo "$members" | grep -q '/.env' || false                             # ... stray credential is NOT ...
  ! echo "$members" | grep -q 'id_ed25519' || false                        # ... private key is NOT.
  ! echo "$members" | grep -q 'secrets/token.txt' || false                # generic secrets/ dir is NOT shipped
  ! echo "$members" | grep -q 'keys/credential' || false                  # generic keys/ dir is NOT shipped
  # Ownership is normalized: every member is 0/0 (no packager account name/uid leaked).
  local owners; owners=$(tar tvzf "$o" | awk '{print $2}' | sort -u)
  [ "$owners" = "0/0" ]
}

@test "make-pack.sh full profile: a checkout reached through a directory SYMLINK still packs the real tree (pwd -P), not the link" {
  local root mp; root="$(_root)"; mp="$root/bin/make-pack.sh"
  # Real tree at real/distro-rig-vps, plus a directory symlink pointing at it; invoke via the symlink.
  local base="$BATS_TEST_TMPDIR/sl"; mkdir -p "$base/real/distro-rig-vps/src"
  install -D -m 0755 "$mp" "$base/real/distro-rig-vps/bin/make-pack.sh"
  echo 'echo hi' > "$base/real/distro-rig-vps/src/keep.sh"
  ln -s "$base/real/distro-rig-vps" "$base/link"
  local h="$BATS_TEST_TMPDIR/slh"; mkdir -p "$h"
  HOME="$h" run bash "$base/link/bin/make-pack.sh" --profile=full   # reached through the symlink
  [ "$status" -eq 0 ]
  local o; o=$(find "$h/tmp" -name '*.tar.gz'); [ -n "$o" ]
  local members; members=$(tar tzf "$o")
  echo "$members" | grep -q 'distro-rig-vps/src/keep.sh'   # the REAL tree was traversed (not just a symlink entry)
  ! echo "$members" | grep -qE '^link( ->|$)|/link$' || false       # the archive is not merely the link node
}

@test "make-pack.sh rejects an unknown profile AND a bare --profile (usage 2)" {
  local root; root="$(_root)"
  HOME="$BATS_TEST_TMPDIR" run bash "$root/bin/make-pack.sh" --profile=bogus; [ "$status" -eq 2 ]
  HOME="$BATS_TEST_TMPDIR" run bash "$root/bin/make-pack.sh" --profile;        [ "$status" -eq 2 ]
}

@test "bin/rigctl pull: checks BOTH pipe statuses (jq unreadable != success) + SIGPIPE 141 = success" {
  local rc; rc="$(_root)/bin/rigctl"
  grep -q 'PIPESTATUS\[@\]'              "$rc"       # captures BOTH jq + base64 statuses atomically
  grep -q 'content_b64 became unreadable' "$rc"      # a jq failure feeding base64 EOF is NOT a false success
  grep -q 'rigctl: pull: corrupt base64'  "$rc"      # genuine corruption still fails
  grep -q '0|141) exit 0'                 "$rc"      # a downstream close (SIGPIPE 141) = success
}

@test "handout/ real copies are byte-identical to the canonical docs/ files (stale copy = drift failure)" {
  local root; root="$(_root)"
  cmp -s "$root/docs/AGENT-GUIDE.md"    "$root/handout/AGENT-GUIDE.md"
  cmp -s "$root/docs/ORCHESTRATOR-GUIDE.md" "$root/handout/ORCHESTRATOR-GUIDE.md"
}
