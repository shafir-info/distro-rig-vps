#!/usr/bin/env bats
# Drift + safety guard for the drvps agent SKILL pack (share/skills/drvps/ + bin/drvps-skill-install).
# The skill lets an AI agent (a drvpsctl/drvpsvc member) auto-discover how to drive the rig after a context
# clear. This suite pins:
#   * SKILL.md carries valid Claude-skill frontmatter (name: drvps + a non-empty description);
#   * FULL verb-drift: every `rigctl <verb>` SKILL.md names -- fenced OR inline prose -- is a REAL allowlisted
#     agent verb (the watcher GLOBAL_VERBS/VM_VERBS allowlist agent-guide.bats also pins), positive-controlled;
#   * the shipped references/ point at the drift-tested handout guides (agent-guide.bats keeps those == docs/);
#   * drvps-skill-install proves ownership by a TOOL-WRITTEN provenance marker (never the skill's name), so it
#     NEVER overwrites/deletes a foreign same-name skill, never descends a planted symlink, and never leaves a
#     half-converted state; copy is self-contained + byte-faithful + idempotent + atomic.

_root() { cd "$BATS_TEST_DIRNAME/.." && pwd -P; }
_tool() { echo "$(_root)/bin/drvps-skill-install"; }

# The watcher's REAL agent allowlist (AST, not a naive grep) -- shared shape with agent-guide.bats.
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

# EVERY `rigctl <verb>` a doc names -- fenced command AND inline prose (`... rigctl recreate ...`), tolerant of
# any horizontal whitespace (one space, several, or a tab) between `rigctl` and the verb. The guide extractor
# only scans fenced first-token lines; a SKILL is short and prose-heavy, so we scan the whole text.
_doc_verbs() { grep -oE 'rigctl[[:space:]]+[a-z][a-z-]*' "$1" | sed -E 's/^rigctl[[:space:]]+//' | LC_ALL=C sort -u; }

_missing() {  # <allow-newline-list> <doc> -> prints any verb named by <doc> that is NOT allowlisted
  local allow="$1" doc="$2" v out=""
  for v in $(_doc_verbs "$doc"); do printf '%s\n' "$allow" | grep -qxF "$v" || out="$out $v"; done
  echo "$out"
}

@test "SKILL.md has valid Claude-skill frontmatter (name: drvps + non-empty description)" {
  local skill; skill="$(_root)/share/skills/drvps/SKILL.md"
  [ -f "$skill" ]
  run head -1 "$skill"; [ "$output" = "---" ]
  run grep -cE '^name:[[:space:]]*drvps[[:space:]]*$' "$skill";     [ "$output" -eq 1 ]
  run grep -cE '^description:[[:space:]]*[^[:space:]].+' "$skill";  [ "$output" -eq 1 ]
}

@test "SKILL.md names ONLY real allowlisted agent verbs (fenced AND inline) -- positive-controlled" {
  local root allow; root="$(_root)"; allow=$(_watcher_allow "$root/src/drvps_rigctl.py")
  [ -n "$allow" ]
  run _missing "$allow" "$root/share/skills/drvps/SKILL.md"
  [ -z "${output// /}" ] || { echo "SKILL.md names non-allowlisted verb(s):$output" >&2; false; }
  # POSITIVE CONTROL: a DISTINCT fake verb per spelling -- inline one-space, inline multi-space, tab-separated
  # fenced -- and EACH must be caught (so a regression to a single-space-only regex, which would still catch the
  # first, is detected: all three must appear).
  local f="$BATS_TEST_TMPDIR/fake.md"
  { cat "$root/share/skills/drvps/SKILL.md"
    printf 'Try `rigctl teleportx 1` now.\n'
    printf 'Or  `rigctl   teleporty 2` maybe.\n'
    printf '```\nrigctl\tteleportz 3\n```\n'
  } > "$f"
  run _missing "$allow" "$f"
  [[ "$output" == *teleportx* ]] && [[ "$output" == *teleporty* ]] && [[ "$output" == *teleportz* ]]
}

@test "shipped references/ point at the drift-tested handout guides (kept == docs/ by agent-guide.bats)" {
  local root a o; root="$(_root)"
  a="$root/share/skills/drvps/references/AGENT-GUIDE.md"; o="$root/share/skills/drvps/references/ORCHESTRATOR-GUIDE.md"
  [ -L "$a" ] && [ -L "$o" ]
  [ "$(readlink -f "$a")" = "$root/handout/AGENT-GUIDE.md" ]
  [ "$(readlink -f "$o")" = "$root/handout/ORCHESTRATOR-GUIDE.md" ]
  [ -r "$a" ] && [ -r "$o" ]
}

@test "drvps-skill-install compiles (python3 -m py_compile)" {
  run python3 -m py_compile "$(_tool)"
  [ "$status" -eq 0 ] || { echo "$output" >&2; false; }
}

@test "copy (default): self-contained, byte-faithful, marker-stamped, idempotent; --status reports copied" {
  local root h d; root="$(_root)"; h="$BATS_TEST_TMPDIR/copy"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  run env HOME="$h" python3 "$(_tool)"; [ "$status" -eq 0 ]
  [ ! -L "$d" ] && [ -d "$d" ]
  cmp -s "$root/share/skills/drvps/SKILL.md" "$d/SKILL.md"
  [ ! -L "$d/references/AGENT-GUIDE.md" ]
  cmp -s "$root/handout/AGENT-GUIDE.md" "$d/references/AGENT-GUIDE.md"
  cmp -s "$root/handout/ORCHESTRATOR-GUIDE.md" "$d/references/ORCHESTRATOR-GUIDE.md"
  grep -q '"tool":"drvps-skill-install"' "$d/.drvps-skill"            # provenance marker, not the skill name
  run env HOME="$h" python3 "$(_tool)"; [ "$status" -eq 0 ]           # idempotent
  run env HOME="$h" python3 "$(_tool)" --status; [ "$status" -eq 0 ]; [[ "$output" == copied:* ]]
}

@test "--link: symlinks the skill to the tree with a provenance marker; uninstall removes both" {
  local root h d lm; root="$(_root)"; h="$BATS_TEST_TMPDIR/link"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  lm="$h/.claude/skills/.drvps.drvps-link"
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -eq 0 ]
  [ -L "$d" ] && [ "$(readlink "$d")" = "$root/share/skills/drvps" ]
  [ -r "$d/SKILL.md" ] && [ -r "$d/references/AGENT-GUIDE.md" ]
  grep -q '"mode":"link"' "$lm"                                              # companion provenance marker
  run env HOME="$h" python3 "$(_tool)" --status; [ "$status" -eq 0 ]; [[ "$output" == linked:* ]]
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -eq 0 ]
  [ ! -e "$d" ] && [ ! -e "$lm" ]                                            # both link and marker gone
}

@test "BLOCKER: a user's OWN symlink to the tree (no provenance marker) is foreign -- never removed or replaced" {
  local root h d; root="$(_root)"; h="$BATS_TEST_TMPDIR/usersym"; mkdir -p "$h/.claude/skills"
  d="$h/.claude/skills/drvps"; ln -s "$root/share/skills/drvps" "$d"        # user's own hand-made symlink (no marker)
  run env HOME="$h" python3 "$(_tool)" --status; [[ "$output" == foreign:* ]]
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -ne 0 ]     # refuses to remove it
  run env HOME="$h" python3 "$(_tool)";             [ "$status" -ne 0 ]     # refuses to replace it
  [ -L "$d" ] && [ "$(readlink "$d")" = "$root/share/skills/drvps" ]        # left intact
}

@test "BLOCKER: an ORPHANED link marker (inode-bound) never claims a later user symlink to the same source" {
  local root h d lm; root="$(_root)"; h="$BATS_TEST_TMPDIR/orphan"; mkdir -p "$h"
  d="$h/.claude/skills/drvps"; lm="$h/.claude/skills/.drvps.drvps-link"
  env HOME="$h" python3 "$(_tool)" --link >/dev/null                        # our link (marker bound to its inode)
  rm "$d"                                                                    # remove our symlink -> marker orphaned
  ln -s "$root/share/skills/drvps" "$d"                                     # user creates their OWN symlink (new inode)
  run env HOME="$h" python3 "$(_tool)" --status; [[ "$output" == foreign:* ]]   # inode mismatch -> foreign
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -ne 0 ]     # refuses to delete the user's symlink
  [ -L "$d" ] && [ "$(readlink "$d")" = "$root/share/skills/drvps" ]        # user symlink intact
}

@test "an orphan link marker with an ABSENT dest is reconciled (cleaned) by uninstall" {
  local h d lm; h="$BATS_TEST_TMPDIR/reconcile"; mkdir -p "$h"
  d="$h/.claude/skills/drvps"; lm="$h/.claude/skills/.drvps.drvps-link"
  env HOME="$h" python3 "$(_tool)" --link >/dev/null; rm "$d"               # orphan the marker
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -eq 0 ]
  [ ! -e "$lm" ]                                                             # stale marker cleaned
}

@test "uninstall removes ONLY a skill this tool installed" {
  local h d; h="$BATS_TEST_TMPDIR/uninst"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -eq 0 ]
  [ ! -e "$d" ]
}

@test "BLOCKER: uninstall preserves a user-replaced/edited managed file (content-hash gated), keeps only ours" {
  local h d; h="$BATS_TEST_TMPDIR/uninst-edit"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  rm -f "$d/SKILL.md"; echo "USER REPLACED" > "$d/SKILL.md"                  # a new file (new inode/bytes) at a managed name
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -eq 0 ]
  [ -f "$d/SKILL.md" ] && grep -q "USER REPLACED" "$d/SKILL.md"             # NOT deleted (hash != recorded)
  [ ! -e "$d/.drvps-skill" ]                                                 # our marker WAS removed
}

@test "BLOCKER: a foreign file occupying the link-marker path is never deleted (copy) or overwritten (link)" {
  local h lm; h="$BATS_TEST_TMPDIR/marker-path"; mkdir -p "$h/.claude/skills"
  lm="$h/.claude/skills/.drvps.drvps-link"; echo "USER FILE" > "$lm"
  run env HOME="$h" python3 "$(_tool)"; [ "$status" -eq 0 ]                  # copy installs (dest absent) ...
  [ -f "$lm" ] && grep -q "USER FILE" "$lm"                                  # ... and leaves the foreign marker-path file intact
  env HOME="$h" python3 "$(_tool)" --uninstall >/dev/null 2>&1
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -ne 0 ]           # link refuses (marker path occupied by a foreign file)
  grep -q "USER FILE" "$lm"                                                   # still intact
}

@test "BLOCKER: a marker must match the FULL mode-specific structure -- a bare {tool,schema} file is not ours" {
  local h d lm; h="$BATS_TEST_TMPDIR/loose"; d="$h/.claude/skills/drvps"; mkdir -p "$d"
  lm="$h/.claude/skills/.drvps.drvps-link"
  printf '{"schema":1,"tool":"drvps-skill-install"}' > "$d/.drvps-skill"      # a copy marker missing mode/sha256
  echo "not our skill" > "$d/SKILL.md"
  run env HOME="$h" python3 "$(_tool)" --status; [[ "$output" == foreign:* ]] # not recognized as a managed copy
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -ne 0 ]       # refuses; leaves it intact
  [ -f "$d/.drvps-skill" ]
  # a bare marker at the LINK path: not reconciled/deleted; --link refuses (foreign file at the marker path)
  rm -rf "$d"; printf '{"schema":1,"tool":"drvps-skill-install"}' > "$lm"
  env HOME="$h" python3 "$(_tool)" --uninstall >/dev/null 2>&1; [ -f "$lm" ]
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -ne 0 ]; [ -f "$lm" ]
}

@test "BLOCKER: an oversize marker (valid prefix + trailing user bytes) is rejected, never treated as ours" {
  local h lm; h="$BATS_TEST_TMPDIR/oversize"; mkdir -p "$h/.claude/skills"
  lm="$h/.claude/skills/.drvps.drvps-link"
  { printf '{"dev":1,"ino":1,"mode":"link","schema":1,"tool":"drvps-skill-install"}'
    head -c 5000 /dev/zero | tr '\0' ' '; printf 'USER-TRAILER'; } > "$lm"     # valid JSON prefix + trailer past 4 KiB
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ -f "$lm" ]              # oversize -> not our marker -> left intact
}

@test "BLOCKER: a marker's schema must be a real JSON int (True/1.0), no duplicate keys, no oversize" {
  local h lm; h="$BATS_TEST_TMPDIR/strict"; mkdir -p "$h/.claude/skills"; lm="$h/.claude/skills/.drvps.drvps-link"
  printf '{"dev":1,"ino":1,"mode":"link","schema":true,"tool":"drvps-skill-install"}' > "$lm"
  env HOME="$h" python3 "$(_tool)" --uninstall >/dev/null 2>&1; [ -f "$lm" ]     # schema:true rejected
  printf '{"dev":1,"ino":1,"mode":"link","schema":1.0,"tool":"drvps-skill-install"}' > "$lm"
  env HOME="$h" python3 "$(_tool)" --uninstall >/dev/null 2>&1; [ -f "$lm" ]     # schema:1.0 rejected
  printf '{"tool":"drvps-skill-install","tool":"drvps-skill-install","dev":1,"ino":1,"mode":"link","schema":1}' > "$lm"
  env HOME="$h" python3 "$(_tool)" --uninstall >/dev/null 2>&1; [ -f "$lm" ]     # duplicate key rejected
  # a structurally-valid link marker with an IMPOSSIBLE dev/ino (os.lstat never returns these) is not ours
  printf '{"dev":-1,"ino":-1,"mode":"link","schema":1,"tool":"drvps-skill-install"}' > "$lm"
  env HOME="$h" python3 "$(_tool)" --uninstall >/dev/null 2>&1; [ -f "$lm" ]     # negative id rejected -> not deleted
  env HOME="$h" python3 "$(_tool)" >/dev/null 2>&1; [ -f "$lm" ]                  # nor deleted by copy stale-cleanup
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -ne 0 ]; [ -f "$lm" ] # --link refuses (foreign at marker path)
}

@test "idempotent --link is a no-op (never replaces an already-correct managed link)" {
  local h d; h="$BATS_TEST_TMPDIR/idem-link"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" --link >/dev/null
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -eq 0 ]; [[ "$output" == *"already linked"* ]]
  run env HOME="$h" python3 "$(_tool)" --status; [ "$status" -eq 0 ]; [[ "$output" == linked:* ]]
}

@test "MAJOR: --status flags a BROKEN (dangling) managed link (exit 3), not healthy" {
  # a self-contained fake checkout so we can delete the link's SOURCE while the tool still runs
  local h co d; h="$BATS_TEST_TMPDIR/broken"; co="$BATS_TEST_TMPDIR/checkout"; mkdir -p "$h" "$co/bin" "$co/share/skills/drvps/references" "$co/handout"
  cp "$(_tool)" "$co/bin/drvps-skill-install"
  cp "$(_root)/share/skills/drvps/SKILL.md" "$co/share/skills/drvps/SKILL.md"
  cp "$(_root)/handout/AGENT-GUIDE.md" "$co/handout/AGENT-GUIDE.md"; cp "$(_root)/handout/ORCHESTRATOR-GUIDE.md" "$co/handout/ORCHESTRATOR-GUIDE.md"
  ln -s ../../../../handout/AGENT-GUIDE.md "$co/share/skills/drvps/references/AGENT-GUIDE.md"
  ln -s ../../../../handout/ORCHESTRATOR-GUIDE.md "$co/share/skills/drvps/references/ORCHESTRATOR-GUIDE.md"
  env HOME="$h" python3 "$co/bin/drvps-skill-install" --link >/dev/null
  d="$h/.claude/skills/drvps"; [ -L "$d" ]
  rm -f "$co/share/skills/drvps/SKILL.md"                                        # the link now dangles for SKILL.md
  run env HOME="$h" python3 "$co/bin/drvps-skill-install" --status
  [ "$status" -eq 3 ] && [[ "$output" == broken:* ]]
}

@test "MAJOR: --link refuses, and --status flags broken, when a REQUIRED reference doc does not resolve" {
  local h co d; h="$BATS_TEST_TMPDIR/danglingref"; co="$BATS_TEST_TMPDIR/co-ref"
  mkdir -p "$h" "$co/bin" "$co/share/skills/drvps/references" "$co/handout"
  cp "$(_tool)" "$co/bin/drvps-skill-install"
  cp "$(_root)/share/skills/drvps/SKILL.md" "$co/share/skills/drvps/SKILL.md"
  cp "$(_root)/handout/ORCHESTRATOR-GUIDE.md" "$co/handout/ORCHESTRATOR-GUIDE.md"
  # AGENT-GUIDE reference symlink is present but its handout target is ABSENT -> a dangling required reference
  ln -s ../../../../handout/AGENT-GUIDE.md "$co/share/skills/drvps/references/AGENT-GUIDE.md"
  ln -s ../../../../handout/ORCHESTRATOR-GUIDE.md "$co/share/skills/drvps/references/ORCHESTRATOR-GUIDE.md"
  run env HOME="$h" python3 "$co/bin/drvps-skill-install" --link
  [ "$status" -ne 0 ] && [[ "$output" == *incomplete* ]]                          # link refuses to install a broken skill
  # now make it resolvable, link, then break a reference and confirm status flags broken
  cp "$(_root)/handout/AGENT-GUIDE.md" "$co/handout/AGENT-GUIDE.md"
  env HOME="$h" python3 "$co/bin/drvps-skill-install" --link >/dev/null; d="$h/.claude/skills/drvps"; [ -L "$d" ]
  rm -f "$co/handout/AGENT-GUIDE.md"                                               # dangle a reference after install
  run env HOME="$h" python3 "$co/bin/drvps-skill-install" --status
  [ "$status" -eq 3 ] && [[ "$output" == broken:* ]]
}

@test "MAJOR: a required doc that stats as a regular file but cannot be READ is rejected by --link" {
  [ -r /proc/self/mem ] || skip "no /proc/self/mem on this platform"
  local h co; h="$BATS_TEST_TMPDIR/unreadable"; co="$BATS_TEST_TMPDIR/co-unread"
  mkdir -p "$h" "$co/bin" "$co/share/skills/drvps/references" "$co/handout"
  cp "$(_tool)" "$co/bin/drvps-skill-install"; cp "$(_root)/share/skills/drvps/SKILL.md" "$co/share/skills/drvps/SKILL.md"
  cp "$(_root)/handout/ORCHESTRATOR-GUIDE.md" "$co/handout/ORCHESTRATOR-GUIDE.md"
  ln -s ../../../../handout/ORCHESTRATOR-GUIDE.md "$co/share/skills/drvps/references/ORCHESTRATOR-GUIDE.md"
  ln -s /proc/self/mem "$co/share/skills/drvps/references/AGENT-GUIDE.md"        # stats regular, but read raises EIO
  run env HOME="$h" python3 "$co/bin/drvps-skill-install" --link
  [ "$status" -ne 0 ] && [[ "$output" == *incomplete* ]]                          # open+read validation catches it (isfile/access would not)
}

@test "MAJOR: --status flags a modified managed copy (exit 3), not 'self-contained'" {
  local h d; h="$BATS_TEST_TMPDIR/status-mod"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  echo tampered >> "$d/SKILL.md"
  run env HOME="$h" python3 "$(_tool)" --status
  [ "$status" -eq 3 ] && [[ "$output" == modified:* ]]
}

@test "BLOCKER: a FOREIGN same-name skill (name: drvps, NO marker) is never clobbered or deleted" {
  local h d; h="$BATS_TEST_TMPDIR/foreign"; d="$h/.claude/skills/drvps"; mkdir -p "$d"
  printf -- '---\nname: drvps\n---\nMY OWN SKILL\n' > "$d/SKILL.md"          # a legit user-authored same-name skill
  run env HOME="$h" python3 "$(_tool)";             [ "$status" -ne 0 ]      # copy refuses
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -ne 0 ]      # uninstall refuses
  run env HOME="$h" python3 "$(_tool)" --status;    [[ "$output" == foreign:* ]]
  grep -q "MY OWN SKILL" "$d/SKILL.md"                                       # untouched
}

@test "BLOCKER: a planted symlink in a managed dir is never followed out of the destination" {
  local root h d ext; root="$(_root)"; h="$BATS_TEST_TMPDIR/nofollow"; d="$h/.claude/skills/drvps"; mkdir -p "$h"
  ext="$BATS_TEST_TMPDIR/external"; mkdir -p "$ext"; echo SECRET > "$ext/AGENT-GUIDE.md"; echo SENTINEL > "$ext/keep"
  env HOME="$h" python3 "$(_tool)" >/dev/null                               # our marked copy
  rm -rf "$d/references"; ln -s "$ext" "$d/references"                      # tamper: references -> external dir
  run env HOME="$h" python3 "$(_tool)" --uninstall; [ "$status" -eq 0 ]     # removes ours; must NOT descend
  [ -f "$ext/AGENT-GUIDE.md" ] && [ -f "$ext/keep" ]                        # external dir intact
}

@test "MAJOR: copy->link with a user EXTRA file fails cleanly (no pre-delete, no nested symlink)" {
  local h d; h="$BATS_TEST_TMPDIR/convert"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  echo userdata > "$d/NOTES.txt"                                            # a user file dropped into our dir
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -ne 0 ]          # refuses
  [ -f "$d/SKILL.md" ]                                                       # our SKILL.md NOT pre-deleted
  [ ! -e "$d/drvps" ]                                                        # no nested symlink
  [ -f "$d/NOTES.txt" ]                                                      # user file intact
}

@test "BLOCKER: a user-EDITED managed file (regular, new bytes) is preserved on refresh via content hashes" {
  local h d; h="$BATS_TEST_TMPDIR/edited"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  echo "MY CUSTOM EDIT" >> "$d/SKILL.md"                                    # user edits our SKILL.md (still a regular file)
  run env HOME="$h" python3 "$(_tool)"; [ "$status" -eq 0 ]                 # refresh succeeds ...
  local kept; kept=$(compgen -G "$d.old-*" | head -1)                       # ... and preserves the edited tree
  [ -n "$kept" ] && grep -q "MY CUSTOM EDIT" "$kept/SKILL.md"
  # an UNMODIFIED install refreshes cleanly (its own backup is discarded -- no litter beyond the preserved edit)
  run env HOME="$h" python3 "$(_tool)"; [ "$status" -eq 0 ]
  [ "$(compgen -G "$d.old-*" | wc -l)" -eq 1 ]
}

@test "BLOCKER: user data hidden behind a managed NAME (SKILL.md/ dir) is preserved on refresh, never rm -rf'd" {
  local h d; h="$BATS_TEST_TMPDIR/typeanomaly"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  rm -f "$d/SKILL.md"; mkdir "$d/SKILL.md"; echo USER-DATA > "$d/SKILL.md/keep"   # a DIRECTORY at a managed name
  run env HOME="$h" python3 "$(_tool)"; [ "$status" -eq 0 ]                  # refresh succeeds ...
  local kept; kept=$(compgen -G "$d.old-*" | head -1)                        # ... and preserves the old tree
  [ -n "$kept" ] && grep -q USER-DATA "$kept/SKILL.md/keep"                   # user data survives (not rm -rf'd)
}

@test "MAJOR: copy->link with a type-anomaly (SKILL.md/ dir) refuses WITHOUT dismantling the dir" {
  local h d; h="$BATS_TEST_TMPDIR/convert2"; mkdir -p "$h"; d="$h/.claude/skills/drvps"
  env HOME="$h" python3 "$(_tool)" >/dev/null
  rm -f "$d/SKILL.md"; mkdir "$d/SKILL.md"; echo X > "$d/SKILL.md/keep"
  run env HOME="$h" python3 "$(_tool)" --link; [ "$status" -ne 0 ]          # refuses
  [ -d "$d/references" ]                                                      # references NOT incrementally removed
  [ -f "$d/SKILL.md/keep" ]                                                   # user data intact
}
