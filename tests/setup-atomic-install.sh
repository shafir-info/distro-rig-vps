#!/usr/bin/env bash
# Unit test for dr-vps-setup's _dr_atomic_install_root -- the atomic publisher behind the egress render-input
# persistence. TWO known incidents live here: (a) an earlier step_proxy never persisted the render inputs at
# all, so drvps-egress-approve crashed on a real host (covered end-to-end by egress-approve-prodpath.sh); and
# (b) the persistence fix first used `... ; mv ...` so mv ran even after cat/chmod/chown had FAILED, which could
# publish a truncated / wrong-mode file. This pins the failure-safety + atomicity of the helper, with a POSITIVE
# CONTROL that the buggy `; mv` variant is genuinely detected. Runs as root (the helper chowns root:root) in a
# disposable container:  podman run --rm -v <repo>:/repo:ro <fedora> bash /repo/tests/setup-atomic-install.sh
set -uo pipefail
echo "RELEASE-GATE-RAN: setup-atomic-install" >&2   # tests/release-gate.sh tier-2 runtime-coverage marker
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root for chown root:root -- run in a container"; exit 0; }
fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

# Extract JUST the helper from the real installer (no full sourcing, so main() never runs) -- the same
# awk-slice pattern firewalld-dr2.sh uses. This is why the helper is top-level, not nested in step_proxy.
eval "$(awk '/^_dr_atomic_install_root\(\) \{/{p=1} p{print} p&&/^\}$/{exit}' /repo/bin/dr-vps-setup)"
type _dr_atomic_install_root >/dev/null 2>&1 || { echo "FAIL: could not extract _dr_atomic_install_root"; exit 1; }
eval "$(awk '/^_dr_rollback_render_input\(\) \{/{p=1} p{print} p&&/^\}$/{exit}' /repo/bin/dr-vps-setup)"
type _dr_rollback_render_input >/dev/null 2>&1 || { echo "FAIL: could not extract _dr_rollback_render_input"; exit 1; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
printf 'NEW-CONTENT\n' > "$W/src"

# 1) SUCCESS: publishes the source bytes, mode 0644, owner root:root
_dr_atomic_install_root "$W/src" "$W/dest.json"; rc=$?
ok "success returns 0"                       "[ $rc = 0 ]"
ok "dest published with the source bytes"    '[ "$(cat "$W/dest.json")" = NEW-CONTENT ]'
ok "dest mode is 0644"                        '[ "$(stat -c %a "$W/dest.json")" = 644 ]'
ok "dest owner is root:root"                  '[ "$(stat -c %U:%G "$W/dest.json")" = root:root ]'

# 2) ATOMIC REPLACE: an existing dest is swapped whole (by RENAME), never left corrupted
printf 'OLD\n' > "$W/dest2.json"
_ino=$(stat -c %i "$W/dest2.json")
_dr_atomic_install_root "$W/src" "$W/dest2.json"
ok "existing dest replaced with the new content" '[ "$(cat "$W/dest2.json")" = NEW-CONTENT ]'
# ATOMICITY: a same-dir RENAME gives the dest a NEW inode (the temp's); an in-place truncate+write keeps the
# SAME inode and is observable half-written by a concurrent reader. So the inode MUST change on replace -- this
# is what catches a regression to a non-atomic direct write (which the content check alone would bless).
ok "replace is a RENAME (dest inode changed), not an in-place write" \
   "[ \"\$(stat -c %i \"\$W/dest2.json\")\" != \"$_ino\" ]"

# 3) FAILURE-SAFETY: cat fails (missing source) -> dest NOT published, no temp leaked
_dr_atomic_install_root "$W/nonexistent-src" "$W/dest3.json"; rc=$?
ok "missing source returns non-zero"         "[ $rc != 0 ]"
ok "dest NOT created on cat failure"         '[ ! -e "$W/dest3.json" ]'
ok "no temp leaked in the dest dir"          '[ -z "$(ls -A "$W"/.dest3.json.* 2>/dev/null)" ]'

# 3b) mv-INTO-DIRECTORY guard: if the dest path is an existing DIR (or a symlink to one), a plain `mv -f` would
# move the temp INSIDE it and return 0 -- "success" with the real path unwritten. `mv -T` must REFUSE -> non-zero.
mkdir "$W/destdir"
_dr_atomic_install_root "$W/src" "$W/destdir"; rc=$?
ok "dir destination returns non-zero (mv -T refuses)"      "[ $rc != 0 ]"
ok "temp NOT moved inside the dir destination"            '[ -z "$(ls -A "$W/destdir" 2>/dev/null)" ]'
# symlink-to-dir dest: `mv -T` replaces the SYMLINK with the file (returns 0) and does NOT follow it into the
# target dir -- so a planted symlink cannot redirect the write, and the render input still lands at the path.
mkdir "$W/realdir"; ln -s realdir "$W/symdir"
_dr_atomic_install_root "$W/src" "$W/symdir"; rc=$?
ok "symlink-to-dir dest: succeeds by REPLACING the symlink (not following it)" "[ $rc = 0 ]"
ok "symlink-to-dir dest is now a regular file with the content"  '[ -f "$W/symdir" ] && [ ! -L "$W/symdir" ] && [ "$(cat "$W/symdir")" = NEW-CONTENT ]'
ok "the symlink was NOT followed into its target dir"            '[ -z "$(ls -A "$W/realdir" 2>/dev/null)" ]'

# 4) POSITIVE CONTROL: the buggy `; mv` variant WOULD publish a (partial) file on the same cat failure -- prove
# the test can tell the correct helper from the incident version, i.e. the guard above is meaningful.
_buggy(){ local _t; _t=$(mktemp -p "$(dirname "$2")" ".$(basename "$2").XXXXXX") || return 1
          cat "$1" >"$_t" 2>/dev/null; chmod 0644 "$_t"; chown root:root "$_t"; mv -f "$_t" "$2"; }   # `;` not `&&`
_buggy "$W/nonexistent-src" "$W/dest4.json" 2>/dev/null || true
ok "positive control: buggy ';' variant DOES publish a partial file" '[ -e "$W/dest4.json" ]'
ok "real helper published NOTHING where the buggy one did"           '[ ! -e "$W/dest3.json" ]'

# 5) ROLLBACK helper (_dr_rollback_render_input <backup> <dest> <had>): restore the pre-publish state during a
# proxy-publish rollback. Two arms, matching the two ways a render input can enter the publish:
# 5a) had=1 (the input EXISTED): restore the saved bytes ATOMICALLY (a rename -> a NEW inode, not an in-place cp).
printf 'PRIOR\n' > "$W/rb.json"; printf 'PRIOR\n' > "$W/rb.bak"   # dest currently holds the (torn) new bytes...
printf 'TORN-NEW\n' > "$W/rb.json"                                # ...simulate the half-committed new content
_ino5=$(stat -c %i "$W/rb.json")
_dr_rollback_render_input "$W/rb.bak" "$W/rb.json" 1
ok "rollback had=1 restores the prior bytes"          '[ "$(cat "$W/rb.json")" = PRIOR ]'
ok "rollback had=1 is a RENAME (inode changed), not in-place cp" \
   "[ \"\$(stat -c %i \"\$W/rb.json\")\" != \"$_ino5\" ]"
ok "rollback had=1 restores mode 0644 root:root"      '[ "$(stat -c %a:%U:%G "$W/rb.json")" = 644:root:root ]'
# 5b) had=0 (the input did NOT exist before -> this publish newly created it): REMOVE it, so a partial persist
# (first input committed, second failed) leaves no orphaned new render input beside the untouched live config.
printf 'ORPHAN-NEW\n' > "$W/rb2.json"
_dr_rollback_render_input "$W/unused-backup" "$W/rb2.json" 0
ok "rollback had=0 removes the newly-created file"    '[ ! -e "$W/rb2.json" ]'

echo "-------------------------------------------"
echo "setup atomic-install: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
