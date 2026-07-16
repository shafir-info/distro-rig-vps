#!/usr/bin/env bats
# Stage 3b (Phase 2) -- the watcher's thin loop, adversarial smoke (--once over a fake spool):
# valid request -> result; symlink/FIFO request refused without hanging; snapshot claim.

load helpers

setup() {
  export SPOOL="$BATS_TEST_TMPDIR/spool"
  mkdir -p "$SPOOL/requests" "$SPOOL/processing" "$SPOOL/results"
  export DR_VPS_SPOOL_DIR="$SPOOL"
  # fake dr-vps: echoes its verb (handles `gate` -> exit 0, `list` -> some output).
  # FDR_CALLS (optional): append each invocation's argv -- lets a test PROVE a verb did not re-run.
  cat >"$BATS_TEST_TMPDIR/fdr" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FDR_CALLS:-/dev/null}"
case "$1" in
  gate) exit 0 ;;
  exec) sleep "${FAKE_EXEC_SLEEP:-0}"; printf 'FAKE exec\n' ;;
  pull) if [ -n "${FAKE_PULL_N:-}" ]; then head -c "$FAKE_PULL_N" /dev/zero | tr '\0' a
        else printf "${FAKE_PULL_BYTES:-FAKE pull}"; fi
        [ -n "${FAKE_PULL_SLEEP:-}" ] && sleep "$FAKE_PULL_SLEEP" || true
        exit "${FAKE_PULL_RC:-0}" ;;   # emit, optionally hang, then exit (nonzero = guest read failed)
  *)    printf 'FAKE %s\n' "$*" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr"
  export DR_VPS_SSH_KEY="$BATS_TEST_TMPDIR/k"
  W="${DR_VPS_SRC}/../src/drvps_rigctl.py"
}

_run_once() { run timeout 20 python3 "$W" --once; }

@test "watch: a valid request -> a result envelope with status ok" {
  printf '{"reqid":"r1","op":"list"}' >"$SPOOL/requests/r1.json"
  _run_once; [ "$status" -eq 0 ]
  [ -f "$SPOOL/results/r1.json" ]
  grep -q '"status": "ok"' "$SPOOL/results/r1.json"
  grep -q 'FAKE list' "$SPOOL/results/r1.json"
  [ ! -e "$SPOOL/requests/r1.json" ]                 # claimed (unlinked)
}

@test "watch: a rejected request -> rejected result, no execution" {
  printf '{"reqid":"r2","op":"rm-host"}' >"$SPOOL/requests/r2.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/r2.json"
  grep -q 'unknown verb' "$SPOOL/results/r2.json"
}

@test "watch: op version -> result envelope ok, ungated global read (no owner_uid needed)" {
  printf '{"reqid":"rV","op":"version"}' >"$SPOOL/requests/rV.json"   # NOTE: no owner_uid -> must still run (not owner-scoped)
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/rV.json"
  grep -q 'FAKE version' "$SPOOL/results/rV.json"                     # decider mapped op:version -> `dr-vps version`
  [ ! -e "$SPOOL/requests/rV.json" ]                                  # claimed (unlinked)
}

@test "watch: exec-detach (guestexec-gated, owner-stamped) + exec-status/output (job-keyed, owner-scoped) dispatch" {
  printf '{"reqid":"j1","op":"exec-detach","vm":"drvps-vm-abc","cmd":"sleep 5","owner_uid":4001}' >"$SPOOL/requests/j1.json"
  printf '{"reqid":"j2","op":"exec-status","job":"0123456789abcdef0123456789abcdef","owner_uid":4002}' >"$SPOOL/requests/j2.json"
  printf '{"reqid":"j3","op":"exec-output","job":"0123456789abcdef0123456789abcdef","owner_uid":4003}' >"$SPOOL/requests/j3.json"
  printf '{"reqid":"j3e","op":"exec-errors","job":"0123456789abcdef0123456789abcdef","owner_uid":4003}' >"$SPOOL/requests/j3e.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q 'FAKE exec-detach drvps-vm-abc sleep 5 --owner 4001' "$SPOOL/results/j1.json"
  grep -q 'FAKE exec-status 0123456789abcdef0123456789abcdef --owner 4002' "$SPOOL/results/j2.json"
  grep -q 'FAKE exec-output 0123456789abcdef0123456789abcdef --owner 4003' "$SPOOL/results/j3.json"
  grep -q 'FAKE exec-errors 0123456789abcdef0123456789abcdef --owner 4003' "$SPOOL/results/j3e.json"
}

@test "watch: exec-status/exec-output/exec-errors WITHOUT owner_uid -> REJECTED (fail-closed, owner-scoped)" {
  printf '{"reqid":"j4","op":"exec-status","job":"0123456789abcdef0123456789abcdef"}' >"$SPOOL/requests/j4.json"
  printf '{"reqid":"j5","op":"exec-output","job":"0123456789abcdef0123456789abcdef"}' >"$SPOOL/requests/j5.json"
  printf '{"reqid":"j5e","op":"exec-errors","job":"0123456789abcdef0123456789abcdef"}' >"$SPOOL/requests/j5e.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/j4.json"
  grep -q '"status": "rejected"' "$SPOOL/results/j5.json"
  grep -q '"status": "rejected"' "$SPOOL/results/j5e.json"
}

@test "watch: exec-status with a hostile job id (non-hex / path traversal) -> REJECTED" {
  printf '{"reqid":"j6","op":"exec-status","job":"../etc/passwd","owner_uid":4001}' >"$SPOOL/requests/j6.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q 'bad job id' "$SPOOL/results/j6.json"
}

@test "watch: an OVERSIZE spool file is unlinked at claim, never parsed (tiny DR_VPS_REQ_MAX_BYTES)" {
  export DR_VPS_REQ_MAX_BYTES=32
  printf '{"reqid":"big1","op":"list","pad":"%s"}' "$(printf 'x%.0s' {1..100})" >"$SPOOL/requests/big1.json"
  _run_once; [ "$status" -eq 0 ]
  [ ! -e "$SPOOL/requests/big1.json" ]               # claim-side cap: silently unlinked
  [ ! -e "$SPOOL/results/big1.json" ]                # no result envelope (never parsed)
}

@test "watch: a SYMLINK request is refused + removed, never followed" {
  ln -s /etc/passwd "$SPOOL/requests/r3.json"
  _run_once; [ "$status" -eq 0 ]                      # did NOT hang or crash
  [ ! -f "$SPOOL/results/r3.json" ]                  # not executed
  [ ! -e "$SPOOL/requests/r3.json" ]                 # symlink dropped (no busy-loop)
}

@test "watch: a FIFO request does NOT hang the watcher (O_NONBLOCK)" {
  mkfifo "$SPOOL/requests/r4.json"
  _run_once; [ "$status" -eq 0 ]                      # O_NONBLOCK -> no pre-fstat hang
  [ ! -f "$SPOOL/results/r4.json" ]
}

@test "watch: filename != reqid is rejected by the loop too" {
  printf '{"reqid":"DIFFERENT","op":"list"}' >"$SPOOL/requests/r5.json"
  _run_once; [ "$status" -eq 0 ]
  # reqid in the body is 'DIFFERENT' but filename basename is 'r5' -> rejected; result under DIFFERENT
  grep -q 'filename != reqid' "$SPOOL/results/DIFFERENT.json"
}

@test "watch: non-.json JUNK in requests/ is swept (can't accumulate to evade the cap)" {
  echo junk >"$SPOOL/requests/notarequest"
  printf '{"reqid":"rj","op":"list"}' >"$SPOOL/requests/rj.json"
  _run_once; [ "$status" -eq 0 ]
  [ ! -e "$SPOOL/requests/notarequest" ]              # junk unlinked
  grep -q '"status": "ok"' "$SPOOL/results/rj.json"   # real request still processed
}

@test "watch: pull returns BINARY-safe base64 in content_b64 (D7/C-3), NOT a utf-8-mangled stdout" {
  export FAKE_PULL_BYTES='a\xffb'                            # 0x61 0xff 0x62 -- 0xff is invalid utf-8
  printf '{"reqid":"rp","op":"pull","vm":"vm1","remote":"/etc/hostname","owner_uid":4001}' >"$SPOOL/requests/rp.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/rp.json"
  [ "$(jq -r '.stdout // "ABSENT"' "$SPOOL/results/rp.json")" = ABSENT ]   # no mangled utf-8 stdout
  printf 'a\xffb' >"$BATS_TEST_TMPDIR/want"
  jq -r '.content_b64' "$SPOOL/results/rp.json" | base64 -d >"$BATS_TEST_TMPDIR/got"
  cmp "$BATS_TEST_TMPDIR/want" "$BATS_TEST_TMPDIR/got"       # bytes survive intact through base64
}

@test "watch: pull of an OVER-CAP file -> explicit error, NOT a silent truncation (D7/C-3)" {
  export DR_VPS_TRANSFER_MAX_BYTES=8
  export FAKE_PULL_BYTES='0123456789ABCDEF'                  # 16 bytes > the 8-byte cap
  printf '{"reqid":"rpc","op":"pull","vm":"vm1","remote":"/big","owner_uid":4001}' >"$SPOOL/requests/rpc.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "error"' "$SPOOL/results/rpc.json"
  grep -q 'exceeds the 8-byte transfer cap' "$SPOOL/results/rpc.json"
  [ "$(jq -r '.content_b64 // "ABSENT"' "$SPOOL/results/rpc.json")" = ABSENT ]   # no truncated payload
}

@test "watch: pull does NOT silently truncate when result_max//2 < transfer_max" {
  # a VALID file (<= transfer_max) must come back COMPLETE even when the result cap's half is smaller
  # than the transfer cap. Old code read result_max//2 (2000) -> truncated a 2001-byte file to 2000
  # and shipped it as ok. The read cap must be transfer_max+1, not result_max//2.
  export DR_VPS_TRANSFER_MAX_BYTES=2500 DR_VPS_RESULT_MAX_BYTES=4000 FAKE_PULL_N=2001
  printf '{"reqid":"rtrunc","op":"pull","vm":"vm1","remote":"/f","owner_uid":4001}' >"$SPOOL/requests/rtrunc.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/rtrunc.json"
  n=$(jq -r '.content_b64' "$SPOOL/results/rtrunc.json" | base64 -d | wc -c)
  [ "$n" -eq 2001 ]                                          # FULL file, not truncated to 2000
}

@test "watch: pull whose base64 exceeds the result cap -> explicit error, never a corrupt JSON" {
  # content_b64 is not a trimmable field; an over-result-cap payload must FAIL CLOSED, not force
  # write_result to byte-slice the JSON into an invalid result.
  export DR_VPS_TRANSFER_MAX_BYTES=5000 DR_VPS_RESULT_MAX_BYTES=2000 FAKE_PULL_N=1200
  printf '{"reqid":"rbig","op":"pull","vm":"vm1","remote":"/f","owner_uid":4001}' >"$SPOOL/requests/rbig.json"
  _run_once; [ "$status" -eq 0 ]
  jq -e . "$SPOOL/results/rbig.json" >/dev/null              # the result is VALID JSON
  grep -q '"status": "error"' "$SPOOL/results/rbig.json"
  grep -q 'exceeds the 2000-byte result cap' "$SPOOL/results/rbig.json"
  [ "$(jq -r '.content_b64 // "ABSENT"' "$SPOOL/results/rbig.json")" = ABSENT ]
}

@test "watch: a pull whose GUEST read FAILS (nonzero exit, empty out) -> error, NOT an empty ok" {
  # supervise marks status=ok for any child that exits; a missing/unreadable guest file makes `head`
  # exit nonzero with empty stdout. That must be an ERROR, not content_b64="" decoded as success.
  export FAKE_PULL_BYTES='' FAKE_PULL_RC=1
  printf '{"reqid":"rfail","op":"pull","vm":"vm1","remote":"/no/such","owner_uid":4001}' >"$SPOOL/requests/rfail.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r '.status' "$SPOOL/results/rfail.json")" = error ]
  [ "$(jq -r '.content_b64 // "ABSENT"' "$SPOOL/results/rfail.json")" = ABSENT ]
  grep -q 'guest read failed' "$SPOOL/results/rfail.json"
}

@test "watch: a TIMED-OUT pull attaches NO content_b64" {
  export DR_VPS_EXEC_TIMEOUT=1 FAKE_PULL_N=64 FAKE_PULL_SLEEP=3
  printf '{"reqid":"rto","op":"pull","vm":"vm1","remote":"/f","owner_uid":4001}' >"$SPOOL/requests/rto.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r '.status' "$SPOOL/results/rto.json")" != ok ]        # timed out -> non-ok
  [ "$(jq -r '.content_b64 // "ABSENT"' "$SPOOL/results/rto.json")" = ABSENT ]   # no partial payload attached
}

@test "watch: a successful pull does NOT write content_b64 into audit.log" {
  export FAKE_PULL_BYTES='PULLPAYLOAD-MARKER-1234567890'
  printf '{"reqid":"raud","op":"pull","vm":"vm1","remote":"/f","owner_uid":4001}' >"$SPOOL/requests/raud.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/raud.json"        # succeeded
  b64=$(printf 'PULLPAYLOAD-MARKER-1234567890' | base64 -w0)
  ! grep -q "content_b64" "$SPOOL/audit.log" || false                 # the payload field is not audited
  ! grep -qF "$b64" "$SPOOL/audit.log" || false                       # nor its bytes
}

@test "watch: a push whose temp write FAILS -> error result + daemon SURVIVES to process the next request" {
  # If processing/ is missing/unwritable, run_action's mkstemp raises. That must yield a status=error
  # RESULT for the push and let the loop continue -- NOT an uncaught crash that loses every other
  # pending request's claimed state. Simulate by removing processing/ before the pass.
  b64=$(printf 'hello' | base64)
  printf '{"reqid":"pfail","op":"push","vm":"vm1","remote":"/tmp/x","content_b64":"%s","owner_uid":4001}' "$b64" >"$SPOOL/requests/pfail.json"
  printf '{"reqid":"pok","op":"list"}' >"$SPOOL/requests/pok.json"
  rmdir "$SPOOL/processing"                                  # force mkstemp(dir=processing) to fail
  _run_once; [ "$status" -eq 0 ]                             # the daemon did NOT crash
  grep -q '"status": "error"' "$SPOOL/results/pfail.json"    # push failure -> error envelope, not a crash
  grep -q '"status": "ok"' "$SPOOL/results/pok.json"         # a following request still gets processed
  mkdir -p "$SPOOL/processing"                               # restore for any later assertions
}

@test "watch: a non-regular DIRECTORY request is DELETED, never persisted into private processing/ (DoS)" {
  # An agent can `mkdir requests/x.json/` full of data. If the watcher MOVED it into the drvps-private
  # processing/ dir the agent could no longer remove what it planted and nothing GCs it -> unbounded
  # disk/inode DoS. It must be DELETED in place instead (the watcher owns the sticky requests/ dir).
  mkdir "$SPOOL/requests/dos.json"
  dd if=/dev/zero of="$SPOOL/requests/dos.json/blob" bs=1024 count=64 status=none
  printf '{"reqid":"rok","op":"list"}' >"$SPOOL/requests/rok.json"
  _run_once; [ "$status" -eq 0 ]
  [ ! -e "$SPOOL/requests/dos.json" ]                       # the poison dir is gone from requests/
  [ -z "$(ls -A "$SPOOL/processing")" ]                     # NOT persisted anywhere under processing/
  grep -q '"status": "ok"' "$SPOOL/results/rok.json"        # the real request is still processed
}

@test "watch: a symlink INSIDE a non-regular dir entry is not followed when purged" {
  # rmtree unlinks the link itself, never the target: a planted symlink -> /etc must not be deleted.
  mkdir "$SPOOL/requests/evil.json"
  ln -s /etc/passwd "$SPOOL/requests/evil.json/link"
  _run_once; [ "$status" -eq 0 ]
  [ ! -e "$SPOOL/requests/evil.json" ]                      # the poison tree is gone
  [ -f /etc/passwd ]                                        # the symlink target is untouched
}

@test "watch: a CLAIMED-only reqid (result GC'd, .claimed remains) does NOT re-execute (replay guard)" {
  # The reaper's count-GC can prune <reqid>.json while <reqid>.claimed remains; results/ is
  # group-listable, so a resubmit of that reqid must be treated as duplicate (at-most-once) and NOT
  # re-run the (possibly mutating) verb -- mirroring the preempt path's .claimed check.
  printf '{"reqid":"rrep","op":"list"}' >"$SPOOL/results/rrep.claimed"   # durable claimed marker, no result
  printf '{"reqid":"rrep","op":"list"}' >"$SPOOL/requests/rrep.json"
  _run_once; [ "$status" -eq 0 ]
  [ ! -f "$SPOOL/results/rrep.json" ]                  # verb NOT re-run (no new result written)
  grep -q '"status": "duplicate"' "$SPOOL/audit.log"   # recorded as duplicate
  [ ! -e "$SPOOL/requests/rrep.json" ]                 # request consumed (claimed + unlinked)
}

@test "watch: a NUL byte in cmd is rejected, never crashes the watcher" {
  printf '{"reqid":"rn","op":"exec","vm":"vm1","cmd":"a\\u0000b","owner_uid":4001}' >"$SPOOL/requests/rn.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/rn.json"
}

@test "watch: destroy PREEMPTS an in-flight exec, then the rescue RUNS (under the same lock)" {
  export FAKE_EXEC_SLEEP=4
  printf '{"reqid":"a-exec","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}'   >"$SPOOL/requests/a-exec.json"
  printf '{"reqid":"z-destroy","op":"destroy","vm":"vm1","owner_uid":4001}'           >"$SPOOL/requests/z-destroy.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "preempted"' "$SPOOL/results/a-exec.json"      # exec killed
  [ -f "$SPOOL/results/z-destroy.json" ]                            # rescue ran...
  grep -q '"status": "ok"' "$SPOOL/results/z-destroy.json"          # ...and completed
}

@test "watch: audit.log SIZE-ROTATES to .1 past DR_VPS_AUDIT_MAX_BYTES (unbounded-growth guard)" {
  export DR_VPS_AUDIT_MAX_BYTES=120
  for i in 1 2 3 4 5 6; do printf '{"reqid":"ar%s","op":"list"}' "$i" >"$SPOOL/requests/ar$i.json"; done
  _run_once; [ "$status" -eq 0 ]
  [ -f "$SPOOL/audit.log.1" ]               # rotated at least once instead of growing without bound
}

@test "watch: a SAME-reqid destroy cannot preempt+HIDE the in-flight exec (claimed-marker guard)" {
  # the fake exec drops a DUPLICATE-reqid destroy mid-run; the preempt replay guard must refuse it
  # (results/same.claimed exists) so the exec runs to completion and the destroy does NOT
  # hide-overwrite the exec's externally-visible result.
  cat >"$BATS_TEST_TMPDIR/fdr2" <<EOF
#!/usr/bin/env bash
case "\$1" in
  gate) exit 0 ;;
  exec) printf '{"reqid":"same","op":"destroy","vm":"vm1","owner_uid":4001}' >"$SPOOL/requests/same.json"; sleep 3; printf 'FAKE exec\n' ;;
  *)    printf 'FAKE %s\n' "\$*" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr2"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr2"
  printf '{"reqid":"same","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}' >"$SPOOL/requests/same.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"op": "exec"' "$SPOOL/results/same.json"       # the EXEC's result is preserved...
  grep -q '"status": "ok"' "$SPOOL/results/same.json"     # ...not "preempted"
  ! grep -q '"op": "destroy"' "$SPOOL/results/same.json" || false  # the destroy did NOT hide-overwrite it
}

# ---- SNAPSHOT ops daemon dispatch (the fake dr-vps echoes `FAKE <argv>`; gate passes) --------------
@test "watch: snap-ls dispatches to 'dr-vps snap-ls' (global, no vm gate)" {
  printf '{"reqid":"s1","op":"snap-ls","owner_uid":4011}' >"$SPOOL/requests/s1.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/s1.json"
  grep -q 'FAKE snap-ls' "$SPOOL/results/s1.json"
}

@test "watch: snap-rm <snap> dispatches to 'dr-vps snap-rm <snap>'" {
  printf '{"reqid":"s2","op":"snap-rm","snap":"drvps-snap-v1-1-abc","owner_uid":4012}' >"$SPOOL/requests/s2.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/s2.json"
  grep -q 'FAKE snap-rm drvps-snap-v1-1-abc' "$SPOOL/results/s2.json"
}

@test "watch: snap-rm with a hostile snap id (leading dash) is REJECTED (no execution)" {
  printf '{"reqid":"s3","op":"snap-rm","snap":"-bad","owner_uid":4013}' >"$SPOOL/requests/s3.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/s3.json"
  grep -q 'bad snap id' "$SPOOL/results/s3.json"
}

@test "watch: snapshot <vm> is lifecycle-gated + dispatches 'dr-vps snapshot <vm>' with flags" {
  printf '{"reqid":"s4","op":"snapshot","vm":"drvps-vm-abc","keep_secrets":true,"notes":"hi","owner_uid":4014}' >"$SPOOL/requests/s4.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/s4.json"
  grep -q 'FAKE snapshot drvps-vm-abc --keep-secrets --notes hi' "$SPOOL/results/s4.json"
}

@test "watch: R8 -- a REAL 90-char snapshot id (drvps-snap-v1-<vsize>-<64hex>) is ACCEPTED (not 'bad snap id')" {
  # the 64-char SAFE_NAME used to REJECT the very ids `rigctl snapshot` returns; SAFE_SNAP now accepts them.
  sid="drvps-snap-v1-10737418240-$(printf 'a%.0s' {1..64})"
  printf '{"reqid":"s5","op":"snap-show","snap":"%s","owner_uid":4015}' "$sid" >"$SPOOL/requests/s5.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/s5.json"
  grep -q "FAKE snap-show $sid" "$SPOOL/results/s5.json"
  ! grep -q 'bad snap id' "$SPOOL/results/s5.json" || false
}

@test "watch: OWNER SCOPING -- the ingress-stamped owner_uid is threaded as '--owner <uid>' to EVERY snap verb" {
  # snap-ls, snap-show, snap-rm, and snapshot each carry the caller's owner_uid so the CLI scopes to the owner.
  printf '{"reqid":"o1","op":"snap-ls","owner_uid":4001}' >"$SPOOL/requests/o1.json"
  printf '{"reqid":"o2","op":"snap-rm","snap":"drvps-snap-v1-1-abc","owner_uid":4002}' >"$SPOOL/requests/o2.json"
  printf '{"reqid":"o3","op":"snapshot","vm":"drvps-vm-abc","owner_uid":4003}' >"$SPOOL/requests/o3.json"
  printf '{"reqid":"o3s","op":"snap-show","snap":"drvps-snap-v1-1-abc","owner_uid":4004}' >"$SPOOL/requests/o3s.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q 'FAKE snap-ls --owner 4001' "$SPOOL/results/o1.json"
  grep -q 'FAKE snap-rm drvps-snap-v1-1-abc --owner 4002' "$SPOOL/results/o2.json"
  grep -q 'FAKE snapshot drvps-vm-abc --owner 4003' "$SPOOL/results/o3.json"
  grep -q 'FAKE snap-show drvps-snap-v1-1-abc --owner 4004' "$SPOOL/results/o3s.json"   # snap-show pinned too
}

@test "watch: OWNER SCOPING -- a snap verb reaching the watcher WITHOUT owner_uid is REJECTED (fail-closed), never run unscoped" {
  # The accepter stamps owner_uid on EVERY socket request; an unstamped snap verb can only be a hand-planted
  # drvps-only spool file or an accepter regression. It must NOT silently run with admin (unscoped) reach.
  printf '{"reqid":"o4","op":"snap-ls"}'                                  >"$SPOOL/requests/o4.json"
  printf '{"reqid":"o4b","op":"snap-rm","snap":"drvps-snap-v1-1-abc"}'    >"$SPOOL/requests/o4b.json"
  printf '{"reqid":"o4c","op":"snapshot","vm":"drvps-vm-abc"}'            >"$SPOOL/requests/o4c.json"
  printf '{"reqid":"o4d","op":"snap-show","snap":"drvps-snap-v1-1-abc"}' >"$SPOOL/requests/o4d.json"
  _run_once; [ "$status" -eq 0 ]
  for r in o4 o4b o4c o4d; do
    grep -q '"status": "rejected"' "$SPOOL/results/$r.json"
    grep -q 'missing owner_uid' "$SPOOL/results/$r.json"
    ! grep -q 'FAKE ' "$SPOOL/results/$r.json" || false                            # never executed
  done
}

@test "watch: OWNER SCOPING -- a non-INTEGER owner_uid is REJECTED (int-only: string/leading-zero/negative/bool), no execution" {
  # The accepter stamps a real kernel uid (JSON int). Anything else can only be a hand-planted spool file and
  # must be refused: a shell-injection string, a leading-zero digit STRING ("04001" != canonical 4001), a
  # negative int, and a JSON bool (an int subclass in Python) all mis-scope if accepted.
  printf '{"reqid":"o5","op":"snap-ls","owner_uid":"root; rm -rf /"}' >"$SPOOL/requests/o5.json"
  printf '{"reqid":"o5b","op":"snap-ls","owner_uid":"04001"}'         >"$SPOOL/requests/o5b.json"
  printf '{"reqid":"o5c","op":"snap-ls","owner_uid":-1}'              >"$SPOOL/requests/o5c.json"
  printf '{"reqid":"o5d","op":"snap-ls","owner_uid":true}'            >"$SPOOL/requests/o5d.json"
  _run_once; [ "$status" -eq 0 ]
  for r in o5 o5b o5c o5d; do
    grep -q '"status": "rejected"' "$SPOOL/results/$r.json"
    grep -q 'bad owner_uid' "$SPOOL/results/$r.json"
    ! grep -q 'FAKE ' "$SPOOL/results/$r.json" || false
  done
}

# ---- snapshot-enabled agent path: `use <name> --from-snap <snap>` (owner-scoped clone-from-snapshot) ----
# The security-hard core (dr_vps_snapshot_use) already owner-scopes the resolve, re-verifies under the
# per-content lock (TOCTOU), and fails closed on secret-bearing. These tests pin the DECIDER envelope that
# exposes it to the agent: owner-stamped (fail-closed if not), a fixed create-shaped argv, no secret bypass.

@test "watch: use <name> --from-snap <snap> dispatches owner-scoped with the create envelope" {
  sid="drvps-snap-v1-5368709120-$(printf 'a%.0s' {1..64})"
  printf '{"reqid":"u1","op":"use","name":"svcg-x","snap":"%s","owner_uid":4021}' "$sid" >"$SPOOL/requests/u1.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/u1.json"
  grep -q "FAKE use svcg-x --from-snap $sid --owner 4021" "$SPOOL/results/u1.json"
  grep -q -- '--net simnet' "$SPOOL/results/u1.json"
  grep -q -- '--project agent' "$SPOOL/results/u1.json"
}

@test "watch: use WITHOUT owner_uid is REJECTED (fail-closed), never clones an unscoped base" {
  printf '{"reqid":"u2","op":"use","name":"svcg-x","snap":"drvps-snap-v1-1-abc"}' >"$SPOOL/requests/u2.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/u2.json"
  grep -q 'missing owner_uid' "$SPOOL/results/u2.json"
  ! grep -q 'FAKE ' "$SPOOL/results/u2.json" || false
}

@test "watch: use with a hostile snap id (leading dash) is REJECTED (no execution)" {
  printf '{"reqid":"u3","op":"use","name":"svcg-x","snap":"-bad","owner_uid":4022}' >"$SPOOL/requests/u3.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/u3.json"
  grep -q 'bad snap id' "$SPOOL/results/u3.json"
  ! grep -q 'FAKE ' "$SPOOL/results/u3.json" || false
}

@test "watch: use with a hostile VM name (leading dash -> option injection) is REJECTED" {
  # a name like --allow-secret-bearing must never be accepted as $1 to `dr-vps use`
  printf '{"reqid":"u4","op":"use","name":"--allow-secret-bearing","snap":"drvps-snap-v1-1-abc","owner_uid":4023}' >"$SPOOL/requests/u4.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/u4.json"
  grep -q 'bad name' "$SPOOL/results/u4.json"
  ! grep -q 'FAKE ' "$SPOOL/results/u4.json" || false
}

@test "watch: use NEVER threads --allow-secret-bearing (agent cannot clone a secret-bearing base)" {
  # even a hand-planted request that tries to smuggle the bypass gets a FIXED envelope without it
  printf '{"reqid":"u5","op":"use","name":"svcg-x","snap":"drvps-snap-v1-1-abc","owner_uid":4024,"allow_secret_bearing":true}' >"$SPOOL/requests/u5.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/u5.json"
  ! grep -q 'allow-secret-bearing' "$SPOOL/results/u5.json" || false
}

@test "watch: use caps cpus like create (out-of-range -> rejected, no execution)" {
  printf '{"reqid":"u6","op":"use","name":"svcg-x","snap":"drvps-snap-v1-1-abc","owner_uid":4025,"cpus":999}' >"$SPOOL/requests/u6.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/u6.json"
  grep -q 'bad cpus' "$SPOOL/results/u6.json"
  ! grep -q 'FAKE ' "$SPOOL/results/u6.json" || false
}

@test "watch: use with a valid ttl/mem/cpus threads them after the create envelope" {
  sid="drvps-snap-v1-1-abc"
  printf '{"reqid":"u7","op":"use","name":"svcg-x","snap":"%s","owner_uid":4026,"ttl":3,"cpus":2}' "$sid" >"$SPOOL/requests/u7.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/u7.json"
  grep -q -- '--ttl 3' "$SPOOL/results/u7.json"
  grep -q -- '--cpus 2' "$SPOOL/results/u7.json"
}

# ---- S4 idempotency keys: the (owner_uid, idem) journal under spool/idem/ ----------------------
# Contract: a client RETRY of a mutator (new reqid, SAME owner+idem+body) must not re-execute the
# verb -- it replays the recorded result. An execute-before-record crash stays INDETERMINATE and
# reconcile-by-type remains the fallback (idem SHRINKS the retry dance, does not remove it).

@test "watch: S4 -- a fresh idem mutator RUNS and journals (owner_uid, idem) -> state done + recorded result" {
  printf '{"reqid":"q1","op":"create","name":"v1","distro":"fedora44","owner_uid":4001,"idem":"key-a"}' >"$SPOOL/requests/q1.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/q1.json"
  j="$SPOOL/idem/4001/key-a.json"
  [ -f "$j" ]
  [ "$(jq -r .state "$j")" = done ]
  [ "$(jq -r .reqid "$j")" = q1 ]
  [ "$(jq -r .result.status "$j")" = ok ]
}

@test "watch: S4 -- a RETRY (new reqid, same owner+idem+body) REPLAYS the recorded result, does NOT re-execute" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-retry"; : >"$FDR_CALLS"
  req='"op":"create","name":"v1","distro":"fedora44","owner_uid":4001,"idem":"key-b"'
  printf '{"reqid":"q2",%s}' "$req" >"$SPOOL/requests/q2.json"
  _run_once; [ "$status" -eq 0 ]
  printf '{"reqid":"q3",%s}' "$req" >"$SPOOL/requests/q3.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(grep -c '^create ' "$FDR_CALLS")" -eq 1 ]                    # executed exactly ONCE
  [ "$(jq -r .idem_replayed "$SPOOL/results/q3.json")" = true ]
  [ "$(jq -r .orig_reqid "$SPOOL/results/q3.json")" = q2 ]
  [ "$(jq -r .status "$SPOOL/results/q3.json")" = ok ]
  [ "$(jq -r .reqid "$SPOOL/results/q3.json")" = q3 ]               # addressed to the RETRY's reqid
}

@test "watch: S4 -- the in-progress journal entry exists BEFORE the verb executes (crash-ordering pin)" {
  # The fake dr-vps observes the journal AT EXECUTION TIME. Without a durable in-progress entry
  # BEFORE run_action, a crash mid-verb leaves a retry with no marker -> silent double-execution.
  cat >"$BATS_TEST_TMPDIR/fdr-observe" <<EOF
#!/usr/bin/env bash
[ "\$1" = gate ] && exit 0
jq -r .state "$SPOOL/idem/4001/key-c.json" 2>/dev/null || echo NO-JOURNAL
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr-observe"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr-observe"
  printf '{"reqid":"q4","op":"create","name":"v1","distro":"fedora44","owner_uid":4001,"idem":"key-c"}' >"$SPOOL/requests/q4.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q 'in-progress' "$SPOOL/results/q4.json"                    # the child SAW the in-progress entry
  ! grep -q 'NO-JOURNAL' "$SPOOL/results/q4.json" || false
  [ "$(jq -r .state "$SPOOL/idem/4001/key-c.json")" = done ]        # ...finalized to done after the run
}

@test "watch: S4 -- watcher CRASH mid-verb -> retry gets INDETERMINATE (honest contract), never re-executes" {
  cat >"$BATS_TEST_TMPDIR/fdr-kill" <<'EOF'
#!/usr/bin/env bash
[ "$1" = gate ] && exit 0
kill -9 $PPID; sleep 5
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr-kill"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr-kill"
  req='"op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-d"'
  printf '{"reqid":"q5",%s}' "$req" >"$SPOOL/requests/q5.json"
  run timeout 20 python3 "$W" --once                                # SIGKILLed mid-verb: nonzero is EXPECTED
  [ "$status" -ne 0 ]
  export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr"                         # fresh watcher, normal fake
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-crash"; : >"$FDR_CALLS"
  printf '{"reqid":"q6",%s}' "$req" >"$SPOOL/requests/q6.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r .status "$SPOOL/results/q6.json")" = indeterminate ]
  ! grep -q '^destroy ' "$FDR_CALLS" || false                                # the mutator was NOT re-executed
}

@test "watch: S4 -- same key, DIFFERENT owner -> both run fresh (journal is per-owner)" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-owner"; : >"$FDR_CALLS"
  printf '{"reqid":"q7","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"shared-key"}' >"$SPOOL/requests/q7.json"
  _run_once; [ "$status" -eq 0 ]
  printf '{"reqid":"q8","op":"destroy","vm":"vm1","owner_uid":4002,"idem":"shared-key"}' >"$SPOOL/requests/q8.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(grep -c '^destroy ' "$FDR_CALLS")" -eq 2 ]
  [ "$(jq -r '.idem_replayed // "ABSENT"' "$SPOOL/results/q8.json")" = ABSENT ]
}

@test "watch: S4 -- same key+owner but a DIFFERENT request body -> REJECTED (key misuse), not replayed, not run" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-misuse"; : >"$FDR_CALLS"
  printf '{"reqid":"q9","op":"create","name":"va","distro":"fedora44","owner_uid":4001,"idem":"key-e"}' >"$SPOOL/requests/q9.json"
  _run_once; [ "$status" -eq 0 ]
  printf '{"reqid":"qA","op":"create","name":"vb","distro":"fedora44","owner_uid":4001,"idem":"key-e"}' >"$SPOOL/requests/qA.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(grep -c '^create ' "$FDR_CALLS")" -eq 1 ]                    # only the FIRST body executed
  grep -q '"status": "rejected"' "$SPOOL/results/qA.json"
  grep -q 'different request' "$SPOOL/results/qA.json"
}

@test "watch: S4 -- an already-DONE idem destroy arriving as a PREEMPT does NOT kill the in-flight exec (replays instead)" {
  printf '{"reqid":"qB","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-f"}' >"$SPOOL/requests/qB.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/qB.json"                 # destroy ran fresh + journaled done
  export FAKE_EXEC_SLEEP=4
  printf '{"reqid":"a-ex2","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}' >"$SPOOL/requests/a-ex2.json"
  printf '{"reqid":"z-re","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-f"}' >"$SPOOL/requests/z-re.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/a-ex2.json"              # exec completed...
  ! grep -q '"status": "preempted"' "$SPOOL/results/a-ex2.json" || false     # ...NOT killed for a replay
  [ "$(jq -r .idem_replayed "$SPOOL/results/z-re.json")" = true ]   # the retried destroy was replayed
}

@test "watch: S4 -- journal write failure (idem/ path blocked) FAILS CLOSED: error result, verb NOT executed" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-jfail"; : >"$FDR_CALLS"
  : >"$SPOOL/idem"                                                  # a FILE where the journal dir must be
  printf '{"reqid":"qC","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-g"}' >"$SPOOL/requests/qC.json"
  _run_once; [ "$status" -eq 0 ]                                    # daemon survives
  grep -q '"status": "error"' "$SPOOL/results/qC.json"
  ! grep -q '^destroy ' "$FDR_CALLS" || false                                # never executed without a durable marker
  rm -f "$SPOOL/idem"
}

@test "watch: S4 -- a request WITHOUT idem journals NOTHING (non-idem path unchanged)" {
  printf '{"reqid":"qD","op":"destroy","vm":"vm1","owner_uid":4001}' >"$SPOOL/requests/qD.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/qD.json"
  [ -z "$(find "$SPOOL/idem" -type f 2>/dev/null)" ]                # no journal entries
}

@test "watch: S4 -- journal entries are drvps-PRIVATE (0700 dirs / 0600 files; S5 hardens further)" {
  printf '{"reqid":"qE","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-h"}' >"$SPOOL/requests/qE.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(stat -c %a "$SPOOL/idem")" = 700 ]
  [ "$(stat -c %a "$SPOOL/idem/4001")" = 700 ]
  [ "$(stat -c %a "$SPOOL/idem/4001/key-h.json")" = 600 ]
}

@test "watch: S4 -- a CORRUPT journal entry -> INDETERMINATE (an attempt may have run), verb NOT executed" {
  printf '{"reqid":"qF","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-i"}' >"$SPOOL/requests/qF.json"
  _run_once; [ "$status" -eq 0 ]                                    # seed a real entry, then corrupt it
  printf 'NOT JSON' >"$SPOOL/idem/4001/key-i.json"
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-corrupt"; : >"$FDR_CALLS"
  printf '{"reqid":"qG","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-i"}' >"$SPOOL/requests/qG.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r .status "$SPOOL/results/qG.json")" = indeterminate ]
  ! grep -q '^destroy ' "$FDR_CALLS" || false                                # never re-executed on a corrupt record
}

@test "watch: S4 -- a FRESH-key idem destroy still PREEMPTS the in-flight exec and journals done" {
  export FAKE_EXEC_SLEEP=4
  printf '{"reqid":"a-ex3","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}' >"$SPOOL/requests/a-ex3.json"
  printf '{"reqid":"z-rf","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-j"}' >"$SPOOL/requests/z-rf.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "preempted"' "$SPOOL/results/a-ex3.json"       # fresh key -> preempt still happens
  grep -q '"status": "ok"' "$SPOOL/results/z-rf.json"               # rescue ran...
  [ "$(jq -r '.idem_replayed // "ABSENT"' "$SPOOL/results/z-rf.json")" = ABSENT ]   # ...fresh, not replayed
  [ "$(jq -r .state "$SPOOL/idem/4001/key-j.json")" = done ]        # ...and was journaled
}

@test "watch: S4 -- idem_begin failure (unwritable idem/, no entry) FAILS CLOSED: error result, verb NOT executed" {
  # resolve sees ENOENT (fresh) but begin cannot create the owner dir -> refuse to execute.
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-beginfail"; : >"$FDR_CALLS"
  mkdir -p "$SPOOL/idem"; chmod 0500 "$SPOOL/idem"
  printf '{"reqid":"qH","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-k"}' >"$SPOOL/requests/qH.json"
  _run_once; [ "$status" -eq 0 ]
  chmod 0700 "$SPOOL/idem"                                          # restore before asserting (cleanup)
  grep -q '"status": "error"' "$SPOOL/results/qH.json"
  grep -q 'idem journal write failed' "$SPOOL/results/qH.json"
  ! grep -q '^destroy ' "$FDR_CALLS" || false
}

# ---- S4: gate-vs-journal ordering, journal hardening, envelope integrity ----

@test "watch: S4 -- a recorded DONE idem recreate REPLAYS even when the CURRENT gate refuses" {
  printf '{"reqid":"g1","op":"recreate","vm":"vm1","owner_uid":4001,"idem":"key-l"}' >"$SPOOL/requests/g1.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/g1.json"                 # first attempt ran + journaled done
  cat >"$BATS_TEST_TMPDIR/fdr-refuse" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FDR_CALLS:-/dev/null}"
[ "$1" = gate ] && exit 1
printf 'FAKE %s\n' "$*"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr-refuse"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr-refuse"
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-gate"; : >"$FDR_CALLS"
  printf '{"reqid":"g2","op":"recreate","vm":"vm1","owner_uid":4001,"idem":"key-l"}' >"$SPOOL/requests/g2.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r .idem_replayed "$SPOOL/results/g2.json")" = true ]     # journal answers, NOT "gate refused"
  ! grep -q '^recreate ' "$FDR_CALLS" || false
}

@test "watch: S4 -- an IN-PROGRESS idem recreate answers indeterminate even when the CURRENT gate refuses" {
  cat >"$BATS_TEST_TMPDIR/fdr-kill2" <<'EOF'
#!/usr/bin/env bash
[ "$1" = gate ] && exit 0
kill -9 $PPID; sleep 5
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr-kill2"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr-kill2"
  printf '{"reqid":"g3","op":"recreate","vm":"vm1","owner_uid":4001,"idem":"key-o"}' >"$SPOOL/requests/g3.json"
  run timeout 20 python3 "$W" --once; [ "$status" -ne 0 ]           # crashed mid-recreate (in-progress persists)
  cat >"$BATS_TEST_TMPDIR/fdr-refuse2" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FDR_CALLS:-/dev/null}"
[ "$1" = gate ] && exit 1
printf 'FAKE %s\n' "$*"
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr-refuse2"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr-refuse2"
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-gate2"; : >"$FDR_CALLS"
  printf '{"reqid":"g4","op":"recreate","vm":"vm1","owner_uid":4001,"idem":"key-o"}' >"$SPOOL/requests/g4.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r .status "$SPOOL/results/g4.json")" = indeterminate ]   # honest answer, NOT "gate refused"
  ! grep -q '^recreate ' "$FDR_CALLS" || false
}

@test "watch: S4 -- preempt with a FRESH key whose journal write FAILS: child NOT killed, destroy errors" {
  export FAKE_EXEC_SLEEP=4
  mkdir -p "$SPOOL/idem"; chmod 0500 "$SPOOL/idem"
  printf '{"reqid":"a-ex4","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}' >"$SPOOL/requests/a-ex4.json"
  printf '{"reqid":"z-rg","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-p"}' >"$SPOOL/requests/z-rg.json"
  _run_once; [ "$status" -eq 0 ]
  chmod 0700 "$SPOOL/idem"
  grep -q '"status": "ok"' "$SPOOL/results/a-ex4.json"              # the exec survived...
  ! grep -q '"status": "preempted"' "$SPOOL/results/a-ex4.json" || false     # ...never killed for an unjournalable rescue
  grep -q '"status": "error"' "$SPOOL/results/z-rg.json"
  grep -q 'idem journal write failed' "$SPOOL/results/z-rg.json"
}

@test "watch: S4 -- a MALFORMED journal entry (valid JSON, wrong shape) -> INDETERMINATE, not key-misuse rejected" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-malformed"; : >"$FDR_CALLS"
  mkdir -p "$SPOOL/idem/4001"; printf '{}' >"$SPOOL/idem/4001/key-m.json"
  printf '{"reqid":"g5","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-m"}' >"$SPOOL/requests/g5.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r .status "$SPOOL/results/g5.json")" = indeterminate ]
  ! grep -q 'different request' "$SPOOL/results/g5.json" || false            # not misclassified as key misuse
  ! grep -q '^destroy ' "$FDR_CALLS" || false
}

@test "watch: S4 -- a SYMLINK at the journal path fails CLOSED (error), never treated as a fresh key" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-symlink"; : >"$FDR_CALLS"
  mkdir -p "$SPOOL/idem/4001"; ln -s /nonexistent "$SPOOL/idem/4001/key-n.json"
  printf '{"reqid":"g6","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"key-n"}' >"$SPOOL/requests/g6.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "error"' "$SPOOL/results/g6.json"
  ! grep -q '^destroy ' "$FDR_CALLS" || false                                # never executed off an abnormal journal path
}

@test "watch: S4 -- an over-cap REJECT envelope (no stdout/stderr) trims 'reason' to VALID JSON, never a byte-slice" {
  export DR_VPS_RESULT_MAX_BYTES=1                                  # write_result floors this to 512
  # sized to EXCEED the 512-byte floor (verified: 550 B envelope): 128-char reqid + 64-char vm + 64-char key
  key=$(printf 'k%.0s' {1..64}); rid1=$(printf 'a%.0s' {1..128}); rid2=$(printf 'b%.0s' {1..128})
  vm=$(printf 'v%.0s' {1..64})
  printf '{"reqid":"%s","op":"destroy","vm":"x%s","owner_uid":4001,"idem":"%s"}' "$rid1" "${vm:1}" "$key" >"$SPOOL/requests/$rid1.json"
  _run_once; [ "$status" -eq 0 ]
  printf '{"reqid":"%s","op":"destroy","vm":"%s","owner_uid":4001,"idem":"%s"}' "$rid2" "$vm" "$key" >"$SPOOL/requests/$rid2.json"
  _run_once; [ "$status" -eq 0 ]                                    # body mismatch -> long rejected envelope
  jq -e . "$SPOOL/results/$rid2.json" >/dev/null                    # VALID JSON despite the tiny cap
  [ "$(jq -r .status "$SPOOL/results/$rid2.json")" = rejected ]
  [ "$(jq -r .truncated "$SPOOL/results/$rid2.json")" = true ]
}

# ---- S5 private result store: result files 0600 + POSIX ACL user:<owner>:r (co-tenant leak fix) ----
# Mechanics only (the real cross-uid DENY was live-verified on the nested harness; a single offline
# test uid cannot re-prove it here).
# Skips where the test fs lacks ACL support so the suite stays OS-portable.
_acl_fs_ok() {
  local t="$BATS_TEST_TMPDIR/.aclprobe"; : >"$t"
  setfacl -m u:65534:r "$t" >/dev/null 2>&1 && getfacl -pcn "$t" 2>/dev/null | grep -q '^user:65534:r'
  local rc=$?; rm -f "$t"; return $rc
}

# NB: with an extended ACL present, `stat %a` reports the ACL MASK in the group triad (so an ACL'd 0600
# file shows 640) -- the REAL confidentiality check is getfacl: group::--- (co-tenants denied via the
# group class) + other::--- with a named-user grant. `_grp_denied` asserts no co-tenant group read.
_acl_owner_only() {  # <file> <owner-uid>
  getfacl -pcn "$1" | grep -q '^user::rw-'
  getfacl -pcn "$1" | grep -q "^user:$2:r--"      # the requesting owner reads
  getfacl -pcn "$1" | grep -q '^group::---'       # co-tenant group denied (the leak)
  getfacl -pcn "$1" | grep -q '^other::---'
}

@test "watch: S5 -- a result file carries a user:<owner>:r ACL with group/other denied (co-tenant leak fix)" {
  _acl_fs_ok || skip "test fs lacks POSIX ACL support"
  printf '{"reqid":"p1","op":"list","owner_uid":4001}' >"$SPOOL/requests/p1.json"   # owner ingress-stamped even on reads
  _run_once; [ "$status" -eq 0 ]
  _acl_owner_only "$SPOOL/results/p1.json" 4001
}

@test "watch: S5 -- a REJECTED result is ACL'd to its owner too (a rejection the agent must be able to read)" {
  _acl_fs_ok || skip "test fs lacks POSIX ACL support"
  printf '{"reqid":"p2","op":"snap-rm","snap":"-bad","owner_uid":4002}' >"$SPOOL/requests/p2.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "rejected"' "$SPOOL/results/p2.json"
  _acl_owner_only "$SPOOL/results/p2.json" 4002
}

@test "watch: S5 -- the .claimed marker is owner-ACL'd, not co-tenant-readable" {
  _acl_fs_ok || skip "test fs lacks POSIX ACL support"
  export FAKE_EXEC_SLEEP=2
  printf '{"reqid":"p3","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4003}' >"$SPOOL/requests/p3.json"
  _run_once; [ "$status" -eq 0 ]
  _acl_owner_only "$SPOOL/results/p3.claimed" 4003
}

@test "watch: S5 -- an idem REPLAY result is ACL'd to the retrying owner" {
  _acl_fs_ok || skip "test fs lacks POSIX ACL support"
  req='"op":"destroy","vm":"vm1","owner_uid":4004,"idem":"pk"'
  printf '{"reqid":"p4a",%s}' "$req" >"$SPOOL/requests/p4a.json"; _run_once; [ "$status" -eq 0 ]
  printf '{"reqid":"p4b",%s}' "$req" >"$SPOOL/requests/p4b.json"; _run_once; [ "$status" -eq 0 ]
  [ "$(jq -r .idem_replayed "$SPOOL/results/p4b.json")" = true ]
  _acl_owner_only "$SPOOL/results/p4b.json" 4004
}

@test "watch: S5 -- legacy mode (DR_VPS_RESULT_PRIVATE=0) keeps 0640 group-readable, no named-user ACL" {
  export DR_VPS_RESULT_PRIVATE=0
  printf '{"reqid":"p5","op":"list","owner_uid":4001}' >"$SPOOL/requests/p5.json"
  _run_once; [ "$status" -eq 0 ]
  [ "$(stat -c %a "$SPOOL/results/p5.json")" = 640 ]
  ! getfacl -pcn "$SPOOL/results/p5.json" 2>/dev/null | grep -q '^user:4001:' || false
}

@test "watch: S5 -- a request with NO owner_uid (unattributable) -> 0600 drvps-only, no ACL (fail closed)" {
  _acl_fs_ok || skip "test fs lacks POSIX ACL support"
  printf '{"reqid":"p6","op":"list"}' >"$SPOOL/requests/p6.json"      # no owner (harness-only; ingress always stamps)
  _run_once; [ "$status" -eq 0 ]
  [ "$(stat -c %a "$SPOOL/results/p6.json")" = 600 ]
  ! getfacl -pcn "$SPOOL/results/p6.json" | grep -qE '^user:[0-9]+:' || false    # no named-user grant
}

# ---- S4: tombstone guard before EVERY terminal write ----
@test "watch: an INVALID same-reqid preempt candidate cannot POISON the in-flight op's result slot" {
  # the fake exec drops a same-reqid destroy with a HOSTILE idem (bad charset) mid-run. find_preempt
  # matches it (op/vm/reqid ok), decide() REJECTS it (bad idem) -> the reject branch must NOT write
  # results/same.json (which would no-clobber and hide the exec's real result). Tombstone guard.
  cat >"$BATS_TEST_TMPDIR/fdr3" <<EOF
#!/usr/bin/env bash
case "\$1" in
  gate) exit 0 ;;
  exec) printf '{"reqid":"fx","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"bad key"}' >"$SPOOL/requests/fx.json"; sleep 3; printf 'EXEC_DONE\n' ;;
  *)    printf 'FAKE %s\n' "\$*" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fdr3"; export DR_VPS_BIN="$BATS_TEST_TMPDIR/fdr3"
  printf '{"reqid":"fx","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}' >"$SPOOL/requests/fx.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"op": "exec"' "$SPOOL/results/fx.json"        # the EXEC's result survives...
  grep -q '"status": "ok"' "$SPOOL/results/fx.json"      # ...as ok
  ! grep -q 'bad idem' "$SPOOL/results/fx.json" || false          # the injected rejection did NOT poison the slot
}

@test "watch: main-path reject for a reqid that is already CLAIMED is refused (no result-slot poison)" {
  # a reqid whose op is in-flight (its .claimed exists, .json not yet) must not have a rejection written
  # into its results slot by a duplicate submission that decide() rejects.
  printf '{"reqid":"dupe","op":"exec","vm":"vm1"}' >"$SPOOL/results/dupe.claimed"   # simulate in-flight claimed
  printf '{"reqid":"dupe","op":"bogus-verb"}' >"$SPOOL/requests/dupe.json"          # a rejectable duplicate
  _run_once; [ "$status" -eq 0 ]
  [ ! -f "$SPOOL/results/dupe.json" ]                    # no rejection written over the claimed slot
  grep -q '"status": "duplicate"' "$SPOOL/audit.log"     # recorded as duplicate instead
}

# ---- S4: per-owner idem quota (no cross-owner eviction) ----
@test "watch: an owner at its idem quota is REFUSED a new key (not executed), other owners untouched" {
  export DR_VPS_IDEM_OWNER_MAX=2
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-quota"; : >"$FDR_CALLS"
  mkdir -p "$SPOOL/idem/4001"
  printf '{"state":"done","req_sha":"%s","reqid":"old1"}' "$(printf 'a%.0s' {1..64})" >"$SPOOL/idem/4001/k1.json"
  printf '{"state":"done","req_sha":"%s","reqid":"old2"}' "$(printf 'b%.0s' {1..64})" >"$SPOOL/idem/4001/k2.json"
  # owner A (4001) at quota (2 keys) -> a NEW key is refused
  printf '{"reqid":"qa","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"knew"}' >"$SPOOL/requests/qa.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "error"' "$SPOOL/results/qa.json"
  grep -q 'quota' "$SPOOL/results/qa.json"
  ! grep -q '^destroy ' "$FDR_CALLS" || false                          # NOT executed
  [ ! -e "$SPOOL/idem/4001/knew.json" ]                       # no new journal entry
  [ -f "$SPOOL/idem/4001/k1.json" ]                           # A's OWN old entries untouched
  # owner B (4002) below quota -> works fresh
  printf '{"reqid":"qb","op":"destroy","vm":"vm1","owner_uid":4002,"idem":"kb"}' >"$SPOOL/requests/qb.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/qb.json"
  [ -f "$SPOOL/idem/4002/kb.json" ]
}


# ---- S4: owner-aware preempt (no cross-owner DoS) ----
@test "watch: a FOREIGN owner's destroy does NOT preempt/kill another owner's in-flight exec" {
  export FAKE_EXEC_SLEEP=4
  # owner 4001 runs exec; owner 4002 tries to destroy the SAME vm mid-run -> must NOT kill 4001's exec.
  printf '{"reqid":"a-own","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}'  >"$SPOOL/requests/a-own.json"
  printf '{"reqid":"z-foreign","op":"destroy","vm":"vm1","owner_uid":4002}'         >"$SPOOL/requests/z-foreign.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "ok"' "$SPOOL/results/a-own.json"          # exec completed...
  ! grep -q '"status": "preempted"' "$SPOOL/results/a-own.json" || false # ...NOT killed by a foreign owner
}

@test "watch: a SAME-owner destroy STILL preempts the in-flight exec (regression: legit preempt works)" {
  export FAKE_EXEC_SLEEP=4
  printf '{"reqid":"a-same","op":"exec","vm":"vm1","cmd":"sleep","owner_uid":4001}' >"$SPOOL/requests/a-same.json"
  printf '{"reqid":"z-same","op":"destroy","vm":"vm1","owner_uid":4001}'            >"$SPOOL/requests/z-same.json"
  _run_once; [ "$status" -eq 0 ]
  grep -q '"status": "preempted"' "$SPOOL/results/a-same.json"  # same-owner preempt still fires
  grep -q '"status": "ok"' "$SPOOL/results/z-same.json"         # rescue ran
}

# ---- S4: re-poll after preempt_cb (no false "preempted") ----
@test "watch: a child that COMPLETES during preempt_cb is NOT reported preempted (real exit kept)" {
  local srcdir; srcdir="$(cd "${DR_VPS_SRC}/../src" && pwd)"
  run python3 - "$srcdir" <<'PY'
import sys, subprocess
sys.path.insert(0, sys.argv[1])
import drvps_rigctl as R
R.PREEMPT_SCAN_S = 0.2                      # fire the preempt scan quickly
p = subprocess.Popen(["sh", "-c", "sleep 0.5; printf DONE"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
calls = {"n": 0}
def cb():
    calls["n"] += 1
    if calls["n"] == 1:
        p.wait()                            # child finishes NATURALLY during the callback
        return {"reqid": "resc", "op": "destroy", "vm": "vm1", "argv": ["true"]}
    return None
rc, out, err, status, rescue = R.supervise(p, 30, 65536, cb)
assert status == "ok", "status=%r (should be ok, not preempted)" % status
assert rc == 0, "rc=%r (child's real exit must be kept)" % rc
assert b"DONE" in out, "out=%r (child output lost)" % out
assert rescue is not None, "rescue must still run afterward"
print("F3-OK")
PY
  [ "$status" -eq 0 ]
  [[ "$output" == *F3-OK* ]]
}

# ---- S4: refuse a symlinked idem journal dir (fail closed) ----
@test "watch: a SYMLINKED idem owner dir is refused (fail closed), never written through" {
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-f5"; : >"$FDR_CALLS"
  mkdir -p "$SPOOL/idem"
  mkdir -p "$BATS_TEST_TMPDIR/evil"
  ln -s "$BATS_TEST_TMPDIR/evil" "$SPOOL/idem/4001"       # planted symlink at the owner dir
  printf '{"reqid":"f5","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"k5"}' >"$SPOOL/requests/f5.json"
  _run_once; [ "$status" -eq 0 ]                          # daemon survives
  grep -q '"status": "error"' "$SPOOL/results/f5.json"
  grep -q 'idem journal write failed' "$SPOOL/results/f5.json"
  ! grep -q '^destroy ' "$FDR_CALLS" || false                      # NOT executed without a durable in-tree record
  [ -z "$(ls -A "$BATS_TEST_TMPDIR/evil" 2>/dev/null)" ] # nothing written THROUGH the symlink
}

# ---- S5: result-ACL + supervision hardening ----
@test "watch: an inherited default ACL on results/ does NOT survive onto a result (only owner granted)" {
  _acl_fs_ok || skip "test fs lacks POSIX ACL support"
  setfacl -d -m u:4002:r "$SPOOL/results"                    # a co-tenant default ACL on the dir
  printf '{"reqid":"m1","op":"list","owner_uid":4001}' >"$SPOOL/requests/m1.json"
  _run_once; [ "$status" -eq 0 ]
  getfacl -pcn "$SPOOL/results/m1.json" | grep -q '^user:4001:r--'   # the requester is granted...
  ! getfacl -pcn "$SPOOL/results/m1.json" | grep -q '^user:4002' || false     # ...the inherited co-tenant is NOT
}

@test "watch: the OVER-CAP reject path does NOT poison an already-claimed reqid slot" {
  export DR_VPS_MAX_PENDING=1
  printf '{"reqid":"cap","op":"exec","vm":"vm1"}' >"$SPOOL/results/cap.claimed"   # in-flight claimed marker
  # two requests -> over the cap of 1; the surplus 'cap' (duplicate reqid) must NOT get a reject written
  printf '{"reqid":"keep","op":"list"}' >"$SPOOL/requests/keep.json";  sleep 0.05
  printf '{"reqid":"cap","op":"list"}'  >"$SPOOL/requests/cap.json"
  _run_once; [ "$status" -eq 0 ]
  [ ! -f "$SPOOL/results/cap.json" ]                         # the claimed slot was NOT poisoned by over-cap reject
}

@test "watch: a preempt_cb that RAISES does not abort supervision or orphan the child" {
  local srcdir; srcdir="$(cd "${DR_VPS_SRC}/../src" && pwd)"
  run python3 - "$srcdir" <<'PY'
import sys, subprocess
sys.path.insert(0, sys.argv[1])
import drvps_rigctl as R
R.PREEMPT_SCAN_S = 0.2
p = subprocess.Popen(["sh", "-c", "sleep 0.5; printf DONE"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
def cb():
    raise OSError("ENOSPC simulated inside the preempt scan")
rc, out, err, status, rescue = R.supervise(p, 30, 65536, cb)   # must NOT propagate the exception
assert status == "ok", "status=%r (cb exception must be swallowed, child runs to completion)" % status
assert b"DONE" in out, "out=%r (child output lost)" % out
assert rescue is None, "no rescue on a failed scan"
assert p.poll() is not None, "child must be reaped, not left running"
print("M2-OK")
PY
  [ "$status" -eq 0 ]
  [[ "$output" == *M2-OK* ]]
}

@test "watch: mark_claimed failure (unwritable results/) -> verb NOT executed (fail closed on the tombstone)" {
  [ "$(id -u)" -ne 0 ] || skip "root bypasses dir perms"
  export FDR_CALLS="$BATS_TEST_TMPDIR/calls-m4"; : >"$FDR_CALLS"
  printf '{"reqid":"m4","op":"destroy","vm":"vm1","owner_uid":4001}' >"$SPOOL/requests/m4.json"
  chmod 500 "$SPOOL/results"                     # marker create (O_CREAT) will EACCES
  _run_once; [ "$status" -eq 0 ]                 # daemon survives
  chmod 700 "$SPOOL/results"                     # restore for teardown
  ! grep -q '^destroy ' "$FDR_CALLS" || false             # the mutator did NOT run without a durable tombstone
}
