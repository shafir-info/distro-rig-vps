#!/usr/bin/env bats
# Stage 4 (Phase 2) -- the agent client: builds a correct request, SUBMITS it over the drvps-side
# ingress socket (the agent has NO filesystem write to the spool), then bounded-waits on the result.
# A faithful accept-loop harness runs the REAL drvps-rigsubmit per connection (mimics systemd
# Accept=yes), so the socket transport + the accepter are exercised end-to-end.

load helpers

setup() {
  export SPOOL="$BATS_TEST_TMPDIR/spool"
  mkdir -p "$SPOOL/requests" "$SPOOL/results"
  export DR_VPS_SPOOL_DIR="$SPOOL"
  RIGCTL="${DR_VPS_SRC}/../bin/rigctl"
  SUB="${DR_VPS_SRC}/drvps_rigsubmit.py"          # accepter logic; the harness runs it per connection
  export DR_VPS_SUBMIT_SOCK="$BATS_TEST_TMPDIR/submit.sock"
  cat >"$BATS_TEST_TMPDIR/harness.py" <<'EOF'
import socket, subprocess, sys, os
sockpath, exe = sys.argv[1], sys.argv[2]
try: os.unlink(sockpath)
except OSError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sockpath); srv.listen(16)
while True:
    conn, _ = srv.accept()
    subprocess.Popen([sys.executable, exe], stdin=conn.fileno(), stdout=conn.fileno())
    conn.close()
EOF
  python3 "$BATS_TEST_TMPDIR/harness.py" "$DR_VPS_SUBMIT_SOCK" "$SUB" &
  HARNESS_PID=$!
  for _ in $(seq 1 50); do [ -S "$DR_VPS_SUBMIT_SOCK" ] && break; sleep 0.1; done
}

teardown() { [ -n "${HARNESS_PID:-}" ] && kill "$HARNESS_PID" 2>/dev/null || true; }

@test "rigctl pull: DECODES the result content_b64 to RAW stdout, binary-safe (D7/C-3)" {
  printf 'x\xffy' >"$BATS_TEST_TMPDIR/want"                  # 0xff is invalid utf-8 -> proves binary safety
  b64=$(base64 -w0 <"$BATS_TEST_TMPDIR/want")
  RIGCTL_TIMEOUT=10 "$RIGCTL" pull vm1 /etc/hostname >"$BATS_TEST_TMPDIR/out" 2>/dev/null &
  rpid=$!
  # the accepter writes the request; read its reqid, then write a matching ok+content_b64 result
  reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok","exit_code":0,"content_b64":"%s"}' "$reqid" "$b64" >"$SPOOL/results/$reqid.json"
  wait "$rpid"; [ "$?" -eq 0 ]
  cmp "$BATS_TEST_TMPDIR/want" "$BATS_TEST_TMPDIR/out"       # rigctl reproduced the exact bytes
}

@test "rigctl console-dump: DECODES content_b64 AND SANITIZES C0+C1 control/escape bytes for display (observability Step 8)" {
  # UNTRUSTED serial output: ESC (\x1b), NUL (\x00), AND a C1 CSI byte (\x9b, terminal-active WITHOUT ESC),
  # wrapped in printable text. rigctl must STRIP all of them (no terminal-escape injection) while KEEPING
  # printable text + newlines.
  printf 'boot\x1b[31mRED\x00\x9b2Khidden\nline2\n' >"$BATS_TEST_TMPDIR/raw"
  b64=$(base64 -w0 <"$BATS_TEST_TMPDIR/raw")
  RIGCTL_TIMEOUT=10 "$RIGCTL" console-dump vm1 >"$BATS_TEST_TMPDIR/out" 2>/dev/null &
  rpid=$!
  reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok","exit_code":0,"content_b64":"%s"}' "$reqid" "$b64" >"$SPOOL/results/$reqid.json"
  wait "$rpid"; [ "$?" -eq 0 ]
  [[ "$(cat "$BATS_TEST_TMPDIR/out")" == *"[31mRED"* ]]     # ESC byte stripped -> literal text remains
  [[ "$(cat "$BATS_TEST_TMPDIR/out")" == *"boot"* ]]
  [[ "$(cat "$BATS_TEST_TMPDIR/out")" == *"line2"* ]]
  ! grep -qP '[\x00\x1b\x9b]' "$BATS_TEST_TMPDIR/out" || false       # no NUL / ESC / C1-CSI control bytes survive
}

@test "rigctl console-dump: a result MISSING content_b64 (status ok, exit 0) is NOT a false-empty success" {
  RIGCTL_TIMEOUT=10 "$RIGCTL" console-dump vm1 >"$BATS_TEST_TMPDIR/out" 2>"$BATS_TEST_TMPDIR/err" &
  rpid=$!
  reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok","exit_code":0}' "$reqid" >"$SPOOL/results/$reqid.json"   # NO content_b64
  rc=0; wait "$rpid" || rc=$?
  [ "$rc" -ne 0 ]                                            # fail closed, not decode-empty-and-exit-0
  [[ "$(cat "$BATS_TEST_TMPDIR/err")" == *"missing content_b64"* ]]   # message on stderr (like pull errors)
}

@test "rigctl console-dump: a 'no persistent log' (status ok, exit 14) result is NOT a false success" {
  RIGCTL_TIMEOUT=10 "$RIGCTL" console-dump vm1 >"$BATS_TEST_TMPDIR/out" 2>/dev/null &
  rpid=$!
  reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok","exit_code":14,"stderr":"no persistent console log (recreate to enable)"}' "$reqid" >"$SPOOL/results/$reqid.json"
  rc=0; wait "$rpid" || rc=$?                                # capture rigctl's exit without tripping bats
  [ "$rc" -ne 0 ]                                            # NOT decoded-and-exit-0
  [[ "$(cat "$BATS_TEST_TMPDIR/out")" == *"recreate to enable"* ]]
}

@test "rigctl pull: a status=ok result with nonzero exit_code is NOT treated as success" {
  # a guest read that failed comes back status=ok, exit_code!=0. rigctl must NOT decode-and-exit-0;
  # it must surface the failure (print envelope, exit nonzero), else a failed pull looks like success.
  "$RIGCTL" pull vm1 /no/such >"$BATS_TEST_TMPDIR/out" 2>/dev/null &
  rpid=$!
  reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok","exit_code":1,"stderr":"pull: guest read failed"}' "$reqid" >"$SPOOL/results/$reqid.json"
  rc=0; wait "$rpid" || rc=$?                         # capture rigctl's exit without bats aborting on nonzero
  [ "$rc" -ne 0 ]                                     # failure surfaced, not exit 0
}

@test "rigctl: SURPLUS argv on fixed-arity verbs -> usage(2), never a silently-dropped command" {
  run "$RIGCTL" exec vm1 echo hello;        [ "$status" -eq 2 ]   # unquoted cmd would submit just 'echo'
  run "$RIGCTL" pull vm1 /r extra;          [ "$status" -eq 2 ]
  run "$RIGCTL" push vm1 /etc/hostname /r x; [ "$status" -eq 2 ]
  run "$RIGCTL" status vm1 extra;           [ "$status" -eq 2 ]
  run "$RIGCTL" list junk;                  [ "$status" -eq 2 ]
  [ -z "$(ls "$SPOOL"/requests/*.json 2>/dev/null)" ]            # nothing submitted for any of them
  # a correctly-quoted command still submits (regression guard)
  RIGCTL_TIMEOUT=1 run "$RIGCTL" exec vm1 'echo hello'; [ "$status" -eq 17 ]   # submitted, then times out
  f=$(ls "$SPOOL"/requests/*.json); [ "$(jq -r .cmd "$f")" = "echo hello" ]
}

@test "rigctl create: a NON-INTEGER numeric arg -> client-side usage error (2), never an empty-body submit" {
  run "$RIGCTL" create web fedora44 2h                 # ttl '2h' is not an integer
  [ "$status" -eq 2 ]
  [[ "$output" == *"ttl must be a non-negative integer"* ]]
  [ -z "$(ls "$SPOOL"/requests/*.json 2>/dev/null)" ]  # nothing was submitted (caught before the socket)
}

@test "rigctl: submits a correct exec request via the socket (charset-fenced reqid)" {
  RIGCTL_TIMEOUT=1 run "$RIGCTL" exec vm1 'id -u'
  [ "$status" -eq 17 ]                               # no watcher -> times out, but request submitted
  f=$(ls "$SPOOL"/requests/*.json)
  jq -e '.op=="exec" and .vm=="vm1" and .cmd=="id -u" and (.reqid|test("^[A-Za-z0-9_-]+$"))' "$f"
  [ -z "$(ls "$SPOOL"/requests/.*.tmp 2>/dev/null)" ]   # no leftover temp
}

@test "rigctl: push embeds base64 of the local file (no host path leaves the agent)" {
  echo "secret-payload" >"$BATS_TEST_TMPDIR/up"
  RIGCTL_TIMEOUT=1 run "$RIGCTL" push vm1 "$BATS_TEST_TMPDIR/up" /tmp/x
  [ "$status" -eq 17 ]
  f=$(ls "$SPOOL"/requests/*.json)
  jq -e '.op=="push" and .vm=="vm1" and .remote=="/tmp/x"' "$f"
  [ "$(jq -r .content_b64 "$f" | base64 -d)" = "secret-payload" ]
}

@test "rigctl: bad usage -> 2 (never reaches the socket)" {
  run "$RIGCTL" exec vm1; [ "$status" -eq 2 ]
}

@test "rigctl: an unreachable submit socket fails fast (not a silent timeout)" {
  DR_VPS_SUBMIT_SOCK="$BATS_TEST_TMPDIR/nope.sock" RIGCTL_TIMEOUT=1 run "$RIGCTL" list
  [ "$status" -eq 2 ]                                 # die() -> 2, does NOT hang for the result timeout
  [[ "$output" == *"could not reach the submit socket"* ]]
}

@test "rigctl: returns the watcher's result envelope (round trip)" {
  ( "$RIGCTL" list >"$BATS_TEST_TMPDIR/out" 2>/dev/null ) &
  cli=$!
  for _ in $(seq 1 40); do f=$(ls "$SPOOL"/requests/*.json 2>/dev/null) && break; sleep 0.1; done
  reqid=$(jq -r .reqid "$f")
  printf '{"reqid":"%s","status":"ok","stdout":"FAKE list"}' "$reqid" >"$SPOOL/results/${reqid}.json"
  wait "$cli"
  grep -q 'FAKE list' "$BATS_TEST_TMPDIR/out"
}

@test "rigctl use: builds an op:use request (name+snap), accepter STAMPS the peer owner_uid" {
  sid="drvps-snap-v1-5368709120-$(printf 'a%.0s' {1..64})"
  ( RIGCTL_TIMEOUT=6 "$RIGCTL" use svcg-x --from-snap "$sid" >/dev/null 2>&1 ) &
  cli=$!
  f=""
  for _ in $(seq 1 50); do f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) && [ -n "$f" ] && break; sleep 0.1; done
  kill "$cli" 2>/dev/null || true
  [ -n "$f" ]
  [ "$(jq -r .op   "$f")" = use ]
  [ "$(jq -r .name "$f")" = svcg-x ]
  [ "$(jq -r .snap "$f")" = "$sid" ]
  [ "$(jq -r '.owner_uid' "$f")" = "$(id -u)" ]      # kernel-verified peer uid, stamped by the accepter
}

@test "rigctl use: missing --from-snap -> client usage error (2), nothing submitted" {
  run "$RIGCTL" use svcg-x
  [ "$status" -eq 2 ]
  [ -z "$(ls "$SPOOL"/requests/*.json 2>/dev/null)" ]
}

@test "rigctl use: a NON-INTEGER --ttl -> client usage error (2), never an empty-body submit" {
  run "$RIGCTL" use svcg-x --from-snap drvps-snap-v1-1-abc --ttl 2h
  [ "$status" -eq 2 ]
  [[ "$output" == *"ttl"* ]]
  [ -z "$(ls "$SPOOL"/requests/*.json 2>/dev/null)" ]
}

@test "rigctl push: a LARGE file (past jq --arg ARG_MAX) submits via --rawfile, not 'Argument list too long' (ARG_MAX-safe submit)" {
  head -c 122880 /dev/zero | tr '\0' 'A' > "$BATS_TEST_TMPDIR/big"   # 120KB -> ~160KB base64 > MAX_ARG_STRLEN
  RIGCTL_TIMEOUT=1 run "$RIGCTL" push vm1 "$BATS_TEST_TMPDIR/big" /tmp/big
  [ "$status" -eq 17 ]                                   # submitted + result-timeout (NOT a client ARG_MAX die)
  [[ "$output" != *"Argument list too long"* ]]
  f=$(ls "$SPOOL"/requests/*.json)
  [ "$(jq -r .content_b64 "$f" | base64 -d | wc -c)" -eq 122880 ]
}

@test "rigctl: RIGCTL_TIMEOUT is validated+normalized BEFORE submit (bogus -> usage 2 pre-submit; 09 not an octal error)" {
  # Malformed value -> rejected before ANY submit (RIGCTL_TIMEOUT is consumed only after send, so an
  # unvalidated non-integer would otherwise crash the client POST-submit with no claimed/never-claimed hint).
  RIGCTL_TIMEOUT=bogus run "$RIGCTL" list
  [ "$status" -eq 2 ]
  [[ "$output" == *"RIGCTL_TIMEOUT must be a non-negative integer"* ]]
  [ -z "$(ls "$SPOOL"/requests/*.json 2>/dev/null || true)" ]     # nothing was enqueued
  # A leading-zero value is decimal-normalized (09 would be an octal error inside $(( )) if unvalidated);
  # a normal round trip then succeeds.
  RIGCTL_TIMEOUT=09 "$RIGCTL" list >"$BATS_TEST_TMPDIR/o" 2>"$BATS_TEST_TMPDIR/e" &
  local rpid=$! reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok"}' "$reqid" >"$SPOOL/results/$reqid.json"
  wait "$rpid"; [ "$?" -eq 0 ]                                     # 09 accepted (=> 9), not an octal crash
}

@test "rigctl: an ack LOST after send (peer closes with no OK) is INDETERMINATE, not a definite failure" {
  # A silent accepter reads the request (so it MAY be enqueued) then closes WITHOUT replying OK.
  local sock="$BATS_TEST_TMPDIR/silent.sock"
  cat >"$BATS_TEST_TMPDIR/silent.py" <<'EOF'
import socket, os, sys
p = sys.argv[1]
try: os.unlink(p)
except OSError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(p); srv.listen(4)
conn, _ = srv.accept()
conn.recv(65536)          # consume the request, then drop the connection with NO acknowledgment
conn.close()
EOF
  python3 "$BATS_TEST_TMPDIR/silent.py" "$sock" &
  local spid=$!
  for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done
  DR_VPS_SUBMIT_SOCK="$sock" RIGCTL_TIMEOUT=2 run "$RIGCTL" exec vm1 'echo hi'
  kill "$spid" 2>/dev/null || true
  [ "$status" -eq 2 ]
  [[ "$output" == *"submit acknowledgment lost after sending"* ]]  # not "could not reach" (which = never sent)
  [[ "$output" == *"INDETERMINATE"* ]]
  [[ "$output" == *"do NOT blindly re-run"* ]]                     # reconcile-first guidance for the agent
}

@test "rigctl console-dump: preserves multibyte UTF-8 while dropping NUL/ESC/C1 without corruption (exit 0)" {
  # A П р ESC[31m NUL C1(U+009B, = 0xC2 0x9B) B \n. The old raw-byte delete ate 0x80-0x9F, corrupting the
  # Cyrillic continuation bytes; the codepoint filter must keep the multibyte text and strip only controls.
  printf 'A\xd0\x9f\xd1\x80\x1b[31m\x00\xc2\x9bB\n' >"$BATS_TEST_TMPDIR/raw"
  local b64; b64=$(base64 -w0 <"$BATS_TEST_TMPDIR/raw")
  RIGCTL_TIMEOUT=10 "$RIGCTL" console-dump vm1 >"$BATS_TEST_TMPDIR/out" 2>/dev/null &
  local rpid=$! reqid=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  printf '{"reqid":"%s","status":"ok","exit_code":0,"content_b64":"%s"}' "$reqid" "$b64" >"$SPOOL/results/$reqid.json"
  wait "$rpid"; [ "$?" -eq 0 ]
  # Exact expected bytes: A + "Пр" (d0 9f d1 80, INTACT) + "[31m" (ESC gone) + "B" (NUL + C1 gone) + newline.
  # A byte-exact cmp proves the multibyte survived AND every control was stripped -- stronger + locale-proof
  # vs grep -P, whose \xNN matches a codepoint (2 bytes) not a raw byte under a UTF-8 locale.
  printf 'A\xd0\x9f\xd1\x80[31mB\n' >"$BATS_TEST_TMPDIR/expected"
  cmp -s "$BATS_TEST_TMPDIR/expected" "$BATS_TEST_TMPDIR/out"
}

@test "rigctl (S1b): create --class service submits .class=service; --class bogus -> usage 2 (client-side, not submitted)" {
  RIGCTL_TIMEOUT=1 run "$RIGCTL" create n fedora44 --class service
  [ "$status" -eq 17 ]                                       # submitted; no watcher -> result-timeout
  f=$(ls "$SPOOL"/requests/*.json)
  jq -e '.op=="create" and .name=="n" and .distro=="fedora44" and .class=="service"' "$f"
  run "$RIGCTL" create n2 fedora44 --class bogus; [ "$status" -eq 2 ]   # bad class rejected client-side
  # --class also composes with positional ttl/mem/cpus
  RIGCTL_TIMEOUT=1 run "$RIGCTL" create n3 fedora44 24 --class service
  [ "$status" -eq 17 ]
}

# ---- S4 idempotency keys: the client threads --idem on mutators, refuses it on reads ------------

@test "rigctl: S4 -- 'destroy <vm> --idem <key>' threads idem into the submitted request" {
  RIGCTL_TIMEOUT=10 "$RIGCTL" destroy vm1 --idem deploy-7 >/dev/null 2>&1 &
  rpid=$!
  reqid=""; f=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  [ "$(jq -r .idem "$f")" = deploy-7 ]
  [ "$(jq -r .op "$f")" = destroy ]
  [ "$(jq -r .vm "$f")" = vm1 ]
  printf '{"reqid":"%s","status":"ok","exit_code":0}' "$reqid" >"$SPOOL/results/$reqid.json"
  wait "$rpid" || true
}

@test "rigctl: S4 -- 'snap-rm <snap> --idem <key>' threads idem too (separate parse path)" {
  RIGCTL_TIMEOUT=10 "$RIGCTL" snap-rm drvps-snap-v1-1-abc --idem rm-1 >/dev/null 2>&1 &
  rpid=$!
  reqid=""; f=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  [ "$(jq -r .idem "$f")" = rm-1 ]
  [ "$(jq -r .op "$f")" = snap-rm ]
  printf '{"reqid":"%s","status":"ok","exit_code":0}' "$reqid" >"$SPOOL/results/$reqid.json"
  wait "$rpid" || true
}

@test "rigctl: S4 -- '--idem' on a READ verb (status) dies client-side (usage), nothing submitted" {
  run "$RIGCTL" status vm1 --idem k1
  [ "$status" -eq 2 ]
  [ -z "$(ls -A "$SPOOL/requests" 2>/dev/null)" ]
}

@test "rigctl: S4 -- a hostile idem key (charset / length) dies client-side, nothing submitted" {
  run "$RIGCTL" destroy vm1 --idem 'k/../x'
  [ "$status" -eq 2 ]
  run "$RIGCTL" destroy vm1 --idem "$(printf 'k%.0s' {1..65})"
  [ "$status" -eq 2 ]
  [ -z "$(ls -A "$SPOOL/requests" 2>/dev/null)" ]
}

@test "rigctl: S4 -- an EMPTY --idem '' dies client-side on EVERY mutator (never silently unprotected)" {
  # advisor MAJOR: an empty key must NOT be silently dropped (submitting unprotected while the caller
  # believes it is protected); RIGCTL_TIMEOUT=1 keeps a regression from hanging the suite.
  for args in "destroy vm1" "recreate vm1" "create n1 fedora44" "snap-rm drvps-snap-v1-1-abc" "snapshot vm1"; do
    run env RIGCTL_TIMEOUT=1 "$RIGCTL" $args --idem ''
    [ "$status" -eq 2 ]
    [[ "$output" == *idem* ]]
  done
  run env RIGCTL_TIMEOUT=1 "$RIGCTL" use n1 --from-snap drvps-snap-v1-1-abc --idem ''
  [ "$status" -eq 2 ]; [[ "$output" == *idem* ]]
  [ -z "$(ls -A "$SPOOL/requests" 2>/dev/null)" ]                  # nothing was submitted
}

@test "rigctl: S4 -- '--idem' threads on create / snapshot / use too" {
  for spec in "create n1 fedora44 --idem c-1|create|c-1" \
              "snapshot vm1 --idem s-1|snapshot|s-1" \
              "use n1 --from-snap drvps-snap-v1-1-abc --idem u-1|use|u-1"; do
    cmd="${spec%%|*}"; rest="${spec#*|}"; wantop="${rest%%|*}"; wantkey="${rest#*|}"
    RIGCTL_TIMEOUT=10 "$RIGCTL" $cmd >/dev/null 2>&1 &
    rpid=$!
    reqid=""; f=""
    for _ in $(seq 1 50); do
      f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
      [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
      sleep 0.1
    done
    [ -n "$reqid" ]
    [ "$(jq -r .op "$f")" = "$wantop" ]
    [ "$(jq -r .idem "$f")" = "$wantkey" ]
    printf '{"reqid":"%s","status":"ok","exit_code":0}' "$reqid" >"$SPOOL/results/$reqid.json"
    wait "$rpid" || true
    rm -f "$f"                                                     # consume for the next iteration
  done
}

@test "rigctl: a result that exists but is UNREADABLE (setfacl anomaly) -> nonzero, never a false exit 0" {
  [ "$(id -u)" -ne 0 ] || skip "root bypasses mode bits -- cannot simulate an unreadable file"
  RIGCTL_TIMEOUT=10 "$RIGCTL" list >"$BATS_TEST_TMPDIR/out" 2>"$BATS_TEST_TMPDIR/err" &
  rpid=$!
  reqid=""; f=""
  for _ in $(seq 1 50); do
    f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) || true
    [ -n "$f" ] && { reqid=$(jq -r .reqid "$f"); break; }
    sleep 0.1
  done
  [ -n "$reqid" ]
  # place it ALREADY-unreadable, atomically (same-fs rename) so rigctl can't win a chmod race
  printf '{"reqid":"%s","status":"ok","exit_code":0}' "$reqid" >"$BATS_TEST_TMPDIR/r.tmp"
  chmod 000 "$BATS_TEST_TMPDIR/r.tmp"
  mv "$BATS_TEST_TMPDIR/r.tmp" "$SPOOL/results/$reqid.json"
  rc=0; wait "$rpid" || rc=$?                               # capture rigctl's exit WITHOUT bats failing on nonzero
  chmod 644 "$SPOOL/results/$reqid.json"                    # restore so teardown can clean up
  [ "$rc" -ne 0 ]                                           # NOT a false success
  grep -q 'UNREADABLE' "$BATS_TEST_TMPDIR/err"
}

@test "rigctl use: S6 -- '--restore-secrets' sets restore_secrets:true; a plain use NEVER carries the field" {
  sid="drvps-snap-v1-1-abc"
  ( RIGCTL_TIMEOUT=6 "$RIGCTL" use svcg-x --from-snap "$sid" --class service --restore-secrets >/dev/null 2>&1 ) &
  cli=$!
  f=""
  for _ in $(seq 1 50); do f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) && [ -n "$f" ] && break; sleep 0.1; done
  kill "$cli" 2>/dev/null || true
  [ -n "$f" ]
  [ "$(jq -r .op "$f")" = use ]
  [ "$(jq -r .restore_secrets "$f")" = true ]                # ack flag -> JSON true (decider shapes on it)
  rm -f "$f"
  ( RIGCTL_TIMEOUT=6 "$RIGCTL" use svcg-y --from-snap "$sid" >/dev/null 2>&1 ) &
  cli=$!
  f=""
  for _ in $(seq 1 50); do f=$(ls "$SPOOL"/requests/*.json 2>/dev/null | head -1) && [ -n "$f" ] && break; sleep 0.1; done
  kill "$cli" 2>/dev/null || true
  [ -n "$f" ]
  [ "$(jq -r 'has("restore_secrets")' "$f")" = false ]       # regression: absent unless explicitly acked
}
