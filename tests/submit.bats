#!/usr/bin/env bats
# Stage 4b (Phase 2) -- drvps-rigsubmit, the ONLY agent ingress. Runs as drvps behind a systemd
# Accept=yes socket (connected socket = stdin/stdout). It writes the request into the drvps-ONLY
# requests/ dir so the agent NEVER has filesystem write to the spool (no poison-dir DoS possible).
# We drive it over a REAL AF_UNIX socketpair (not a plain pipe) because the accepter reads the client's
# uid UNFORGEABLY via SO_PEERCRED off the connected socket and STAMPS it as owner_uid -- a plain pipe
# has no peer credentials, so the byte-pipe shortcut no longer exercises the true ingress. The full
# rigctl->accept-loop round trip is additionally covered in rigctl.bats.

load helpers

setup() {
  export SPOOL="$BATS_TEST_TMPDIR/spool"
  mkdir -p "$SPOOL/requests" "$SPOOL/results"
  export DR_VPS_SPOOL_DIR="$SPOOL"
  SUB="${DR_VPS_SRC}/drvps_rigsubmit.py"          # the accepter logic (bin/drvps-rigsubmit is its env-sourcing launcher)
  # One-shot socketpair driver: hands the accepter one END of a real AF_UNIX stream as stdin/stdout
  # (so SO_PEERCRED resolves to THIS process's uid), sends the request bytes, and echoes the reply
  # line. This is the faithful analogue of the systemd Accept=yes connected socket.
  SOCKDRV="$BATS_TEST_TMPDIR/sockdrv.py"
  cat >"$SOCKDRV" <<'EOF'
import socket, subprocess, sys
cmd = sys.argv[1:]                                   # the accepter command to run (python3 SUB, or the launcher)
data = sys.stdin.buffer.read()                       # request bytes (from the bats file redirect)
parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
p = subprocess.Popen(cmd, stdin=child.fileno(), stdout=child.fileno())
child.close()                                        # the child process holds its own dup
parent.sendall(data)
parent.shutdown(socket.SHUT_WR)                       # EOF so the accepter's bounded read returns
chunks = []
while True:
    b = parent.recv(65536)
    if not b:
        break
    chunks.append(b)
p.wait()
sys.stdout.write(b"".join(chunks).decode("utf-8", "replace"))
EOF
}

_submit() {                                            # $1 = request bytes, delivered over a real socketpair
  printf '%s' "$1" >"$BATS_TEST_TMPDIR/_req"
  run python3 "$SOCKDRV" python3 "$SUB" <"$BATS_TEST_TMPDIR/_req"
}

@test "drvps_common.write_all: loops over SHORT writes so a request/result/push temp is never truncated" {
  run python3 - "$DR_VPS_SRC" <<'PY'
import sys, os, threading
sys.path.insert(0, sys.argv[1])
import drvps_common
real = os.write
os.write = lambda fd, b: real(fd, bytes(b[:3]))   # simulate a filesystem that writes <=3 bytes/call
r, w = os.pipe(); buf = bytearray()
def drain():
    while True:
        c = os.read(r, 4096)
        if not c: break
        buf.extend(c)
t = threading.Thread(target=drain); t.start()
data = b"Z" * 100
n = drvps_common.write_all(w, data)
os.close(w); t.join()
assert n == 100, n
assert bytes(buf) == data, len(buf)
print("WRITEALL-OK")
PY
  [ "$status" -eq 0 ]
  [[ "$output" == *WRITEALL-OK* ]]
}

@test "submit: a valid request is written into requests/ (0600, reqid+op preserved, owner_uid stamped) + OK <reqid>" {
  _submit '{"reqid":"rok1","op":"list"}'
  [ "$status" -eq 0 ]
  [ "$output" = "OK rok1" ]
  [ -f "$SPOOL/requests/rok1.json" ]
  # the accepter re-serializes the request with the kernel-verified owner_uid stamped on; the client's
  # own reqid/op are preserved verbatim and owner_uid == the connecting (this) process's uid.
  jq -e --argjson u "$(id -u)" '.reqid=="rok1" and .op=="list" and (.owner_uid==$u)' "$SPOOL/requests/rok1.json"
  [ "$(stat -c '%a' "$SPOOL/requests/rok1.json")" = "600" ]
  [ -z "$(ls -A "$SPOOL"/requests/.*.tmp 2>/dev/null)" ]   # no leftover temp
}

@test "submit: SO_PEERCRED uid is unpacked UNSIGNED (a client uid >= 2^31 must NOT stamp negative)" {
  # uid_t is unsigned 32-bit; a signed unpack would turn a high uid into a negative owner_uid,
  # which the watcher rejects -> that client is locked out of EVERY verb. Drive the REAL _peer_uid with a
  # synthetic SO_PEERCRED blob carrying a high uid and assert it comes back as the correct positive value.
  run python3 - "$DR_VPS_SRC" <<'PY'
import sys, os, struct, socket
sys.path.insert(0, sys.argv[1])
import drvps_rigsubmit as S
HIGH = 3000000000                                   # > 2^31, a real-world high uid
class FakeSock:
    def getsockopt(self, lvl, opt, size): return struct.pack("iII", 4321, HIGH, HIGH)
    def close(self): pass
_orig = socket.socket
socket.socket = lambda *a, **k: FakeSock()          # _peer_uid dup(0)s then wraps it -> our fake
try:
    uid = S._peer_uid()
finally:
    socket.socket = _orig
assert uid == HIGH, "got %r (signed unpack regressed?)" % (uid,)
print("PEERCRED-UNSIGNED-OK")
PY
  [ "$status" -eq 0 ]
  [[ "$output" == *PEERCRED-UNSIGNED-OK* ]]
}

@test "submit: a CLIENT-supplied owner_uid is OVERWRITTEN by the SO_PEERCRED uid (no forgery)" {
  # A hostile client sets owner_uid to someone else's uid (0/root here) to act on their snapshots.
  # The accepter MUST discard the client value and stamp the kernel-verified peer uid instead.
  _submit '{"reqid":"rforge","op":"list","owner_uid":0}'
  [ "$status" -eq 0 ]; [ "$output" = "OK rforge" ]
  jq -e --argjson u "$(id -u)" '.owner_uid==$u' "$SPOOL/requests/rforge.json"   # stamped, not the forged 0
}

@test "submit: a bad reqid (charset) is refused, nothing written" {
  _submit '{"reqid":"bad id!","op":"list"}'
  [ "$status" -eq 0 ]; [[ "$output" == ERR* ]]
  [ -z "$(ls -A "$SPOOL/requests")" ]
}

@test "submit: a missing/non-string reqid is refused" {
  _submit '{"op":"list"}';            [[ "$output" == "ERR bad reqid" ]]
  _submit '{"reqid":42,"op":"list"}'; [[ "$output" == "ERR bad reqid" ]]
}

@test "submit: an oversize payload is refused (req_max), nothing written" {
  local big; big=$(printf 'A%.0s' {1..100})
  DR_VPS_REQ_MAX_BYTES=32 _submit "{\"reqid\":\"rbig\",\"x\":\"$big\"}"
  [[ "$output" == "ERR request too large" ]]
  [ -z "$(ls -A "$SPOOL/requests")" ]
}

@test "submit: empty / non-JSON / non-object payloads are refused" {
  _submit '';          [[ "$output" == "ERR empty request" ]]
  _submit 'not json';  [[ "$output" == "ERR not valid JSON" ]]
  _submit '[1,2,3]';   [[ "$output" == "ERR request not an object" ]]
}

@test "submit: at the flood cap the ingress refuses BEFORE writing (early inode bound)" {
  printf '{}' >"$SPOOL/requests/a.json"; printf '{}' >"$SPOOL/requests/b.json"
  DR_VPS_MAX_PENDING=2 _submit '{"reqid":"rcap","op":"list"}'
  [[ "$output" == "ERR spool over capacity" ]]
  [ ! -e "$SPOOL/requests/rcap.json" ]
}

@test "submit: a concurrent in-flight SAME reqid is refused (temp O_EXCL)" {
  # simulate an in-flight submit of rdup by pre-planting its temp; the O_EXCL create must refuse.
  printf '{}' >"$SPOOL/requests/.rdup.tmp"
  _submit '{"reqid":"rdup","op":"list"}'
  [[ "$output" == ERR*duplicate* ]]
  [ ! -e "$SPOOL/requests/rdup.json" ]
}

@test "submit: an already-PENDING reqid is NOT clobbered (no-clobber renameat2) -- co-agent can't overwrite" {
  # A second submit reusing a still-pending reqid must be REFUSED, not silently replace the first
  # (a malicious co-agent must not overwrite another's pending request by reusing its reqid).
  _submit '{"reqid":"rpin","op":"list"}';               [ "$output" = "OK rpin" ]
  _submit '{"reqid":"rpin","op":"exec","vm":"v","cmd":"id"}'
  [[ "$output" == ERR*duplicate* ]]                                        # refused, not "OK"
  jq -e '.reqid=="rpin" and .op=="list"' "$SPOOL/requests/rpin.json"       # the FIRST request is preserved (not the exec)
}

@test "submit launcher: bin/drvps-rigsubmit sources env + execs the accepter (stdin/stdout preserved)" {
  # the production entrypoint is the bash launcher (mirrors drvps-rigctl): it sources the installed
  # env so the accepter uses the SAME DR_VPS_SPOOL_DIR as the watcher, then execs the python.
  local LAUNCH="${DR_VPS_SRC}/../bin/drvps-rigsubmit"
  printf '%s' '{"reqid":"rlaunch","op":"list"}' >"$BATS_TEST_TMPDIR/_req"
  run python3 "$SOCKDRV" "$LAUNCH" <"$BATS_TEST_TMPDIR/_req"   # over a real socketpair (peercred needs a socket)
  [ "$status" -eq 0 ]; [ "$output" = "OK rlaunch" ]
  [ -f "$SPOOL/requests/rlaunch.json" ]                  # DR_VPS_SPOOL_DIR from the test env honored
}

@test "submit: a SYMLINKED requests dir is refused (O_NOFOLLOW), never written through" {
  rm -rf "$SPOOL/requests"; mkdir "$SPOOL/elsewhere"
  ln -s "$SPOOL/elsewhere" "$SPOOL/requests"
  _submit '{"reqid":"rsym","op":"list"}'
  [[ "$output" == "ERR spool unavailable" ]]
  [ -z "$(ls -A "$SPOOL/elsewhere")" ]                    # nothing written through the symlink
}
