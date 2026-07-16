#!/usr/bin/env python3
"""The shared spool caps (src/drvps_common.py) + the accepter's READ_TIMEOUT parse DEFENSIVELY.
Both daemons are Restart=always: a malformed (hand-edited) env override that raises at import is a
CRASH LOOP, so it must fall back to the default instead. A zero/negative override must clamp to a
positive floor: a non-positive REQ_MAX turns the accepter's read(cap+1) into an UNBOUNDED read and
defeats the watcher's claim cap; a non-positive MAX_PENDING turns the flood cap into reject-all;
a non-positive READ_TIMEOUT makes settimeout() non-blocking (0) or raise (negative). No I/O."""
import os, sys, importlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import drvps_common as C  # noqa

npass = [0]; nfail = [0]
def ok(c, m):
    if c: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", m)

def with_env(name, val, fn):
    old = os.environ.get(name)
    try:
        if val is None: os.environ.pop(name, None)
        else: os.environ[name] = val
        return fn()
    finally:
        if old is None: os.environ.pop(name, None)
        else: os.environ[name] = old

# ---- defaults (no env)
ok(with_env("DR_VPS_REQ_MAX_BYTES", None, C.req_max_bytes) == 1 << 20, "req_max default 1MiB")
ok(with_env("DR_VPS_MAX_PENDING", None, C.max_pending) == 256, "max_pending default 256")

# ---- legitimate small operator/test overrides survive un-clamped (suites set 32 / 1)
ok(with_env("DR_VPS_REQ_MAX_BYTES", "32", C.req_max_bytes) == 32, "small req_max override kept")
ok(with_env("DR_VPS_MAX_PENDING", "1", C.max_pending) == 1, "small max_pending override kept")

# ---- malformed -> DEFAULT, never a raise (the crash-loop guard)
for bad in ("banana", "", "1e6", "0x10", "12 MiB"):
    try:
        ok(with_env("DR_VPS_REQ_MAX_BYTES", bad, C.req_max_bytes) == 1 << 20,
           "malformed req_max %r -> default" % bad)
        ok(with_env("DR_VPS_MAX_PENDING", bad, C.max_pending) == 256,
           "malformed max_pending %r -> default" % bad)
    except ValueError:
        ok(False, "malformed %r RAISED (crash-loop for a Restart=always daemon)" % bad)

# ---- zero/negative -> clamped to the positive floor (bounds stay meaningful)
ok(with_env("DR_VPS_REQ_MAX_BYTES", "0", C.req_max_bytes) == 1, "req_max 0 -> floor 1 (read stays bounded)")
ok(with_env("DR_VPS_REQ_MAX_BYTES", "-5", C.req_max_bytes) == 1, "req_max negative -> floor 1")
ok(with_env("DR_VPS_MAX_PENDING", "0", C.max_pending) == 1, "max_pending 0 -> floor 1 (not reject-all)")
ok(with_env("DR_VPS_MAX_PENDING", "-1", C.max_pending) == 1, "max_pending negative -> floor 1")

# ---- absurd ceilings clamp (a fat-fingered exponent cannot unbound the daemons)
ok(with_env("DR_VPS_REQ_MAX_BYTES", str(1 << 40), C.req_max_bytes) == 1 << 30, "req_max huge -> 1GiB ceiling")
ok(with_env("DR_VPS_MAX_PENDING", str(1 << 40), C.max_pending) == 1 << 20, "max_pending huge -> ceiling")

# ---- the accepter's READ_TIMEOUT (module-level float parse in drvps_rigsubmit.py): same contract.
#      Reload the module under each env so the import-time assignment is the code path under test.
import drvps_rigsubmit as R  # noqa

def rt(val):
    return with_env("DR_VPS_SUBMIT_READ_TIMEOUT", val,
                    lambda: (importlib.reload(R), R.READ_TIMEOUT)[1])

ok(rt(None) == 5.0, "read_timeout default 5s")
ok(rt("2.5") == 2.5, "valid read_timeout override kept")
try:
    ok(rt("banana") == 5.0, "malformed read_timeout -> default, no raise")
except ValueError:
    ok(False, "malformed read_timeout RAISED (accepter crash on every connection)")
ok(rt("0") > 0, "read_timeout 0 -> clamped positive (0 = non-blocking socket, EAGAIN storm)")
ok(rt("-3") > 0, "read_timeout negative -> clamped positive (settimeout raises on negative)")
ok(rt("nan") == 5.0, "non-finite read_timeout -> default")
ok(rt("inf") == 5.0, "non-finite read_timeout -> default (inf = slow-loris hold forever)")
ok(rt("999999") <= 3600, "huge read_timeout -> bounded ceiling")
importlib.reload(R)   # leave the module in the clean-env state

print("-------------------------------------------")
print("drvps-common caps: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
