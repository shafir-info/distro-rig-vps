#!/usr/bin/env python3
"""write_result trim contract (src/drvps_rigctl.py): every published result is VALID JSON, even at
the last resort. The old fallback byte-cut raw JSON, which can split mid-string/mid-escape and hand
every reader a broken envelope -- reachable when nothing in the stdout/stderr/reason trim set can
give bytes back, e.g. an over-cap content_b64 under a lowered DR_VPS_RESULT_MAX_BYTES."""
import json, os, shutil, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import drvps_rigctl as W  # noqa

npass = [0]; nfail = [0]
def ok(c, m):
    if c: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", m)

TD = tempfile.mkdtemp(prefix="drvps-wr-test.")
os.makedirs(os.path.join(TD, "results"))

def wr(reqid, obj, cap):
    W.write_result(TD, reqid, obj, cap, owner=None, private=False)
    with open(os.path.join(TD, "results", reqid + ".json"), "rb") as f:
        return f.read()

# ---- normal trim: a big stdout is cut back, envelope stays valid JSON with the truncated flag
raw = wr("r1", {"reqid": "r1", "status": "ok", "exit_code": 0, "stdout": "A" * 4096, "stderr": ""}, 1024)
ok(len(raw) <= 1024, "stdout trim respects the cap")
try:
    o = json.loads(raw)
    ok(o.get("truncated") is True and o.get("reqid") == "r1", "trimmed envelope keeps reqid + truncated flag")
except ValueError:
    ok(False, "trimmed envelope is INVALID JSON")

# ---- under the cap: untouched, no truncated flag
raw = wr("r2", {"reqid": "r2", "status": "ok", "exit_code": 0, "stdout": "hi"}, 1024)
o = json.loads(raw)
ok(o.get("stdout") == "hi" and "truncated" not in o, "under-cap result untouched")

# ---- LAST RESORT: nothing trimmable (the bulk sits in content_b64) -> must STILL be valid JSON
raw = wr("r3", {"reqid": "r3", "status": "ok", "exit_code": 0, "content_b64": "Q" * 4096}, 512)
ok(len(raw) <= 512, "last-resort respects the cap")
try:
    o = json.loads(raw)
    ok(o.get("truncated") is True and o.get("reqid") == "r3" and o.get("status") == "ok",
       "last-resort keeps reqid/status + truncated flag")
except ValueError:
    ok(False, "last-resort published INVALID JSON (raw byte cut mid-string)")

shutil.rmtree(TD, ignore_errors=True)
print("-------------------------------------------")
print("drvps write_result: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
