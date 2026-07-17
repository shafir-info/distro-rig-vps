#!/usr/bin/env python3
"""write_result trim contract (src/drvps_rigctl.py): every published result is VALID JSON, even at
the last resort. The old fallback byte-cut raw JSON, which can split mid-string/mid-escape and hand
every reader a broken envelope -- reachable when nothing in the stdout/stderr/reason trim set can
give bytes back, e.g. an over-cap content_b64 under a lowered DR_VPS_RESULT_MAX_BYTES.
Also verifies S5 result privacy end-to-end on an ACL-capable fs: the exact per-owner POSIX ACL
entry set on result + claimed marker, a planted-default-ACL positive control for --set vs -m, and
both fail-closed setfacl flavors (loud, non-raising, tombstone verdict preserved). Set
DRVPS_REQUIRE_ACL=1 to turn the S5 SKIP paths into failures where ACLs are expected (CI)."""
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

# ---- S5 per-owner ACL privacy verification: a PRIVATE result gets 0600 drvps-owned + a
# named-owner POSIX ACL keyed to the SO_PEERCRED uid, so a co-drvpsctl uid cannot read another owner's
# result. Runs on a real ACL-capable fs (e.g. the drvps host); SKIPS loudly where ACLs are unavailable
# (a documented blind spot -- never a silent pass). OWNER is a uid distinct from the file owner (the
# test runner), which proves the NAMED entry is added, not merely the base owner bits.
import subprocess, stat as _stat
OWNER = 4001


def _acl_supported(dirpath):
    probe = os.path.join(dirpath, ".acl-probe")
    open(probe, "w").close()
    try:
        r = subprocess.run(["setfacl", "-m", "u:%d:r" % OWNER, probe],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # read back like the launcher's and the doctor's probes: some filesystems accept the
        # setfacl yet DROP the entry -- rc alone would then mis-enter the S5 branch and blame
        # write_result for an fs property
        return r.returncode == 0 and ("user:%d:r--" % OWNER) in _getfacl_entries(probe)
    except OSError:
        return False
    finally:
        try:
            os.unlink(probe)
        except OSError:
            pass


def _getfacl_entries(path):
    # -n (numeric): the named entry must read user:4001:r-- even on a host where uid 4001 maps to
    # a name -- without it every named-entry assertion false-fails there.
    out = subprocess.run(["getfacl", "-pcn", path], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout.decode()
    ents = set()
    for line in out.splitlines():
        line = line.split("#", 1)[0].strip()   # drop the #effective:... comment + header lines
        if line:
            ents.add(line)
    return ents


RDIR = os.path.join(TD, "results")


def assert_private_acl(path, owner, label):
    """The exact S5 entry set _apply_owner_acl --set must yield -- applied to the RESULT and the
    CLAIMED MARKER alike (both run the same code path today; one helper keeps a future divergence
    from being half-tested). NB: with a POSIX ACL mask present, st_mode's GROUP bits display the
    MASK (r--), so the file reads 0640 -- the group denial is proven by the ACL entry, not the
    (mask-overloaded) mode bits; only the WORLD bits are meaningful on st_mode here."""
    ents = _getfacl_entries(path)
    ok((_stat.S_IMODE(os.stat(path).st_mode) & 0o007) == 0, label + ": no world (other) access on mode bits")
    ok("user::rw-" in ents, label + ": file-owner base entry rw-")
    ok(("user:%d:r--" % owner) in ents, label + ": named-owner ACL grants r-- to uid %d" % owner)
    ok("group::---" in ents, label + ": group denied (no co-tenant group read)")
    ok("other::---" in ents, label + ": other denied")
    ok("mask::r--" in ents, label + ": mask pinned r-- (named-owner entry stays effective r)")
    stray = [e for e in ents
             if (e.startswith("user:") and not e.startswith("user::") and e != ("user:%d:r--" % owner))
             or (e.startswith("group:") and not e.startswith("group::"))]
    ok(not stray, label + ": no stray named user/group ACL survives --set: %r" % stray)


if shutil.which("setfacl") and shutil.which("getfacl") and _acl_supported(RDIR):
    W.write_result(TD, "acl1", {"reqid": "acl1", "status": "ok", "exit_code": 0, "stdout": "x"},
                   1024, owner=OWNER, private=True)
    assert_private_acl(os.path.join(RDIR, "acl1.json"), OWNER, "private result")

    # mark_claimed (the at-most-once tombstone) carries the SAME privacy -- and its durable-tombstone
    # verdict is load-bearing (callers refuse to execute on False), so assert the return too.
    rv = W.mark_claimed(TD, "acl1", op="exec", vm="vm1", owner=OWNER, private=True)
    ok(rv is True, "claimed marker durably established (True) in the S5 happy path")
    assert_private_acl(os.path.join(RDIR, "acl1.claimed"), OWNER, "claimed marker")

    # POSITIVE CONTROL for `--set` vs `-m` (the regression _apply_owner_acl's comment warns about):
    # plant an inheritable co-tenant default ACL on a results dir; a fresh private result there must
    # NOT carry the inherited entry. Without this plant the stray-entry assertion above can never
    # fail -- a file created in a clean dir has no named entries, where `-m` of the full 5-entry
    # list and `--set` are byte-identical -- so the detector had no proof it fires.
    TD2 = tempfile.mkdtemp(prefix="drvps-wr-inh.")
    os.makedirs(os.path.join(TD2, "results"))
    r = subprocess.run(["setfacl", "-d", "-m", "u:4002:r", os.path.join(TD2, "results")],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    inherited = False
    if r.returncode == 0:
        # the control's premise must be OBSERVABLE: prove a file created here really inherits the
        # planted co-tenant entry before asserting that write_result/mark_claimed remove it
        pf = os.path.join(TD2, "results", ".inherit-probe")
        open(pf, "w").close()
        inherited = ("user:4002:r--" in _getfacl_entries(pf))
        os.unlink(pf)
    if inherited:
        W.write_result(TD2, "aclinh", {"reqid": "aclinh", "status": "ok", "exit_code": 0, "stdout": "z"},
                       1024, owner=OWNER, private=True)
        assert_private_acl(os.path.join(TD2, "results", "aclinh.json"), OWNER, "default-ACL-inheriting result")
        # the marker takes the same inheriting-dir path; covering it here keeps a future
        # per-callsite divergence of the ACL application from being half-tested
        rvi = W.mark_claimed(TD2, "aclinh", op="exec", vm="vm1", owner=OWNER, private=True)
        ok(rvi is True, "claimed marker durably established (True) in the inheriting dir")
        assert_private_acl(os.path.join(TD2, "results", "aclinh.claimed"), OWNER, "default-ACL-inheriting claimed marker")
    elif os.environ.get("DRVPS_REQUIRE_ACL") == "1":
        ok(False, "DRVPS_REQUIRE_ACL=1 but no propagating default ACL here -- --set positive control went untested")
    else:
        print("SKIP: cannot plant a propagating default ACL here -- the --set-vs--m positive control is skipped")
    shutil.rmtree(TD2, ignore_errors=True)

    # FAIL-CLOSED: if setfacl fails, the file stays 0600 (confidentiality intact -- a cross-uid agent
    # just can't read it), write_result must NOT raise on a Restart=always daemon, mark_claimed must
    # still return True (an ACL failure is NOT a tombstone failure -- that distinction guards the
    # at-most-once contract), and the failure must be LOUD: the stderr line is the operator's only
    # signal before agents start timing out on unreadable results, so ASSERT it instead of muting it.
    # Exercise BOTH real flavors: setfacl exiting nonzero (non-ACL fs -> CalledProcessError via
    # check=True) and an unrunnable binary (OSError) -- today both land in one `except Exception`,
    # but a future narrowing of that handler must not silently lose either arm.
    import contextlib, io
    _real_run = subprocess.run

    def _mkboom(flavor):
        def _boom(*a, **k):
            if a and a[0] and a[0][0] == "setfacl":
                if flavor == "nonzero-exit":
                    # honor the check= contract: a bare nonzero return stays silent unless the
                    # caller asked check=True -- so dropping check=True in the product turns the
                    # loud-stderr assertions below red instead of re-silencing real failures
                    if k.get("check"):
                        raise subprocess.CalledProcessError(1, a[0])
                    return subprocess.CompletedProcess(a[0], 1)
                raise OSError("simulated missing setfacl")
            return _real_run(*a, **k)
        return _boom

    for flavor, rid in (("nonzero-exit", "acl2"), ("unrunnable", "acl3")):
        W.subprocess.run = _mkboom(flavor)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):   # capture the loud line; asserted below
                W.write_result(TD, rid, {"reqid": rid, "status": "ok", "exit_code": 0, "stdout": "y"},
                               1024, owner=OWNER, private=True)
                rv = W.mark_claimed(TD, rid, op="exec", vm="vm1", owner=OWNER, private=True)
        finally:
            W.subprocess.run = _real_run
        cap = buf.getvalue()
        p2 = os.path.join(RDIR, rid + ".json")
        ok(_stat.S_IMODE(os.stat(p2).st_mode) == 0o600, "setfacl %s: result stays 0600 (confidentiality intact)" % flavor)
        ok(("user:%d:r--" % OWNER) not in _getfacl_entries(p2), "setfacl %s: no named-owner ACL on the result" % flavor)
        cp2 = os.path.join(RDIR, rid + ".claimed")
        ok(_stat.S_IMODE(os.stat(cp2).st_mode) == 0o600, "setfacl %s: claimed marker stays 0600" % flavor)
        ok(("user:%d:r--" % OWNER) not in _getfacl_entries(cp2), "setfacl %s: no named-owner ACL on the marker" % flavor)
        ok(rv is True, "setfacl %s: ACL failure is NOT a tombstone failure (mark_claimed returns True)" % flavor)
        ok("setfacl" in cap and cap.count("FAILED") >= 2,
           "setfacl %s: loud stderr for BOTH publishes (got %r)" % (flavor, cap[:120]))
elif os.environ.get("DRVPS_REQUIRE_ACL") == "1":
    ok(False, "DRVPS_REQUIRE_ACL=1 but ACLs are unavailable here -- the whole S5 property went untested")
else:
    print("SKIP: ACLs unavailable here (setfacl/getfacl missing or non-ACL fs) -- S5 ACL assertions skipped")

shutil.rmtree(TD, ignore_errors=True)
print("-------------------------------------------")
print("drvps write_result: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
