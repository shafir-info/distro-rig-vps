#!/usr/bin/env python3
"""Tests the v1 -> v2 egress store migration (bin/drvps-egress-migrate; arch doc Stage 3). Builds a v1-format
store (single-UID) + a provisioned v2 store, runs migrate() at the Python-API level, and checks: pending
(with the authoritative owner sidecar) -> v2 pending; decisions/root -> v2 published/decisions; decisions/
expiry -> v2 expiry; a decided pending is DROPPED; an in-flight (dirty) v1 review state ABORTS; idempotent
no-clobber re-run. ASCII only."""
import importlib.util
import json
import os
import sys
import tempfile
import shutil
import stat as _stat
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_egress_layout as L  # noqa
import drvps_egress_req as R      # noqa
_ldr = SourceFileLoader("migrate", os.path.join(HERE, "..", "bin", "drvps-egress-migrate"))
_spec = importlib.util.spec_from_loader("migrate", _ldr)
MG = importlib.util.module_from_spec(_spec)
_ldr.exec_module(MG)

npass = [0]
nfail = [0]


def ok(c, m):
    if c:
        npass[0] += 1
    else:
        nfail[0] += 1
        print("FAIL:", m)


UID, GID = os.getuid(), os.getgid()
IDS = {L.ROOT: (UID, GID), L.SVC: (UID, GID)}
TMP = tempfile.mkdtemp(prefix="egress-migrate-")
os.chmod(TMP, 0o755)


def build_v1(root):
    """Create a v1-format store tree under root/egress and return its base path."""
    base = os.path.join(root, "egress")
    for parts in (("pending",), ("owner",), ("review", "claimed"), ("review", "copy"),
                  ("review", "manifest"), ("review", "journal"), ("decisions", "root"), ("decisions", "expiry")):
        os.makedirs(os.path.join(base, *parts), 0o700, exist_ok=True)
    return base


def put(base, parts, name, obj, mode=0o600):
    path = os.path.join(base, *parts, name)
    with open(path, "w") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True))
    os.chmod(path, mode)


def v1_pending(base, reqid, uid, op, host, port, ts):
    put(base, ("pending",), reqid, {"ver": 1, "reqid": reqid, "op": op, "host": host, "port": port,
                                    "owner_uid": uid, "ts": ts})
    put(base, ("owner",), reqid, {"ver": 1, "reqid": reqid, "owner_uid": uid})


def v1_root_decision(base, reqid, state, reason, uid, op, host, port, ts=5):
    put(base, ("decisions", "root"), reqid, {"reqid": reqid, "state": state, "reason": reason, "ts": ts,
        "owner_uid": uid, "op": op, "host": host, "port": port, "batch_id": None,
        "before_hash": None, "after_hash": None}, mode=0o644)


def v1_expiry_decision(base, reqid, uid, op, host, port, ts=5):
    put(base, ("decisions", "expiry"), reqid, {"reqid": reqid, "state": "expired", "reason": "expired",
        "ts": ts, "owner_uid": uid, "op": op, "host": host, "port": port, "batch_id": None,
        "before_hash": None, "after_hash": None}, mode=0o644)   # v1 expiry decisions were SHARED_MODE 0644


def v2_path(root):
    return os.path.join(root, "distro-rig-vps-egress")     # migration BUILDS this (must be absent)


def paths(v1, v2):
    return MG.Paths(v1_base=v1, v2_anchor=v2, ids=IDS)


rid_a = "a" * 32
rid_b = "b" * 32
rid_c = "c" * 32
rid_d = "d" * 32

# ---- happy path: migration BUILDS v2 (staging+cutover); pending + root + expiry migrated; decided dropped ----
d = tempfile.mkdtemp(dir=TMP)
os.chmod(d, 0o755)
v1 = build_v1(d)
v1_pending(v1, rid_a, UID, "add-splice", "keep.example", 443, 100)          # ordinary pending -> migrate
v1_pending(v1, rid_b, UID, "add-splice", "decided.example", 443, 100)       # pending BUT also decided -> drop
v1_root_decision(v1, rid_b, "applied", "applied", UID, "add-splice", "decided.example", 443)
v1_root_decision(v1, rid_c, "rejected", "operator-declined", UID, "add-splice", "rej.example", 443)
v1_expiry_decision(v1, rid_d, UID, "add-splice", "exp.example", 443)
v2 = v2_path(d)
ok(not os.path.exists(v2), "v2 anchor is ABSENT before migration (migration builds it)")
out, code = MG.migrate(paths(v1, v2), check_quiesce=False)
ok(code == 0 and out["status"] == "ok", "migration succeeds (exit 0)")
ok(L.probe(v2, IDS) == L.OK, "migration built a fully-provisioned v2 store (marker present, probe OK)")
ok(out["migrated"]["pending"] == 1, "exactly one ordinary pending migrated (decided one dropped)")
ok(out["migrated"]["decisions"] == 2 and out["migrated"]["expiry"] == 1, "2 root decisions + 1 expiry migrated")
# v2 pending: rid_a present + readable (v2 schema, owner from sidecar); rid_b absent (decided)
pfd = R.open_ns(v2, *L.NS_PENDING)
try:
    req = R.read_request(pfd, rid_a, expect_uid=UID, expect_gid=GID)
    ok(req["ver"] == 2 and req["host"] == "keep.example" and req["owner_uid"] == UID, "migrated pending is valid v2")
    ok(not os.path.exists(os.path.join(v2, "pending", rid_b)), "decided pending was DROPPED (not migrated as active)")
finally:
    os.close(pfd)
# v2 published/decisions: rid_b applied, rid_c rejected -- valid v2 terminals, mode 0640
dfd = R.open_ns(v2, *L.NS_DECISIONS)
efd = R.open_ns(v2, *L.NS_EXPIRY)
try:
    db = R.read_published_decision(dfd, rid_b, expect_uid=UID, expect_gid=GID)
    ok(db and db["state"] == "applied" and db["batch_id"] is None, "root applied migrated as a bound-less v2 terminal")
    dc = R.read_published_decision(dfd, rid_c, expect_uid=UID, expect_gid=GID)
    ok(dc and dc["state"] == "rejected" and dc["reason"] == "operator-declined", "root rejected migrated with reason")
    ok(_stat.S_IMODE(os.lstat(os.path.join(v2, "published", "decisions", rid_b)).st_mode) == 0o640,
       "migrated published decision mode 0640")
    de = R.read_expiry_decision(efd, rid_d, expect_uid=UID, expect_gid=GID)
    ok(de and de["state"] == "expired", "expiry terminal migrated")
finally:
    os.close(dfd)
    os.close(efd)

# ---- idempotent: a second run is a no-op (v2 already present -- migration does not touch a live store) ----
out2, code2 = MG.migrate(paths(v1, v2), check_quiesce=False)
ok(code2 == 0 and "already" in out2.get("note", ""), "re-run is a no-op (v2 already present)")

# ---- v2 already present (greenfield) -> no-op, do not touch it ----
d2 = tempfile.mkdtemp(dir=TMP)
os.chmod(d2, 0o755)
v1b = build_v1(d2)
v1_pending(v1b, rid_a, UID, "add-splice", "x.example", 443, 1)
v2b = v2_path(d2)
L.provision(v2b, IDS)                                     # pre-existing v2 (as if greenfield-provisioned)
out3, code3 = MG.migrate(paths(v1b, v2b), check_quiesce=False)
ok(code3 == 0 and "already" in out3.get("note", ""), "present v2 -> no-op (migration will not clobber it)")
ok(not os.path.exists(os.path.join(v2b, "pending", rid_a)), "present-v2 no-op copied NOTHING")

# ---- DEGRADED v1 pair (same reqid in root+expiry) -> skip BOTH, count degraded, drop its pending ----
d5 = tempfile.mkdtemp(dir=TMP)
os.chmod(d5, 0o755)
v1e = build_v1(d5)
dg = "e" * 32
v1_pending(v1e, dg, UID, "add-splice", "deg.example", 443, 1)
v1_root_decision(v1e, dg, "applied", "applied", UID, "add-splice", "deg.example", 443)
v1_expiry_decision(v1e, dg, UID, "add-splice", "deg.example", 443)   # SAME reqid in both -> degraded
v2e = v2_path(d5)
out6, code6 = MG.migrate(paths(v1e, v2e), check_quiesce=False)
ok(code6 == 0 and out6["degraded"] == 1, "v1 two-terminal pair counted as degraded")
ok(not os.path.exists(os.path.join(v2e, "published", "decisions", dg))
   and not os.path.exists(os.path.join(v2e, "expiry", dg))
   and not os.path.exists(os.path.join(v2e, "pending", dg)),
   "degraded reqid: neither terminal nor pending migrated (no v2 degraded pair created)")

# ---- dirty v1 review state (in-flight batch) -> abort, BUILD NOTHING ----
d3 = tempfile.mkdtemp(dir=TMP)
os.chmod(d3, 0o755)
v1c = build_v1(d3)
v1_pending(v1c, rid_a, UID, "add-splice", "y.example", 443, 1)
with open(os.path.join(v1c, "review", "manifest", "0" * 16), "w") as fh:
    fh.write("{}")                                       # an in-flight v1 batch manifest -> not clean
v2c = v2_path(d3)
out4, code4 = MG.migrate(paths(v1c, v2c), check_quiesce=False)
ok(code4 == 3 and out4["reason"].startswith("v1-review-not-clean"), "dirty v1 review state -> abort")
ok(not os.path.exists(v2c), "aborted migration built NO v2 anchor (no partial/staging leak)")

# ---- malformed v1 terminal (reason:null -> invalid v2 contract): SKIP the terminal, PRESERVE its pending ----
d7 = tempfile.mkdtemp(dir=TMP)
os.chmod(d7, 0o755)
v1g = build_v1(d7)
bt = "f" * 32
v1_pending(v1g, bt, UID, "add-splice", "badterm.example", 443, 1)
put(v1g, ("decisions", "root"), bt, {"reqid": bt, "state": "applied", "reason": None, "ts": 5,
    "owner_uid": UID, "op": "add-splice", "host": "badterm.example", "port": 443, "batch_id": None,
    "before_hash": None, "after_hash": None}, mode=0o644)   # reason:null -> fails the v2 terminal contract
v2g = v2_path(d7)
out7, code7 = MG.migrate(paths(v1g, v2g), check_quiesce=False)
ok(code7 == 0 and out7["skipped"] >= 1, "an invalid-v2-terminal v1 record is counted as skipped")
ok(not os.path.exists(os.path.join(v2g, "published", "decisions", bt)), "the invalid v2 terminal is NOT written")
ok(os.path.exists(os.path.join(v2g, "pending", bt)),
   "its pending request is PRESERVED (a failed terminal copy must not drop the pending)")

# ---- hostile v1 source metadata: a wrong-MODE pending (0666) is rejected by the pinned 0600 -> skipped ----
d8 = tempfile.mkdtemp(dir=TMP)
os.chmod(d8, 0o755)
v1h = build_v1(d8)
wm = "1" * 32
v1_pending(v1h, wm, UID, "add-splice", "wrongmode.example", 443, 1)
os.chmod(os.path.join(v1h, "pending", wm), 0o666)          # tamper the source mode
gd = "2" * 32
v1_pending(v1h, gd, UID, "add-splice", "goodsrc.example", 443, 1)   # a clean neighbor still migrates
v2h = v2_path(d8)
out8, code8 = MG.migrate(paths(v1h, v2h), check_quiesce=False)
ok(code8 == 0 and out8["skipped"] >= 1, "a wrong-mode v1 source is skipped (pinned 0600), migration survives")
ok(not os.path.exists(os.path.join(v2h, "pending", wm)), "the tampered 0666 pending was NOT migrated")
ok(os.path.exists(os.path.join(v2h, "pending", gd)), "the clean neighbor still migrated")
# a wrong-mode OWNER sidecar (0666) -> the authoritative owner read fails -> its pending is skipped (dropped)
d9 = tempfile.mkdtemp(dir=TMP)
os.chmod(d9, 0o755)
v1i = build_v1(d9)
wo = "3" * 32
v1_pending(v1i, wo, UID, "add-splice", "wrongowner.example", 443, 1)
os.chmod(os.path.join(v1i, "owner", wo), 0o666)            # tamper the owner sidecar mode
v2i = v2_path(d9)
out9, code9 = MG.migrate(paths(v1i, v2i), check_quiesce=False)
ok(code9 == 0 and out9["skipped"] >= 1 and not os.path.exists(os.path.join(v2i, "pending", wo)),
   "a wrong-mode owner sidecar -> the pending is skipped (no attacker-chosen attribution)")

# ---- a partial pre-manifest claim in review/copy -> abort (in-flight review state), build nothing ----
d10 = tempfile.mkdtemp(dir=TMP)
os.chmod(d10, 0o755)
v1j = build_v1(d10)
v1_pending(v1j, rid_a, UID, "add-splice", "z.example", 443, 1)
with open(os.path.join(v1j, "review", "copy", "b" * 16 + "." + "a" * 32), "w") as fh:
    fh.write("{}")                                       # a frozen copy with no manifest -> partial claim
v2j = v2_path(d10)
out10, code10 = MG.migrate(paths(v1j, v2j), check_quiesce=False)
ok(code10 == 3 and out10["reason"].startswith("v1-review-not-clean"), "a non-empty review/copy -> abort")
ok(not os.path.exists(v2j), "aborted (review/copy) built NO v2 anchor")

# ---- a MISSING review namespace (a swapped/renamed generation) -> abort fail-closed, build nothing ----
d11 = tempfile.mkdtemp(dir=TMP)
os.chmod(d11, 0o755)
v1k = build_v1(d11)
v1_pending(v1k, rid_a, UID, "add-splice", "w.example", 443, 1)
os.rmdir(os.path.join(v1k, "review", "manifest"))       # a review namespace vanished (rename/swap)
v2k = v2_path(d11)
out11, code11 = MG.migrate(paths(v1k, v2k), check_quiesce=False)
ok(code11 == 3 and out11["reason"].startswith("v1-namespace-missing"), "a MISSING v1 namespace -> abort")
ok(not os.path.exists(v2k), "aborted (missing v1 namespace) built NO v2 anchor")

# ---- quiescence self-check (check_quiesce=True): a NOT-quiesced runtime aborts; an indeterminate systemctl
#      query also aborts fail-closed; only a positively-safe (inactive/failed) state proceeds ----
d12 = tempfile.mkdtemp(dir=TMP)
os.chmod(d12, 0o755)
v1l = build_v1(d12)
v1_pending(v1l, rid_a, UID, "add-splice", "q.example", 443, 1)
v2l = v2_path(d12)
_oq = MG._quiesced
MG._quiesced = lambda: False                            # simulate a still-active / indeterminate runtime
try:
    out12, code12 = MG.migrate(paths(v1l, v2l), check_quiesce=True)
finally:
    MG._quiesced = _oq
ok(code12 == 5 and out12["reason"] == "v1-not-quiesced", "a NOT-quiesced migration aborts (self-check, cannot bypass)")
ok(not os.path.exists(v2l), "not-quiesced abort built NO v2 anchor")

# _quiesced() is FAIL-CLOSED across every indeterminate systemctl outcome, and safe ONLY on inactive/failed.
import subprocess as _sp
_orun = _sp.run


def _fake(rc, out):
    def _run(*a, **k):
        class _R:
            returncode = rc
            stdout = out
        return _R()
    return _run


_cases = [
    ("non-zero exit", _fake(1, ""), False),
    ("active state", _fake(0, "active"), False),
    ("activating state", _fake(0, "activating"), False),
    ("unknown/empty state", _fake(0, ""), False),
    ("inactive state", _fake(0, "inactive"), True),
    ("failed state", _fake(0, "failed"), True),
]
for _name, _fn, _want in _cases:
    _sp.run = _fn
    try:
        ok(MG._quiesced() is _want, "_quiesced() on '%s' -> %s (fail-closed)" % (_name, _want))
    finally:
        _sp.run = _orun


def _raise_timeout(*a, **k):
    raise _sp.TimeoutExpired(cmd="systemctl", timeout=15)


def _raise_oserror(*a, **k):
    raise OSError("boom")


for _name, _fn in (("TimeoutExpired", _raise_timeout), ("OSError", _raise_oserror)):
    _sp.run = _fn
    try:
        ok(MG._quiesced() is False, "_quiesced() on a %s -> False (fail-closed)" % _name)
    finally:
        _sp.run = _orun


def _raise_notfound(*a, **k):
    raise FileNotFoundError("no systemctl")


_sp.run = _raise_notfound
try:
    ok(MG._quiesced() is True, "_quiesced() with NO systemctl -> True (no systemd runtime)")
finally:
    _sp.run = _orun

# ---- ambiguous/non-canonical hostile v1 SOURCE records are rejected (not normalized into v2 state) ----
def put_raw(base, parts, name, raw, mode=0o600):
    path = os.path.join(base, *parts, name)
    with open(path, "wb") as fh:
        fh.write(raw)
    os.chmod(path, mode)


d13 = tempfile.mkdtemp(dir=TMP)
os.chmod(d13, 0o755)
v1m = build_v1(d13)
# a valid neighbor still migrates
clean = "8" * 32
v1_pending(v1m, clean, UID, "add-splice", "clean.example", 443, 1)
# 1) duplicate-key "op" (last-key-wins would flip the operation) -> rejected
dk = "9" * 32
put_raw(v1m, ("pending",), dk, ('{"ver":1,"reqid":"' + dk + '","op":"add-splice","op":"remove-splice",'
        '"host":"x.example","port":443,"owner_uid":' + str(UID) + ',"ts":1}').encode("ascii"))
put(v1m, ("owner",), dk, {"ver": 1, "reqid": dk, "owner_uid": UID})
# 2) unknown extra field -> rejected
uk = "6" * 32
put_raw(v1m, ("pending",), uk, ('{"ver":1,"reqid":"' + uk + '","op":"add-splice","host":"x.example",'
        '"port":443,"owner_uid":' + str(UID) + ',"ts":1,"evil":1}').encode("ascii"))
put(v1m, ("owner",), uk, {"ver": 1, "reqid": uk, "owner_uid": UID})
# 3) non-canonical (reordered keys) -> rejected
nc = "5" * 32
put_raw(v1m, ("pending",), nc, ('{"op":"add-splice","ver":1,"reqid":"' + nc + '","host":"x.example",'
        '"port":443,"owner_uid":' + str(UID) + ',"ts":1}').encode("ascii"))
put(v1m, ("owner",), nc, {"ver": 1, "reqid": nc, "owner_uid": UID})
# 4) wrong version -> rejected
wv = "4" * 32
put(v1m, ("pending",), wv, {"ver": 2, "reqid": wv, "op": "add-splice", "host": "x.example", "port": 443,
                            "owner_uid": UID, "ts": 1})
put(v1m, ("owner",), wv, {"ver": 1, "reqid": wv, "owner_uid": UID})
v2m = v2_path(d13)
out13, code13 = MG.migrate(paths(v1m, v2m), check_quiesce=False)
ok(code13 == 0 and out13["skipped"] >= 4, "duplicate-key/unknown-field/non-canonical/wrong-version v1 records rejected")
for _r in (dk, uk, nc, wv):
    ok(not os.path.exists(os.path.join(v2m, "pending", _r)), "ambiguous v1 record %s NOT migrated" % _r[:4])
ok(os.path.exists(os.path.join(v2m, "pending", clean)), "the clean neighbor still migrated")

# ---- the SAME hostile forms in OWNER sidecars + ROOT/EXPIRY terminals: all four v1 source types share the one
#      _v1_parse gate, so the reject-not-normalize contract holds for every authoritative input, not just the
#      pending request. A malformed OWNER drops its pending (no attacker-chosen attribution); a malformed
#      TERMINAL is skipped but its pending is PRESERVED (a failed terminal copy must never drop a valid pending). ----
def _hx(n):
    return format(n, "032x")                                 # a distinct 32-char hex reqid


def _dec(rid, state):                                        # a well-formed v1 decision dict (11 exact fields)
    return {"reqid": rid, "state": state, "reason": state, "ts": 5, "owner_uid": UID, "op": "add-splice",
            "host": "term.example", "port": 443, "batch_id": None, "before_hash": None, "after_hash": None}


d14 = tempfile.mkdtemp(dir=TMP)
os.chmod(d14, 0o755)
v1n = build_v1(d14)
nbr = _hx(0x10)
v1_pending(v1n, nbr, UID, "add-splice", "neighbor.example", 443, 1)       # a clean neighbor still migrates

# malformed OWNER sidecars (each pending itself is valid) -> the pending is DROPPED
o_dup, o_unk, o_nc, o_wv = _hx(0x11), _hx(0x12), _hx(0x13), _hx(0x14)
for _r in (o_dup, o_unk, o_nc, o_wv):
    v1_pending(v1n, _r, UID, "add-splice", "o.example", 443, 1)
put_raw(v1n, ("owner",), o_dup, ('{"owner_uid":' + str(UID) + ',"owner_uid":9999,"reqid":"' + o_dup +
        '","ver":1}').encode("ascii"))                                    # duplicate owner_uid
put_raw(v1n, ("owner",), o_unk, ('{"owner_uid":' + str(UID) + ',"reqid":"' + o_unk +
        '","ver":1,"evil":1}').encode("ascii"))                          # unknown field
put_raw(v1n, ("owner",), o_nc, ('{"ver":1,"reqid":"' + o_nc + '","owner_uid":' + str(UID) +
        '}').encode("ascii"))                                            # non-canonical (reordered)
put(v1n, ("owner",), o_wv, {"ver": 2, "reqid": o_wv, "owner_uid": UID})   # wrong version

# malformed ROOT + EXPIRY terminals (each pending is valid) -> the terminal is SKIPPED, its pending PRESERVED
term = []
for _dir, _state, _base in (("root", "applied", 0x20), ("expiry", "expired", 0x30)):
    r_dup, r_unk, r_nc = _hx(_base + 1), _hx(_base + 2), _hx(_base + 3)
    term += [(_dir, r_dup), (_dir, r_unk), (_dir, r_nc)]
    for _r in (r_dup, r_unk, r_nc):
        v1_pending(v1n, _r, UID, "add-splice", "t.example", 443, 1)
    _canon = json.dumps(_dec(r_dup, _state), separators=(",", ":"), sort_keys=True)
    put_raw(v1n, ("decisions", _dir), r_dup, ('{"ts":5,' + _canon[1:]).encode("ascii"), 0o644)  # duplicate ts
    put_raw(v1n, ("decisions", _dir), r_unk,
            json.dumps(dict(_dec(r_unk, _state), ver=1), separators=(",", ":"), sort_keys=True).encode("ascii"),
            0o644)                                                        # unknown field ("ver" on an unversioned rec)
    put_raw(v1n, ("decisions", _dir), r_nc,
            json.dumps(_dec(r_nc, _state), separators=(",", ":")).encode("ascii"), 0o644)   # non-canonical (unsorted)
v2n = v2_path(d14)
out14, code14 = MG.migrate(paths(v1n, v2n), check_quiesce=False)
ok(code14 == 0 and out14["skipped"] >= 10, "malformed owner+root+expiry v1 sources rejected (>=10 skipped)")
for _r in (o_dup, o_unk, o_nc, o_wv):
    ok(not os.path.exists(os.path.join(v2n, "pending", _r)),
       "malformed OWNER %s -> its pending is DROPPED (no attacker-chosen attribution)" % _r[-4:])
for _dir, _r in term:
    _tdir = "published/decisions" if _dir == "root" else "expiry"
    ok(not os.path.exists(os.path.join(v2n, *_tdir.split("/"), _r)),
       "malformed %s terminal %s -> the terminal is NOT written" % (_dir, _r[-4:]))
    ok(os.path.exists(os.path.join(v2n, "pending", _r)),
       "malformed %s terminal %s -> its valid pending is PRESERVED" % (_dir, _r[-4:]))
ok(os.path.exists(os.path.join(v2n, "pending", nbr)), "the clean neighbor still migrated (all-source hostile run)")

# ---- no v1 store -> nothing to do ----
d4 = tempfile.mkdtemp(dir=TMP)
os.chmod(d4, 0o755)
out5, code5 = MG.migrate(paths(os.path.join(d4, "egress"), v2_path(d4)))
ok(code5 == 0 and "nothing to migrate" in out5.get("note", ""), "no v1 store -> nothing to migrate")

shutil.rmtree(TMP, ignore_errors=True)
print("-------------------------------------------")
print("egress migrate (v1->v2): PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
