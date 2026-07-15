#!/usr/bin/env python3
"""Tests the v2 egress request store primitives (tools/drvps_egress_req.py; arch doc EGRESS-STORE-ARCH-
UPGRADE.md). Real v2 store trees (provisioned via drvps_egress_layout) the test owns; dir-fd-relative ops.
SINGLE-UID: root and drvps both map to the current uid, so the cross-UID read edge is proven structurally
here (group set + mode 0640) and end-to-end by the split-UID container e2e. ASCII only."""
import json
import os
import re
import sys
import tempfile
import shutil
import stat as _stat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_egress_layout as L  # noqa: E402
import drvps_egress_req as R      # noqa: E402

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
TD = tempfile.mkdtemp(prefix="egress-req-")
os.chmod(TD, 0o755)
ANCHOR = os.path.join(TD, "distro-rig-vps-egress")
L.provision(ANCHOR, IDS)

PEND = R.open_ns(ANCHOR, *L.NS_PENDING)
EXP = R.open_ns(ANCHOR, *L.NS_EXPIRY)
BAT = R.open_ns(ANCHOR, *L.NS_BATCHES)
DEC = R.open_ns(ANCHOR, *L.NS_DECISIONS)
CLM = R.open_ns(ANCHOR, *L.NS_CLAIMS)


def pend_path(name):
    return os.path.join(ANCHOR, "pending", name)


# ---- reqid identity ----
a = R.reqid_for(1000, "add-splice", "x.com", 443)
ok(a == R.reqid_for(1000, "add-splice", "x.com", 443), "reqid_for deterministic")
ok(a != R.reqid_for(1000, "remove-splice", "x.com", 443), "opposing op -> different tuple key")
ok(bool(re.fullmatch(r"[0-9a-f]{32}", R.new_reqid())), "new_reqid is a 32-hex nonce")
ok(bool(re.fullmatch(r"[0-9a-f]{16}", R.new_batch_id())), "new_batch_id is a 16-hex nonce")

# ---- submit_request: NO owner sidecar; record carries owner_uid ----
rid = R.submit_request(PEND, UID, "add-splice", "callback.crm.example", 443, 100)
ok(bool(re.fullmatch(r"[0-9a-f]{32}", rid)), "submit returns a 32-hex nonce reqid")
ok(os.path.exists(pend_path(rid)), "pending request written")
ok(not os.path.exists(os.path.join(ANCHOR, "owner")), "v2: NO owner/ sidecar namespace exists")
ok(_stat.S_IMODE(os.lstat(pend_path(rid)).st_mode) == 0o600, "pending record mode 0600")
rid2 = R.submit_request(PEND, UID, "add-splice", "callback.crm.example", 443, 200)
ok(rid2 != rid, "same tuple, new attempt -> different nonce reqid")
rid3 = R.submit_request(PEND, UID, "add-splice", "explicit.example", 443, 300, reqid=rid)
ok(rid3 == rid, "explicit reqid honored (idempotent republish)")

# ---- read_request: schema + owner + hostile file ----
got = R.read_request(PEND, rid, expect_uid=UID)
ok(got["op"] == "add-splice" and got["owner_uid"] == UID and got["ver"] == 2, "read_request round-trip (ver 2)")
ok(R.read_owner_uid(PEND, rid) == UID, "read_owner_uid from the record itself")
try:
    R.read_request(PEND, rid, expect_uid=UID + 1)
    ok(False, "wrong owner should reject")
except R.EgressReqError as e:
    ok(e.reason == "wrong-owner", "wrong owner -> wrong-owner")

extra = json.dumps({"ver": 2, "reqid": "z" * 32, "op": "add-splice", "host": "x.com", "port": 443,
                    "owner_uid": UID, "ts": 1, "evil": 1}, separators=(",", ":")).encode()
with open(pend_path("z" * 32), "wb") as fh:
    fh.write(extra)
os.chmod(pend_path("z" * 32), 0o600)               # canonical mode so the SCHEMA check (not mode) is exercised
try:
    R.read_request(PEND, "z" * 32)
    ok(False, "extra field should reject")
except R.EgressReqError as e:
    ok(e.reason == "unknown-field", "extra field -> unknown-field")

os.symlink("/etc/passwd", pend_path("s" * 32))
try:
    R.read_request(PEND, "s" * 32)
    ok(False, "symlink should raise")
except OSError:
    ok(True, "symlink refused by O_NOFOLLOW")
except R.EgressReqError:
    ok(False, "symlink raised EgressReqError not OSError")

with open(pend_path("o" * 32), "wb") as fh:
    fh.write(b"x" * (R.MAX_REQ_BYTES + 10))
os.chmod(pend_path("o" * 32), 0o600)               # canonical mode so OVERSIZE (not mode) is the reject reason
try:
    R.read_request(PEND, "o" * 32)
    ok(False, "oversize should reject")
except R.EgressReqError as e:
    ok(e.reason == "oversize", "oversize -> oversize")

# hardlink (st_nlink==2) -> mandatory nlink==1 check rejects (arch §7)
os.link(pend_path(rid), pend_path("h" * 32))
try:
    R.read_request(PEND, "h" * 32)
    ok(False, "hardlinked record should reject")
except R.EgressReqError as e:
    ok(e.reason == "malformed-storage", "st_nlink>1 -> malformed-storage")
os.unlink(pend_path("h" * 32))
for n in ("z" * 32, "s" * 32, "o" * 32):
    try:
        os.unlink(pend_path(n))
    except OSError:
        pass

# ---- terminals: published decision (root->drvps edge) + expiry ----
R.write_published_decision(DEC, rid, "applied", "applied", 1000, group_gid=GID,
                           owner_uid=UID, op="add-splice", host="callback.crm.example", port=443,
                           batch_id="b" * 16, digest="d" * 64, after_hash="a" * 64)
dp = os.path.join(ANCHOR, "published", "decisions", rid)
ok(_stat.S_IMODE(os.lstat(dp).st_mode) == 0o640, "published decision mode 0640 (group read edge)")
ok(os.lstat(dp).st_gid == GID, "published decision group = drvps gid")
term = R.read_terminal(DEC, EXP, rid)
ok(term and term["state"] == "applied" and term["batch_id"] == "b" * 16, "read_terminal applied + binds batch")

R.write_expiry_decision(EXP, rid2, 1000, owner_uid=UID, op="add-splice", host="x", port=443)
ep = os.path.join(ANCHOR, "expiry", rid2)
ok(_stat.S_IMODE(os.lstat(ep).st_mode) == 0o600, "expiry terminal mode 0600 (drvps-owned)")
ok(R.read_terminal(DEC, EXP, rid2)["state"] == "expired", "read_terminal expired")

# degraded: same reqid in BOTH namespaces -> raise
R.write_expiry_decision(EXP, rid, 1001, owner_uid=UID, op="add-splice", host="x", port=443)
try:
    R.read_terminal(DEC, EXP, rid)
    ok(False, "two-terminal should raise degraded")
except R.EgressReqError as e:
    ok(e.reason == "degraded", "two terminals -> degraded")
os.unlink(os.path.join(ANCHOR, "expiry", rid))     # heal the degraded pair for later tests

# malformed decision -> read raises (never clears pending)
with open(os.path.join(ANCHOR, "published", "decisions", "m" * 32), "w") as fh:
    fh.write('{"reqid":"' + "m" * 32 + '","state":"bogus","ts":1}')
os.chmod(os.path.join(ANCHOR, "published", "decisions", "m" * 32), 0o640)   # canonical mode; test the SCHEMA path
try:
    R.read_published_decision(DEC, "m" * 32)
    ok(False, "malformed decision state should raise")
except R.EgressReqError:
    ok(True, "malformed decision -> raise")
os.unlink(os.path.join(ANCHOR, "published", "decisions", "m" * 32))

# ---- snapshot_batch -> immutable batch + published leases ----
s1 = R.submit_request(PEND, UID, "add-splice", "one.example", 443, 500)
s2 = R.submit_request(PEND, UID, "add-splice", "two.example", 443, 501)
bid = R.new_batch_id()
b_out, digest = R.snapshot_batch([s1, s2], PEND, BAT, CLM, bid, claim_ts=600, lease_expires=999999, group_gid=GID, policy="0" * 64)
ok(b_out == bid and bool(re.fullmatch(r"[0-9a-f]{64}", digest)), "snapshot returns (batch_id, digest)")
ok(os.path.isdir(os.path.join(ANCHOR, "root-private", "batches", bid)), "batch dir created (root-private)")
ok(os.path.isfile(os.path.join(ANCHOR, "root-private", "batches", bid, "manifest")), "manifest written")
ok(os.path.isfile(os.path.join(ANCHOR, "published", "claims", s1)), "lease s1 published")
cl = os.path.join(ANCHOR, "published", "claims", s1)
ok(_stat.S_IMODE(os.lstat(cl).st_mode) == 0o640 and os.lstat(cl).st_gid == GID, "lease mode 0640 root:drvps")
man = R.read_manifest(BAT, bid)
ok(sorted(man["reqids"]) == sorted([s1, s2]) and man["digest"] == digest, "read_manifest binds reqids+digest")
snap = R.read_snapshot_request(BAT, bid, s1)
ok(snap["host"] == "one.example", "read_snapshot_request from the frozen copy")
# digest is deterministic + binds the exact bytes
pairs = []
for r in (s1, s2):
    o = R.read_request(PEND, r)
    pairs.append((r, json.dumps(o, separators=(",", ":"), sort_keys=True)))
ok(R._digest(bid, "0" * 64, pairs) == digest, "digest binds {batch_id, policy, canonical bytes} deterministically")

# double-claim -> already-claimed + rollback (no half batch)
bid2 = R.new_batch_id()
try:
    R.snapshot_batch([s1], PEND, BAT, CLM, bid2, claim_ts=610, lease_expires=999999, group_gid=GID, policy="0" * 64)
    ok(False, "re-claiming an already-leased reqid should raise")
except R.EgressReqError as e:
    ok(e.reason == "already-claimed", "double claim -> already-claimed")
ok(not os.path.exists(os.path.join(ANCHOR, "root-private", "batches", bid2)), "failed snapshot rolled back its batch dir")

# ---- lease_status ----
st, lease = R.lease_status(CLM, s1, now=1000, expect_root_uid=UID, expect_svc_gid=GID)
ok(st == R.LEASE_FRESH and lease["batch_id"] == bid, "lease_status FRESH before expiry")
st, _ = R.lease_status(CLM, s1, now=10 ** 9, expect_root_uid=UID, expect_svc_gid=GID)
ok(st == R.LEASE_STALE, "lease_status STALE after expiry")
st, _ = R.lease_status(CLM, "n" * 32, now=1000, expect_root_uid=UID, expect_svc_gid=GID)
ok(st == R.LEASE_NONE, "lease_status NONE when no lease")
st, _ = R.lease_status(CLM, s1, now=1000, expect_root_uid=UID + 12345)
ok(st == R.LEASE_SUSPECT, "lease_status SUSPECT on wrong-owner lease (never NONE)")
# renew extends expiry
R.renew_lease(CLM, s1, bid, digest, new_expires=10 ** 10, group_gid=GID)
st, lease = R.lease_status(CLM, s1, now=10 ** 9, expect_root_uid=UID, expect_svc_gid=GID)
ok(st == R.LEASE_FRESH and lease["expires"] == 10 ** 10, "renew_lease extends expiry -> FRESH again")

# ---- release_batch: leases gone, batch dir gone ----
R.release_batch(bid, [s1, s2], BAT, CLM)
ok(not os.path.exists(os.path.join(ANCHOR, "published", "claims", s1)), "release drops lease s1")
ok(not os.path.exists(os.path.join(ANCHOR, "root-private", "batches", bid)), "release drops batch dir")

# ---- pending-aware GC (both namespaces) ----
# published decisions GC: old + pending-absent -> collected; pending-present -> retained; degraded -> retained
g1 = R.new_reqid()
g2 = R.new_reqid()
g3 = R.new_reqid()
R.write_published_decision(DEC, g1, "applied", "applied", 100, group_gid=GID, owner_uid=UID, op="add-splice", host="a", port=443)
R.write_published_decision(DEC, g2, "applied", "applied", 100, group_gid=GID, owner_uid=UID, op="add-splice", host="b", port=443)
R.write_published_decision(DEC, g3, "applied", "applied", 100, group_gid=GID, owner_uid=UID, op="add-splice", host="c", port=443)
R.submit_request(PEND, UID, "add-splice", "b.example", 443, 100, reqid=g2)   # g2 still pending -> retain
R.write_expiry_decision(EXP, g3, 100, owner_uid=UID, op="add-splice", host="c", port=443)  # g3 degraded -> retain
removed = R.gc_published_decisions(DEC, EXP, PEND, retention_s=10, now=10000, expect_root_uid=UID, expect_svc_gid=GID)
ok(removed == 1, "gc_published removed exactly the collectible terminal (g1)")
ok(not os.path.exists(os.path.join(ANCHOR, "published", "decisions", g1)), "g1 collected")
ok(os.path.exists(os.path.join(ANCHOR, "published", "decisions", g2)), "g2 retained (pending present)")
ok(os.path.exists(os.path.join(ANCHOR, "published", "decisions", g3)), "g3 retained (degraded pair)")
# too-young terminal is not collected
gy = R.new_reqid()
R.write_published_decision(DEC, gy, "applied", "applied", 9999, group_gid=GID, owner_uid=UID, op="add-splice", host="y", port=443)
ok(R.gc_published_decisions(DEC, EXP, PEND, retention_s=10000, now=10000, expect_root_uid=UID, expect_svc_gid=GID) == 0, "young terminal retained")

# expiry GC (drvps side): old + pending-absent -> collected
e1 = R.new_reqid()
R.write_expiry_decision(EXP, e1, 100, owner_uid=UID, op="add-splice", host="e", port=443)
ok(R.gc_expiry(EXP, DEC, PEND, retention_s=10, now=10000, expect_svc_uid=UID, expect_svc_gid=GID) == 1, "gc_expiry collects old pending-absent expiry")

# ---- exact mode + exact-schema enforcement on cross-domain reads ----
# wrong MODE on a published decision -> rejected (records are written 0640; a deviation is tamper)
wm = R.new_reqid()
R.write_published_decision(DEC, wm, "applied", "applied", 1, group_gid=GID, owner_uid=UID, op="add-splice", host="wm", port=443)
os.chmod(os.path.join(ANCHOR, "published", "decisions", wm), 0o666)
try:
    R.read_published_decision(DEC, wm, expect_uid=UID)
    ok(False, "wrong-mode published decision should reject")
except R.EgressReqError as e:
    ok(e.reason == "wrong-mode", "0666 published decision -> wrong-mode")
# wrong MODE on a pending request -> rejected
wmp = R.submit_request(PEND, UID, "add-splice", "wmp.example", 443, 1)
os.chmod(pend_path(wmp), 0o644)
try:
    R.read_request(PEND, wmp)
    ok(False, "wrong-mode request should reject")
except R.EgressReqError as e:
    ok(e.reason == "wrong-mode", "0644 request -> wrong-mode")
# UNKNOWN field in a terminal -> malformed (exact field set)
xf = R.new_reqid()
blob = json.dumps({"reqid": xf, "state": "applied", "reason": "applied", "ts": 1, "owner_uid": UID,
                   "op": "add-splice", "host": "x", "port": 443, "batch_id": None, "digest": None,
                   "after_hash": None, "evil": 1}, separators=(",", ":")).encode()
R._atomic_publish(DEC, xf, blob, mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
try:
    R.read_published_decision(DEC, xf, expect_uid=UID)
    ok(False, "extra terminal field should reject")
except R.EgressReqError:
    ok(True, "extra terminal field -> malformed")
# bad state/reason combo (applied with reason 'expired') -> malformed
bc = R.new_reqid()
blob = json.dumps({"reqid": bc, "state": "applied", "reason": "expired", "ts": 1, "owner_uid": UID,
                   "op": "add-splice", "host": "x", "port": 443, "batch_id": None, "digest": None,
                   "after_hash": None}, separators=(",", ":")).encode()
R._atomic_publish(DEC, bc, blob, mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
try:
    R.read_published_decision(DEC, bc, expect_uid=UID)
    ok(False, "applied+reason:expired should reject")
except R.EgressReqError:
    ok(True, "bad state/reason combo -> malformed")
# lease with a wrong MODE -> SUSPECT (never NONE)
wl = R.new_reqid()
R._atomic_publish(CLM, wl, R._lease_blob(wl, "0" * 16, "d" * 64, 10 ** 12), mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
os.chmod(os.path.join(ANCHOR, "published", "claims", wl), 0o600)
stt, _ = R.lease_status(CLM, wl, now=1, expect_root_uid=UID, expect_svc_gid=GID)
ok(stt == R.LEASE_SUSPECT, "wrong-mode lease -> SUSPECT (never NONE)")
# lease with an extra field -> SUSPECT
xl = R.new_reqid()
R._atomic_publish(CLM, xl, json.dumps({"ver": 2, "reqid": xl, "batch_id": "0" * 16, "digest": "d" * 64,
                  "expires": 10 ** 12, "evil": 1}, separators=(",", ":")).encode(),
                  mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
stt, _ = R.lease_status(CLM, xl, now=1, expect_root_uid=UID, expect_svc_gid=GID)
ok(stt == R.LEASE_SUSPECT, "extra-field lease -> SUSPECT")

# ---- canonical-byte rule (arch §7): non-canonical (reordered-key) bytes are rejected ----
ncr = R.new_reqid()
noncanon = ('{"op":"add-splice","ver":2,"reqid":"' + ncr + '","host":"x.example","port":443,"owner_uid":'
            + str(UID) + ',"ts":1}').encode("ascii")   # valid fields but NON-canonical key order
with open(pend_path(ncr), "wb") as fh:
    fh.write(noncanon)
os.chmod(pend_path(ncr), 0o600)
try:
    R.read_request(PEND, ncr)
    ok(False, "non-canonical request bytes should reject")
except R.EgressReqError as e:
    ok(e.reason == "malformed-storage", "non-canonical request bytes -> malformed (canonical-byte rule)")
ncl = R.new_reqid()
R._atomic_publish(CLM, ncl, ('{"reqid":"' + ncl + '","ver":2,"batch_id":"' + "0" * 16 + '","digest":"'
                  + "d" * 64 + '","expires":' + str(10 ** 12) + '}').encode("ascii"),
                  mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
stt, _ = R.lease_status(CLM, ncl, now=1, expect_root_uid=UID, expect_svc_gid=GID)
ok(stt == R.LEASE_SUSPECT, "non-canonical lease bytes -> SUSPECT")
# non-canonical terminal (reordered keys) -> malformed
nct = R.new_reqid()
R._atomic_publish(DEC, nct, ('{"state":"applied","reqid":"' + nct + '","reason":"applied","ts":1,"owner_uid":'
                  + str(UID) + ',"op":"add-splice","host":"x","port":443,"batch_id":null,"digest":null,'
                  '"after_hash":null}').encode("ascii"), mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
try:
    R.read_published_decision(DEC, nct, expect_uid=UID)
    ok(False, "non-canonical terminal should reject")
except R.EgressReqError:
    ok(True, "non-canonical terminal bytes -> malformed")
# a non-hex policy is rejected by snapshot_batch (the digest policy must be 64-hex)
sp = R.submit_request(PEND, UID, "add-splice", "policy.example", 443, 1)
try:
    R.snapshot_batch([sp], PEND, BAT, CLM, R.new_batch_id(), 1, 10 ** 12, GID, policy="nothex")
    ok(False, "non-hex policy should reject")
except R.EgressReqError as e:
    ok(e.reason == "bad-type", "non-hex policy -> bad-type (digest policy is 64-hex)")

for fd in (PEND, EXP, BAT, DEC, CLM):
    os.close(fd)
shutil.rmtree(TD, ignore_errors=True)
print("-------------------------------------------")
print("drvps-egress-req(v2): PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
