#!/usr/bin/env python3
"""Tests the v2 drvpsvc MEMBER-facing egress ops + reaper expiry sweep (tools/drvps_egress_member.py;
docs/EGRESS-STORE-ARCH-UPGRADE.md). v2 changes vs v1: the request record carries owner_uid (no owner/
sidecar); the reaper reads root claim LEASES to suppress expiry (claim recovery + root-decision GC moved to
the root approve tool); root decisions live in published/decisions, expiry in expiry/. SINGLE-UID: the store
is provisioned via drvps_egress_layout and MB uses a single-UID ids override (the cross-UID edge is proven by
the split-UID container e2e). Section 9 (watcher decide() argv shaping) is store-independent and unchanged."""
import json
import os
import re
import sys
import tempfile
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_egress_layout as L   # noqa
import drvps_egress_member as MB  # noqa
import drvps_egress_req as R      # noqa

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
MB._IDS_OVERRIDE = IDS                            # single-UID: member probe/lease checks use these ids
TMP = tempfile.mkdtemp(prefix="egress-verb-")
os.chmod(TMP, 0o755)


def mkbase():
    d = tempfile.mkdtemp(dir=TMP)
    os.chmod(d, 0o755)
    anchor = os.path.join(d, "distro-rig-vps-egress")
    L.provision(anchor, IDS)
    return anchor


def mkfleet(splices=()):
    fp = tempfile.mktemp(dir=TMP)
    open(fp, "w").write(json.dumps({"mirror_allowlist": ["deb.debian.org"],
                                    "splice_allowlist": [{"host": h, "port": 443} for h in splices]}))
    return fp


def fleet(splices=(), egress=None):
    base = mkbase()
    fp = tempfile.mktemp(dir=TMP)
    obj = {"mirror_allowlist": ["deb.debian.org"],
           "splice_allowlist": [{"host": h, "port": 443} for h in splices]}
    if egress is not None:
        obj["egress"] = egress
    open(fp, "w").write(json.dumps(obj))
    return base, fp


def sub(base, fleet_path, owner, op, host, port=443, ts=100):
    return MB.cmd_submit(SimpleNamespace(base=base, lock=MB._lock_path(base), fleet=fleet_path, owner=owner,
                                         op=op, host=host, port=port, ts=ts))


def lst(base, owner):
    return MB.cmd_list(SimpleNamespace(base=base, owner=owner))


def st(base, owner, reqid):
    return MB.cmd_status(SimpleNamespace(base=base, owner=owner, reqid=reqid))


def expire(base, ttl=3600, now=5000, retention=0):
    return MB.cmd_expire(SimpleNamespace(base=base, lock=MB._lock_path(base), ttl=ttl, now=now,
                                         retention=retention, claim_ttl=3600))


def store(base):
    return MB.Store(base)


def pend_path(base, reqid):
    return os.path.join(base, "pending", reqid)


def write_terminal(base, reqid, state, reason, owner, op, host, port, ts=200):
    dfd = R.open_ns(base, *L.NS_DECISIONS)
    try:
        R.write_published_decision(dfd, reqid, state, reason, ts, group_gid=GID,
                                   owner_uid=owner, op=op, host=host, port=port)
    finally:
        os.close(dfd)
    pfd = R.open_ns(base, *L.NS_PENDING)          # v2: the reaper clears decided pending; simulate it for list/status
    try:
        R._unlink_quiet(pfd, reqid)
    finally:
        os.close(pfd)


def put_lease(base, reqid, batch_id="0" * 16, digest="d" * 64, expires=10 ** 12, raw=None):
    cfd = R.open_ns(base, *L.NS_CLAIMS)
    try:
        blob = raw if raw is not None else R._lease_blob(reqid, batch_id, digest, expires)
        R._atomic_publish(cfd, reqid, blob, mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
    finally:
        os.close(cfd)


# 1. add -> pending + NONCE reqid; same tuple re-submit -> SAME reqid (dedup), no 2nd pending
base, fp = fleet()
r1 = sub(base, fp, 1008, "add-splice", "callback.crm.example")
ok(r1["status"] == "pending" and bool(re.fullmatch(r"[0-9a-f]{32}", r1["reqid"])), "add -> pending + 32-hex nonce reqid")
r2 = sub(base, fp, 1008, "add-splice", "callback.crm.example")
ok(r2["reqid"] == r1["reqid"] and r2.get("idempotent"), "same tuple in-flight -> SAME reqid (dedup)")
pfd = R.open_ns(base, *L.NS_PENDING)
ok(len(R.list_names(pfd)) == 1, "dedup did not create a 2nd pending")
os.close(pfd)

# 2. add -> (applied) -> remove -> (applied) -> add-again is a NEW attempt (per-attempt nonce)
base, fp0 = fleet()
ra = sub(base, fp0, 1008, "add-splice", "cycle.crm.example")["reqid"]
write_terminal(base, ra, "applied", "applied", 1008, "add-splice", "cycle.crm.example", 443)
fp1 = mkfleet(splices=["cycle.crm.example"])
rr = sub(base, fp1, 1008, "remove-splice", "cycle.crm.example")["reqid"]
write_terminal(base, rr, "applied", "applied", 1008, "remove-splice", "cycle.crm.example", 443)
fp2 = mkfleet()
again = sub(base, fp2, 1008, "add-splice", "cycle.crm.example")
ok(again["status"] == "pending" and again["reqid"] not in (ra, rr), "re-add after a full cycle -> NEW attempt reqid")
ok(st(base, 1008, again["reqid"])["state"] == "pending", "the new attempt is pending (NOT the stale applied)")
ok(st(base, 1008, ra)["state"] == "applied", "the old add terminal is still its own applied outcome")

# 3. already-active / already-absent
base, fp = fleet(splices=["dup.crm.example"])
ok(sub(base, fp, 1008, "add-splice", "dup.crm.example")["status"] == "already-active", "add active host -> already-active")
base, fp = fleet()
ok(sub(base, fp, 1008, "remove-splice", "ghost.crm.example")["status"] == "already-absent", "remove absent -> already-absent")

# 4. bad fqdn / bad port
base, fp = fleet()
ok(sub(base, fp, 1008, "add-splice", "-bad.example")["reason"] == "leading-dash", "bad fqdn refused")
ok(sub(base, fp, 1008, "add-splice", "h.example", port=8443)["reason"] == "bad-port", "non-443 refused")

# 5. caps: per-owner, global, max-active reserve
base, fp = fleet(egress={"per_owner_pending": 2})
sub(base, fp, 1008, "add-splice", "a.crm.example")
sub(base, fp, 1008, "add-splice", "b.crm.example")
ok(sub(base, fp, 1008, "add-splice", "c.crm.example")["reason"] == "owner-pending-cap", "per-owner cap")
ok(sub(base, fp, 2000, "add-splice", "d.crm.example")["status"] == "pending", "other owner not blocked by owner cap")
base, fp = fleet(egress={"per_owner_pending": 50, "global_pending": 2})
sub(base, fp, 1, "add-splice", "g1.crm.example")
sub(base, fp, 2, "add-splice", "g2.crm.example")
ok(sub(base, fp, 3, "add-splice", "g3.crm.example")["reason"] == "global-pending-cap", "global cap")
base, fp = fleet(splices=["x1.crm.example"], egress={"max_active": 2})
ok(sub(base, fp, 1008, "add-splice", "x2.crm.example")["status"] == "pending", "1st add under max-active ok")
ok(sub(base, fp, 2000, "add-splice", "x3.crm.example")["reason"] == "max-active", "2nd add reserved-out by max-active")

# 6. list owner-scoped (pending) + decided attempts
base = mkbase()
fp = mkfleet()
mine = sub(base, fp, 1008, "add-splice", "mine.crm.example")["reqid"]
sub(base, fp, 2000, "add-splice", "theirs.crm.example")
done = sub(base, fp, 1008, "add-splice", "done.crm.example")["reqid"]
write_terminal(base, done, "rejected", "operator-declined", 1008, "add-splice", "done.crm.example", 443)
LR = lst(base, 1008)
ok([r["host"] for r in LR["requests"]] == ["mine.crm.example"], "list pending is owner-scoped")
ok(any(d["reqid"] == done and d["state"] == "rejected" and d["reason"] == "operator-declined" for d in LR["decided"]),
   "list.decided shows the owner's resolved attempt + reason")

# 7. status BY REQID delivers add AND remove outcomes; foreign/unknown -> not-found
base = mkbase()
fp = mkfleet(splices=["gone.crm.example"])
remreq = sub(base, fp, 1008, "remove-splice", "gone.crm.example")["reqid"]
write_terminal(base, remreq, "applied", "applied", 1008, "remove-splice", "gone.crm.example", 443)
s = st(base, 1008, remreq)
ok(s["state"] == "applied" and s["op"] == "remove-splice" and s["host"] == "gone.crm.example",
   "status by reqid delivers a REMOVE outcome")
rej = sub(base, mkfleet(), 1008, "add-splice", "nope.crm.example")["reqid"]
write_terminal(base, rej, "rejected", "operator-declined", 1008, "add-splice", "nope.crm.example", 443)
ok(st(base, 1008, rej)["reason"] == "operator-declined", "status returns the terminal REASON")
ok(st(base, 9999, remreq)["status"] == "not-found", "a foreign owner cannot read another's outcome")
ok(st(base, 1008, "deadbeef" * 4)["status"] == "not-found", "unknown reqid -> not-found")

# 8. expiry sweep -> expired terminal + status; retention GC drops old terminals
base, fp = fleet()
old = sub(base, fp, 1008, "add-splice", "stale.crm.example", ts=1000)["reqid"]
recent = sub(base, fp, 1008, "add-splice", "fresh.crm.example", ts=100000)["reqid"]
ex = expire(base, ttl=3600, now=5000)
ok(old in ex["expired"] and recent not in ex["expired"], "past-TTL expired, recent survives")
sexp = st(base, 1008, old)
ok(sexp["state"] == "expired" and sexp["host"] == "stale.crm.example", "member polls the expired outcome by reqid")
gc = expire(base, ttl=3600, now=5000 + 10 ** 7, retention=10 ** 6)
ok(gc["gc"] >= 1 and st(base, 1008, old)["status"] == "not-found", "retention GC bounds terminal storage")

# 8c. degraded (two-terminal) -> not-found (no oracle)
base = mkbase()
dreq = "d" * 32
dfd, efd = R.open_ns(base, *L.NS_DECISIONS), R.open_ns(base, *L.NS_EXPIRY)
try:
    R.write_published_decision(dfd, dreq, "applied", "applied", 1, group_gid=GID, owner_uid=1008, op="add-splice", host="x", port=443)
    R.write_expiry_decision(efd, dreq, 1, owner_uid=1008, op="add-splice", host="x", port=443)
finally:
    os.close(dfd)
    os.close(efd)
ok(st(base, 1008, dreq)["status"] == "not-found", "degraded (two-terminal) -> not-found")

# 8d. v2 LEASE: a leased reqid is under review -> NEVER expired; shows under-review
base, fp = fleet()
lreq = sub(base, fp, 1008, "add-splice", "leased.crm.example", ts=1000)["reqid"]
put_lease(base, lreq)
exl = expire(base, ttl=3600, now=10 ** 6)
ok(lreq not in exl["expired"] and lreq in exl["leased"], "a leased reqid is NOT expired (under review by root)")
ok(st(base, 1008, lreq)["state"] == "under-review", "leased reqid shows under-review")

# 8e. v2 LEASE fault: a malformed root lease SUPPRESSES expiry AND surfaces a fault (never 'no claim')
base, fp = fleet()
sreq = sub(base, fp, 1008, "add-splice", "suspect.crm.example", ts=1000)["reqid"]
put_lease(base, sreq, raw=b"{ not json")
exs = expire(base, ttl=3600, now=10 ** 6)
ok(sreq not in exs["expired"] and sreq in exs["lease_faults"] and sreq in exs["leased"],
   "a malformed lease suppresses expiry AND is surfaced as a lease fault")

# 8p. a STALE (expired but valid) root lease suppresses expiry AND surfaces a lease fault (arch §7)
base, fp = fleet()
slreq = sub(base, fp, 1008, "add-splice", "stalelease.crm.example", ts=1000)["reqid"]
put_lease(base, slreq, expires=1)                 # a valid lease, already expired (now >> 1)
exsl = expire(base, ttl=3600, now=10 ** 6)
ok(slreq not in exsl["expired"] and slreq in exsl["leased"] and slreq in exsl["lease_faults"],
   "a STALE lease suppresses expiry AND is surfaced as a lease fault (not silently pinned)")

# 8f. v2 duty: the reaper CLEARS decided pending (a decided reqid whose pending lingers)
base, fp = fleet()
dp = sub(base, fp, 1008, "add-splice", "decidedpending.crm.example", ts=1000)["reqid"]
dfd = R.open_ns(base, *L.NS_DECISIONS)
try:
    R.write_published_decision(dfd, dp, "applied", "applied", 1, group_gid=GID, owner_uid=1008,
                               op="add-splice", host="decidedpending.crm.example", port=443)
finally:
    os.close(dfd)
exc = expire(base, ttl=3600, now=10 ** 6)
ok(dp in exc["cleaned"] and not os.path.exists(pend_path(base, dp)), "reaper clears decided pending (drvps duty)")

# 8o. the reaper clears decided pending EVEN when a leftover LEASE still exists (terminal
#     precedence -- root writes the decision before removing its lease; the reaper must not be blocked by it)
base, fp = fleet()
tl = sub(base, fp, 1008, "add-splice", "termlease.crm.example", ts=1000)["reqid"]
dfd = R.open_ns(base, *L.NS_DECISIONS)
try:
    R.write_published_decision(dfd, tl, "applied", "applied", 1, group_gid=GID, owner_uid=1008,
                               op="add-splice", host="termlease.crm.example", port=443)
finally:
    os.close(dfd)
put_lease(base, tl)                               # a leftover lease coexisting with the durable terminal
extl = expire(base, ttl=3600, now=10 ** 6)
ok(tl in extl["cleaned"] and not os.path.exists(pend_path(base, tl)),
   "reaper clears decided pending despite a leftover lease (terminal-first)")

# 8g. status returns the TERMINAL even when pending was not yet cleared (terminal precedence)
base, fp = fleet()
rid = sub(base, fp, 1008, "add-splice", "race.example")["reqid"]
dfd = R.open_ns(base, *L.NS_DECISIONS)
try:
    R.write_published_decision(dfd, rid, "applied", "applied", 200, group_gid=GID, owner_uid=1008,
                               op="add-splice", host="race.example", port=443)
finally:
    os.close(dfd)                                # pending intentionally NOT cleared
ok(st(base, 1008, rid)["state"] == "applied", "status returns applied despite a lingering pending file")

# 8j. the DATA lock is bound to the store anchor -- the prod anchor forces the fixed root-owned lock
ok(MB._lock_path(MB.PROD_ANCHOR) == MB.LOCK_PATH, "prod store anchor -> fixed root-owned lock (no --lock seam)")
ok(MB._lock_path("/tmp/x/distro-rig-vps-egress") == "/tmp/x/egress.lock", "a non-prod base -> a lock beside it")

# 8k. cmd_expire quarantines an over-long-named + a directory-valued pending entry (no wedge)
base, fp = fleet()
s = store(base)
longn = "z" * 200
open(pend_path(base, longn), "w").write("{}")
os.mkdir(pend_path(base, "e" * 32))
expire(base, ttl=3600, now=100000)
pfd = R.open_ns(base, *L.NS_PENDING)
names = R.list_names(pfd)
os.close(pfd)
ok(longn not in names, "over-long pending name quarantined")
ok(("e" * 32) not in names, "directory-valued pending entry quarantined")

# 8l. content-invalid records (bad ts / list host) are QUARANTINED; they don't abort the sweep
base, fp = fleet()
good = sub(base, fp, 1008, "add-splice", "good.crm.example", ts=1)["reqid"]
badn = "a" * 32
open(pend_path(base, badn), "w").write(json.dumps(
    {"ver": 2, "reqid": badn, "op": "add-splice", "host": [], "port": 443, "owner_uid": 1, "ts": "nope"}))
exq = expire(base, ttl=3600, now=100000)
pfd = R.open_ns(base, *L.NS_PENDING)
names = R.list_names(pfd)
os.close(pfd)
ok(exq["status"] == "ok" and badn not in names, "content-invalid pending record quarantined (sweep survives)")
ok(good in exq["expired"], "the valid past-TTL request still expired despite the malformed neighbor")

# 8m. a SYMLINKED namespace dir fails closed (open_sub_fd O_NOFOLLOW) -- no redirect
base = mkbase()
os.rmdir(os.path.join(base, "pending"))
os.symlink("/tmp", os.path.join(base, "pending"))
try:
    fd = R.open_ns(base, *L.NS_PENDING)
    os.close(fd)
    ok(False, "a symlinked namespace dir must not open")
except OSError:
    ok(True, "open_sub_fd O_NOFOLLOW rejects a symlinked namespace dir (no redirect)")

# 8n. v2: submit on an ABSENT (never-provisioned) store is refused; list empty; status not-found
absent = os.path.join(tempfile.mkdtemp(dir=TMP), "distro-rig-vps-egress")
ok(sub(absent, mkfleet(), 1008, "add-splice", "x.crm.example")["reason"] == "store-not-initialized",
   "submit on an ABSENT store -> store-not-initialized")
ok(lst(absent, 1008)["requests"] == [] and st(absent, 1008, "a" * 32)["status"] == "not-found",
   "list/status on an ABSENT store degrade gracefully")

# 9. watcher decide() shaping (store-independent; unchanged)
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import drvps_rigctl as W  # noqa
CAPS = {"bin": "/opt/distro-rig-vps/bin/dr-vps", "req_max": 65536, "net": "simnet", "pubkey": "/k.pub", "mem_max": 8192, "cpu_max": 8}


def dec(req):
    return W.decide(req["reqid"] + ".json", json.dumps(req), lambda m, v: True, CAPS)


ok(dec({"reqid": "e1", "op": "egress", "egress_op": "add-splice", "host": "cb.crm.example", "port": 443, "owner_uid": 1008})["argv"]
   == [CAPS["bin"], "egress", "add-splice", "cb.crm.example", "443", "--owner", "1008"], "decide: add argv")
ok(dec({"reqid": "e2", "op": "egress", "egress_op": "add-splice", "host": "h.example", "port": 443})["reason"]
   == "owner-scoped verb missing owner_uid", "decide: unstamped egress fails closed")
qr = "a" * 32
ok(dec({"reqid": "e3", "op": "egress", "egress_op": "status", "qreqid": qr, "owner_uid": 1008})["argv"]
   == [CAPS["bin"], "egress", "status", qr, "--owner", "1008"], "decide: status argv by qreqid")
ok(dec({"reqid": "e4", "op": "egress", "egress_op": "status", "qreqid": "bad/id", "owner_uid": 1008})["reason"] == "bad qreqid",
   "decide: malformed qreqid rejected")
ok(dec({"reqid": "e5", "op": "egress", "egress_op": "add-splice", "host": "-evil", "port": 443, "owner_uid": 1})["reason"] == "bad host",
   "decide: leading-dash host rejected")
ok(dec({"reqid": "e6", "op": "egress", "egress_op": "list", "owner_uid": 1008})["argv"]
   == [CAPS["bin"], "egress", "list", "--owner", "1008"], "decide: list argv")

import shutil
shutil.rmtree(TMP, ignore_errors=True)
print("-------------------------------------------")
print("egress verb (member ops + decide): PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
