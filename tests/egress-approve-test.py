#!/usr/bin/env python3
"""Offline test of the v2 bin/drvps-egress-approve (docs/EGRESS-STORE-ARCH-UPGRADE.md). The privileged CLI
has NO runtime seam, so this drives the tool at the PYTHON API level: Paths(test_root=..., restart=...,
ids=...) with a single-UID ids map (root+drvps both map to the test uid -- the cross-UID edge is proven by
the split-UID container e2e). The store is PROVISIONED via drvps_egress_layout (the installer's job in v2;
the test stands in for the root installer -- the approve tool never provisions). A background TCP listener on
127.0.0.1:3128 is the healthy squid stand-in; a stub `squid` handles `-k parse`; a swappable restart argv
exercises success / clean rollback / DEGRADED. v2 duty split: the approve tool writes the durable published
decision but does NOT clear pending (the drvps reaper does) -- assertions reflect that."""
import importlib.util
import io
import json
import os
import socket
import stat
import sys
import tempfile
import threading
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_egress_layout as L  # noqa
import drvps_egress_req as R      # noqa
_ldr = SourceFileLoader("approve", os.path.join(HERE, "..", "bin", "drvps-egress-approve"))
_spec = importlib.util.spec_from_loader("approve", _ldr)
A = importlib.util.module_from_spec(_spec)
_ldr.exec_module(A)

npass = [0]
nfail = [0]


def ok(c, m):
    if c:
        npass[0] += 1
    else:
        nfail[0] += 1
        print("FAIL:", m)


def _serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", 3128))
        s.listen(16)
    except OSError:
        return
    while True:
        try:
            c, _ = s.accept()
            c.close()
        except OSError:
            break


threading.Thread(target=_serve, daemon=True).start()

UID, GID = os.getuid(), os.getgid()
IDS = {L.ROOT: (UID, GID), L.SVC: (UID, GID)}
TMP = tempfile.mkdtemp(prefix="approve-t-")
os.chmod(TMP, 0o755)


def sandbox(restart, fleet='{"mirror_allowlist":["deb.debian.org"]}'):
    d = tempfile.mkdtemp(dir=TMP)
    os.chmod(d, 0o755)
    open(os.path.join(d, "fleet.json"), "w").write(fleet)
    os.chmod(os.path.join(d, "fleet.json"), 0o600)
    open(os.path.join(d, "params.json"), "w").write(
        '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"/bin/true"}')
    open(os.path.join(d, "hostfacts.json"), "w").write("{}")
    sq = os.path.join(d, "squid")
    open(sq, "w").write("#!/bin/sh\nexit 0\n")
    os.chmod(sq, 0o755)
    p = A.Paths(test_root=d, restart=restart, ids=IDS)
    L.provision(p.base, IDS)                     # the ROOT INSTALLER provisions the v2 store (approve verifies only)
    return p, d


def sh(*lines):
    f = tempfile.mktemp(dir=TMP)
    open(f, "w").write("#!/bin/sh\n" + "\n".join(lines) + "\n")
    os.chmod(f, 0o755)
    return [f]


def stage(p, uid, op, host, port):
    pf = R.open_ns(p.base, *L.NS_PENDING)
    try:
        return R.submit_request(pf, uid, op, host, port, 1)
    finally:
        os.close(pf)


def apply(p, args=(), answer="YES"):
    old = sys.stdin
    sys.stdin = io.StringIO(answer + "\n")
    try:
        return A.cmd_apply(p, list(args))
    finally:
        sys.stdin = old


def dec_path(p, r):
    return os.path.join(L.node_path(p.base, L.NS_DECISIONS), r)


def pend_path(p, r):
    return os.path.join(p.base, "pending", r)


def lease_path(p, r):
    return os.path.join(L.node_path(p.base, L.NS_CLAIMS), r)


def batch_path(p, b):
    return os.path.join(L.node_path(p.base, L.NS_BATCHES), b)


def jrnl_path(p, b):
    return os.path.join(L.node_path(p.base, L.NS_JOURNALS), b)


def has_decision(p, r):
    return os.path.exists(dec_path(p, r))


def pending_exists(p, r):
    return os.path.exists(pend_path(p, r))


def snapshot(p, reqids, bid, claim_ts=100, lease_expires=10 ** 12):
    pf, bf, cf = R.open_ns(p.base, *L.NS_PENDING), R.open_ns(p.base, *L.NS_BATCHES), R.open_ns(p.base, *L.NS_CLAIMS)
    try:
        return R.snapshot_batch(reqids, pf, bf, cf, bid, claim_ts, lease_expires, GID, policy="0" * 64)[1]   # digest
    finally:
        for fd in (pf, bf, cf):
            os.close(fd)


def journal(p, bid, digest, entries, after_conf="c" * 64, after_fleet="f" * 64):
    A._write_journal(p, bid, digest, entries, after_fleet, after_conf)


def conf_hash(p):
    """The squid.conf hash the CURRENT fleet renders to -- the exact resulting-state hash a real journal
    binds (recovery completion requires hash(render(current fleet)) == journal.after_conf_hash)."""
    params, facts = A._render_params(p)
    _fb, fleet = A._fleet_snapshot(p)
    return A._hash(A.M.render_squid(A.M.load_model(fleet), params, facts))


def fleet_hash(p):
    """The raw on-disk fleet.json hash -- recovery completion also requires it == journal.after_fleet_hash
    (so a non-rendered fleet field change cannot spoof completion)."""
    return A._hash(A._read_bytes(p.fleet))


def write_expiry(p, reqid, op="add-splice", host="h", port=443, ts=1):
    ef = R.open_ns(p.base, *L.NS_EXPIRY)
    try:
        R.write_expiry_decision(ef, reqid, ts, owner_uid=UID, op=op, host=host, port=port)
    finally:
        os.close(ef)


# 0. the production CLI exposes NO seam (fixed paths); constructing with explicit ids avoids a drvps lookup
ok(A.Paths(ids=IDS).fleet == "/etc/distro-rig-vps/fleet.json" and A.Paths(ids=IDS).restart == A.PROD_RESTART,
   "production Paths are fixed (no runtime seam)")
ok(A.Paths(ids=IDS).base == L.ANCHOR, "production base is the v2 root-owned anchor")
ok(A.Paths(ids=IDS).session_lock == A.EGRESS_SESSION_LOCK_PATH, "production session lock is a fixed root-owned path")

# 1. apply(YES) success -> applied decision durable; v2: pending NOT cleared by approve (the reaper clears it);
#    lease + batch removed
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "callback.crm.example", 443)
ok(apply(p) == 0, "apply(YES) -> 0 (healthy)")
ok("callback.crm.example" in open(p.fleet).read(), "splice merged into fleet.json")
ok("splice_dst dstdomain -n callback.crm.example" in open(p.squid_conf).read(), "splice squid.conf installed")
ok(stat.S_IMODE(os.stat(p.fleet).st_mode) == 0o600, "fleet.json mode 0600 preserved")
ok(has_decision(p, rid), "applied decision durable in published/decisions")
ok(pending_exists(p, rid), "v2: pending NOT cleared by approve (the drvps reaper clears decided pending)")
ok(not os.path.exists(lease_path(p, rid)), "lease removed after apply")
ok(len(os.listdir(L.node_path(p.base, L.NS_BATCHES))) == 0, "batch dir removed after apply")
ok(json.load(open(dec_path(p, rid)))["state"] == "applied", "decision state == applied")
ok(stat.S_IMODE(os.lstat(dec_path(p, rid)).st_mode) == 0o640, "published decision mode 0640 (drvps read edge)")
ok(apply(p) == 1, "idempotent rerun -> nothing to open (1); decided-pending skipped")

# 2. apply(no) aborts, no change, lease+batch released
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1, "add-splice", "n.example", 443)
ok(apply(p, answer="no") == 1 and "splice_allowlist" not in open(p.fleet).read(), "apply(no) aborts, unchanged")
ok(not os.path.exists(lease_path(p, rid)) and len(os.listdir(L.node_path(p.base, L.NS_BATCHES))) == 0,
   "apply(no) releases the snapshot batch + lease")

# 3. missing selected reqid -> abort (no partial)
p, _ = sandbox(sh("exit 0"))
stage(p, 1, "add-splice", "ok.example", 443)
ok(apply(p, args=["deadbeef" * 4]) == 3, "missing selected reqid -> 3")

# 4. bad-fqdn + non-443 -> DURABLE published reject; pending NOT cleared (reaper clears); nothing applied
p, _ = sandbox(sh("exit 0"))
rb = stage(p, 1, "add-splice", "-bad.example", 443)
rp = stage(p, 1, "add-splice", "hostx.example", 8443)
ok(apply(p) == 1, "all-invalid -> nothing to open (1)")
ok(has_decision(p, rb) and json.load(open(dec_path(p, rb)))["state"] == "rejected", "bad-fqdn durably rejected")
ok(has_decision(p, rp) and json.load(open(dec_path(p, rp)))["state"] == "rejected", "non-443 durably rejected")

# 5. already-active -> already-active reject, NOT applied
p, _ = sandbox(sh("exit 0"), fleet='{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"dup.example","port":443}]}')
ra = stage(p, 1, "add-splice", "dup.example", 443)
ok(apply(p) == 1 and json.load(open(dec_path(p, ra)))["reason"] == "already-active", "add already-active -> resolved, not applied")

# 6. conflict abort
p, _ = sandbox(sh("exit 0"))
stage(p, 1, "add-splice", "c.example", 443)
stage(p, 2, "remove-splice", "c.example", 443)
ok(apply(p) == 3, "add+remove conflict -> 3")

# 7. malformed pending -> durably rejected before snapshot (does not wedge)
p, _ = sandbox(sh("exit 0"))
good = stage(p, 1, "add-splice", "good.example", 443)
badname = "b" * 32
open(pend_path(p, badname), "w").write("{ not json")
os.chmod(pend_path(p, badname), 0o600)
rc = apply(p)
ok(has_decision(p, badname) and json.load(open(dec_path(p, badname)))["state"] == "rejected", "malformed pending durably rejected")
ok(rc == 0 and has_decision(p, good), "the good request still applied despite the malformed neighbor")

# 8. CLEAN rollback: restart fails ONCE then succeeds -> rolled back, exit 3, no applied, fleet restored
marker = tempfile.mktemp(dir=TMP)
open(marker, "w").close()
p, _ = sandbox(sh('if [ -f %s ]; then rm -f %s; exit 1; else exit 0; fi' % (marker, marker)))
before = open(p.fleet).read()
rr = stage(p, 1, "add-splice", "roll.example", 443)
ok(apply(p) == 3, "restart fails-then-ok -> clean rollback (3)")
ok(open(p.fleet).read() == before and not has_decision(p, rr), "rollback restored fleet + NO applied decision")
ok(not os.path.exists(lease_path(p, rr)) and len(os.listdir(L.node_path(p.base, L.NS_BATCHES))) == 0,
   "clean rollback releases the batch + lease")

# 9. DEGRADED: restart always fails -> apply fails AND rollback fails -> exit 4; batch+journal+lease RETAINED
p, _ = sandbox(sh("exit 1"))
dr = stage(p, 1008, "add-splice", "deg.example", 443)
ok(apply(p) == 4, "restart always-fails -> DEGRADED (4)")
ok(os.path.exists(lease_path(p, dr)) and len(os.listdir(L.node_path(p.base, L.NS_BATCHES))) == 1
   and len(os.listdir(L.node_path(p.base, L.NS_JOURNALS))) == 1,
   "DEGRADED retains the batch + journal + lease (recovery owns them)")

# 10. max_active enforced authoritatively AT COMMIT
p, _ = sandbox(sh("exit 0"), fleet='{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"one.example","port":443}],"egress":{"max_active":1}}')
stage(p, 1, "add-splice", "two.example", 443)
ok(apply(p) == 3, "approve refuses a batch exceeding max_active (nothing opened)")
ok("two.example" not in open(p.fleet).read(), "over-cap add did NOT reach fleet.json")

# 11. applied decision is SELF-ATTRIBUTING + binds the batch/digest/after_hash
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "attrib.example", 443)
ok(apply(p) == 0, "apply for the attribution case")
dec = json.load(open(dec_path(p, rid)))
ok(dec["owner_uid"] == 1008 and dec["op"] == "add-splice" and dec["host"] == "attrib.example" and dec["state"] == "applied",
   "applied decision carries owner_uid/op/host")
ok(isinstance(dec.get("batch_id"), str) and isinstance(dec.get("digest"), str) and dec.get("after_hash"),
   "applied decision binds batch_id + digest + after_hash (state-specific completion)")

# 12. mixed-case active fleet host IS removable
p, _ = sandbox(sh("exit 0"), fleet='{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"Gone.Example","port":443}]}')
stage(p, 1008, "remove-splice", "gone.example", 443)
ok(apply(p) == 0, "remove of a mixed-case active host applies")
fl = open(p.fleet).read()
ok("Gone.Example" not in fl and "gone.example" not in fl, "mixed-case host removed from fleet")

# 13. reject refuses a non-hex reqid; accepts a well-formed one
p, _ = sandbox(sh("exit 0"))
ok(A.cmd_reject(p, "../etc/passwd", "operator-declined") == 2, "reject refuses a path-like reqid (exit 2)")
ok(A.cmd_reject(p, "0123456789abcdef0123456789abcdef", "operator-declined") in (0, 1),
   "reject accepts a well-formed 32-hex reqid")

# 14. splice_allowlist:null is model-valid -> approve must NOT crash
p, _ = sandbox(sh("exit 0"), fleet='{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":null}')
stage(p, 1008, "add-splice", "nn.example", 443)
ok(apply(p) == 0 and "nn.example" in open(p.fleet).read(), "approve handles splice_allowlist:null; add applied")

# 15. JOURNAL recovery -- crash AFTER commit (fleet reflects add) before decisions: recovery FINISHES the
#     applied decision, removes lease, drops journal, removes batch
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "recov.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"recov.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "recov.example", 443, rid]], after_conf=conf_hash(p), after_fleet=fleet_hash(p))
ok(A._recover(p) == 0, "journal recovery resolves the committed batch (0 retained)")
ok(json.load(open(dec_path(p, rid)))["state"] == "applied", "journal recovery FINISHES the applied decision")
ok(not os.path.exists(jrnl_path(p, bid)) and not os.path.exists(lease_path(p, rid))
   and not os.path.exists(batch_path(p, bid)), "recovery drops journal + lease + batch")

# 15b. crash where the fleet does NOT reflect the add: recovery RELEASES (no applied), rerun re-applies
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "norecov.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
journal(p, bid, digest, [["add-splice", "norecov.example", 443, rid]])   # fleet still has NO splice
ok(A._recover(p) == 0 and not has_decision(p, rid), "un-committed journal writes NO applied decision")
ok(not os.path.exists(jrnl_path(p, bid)) and not os.path.exists(lease_path(p, rid)), "un-committed recovery releases")

# 16. reject refuses a LEASED (under-review) reqid
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1, "add-splice", "claimedhost.example", 443)
snapshot(p, [rid], R.new_batch_id())
ok(A.cmd_reject(p, rid, "operator-declined") == 3, "reject refuses a leased reqid")

# 17. recovery must NOT write applied unless squid is proven restarted + healthy (retain)
p, _ = sandbox(sh("exit 1"))       # restart FAILS -> _reconcile_squid unhealthy
rid = stage(p, 1008, "add-splice", "unhealthy.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"unhealthy.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "unhealthy.example", 443, rid]])
ok(A._recover(p) >= 1, "recovery RETAINS while squid unhealthy")
ok(not has_decision(p, rid), "recovery writes NO applied while squid is unhealthy")
ok(os.path.exists(jrnl_path(p, bid)) and os.path.exists(lease_path(p, rid)), "retains journal + lease when unhealthy")

# 18. a malformed ORPHAN journal (no batch) is dropped; a malformed journal WITH a live batch is RETAINED
p, _ = sandbox(sh("exit 0"))
bj = R.new_batch_id()
A._write_journal(p, bj, "d" * 64, [["add-splice", "x", 443, "a" * 32]], "f", "c")
os.remove(jrnl_path(p, bj))
open(jrnl_path(p, bj), "w").write('{"entries":[null]}')   # malformed, no batch
ok(A._recover(p) == 0 and not os.path.exists(jrnl_path(p, bj)), "malformed orphan journal dropped without crashing")
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "live.example", 443)
bid = R.new_batch_id()
snapshot(p, [rid], bid)
open(jrnl_path(p, bid), "w").write("{ not json")            # malformed journal for a LIVE batch
ok(A._recover(p) >= 1 and os.path.exists(jrnl_path(p, bid)), "malformed journal with a live batch is RETAINED (fail-closed)")

# 19. STATE-SPECIFIC completion: a rival EXPIRY terminal for a journal reqid -> CONFLICT -> hard-degraded.
#     Recovery STILL publishes the applied decision (the sink is open) then RETAINS journal+lease+batch as a
#     surfaced degraded pair -- it never cleans up under a rival terminal (arch §4).
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "conf.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"conf.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "conf.example", 443, rid]], after_conf=conf_hash(p), after_fleet=fleet_hash(p))
write_expiry(p, rid, host="conf.example")                  # a compromised drvps wrote a rival expiry terminal
ok(A._recover(p) >= 1, "rival expiry terminal -> journal RETAINED (hard-degraded)")
# arch: root MUST still publish its applied (the sink IS open); the rival expiry makes it a degraded pair
ok(has_decision(p, rid) and json.load(open(dec_path(p, rid)))["state"] == "applied",
   "recovery PUBLISHES the applied decision even under a rival expiry (records the open sink)")
ok(os.path.exists(jrnl_path(p, bid)) and os.path.exists(lease_path(p, rid)),
   "conflict retains journal + lease (degraded, surfaced -- not cleaned up)")

# 20. NON-JOURNALED batch at startup is provably abandoned (session lock) -> released (leases + batch)
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "abandoned.example", 443)
bid = R.new_batch_id()
snapshot(p, [rid], bid)                                    # snapshot WITHOUT a journal -> abandoned
ok(A._recover(p) == 0, "abandoned non-journaled batch recovery -> 0 retained")
ok(not os.path.exists(batch_path(p, bid)) and not os.path.exists(lease_path(p, rid)),
   "abandoned batch released (batch + lease gone), reqid returns to plain pending")

# 21. ORPHAN LEASE (batch + journal both gone) -> dropped
p, _ = sandbox(sh("exit 0"))
orphan = "a" * 32
cf = R.open_ns(p.base, *L.NS_CLAIMS)
try:
    R._atomic_publish(cf, orphan, R._lease_blob(orphan, "0" * 16, "d" * 64, 10 ** 12),
                      mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
finally:
    os.close(cf)
ok(A._recover(p) == 0 and not os.path.exists(lease_path(p, orphan)), "orphan lease (batch gone) dropped by recovery")

# 22. while a journal is RETAINED (unhealthy squid), a NEW apply ABORTS -- no new work, no false terminalize
p, _ = sandbox(sh("exit 1"))
rid = stage(p, 1008, "add-splice", "gated.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"gated.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "gated.example", 443, rid]])
ok(apply(p) == 4, "apply ABORTS while a journal is retained (recovery incomplete)")
ok(not has_decision(p, rid), "retained journal's reqid NOT terminalized as already-active")

# 23. an over-long (non-reqid) pending name does not crash apply (the reaper quarantines it; approve skips it)
p, _ = sandbox(sh("exit 0"))
stage(p, 1008, "add-splice", "okname.example", 443)
open(pend_path(p, "y" * 200), "w").write("{}")
ok(apply(p) == 0, "apply does not crash on an over-long pending name")
ok("okname.example" in open(p.fleet).read(), "the valid request applied despite the over-long neighbor")

# 24. DAMAGED store -> approve fails CLOSED (root-zone failure is loud, never silent 'no work')
p, _ = sandbox(sh("exit 0"))
os.chmod(L.node_path(p.base, L.NS_DECISIONS), 0o2700)      # wrong mode on a published node
try:
    A.cmd_list(p)
    ok(False, "cmd_list on a damaged store should raise LayoutError")
except L.LayoutError:
    ok(True, "damaged store raises LayoutError (fail closed)")
os.chmod(L.node_path(p.base, L.NS_DECISIONS), 0o2750)      # heal

# 25. ABSENT store -> degrade gracefully, create nothing
_ur = tempfile.mkdtemp(dir=TMP)
os.chmod(_ur, 0o755)
open(os.path.join(_ur, "fleet.json"), "w").write('{"mirror_allowlist":["deb.debian.org"]}')
open(os.path.join(_ur, "params.json"), "w").write(
    '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"/bin/true"}')
open(os.path.join(_ur, "hostfacts.json"), "w").write("{}")
_sq = os.path.join(_ur, "squid")
open(_sq, "w").write("#!/bin/sh\nexit 0\n")
os.chmod(_sq, 0o755)
pu = A.Paths(test_root=_ur, restart=sh("exit 0"), ids=IDS)   # NOT provisioned -> ABSENT
ok(pu.status() == L.ABSENT, "status() is ABSENT on a never-provisioned store")
ok(A.cmd_list(pu) == 0 and not os.path.exists(pu.base), "cmd_list on ABSENT store returns 0, creates NOTHING")
ok(apply(pu) == 0 and not os.path.exists(pu.base), "cmd_apply on ABSENT store returns 0, creates NOTHING")
ok(A.cmd_reject(pu, "0123456789abcdef0123456789abcdef", "operator-declined") == 2 and not os.path.exists(pu.base),
   "cmd_reject on ABSENT store refuses (2), creates NOTHING")
L.provision(pu.base, IDS)
ok(pu.status() == L.OK and A.cmd_list(pu) == 0, "after provisioning, status OK + root proceeds")

# 26. gc subcommand: recovery-clean + pending-aware retention GC of published decisions
p, _ = sandbox(sh("exit 0"))
old = R.new_reqid()
dfd = R.open_ns(p.base, *L.NS_DECISIONS)
try:
    R.write_published_decision(dfd, old, "applied", "applied", 100, group_gid=GID, owner_uid=UID, op="add-splice", host="old", port=443)
finally:
    os.close(dfd)
os.environ["DR_VPS_EGRESS_RETENTION_S"] = "10"
try:
    ok(A.cmd_gc(p) == 0, "gc subcommand returns 0 (recovery clean)")
finally:
    del os.environ["DR_VPS_EGRESS_RETENTION_S"]
ok(not has_decision(p, old), "gc removed the old pending-absent decision")

# 27. a RIVAL EXPIRY appearing DURING commit is a hard-degraded conflict. Root STILL publishes its
#     applied decision (the sink IS open), then RETAINS journal+batch+leases + returns 4 -- it never cleans up
#     an opened sink under a rival terminal. The restart hook (run mid-commit) plants the rival expiry.
_d = tempfile.mkdtemp(dir=TMP)
os.chmod(_d, 0o755)
open(os.path.join(_d, "fleet.json"), "w").write('{"mirror_allowlist":["deb.debian.org"]}')
os.chmod(os.path.join(_d, "fleet.json"), 0o600)
open(os.path.join(_d, "params.json"), "w").write(
    '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"/bin/true"}')
open(os.path.join(_d, "hostfacts.json"), "w").write("{}")
_sq2 = os.path.join(_d, "squid")
open(_sq2, "w").write("#!/bin/sh\nexit 0\n")
os.chmod(_sq2, 0o755)
_base = os.path.join(os.path.realpath(_d), "distro-rig-vps-egress")
_hookcode = ("#!/usr/bin/env python3\nimport sys, os\nsys.path.insert(0, %r)\n"
             "import drvps_egress_layout as L, drvps_egress_req as R\n"
             "pfd = R.open_ns(%r, *L.NS_PENDING); efd = R.open_ns(%r, *L.NS_EXPIRY)\n"
             "for n in R.list_names(pfd):\n"
             "    try: R.write_expiry_decision(efd, n, 1, owner_uid=%d, op='add-splice', host='x', port=443)\n"
             "    except Exception: pass\n"
             "os.close(pfd); os.close(efd); sys.exit(0)\n"
             % (os.path.join(HERE, "..", "tools"), _base, _base, UID))
_hook = tempfile.mktemp(dir=TMP)
open(_hook, "w").write(_hookcode)
os.chmod(_hook, 0o755)
p = A.Paths(test_root=_d, restart=[_hook], ids=IDS)
L.provision(p.base, IDS)
rid = stage(p, 1008, "add-splice", "rival.example", 443)
rc = apply(p)
ok(rc == 4, "rival expiry during commit -> hard-degraded (4), not completion")
# arch: root MUST publish its applied even under a rival expiry (records the OPEN sink) -> a degraded pair
ok(has_decision(p, rid) and json.load(open(dec_path(p, rid)))["state"] == "applied",
   "applied IS published (the sink is open); the rival expiry makes it degraded")
ok(len(os.listdir(L.node_path(p.base, L.NS_BATCHES))) == 1
   and len(os.listdir(L.node_path(p.base, L.NS_JOURNALS))) == 1
   and os.path.exists(lease_path(p, rid)),
   "journal + batch + lease RETAINED for recovery (degraded, not cleaned up)")

# 28. recovery with a NON-MATCHING applied decision (wrong batch/digest) -> conflict -> RETAIN
#     (never accept a foreign applied as completion, never erase the journal)
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "mismatch.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"mismatch.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "mismatch.example", 443, rid]], after_conf=conf_hash(p), after_fleet=fleet_hash(p))
dfd = R.open_ns(p.base, *L.NS_DECISIONS)      # a published applied bound to a DIFFERENT batch/digest
try:
    R.write_published_decision(dfd, rid, "applied", "applied", 1, group_gid=GID, owner_uid=UID,
                               op="add-splice", host="mismatch.example", port=443,
                               batch_id="e" * 16, digest="e" * 64, after_hash="e" * 64)
finally:
    os.close(dfd)
ok(A._recover(p) >= 1, "non-matching applied decision -> conflict -> retain")
ok(os.path.exists(jrnl_path(p, bid)), "journal retained (evidence not erased under a foreign applied)")

# 29. a SUSPECT (malformed) claim lease surfaces as a retained recovery fault (gates apply/gc)
p, _ = sandbox(sh("exit 0"))
sus = "a" * 32
cf = R.open_ns(p.base, *L.NS_CLAIMS)
try:
    R._atomic_publish(cf, sus, b"{ not a lease", mode=L.PUBLISHED_FILE_MODE, group_gid=GID)
finally:
    os.close(cf)
ok(A._recover(p) >= 1, "a suspect claim is a retained fault (fail closed, gates new work)")
ok(os.path.exists(lease_path(p, sus)), "suspect claim is NOT blindly removed")

# 30. a journal whose after_fleet_hash does NOT match the current fleet is NOT completed (a
#     non-rendered fleet field change cannot spoof completion via the rendered-conf hash alone) -> retained
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "fleetbind.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"fleetbind.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "fleetbind.example", 443, rid]], after_conf=conf_hash(p), after_fleet="0" * 64)
ok(A._recover(p) >= 1 and not has_decision(p, rid),
   "wrong after_fleet_hash -> NOT completed (retained, no applied) even though the conf matches")
ok(os.path.exists(jrnl_path(p, bid)), "journal retained on a fleet-hash mismatch")

# 31. owner binding: a pre-existing applied decision bound to THIS batch/digest/after but the
#     WRONG owner_uid is NOT accepted as ours -> conflict -> retain (never accept a misattributed decision)
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "ownerbind.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"ownerbind.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
ac = conf_hash(p)
journal(p, bid, digest, [["add-splice", "ownerbind.example", 443, rid]], after_conf=ac, after_fleet=fleet_hash(p))
dfd = R.open_ns(p.base, *L.NS_DECISIONS)             # a decision bound to our batch but the WRONG owner (9999)
try:
    R.write_published_decision(dfd, rid, "applied", "applied", 1, group_gid=GID, owner_uid=9999,
                               op="add-splice", host="ownerbind.example", port=443,
                               batch_id=bid, digest=digest, after_hash=ac)
finally:
    os.close(dfd)
ok(A._recover(p) >= 1 and os.path.exists(jrnl_path(p, bid)),
   "a wrong-owner applied decision -> conflict -> retained (not accepted as ours)")

# 32. SNAPSHOT AUTHORITY: recovery derives semantics from the frozen SNAPSHOT + authenticates the journal
#     against the manifest digest. A well-formed journal naming a DIFFERENT host/reqid with a FALSE digest is
#     rejected -> retained, NO applied for the journal's fabricated host (arch §7 snapshot authority).
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "authed.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)                     # the REAL manifest/snapshot digest (for authed.example)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"authed.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
# a well-formed journal for the SAME reqid but naming evil.example + carrying a FALSE (non-snapshot) digest
journal(p, bid, "e" * 64, [["add-splice", "evil.example", 443, rid]],
        after_conf=conf_hash(p), after_fleet=fleet_hash(p))
ok(A._recover(p) >= 1, "M-auth: journal digest != manifest digest -> retained (not completed)")
ok(not has_decision(p, rid), "M-auth: NO applied published for the fabricated journal entry")
ok(os.path.exists(jrnl_path(p, bid)), "M-auth: journal + batch retained as a hard fault")

# 33. result-hash vs reflected: a journal whose result hashes describe the PRE-commit fleet (the op
#     is NOT reflected in the live fleet) must NOT complete -> NO applied for the absent host; retained.
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "ghost.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
# fleet UNCHANGED (ghost.example ABSENT); the journal's after-hashes = the current (pre-commit) fleet/conf
journal(p, bid, digest, [["add-splice", "ghost.example", 443, rid]], after_conf=conf_hash(p), after_fleet=fleet_hash(p))
ok(A._recover(p) >= 1 and not has_decision(p, rid),
   "after-hashes match but the op is NOT reflected -> retained, NO false applied for the absent host")

# 34. SNAPSHOT AUTHORITY (post-authentication): a journal with the CORRECT digest but forged ENTRIES still
#     completes using the FROZEN snapshot values, never the journal's fabricated host.
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "authed2.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
committed = '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"authed2.example","port":443}]}\n'
A._atomic_install(p.fleet, committed, 0o600)
journal(p, bid, digest, [["add-splice", "evil.example", 443, rid]],   # forged entries; correct digest
        after_conf=conf_hash(p), after_fleet=fleet_hash(p))
ok(A._recover(p) == 0, "authenticated journal completes")
dec = json.load(open(dec_path(p, rid)))
ok(dec["host"] == "authed2.example" and dec["state"] == "applied",
   "snapshot authority: applied uses the FROZEN host, not the journal's forged evil.example")

# 35. terminal-aware release: a not-committed journal (op NOT reflected) that has a RIVAL EXPIRY
#     terminal must be RETAINED, never released/erased (hard-degraded evidence)
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "rivalrelease.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
write_expiry(p, rid, host="rivalrelease.example")   # a rival terminal, fleet UNCHANGED (op not reflected)
journal(p, bid, digest, [["add-splice", "rivalrelease.example", 443, rid]], after_conf="a" * 64, after_fleet="b" * 64)
ok(A._recover(p) >= 1, "not-committed batch WITH a rival terminal -> retained (not released)")
ok(os.path.exists(jrnl_path(p, bid)) and os.path.exists(lease_path(p, rid)),
   "journal + lease retained (evidence not erased)")

# 36. an exact applied decision + a fleet ROLLBACK (op no longer reflected) must RETAIN -- do not
#     erase the journal/batch/lease while leaving an inconsistent applied decision published
p, _ = sandbox(sh("exit 0"))
rid = stage(p, 1008, "add-splice", "rollback.example", 443)
bid = R.new_batch_id()
digest = snapshot(p, [rid], bid)
dfd = R.open_ns(p.base, *L.NS_DECISIONS)
try:
    R.write_published_decision(dfd, rid, "applied", "applied", 1, group_gid=GID, owner_uid=1008,
                               op="add-splice", host="rollback.example", port=443,
                               batch_id=bid, digest=digest, after_hash="c" * 64)
finally:
    os.close(dfd)
journal(p, bid, digest, [["add-splice", "rollback.example", 443, rid]], after_conf="a" * 64, after_fleet="b" * 64)
ok(A._recover(p) >= 1 and has_decision(p, rid),
   "applied decision + fleet rollback -> retained; the applied decision is NOT erased")
ok(os.path.exists(jrnl_path(p, bid)), "journal retained (inconsistent durable state surfaced)")

import shutil
shutil.rmtree(TMP, ignore_errors=True)
print("-------------------------------------------")
print("egress approve (v2): PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
