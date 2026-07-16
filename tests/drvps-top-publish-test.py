#!/usr/bin/env python3
"""Tests the drvps-top PUBLISHER producer (tools/drvps_top_publish.py) by ROUND-TRIPPING every built
frame through the validator drvps_top_feed.parse_validate (the oracle). No IO."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_top_publish as P  # noqa
import drvps_top_feed as F  # noqa

npass = [0]; nfail = [0]
def ok(c, m):
    if c: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", m)

ID = ["drvps-vm-%016x" % (0x1000 + i) for i in range(6)]
CLOCK = {"realtime_s": 1783960000, "boottime_ns": 5300000000000, "interval_ms": 3000}
HOST = {"load1_milli": 4880, "memavail_kib": 39000000, "host_cpu_count": 8}
OKSRC = {"db_status": "ok", "db_boottime_ns": 5300000000000,
         "libvirt_status": "ok", "libvirt_boottime_ns": 5300000000000,
         "stats_boottime_ns": 5300000000000}

def rec(vm_id, rc="normal", live="running", **over):
    r = dict(reconcile_class=rc, vm_id=vm_id, vm_name="weftg-x", store_state="running",
             live_state=live, vm_class="throwaway", base_kind="golden", base_distro="fedora44",
             base_hex="bc07c9f7", created_epoch=1783959000, cpu=3123, ram_cur=1572864,
             ram_max=1572864, domain_uuid="uuid-" + vm_id[-4:])
    r.update(over); return r

def build_ok(label, sources, records, live_domains=(), ownerpolicy="no", stats_ran=True, seq=1):
    try:
        blob = P.build_feed("pub-a1b2c3", seq, CLOCK, sources, HOST, records, live_domains,
                            ownerpolicy=ownerpolicy, stats_ran=stats_ran)
        h, rows = F.parse_validate(blob)          # the oracle: a producer must never emit a bad frame
        ok(True, "%s -> valid frame (%d rows)" % (label, len(rows)))
        return h, rows
    except (F.FeedError, P.PublishError, KeyError, TypeError) as e:
        ok(False, "%s -> BUILD/VALIDATE FAILED: %r" % (label, e))
        return None, None

def build_raises(label, sources, records):
    try:
        P.build_feed("pub-a1b2c3", 1, CLOCK, sources, HOST, records, (), stats_ran=True)
        ok(False, "%s should FAIL CLOSED" % label)
    except P.PublishError:
        ok(True, "%s -> PublishError (fail closed)" % label)

# 1. all sources ok: normal running (stats), normal shutoff, untracked, absent, uuid, name
h, rows = build_ok("all-ok mixed", OKSRC, [
    rec(ID[0]),                                   # normal running -> eligible, stats
    rec(ID[1], live="shutoff"),                   # normal shutoff -> no stats
    rec(ID[2], rc="untracked"),                   # projection
    rec(ID[3], rc="absent"),
    rec(ID[4], rc="uuid"),
    rec(ID[5], rc="name"),
], live_domains=[("web01", "u-other"), ("drvps-vm-" + "a"*16, "u-drvps")])
if h:
    ok(h["stats_status"] == "ok", "1 of 1 eligible present -> stats ok")
    d = {r["vm_id"]: r for r in rows}
    ok(d[ID[2]]["vm_name"] == "--" and d[ID[2]]["base_flag"] == "unknown" and d[ID[2]]["created_epoch"] == 0,
       "untracked projected")
    ok(d[ID[2]]["live_state"] == "running", "untracked live_state PRESERVED exactly (not fabricated)")
    ok(d[ID[3]]["live_state"] == "--", "absent live --")
    ok(h["c_untracked"] == 1 and h["c_absent"] == 1 and h["c_uuid"] == 1 and h["c_name"] == 1,
       "counters match rows")
    ok(h["c_other"] == 1, "c_other counts the non-drvps live domain")

# stats: single eligible with a sample -> ok
h2, _ = build_ok("stats ok", OKSRC, [rec(ID[0])])
ok(h2 and h2["stats_status"] == "ok", "one eligible present -> ok")

# partial: two eligible, one missing sample
h3, _ = build_ok("stats partial", OKSRC,
                 [rec(ID[0]), rec(ID[1], cpu=None, ram_cur=None, ram_max=None)])
ok(h3 and h3["stats_status"] == "partial", "one eligible missing -> partial")

# 2. db stale (masked) -> all unreconciled, counters 0
h4, rows4 = build_ok("db-stale masked", dict(OKSRC, db_status="stale"),
                     [rec(ID[0]), rec(ID[1], rc="absent")])
if h4:
    ok(all(r["reconcile_class"] == "unreconciled" for r in rows4), "masked -> all unreconciled")
    ok(h4["c_absent"] == 0 and h4["c_other"] == 0, "masked -> counters 0")

# 3. libvirt down -> all unreconciled + unknown, stats down
h5, rows5 = build_ok("libvirt-down", dict(OKSRC, libvirt_status="down", libvirt_boottime_ns=0),
                     [rec(ID[0])])
if h5:
    ok(all(r["live_state"] == "unknown" for r in rows5), "libvirt down -> live unknown")
    ok(h5["stats_status"] == "down", "libvirt down -> stats down")

# 4. owner policy uid: untracked owner forced to '-'
h6, rows6 = build_ok("owner uid", OKSRC,
                     [rec(ID[0], owner_display="1008"), rec(ID[2], rc="untracked", owner_display="9999")],
                     ownerpolicy="uid")
if h6:
    du = {r["vm_id"]: r for r in rows6}
    ok(du[ID[0]]["owner_display"] == "1008", "normal keeps owner")
    ok(du[ID[2]]["owner_display"] == "-", "untracked owner forced to -")

# 5. FAIL CLOSED on an invalid/missing live_state for a live-backed class (never fabricate)
build_raises("normal bad live_state", OKSRC, [rec(ID[0], live="future-state")])
build_raises("untracked missing live_state", OKSRC, [rec(ID[2], rc="untracked", live=None)])

# 6. masked untracked -> projected to sentinels (provenance), even though rc is now unreconciled
hm, rm = build_ok("masked untracked projection", dict(OKSRC, db_status="stale"),
                  [rec(ID[2], rc="untracked", owner_display="9999")], ownerpolicy="uid")
if hm:
    u = rm[0]
    ok(u["reconcile_class"] == "unreconciled" and u["vm_name"] == "--" and u["store_state"] == "unknown"
       and u["vm_class"] == "--" and u["base_flag"] == "unknown" and u["created_epoch"] == 0
       and u["owner_display"] == "-", "masked untracked fully projected (no store/owner leak)")

# 7. a bad/incomplete stats tuple -> `--`, NEVER aborts the publish
hb, rb = build_ok("bad stats tuple -> --", OKSRC, [rec(ID[0], ram_max=None)])           # one RAM missing
ok(hb and rb[0]["cpu"] is None, "incomplete stats tuple dropped to --")
hb2, rb2 = build_ok("ram_cur>ram_max -> --", OKSRC, [rec(ID[0], ram_cur=9, ram_max=1)])
ok(hb2 and rb2[0]["cpu"] is None, "invalid ram order dropped to --")

# 7b. absolute stats field caps (independent of the relational cpu<=host*1000 check) -> `--`, not abort
def build_host(label, host, records):
    try:
        h, rows = F.parse_validate(P.build_feed("pub-a1b2c3", 1, CLOCK, OKSRC, host, records, (), stats_ran=True))
        ok(rows[0]["cpu"] is None, label)
    except (F.FeedError, P.PublishError) as e:
        ok(False, "%s -> %r" % (label, e))
build_host("cpu over field cap (1e6) -> --", {"load1_milli": 1, "memavail_kib": 1, "host_cpu_count": 2000},
           [rec(ID[0], cpu=1000001)])
build_host("ram over 2^63-1 -> --", HOST, [rec(ID[0], ram_cur=1 << 63, ram_max=1 << 63)])

# 8. c_other: an absent/uuidbad record does NOT suppress a same-uuid non-drvps live domain
hc, _ = build_ok("c_other claim filter", OKSRC,
                 [rec(ID[3], rc="absent", domain_uuid="shared")],
                 live_domains=[("web01", "shared")])
ok(hc and hc["c_other"] == 1, "absent record does not claim the live uuid -> c_other=1")

# 9. ran with ZERO eligible VMs -> stats ok (trivially), not down
hz, _ = build_ok("zero-eligible stats", OKSRC, [rec(ID[1], live="shutoff")])
ok(hz and hz["stats_status"] == "ok", "zero eligible + ran -> ok")

# 10. db down + records -> status-only (no rows)
hd, rd = build_ok("db-down status-only", dict(OKSRC, db_status="down", db_boottime_ns=0),
                  [rec(ID[0]), rec(ID[1])])
ok(hd and len(rd) == 0, "db down -> no rows (status-only)")

# ---- store_gate SEMANTIC enforcement: a same-named NON-unique index / no-op (RAISE-free) trigger must be
# REFUSED, not blessed by name (a corrupt/half-migrated store store_init would reject must not run) ----
import sqlite3  # noqa
def _mkstore(idx, trg_ins):
    c = sqlite3.connect(":memory:"); c.text_factory = bytes   # production connect_ro uses text_factory=bytes
    c.executescript(
        "CREATE TABLE vms(owner_uid TEXT,class TEXT,domain_uuid TEXT,artifact_id TEXT,state TEXT,name TEXT,created_at TEXT);"
        "CREATE TABLE images(kind TEXT,name TEXT,provenance TEXT,artifact_id TEXT);"
        "CREATE TABLE snapshots(id TEXT,parent_golden_id TEXT,secret_bearing INT,validation_status TEXT,created_at TEXT,name TEXT);"
        + idx + "CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);" + trg_ins +
        "CREATE TRIGGER images_kind_upd BEFORE UPDATE OF kind ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'x'); END;"
        "CREATE TRIGGER snapshots_ins BEFORE INSERT ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'x'); END;"
        "CREATE TRIGGER snapshots_upd BEFORE UPDATE ON snapshots WHEN NEW.name IS NULL BEGIN SELECT RAISE(ABORT,'x'); END;")
    return c
_UNIQ = "CREATE UNIQUE INDEX images_kind_name_uq ON images(kind,name);"
_NON = "CREATE INDEX images_kind_name_uq ON images(kind,name);"
_RA = "CREATE TRIGGER images_kind_ins BEFORE INSERT ON images WHEN NEW.kind NOT IN ('golden','snapshot') BEGIN SELECT RAISE(ABORT,'x'); END;"
_NO = "CREATE TRIGGER images_kind_ins BEFORE INSERT ON images BEGIN SELECT 1; END;"
def _gate_ok(idx, trg):
    try: P.store_gate(_mkstore(idx, trg)); return True
    except P.StoreGateError: return False
ok(_gate_ok(_UNIQ, _RA), "store_gate ACCEPTS correct enforcement objects")
ok(not _gate_ok(_NON, _RA), "store_gate REJECTS a same-named NON-unique index")
ok(not _gate_ok(_UNIQ, _NO), "store_gate REJECTS a no-op (RAISE-free) trigger")

print("-------------------------------------------")
print("drvps-top-publish: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
