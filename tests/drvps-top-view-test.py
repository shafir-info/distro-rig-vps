#!/usr/bin/env python3
"""Tests the drvps-top VIEWER render core (tools/drvps_top_view.py) against the committed byte-exact
feed fixtures (parse_validate -> render_frame). No IO beyond reading the fixtures."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_top_view as V  # noqa
import drvps_top_feed as F  # noqa

FIXD = os.path.join(HERE, "..", "docs", "drvps-top-share-fixtures")
npass = [0]; nfail = [0]
def ok(c, m):
    if c: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", m)

def load(name):
    with open(os.path.join(FIXD, name), "rb") as fh:
        return F.parse_validate(fh.read())

# valid-anomalies: every unmasked reconcile class + nonzero counters
h, rows = load("valid-anomalies.feed")
BT = h["boottime_ns"]
frame = V.render_frame(h, rows, BT + h["interval_ms"] * 1000000)   # fresh
ok(frame.startswith("drvps-top  seq="), "header line")
ok("[STALE]" not in frame, "fresh frame not stale")
ok("absent 1 uuid 1 name 1 untracked 1" in frame, "anomaly counters rendered")
ok(all(r["vm_id"] in frame for r in rows), "every VM row rendered")
ok("NAME" in frame and "STORE" in frame and "AGE" in frame, "name/store/age columns present")
ok(any(r["vm_name"] in frame for r in rows if r["vm_name"] != "--"), "a vm_name value rendered")
ok(any(r["store_state"] in frame for r in rows), "a store_state value rendered")
ok(frame.endswith("\n"), "trailing newline")

# staleness: dt beyond STALE_MULT intervals -> [STALE]
old = V.render_frame(h, rows, BT + (V.STALE_MULT + 2) * h["interval_ms"] * 1000000)
ok("[STALE]" in old, "beyond STALE_MULT -> stale")
ok(V.is_stale(h, BT - 1), "negative dt -> stale")
ok(V.is_stale({"boottime_ns": 0, "interval_ms": 3000}, 10), "boottime 0 -> stale")

# libvirt-down fixture: rows show unknown/unreconciled, banner shows libvirt:down
h2, rows2 = load("valid-libvirt-down.feed")
f2 = V.render_frame(h2, rows2, h2["boottime_ns"] + 1000)
ok("libvirt:down" in f2, "libvirt down banner")
ok("unknown" in f2 and "unreconciled" in f2, "masked rows rendered")

# owner-uid fixture renders owner column
h3, rows3 = load("valid-owneruid.feed")
f3 = V.render_frame(h3, rows3, h3["boottime_ns"] + 1000)
ok("owner=" in f3, "owner column when ownerpolicy != no")

# empty fixture
h4, rows4 = load("valid-empty.feed")
ok("(no tracked VMs)" in V.render_frame(h4, rows4, h4["boottime_ns"] + 1000), "empty -> placeholder")

# ---- hostile-file OPEN protocol (sec 7.2/7.3): drive read_feed against a REAL feed dir/file --------
import io, shutil, stat, tempfile
import drvps_top_config as C  # noqa

UID, GID = os.getuid(), os.getgid()
GOOD = open(os.path.join(FIXD, "valid-anomalies.feed"), "rb").read()


def _setup(tmp, feed_bytes=GOOD, feed_mode=0o640, dir_mode=0o710, feed_uid=None, feed_gid=None):
    fdir = os.path.join(tmp, "run"); os.mkdir(fdir); os.chmod(fdir, dir_mode)
    feed = os.path.join(fdir, "feed"); open(feed, "wb").write(feed_bytes); os.chmod(feed, feed_mode)
    conf = os.path.join(tmp, "viewer.conf")
    open(conf, "w").write("feed_dir=%s\nfeed_name=feed\nfeed_uid=%d\nfeed_gid=%d\n"
                          "feed_mode=0640\ndir_mode=0710\nmax_bytes=262144\n"
                          % (fdir, UID if feed_uid is None else feed_uid, GID if feed_gid is None else feed_gid))
    os.chmod(conf, 0o644)
    return fdir, feed, C.load_config(path=conf, require_uid=UID, require_gid=GID)


def _rejects(cfg, label):
    try:
        V.read_feed(cfg); ok(False, "%s NOT rejected" % label)
    except (F.FeedError, C.ConfigError, OSError):
        ok(True, "%s rejected" % label)


T = tempfile.mkdtemp()
try:
    fdir, feed, cfg = _setup(T)
    hh, rr = V.read_feed(cfg)
    ok(hh["seq"] == h["seq"] and len(rr) == len(rows), "read_feed: valid feed parses via the shared contract")
    # symlink planted at feed -> O_NOFOLLOW rejects
    os.remove(feed); os.symlink("/etc/passwd", feed); _rejects(cfg, "symlink feed")
    os.remove(feed); open(feed, "wb").write(GOOD)
    # wrong mode 0644 (must be exactly 0640)
    os.chmod(feed, 0o644); _rejects(cfg, "wrong-mode feed"); os.chmod(feed, 0o640)
    # hardlink -> nlink 2
    ln = os.path.join(fdir, "h2"); os.link(feed, ln); _rejects(cfg, "nlink>1 feed"); os.remove(ln)
    # owner mismatch vs the trust anchor (config claims a different feed_uid)
    _, _, cfg_wrong = _setup(tempfile.mkdtemp(dir=T), feed_uid=UID + 12345)
    _rejects(cfg_wrong, "owner-mismatch feed")
    # oversize (> max_bytes) -> rejected while reading
    big = os.path.join(T, "big"); os.mkdir(big); os.chmod(big, 0o710)
    bf = os.path.join(big, "feed"); open(bf, "wb").write(b"H\t" + b"x" * (F.MAX_BYTES + 10)); os.chmod(bf, 0o640)
    bc = os.path.join(T, "bigconf"); open(bc, "w").write(
        "feed_dir=%s\nfeed_name=feed\nfeed_uid=%d\nfeed_gid=%d\nfeed_mode=0640\ndir_mode=0710\nmax_bytes=262144\n" % (big, UID, GID))
    os.chmod(bc, 0o644); _rejects(C.load_config(path=bc, require_uid=UID, require_gid=GID), "oversize feed")
    # NUL byte
    os.remove(feed); open(feed, "wb").write(GOOD[:10] + b"\x00" + GOOD[10:]); os.chmod(feed, 0o640); _rejects(cfg, "NUL feed")
    os.remove(feed); open(feed, "wb").write(GOOD); os.chmod(feed, 0o640)
    # wrong dir mode
    os.chmod(fdir, 0o755); _rejects(cfg, "wrong dir-mode"); os.chmod(fdir, 0o710)
    # poll_once keeps last-good frame + a FIXED error line on a bad poll (never echoes feed bytes)
    parsed, good = V.poll_once(cfg); ok(parsed is not None, "poll_once: good frame parsed")
    os.chmod(feed, 0o644)
    parsed2, err = V.poll_once(cfg)
    ok(parsed2 is None and err.startswith("drvps-top: no valid feed"), "poll_once: bad poll -> fixed local error, no feed bytes")
    os.chmod(feed, 0o640)
    # run --once returns 0 on a valid frame
    buf = io.StringIO(); ok(V.run(cfg, once=True, out=buf) == 0 and buf.getvalue().startswith("drvps-top"),
                            "run --once: valid frame -> rc 0")
finally:
    shutil.rmtree(T, ignore_errors=True)

print("-------------------------------------------")
print("drvps-top-view: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
