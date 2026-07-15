#!/usr/bin/env python3
"""Tests the viewer trust-config grammar (tools/drvps_top_config.py). No I/O."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_top_config as C  # noqa

npass = [0]; nfail = [0]
def ok(c, m):
    if c: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", m)

VALID = ("# drvps-top viewer trust anchor\n"
         "feed_dir=/run/drvps-top\n"
         "feed_name=feed\n"
         "\n"
         "feed_uid=973\n"
         "feed_gid=972\n"
         "feed_mode=0640\n"
         "dir_mode=0710\n"
         "max_bytes=262144\n")

cfg = C.parse_config(VALID)
ok(cfg["feed_uid"] == 973 and cfg["feed_gid"] == 972, "valid uid/gid")
ok(cfg["feed_mode"] == 0o640 and cfg["dir_mode"] == 0o710, "valid modes")
ok(cfg["feed_dir"] == "/run/drvps-top" and cfg["feed_name"] == "feed", "valid path/name")
ok(cfg["max_bytes"] == 262144, "valid max_bytes")

def rej(text, reason, label):
    try:
        C.parse_config(text); ok(False, "%s should reject" % label)
    except C.ConfigError as e:
        ok(str(e) == reason, "%s -> '%s' (got '%s')" % (label, reason, e))

def mut(old, new):
    return VALID.replace(old, new, 1)

rej(mut("feed_uid=973\n", ""), "missing:feed_uid", "missing key")
rej(VALID + "feed_uid=1\n", "dup-key:feed_uid", "dup key")
rej(mut("feed_name=feed\n", "feed_name=feed\nbogus=1\n"), "unknown-key:bogus", "unknown key")
rej(mut("feed_uid=973", "feed_uid=0973"), "bad-int:feed_uid", "leading-zero uid")
rej(mut("feed_uid=973", "feed_uid=-1"), "bad-int:feed_uid", "negative uid")
rej(mut("feed_uid=973", "feed_uid=99999999999"), "range:feed_uid", "uid out of range")
rej(mut("feed_uid=973", "feed_uid=" + "9" * 5000), "bad-int:feed_uid", "huge-digit uid (length cap, no raw int cost)")
rej(mut("feed_mode=0640", "feed_mode=640"), "bad-mode:feed_mode", "non-octal mode")
rej(mut("feed_mode=0640", "feed_mode=0644"), "feed_mode-value", "wrong feed_mode")
rej(mut("dir_mode=0710", "dir_mode=0755"), "dir_mode-value", "wrong dir_mode")
rej(mut("max_bytes=262144", "max_bytes=131072"), "max_bytes-mismatch", "max_bytes mismatch")
rej(mut("feed_name=feed", "feed_name=../etc/x"), "feed_name", "feed_name traversal")
rej(mut("feed_name=feed", "feed_name=a/b"), "feed_name", "feed_name slash")
rej(mut("feed_dir=/run/drvps-top", "feed_dir=/run/../etc"), "feed_dir", "feed_dir traversal")
rej(mut("feed_dir=/run/drvps-top", "feed_dir=run/x"), "feed_dir", "feed_dir relative")
rej(VALID[:-1], "no-final-newline", "no final newline")
rej(mut("feed_name=feed\n", "feed_name=fe\x00ed\n"), "bad-byte", "nul byte")
rej(mut("feed_uid=973\n", "feed_uid\n"), "syntax", "no equals")

# ---- load_config(): the hostile-file gate around parse_config (O_NOFOLLOW, fstat regular
#      root:root, no group/world write, size cap). The require_uid/require_gid seam lets the
#      test validate against a file IT owns instead of root -- same code path, owner it can create.
import tempfile, shutil
MYUID = os.getuid(); MYGID = os.getgid()
TD = tempfile.mkdtemp(prefix="drvps-top-cfg-"); os.chmod(TD, 0o700)

def _mk(name, data=VALID, mode=0o644):
    p = os.path.join(TD, name)
    with open(p, "w") as fh: fh.write(data)
    os.chmod(p, mode)
    return p

def lrej(path, reason, label, **kw):
    kw.setdefault("require_uid", MYUID); kw.setdefault("require_gid", MYGID)
    try:
        C.load_config(path, **kw); ok(False, "%s should reject" % label)
    except C.ConfigError as e:
        ok(str(e) == reason, "%s -> '%s' (got '%s')" % (label, reason, e))

good = _mk("good.conf")
c = C.load_config(good, require_uid=MYUID, require_gid=MYGID)
ok(c["feed_uid"] == 973 and c["feed_mode"] == 0o640, "load_config success (own file)")

link = os.path.join(TD, "link.conf"); os.symlink(good, link)
try:
    C.load_config(link, require_uid=MYUID, require_gid=MYGID); ok(False, "symlink should raise")
except C.ConfigError:
    ok(False, "symlink raised ConfigError (want O_NOFOLLOW OSError)")
except OSError:
    ok(True, "symlink refused by O_NOFOLLOW")

adir = os.path.join(TD, "adir"); os.mkdir(adir)
lrej(adir, "config-not-regular", "directory not regular")
# FIFO must NOT block the open (O_NONBLOCK) and must reject as non-regular. A blocking
# open here would hang the whole suite; reaching this assert at all proves it did not block.
fifo = os.path.join(TD, "afifo"); os.mkfifo(fifo, 0o644)
lrej(fifo, "config-not-regular", "FIFO non-regular (open did not block)")
# wrong owner: require a uid that is NOT this file's owner regardless of who runs the test (root-safe).
lrej(good, "config-not-root-owned", "wrong owner", require_uid=MYUID + 1, require_gid=MYGID + 1)
lrej(_mk("gw.conf", mode=0o664), "config-group-world-writable", "group-writable")
lrej(_mk("setid.conf", mode=0o4644), "config-setid", "set-uid bit rejected")
lrej(_mk("big.conf", data="#c\n" * 3000), "config-too-large", "oversize (>8192)")

naf = os.path.join(TD, "na.conf")
with open(naf, "wb") as fh: fh.write(b"feed_dir=/run/x\n\xff\n")
os.chmod(naf, 0o644)
lrej(naf, "non-ascii", "non-ascii bytes surfaced as ConfigError")

# short read: fewer bytes than fstat's size (partial read of a small regular file is anomalous ->
# reject). Deterministic via a scoped os.read patch (C.os is the same module object).
_orig_read = os.read
os.read = lambda fd, n, _r=_orig_read: _r(fd, 1)  # always return 1 byte, < file size
try:
    lrej(good, "config-short-read", "short read (partial) rejected")
finally:
    os.read = _orig_read

lrej(_mk("bad.conf", data=mut("feed_mode=0640", "feed_mode=0644")),
     "feed_mode-value", "parse_config reason surfaced through load_config")

shutil.rmtree(TD, ignore_errors=True)

print("-------------------------------------------")
print("drvps-top config: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
