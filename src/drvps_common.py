#!/usr/bin/env python3
# drvps_common.py -- constants + env readers SHARED by the ingress accepter (drvps_rigsubmit.py) and
# the watcher (drvps_rigctl.py). Before this, each program carried its own copy of the request-id
# charset and the spool caps with COMMENT-ONLY parity ("identical to the watcher's ...") -- a drift
# hazard: widening one copy silently splits accept/reject behavior between the two
# daemons. One source of truth here fixes that. Both programs exec from src/ (their launchers run
# `python3 <root>/src/drvps_*.py`), so sys.path[0] is this file's dir and `import drvps_common` works.
# stdlib-only; no side effects on import.
import math
import os
import re

# A request id: charset-fenced, 1..128 chars. The ACCEPTER fast-fails on it and the WATCHER re-checks
# it (+ that filename == reqid) -- now identical BY CONSTRUCTION, not by comment.
REQID_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}\Z')   # \Z not $: Python $ matches before a trailing newline (shared accepter+watcher)


def cap_int(name, default, lo, hi):
    """Parse an integer env override DEFENSIVELY: malformed -> default, then clamp to [lo, hi].
    Both daemons are Restart=always, so a hand-edited value that raised at import would be a crash
    LOOP. lo stays 1 on the spool caps: legitimate small operator/test overrides survive, while a
    zero/negative override -- which would turn the accepter's read(cap+1) into an UNBOUNDED read,
    or the flood cap into reject-all -- cannot."""
    try:
        v = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def cap_float(name, default, lo, hi):
    """cap_int for float envs (timeouts). A non-FINITE parse (nan/inf) counts as malformed too:
    nan poisons min/max clamping and inf would hold a slow-loris socket forever."""
    try:
        v = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        v = default
    if not math.isfinite(v):
        v = default
    return max(lo, min(hi, v))


def req_max_bytes():
    """Max bytes of a single request (accepter read cap == watcher claim cap). DR_VPS_REQ_MAX_BYTES."""
    return cap_int("DR_VPS_REQ_MAX_BYTES", 1 << 20, 1, 1 << 30)


def max_pending():
    """Pending-request flood cap, shared by the accepter (early reject) + watcher (list cap)."""
    return cap_int("DR_VPS_MAX_PENDING", 256, 1, 1 << 20)


def write_all(fd, data):
    """Write ALL of `data` to fd, looping over partial writes. A bare os.write() can return
    a short count (POSIX-permitted; e.g. the filesystem fills mid-write), which -- unchecked -- would
    publish a TRUNCATED request/result/push temp as success. EINTR is retried; a 0-byte return with
    bytes remaining raises (no forward progress). Callers publish (rename/link/scp) only after this
    returns, so a truncated file is never made visible."""
    mv = memoryview(data)
    total = 0
    while total < len(mv):
        try:
            n = os.write(fd, mv[total:])
        except InterruptedError:            # EINTR -- retry the remaining bytes
            continue
        if n <= 0:
            raise OSError("short write: wrote %d of %d bytes (no progress)" % (total, len(mv)))
        total += n
    return total


def console_compact(path, cap):
    """Stage-1 console-log bound: tail-compact the console log at `path` to at most `cap` bytes, IN PLACE,
    via a NO-FOLLOW fd. Keeps a recent TAIL. BEST-EFFORT vs a concurrent virtlogd O_APPEND writer: bytes written
    during the compaction window may be DROPPED and a reader may transiently see a mixed file -- NOT a guaranteed
    contiguous suffix of the full stream (no file corruption). See README Known-limitations.
    REFUSES (raises) a symlink (O_NOFOLLOW -> ELOOP), a non-regular file, a file NOT owned by us
    (st_uid != geteuid -- a hijacked/relabelled path), or a hard-linked file (st_nlink != 1). Never unlinks or
    renames -- the inode is preserved, so virtlogd keeps writing to the same file. Returns 0 no-op (<=cap) or 1."""
    import stat as _stat
    if cap <= 0:
        raise ValueError("cap must be a positive integer")
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file: %s" % path)
        if st.st_uid != os.geteuid():
            raise OSError("not owned by us (uid %d != %d): %s" % (st.st_uid, os.geteuid(), path))
        if st.st_nlink != 1:
            raise OSError("hard-linked (nlink=%d): %s" % (st.st_nlink, path))
        if st.st_mode & 0o022:                              # group/other WRITE = tamper-injectable -> refuse
            raise OSError("group/other-writable (mode 0%o): %s" % (st.st_mode & 0o777, path))
        if st.st_size <= cap:
            return 0
        os.lseek(fd, st.st_size - cap, os.SEEK_SET)         # the last `cap` bytes = the tail
        data = b""
        while len(data) < cap:
            chunk = os.read(fd, cap - len(data))
            if not chunk:
                break
            data += chunk
        mv = memoryview(data)                               # rewrite the tail at offset 0 -- LOOP so a short
        off = 0                                             # pwrite can't leave a partial overwrite unreported
        while off < len(mv):
            k = os.pwrite(fd, mv[off:], off)
            if k <= 0:
                raise OSError("short pwrite (%d of %d): %s" % (off, len(mv), path))
            off += k
        os.ftruncate(fd, len(mv))                           # drop the old head/middle
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    import sys
    _a = sys.argv[1:]
    if len(_a) == 3 and _a[0] == "console-compact":
        try:
            console_compact(_a[1], int(_a[2]))
            sys.exit(0)
        except Exception as _e:                             # symlink/owner/nlink/non-regular/io -> refuse
            sys.stderr.write("console-compact: %s\n" % _e)
            sys.exit(3)
    sys.stderr.write("usage: drvps_common.py console-compact <path> <cap-bytes>\n")
    sys.exit(2)
