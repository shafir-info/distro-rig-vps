#!/usr/bin/env python3
"""drvps egress request STORE v2 -- single-writer-per-namespace protocol (docs/EGRESS-STORE-ARCH-UPGRADE.md).

v2 ends the recurring root<->drvps hazard class by giving every namespace exactly ONE writer under a
root-owned anchor (tools/drvps_egress_layout.py). This module is the store PRIMITIVE layer used by the
drvps member (writes `pending/`, `expiry/`; reads `published/`) and the root approve tool (reads `pending/`;
writes `root-private/{batches,journals}` and `published/{decisions,claims}`). Who-writes-what:

  pending/<reqid>              drvps writes (submit); root READS (hostile inbox)      0600 drvps:drvps
  expiry/<reqid>              drvps writes (expiry terminal); root READS             0600 drvps:drvps
  root-private/batches/<id>/  root writes (immutable snapshot + manifest)            0600/0700 root:root
  root-private/journals/<id>  root writes (commit journal)                           0600 root:root
  published/decisions/<reqid> root writes (applied|rejected terminal); drvps READS   0640 root:drvps
  published/claims/<reqid>    root writes (claim LEASE); drvps READS (skip expiry)   0640 root:drvps

State machine: pending -> (snapshot+lease = under review) -> (applied | rejected | expired). Terminals are
durable + NO-CLOBBER; FIRST terminal wins. reqid is a per-ATTEMPT nonce (new_reqid), so an add->remove->add
cycle and a retry-after-reject each get their own terminal and never alias a stale one. The request record
carries its own SO_PEERCRED-stamped owner_uid (v2 collapses the old `owner/` sidecar -- arch §4.5). ALL
cross-domain reads enforce an EXACT schema + regular-file + no-set-id + uid/gid + st_nlink==1 + size cap, so
a malformed / hardlinked / wrongly-owned record fails CLOSED instead of driving privileged state. ASCII only.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat

import drvps_egress_layout as L

SCHEMA_VER = 2
_REQID_RE = re.compile(r"\A[0-9a-f]{32}\Z")     # store reqid: a 32-hex per-attempt nonce
_BATCH_RE = re.compile(r"\A[0-9a-f]{16}\Z")     # batch id: a 16-hex nonce (batch dir + journal name)
_REASON_RE = re.compile(r"\A[a-z][a-z0-9-]{1,63}\Z")   # a rejected decision's reason CODE (lowercase)
REQ_FIELDS = frozenset(("ver", "reqid", "op", "host", "port", "owner_uid", "ts"))
OPS = frozenset(("add-splice", "remove-splice"))
MAX_REQ_BYTES = 4096
MAX_REC_BYTES = 8192                             # decisions/leases/manifests are a touch larger than a request
DECISION_STATES = frozenset(("applied", "rejected", "expired"))
_NS_MAX = 100000     # max dirents a single namespace scan EXAMINES (bounds memory + lock-hold on a mass-planted store)


class EgressReqError(ValueError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s%s" % (reason, (": " + detail) if detail else ""))
        self.reason = reason


def reqid_for(owner_uid: int, op: str, host: str, port: int) -> str:
    """The canonical TUPLE hash -- NOT the stored reqid (that is a per-attempt nonce); a stable comparison
    key for the member's in-flight dedup + tests."""
    key = "%d\x00%s\x00%s\x00%d" % (owner_uid, op, host, port)
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:32]


def new_reqid() -> str:
    return os.urandom(16).hex()


def new_batch_id() -> str:
    return os.urandom(8).hex()


# ---- symlink-safe, fd-relative store access -----------------------------------------------------
# A compromised drvps could plant a SYMLINK in a drvps-writable namespace to redirect the root reader, or
# swap an ancestor between a check and its use (TOCTOU). Defence: open the anchor's PARENT (root-owned) by
# path, then openat every component O_NOFOLLOW and hold the dir-fds. All enumeration is fd-relative + bounded.
# The anchor is root:drvps 0710 -- group has +x (traverse) but NOT +r, so O_RDONLY|O_DIRECTORY would EACCES
# for the drvps runtime. Traverse the anchor + intermediates with O_PATH (needs
# only +x); open the FINAL namespace dir the caller scandir's with O_RDONLY (drvps has +r on pending/expiry
# and the published subdirs). O_PATH fds work as dir_fd for openat/scandir'less traversal but not for read.
_O_TRAVERSE = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_O_READDIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _openat_dir(dir_fd, name):
    return os.open(name, _O_READDIR, dir_fd=dir_fd)


def _openat_traverse(dir_fd, name):
    return os.open(name, _O_TRAVERSE, dir_fd=dir_fd)


def open_base_fd(base):
    """A TRAVERSE-ONLY (O_PATH) dir-fd for the anchor, reached via a symlink-safe chain: open the anchor's
    PARENT by path (root-owned 0755 -> O_RDONLY ok), then openat the anchor O_PATH|O_NOFOLLOW (the anchor is
    0710, so group has only +x). Used solely as a base to descend. Caller closes. Raises OSError on a
    missing/symlinked base."""
    b = base.rstrip("/")
    parent, name = (os.path.dirname(b) or "/"), os.path.basename(b)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return _openat_traverse(pfd, name)
    finally:
        os.close(pfd)


def open_sub_fd(base_fd, *parts):
    """A READ dir-fd for base/<parts...>: traverse intermediates O_PATH|O_NOFOLLOW, open the FINAL component
    O_RDONLY|O_NOFOLLOW (the caller scandir's it). Caller closes. Raises OSError on any symlinked/missing
    component; ValueError if no parts (the anchor itself is 0710 and not readable by drvps -- callers always
    descend into a namespace)."""
    if not parts:
        raise ValueError("open_sub_fd requires at least one component")
    chain = []
    cur = base_fd
    try:
        for part in parts[:-1]:
            fd = _openat_traverse(cur, part)
            chain.append(fd)
            cur = fd
        # Open the FINAL component O_PATH|O_NOFOLLOW, verify it is a real directory, THEN obtain a readable
        # descriptor via it. O_PATH|O_NOFOLLOW reliably does NOT follow a symlink on every kernel (it returns
        # an fd to the symlink itself, which the S_ISDIR check then rejects) -- unlike a bare
        # O_RDONLY|O_DIRECTORY|O_NOFOLLOW, whose no-follow guarantee has been observed to vary on old kernels.
        lfd = _openat_traverse(cur, parts[-1])
        try:
            if not stat.S_ISDIR(os.fstat(lfd).st_mode):
                raise NotADirectoryError("not a directory (symlink?): %s" % parts[-1])
            return os.open(".", _O_READDIR, dir_fd=lfd)
        finally:
            os.close(lfd)
    finally:
        for fd in chain:
            os.close(fd)


def open_ns(base, *parts):
    """Convenience: a fresh dir-fd for the namespace base/<parts...> via the full symlink-safe chain."""
    bfd = open_base_fd(base)
    try:
        return open_sub_fd(bfd, *parts)
    finally:
        os.close(bfd)


def list_names(dir_fd, cap=_NS_MAX):
    """Bounded fd-relative listing (non-hidden names). The cap bounds every dirent EXAMINED (hidden entries
    still consume the budget), so a namespace stuffed with `.q.*` cannot be scanned to exhaustion under the
    lock. On overflow we FAIL CLOSED (raise) -- a namespace at the cap is far past the operator-gated live set."""
    out = []
    scanned = 0
    with os.scandir(dir_fd) as it:
        for e in it:
            scanned += 1
            if scanned > cap:
                raise EgressReqError("namespace-overflow", "%d+ entries" % cap)
            if e.name.startswith("."):
                continue
            out.append(e.name)
    return out


def _mkdirat_nofollow(parent_fd, name, mode):
    """openat `name` O_NOFOLLOW; mkdirat it if missing, then re-open. A symlink planted/raced at `name` ->
    ELOOP -> fail closed. (Used only by root in root-private, whose parents are all root-owned.)"""
    try:
        return _openat_dir(parent_fd, name)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        return _openat_dir(parent_fd, name)


def _fsync_dir(dir_fd):
    os.fsync(dir_fd)


def _write_all(fd, data):
    mv = memoryview(data)
    n = 0
    while n < len(mv):
        n += os.write(fd, mv[n:])


def _atomic_publish(dir_fd, name, data, mode=L.PRIVATE_FILE_MODE, group_gid=None):
    """Write `data` to a temp in the same dir, fsync, check `name` is ABSENT, then RENAME the temp to `name`
    (the atomic visibility commit) + fsync the dir. Raises EgressReqError('dup') if `name` already exists
    (first-wins). Rename (not link+unlink) leaves the published inode at st_nlink==1 with no transient
    nlink==2 window a crash could freeze into a permanently-rejected record. The
    absent-check + rename is race-free: EVERY caller holds the exclusive data lock, so no second writer
    contends `name`. fchmod forces the EXACT mode (umask-independent); group_gid sets the group for a
    published record so drvps can read it regardless of setgid inheritance."""
    if not isinstance(data, (bytes, bytearray)):
        raise EgressReqError("bad-type", "data")
    tmp = "." + name + ".tmp." + os.urandom(6).hex()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    try:
        if group_gid is not None:
            os.fchown(fd, -1, group_gid)         # set group only (owner stays the writer); drvps read edge
        os.fchmod(fd, mode)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        try:
            os.lstat(name, dir_fd=dir_fd)        # first-wins: refuse if `name` already exists (no clobber)
            raise EgressReqError("dup", name)
        except FileNotFoundError:
            pass
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)   # atomic; leaves st_nlink==1
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        raise
    _fsync_dir(dir_fd)


def _atomic_replace(dir_fd, name, data, mode=L.PUBLISHED_FILE_MODE, group_gid=None):
    """Like _atomic_publish but REPLACES an existing `name` (rename, not no-clobber link). Used for lease
    RENEWAL across the YES pause (arch §7). Same exact-mode + group semantics."""
    if not isinstance(data, (bytes, bytearray)):
        raise EgressReqError("bad-type", "data")
    tmp = "." + name + ".tmp." + os.urandom(6).hex()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    try:
        if group_gid is not None:
            os.fchown(fd, -1, group_gid)
        os.fchmod(fd, mode)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        _fsync_dir(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        raise


def _read_regular(dir_fd, name, expect_uid=None, expect_gid=None, expect_mode=None,
                  max_bytes=MAX_REQ_BYTES, require_nlink1=True):
    """openat O_NOFOLLOW|O_NONBLOCK; fstat regular + no-set-id + st_nlink==1 (mandatory -- blocks a
    DAC-override confused-reader onto an unexpected root-owned hardlink, arch §7) + optional owner/group/mode +
    size cap; return the bytes. O_NONBLOCK so a planted FIFO returns immediately instead of deadlocking the
    lock. expect_mode pins the EXACT permission bits (records are written with a fixed umask-independent mode,
    so a deviation is tamper/corruption -> fail closed)."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise EgressReqError("malformed-storage", "not-regular")
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise EgressReqError("malformed-storage", "set-id")
        if require_nlink1 and st.st_nlink != 1:
            raise EgressReqError("malformed-storage", "nlink=%d" % st.st_nlink)
        if expect_uid is not None and st.st_uid != expect_uid:
            raise EgressReqError("wrong-owner", name)
        if expect_gid is not None and st.st_gid != expect_gid:
            raise EgressReqError("wrong-group", name)
        if expect_mode is not None and stat.S_IMODE(st.st_mode) != expect_mode:
            raise EgressReqError("wrong-mode", "%s:%o" % (name, stat.S_IMODE(st.st_mode)))
        if st.st_size > max_bytes:
            raise EgressReqError("oversize", name)
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise EgressReqError("oversize", name)
    return data


def _quarantine_at(dir_fd, name):
    """Move a NON-REGULAR entry planted where a regular file is expected OUT of the live namespace via an
    O(1) rename to a hidden `.q.*` name (skipped by list_names). No recursion -> a deep/wide planted tree
    cannot DoS the sweep. drvps-only (root never mutates a drvps namespace in v2)."""
    try:
        os.rename(name, ".q." + name[:80] + "." + os.urandom(4).hex(), src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except OSError:
        pass


def _unlink_quiet(dir_fd, name):
    """Unlink name; return True iff it was actually removed (a FileNotFound or a quarantined non-regular
    entry -> False, so a caller counting real removals is accurate)."""
    try:
        os.unlink(name, dir_fd=dir_fd)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        _quarantine_at(dir_fd, name)
        return False


# ---- request lifecycle (drvps writes pending/) --------------------------------------------------
def _canonical(obj) -> bytes:
    """The canonical serialization of a store record (sorted keys, no whitespace). A record whose on-disk
    bytes differ from this is non-canonical (reordered keys, whitespace, or duplicate keys collapsed by the
    parser) -> rejected, closing the serialization-ambiguity surface (arch §7 canonical-byte rule)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("ascii")


def _canon_request(reqid, op, host, port, owner_uid, ts) -> bytes:
    return _canonical({"ver": SCHEMA_VER, "reqid": reqid, "op": op, "host": host, "port": port,
                       "owner_uid": owner_uid, "ts": ts})


def submit_request(pending_dir_fd, owner_uid, op, host, port, ts, reqid=None, group_gid=None) -> str:
    """Publish the pending request (the atomic visibility commit). v2 has NO owner sidecar -- the record
    carries its own owner_uid, which the member stamps from SO_PEERCRED (arch §4.5). `reqid` is a per-attempt
    nonce (the member passes a dedup-matched existing reqid for an idempotent republish). group_gid forces the
    record's group to the service group so the inbox is drvps:drvps even when the writer's PRIMARY group is not
    the service group (a supplemental-membership deploy). Returns the reqid."""
    if op not in OPS:
        raise EgressReqError("bad-type", "op")
    if not isinstance(owner_uid, int) or isinstance(owner_uid, bool) or owner_uid < 0:
        raise EgressReqError("wrong-owner", "uid")
    if reqid is None:
        reqid = new_reqid()
    req = _canon_request(reqid, op, host, port, owner_uid, ts)
    try:
        _atomic_publish(pending_dir_fd, reqid, req, mode=L.PRIVATE_FILE_MODE, group_gid=group_gid)
    except EgressReqError as e:
        if e.reason != "dup":                    # a re-published request for the same reqid is fine (idempotent)
            raise
    return reqid


def _parse_request(data, reqid) -> dict:
    try:
        obj = json.loads(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise EgressReqError("malformed-storage", reqid)
    if not isinstance(obj, dict) or set(obj) != REQ_FIELDS:
        raise EgressReqError("unknown-field", reqid)   # exact schema; reject unknown/missing
    # `op` must be a STRING before the membership test (`"op":[]` is unhashable -> TypeError aborts the sweep)
    if not isinstance(obj["op"], str) or obj["op"] not in OPS or obj["ver"] != SCHEMA_VER or obj["reqid"] != reqid:
        raise EgressReqError("malformed-storage", reqid)
    if not isinstance(obj["owner_uid"], int) or isinstance(obj["owner_uid"], bool) or obj["owner_uid"] < 0:
        raise EgressReqError("malformed-storage", "owner_uid")
    if not isinstance(obj["port"], int) or isinstance(obj["port"], bool) or not (0 < obj["port"] < 65536):
        raise EgressReqError("malformed-storage", "port")
    if not isinstance(obj["ts"], int) or isinstance(obj["ts"], bool):
        raise EgressReqError("malformed-storage", "ts")
    if not isinstance(obj["host"], str):
        raise EgressReqError("malformed-storage", "host")
    if data != _canonical(obj):                      # canonical-byte rule (arch §7): reject non-canonical bytes
        raise EgressReqError("malformed-storage", "non-canonical:" + reqid)
    return obj


def read_request(pending_dir_fd, reqid, expect_uid=None, expect_gid=None) -> dict:
    """Exact-schema read of a pending request (the hostile inbox). expect_uid/gid pin the record's
    authoritative owner (drvps); the mode is pinned to PRIVATE_FILE_MODE (records are written 0600, so a
    deviation is tamper). st_nlink==1 is mandatory (arch §7)."""
    data = _read_regular(pending_dir_fd, reqid, expect_uid=expect_uid, expect_gid=expect_gid,
                         expect_mode=L.PRIVATE_FILE_MODE)
    return _parse_request(data, reqid)


def read_owner_uid(pending_dir_fd, reqid, expect_uid=None, expect_gid=None) -> int:
    """The authoritative owner for reqid, from the request record itself (v2: no owner sidecar)."""
    return read_request(pending_dir_fd, reqid, expect_uid=expect_uid, expect_gid=expect_gid)["owner_uid"]


# ---- terminals (published/decisions = root; expiry = drvps; FIRST terminal wins) ----------------
def _decision_blob(reqid, state, reason, ts, owner_uid=None, op=None, host=None, port=None,
                   batch_id=None, digest=None, after_hash=None):
    # SELF-ATTRIBUTING terminal: owner_uid/op/host/port let a member poll one outcome by reqid. batch_id/
    # digest/after_hash bind an `applied` terminal to the exact batch + resulting state so root's journal
    # completion is state-specific (arch §4 root session lock).
    return json.dumps({"reqid": reqid, "state": state, "reason": reason, "ts": ts,
                       "owner_uid": owner_uid, "op": op, "host": host, "port": port,
                       "batch_id": batch_id, "digest": digest, "after_hash": after_hash},
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def write_published_decision(decisions_dir_fd, reqid, state, reason, ts, group_gid, **kw):
    """Root operator terminal (applied|rejected) into published/decisions/ (0640 root:drvps). Caller holds
    the data lock and has checked read_terminal() first. group_gid = the drvps gid (drvps read edge)."""
    if state not in ("applied", "rejected"):
        raise EgressReqError("bad-type", "published-state")
    _atomic_publish(decisions_dir_fd, reqid, _decision_blob(reqid, state, reason, ts, **kw),
                    mode=L.PUBLISHED_FILE_MODE, group_gid=group_gid)


def write_expiry_decision(expiry_dir_fd, reqid, ts, group_gid=None, **kw):
    """drvps watcher expiry terminal into expiry/ (0600 drvps:drvps). Caller holds the lock + skips leased
    reqids. group_gid forces the service group (supplemental-membership deploys)."""
    _atomic_publish(expiry_dir_fd, reqid, _decision_blob(reqid, "expired", "expired", ts, **kw),
                    mode=L.PRIVATE_FILE_MODE, group_gid=group_gid)


# a terminal record carries EXACTLY these keys (from _decision_blob); an unknown/missing key -> malformed.
_TERMINAL_FIELDS = frozenset(("reqid", "state", "reason", "ts", "owner_uid", "op", "host", "port",
                              "batch_id", "digest", "after_hash"))
_HEX16 = re.compile(r"\A[0-9a-f]{16}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _parse_terminal(data, reqid, want_states):
    """EXACT-schema parse of a terminal: exact key set, typed fields, valid state, and
    a valid state<->reason combo. A malformed terminal raises so it can never drive privileged state."""
    try:
        obj = json.loads(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise EgressReqError("malformed-storage", "decision:" + reqid)
    if not isinstance(obj, dict) or set(obj) != _TERMINAL_FIELDS:
        raise EgressReqError("malformed-storage", "decision-fields:" + reqid)
    if obj["reqid"] != reqid:
        raise EgressReqError("malformed-storage", "decision-reqid:" + reqid)
    st = obj["state"]
    if not isinstance(st, str) or st not in want_states:
        raise EgressReqError("malformed-storage", "decision-state:" + reqid)
    if not isinstance(obj["ts"], int) or isinstance(obj["ts"], bool):
        raise EgressReqError("malformed-storage", "decision-ts:" + reqid)
    reason = obj["reason"]
    if not isinstance(reason, str):
        raise EgressReqError("malformed-storage", "decision-reason:" + reqid)
    # state<->reason combo: applied->"applied", expired->"expired", rejected->a lowercase reason CODE
    if st == "applied" and reason != "applied":
        raise EgressReqError("malformed-storage", "decision-combo:" + reqid)
    if st == "expired" and reason != "expired":
        raise EgressReqError("malformed-storage", "decision-combo:" + reqid)
    if st == "rejected" and not _REASON_RE.match(reason):
        raise EgressReqError("malformed-storage", "decision-reason-code:" + reqid)
    # attribution + binding types (None allowed; when present, exact form + range)
    if obj["owner_uid"] is not None and (not isinstance(obj["owner_uid"], int)
                                         or isinstance(obj["owner_uid"], bool) or obj["owner_uid"] < 0):
        raise EgressReqError("malformed-storage", "decision-owner:" + reqid)
    if obj["port"] is not None and (not isinstance(obj["port"], int) or isinstance(obj["port"], bool)
                                    or not (0 < obj["port"] < 65536)):
        raise EgressReqError("malformed-storage", "decision-port:" + reqid)
    if obj["op"] is not None and (not isinstance(obj["op"], str) or obj["op"] not in OPS):
        raise EgressReqError("malformed-storage", "decision-op:" + reqid)
    if obj["host"] is not None and not isinstance(obj["host"], str):
        raise EgressReqError("malformed-storage", "decision-host:" + reqid)
    if obj["batch_id"] is not None and not (isinstance(obj["batch_id"], str) and _HEX16.match(obj["batch_id"])):
        raise EgressReqError("malformed-storage", "decision-batch:" + reqid)
    if obj["digest"] is not None and not (isinstance(obj["digest"], str) and _HEX64.match(obj["digest"])):
        raise EgressReqError("malformed-storage", "decision-digest:" + reqid)
    if obj["after_hash"] is not None and not (isinstance(obj["after_hash"], str) and _HEX64.match(obj["after_hash"])):
        raise EgressReqError("malformed-storage", "decision-afterhash:" + reqid)
    if data != _canonical(obj):                      # canonical-byte rule (arch §7)
        raise EgressReqError("malformed-storage", "decision-non-canonical:" + reqid)
    return obj


def read_published_decision(decisions_dir_fd, reqid, expect_uid=None, expect_gid=None):
    """Exact-schema read of a root decision (state in {applied,rejected}), pinned root:drvps 0640 (the
    published read edge). A malformed one raises so it can never clear pending. Returns dict or None if absent."""
    try:
        data = _read_regular(decisions_dir_fd, reqid, expect_uid=expect_uid, expect_gid=expect_gid,
                             expect_mode=L.PUBLISHED_FILE_MODE, max_bytes=MAX_REC_BYTES)
    except FileNotFoundError:
        return None
    return _parse_terminal(data, reqid, ("applied", "rejected"))


def read_expiry_decision(expiry_dir_fd, reqid, expect_uid=None, expect_gid=None):
    """Exact-schema read of a drvps expiry terminal (state=='expired'), pinned drvps:drvps 0600. Returns dict
    or None if absent."""
    try:
        data = _read_regular(expiry_dir_fd, reqid, expect_uid=expect_uid, expect_gid=expect_gid,
                             expect_mode=L.PRIVATE_FILE_MODE, max_bytes=MAX_REC_BYTES)
    except FileNotFoundError:
        return None
    return _parse_terminal(data, reqid, ("expired",))


def read_terminal(decisions_dir_fd, expiry_dir_fd, reqid, root_uid=None, svc_uid=None, svc_gid=None):
    """The single winning terminal for reqid, or None. A record in BOTH namespaces = corruption -> DEGRADED
    (raise), NEVER resolved by timestamp. Owners are pinned: published decision root:drvps, expiry drvps:drvps."""
    found = []
    d = read_published_decision(decisions_dir_fd, reqid, expect_uid=root_uid, expect_gid=svc_gid)
    if d is not None:
        found.append(d)
    e = read_expiry_decision(expiry_dir_fd, reqid, expect_uid=svc_uid, expect_gid=svc_gid)
    if e is not None:
        found.append(e)
    if len(found) > 1:
        raise EgressReqError("degraded", "two terminal records for " + reqid)
    return found[0] if found else None


# ---- snapshot batch (root writes root-private/batches + published/claims) ------------------------
# batches/<id>/ holds the immutable frozen request copies + a manifest (root-private). claims/<reqid>
# holds the drvps-visible LEASE (root:drvps), so the reaper skips expiry while a batch is under review.
def _digest(batch_id, policy, pairs):
    """Bind {batch_id, policy/fleet version, sorted (reqid, canonical bytes)} into a self-contained digest
    (arch §4 snapshot digest): the canonical request bytes carry owner_uid/op/host/port, so the digest fixes
    the full request identity AND the exact policy/fleet the batch was snapshotted against. Hashed over a
    CANONICAL JSON object (not delimiter concatenation), so no field content can shift the framing."""
    return hashlib.sha256(_canonical({"batch_id": batch_id, "policy": policy,
                                      "pairs": sorted([r, b] for r, b in pairs)})).hexdigest()


def _lease_blob(reqid, batch_id, digest, expires):
    return json.dumps({"ver": SCHEMA_VER, "reqid": reqid, "batch_id": batch_id, "digest": digest,
                       "expires": expires}, separators=(",", ":"), sort_keys=True).encode("ascii")


def snapshot_batch(reqids, pending_dir_fd, batches_dir_fd, claims_dir_fd, batch_id, claim_ts,
                   lease_expires, group_gid, policy, expect_uid=None, expect_gid=None):
    """Freeze `reqids` from pending into an immutable root-private batch, then publish drvps-visible claim
    leases. Ordering (arch §7): snapshot copies + manifest FIRST (root-private), THEN leases. Originals stay
    in pending (owner-visible). `policy` is the 64-hex policy/fleet version bound into the digest (required).
    expect_uid/gid pin each frozen request to drvps ownership at freeze time. Returns (batch_id, digest).
    Rolls back its own partial state on failure. A reqid whose lease already exists -> 'already-claimed'."""
    if not (isinstance(policy, str) and _HEX64.match(policy)):
        raise EgressReqError("bad-type", "policy")
    made_batch = False
    leased = []
    try:
        bdir = _mkdirat_nofollow(batches_dir_fd, batch_id, 0o700)   # root:root 0700
        made_batch = True
        os.close(bdir)
        bfd = open_sub_fd(batches_dir_fd, batch_id)
        try:
            pairs = []
            for reqid in reqids:
                obj = read_request(pending_dir_fd, reqid, expect_uid=expect_uid, expect_gid=expect_gid)
                blob = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("ascii")
                _atomic_publish(bfd, reqid, blob, mode=L.PRIVATE_FILE_MODE)   # frozen copy (root:root 0600)
                pairs.append((reqid, blob.decode("ascii")))
            digest = _digest(batch_id, policy, pairs)
            manifest = _canonical({"ver": SCHEMA_VER, "batch_id": batch_id, "reqids": sorted(reqids),
                                   "digest": digest, "policy": policy, "claim_ts": claim_ts})
            _atomic_publish(bfd, "manifest", manifest, mode=L.PRIVATE_FILE_MODE)   # root-private visibility commit
        finally:
            os.close(bfd)
        for reqid in reqids:                                        # THEN the drvps-visible leases
            try:
                _atomic_publish(claims_dir_fd, reqid, _lease_blob(reqid, batch_id, digest, lease_expires),
                                mode=L.PUBLISHED_FILE_MODE, group_gid=group_gid)
            except EgressReqError as e:
                raise EgressReqError("already-claimed", reqid) if e.reason == "dup" else e
            leased.append(reqid)
        return (batch_id, digest)
    except BaseException:
        for reqid in leased:
            _unlink_quiet(claims_dir_fd, reqid)
        if made_batch:
            _remove_batch_dir(batches_dir_fd, batch_id)
        raise


def _remove_batch_dir(batches_dir_fd, batch_id):
    """Remove batches/<id>/ (manifest + frozen copies + the dir). root-private, root-only -- no hostile
    content, so a bounded fd-relative unlink of each child then rmdir is safe."""
    try:
        bfd = open_sub_fd(batches_dir_fd, batch_id)
    except FileNotFoundError:
        return
    except OSError:
        _quarantine_at(batches_dir_fd, batch_id)
        return
    try:
        for name in list_names(bfd):
            _unlink_quiet(bfd, name)
        # also drop hidden temps
        try:
            with os.scandir(bfd) as it:
                leftovers = [e.name for e in it if e.name not in (".", "..")]
            for n in leftovers:
                _unlink_quiet(bfd, n)
        except OSError:
            pass
    finally:
        os.close(bfd)
    try:
        os.rmdir(batch_id, dir_fd=batches_dir_fd)
    except OSError:
        _quarantine_at(batches_dir_fd, batch_id)


def read_manifest(batches_dir_fd, batch_id, expect_uid=None) -> dict:
    """Exact-schema read of a batch manifest from root-private (root:root 0600)."""
    if not _BATCH_RE.match(batch_id):
        raise EgressReqError("malformed-storage", "batch-id:" + batch_id)
    bfd = open_sub_fd(batches_dir_fd, batch_id)
    try:
        data = _read_regular(bfd, "manifest", expect_uid=expect_uid, expect_mode=L.PRIVATE_FILE_MODE,
                             max_bytes=MAX_REC_BYTES)
    finally:
        os.close(bfd)
    try:
        obj = json.loads(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise EgressReqError("malformed-storage", "manifest:" + batch_id)
    reqids = obj.get("reqids") if isinstance(obj, dict) else None
    if (not isinstance(obj, dict)
            or set(obj) != frozenset(("ver", "batch_id", "reqids", "digest", "policy", "claim_ts"))
            or obj.get("ver") != SCHEMA_VER or obj.get("batch_id") != batch_id
            or not (isinstance(obj.get("digest"), str) and _HEX64.match(obj["digest"]))
            or not (isinstance(obj.get("policy"), str) and _HEX64.match(obj["policy"]))
            or not isinstance(obj.get("claim_ts"), int) or isinstance(obj.get("claim_ts"), bool)
            or not isinstance(reqids, list)
            or not all(isinstance(r, str) and _REQID_RE.match(r) for r in reqids)):
        raise EgressReqError("malformed-storage", "manifest:" + batch_id)
    if data != _canonical(obj):                      # canonical-byte rule (arch §7)
        raise EgressReqError("malformed-storage", "manifest-non-canonical:" + batch_id)
    return obj


def read_snapshot_request(batches_dir_fd, batch_id, reqid, expect_uid=None) -> dict:
    """Exact-schema read of a FROZEN request copy from the batch snapshot -- the ONE authoritative source
    after claim (arch §4: no second authoritative read from pending). Pinned root:root 0600."""
    bfd = open_sub_fd(batches_dir_fd, batch_id)
    try:
        data = _read_regular(bfd, reqid, expect_uid=expect_uid, expect_mode=L.PRIVATE_FILE_MODE)
    finally:
        os.close(bfd)
    return _parse_request(data, reqid)


def release_batch(batch_id, reqids, batches_dir_fd, claims_dir_fd):
    """Return a batch to plain pending: drop the drvps-visible LEASES first (reqids become expiry-eligible),
    then remove the root-private batch dir. Idempotent. Used for a non-YES abort + abandoned-batch recovery.
    NEVER call this once an `applied` terminal is being published (arch §7: never remove a lease before its
    terminal is durable -- the applied path removes leases only AFTER the decisions land)."""
    for reqid in reqids:
        _unlink_quiet(claims_dir_fd, reqid)
    _remove_batch_dir(batches_dir_fd, batch_id)


def renew_lease(claims_dir_fd, reqid, batch_id, digest, new_expires, group_gid):
    """Refresh a claim lease's expiry across the unbounded YES pause (arch §7 lease protocol)."""
    _atomic_replace(claims_dir_fd, reqid, _lease_blob(reqid, batch_id, digest, new_expires),
                    mode=L.PUBLISHED_FILE_MODE, group_gid=group_gid)


# lease read status (drvps reaper): NONE=no lease (expiry-eligible); FRESH/STALE=suppress expiry;
# SUSPECT=suppress expiry AND surface a root-zone failure (arch §7: a malformed/wrong-owner claim must
# never be treated as "no claim").
LEASE_NONE = "none"
LEASE_FRESH = "fresh"
LEASE_STALE = "stale"
LEASE_SUSPECT = "suspect"


_LEASE_FIELDS = frozenset(("ver", "reqid", "batch_id", "digest", "expires"))


def lease_status(claims_dir_fd, reqid, now, expect_root_uid, expect_svc_gid=None):
    """Return (status, lease_or_None). The lease is pinned root:drvps 0640 with an EXACT field set + formats;
    a wrongly-owned / malformed / mis-moded / unreadable / type-invalid lease is SUSPECT (suppress expiry AND
    surface a failure), NEVER NONE."""
    try:
        data = _read_regular(claims_dir_fd, reqid, expect_uid=expect_root_uid, expect_gid=expect_svc_gid,
                             expect_mode=L.PUBLISHED_FILE_MODE, max_bytes=MAX_REC_BYTES)
    except FileNotFoundError:
        return (LEASE_NONE, None)
    except (EgressReqError, OSError):
        return (LEASE_SUSPECT, None)
    try:
        obj = json.loads(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return (LEASE_SUSPECT, None)
    if (not isinstance(obj, dict) or set(obj) != _LEASE_FIELDS or obj.get("ver") != SCHEMA_VER
            or obj.get("reqid") != reqid
            or not (isinstance(obj.get("batch_id"), str) and _HEX16.match(obj["batch_id"]))
            or not (isinstance(obj.get("digest"), str) and _HEX64.match(obj["digest"]))
            or not isinstance(obj.get("expires"), int) or isinstance(obj.get("expires"), bool)
            or data != _canonical(obj)):             # canonical-byte rule (arch §7)
        return (LEASE_SUSPECT, obj if isinstance(obj, dict) else None)
    return (LEASE_FRESH if now < obj["expires"] else LEASE_STALE, obj)


# ---- pending-aware terminal GC (arch §4: BOTH terminal namespaces) -------------------------------
def _pending_set(pending_dir_fd):
    """The set of reqids currently in pending -- a bounded scan under the data lock. Raises namespace-overflow
    (fail closed) so a mass-planted inbox aborts the GC pass (removes ZERO terminals)."""
    return set(n for n in list_names(pending_dir_fd) if _REQID_RE.match(n))


def _gc_one_ns(term_fd, other_fd, pending_reqids, retention_s, now, expect_uid, expect_gid, read_fn):
    removed = 0
    names = list_names(term_fd)
    for name in names:
        if not _REQID_RE.match(name):
            continue                                   # never GC a non-reqid entry (leave for diagnosis)
        if name in pending_reqids:
            continue                                   # a surviving pending -> a crash mid-cleanup; keep the terminal
        # degraded pair (a terminal in BOTH namespaces) -> never independently collected (arch §4)
        try:
            os.lstat(name, dir_fd=other_fd)            # exists in the sibling namespace -> degraded pair
            continue
        except FileNotFoundError:
            pass                                       # absent in the sibling -> not degraded, proceed
        except OSError:
            continue                                   # sibling unreadable -> conservative: keep
        try:
            obj = read_fn(term_fd, name, expect_uid, expect_gid)
        except (EgressReqError, OSError):
            continue                                   # malformed -> RETAIN for diagnosis (GC != repair)
        if obj is None:
            continue
        ts = obj.get("ts")
        if isinstance(ts, int) and not isinstance(ts, bool) and now - ts >= retention_s:
            if _unlink_quiet(term_fd, name):        # count only a REAL removal
                removed += 1
    return removed


def gc_published_decisions(decisions_dir_fd, expiry_dir_fd, pending_dir_fd, retention_s, now,
                           expect_root_uid=None, expect_svc_gid=None) -> int:
    """Root-side retention GC over published/decisions/. Removes a terminal ONLY when a bounded pending scan
    proves pending/<reqid> absent AND no rival expiry terminal exists (degraded pairs retained). If pending
    is missing/overflowing/unreadable, removes ZERO (raises/aborts). GC is retention cleanup, NOT repair.
    Owner+group pinned root:drvps."""
    pend = _pending_set(pending_dir_fd)
    return _gc_one_ns(decisions_dir_fd, expiry_dir_fd, pend, retention_s, now, expect_root_uid,
                      expect_svc_gid, read_published_decision)


def gc_expiry(expiry_dir_fd, decisions_dir_fd, pending_dir_fd, retention_s, now, expect_svc_uid=None,
              expect_svc_gid=None) -> int:
    """drvps-side retention GC over expiry/. Same pending-aware + degraded-pair rules (arch §4). Pinned
    drvps:drvps."""
    pend = _pending_set(pending_dir_fd)
    return _gc_one_ns(expiry_dir_fd, decisions_dir_fd, pend, retention_s, now, expect_svc_uid,
                      expect_svc_gid, read_expiry_decision)
