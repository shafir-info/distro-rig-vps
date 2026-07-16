#!/usr/bin/env python3
# drvps-rigsubmit -- the ONLY agent ingress to the Phase-2 control-loop spool.
#
# Runs as the never-root service user (drvps) behind a systemd socket unit with Accept=yes: the
# connected AF_UNIX stream is handed to us as stdin/stdout. We read ONE bounded JSON request, validate
# its reqid + size, and atomically write it into the drvps-ONLY requests/ dir (mode 0700). Then we
# reply a single line: "OK <reqid>" or "ERR <reason>".
#
# WHY a socket instead of a shared spool dir: requests/ used to be group-writable (drvpsctl) so the
# agent could drop request files directly -- but that also let the agent `mkdir requests/x.json/`,
# `chmod 000` it, and fill it with data. A NEVER-ROOT watcher cannot reclaim a 000 agent-owned
# directory (it can rmdir an EMPTY child of its sticky parent, but cannot traverse a 000 dir to empty
# it first, and cannot chmod a dir it does not own) -> an unbounded host disk/inode DoS with no
# non-root remedy. Making requests/ drvps-only and routing every submit through this accepter closes
# the class STRUCTURALLY (the agent can no longer create any filesystem entry there) while keeping the
# whole runtime never-root. This accepter stays deliberately THIN: it does NOT validate verbs/args --
# the watcher remains the single authoritative validator of request semantics, so this ingress adds
# the smallest possible new attack surface.
import os, sys, json, signal, errno, ctypes, socket, struct
import drvps_common   # shared REQID_RE + spool caps (one source of truth with the watcher; H-3)

_libc = ctypes.CDLL(None, use_errno=True)
_RENAME_NOREPLACE = 1                                    # linux/fs.h RENAME_NOREPLACE
try:
    _libc.renameat2.restype = ctypes.c_int
    _libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _HAVE_RENAMEAT2 = True
except AttributeError:
    _HAVE_RENAMEAT2 = False


def _rename_noreplace(old_dirfd, oldname, new_dirfd, newname):
    """Atomic NO-CLOBBER publish via renameat2(RENAME_NOREPLACE). Unlike os.rename() it FAILS with
    EEXIST if the destination already exists instead of silently replacing it -- so a second submit of
    an already-pending reqid cannot overwrite the first (a malicious co-agent in the drvpsctl group
    must not be able to clobber another agent's pending request by reusing/guessing its reqid). It also
    keeps nlink==1 (the watcher's claim rejects nlink!=1), unlike a link()+unlink() publish which would
    briefly expose the final at nlink==2. Fail CLOSED (ENOSYS) rather than fall back to a clobbering
    rename if the syscall is somehow unavailable."""
    if not _HAVE_RENAMEAT2:
        raise OSError(errno.ENOSYS, "renameat2 unavailable")
    if _libc.renameat2(old_dirfd, oldname.encode(), new_dirfd, newname.encode(), _RENAME_NOREPLACE) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


REQID_RE     = drvps_common.REQID_RE                     # shared with the watcher (one source of truth)
SPOOL        = os.environ.get("DR_VPS_SPOOL_DIR", "/var/spool/distro-rig-vps")
REQ_MAX      = drvps_common.req_max_bytes()              # == the watcher's req_max
MAX_PENDING  = drvps_common.max_pending()                # == the watcher's flood cap
READ_TIMEOUT = drvps_common.cap_float("DR_VPS_SUBMIT_READ_TIMEOUT", 5.0, 0.1, 3600.0)   # defeat a slow-loris socket hold; defensive parse (malformed would crash EVERY connection)


def _peer_uid():
    """The connecting client's uid, read UNFORGEABLY from the kernel via SO_PEERCRED on the connected
    AF_UNIX stream (fd 0 under Accept=yes). The kernel stamps the peer's credentials at connect(); a
    client cannot spoof them, so this -- not any field in the request JSON -- is the ONLY authority on
    who is asking. We dup(0) so closing the wrapper never touches the real stdin fd. Returns the uid, or
    None if it cannot be read (the caller then fails the submit CLOSED: a request whose owner we cannot
    establish must not be spooled)."""
    try:
        dfd = os.dup(0)
    except OSError:
        return None
    try:
        s = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM, fileno=dfd)
    except OSError:
        try:
            os.close(dfd)
        except OSError:
            pass
        return None
    try:
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; }. pid_t is SIGNED but uid_t/gid_t are UNSIGNED
        # 32-bit -- so unpack as "iII", NOT "3i" : a real client uid >= 2^31 (systemd-homed,
        # enterprise NSS, nfs idmap, large uid-maps) would otherwise stamp a NEGATIVE owner_uid, which the
        # watcher rejects -- locking that client out of EVERY verb (owner_uid is stamped on all requests).
        creds = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII"))
        _pid, uid, _gid = struct.unpack("iII", creds)
        return uid
    except OSError:
        return None
    finally:
        s.close()   # closes the dup, not fd 0


def _reply(line):
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def _fail(reason):
    # A rejected submit is a NORMAL outcome (bad input / over capacity), not a unit failure: reply
    # ERR and exit 0 so systemd does not treat a hostile/oversized payload as a crashing service.
    _reply("ERR " + reason)
    sys.exit(0)


def main():
    reqdir = os.path.join(SPOOL, "requests")

    # Bounded, timeout-guarded read: a peer that connects and dribbles (or never sends EOF) must not
    # pin an Accept=yes instance forever. SIGALRM fires -> ERR + exit.
    signal.signal(signal.SIGALRM, lambda *_a: _fail("read timeout"))
    signal.setitimer(signal.ITIMER_REAL, READ_TIMEOUT)
    try:
        data = sys.stdin.buffer.read(REQ_MAX + 1)
    except Exception:
        _fail("read error")
    signal.setitimer(signal.ITIMER_REAL, 0)

    if not data:
        _fail("empty request")
    if len(data) > REQ_MAX:
        _fail("request too large")
    try:
        obj = json.loads(data)
    except Exception:
        _fail("not valid JSON")
    if not isinstance(obj, dict):
        _fail("request not an object")
    reqid = obj.get("reqid")
    if not isinstance(reqid, str) or not REQID_RE.match(reqid):
        _fail("bad reqid")

    # OWNER STAMP (security anchor): overwrite any client-supplied owner_uid with the kernel-verified
    # peer uid. The watcher scopes snapshot ownership to this value, so it MUST come from SO_PEERCRED and
    # never from a field the client controls -- otherwise client B could forge owner_uid=<A> and act on
    # A's snapshots. Fail CLOSED if the peer uid is unreadable (never spool an unattributable request).
    # We then re-serialize the request we actually write so the stamped value is what the watcher sees;
    # the watcher re-parses JSON, so the compact re-encoding is semantically identical to the original.
    uid = _peer_uid()
    if uid is None:
        _fail("cannot read peer credentials")
    obj["owner_uid"] = uid
    try:
        data = json.dumps(obj, separators=(",", ":")).encode()
    except Exception:
        _fail("cannot re-encode request")
    if len(data) > REQ_MAX:
        _fail("request too large")

    # Open the requests dir no-follow (a symlinked requests/ would be an install-time tamper; refuse).
    try:
        dirfd = os.open(reqdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        _fail("spool unavailable")
    try:
        # Early inode/flood bound: refuse when the spool is already at the cap. The watcher's cap is
        # authoritative; this just avoids writing surplus files the watcher would only reject.
        try:
            if len(os.listdir(dirfd)) >= MAX_PENDING:
                _fail("spool over capacity")
        except OSError:
            _fail("spool unavailable")

        # Atomic publish: write a private temp with O_CREAT|O_EXCL|O_NOFOLLOW (O_EXCL refuses a
        # concurrent in-flight SAME-reqid submit), then NO-CLOBBER renameat2 onto the final name so an
        # already-PENDING same-reqid request can never be overwritten. The watcher only ever sees a
        # complete file, always at nlink==1.
        tmpname = "." + reqid + ".tmp"
        try:
            fd = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
        except FileExistsError:
            _fail("duplicate reqid (submit in flight)")
        except OSError as e:
            _fail("cannot create request (%s)" % (e.strerror or "error"))
        try:
            drvps_common.write_all(fd, data)   # write-all + fsync BEFORE the no-clobber rename: never
            os.fsync(fd)                        # publish a short-written/unflushed (truncated) request
        finally:
            os.close(fd)
        try:
            _rename_noreplace(dirfd, tmpname, dirfd, reqid + ".json")
        except OSError as e:
            try:
                os.unlink(tmpname, dir_fd=dirfd)
            except OSError:
                pass
            if e.errno == errno.EEXIST:
                _fail("duplicate reqid (already pending)")
            _fail("cannot publish request (%s)" % (e.strerror or "error"))
    finally:
        os.close(dirfd)

    _reply("OK " + reqid)


if __name__ == "__main__":
    main()
