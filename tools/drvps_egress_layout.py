#!/usr/bin/env python3
"""drvps egress store LAYOUT + ownership/mode CONTRACT (v2 -- docs/EGRESS-STORE-ARCH-UPGRADE.md).

The v2 store ends the recurring root<->drvps hazard class by giving every
namespace EXACTLY ONE writer under a ROOT-OWNED anchor, so the trust boundary no longer runs through
shared-write directories. This module is the SINGLE SOURCE OF TRUTH for that topology; req/member/approve
and the installer all import the node table + modes from here (never re-declare them):

  /var/lib/distro-rig-vps-egress/     root:drvps 0710   anchor -- root-owned => drvps cannot rename children
  |-- pending/                        drvps:drvps 0700  drvps writes requests; root READS (hostile inbox)
  |-- expiry/                         drvps:drvps 0700  drvps writes expiry terminals; root READS
  |-- root-private/                   root:root  0700   invisible to drvps
  |   |-- batches/                    root:root  0700     immutable request snapshots + manifests
  |   `-- journals/                   root:root  0700     commit journals
  `-- published/                      root:drvps 0750   root writes, drvps READS (group drvps)
      |-- decisions/                  root:drvps 2750     applied/rejected terminals (files 0640 root:drvps)
      `-- claims/                     root:drvps 2750     read-only claim leases       (files 0640 root:drvps)
  .store-schema                       root:drvps 0640   installation/schema marker, written LAST

Record file modes: pending/expiry + root-private records are 0600 (root reads the inbox as the privileged
reader; root-private is root-only) -- NO cross-UID mode hack. ONLY published/{decisions,claims} files are
0640 root:drvps, the single root->drvps read edge, umask-independent via explicit fchown+fchmod.

The INSTALLER (root) calls provision(); RUNTIME tools call probe(), which is READ-ONLY + fail-closed:
  * absent anchor OR absent marker            -> ABSENT   (not installed; a fresh store has no work)
  * anchor+marker present, every node correct -> OK
  * present-but-DAMAGED (wrong owner/group/mode/type, a symlinked component, or wrong schema) -> raise
    LayoutError (HARD fail -- never a silent "no work"; the marker is written LAST so its presence asserts
    a fully-provisioned tree, and drvps cannot forge it: the anchor is 0710 so drvps cannot write there).

The offline suite runs single-UID, so it can only prove the mode/type/marker half of the contract (the
owner checks pass trivially when every principal maps to the same uid, but the CHECKING CODE PATH is still
exercised, and forced to raise with a deliberately-wrong expected uid). The split-UID container e2e (run as
root against a real `drvps` user) proves the cross-UID ownership half and gates every ownership stage. ASCII only.
"""
from __future__ import annotations
import json
import os
import stat
import time

# ---- production constants -----------------------------------------------------------------------
ANCHOR = "/var/lib/distro-rig-vps-egress"   # v2 root-owned SIBLING anchor (NOT under the drvps-owned
                                            # /var/lib/distro-rig-vps base, whose child dirs drvps could rename)
SERVICE_USER = "drvps"                      # the socket watcher / reaper run as this user
SERVICE_GROUP = "drvps"                     # published/ group interface (the watcher/reaper are in it; members are not)
SCHEMA_VER = 2
MARKER_NAME = ".store-schema"               # under the anchor; root:drvps 0640 (drvps can read schema, cannot write)
MARKER_MODE = 0o640
_MARKER_MAX = 4096

# principals
ROOT = "root"
SVC = "drvps"

# The node table: (parts-relative-to-anchor, owner_principal, group_principal, dir_mode). Ordered
# PARENTS-FIRST so provision() can create top-down and reuse each parent. THE ONLY topology declaration.
NODES = (
    ((),                            ROOT, SVC,  0o710),
    (("pending",),                  SVC,  SVC,  0o700),
    (("expiry",),                   SVC,  SVC,  0o700),
    (("root-private",),             ROOT, ROOT, 0o700),
    (("root-private", "batches"),   ROOT, ROOT, 0o700),
    (("root-private", "journals"),  ROOT, ROOT, 0o700),
    (("published",),                ROOT, SVC,  0o750),
    (("published", "decisions"),    ROOT, SVC,  0o2750),
    (("published", "claims"),       ROOT, SVC,  0o2750),
)

# MEMBER_NODES: the subset a drvps runtime (member/reaper) can legitimately see. root-private/ is
# 0700 root:root -- drvps cannot even open it (EACCES), and never needs to -- so the member verifies only
# the anchor + its own leaves + the published read interface (all drvps-traversable/readable). The ROOT
# approve tool verifies the FULL NODES set (it can read everything).
MEMBER_NODES = tuple(n for n in NODES if not n[0] or n[0][0] != "root-private")

# namespace path tuples -- downstream imports THESE (single source; never a literal "pending" string)
NS_PENDING = ("pending",)
NS_EXPIRY = ("expiry",)
NS_BATCHES = ("root-private", "batches")
NS_JOURNALS = ("root-private", "journals")
NS_DECISIONS = ("published", "decisions")
NS_CLAIMS = ("published", "claims")

# record file modes (see module docstring)
PRIVATE_FILE_MODE = 0o600      # pending/expiry (drvps-owned, root reads as root) + root-private (root-only)
PUBLISHED_FILE_MODE = 0o640    # published/{decisions,claims} -- the ONE root:drvps read edge

# probe() status
ABSENT = "absent"
OK = "ok"

_O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC        # read (needs +r; supports fchmod/fsync)
_O_TRAVERSE = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC     # traverse-only (needs only +x)


class LayoutError(Exception):
    """A present-but-damaged / tampered store tree. Runtime tools fail CLOSED HARD on this -- never a silent
    'no work'. (An absent anchor/marker is NOT this: probe() returns ABSENT for a fresh/never-installed store.)"""


def production_ids():
    """{principal: (uid, gid)} for the real deploy: root=0/0, drvps=<its uid>/<its gid>. Tests inject their own."""
    import pwd
    import grp
    su = pwd.getpwnam(SERVICE_USER)
    sg = grp.getgrnam(SERVICE_GROUP)
    return {ROOT: (0, 0), SVC: (su.pw_uid, sg.gr_gid)}


def node_path(anchor, parts):
    a = anchor.rstrip("/")
    return os.path.join(a, *parts) if parts else a


def marker_path(anchor):
    return os.path.join(anchor.rstrip("/"), MARKER_NAME)


def _write_all(fd, data):
    mv = memoryview(data)
    n = 0
    while n < len(mv):
        n += os.write(fd, mv[n:])


def _anchor_fd(anchor, traverse=False):
    """A dir-fd for the anchor, reached SYMLINK-SAFELY: open the anchor's parent (root-owned) by path, then
    openat the anchor O_NOFOLLOW. `traverse` -> O_PATH (needs only +x; the anchor is 0710, so a drvps runtime
    can traverse but not O_RDONLY it); the O_RDONLY form is for root (fsync/marker
    write). Raises FileNotFoundError if the anchor is absent."""
    b = anchor.rstrip("/")
    parent, name = (os.path.dirname(b) or "/"), os.path.basename(b)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return os.open(name, _O_TRAVERSE if traverse else _O_DIR, dir_fd=pfd)
    finally:
        os.close(pfd)


def _mkdirat_open(dir_fd, name, mode):
    """openat `name` O_NOFOLLOW; mkdirat it if missing, then re-open O_NOFOLLOW. A symlink planted/raced at
    `name` makes the (re-)open fail with ELOOP -> a privileged creator never follows it out of the tree."""
    try:
        return os.open(name, _O_DIR, dir_fd=dir_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode, dir_fd=dir_fd)
        except FileExistsError:
            pass
        return os.open(name, _O_DIR, dir_fd=dir_fd)


# ---- provision (installer / root only) ----------------------------------------------------------
def provision(anchor=ANCHOR, ids=None):
    """Create the whole v2 tree with exact owner/group/mode/setgid, then write the schema marker LAST.
    Idempotent (re-run refreshes owner/mode + the marker ts; never destroys records). Runs as ROOT at
    install time -- the anchor's ancestors are root-owned so a path open of the parent is safe; everything
    AT/below the anchor is created via mkdirat + O_NOFOLLOW. Not reachable at runtime (arch doc: runtime
    tools verify only)."""
    if ids is None:
        ids = production_ids()
    b = anchor.rstrip("/")
    parent, base_name = (os.path.dirname(b) or "/"), os.path.basename(b)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for parts, owner, group, mode in NODES:
            comps = [base_name] + list(parts)
            cur, chain = pfd, []
            try:
                for c in comps:
                    # intermediate dirs get a tight transient mode; the exact mode is set on the LEAF below,
                    # and every intermediate is itself a NODE (parents-first) so it is corrected on its own pass
                    fd = _mkdirat_open(cur, c, 0o700)
                    chain.append(fd)
                    cur = fd
                os.fchown(cur, ids[owner][0], ids[group][1])   # by-fd -> the real inode (race-free)
                os.fchmod(cur, mode)                            # exact mode incl. setgid, umask-independent
                os.fsync(cur)                                   # persist the dir before the marker is exposed
            finally:
                for fd in chain:
                    os.close(fd)
        os.fsync(pfd)                                           # persist the anchor's dir entry in its parent
    finally:
        os.close(pfd)
    _write_marker(anchor, ids)


def _write_marker(anchor, ids):
    """The marker asserts 'fully installed, schema=N'. Written LAST + atomically. root:drvps 0640 so the
    drvps runtime can read the schema; the anchor is 0710 so drvps cannot create/replace it."""
    data = json.dumps({"schema": SCHEMA_VER, "ts": int(time.time())},
                      sort_keys=True, separators=(",", ":")).encode("ascii")
    afd = _anchor_fd(anchor)
    try:
        tmp = "." + MARKER_NAME + ".tmp." + os.urandom(6).hex()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     MARKER_MODE, dir_fd=afd)
        try:
            _write_all(fd, data)
            os.fchown(fd, ids[ROOT][0], ids[SVC][1])   # root owner, drvps group
            os.fchmod(fd, MARKER_MODE)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rename(tmp, MARKER_NAME, src_dir_fd=afd, dst_dir_fd=afd)   # atomic replace on re-provision
            os.fsync(afd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=afd)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(afd)


# ---- probe (runtime, read-only, fail-closed) ----------------------------------------------------
def probe(anchor=ANCHOR, ids=None, nodes=NODES):
    """Read-only store status. Returns ABSENT (fresh/not-installed: no anchor OR no marker) or OK (fully
    verified). RAISES LayoutError on a present-but-damaged tree (wrong owner/group/mode/type, symlinked
    component, or wrong schema). The marker is written LAST, so 'anchor present but marker absent' is a
    partially-provisioned / never-finished install -> ABSENT (the installer re-runs; runtime does nothing).
    `nodes` selects which subset to verify (root tools pass NODES; the drvps member passes MEMBER_NODES,
    since it cannot read the root-private subtree)."""
    if ids is None:
        ids = production_ids()
    try:
        afd = _anchor_fd(anchor, traverse=True)      # O_PATH: the drvps runtime can traverse the 0710 anchor
    except FileNotFoundError:
        return ABSENT
    except OSError as e:
        raise LayoutError("anchor unsafe: %s" % e.strerror)
    try:
        try:
            m = _read_marker(afd, ids)
        except FileNotFoundError:
            return ABSENT
    finally:
        os.close(afd)
    if m.get("schema") != SCHEMA_VER:
        raise LayoutError("schema-mismatch: %r (want %d)" % (m.get("schema"), SCHEMA_VER))
    _verify_nodes(anchor, ids, nodes)
    return OK


def probe_member(anchor=ANCHOR, ids=None):
    """Drvps-scoped probe: verify only the nodes a drvps runtime can/should see (anchor + its own leaves +
    the published read interface), NOT the root-private subtree it cannot open."""
    return probe(anchor, ids, MEMBER_NODES)


def _read_marker(afd, ids):
    try:
        fd = os.open(MARKER_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=afd)
    except FileNotFoundError:
        raise                                          # -> probe maps to ABSENT
    except OSError as e:
        raise LayoutError("marker unsafe: %s" % e.strerror)   # a symlinked marker (ELOOP) is tamper, not absent
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LayoutError("marker not a regular file")
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise LayoutError("marker has a set-id bit")
        if st.st_nlink != 1:
            raise LayoutError("marker st_nlink=%d (not 1)" % st.st_nlink)
        if st.st_uid != ids[ROOT][0] or st.st_gid != ids[SVC][1]:
            raise LayoutError("marker not root:drvps (uid/gid %d/%d)" % (st.st_uid, st.st_gid))
        if stat.S_IMODE(st.st_mode) != MARKER_MODE:
            raise LayoutError("marker mode %o (want %o)" % (stat.S_IMODE(st.st_mode), MARKER_MODE))
        if st.st_size > _MARKER_MAX:
            raise LayoutError("marker oversize")
        data = os.read(fd, _MARKER_MAX + 1)
    finally:
        os.close(fd)
    if len(data) > _MARKER_MAX:
        raise LayoutError("marker oversize")
    try:
        obj = json.loads(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise LayoutError("marker malformed")
    if not isinstance(obj, dict) or set(obj) != frozenset(("schema", "ts")):
        raise LayoutError("marker fields invalid")
    if not isinstance(obj["schema"], int) or isinstance(obj["schema"], bool):
        raise LayoutError("marker schema not an int")
    if not isinstance(obj["ts"], int) or isinstance(obj["ts"], bool):
        raise LayoutError("marker ts not an int")
    if data != json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii"):
        raise LayoutError("marker not canonical")    # canonical-byte rule (arch §7)
    return obj


def _verify_nodes(anchor, ids, nodes=NODES):
    """Fail-closed verify of each node in `nodes`: exact owner uid, group gid, mode (incl. setgid), and dir
    type, reached via an O_NOFOLLOW chain from the anchor's root-owned parent (a symlinked component ->
    ELOOP -> LayoutError, never a redirect)."""
    b = anchor.rstrip("/")
    parent, base_name = (os.path.dirname(b) or "/"), os.path.basename(b)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for parts, owner, group, mode in nodes:
            comps = [base_name] + list(parts)
            label = "/".join(comps)
            cur, chain = pfd, []
            try:
                for c in comps:
                    try:
                        fd = os.open(c, _O_TRAVERSE, dir_fd=cur)   # O_PATH: fstat only (drvps can't O_RDONLY 0710)
                    except FileNotFoundError:
                        raise LayoutError("missing node: %s" % label)
                    except OSError as e:
                        raise LayoutError("unsafe node %s: %s" % (label, e.strerror))
                    chain.append(fd)
                    cur = fd
                st = os.fstat(cur)
                if not stat.S_ISDIR(st.st_mode):
                    raise LayoutError("node not a directory: %s" % label)
                want_uid, want_gid = ids[owner][0], ids[group][1]
                if st.st_uid != want_uid or st.st_gid != want_gid:
                    raise LayoutError("wrong owner %s: %d/%d != %d/%d"
                                      % (label, st.st_uid, st.st_gid, want_uid, want_gid))
                if stat.S_IMODE(st.st_mode) != mode:
                    raise LayoutError("wrong mode %s: %o != %o" % (label, stat.S_IMODE(st.st_mode), mode))
            finally:
                for fd in chain:
                    os.close(fd)
    finally:
        os.close(pfd)


# ---- CLI (installer entrypoint: `drvps_egress_layout.py provision [ANCHOR]`) ---------------------
def _ids_for(svc_user, svc_group):
    """Resolve {root,drvps} ids from a service user/group NAME (installer passes DR_VPS_SERVICE_USER so the
    layout tracks the deploy's actual service identity instead of the hardcoded default)."""
    import pwd
    import grp
    su = pwd.getpwnam(svc_user)
    sg = grp.getgrnam(svc_group)
    return {ROOT: (0, 0), SVC: (su.pw_uid, sg.gr_gid)}


def main(argv):
    if not argv or argv[0] not in ("provision", "probe"):
        print("usage: drvps_egress_layout.py provision [ANCHOR [SVC_USER [SVC_GROUP]]] | probe [ANCHOR]")
        return 2
    anchor = argv[1] if len(argv) > 1 else ANCHOR
    if argv[0] == "provision":
        ids = None
        if len(argv) > 2:
            ids = _ids_for(argv[2], argv[3] if len(argv) > 3 else argv[2])
        provision(anchor, ids)
        print("provisioned %s (schema %d)" % (anchor, SCHEMA_VER))
        return 0
    try:
        st = probe(anchor)
    except LayoutError as e:
        print("DAMAGED: %s" % e)
        return 1
    print(st)
    return 0 if st == OK else 3


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
