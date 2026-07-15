#!/usr/bin/env python3
"""Split-UID (real root vs real drvps) checks for the v2 egress store boundary -- the standing regression the
offline single-UID suites structurally cannot see (docs/EGRESS-STORE-ARCH-UPGRADE.md §9). Run inside a
disposable container: `provision` + `root-check` + `root-read` as ROOT, `drvps-check` as the drvps user.
Proves that drvps can TRAVERSE the 0710 anchor via O_PATH plus the cross-UID DAC:
drvps reads the 0640 root:drvps published records, cannot read root-private (0700 root:root), cannot write
the published namespaces, and root reads the drvps-owned inbox. ASCII only."""
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
import drvps_egress_layout as L   # noqa: E402
import drvps_egress_req as R      # noqa: E402

ANCHOR = "/var/lib/distro-rig-vps-egress"
DEC_REQID = "a" * 32
npass = [0]
nfail = [0]


def ok(c, m):
    if c:
        npass[0] += 1
        print("PASS ", m)
    else:
        nfail[0] += 1
        print("FAIL ", m)


def _ids():
    return L.production_ids()


def _drvps_ids():
    import pwd
    import grp
    return pwd.getpwnam("drvps").pw_uid, grp.getgrnam("drvps").gr_gid


def _svc_gid():
    import grp
    return grp.getgrnam("drvps").gr_gid


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def provision():
    L.provision(ANCHOR, _ids())
    print("provisioned", ANCHOR)
    return 0


def root_check():
    ii = _ids()
    du, dg = _drvps_ids()
    ok(L.probe(ANCHOR, ii) == L.OK, "root probe(full) == OK")
    a = os.lstat(ANCHOR)
    ok(a.st_uid == 0 and a.st_gid == dg and _mode(ANCHOR) == 0o710, "anchor root:drvps 0710 (real UID/GID)")
    p = os.lstat(ANCHOR + "/pending")
    ok(p.st_uid == du and p.st_gid == dg and _mode(ANCHOR + "/pending") == 0o700, "pending drvps:drvps 0700")
    d = os.lstat(ANCHOR + "/published/decisions")
    ok(d.st_uid == 0 and d.st_gid == dg and _mode(ANCHOR + "/published/decisions") == 0o2750,
       "published/decisions root:drvps 2750 (setgid)")
    rp = os.lstat(ANCHOR + "/root-private")
    ok(rp.st_uid == 0 and rp.st_gid == 0 and _mode(ANCHOR + "/root-private") == 0o700, "root-private root:root 0700")
    mk = os.lstat(ANCHOR + "/.store-schema")
    ok(mk.st_uid == 0 and mk.st_gid == dg and _mode(ANCHOR + "/.store-schema") == 0o640, "marker root:drvps 0640")
    # root writes a published decision for the drvps side to read (real 0640 root:drvps)
    dfd = R.open_ns(ANCHOR, *L.NS_DECISIONS)
    try:
        R.write_published_decision(dfd, DEC_REQID, "applied", "applied", 1, group_gid=dg, owner_uid=du,
                                   op="add-splice", host="pub.example", port=443)
    finally:
        os.close(dfd)
    fp = ANCHOR + "/published/decisions/" + DEC_REQID
    ok(os.lstat(fp).st_uid == 0 and os.lstat(fp).st_gid == dg and _mode(fp) == 0o640,
       "root-written published decision is 0640 root:drvps")
    return 1 if nfail[0] else 0


def drvps_check():
    # Drive the REAL member CLI (drvps_egress_member), NOT a hand-rolled equivalent -- so this proves the
    # actual _ids()/cmd_submit path, including the getgrnam service-group resolution under SUPPLEMENTAL
    # membership (exercise the corrected member implementation, not a copy).
    import json
    import tempfile
    from types import SimpleNamespace
    import drvps_egress_member as MB
    ids = MB._ids()                                  # the member's OWN resolution (getgrnam service group)
    sg = ids[L.SVC][1]
    ok(os.getgid() != sg, "the drvps account holds the service group SUPPLEMENTALLY (primary gid != service gid)")
    # via the real member probe: traverse the 0710 anchor (O_PATH) + verify the drvps-visible nodes
    try:
        ok(MB.Store(ANCHOR).probe() == L.OK, "member Store.probe() == OK (B1: traverse 0710 + verify published)")
    except Exception as e:  # noqa: BLE001
        ok(False, "member Store.probe() raised %r (B1/supplemental regression)" % e)
    # submit via the REAL member cmd_submit (takes the shared lock, resolves the group, writes the inbox)
    fleet = tempfile.mktemp()
    with open(fleet, "w") as fh:
        fh.write(json.dumps({"mirror_allowlist": ["deb.debian.org"], "splice_allowlist": []}))
    a = SimpleNamespace(base=ANCHOR, lock=MB._lock_path(ANCHOR), fleet=fleet, owner=os.getuid(),
                        op="add-splice", host="member.example", port=443, ts=1)
    res = MB.cmd_submit(a)
    ok(res.get("status") == "pending" and res.get("reqid"), "member cmd_submit -> pending (real CLI path)")
    if res.get("reqid"):
        pf = ANCHOR + "/pending/" + res["reqid"]
        ok(os.lstat(pf).st_uid == os.getuid() and os.lstat(pf).st_gid == sg,
           "member-written pending is drvps:drvps even under a supplemental group")
    # drvps READS the root-written published decision (0640 root:drvps)
    dfd = R.open_ns(ANCHOR, *L.NS_DECISIONS)
    try:
        dec = R.read_published_decision(dfd, DEC_REQID, expect_uid=0, expect_gid=sg)
        ok(dec is not None and dec["state"] == "applied", "drvps reads a 0640 root:drvps published decision")
    finally:
        os.close(dfd)
    # drvps CANNOT read root-private (0700 root:root)
    try:
        fd = R.open_ns(ANCHOR, *L.NS_BATCHES)
        os.close(fd)
        ok(False, "drvps must NOT be able to open root-private/batches")
    except OSError:
        ok(True, "drvps CANNOT open root-private (0700 root:root) -> EACCES")
    # drvps CANNOT create a file in published/decisions (2750 root:drvps -- no group write)
    try:
        dfd = R.open_ns(ANCHOR, *L.NS_DECISIONS)
        try:
            fd = os.open("evil", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dfd)
            os.close(fd)
            ok(False, "drvps must NOT be able to write into published/decisions")
        finally:
            os.close(dfd)
    except OSError:
        ok(True, "drvps CANNOT write into published/decisions (2750, no group write) -> EACCES")
    return 1 if nfail[0] else 0


def root_read():
    """Root reads the drvps-written pending inbox (0600 drvps:drvps) as the privileged reader."""
    du, dg = _drvps_ids()
    pfd = R.open_ns(ANCHOR, *L.NS_PENDING)
    try:
        names = [n for n in R.list_names(pfd) if len(n) == 32]
        ok(bool(names), "root sees the drvps-written pending request")
        req = R.read_request(pfd, names[0], expect_uid=du, expect_gid=dg)
        ok(req["host"] == "member.example", "root reads the drvps-owned 0600 inbox record")
    finally:
        os.close(pfd)
    return 1 if nfail[0] else 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    fn = {"provision": provision, "root-check": root_check, "drvps-check": drvps_check, "root-read": root_read}.get(mode)
    if fn is None:
        print("usage: egress-splituid-check.py provision|root-check|drvps-check|root-read")
        sys.exit(2)
    sys.exit(fn())
