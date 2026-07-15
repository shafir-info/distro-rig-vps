#!/usr/bin/env python3
"""Tests the v2 egress store LAYOUT + ownership/mode contract (tools/drvps_egress_layout.py; arch doc
docs/EGRESS-STORE-ARCH-UPGRADE.md Stage 0). Offline + SINGLE-UID: every principal maps to the current uid,
so the cross-UID OWNERSHIP half is proven by the split-UID container e2e, not here. What IS provable
single-UID -- and asserted here -- is the contract TABLE, the provision/probe round-trip, the mode/setgid/
marker invariants, and every fail-closed path (symlinked node, wrong mode, non-dir, missing node/marker,
wrong owner via injected ids, wrong schema). ASCII only."""
import json
import os
import stat
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_egress_layout as L  # noqa: E402

npass = [0]
nfail = [0]


def ok(c, m):
    if c:
        npass[0] += 1
    else:
        nfail[0] += 1
        print("FAIL:", m)


UID, GID = os.getuid(), os.getgid()
# single-UID: root and drvps both map to us, so provision()'s fchown is a no-op and the owner CHECK path
# passes trivially -- but it still RUNS (and is forced to fail below via a deliberately-wrong injected id).
IDS = {L.ROOT: (UID, GID), L.SVC: (UID, GID)}
_TMPS = []


def fresh():
    """A new provisioned anchor under a private tmp parent (mimics the root-owned /var/lib parent)."""
    d = tempfile.mkdtemp(prefix="egress-layout-")
    os.chmod(d, 0o755)
    _TMPS.append(d)
    anchor = os.path.join(d, "distro-rig-vps-egress")
    L.provision(anchor, IDS)
    return anchor


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


# ---- contract table: shape, ordering, setgid, namespace tuples ----------------------------------
ok(L.NODES[0][0] == (), "NODES[0] is the anchor (empty parts)")
_seen = set()
_parents_first = True
for parts, owner, group, mode in L.NODES:
    if parts and tuple(parts[:-1]) not in _seen:
        _parents_first = False
    _seen.add(tuple(parts))
ok(_parents_first, "NODES is ordered parents-first (provision can create top-down)")

_by_parts = {tuple(p): (o, g, m) for (p, o, g, m) in L.NODES}
ok(_by_parts[()] == (L.ROOT, L.SVC, 0o710), "anchor is root:drvps 0710")
ok(_by_parts[("pending",)] == (L.SVC, L.SVC, 0o700), "pending is drvps:drvps 0700")
ok(_by_parts[("expiry",)] == (L.SVC, L.SVC, 0o700), "expiry is drvps:drvps 0700")
ok(_by_parts[("root-private",)] == (L.ROOT, L.ROOT, 0o700), "root-private is root:root 0700")
ok(_by_parts[("root-private", "batches")] == (L.ROOT, L.ROOT, 0o700), "batches is root:root 0700")
ok(_by_parts[("root-private", "journals")] == (L.ROOT, L.ROOT, 0o700), "journals is root:root 0700")
ok(_by_parts[("published",)] == (L.ROOT, L.SVC, 0o750), "published is root:drvps 0750")
ok(_by_parts[("published", "decisions")] == (L.ROOT, L.SVC, 0o2750), "decisions is root:drvps 2750 (setgid)")
ok(_by_parts[("published", "claims")] == (L.ROOT, L.SVC, 0o2750), "claims is root:drvps 2750 (setgid)")
ok(bool(_by_parts[("published", "decisions")][2] & stat.S_ISGID), "decisions has the setgid bit")
ok(bool(_by_parts[("published", "claims")][2] & stat.S_ISGID), "claims has the setgid bit")
# the namespace tuples downstream imports must each be a real node
for ns in (L.NS_PENDING, L.NS_EXPIRY, L.NS_BATCHES, L.NS_JOURNALS, L.NS_DECISIONS, L.NS_CLAIMS):
    ok(tuple(ns) in _by_parts, "NS tuple %s is a declared node" % (ns,))
ok(L.PRIVATE_FILE_MODE == 0o600 and L.PUBLISHED_FILE_MODE == 0o640, "file-mode contract 0600 / 0640")
ok(L.SCHEMA_VER == 2, "schema version is 2")

# ---- provision -> probe OK; on-disk modes + marker ----------------------------------------------
A = fresh()
ok(L.probe(A, IDS) == L.OK, "probe(provisioned) == OK")
ok(mode_of(A) == 0o710, "anchor mode 0710 on disk")
ok(mode_of(os.path.join(A, "pending")) == 0o700, "pending mode 0700 on disk")
ok(mode_of(os.path.join(A, "published", "decisions")) == 0o2750, "decisions mode 2750 on disk (setgid set)")
ok(mode_of(os.path.join(A, "published", "claims")) == 0o2750, "claims mode 2750 on disk (setgid set)")
ok(mode_of(os.path.join(A, "root-private")) == 0o700, "root-private mode 0700 on disk")
mk = L.marker_path(A)
ok(os.path.isfile(mk), "marker file exists")
ok(mode_of(mk) == 0o640, "marker mode 0640 on disk")
_m = json.loads(open(mk).read())
ok(_m.get("schema") == L.SCHEMA_VER, "marker records schema 2")
ok(isinstance(_m.get("ts"), int), "marker records an int ts")
# node_path / marker_path helpers
ok(L.node_path(A, L.NS_DECISIONS) == os.path.join(A, "published", "decisions"), "node_path composes")

# ---- idempotency: re-provision keeps OK, refreshes marker ts ------------------------------------
_ts1 = json.loads(open(mk).read())["ts"]
L.provision(A, IDS)
ok(L.probe(A, IDS) == L.OK, "re-provision stays OK (idempotent)")
ok(json.loads(open(mk).read())["ts"] >= _ts1, "re-provision refreshes marker ts (non-decreasing)")

# ---- ABSENT paths (fresh / partially provisioned) -----------------------------------------------
_bare = tempfile.mkdtemp(prefix="egress-layout-")
_TMPS.append(_bare)
ok(L.probe(os.path.join(_bare, "distro-rig-vps-egress"), IDS) == L.ABSENT, "absent anchor -> ABSENT")
# anchor present but marker absent (crash before the LAST write) -> ABSENT, not damaged
A2 = fresh()
os.unlink(L.marker_path(A2))
ok(L.probe(A2, IDS) == L.ABSENT, "anchor present, marker absent -> ABSENT (partial install)")


def raises_layout(anchor, ids, label):
    try:
        L.probe(anchor, ids)
        ok(False, label + " (expected LayoutError, got none)")
    except L.LayoutError:
        ok(True, label)
    except Exception as e:  # noqa: BLE001
        ok(False, label + " (expected LayoutError, got %r)" % e)


# ---- DAMAGED: symlinked node component -----------------------------------------------------------
A3 = fresh()
os.rmdir(os.path.join(A3, "pending"))                       # empty on a fresh store
os.symlink("/tmp", os.path.join(A3, "pending"))
raises_layout(A3, IDS, "symlinked node component -> LayoutError")

# ---- DAMAGED: wrong mode on a node ---------------------------------------------------------------
A4 = fresh()
os.chmod(os.path.join(A4, "pending"), 0o777)
raises_layout(A4, IDS, "wrong node mode -> LayoutError")

# ---- DAMAGED: node replaced by a non-directory ---------------------------------------------------
A5 = fresh()
os.rmdir(os.path.join(A5, "published", "claims"))
with open(os.path.join(A5, "published", "claims"), "w") as fh:
    fh.write("x")
raises_layout(A5, IDS, "node replaced by a regular file -> LayoutError")

# ---- DAMAGED: missing node -----------------------------------------------------------------------
A6 = fresh()
os.rmdir(os.path.join(A6, "expiry"))
raises_layout(A6, IDS, "missing node -> LayoutError")

# ---- DAMAGED: wrong OWNER (injected ids force the owner-check to fire, single-UID) ---------------
A7 = fresh()
_wrong_svc = {L.ROOT: (UID, GID), L.SVC: (UID + 987654, GID)}   # pending is owner SVC -> uid mismatch
raises_layout(A7, _wrong_svc, "wrong node owner (injected id) -> LayoutError")
_wrong_root = {L.ROOT: (UID + 987654, GID), L.SVC: (UID, GID)}  # marker must be root-owned -> uid mismatch
raises_layout(A7, _wrong_root, "marker not root-owned (injected id) -> LayoutError")

# ---- DAMAGED: wrong schema in the marker ---------------------------------------------------------
A8 = fresh()
with open(L.marker_path(A8), "w") as fh:
    fh.write(json.dumps({"schema": 99, "ts": 1}))
raises_layout(A8, IDS, "wrong marker schema -> LayoutError")

# ---- DAMAGED: symlinked marker -------------------------------------------------------------------
A9 = fresh()
os.unlink(L.marker_path(A9))
os.symlink("/etc/hostname", L.marker_path(A9))
raises_layout(A9, IDS, "symlinked marker -> LayoutError (tamper, not ABSENT)")

# ---- DAMAGED: malformed marker JSON --------------------------------------------------------------
A10 = fresh()
with open(L.marker_path(A10), "w") as fh:
    fh.write("{not json")
raises_layout(A10, IDS, "malformed marker JSON -> LayoutError")

# ---- DAMAGED: non-canonical marker bytes (valid fields, whitespace) -> LayoutError ----------------
A11 = fresh()
with open(L.marker_path(A11), "w") as fh:
    fh.write('{"schema": 2, "ts": 1}')                 # valid fields but non-canonical (whitespace)
os.chmod(L.marker_path(A11), 0o640)
raises_layout(A11, IDS, "non-canonical marker bytes -> LayoutError (canonical-byte rule)")

for d in _TMPS:
    shutil.rmtree(d, ignore_errors=True)
print("-------------------------------------------")
print("drvps-egress-layout: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
