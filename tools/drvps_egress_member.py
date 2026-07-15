#!/usr/bin/env python3
"""drvps_egress_member.py v2 -- the drvpsvc MEMBER-facing egress ops + the reaper expiry sweep, against the
v2 store (docs/EGRESS-STORE-ARCH-UPGRADE.md). Invoked by src/dr_vps_egress.sh AFTER _dr_vps_egress_admit.
Runs as the drvps service user: it writes ONLY its own leaves (pending/, expiry/) and READS the root
publication interface (published/{decisions,claims}); it never touches root-private/ (0700 root:root) and
never PROVISIONS the store (the installer does that -- the member/reaper only verify + fail closed).

Every op is bound to the SO_PEERCRED-stamped owner_uid the watcher passes in (never the client's claim),
carried IN the request record (v2 drops the old owner/ sidecar). Idempotent per (owner_uid, op, host, port):
a same-tuple re-submit returns the SAME pending reqid. add of an already-active host -> already-active;
remove of an absent host -> already-absent. Caps come from fleet["egress"] with safe defaults.

The reaper `expire` sweep respects root claim LEASES: a leased reqid is under review and is NEVER expired
(a malformed/wrongly-owned lease SUPPRESSES expiry AND surfaces a root-zone failure -- never "no claim"),
clears pending for already-decided reqids, expires past-TTL un-leased pending, and retention-GCs expiry/.
Prints ONE JSON object; exit 0 for member-visible outcomes, 2 for usage, 1 for an internal error. ASCII only.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import drvps_egress_layout as L   # noqa: E402
import drvps_egress_model as M    # noqa: E402
import drvps_egress_req as R      # noqa: E402

_REQID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
DEFAULT_CAPS = {"per_owner_pending": 5, "global_pending": 50, "max_active": 20}
PROD_ANCHOR = L.ANCHOR                            # v2 root-owned sibling anchor (matches the approve tool)
LOCK_PATH = "/etc/distro-rig-vps/egress.lock"    # ROOT-owned dir -> tamper-proof shared DATA lock

# ids: the member runs as drvps, so its own UID is the drvps principal and root is uid 0; the store GROUP is
# resolved by NAME (grp.getgrnam) so it is correct even when drvps holds the service group SUPPLEMENTALLY
# (its primary gid then differs). Tests inject a single-UID override.
_IDS_OVERRIDE = None


def _ids():
    if _IDS_OVERRIDE is not None:
        return _IDS_OVERRIDE
    # Resolve the SERVICE_GROUP gid by NAME (not os.getgid()): the store group is drvps even when the process
    # holds drvps only as a SUPPLEMENTAL group (its primary gid then differs). Fall back to getgid() if the
    # group is unresolvable (a degraded env -> probe will surface any real mismatch).
    try:
        import grp
        sg = grp.getgrnam(L.SERVICE_GROUP).gr_gid
    except (KeyError, OSError):
        sg = os.getgid()
    return {L.ROOT: (0, 0), L.SVC: (os.getuid(), sg)}


def _pins():
    """(root_uid, svc_uid, svc_gid) for pinning cross-domain reads: published decisions/leases are root:drvps,
    pending/expiry are drvps:drvps."""
    ids = _ids()
    return ids[L.ROOT][0], ids[L.SVC][0], ids[L.SVC][1]


def _lock_path(base):
    """The DATA lock is BOUND to the store anchor (no --lock seam). The production anchor
    forces the fixed root-owned production lock; a test anchor uses a lock beside it. Canonicalize both sides."""
    if os.path.realpath(base) == os.path.realpath(PROD_ANCHOR):
        return LOCK_PATH
    return os.path.join(os.path.dirname(base.rstrip("/")), "egress.lock")


class Store:
    """Handles for the drvps-visible v2 namespaces. NO owner/, review/, or root-private/ (v2)."""
    def __init__(self, base):
        self.base = base
        self.pending = L.node_path(base, L.NS_PENDING)
        self.expiry = L.node_path(base, L.NS_EXPIRY)
        self.decisions = L.node_path(base, L.NS_DECISIONS)
        self.claims = L.node_path(base, L.NS_CLAIMS)

    def probe(self):
        """Drvps-scoped store status: ABSENT | OK; raises L.LayoutError on a damaged tree (fail closed)."""
        return L.probe_member(self.base, _ids())

    def dfd(self, parts):
        return R.open_ns(self.base, *parts)


def _load_fleet(fleet_path):
    try:
        with open(fleet_path, "r") as f:
            fleet = json.load(f)
    except (FileNotFoundError, ValueError):
        return {}
    return fleet if isinstance(fleet, dict) else {}


def _active_hosts(fleet):
    out = set()
    for e in fleet.get("splice_allowlist", []) or []:
        if isinstance(e, dict):
            h, why = M.canon_fqdn(e.get("host"))
            if h is not None:
                out.add(h)
    return out


def _caps(fleet):
    caps = dict(DEFAULT_CAPS)
    cfg = fleet.get("egress")
    if isinstance(cfg, dict):
        for k in caps:
            v = cfg.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                caps[k] = v
    return caps


def _owner_pending_count(store, owner_uid):
    """(owner's pending count, global pending count). Owner read from the request record itself (v2)."""
    _ru, su, sg = _pins()
    pfd = store.dfd(L.NS_PENDING)
    own, glob = 0, 0
    try:
        for n in R.list_names(pfd):
            glob += 1
            try:
                if R.read_owner_uid(pfd, n, expect_uid=su, expect_gid=sg) == owner_uid:
                    own += 1
            except (R.EgressReqError, OSError):
                continue
    finally:
        os.close(pfd)
    return own, glob


def _term_fds(store):
    return store.dfd(L.NS_DECISIONS), store.dfd(L.NS_EXPIRY)


def _leased(store, reqid):
    return os.path.exists(os.path.join(store.claims, reqid))


def _state_of(store, reqid):
    """pending | under-review | applied | rejected | expired (terminal wins over lease)."""
    ru, su, sg = _pins()
    dfd, efd = _term_fds(store)
    try:
        term = R.read_terminal(dfd, efd, reqid, root_uid=ru, svc_uid=su, svc_gid=sg)
    finally:
        os.close(dfd)
        os.close(efd)
    if term:
        return term.get("state", "decided")
    return "under-review" if _leased(store, reqid) else "pending"


def _pending_reqid(store, reqid):
    return os.path.exists(os.path.join(store.pending, reqid))


def _open_lock(path):
    try:
        return os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o660)
    except PermissionError:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _lock(path):
    import fcntl
    lfd = _open_lock(path)
    fcntl.flock(lfd, fcntl.LOCK_EX)
    return lfd


def _unlock(lfd):
    import fcntl
    fcntl.flock(lfd, fcntl.LOCK_UN)
    os.close(lfd)


def _dedup_pending(store, owner_uid, op, host, port):
    """The reqid of an ACTIVE (pending, not-terminal) same-tuple request owned by owner_uid, or None.
    In-flight dedup so an accidental double-submit returns the first attempt. Runs under the data lock."""
    ru, su, sg = _pins()
    pfd, dfd, efd = store.dfd(L.NS_PENDING), store.dfd(L.NS_DECISIONS), store.dfd(L.NS_EXPIRY)
    try:
        for n in R.list_names(pfd):
            try:
                req = R.read_request(pfd, n, expect_uid=su, expect_gid=sg)
                if req["owner_uid"] != owner_uid or req["op"] != op or req["host"] != host or req["port"] != port:
                    continue
                if R.read_terminal(dfd, efd, n, root_uid=ru, svc_uid=su, svc_gid=sg):
                    continue
            except (R.EgressReqError, OSError):
                continue
            return n
    finally:
        for fd in (pfd, dfd, efd):
            os.close(fd)
    return None


def _pending_add_hosts(store):
    _ru, su, sg = _pins()
    pfd = store.dfd(L.NS_PENDING)
    hosts = set()
    try:
        for n in R.list_names(pfd):
            try:
                req = R.read_request(pfd, n, expect_uid=su, expect_gid=sg)
            except (R.EgressReqError, OSError):
                continue
            if req["op"] == "add-splice":
                hosts.add(req["host"])
    finally:
        os.close(pfd)
    return hosts


def _not_installed(store):
    """Probe the store; return a member-visible refusal dict if it is not installed, None if OK. A DAMAGED
    tree fails closed (raises L.LayoutError -> the caller surfaces status=error)."""
    return store.probe() == L.ABSENT


def cmd_submit(a):
    store = Store(a.base)
    host, why = M.canon_fqdn(a.host)
    if host is None:
        return {"status": "refused", "reason": why, "host": a.host}
    if a.port != 443:
        return {"status": "refused", "reason": "bad-port", "host": host, "port": a.port}
    if _not_installed(store):
        return {"status": "refused", "reason": "store-not-initialized", "host": host}
    lfd = _lock(a.lock)
    try:
        fleet = _load_fleet(a.fleet)
        active = _active_hosts(fleet)
        if a.op == "add-splice" and host in active:
            return {"status": "already-active", "host": host, "port": a.port}
        if a.op == "remove-splice" and host not in active:
            return {"status": "already-absent", "host": host, "port": a.port}

        dup = _dedup_pending(store, a.owner, a.op, host, a.port)
        if dup:
            return {"status": "pending", "reqid": dup, "host": host, "port": a.port, "op": a.op,
                    "idempotent": True}

        caps = _caps(fleet)
        own, glob = _owner_pending_count(store, a.owner)
        if own >= caps["per_owner_pending"]:
            return {"status": "refused", "reason": "owner-pending-cap", "limit": caps["per_owner_pending"]}
        if glob >= caps["global_pending"]:
            return {"status": "refused", "reason": "global-pending-cap", "limit": caps["global_pending"]}
        if a.op == "add-splice" and host not in active:
            projected = active | _pending_add_hosts(store) | {host}
            if len(projected) > caps["max_active"]:
                return {"status": "refused", "reason": "max-active", "limit": caps["max_active"]}

        _ru, _su, sg = _pins()
        pfd = store.dfd(L.NS_PENDING)
        try:
            rid = R.submit_request(pfd, a.owner, a.op, host, a.port, a.ts, group_gid=sg)
        except R.EgressReqError as e:
            return {"status": "refused", "reason": e.reason, "host": host}
        finally:
            os.close(pfd)
        return {"status": "pending", "reqid": rid, "host": host, "port": a.port, "op": a.op}
    finally:
        _unlock(lfd)


def _owner_terminals(store, owner_uid):
    """Decided attempts (self-attributing terminals) owned by owner_uid, still within retention."""
    out = []
    ru, su, sg = _pins()
    for parts, reader, ex_uid in ((L.NS_DECISIONS, R.read_published_decision, ru),
                                  (L.NS_EXPIRY, R.read_expiry_decision, su)):
        fd = store.dfd(parts)
        try:
            for n in R.list_names(fd):
                try:
                    obj = reader(fd, n, expect_uid=ex_uid, expect_gid=sg)
                except (R.EgressReqError, OSError):
                    continue
                if isinstance(obj, dict) and obj.get("owner_uid") == owner_uid:
                    out.append({"reqid": n, "op": obj.get("op"), "host": obj.get("host"),
                                "port": obj.get("port"), "state": obj.get("state"),
                                "reason": obj.get("reason"), "ts": obj.get("ts")})
        finally:
            os.close(fd)
    return out


def cmd_list(a):
    store = Store(a.base)
    if _not_installed(store):
        return {"status": "ok", "requests": [], "decided": []}
    decided = sorted(_owner_terminals(store, a.owner), key=lambda d: d.get("ts") or 0)
    seen = {d["reqid"] for d in decided}
    _ru, su, sg = _pins()
    pfd = store.dfd(L.NS_PENDING)
    reqs = []
    try:
        for n in sorted(R.list_names(pfd)):
            if n in seen:
                continue
            try:
                req = R.read_request(pfd, n, expect_uid=su, expect_gid=sg)
            except (R.EgressReqError, OSError):
                continue
            if req["owner_uid"] != a.owner:
                continue
            reqs.append({"reqid": n, "op": req["op"], "host": req["host"], "port": req["port"],
                         "state": _state_of(store, n)})
    finally:
        os.close(pfd)
    return {"status": "ok", "requests": reqs, "decided": decided}


def cmd_status(a):
    """One ATTEMPT's outcome by reqid. LOCK-FREE: a re-read of the terminal before returning any non-terminal
    state closes the TOCTOU (approve writes the terminal BEFORE the reaper clears pending), so a status poll
    never blocks behind an approve. An unknown / foreign / degraded reqid all return not-found (no oracle)."""
    store = Store(a.base)
    reqid = a.reqid
    if _not_installed(store):
        return {"status": "not-found", "reqid": reqid}
    ru, su, sg = _pins()

    def _terminal():
        dfd, efd = _term_fds(store)
        try:
            try:
                return R.read_terminal(dfd, efd, reqid, root_uid=ru, svc_uid=su, svc_gid=sg)
            except R.EgressReqError:
                return "degraded"
        finally:
            os.close(dfd)
            os.close(efd)

    def _out(term):
        if term.get("owner_uid") != a.owner:
            return {"status": "not-found", "reqid": reqid}
        return {"status": "ok", "reqid": reqid, "state": term.get("state"), "reason": term.get("reason"),
                "op": term.get("op"), "host": term.get("host"), "port": term.get("port"), "ts": term.get("ts")}

    term = _terminal()
    if isinstance(term, dict):
        return _out(term)
    if term == "degraded":
        return {"status": "not-found", "reqid": reqid}
    pfd = store.dfd(L.NS_PENDING)
    try:
        try:
            req = R.read_request(pfd, reqid, expect_uid=su, expect_gid=sg)
        except (R.EgressReqError, OSError):
            req = None
    finally:
        os.close(pfd)
    if req is not None and req.get("owner_uid") == a.owner:
        term = _terminal()                           # re-read: a decision may have landed since the first read
        if isinstance(term, dict):
            return _out(term)
        if term == "degraded":                       # a degraded pair on the reread -> not-found (no oracle)
            return {"status": "not-found", "reqid": reqid}
        stt = "under-review" if _leased(store, reqid) else "pending"
        return {"status": "ok", "reqid": reqid, "state": stt, "op": req.get("op"),
                "host": req.get("host"), "port": req.get("port")}
    term = _terminal()
    if isinstance(term, dict):
        return _out(term)
    return {"status": "not-found", "reqid": reqid}


def _clear(store, reqid):
    dfd = store.dfd(L.NS_PENDING)
    try:
        R._unlink_quiet(dfd, reqid)
    finally:
        os.close(dfd)


def _quarantine_invalid(store):
    """Move any INVALID pending entry OUT of the live namespace so it can neither wedge the expiry sweep nor
    permanently consume the pending cap. Invalid = a non-reqid NAME, a NON-REGULAR file, OR unparseable/
    type-wrong CONTENT (read_request rejects it). v2 has no owner/ sidecar to sweep."""
    _ru, su, sg = _pins()
    pfd = store.dfd(L.NS_PENDING)
    try:
        for n in R.list_names(pfd):
            if not _REQID_RE.match(n):
                R._quarantine_at(pfd, n)
                continue
            try:
                R.read_request(pfd, n, expect_uid=su, expect_gid=sg)
            except (R.EgressReqError, OSError, TypeError, ValueError):
                R._quarantine_at(pfd, n)
    finally:
        os.close(pfd)


def cmd_expire(a):
    """Reaper EXPIRY SWEEP (PLAN 1.6, v2). Under the data lock: expire past-TTL un-leased pending (self-
    attributing `expired` terminal in expiry/), clear pending for already-decided reqids, and retention-GC
    expiry/. A LEASED reqid (published/claims/<reqid>) is under review by root -> never expired; a malformed/
    wrongly-owned lease suppresses expiry AND surfaces a root-zone failure (arch §7). A degraded (two-terminal)
    reqid is left for the operator. v2: the reaper NEVER touches root-private/ or published/ (claim recovery
    + root-decision GC are the root approve tool's job)."""
    import fcntl
    store = Store(a.base)
    if store.probe() == L.ABSENT:
        return {"status": "ok", "expired": [], "cleaned": [], "degraded": [], "gc": 0, "leased": [],
                "lease_faults": []}
    lfd = _open_lock(a.lock)
    fcntl.flock(lfd, fcntl.LOCK_EX)
    ru, su, sg = _pins()
    expired, cleaned, degraded, leased, lease_faults = [], [], [], [], []
    pfd = dfd = efd = cfd = None
    try:
        _quarantine_invalid(store)
        pfd, dfd, efd, cfd = (store.dfd(L.NS_PENDING), store.dfd(L.NS_DECISIONS),
                              store.dfd(L.NS_EXPIRY), store.dfd(L.NS_CLAIMS))
        for n in R.list_names(pfd):
            if not _REQID_RE.match(n):
                continue
            # TERMINAL FIRST (precedence): a decided reqid whose pending lingers is
            # cleared EVEN IF a leftover lease still exists (root wrote the decision before removing the lease).
            try:
                term = R.read_terminal(dfd, efd, n, root_uid=ru, svc_uid=su, svc_gid=sg)
            except R.EgressReqError:
                degraded.append(n)
                continue
            if term:
                _clear(store, n)                      # decided but pending not cleared -> drop it (drvps duty)
                cleaned.append(n)
                continue
            # LEASE: under review by root -> never expire; a suspect lease surfaces a fault (still suppress)
            lst, _lease = R.lease_status(cfd, n, a.now, expect_root_uid=ru, expect_svc_gid=sg)
            if lst != R.LEASE_NONE:
                leased.append(n)                      # any lease -> under review by root -> never expire
                if lst in (R.LEASE_SUSPECT, R.LEASE_STALE):
                    lease_faults.append(n)            # malformed OR ambiguously-stale root claim -> surface (arch §7)
                continue
            try:
                req = R.read_request(pfd, n, expect_uid=su, expect_gid=sg)
            except (R.EgressReqError, OSError):
                continue
            if a.now - req["ts"] >= a.ttl:
                R.write_expiry_decision(efd, n, a.now, group_gid=sg, owner_uid=req["owner_uid"], op=req["op"],
                                        host=req["host"], port=req["port"])
                _clear(store, n)
                expired.append(n)
        gc = R.gc_expiry(efd, dfd, pfd, a.retention, a.now, expect_svc_uid=su, expect_svc_gid=sg) if a.retention > a.ttl else 0
    finally:
        for fd in (pfd, dfd, efd, cfd):
            if fd is not None:
                os.close(fd)
        fcntl.flock(lfd, fcntl.LOCK_UN)
        os.close(lfd)
    return {"status": "ok", "expired": expired, "cleaned": cleaned, "degraded": degraded,
            "leased": leased, "lease_faults": lease_faults, "gc": gc}


def main(argv):
    p = argparse.ArgumentParser(prog="drvps_egress_member")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("submit", "list", "status"):
        s = sub.add_parser(name)
        s.add_argument("--base", required=True)
        s.add_argument("--owner", type=int, required=True)
        if name == "submit":
            s.add_argument("--fleet", required=True)
            s.add_argument("--op", required=True, choices=["add-splice", "remove-splice"])
            s.add_argument("--host", required=True)
            s.add_argument("--port", type=int, required=True)
            s.add_argument("--ts", type=int, required=True)
        if name == "status":
            s.add_argument("--reqid", required=True)
    se = sub.add_parser("expire")
    se.add_argument("--base", required=True)
    se.add_argument("--ttl", type=int, required=True)
    se.add_argument("--now", type=int, required=True)
    se.add_argument("--retention", type=int, default=0)
    se.add_argument("--claim-ttl", dest="claim_ttl", type=int, default=3600)   # accepted for compat; v2 unused
    a = p.parse_args(argv)
    if a.cmd in ("submit", "expire"):
        a.lock = _lock_path(a.base)
    if getattr(a, "owner", 0) < 0:
        print(json.dumps({"status": "refused", "reason": "bad-owner"}))
        return 2
    try:
        out = {"submit": cmd_submit, "list": cmd_list, "status": cmd_status, "expire": cmd_expire}[a.cmd](a)
    except L.LayoutError as e:                        # a DAMAGED store -> fail closed, never a stack trace
        print(json.dumps({"status": "error", "reason": "store-damaged", "detail": str(e)[:120]}))
        return 1
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"status": "error", "reason": "internal", "detail": str(e)[:120]}))
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
