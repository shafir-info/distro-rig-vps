#!/usr/bin/env python3
"""drvps-top PUBLISHER core (CONCEPT-DRVPS-TOP-SHARE). The PRODUCER transform: a normalized rig
inventory -> a valid feed frame, applying the contract's producer rules (masking, reconcile<->live
matrix, untracked projection, counters, base_flag, c_other) so drvps_top_feed.serialize() accepts it.

`build_feed` is PURE + offline-testable (round-tripped through the validator). The LIVE
acquisition (store.db + libvirt reads, as User=drvps) and the atomic /run/drvps-top/feed writer are
separate, live-gated functions -- they cannot be proven offline (real-environment-smoke) so they log
and are deferred to the operator's isolated-env run. ASCII only.
"""
from __future__ import annotations
import errno
import fcntl
import os
import re
import subprocess
import sys
import time

import drvps_top_feed as F


class PublishError(ValueError):
    """A producer/acquisition-consistency failure -> the caller retains the prior frame (fail closed)."""


class StoreGateError(PublishError):
    """The store failed store_init's read-only refusal set (schema/index/trigger/invariant) -> DB down."""


def _base(rec):
    return F.make_base_flag(rec.get("base_kind"), rec.get("base_distro"), rec.get("base_hex"))


CPU_FIELD_MAX = 1000000        # the validator's absolute cpu field cap (_dashint f[9], 1000000)


def _valid_stats(cpu, ram_cur, ram_max, host_cpu):
    """A COMPLETE, in-range stats tuple. Any bad/missing/out-of-range value -> False -> the row emits
    all `--` (never aborts the publish, per C-§4.1). Mirrors EVERY validator numeric check: the
    ABSOLUTE field caps (cpu<=1e6, ram<=2^63-1) AND the relational ones (cpu<=host_cpu*1000,
    ram_cur<=ram_max), so a producer can never build a stats tuple serialize() would reject."""
    for v in (cpu, ram_cur, ram_max):
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return False
    if cpu > CPU_FIELD_MAX or cpu > host_cpu * 1000:
        return False
    if ram_cur > F.MAX_U63 or ram_max > F.MAX_U63:
        return False
    return ram_cur <= ram_max


def build_feed(instance, seq, clock, sources, host, records, live_domains, ownerpolicy="no",
               stats_ran=True):
    """Produce feed bytes from a normalized inventory. NEVER builds a frame the validator would reject,
    and NEVER silently substitutes data: a live-backed row with a bad live_state FAILS CLOSED
    (PublishError); a bad stats tuple becomes `--`. `records`: VM dicts (reconcile_class,vm_id,vm_name,
    store_state,live_state,vm_class,created_epoch,base_kind/distro/hex,cpu/ram_cur/ram_max,domain_uuid
    [,owner_display]). `live_domains`: [(name,uuid)] over ALL live libvirt domains (for c_other)."""
    db_ok = sources["db_status"] == "ok"
    lv_ok = sources["libvirt_status"] == "ok"
    lv_down = sources["libvirt_status"] == "down"
    db_down = sources["db_status"] == "down"
    masked = not (db_ok and lv_ok)

    use_records = [] if db_down else records        # DB down => status-only (else serialize -> dbdown-rows)
    rows, claimed_uuids = [], set()
    n_elig = n_present = 0                           # stats eligibility on the IDENTIFIED normal domains
    tally = {"absent": 0, "uuid": 0, "name": 0, "untracked": 0, "uuidbad": 0}
    for rec in use_records:
        orig_rc = rec["reconcile_class"]            # provenance: project + tally by the ORIGINAL class
        rc = "unreconciled" if masked else orig_rc
        # live_state: `unknown` iff libvirt down; a live-backed class needs a REAL observed state
        if lv_down:
            live = "unknown"
        elif orig_rc in ("normal", "untracked"):
            live = rec.get("live_state")
            if live not in F.LIVE_REAL:             # fail closed -- never fabricate a state
                raise PublishError("bad live_state %r for %s row %s" % (live, orig_rc, rec.get("vm_id")))
        else:                                       # absent/uuid/name/uuidbad -> no attributed live domain
            live = "--"
        # store-field projection keyed on the ORIGINAL class (an untracked domain has NO store row),
        # applied even when masking has rewritten reconcile_class -> unreconciled.
        if orig_rc == "untracked":
            vm_name, store_state, vm_class, base_flag, created = "--", "unknown", "--", "unknown", 0
        else:
            vm_name = rec.get("vm_name", "--")
            store_state = rec.get("store_state", "unknown")
            vm_class = rec.get("vm_class", "--")
            base_flag = _base(rec)
            created = rec.get("created_epoch", 0)
        # stats: only an eligible (FINAL normal+running) row, and only a COMPLETE valid tuple
        cpu = ram_cur = ram_max = None
        if rc == "normal" and live == "running" and stats_ran:
            c, rcur, rmax = rec.get("cpu"), rec.get("ram_cur"), rec.get("ram_max")
            if _valid_stats(c, rcur, rmax, host["host_cpu_count"]):
                cpu, ram_cur, ram_max = c, rcur, rmax
        row = {"reconcile_class": rc, "vm_id": rec["vm_id"], "vm_name": vm_name,
               "store_state": store_state, "live_state": live, "vm_class": vm_class,
               "base_flag": base_flag, "created_epoch": created,
               "cpu": cpu, "ram_cur": ram_cur, "ram_max": ram_max}
        if ownerpolicy != "no":
            row["owner_display"] = "-" if orig_rc == "untracked" else rec.get("owner_display", "-")
        rows.append(row)
        if not masked and orig_rc in tally:
            tally[orig_rc] += 1
        # only classes that ACTUALLY claim a live-domain uuid suppress it from c_other (base sec 5.2)
        if not masked and orig_rc in ("normal", "name", "uuid", "untracked") and rec.get("domain_uuid"):
            claimed_uuids.add(rec["domain_uuid"])
        # stats eligibility = a normal domain shown running (rc is FINAL; masked==down anyway). A running row
        # is PRESENT iff its complete tuple sampled. A FAILED domstats is represented `running` with NO cpu
        # (in classify), so it is eligible-but-not-present here -> a sample failure yields partial/down, never a
        # false `ok`; this matches the validator (which also keys eligibility on live_state==running).
        if rc == "normal" and live == "running":
            n_elig += 1
            if cpu is not None:
                n_present += 1

    # stats_status DERIVED (C-§4.1): not-ran/masked -> down; any failed sample -> partial/down (never trivially
    # ok); zero-eligible -> ok; none present -> down; all present -> ok; some -> partial.
    if not stats_ran or masked:
        stats_status, stats_bt = "down", 0
    elif n_elig == 0:
        stats_status, stats_bt = "ok", sources["stats_boottime_ns"]
    elif n_present == 0:
        stats_status, stats_bt = "down", 0
    elif n_present == n_elig:
        stats_status, stats_bt = "ok", sources["stats_boottime_ns"]
    else:
        stats_status, stats_bt = "partial", sources["stats_boottime_ns"]

    if masked:
        c = dict(c_absent=0, c_uuid=0, c_name=0, c_untracked=0, c_other=0, c_ledger=0)
    else:
        c = dict(c_absent=tally["absent"], c_uuid=tally["uuid"], c_name=tally["name"],
                 c_untracked=tally["untracked"], c_ledger=tally["uuidbad"],
                 c_other=F.count_other(live_domains, claimed_uuids))

    header = {
        "instance": instance, "seq": seq,
        "realtime_s": clock["realtime_s"], "boottime_ns": clock["boottime_ns"],
        "interval_ms": clock["interval_ms"],
        "db_status": sources["db_status"], "db_boottime_ns": sources["db_boottime_ns"],
        "libvirt_status": sources["libvirt_status"], "libvirt_boottime_ns": sources["libvirt_boottime_ns"],
        "stats_status": stats_status, "stats_boottime_ns": stats_bt,
        "load1_milli": host["load1_milli"], "memavail_kib": host["memavail_kib"],
        "host_cpu_count": host["host_cpu_count"], "ownerpolicy": ownerpolicy,
        **c,
    }
    return F.serialize(header, rows)


# =============================================================================================
# LIVE ACQUISITION (privileged: sqlite3 read-only + virsh -r) + atomic feed write (sec 7.1/8).
# The pure build_feed() above is offline-proven; the acquisition touches the outside world, so it
# is SEAMED (a db path + a virsh runner) for offline tests and LOGGED, with real sqlite/virsh proven
# in the container/operator run (real-environment-smoke). ASCII only.
# =============================================================================================
import sqlite3                                              # noqa: E402  (grouped with the acquisition layer)

REQUIRED_COLS = {
    "vms": ("owner_uid", "class", "domain_uuid", "artifact_id", "state", "name", "created_at"),
    "images": ("kind", "name", "provenance", "artifact_id"),
    "snapshots": ("parent_golden_id", "secret_bearing", "validation_status", "created_at", "name"),
}
REQUIRED_INDEXES = ("images_kind_name_uq", "snapshots_name_uq")
REQUIRED_TRIGGERS = ("images_kind_ins", "images_kind_upd", "snapshots_ins", "snapshots_upd")
_RE_UUID = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_RE_VMID = F.RE_VMID
_RE_DIGITS = re.compile(r"\A[0-9]{1,18}\Z")
_LIVE_NUM = {"0": "nostate", "1": "running", "2": "blocked", "3": "paused", "4": "shutdown",
             "5": "shutoff", "6": "crashed", "7": "pmsuspended"}   # 0 = a GENUINE VIR_DOMAIN_NOSTATE observation
VIRSH_TIMEOUT = 4.0
MAX_VIRSH_OUT = 1 << 20                                     # cap any single virsh capture
STATS_PASS_DEADLINE = 20.0                                  # whole normal+untracked stats pass bound


def _b2s(v):
    """sqlite text_factory=bytes value -> strict-ASCII str, or None (unrepresentable/NULL/non-text)."""
    if v is None:
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        try:
            return bytes(v).decode("ascii", "strict")
        except UnicodeDecodeError:
            return None
    return None


def connect_ro(db_path):
    con = sqlite3.connect("file:%s?mode=ro&cache=private" % db_path, uri=True, timeout=0.75)
    con.text_factory = bytes                               # hostile text -> bytes; the contract canonicalizes
    con.execute("PRAGMA query_only=ON")
    return con


def _names(con, kind):
    return {_b2s(r[0]) for r in con.execute("SELECT name FROM sqlite_master WHERE type=?", (kind,))}


def store_gate(con):
    """Reproduce dr_vps_store_init's READ-ONLY refusal set: required columns, the UNIQUE indexes + CHECK
    triggers (type-checked), and the data invariants. Any failure -> StoreGateError (never migrates)."""
    for tbl, cols in REQUIRED_COLS.items():
        have = {_b2s(r[1]) for r in con.execute("PRAGMA table_info(%s)" % tbl)}
        miss = [c for c in cols if c not in have]
        if miss:
            raise StoreGateError("schema:%s missing %s" % (tbl, ",".join(miss)))
    idx, trg = _names(con, "index"), _names(con, "trigger")
    for o in REQUIRED_INDEXES:
        if o not in idx:
            raise StoreGateError("enforcement: unique index %s missing" % o)
    for o in REQUIRED_TRIGGERS:
        if o not in trg:
            raise StoreGateError("enforcement: check trigger %s missing" % o)
    inv = con.execute(
        "SELECT (SELECT count(*) FROM images WHERE kind NOT IN ('golden','snapshot'))"
        " + (SELECT count(*) FROM images WHERE (kind='golden' AND artifact_id NOT GLOB 'drvps-raw-v1-*')"
        "        OR (kind='snapshot' AND artifact_id NOT GLOB 'drvps-snap-v1-*'))"
        " + (SELECT count(*) FROM images i WHERE i.kind='snapshot'"
        "        AND NOT EXISTS(SELECT 1 FROM snapshots s WHERE s.id=i.artifact_id))"
        " + (SELECT count(*) FROM snapshots s"
        "        WHERE NOT EXISTS(SELECT 1 FROM images i WHERE i.artifact_id=s.id AND i.kind='snapshot'))").fetchone()[0]
    if inv != 0:
        raise StoreGateError("invariant: %s snapshot/kind violation(s)" % inv)


def read_store_rows(con):
    """One read-only snapshot: each vms row LEFT JOIN images -> a dict of typed/None fields."""
    q = ("SELECT v.id, v.owner_uid, v.state, v.class, v.domain_uuid, v.name, v.created_at, i.kind,"
         " CASE WHEN json_valid(i.provenance) THEN json_extract(i.provenance,'$.distro') END, v.artifact_id"
         " FROM vms v LEFT JOIN images i ON i.artifact_id=v.artifact_id ORDER BY v.created_at")
    out = []
    for r in con.execute(q):
        vm_id = _b2s(r[0])
        if vm_id is None or not _RE_VMID.match(vm_id):     # a gate-passing store with a corrupt primary key is
            raise StoreGateError("corrupt vm.id %r" % (r[0],))  # corruption -> fail the WHOLE acquisition (db down)
        out.append({"id": vm_id, "owner_uid": _b2s(r[1]), "state": r[2], "class": _b2s(r[3]),
                    "domain_uuid": _b2s(r[4]), "name": r[5], "created_at": _b2s(r[6]),
                    "kind": _b2s(r[7]), "distro": r[8], "artifact_id": _b2s(r[9])})
    return out


# ---- virsh runner (read-only, process-group bounded) ----------------------------------------
def _run_bounded(argv, timeout):
    """Run a read-only subprocess in its OWN session (setsid) so a TERM-ignoring descendant is killed via the
    process GROUP on timeout; capture <= MAX_VIRSH_OUT bytes. Returns (rc, stdout_str): rc is the process exit
    (0 = success), or NEGATIVE on spawn-failure/timeout so the caller distinguishes a genuine success (rc 0,
    possibly empty) from a failure/timeout with partial output. Never raises."""
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return -1, ""
    rc = -1
    try:
        out, _ = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), 9)                # kill the WHOLE group, not just the child
        except OSError:
            pass
        try:
            out, _ = p.communicate(timeout=2)
        except Exception:
            out = b""
        rc = -2                                            # timed out -> a FAILURE regardless of partial stdout
    except Exception:
        out = b""
    if out is None:
        out = b""
    try:
        return rc, out[:MAX_VIRSH_OUT].decode("ascii", "replace")
    except Exception:
        return rc, ""


def _virsh_argv(virsh, args):
    return [virsh, "-r", "--no-pkttyagent", "-c", os.environ.get("DR_LIBVIRT_URI", "qemu:///system")] + list(args)


def parse_identity(text):
    """virsh list --all --uuid --name -> [(uuid, name)] (name '' if none). Skips headers/separators."""
    out = []
    for ln in text.split("\n"):
        toks = ln.split()
        if not toks or toks[0] == "Id" or set(ln.strip()) <= set("-"):
            continue
        uuid = next((t.lower() for t in toks if _RE_UUID.match(t.lower())), None)
        if uuid is None:
            continue
        name = next((t for t in toks if t != uuid and not t.isdigit() and t != "-"), "")
        out.append((uuid, name))
    return out


def parse_domstats(text):
    """virsh domstats --raw output -> {state,cpu_time,vcpu,balloon_cur,balloon_max} (str values or None)."""
    d = {}
    for ln in text.split("\n"):
        if "=" not in ln or ln.startswith("Domain:"):
            continue
        k, v = ln.split("=", 1)
        d[k.strip()] = v.strip()
    return {"state": d.get("state.state"), "cpu_time": d.get("cpu.time"),
            "balloon_cur": d.get("balloon.current"), "balloon_max": d.get("balloon.maximum")}


def _store_state(raw):
    s = F.canonicalize(raw, F.LEN["store_state"], "unknown")
    return s if s else "unknown"


def _created_epoch(s):
    """created_at -> epoch. Accepts an integer epoch OR an ISO-8601 UTC timestamp (the store writes either).
    A value that is neither parses to 0 (the row's AGE renders `--`) -- created_at is a display field, not
    identity, so a best-effort fallback here does not weaken any security/reconcile decision."""
    if s is None:
        return 0
    if _RE_DIGITS.match(s):
        return int(s)
    try:
        from datetime import datetime, timezone
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return max(0, int(t.timestamp()))
    except (ValueError, OverflowError):
        return 0


_owner_cache = {}


def _nss_name(uid_s):
    """uid string -> the account name, or None. Cached; a missing/invalid uid is None (owner shows `-`)."""
    if uid_s in _owner_cache:
        return _owner_cache[uid_s]
    nm = None
    try:
        import pwd
        nm = pwd.getpwuid(int(uid_s)).pw_name
    except (KeyError, ValueError, OverflowError):
        nm = None
    _owner_cache[uid_s] = nm
    return nm


def _owner_display(policy, uid_s, namefn):
    """Per the SHARED contract's owner grammar: policy 'uid' -> '<uid>' (numeric) or '-'; 'name-and-uid' ->
    '<uid>:<name>' or '-'. A NULL/non-numeric uid, or (for name-and-uid) an NSS miss, is the '-' UNAVAILABLE
    sentinel -- NEVER 'operator' or a bare name (both fail the validator)."""
    if policy == "no":
        return None
    if uid_s is None or not uid_s.isdigit():
        return "-"
    if policy == "uid":
        return uid_s
    nm = namefn(uid_s) if namefn else None                 # name-and-uid needs a non-empty name (contract)
    maxnm = F.LEN["owner_display"] - len(uid_s) - 1         # keep "<uid>:<name>" within the 64 cap
    nm = F.canonicalize(nm, max(1, maxnm), "") if nm else ""
    return "%s:%s" % (uid_s, nm) if nm else "-"


def _cpu_field(cpu_prev, cpu_now, bt_prev, bt_now, host_cpu):
    """Aggregate CPU% * 10 (the feed's deci-unit; the viewer renders /10) from cpu.time deltas over the
    boottime delta. A reset/wrap (cpu decreases) or non-positive wall delta -> None. Clamped to the cap."""
    if cpu_prev is None or cpu_now is None or cpu_now < cpu_prev or bt_now <= bt_prev:
        return None
    v = int(round(1000 * (cpu_now - cpu_prev) / (bt_now - bt_prev)))
    return max(0, min(v, host_cpu * 1000, CPU_FIELD_MAX))


def classify(store_rows, identity, domstats_fn, ownerpolicy="no", namefn=None,
             baseline=None, boottime_ns=0, host_cpu=1):
    """Reconcile each store row against the live identity frame (mirrors acquire_top), fetch live_state
    (+ balloon ram + cpu.time) for live-backed rows via domstats_fn(uuid), compute CPU% from the prior
    tick's `baseline`, and project untracked live domains. Returns (records, live_domains, new_baseline);
    new_baseline threads cpu.time+boottime to the next tick. domstats_fn(uuid)->parse_domstats or None."""
    have = bool(identity)
    baseline = baseline or {}
    new_baseline = {}
    u2n = {}
    n2u = {}
    for uuid, name in identity:
        u2n[uuid] = name
        if name:
            n2u.setdefault(name, uuid)
    records = []
    claimed = set()

    def _sample(uuid):
        """-> (live_state, cpu, ram_cur, ram_max). A failed/deadline-skipped/unrecognized-state sample yields
        live_state 'running' with cpu None (eligible-but-unsampled). Records the cpu baseline only on a
        successful cpu.time read."""
        ds = domstats_fn(uuid) if domstats_fn else None
        # a RECOGNIZED virDomainState (0-7, incl. 0=genuine nostate) is used as-is. A None domstats (failed/
        # timed-out/deadline) OR an rc-0 result with a missing/unrecognized/future state is a FAILED sample: the
        # domain is live-matched but unread -> represent it `running` with NO stats (eligible-but-not-present ->
        # partial/down, never a false `ok`, never a fabricated `nostate`).
        st = _LIVE_NUM.get(ds["state"]) if (ds and ds.get("state")) else None
        if st is None:
            # GATE: an unrecognized state discards ANY cpu/balloon the same record carried AND leaves the cpu
            # baseline UNTOUCHED -- a failed sample must never leak a metric that would make it stats-present.
            return "running", None, None, None
        rc = rm = cpu = None
        if (ds.get("balloon_cur") or "").isdigit() and (ds.get("balloon_max") or "").isdigit():
            rc, rm = int(ds["balloon_cur"]), int(ds["balloon_max"])
        ct = ds.get("cpu_time")
        if ct is not None and ct.isdigit():
            ctv = int(ct)
            prev = baseline.get(uuid)
            if prev is not None:
                cpu = _cpu_field(prev[0], ctv, prev[1], boottime_ns, host_cpu)
            new_baseline[uuid] = (ctv, boottime_ns)        # baseline for the NEXT tick
        return st, cpu, rc, rm

    for row in store_rows:
        vm_id = row["id"]
        if vm_id is None or not _RE_VMID.match(vm_id):
            continue                                       # a non-grammatical store id cannot be represented
        du = row["domain_uuid"]
        du_ok = du is not None and _RE_UUID.match(du)
        live_state = "--"
        cpu = ram_cur = ram_max = None
        if not du_ok:
            rc = "uuidbad"
        elif have and du in u2n:
            claimed.add(du)
            rc = "normal" if u2n[du] == vm_id else "name"
        elif have and vm_id in n2u:
            claimed.add(n2u[vm_id])
            rc = "uuid"
        else:
            rc = "absent"
        if rc == "normal":
            live_state, cpu, ram_cur, ram_max = _sample(du)
        vm_class = row["class"] if row["class"] in F.VM_CLASS else "--"
        rec = {"reconcile_class": rc, "vm_id": vm_id,
               "vm_name": F.canonicalize(row["name"], F.LEN["vm_name"], "-"),
               "store_state": _store_state(row["state"]), "live_state": live_state,
               "vm_class": vm_class, "created_epoch": _created_epoch(row["created_at"]),
               "base_kind": row["kind"], "base_distro": row["distro"],
               "base_hex": (row["artifact_id"].rsplit("-", 1)[-1][:8] if row["artifact_id"] else None),
               "cpu": cpu, "ram_cur": ram_cur, "ram_max": ram_max, "domain_uuid": du if du_ok else None}
        if ownerpolicy != "no":
            rec["owner_display"] = _owner_display(ownerpolicy, row["owner_uid"], namefn)
        records.append(rec)

    # untracked: a drvps-vm-shaped live domain not consumed by any store row
    for uuid, name in identity:
        if uuid in claimed or not (name and _RE_VMID.match(name)):
            continue
        live_state, _cpu, ram_cur, ram_max = _sample(uuid)   # untracked cpu is not emitted (build_feed forces --)
        rec = {"reconcile_class": "untracked", "vm_id": name, "vm_name": "--",
               "store_state": "unknown", "live_state": live_state, "vm_class": "--",
               "created_epoch": 0, "base_kind": None, "base_distro": None, "base_hex": None,
               "cpu": None, "ram_cur": ram_cur, "ram_max": ram_max, "domain_uuid": uuid}
        if ownerpolicy != "no":
            rec["owner_display"] = "-"
        records.append(rec)
    return records, list(identity), new_baseline


def open_feed_dir_locked(feed_dir):
    """Open the runtime dir and take the SINGLE-PUBLISHER lock: a non-blocking exclusive flock HELD for the
    caller's lifetime (the loop keeps this fd open). A 2nd publisher gets EWOULDBLOCK -> PublishError so it can
    exit with the dedicated code. Returns the dir fd (used for every subsequent write_feed)."""
    dfd = os.open(feed_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(dfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        os.close(dfd)
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise PublishError("another publisher holds the feed lock")
        raise
    return dfd


def write_feed(dfd, blob, feed_uid, feed_gid, feed_mode=0o640):
    """Publish per sec 7.1 into the ALREADY-LOCKED dir fd `dfd` (the caller holds the single-publisher flock):
    sweep stale temps (via the trusted dir fd), create a unique temp (O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW 0600),
    write (rejecting a 0-byte short write) + fchown feed_uid:feed_gid + fchmod feed_mode + fsync,
    renameat(dir, tmp, dir, 'feed')."""
    for n in os.listdir(dfd):                              # the TRUSTED dir fd, not a fresh path lookup
        if n.startswith(".feed.tmp."):
            try:
                os.unlink(n, dir_fd=dfd)
            except OSError:
                pass
    tmp = ".feed.tmp.%d.%s" % (os.getpid(), os.urandom(6).hex())
    tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    published = False
    try:
        mv, off = memoryview(blob), 0
        while off < len(mv):
            n = os.write(tfd, mv[off:])
            if n <= 0:                                     # a 0-byte write must not spin -> treat as a write failure
                raise PublishError("short write to the feed temp")
            off += n
        os.fchown(tfd, feed_uid, feed_gid)
        os.fchmod(tfd, feed_mode)
        os.fsync(tfd)
        os.close(tfd)
        tfd = -1
        os.rename(tmp, "feed", src_dir_fd=dfd, dst_dir_fd=dfd)   # atomic same-dir replace (no follow of target)
        published = True
    finally:
        if tfd != -1:
            os.close(tfd)
        if not published:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass


# ---- host + clock sampling (real /proc; seamable by passing host/clock in) ------------------
def sample_host():
    load1_milli = 0
    memavail_kib = 0
    try:
        with open("/proc/loadavg") as fh:
            load1_milli = int(round(float(fh.read().split()[0]) * 1000))
    except (OSError, ValueError, IndexError):
        pass
    try:
        with open("/proc/meminfo") as fh:
            for ln in fh:
                if ln.startswith("MemAvailable:"):
                    memavail_kib = int(ln.split()[1])
                    break
    except (OSError, ValueError, IndexError):
        pass
    return {"load1_milli": max(0, load1_milli), "memavail_kib": max(0, memavail_kib),
            "host_cpu_count": os.cpu_count() or 1}


def sample_clock(interval_ms):
    return {"realtime_s": int(time.time()), "boottime_ns": time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            "interval_ms": interval_ms}


def acquire_and_build(instance, seq, db_path, virsh, clock, host, ownerpolicy="no", stats_ran=True,
                      baseline=None):
    """The full real pipeline. A store-gate/sqlite failure -> db_status=down (status-only frame); a
    libvirt failure -> libvirt_status=down (masked frame). Never raises on acquisition -- fail closed
    to a valid degraded frame so the viewer shows source-down, not a fabricated empty rig. Returns
    (blob, new_baseline) -- thread new_baseline back in for cross-tick CPU%."""
    now_bt = clock["boottime_ns"]
    sources = {"db_status": "ok", "db_boottime_ns": now_bt,
               "libvirt_status": "ok", "libvirt_boottime_ns": now_bt, "stats_boottime_ns": now_bt}
    store_rows = []
    try:
        con = connect_ro(db_path)
        try:
            store_gate(con)
            store_rows = read_store_rows(con)
        finally:
            con.close()
    except (StoreGateError, sqlite3.Error, OSError):
        sources["db_status"] = "down"
        sources["db_boottime_ns"] = 0
    ident_rc, ident_txt = _run_bounded(_virsh_argv(virsh, ("list", "--all", "--uuid", "--name")), VIRSH_TIMEOUT)
    if ident_rc != 0:                                      # a FAILED/timed-out virsh -> libvirt DOWN (never trust partial output)
        sources["libvirt_status"] = "down"
        sources["libvirt_boottime_ns"] = 0
        identity = []
    else:
        identity = parse_identity(ident_txt)               # rc 0 with 0 domains is a legitimate empty inventory

    deadline = time.monotonic() + STATS_PASS_DEADLINE

    def domstats_fn(uuid):
        if time.monotonic() > deadline:                    # whole-pass bound: past the deadline -> no stat
            return None
        rc, out = _run_bounded(
            _virsh_argv(virsh, ("domstats", "--raw", "--nowait", "--state", "--cpu-total", "--balloon", uuid)),
            VIRSH_TIMEOUT)
        return parse_domstats(out) if rc == 0 else None    # a failed/timed-out stat -> no data (never partial)

    records, live_domains, new_baseline = classify(
        store_rows, identity, domstats_fn, ownerpolicy=ownerpolicy,
        namefn=(_nss_name if ownerpolicy == "name-and-uid" else None),
        baseline=baseline, boottime_ns=now_bt, host_cpu=host["host_cpu_count"])
    blob = build_feed(instance, seq, clock, sources, host, records, live_domains,
                      ownerpolicy=ownerpolicy, stats_ran=stats_ran)
    return blob, new_baseline


def _instance():
    v = os.environ.get("DRVPS_TOP_INSTANCE", "drvps-top")
    return v if F.RE_INSTANCE.match(v) else "drvps-top"


def main(argv):
    once = "--once" in argv
    interval_ms = 3000
    db_path = os.environ.get("DR_VPS_DB",
                             os.path.join(os.environ.get("DR_VPS_STATE_DIR", "/var/lib/distro-rig-vps"), "store.db"))
    virsh = os.environ.get("DR_VIRSH", "virsh")
    ownerpolicy = os.environ.get("DRVPS_TOP_OWNERPOLICY", "no")
    if ownerpolicy not in F.OWNER_POLICY:
        ownerpolicy = "no"
    inst = _instance()
    if once:
        clock = sample_clock(interval_ms)
        try:
            blob, _ = acquire_and_build(inst, 1, db_path, virsh, clock, sample_host(),
                                        ownerpolicy=ownerpolicy, stats_ran=True)
        except (PublishError, F.FeedError) as e:
            sys.stderr.write("drvps-top-publish: %s\n" % (e.args[0] if e.args else type(e).__name__))
            return 1
        sys.stdout.buffer.write(blob)
        return 0
    # live loop -> atomic write into the runtime dir. Take the SINGLE-PUBLISHER lock ONCE and HOLD it for the
    # whole loop; a 2nd publisher exits with the dedicated code 3 (never alternates writes with us).
    feed_dir = os.environ.get("DRVPS_TOP_FEED_DIR", "/run/drvps-top")
    feed_uid = int(os.environ.get("DRVPS_TOP_FEED_UID", str(os.getuid())))
    feed_gid = int(os.environ.get("DRVPS_TOP_FEED_GID", str(os.getgid())))
    try:
        dfd = open_feed_dir_locked(feed_dir)
    except PublishError:
        sys.stderr.write("drvps-top-publish: another publisher already holds %s -- exiting\n" % feed_dir)
        return 3
    except OSError as e:
        sys.stderr.write("drvps-top-publish: cannot open %s (%s)\n" % (feed_dir, e))
        return 4
    seq = 0
    baseline = {}
    try:
        while True:
            seq += 1
            clock = sample_clock(interval_ms)
            try:
                blob, baseline = acquire_and_build(inst, seq, db_path, virsh, clock, sample_host(),
                                                   ownerpolicy=ownerpolicy, stats_ran=True, baseline=baseline)
                write_feed(dfd, blob, feed_uid, feed_gid)
            except PublishError as e:
                sys.stderr.write("drvps-top-publish: retained prior frame (%s)\n" % (e.args[0] if e.args else "publish"))
            except (F.FeedError, OSError) as e:
                sys.stderr.write("drvps-top-publish: skip tick (%s)\n" % (e.args[0] if getattr(e, "args", None) else type(e).__name__))
            time.sleep(interval_ms / 1000.0)
    finally:
        os.close(dfd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
