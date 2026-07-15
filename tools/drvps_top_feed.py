#!/usr/bin/env python3
"""drvps-top shared FEED CONTRACT (schema v1) -- the SINGLE source of truth for the
publisher (serialize) and the viewer (parse+validate). Design: docs/CONCEPT-DRVPS-TOP-SHARE.md.

This module IS the normative schema: field counts, enums, numeric grammar, caps, per-field
rules, status/stamp invariants, owner grammar. Both sides import it; neither reimplements
parsing. ASCII only. No I/O, no rig access -- pure bytes<->objects.
"""
from __future__ import annotations
import re

VER = "1"
# ---- frozen caps ----------------------------------------------------------------------------
MAX_BYTES = 262144
MAX_ROWS = 4096
LEN = {"vm_name": 64, "store_state": 16, "base_flag": 48, "owner_display": 64,
       "vm_id": 40, "enum": 16, "instance": 32}
# ---- frozen enums ---------------------------------------------------------------------------
RECONCILE = {"normal", "absent", "uuid", "name", "untracked", "uuidbad", "unreconciled"}
# the 8 real virDomainState members (incl. `nostate` = VIR_DOMAIN_NOSTATE, an OBSERVED state, not a
# sentinel) + the two feed sentinels. Unlisted/future libvirt states fail-closed at the enum.
LIVE_STATE = {"nostate", "running", "paused", "shutoff", "crashed", "blocked", "shutdown",
              "pmsuspended", "unknown", "--"}
# the REAL (observed-domain) live states -- LIVE_STATE minus the two sentinels: `unknown` (libvirt
# unobservable) and `--` (no live domain attributed). A live-backed reconcile class needs one of these.
LIVE_REAL = LIVE_STATE - {"unknown", "--"}
VM_CLASS = {"throwaway", "service", "--"}
SRC_STATUS3 = {"ok", "stale", "down"}          # db, libvirt
STATS_STATUS = {"ok", "partial", "down"}       # stats
OWNER_POLICY = {"no", "uid", "name-and-uid"}
# ---- frozen grammars ------------------------------------------------------------------------
RE_INSTANCE = re.compile(r"\A[A-Za-z0-9_-]{1,32}\Z")
RE_VMID = re.compile(r"\Adrvps-vm-[0-9a-f]{16}\Z")
RE_BASEFLAG = re.compile(r"\A(golden:[a-z0-9]{1,16}@[0-9a-f]{8}|snapshot|orphan|unknown)\Z")
RE_UINT = re.compile(r"\A(0|[1-9][0-9]*)\Z")   # NO +/-, leading zero, whitespace, exponent
RE_TEXT = re.compile(r"\A[\x20-\x7e]*\Z")      # printable ASCII (TAB/CR/LF/NUL/non-ascii excluded)
MAX_U63 = (1 << 63) - 1
MAX_UID = (1 << 32) - 1          # 4294967295

class FeedError(ValueError):
    """Raised on any malformed feed; str(e) is a fixed, byte-free reason."""


MAX_DIGITS = 20

def _uint(tok, lo, hi, what):
    # length cap FIRST so a 4000-digit token can never reach int() and raise a raw ValueError
    if not (1 <= len(tok) <= MAX_DIGITS) or not RE_UINT.match(tok):
        raise FeedError("bad-number:%s" % what)
    try:
        v = int(tok)
    except ValueError:                       # defensive; RE_UINT + length should preclude it
        raise FeedError("bad-number:%s" % what)
    if v < lo or v > hi:
        raise FeedError("range:%s" % what)
    return v


def _dashint(tok, hi, what):
    if tok == "--":
        return None
    return _uint(tok, 0, hi, what)


def _enum(tok, allowed, what):
    if tok not in allowed:
        raise FeedError("bad-enum:%s" % what)
    return tok


def _text(tok, maxlen, what, allow_empty=False):
    if not RE_TEXT.match(tok):
        raise FeedError("bad-text:%s" % what)
    if len(tok) > maxlen:
        raise FeedError("too-long:%s" % what)
    if tok == "" and not allow_empty:
        raise FeedError("empty:%s" % what)
    return tok


# ---- producer-side canonicalizer (sec 6): bytes -> a safe printable field -------------------
def canonicalize(raw, maxlen, empty_placeholder="-"):
    """raw: bytes (from sqlite text_factory=bytes / libvirt / NSS). Return a printable-ASCII str
    <= maxlen with every byte outside 0x20..0x7e (incl TAB/CR/LF/NUL) replaced by '?'. Never
    used for identity keys (those must already be canonical or the acquisition fails)."""
    if maxlen < 1:
        raise FeedError("bad-maxlen")
    # a placeholder must itself be printable-ASCII and fit maxlen
    ph = "".join(c if 0x20 <= ord(c) <= 0x7e else "?" for c in str(empty_placeholder))[:maxlen] or "-"
    if raw is None:
        return ph
    if isinstance(raw, str):
        raw = raw.encode("latin-1", "replace")
    out = bytes((b if 0x20 <= b <= 0x7e else 0x3f) for b in raw)[:maxlen]
    s = out.decode("ascii")
    return s if s != "" else ph


RE_DISTRO = re.compile(r"\A[a-z0-9]{1,16}\Z")
RE_HEX8 = re.compile(r"\A[0-9a-f]{8}\Z")

def _ascii_strict(raw):
    """ANY value -> a str, or None if it is not a strict-ASCII str/bytes/bytearray. Producer
    provenance (kind, distro, short-id) may arrive as raw sqlite bytes (text_factory=bytes); a
    non-ASCII or non-string-like component is treated as unrepresentable rather than crashing.
    Total: never raises, so make_base_flag() is total for EVERY input type."""
    try:
        if isinstance(raw, str):
            return str.__str__(raw)               # EXACT plain-str copy: bypasses a subclass __str__
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).decode("ascii", "strict")
    except Exception:                             # a subclass overriding __bytes__/str() -> None
        return None
    return None                                   # None or any other type -> unrepresentable


def canon_distro(raw):
    """bytes/str -> a [a-z0-9]{1,16} distro token, lowercased; or None if it cannot be represented
    (non-ASCII, dash, space, uppercase-after-lowering that leaves non-[a-z0-9], too long, empty)."""
    s = _ascii_strict(raw)                        # already a plain str or None
    if s is None:
        return None
    s = s.lower()                                 # plain str: .lower() cannot be overridden to raise
    return s if RE_DISTRO.match(s) else None


def make_base_flag(kind, distro_raw, hex8):
    """The ONE deterministic base_flag producer (publishers MUST use this -> no divergence).
    EVERY provenance component (kind, distro, short-id) may arrive as raw sqlite bytes OR str; each
    is ASCII-decoded here. A malformed/unrepresentable distro OR hex makes the WHOLE
    golden field `unknown` -- never a partial/garbled `golden:...`. Total function: never raises."""
    if kind is None:
        return "orphan"               # explicit None -> orphan (an absent classification)
    k = _ascii_strict(kind)           # bytes/str -> str; undecodable/other type -> None -> unknown
    if k == "snapshot":
        return "snapshot"
    if k == "golden":
        d = canon_distro(distro_raw)
        h = _ascii_strict(hex8)
        if d is None or h is None or not RE_HEX8.match(h):
            return "unknown"
        return "golden:%s@%s" % (d, h)
    if k in ("", "orphan"):           # empty/explicit orphan -> orphan
        return "orphan"
    return "unknown"                  # unknown string, undecodable, or unsupported type


def count_other(domains, claimed_uuids):
    """The ONE deterministic `c_other` producer (NORMATIVE; publishers MUST use this -> no divergence
    on the one non-row-derivable counter). `domains` = an iterable of (name, uuid) over
    ALL live libvirt domains (active AND inactive) from the live-identity frame; `claimed_uuids` = the
    set of live-domain UUIDs already represented by a reconcile V row (normal/name/uuid/untracked).
    c_other = live domains whose NAME is NOT drvps-vm-shaped AND whose UUID is not claimed (base
    CONCEPT sec 5.2: a domain claimed by a name!=/uuid!= row is NOT also counted in other). A malformed/
    None domain name is not drvps-shaped -> counted. A true count > 65535 FAILS the libvirt acquisition
    (raise FeedError) so the caller retains the prior frame -- it never saturates. Total; deterministic."""
    n = 0
    claimed = set(claimed_uuids)
    for name, uuid in domains:
        nm = _ascii_strict(name)
        if nm is not None and RE_VMID.match(nm):
            continue                              # drvps-shaped -> a tracked/untracked V row, never `other`
        if uuid in claimed:
            continue                              # already represented by a reconcile row
        n += 1
    if n > 65535:
        raise FeedError("c_other-overflow")
    return n


# ---- serialize (publisher) ------------------------------------------------------------------
def serialize(header: dict, rows: list) -> bytes:
    """header keys: instance,seq,realtime_s,boottime_ns,interval_ms, db_status,db_boottime_ns,
    libvirt_status,libvirt_boottime_ns, stats_status,stats_boottime_ns,
    c_absent,c_uuid,c_name,c_untracked,c_other,c_ledger, load1_milli,memavail_kib,host_cpu_count,
    ownerpolicy. rows: list of dicts with reconcile_class,vm_id,vm_name,store_state,live_state,
    vm_class,base_flag,created_epoch,cpu,ram_cur,ram_max,[owner_display].
    Validates on the way out (a publisher bug must not emit a bad feed)."""
    pol = header["ownerpolicy"]
    lines = [_h_line(header, len(rows))]
    for r in rows:
        lines.append(_v_line(r, pol))
    lines.append("E\t%s\t%d\t%d" % (header["instance"], header["seq"], len(rows)))
    try:
        blob = ("\n".join(lines) + "\n").encode("ascii", "strict")
    except UnicodeEncodeError:               # a publisher that skipped canonicalize()
        raise FeedError("non-ascii-field")
    # SINGLE source of truth: the emitted feed MUST pass the same validator the viewer uses.
    # This guarantees serialize() and parse_validate() can never disagree.
    parse_validate(blob)
    return blob


def _h_line(h, n):
    f = ["H", VER, h["instance"], str(h["seq"]), str(h["realtime_s"]), str(h["boottime_ns"]),
         str(h["interval_ms"]), h["db_status"], str(h["db_boottime_ns"]),
         h["libvirt_status"], str(h["libvirt_boottime_ns"]), h["stats_status"],
         str(h["stats_boottime_ns"]), str(n), str(h["c_absent"]), str(h["c_uuid"]),
         str(h["c_name"]), str(h["c_untracked"]), str(h["c_other"]), str(h["c_ledger"]),
         str(h["load1_milli"]), str(h["memavail_kib"]), str(h["host_cpu_count"]), h["ownerpolicy"]]
    return "\t".join(f)


def _v_line(r, pol):
    def num(x):
        return "--" if x is None else str(x)
    f = ["V", r["reconcile_class"], r["vm_id"], r["vm_name"], r["store_state"], r["live_state"],
         r["vm_class"], r["base_flag"], str(r["created_epoch"]), num(r["cpu"]),
         num(r["ram_cur"]), num(r["ram_max"])]
    if pol != "no":
        f.append(r["owner_display"])
    return "\t".join(f)


# ---- parse + validate (viewer) --------------------------------------------------------------
def parse_validate(blob: bytes):
    """Return (header:dict, rows:list[dict]) of TYPED values, or raise FeedError. Bytes never
    flow back out untyped -- no delimiter re-serialization on the viewer side."""
    if not isinstance(blob, (bytes, bytearray)):
        raise FeedError("not-bytes")
    if len(blob) > MAX_BYTES:
        raise FeedError("oversize")
    if b"\x00" in blob:
        raise FeedError("nul")
    if b"\r" in blob:
        raise FeedError("cr")
    if not blob.endswith(b"\n"):
        raise FeedError("no-final-newline")
    try:
        text = blob.decode("ascii")
    except UnicodeDecodeError:
        raise FeedError("non-ascii")
    lines = text.split("\n")
    if lines[-1] != "":
        raise FeedError("trailing")
    lines = lines[:-1]                      # drop the final empty from the trailing \n
    if "" in lines:
        raise FeedError("blank-line")
    if len(lines) < 2 or lines[0][:2] != "H\t" or lines[-1][:2] != "E\t":
        raise FeedError("framing")
    header = _parse_h(lines[0])
    pol = header["ownerpolicy"]
    vlines = lines[1:-1]
    if len(vlines) != header["row_count"]:
        raise FeedError("rowcount-h")
    seen = set()
    rows = [_parse_v(l, pol, seen) for l in vlines]
    e = lines[-1].split("\t")
    if len(e) != 4 or e[0] != "E":
        raise FeedError("e-fields")
    if e[1] != header["instance"] or e[2] != str(header["seq"]):
        raise FeedError("e-mismatch")
    if _uint(e[3], 0, MAX_ROWS, "e-rowcount") != len(rows):
        raise FeedError("rowcount-e")
    _validate_frame(header, rows)
    return header, rows


def _parse_h(line):
    f = line.split("\t")
    if len(f) != 24 or f[0] != "H":
        raise FeedError("h-fields")
    if f[1] != VER:
        raise FeedError("version")
    if not RE_INSTANCE.match(f[2]):
        raise FeedError("instance")
    h = {"instance": f[2],
         "seq": _uint(f[3], 0, MAX_U63, "seq"),
         "realtime_s": _uint(f[4], 0, MAX_U63, "realtime_s"),
         "boottime_ns": _uint(f[5], 0, MAX_U63, "boottime_ns"),
         "interval_ms": _uint(f[6], 100, 3600000, "interval_ms"),
         "db_status": _enum(f[7], SRC_STATUS3, "db_status"),
         "db_boottime_ns": _uint(f[8], 0, MAX_U63, "db_boottime_ns"),
         "libvirt_status": _enum(f[9], SRC_STATUS3, "libvirt_status"),
         "libvirt_boottime_ns": _uint(f[10], 0, MAX_U63, "libvirt_boottime_ns"),
         "stats_status": _enum(f[11], STATS_STATUS, "stats_status"),
         "stats_boottime_ns": _uint(f[12], 0, MAX_U63, "stats_boottime_ns"),
         "row_count": _uint(f[13], 0, MAX_ROWS, "row_count"),
         "c_absent": _uint(f[14], 0, 65535, "c_absent"),
         "c_uuid": _uint(f[15], 0, 65535, "c_uuid"),
         "c_name": _uint(f[16], 0, 65535, "c_name"),
         "c_untracked": _uint(f[17], 0, 65535, "c_untracked"),
         "c_other": _uint(f[18], 0, 65535, "c_other"),
         "c_ledger": _uint(f[19], 0, 65535, "c_ledger"),
         "load1_milli": _uint(f[20], 0, 1000000, "load1_milli"),
         "memavail_kib": _uint(f[21], 0, MAX_U63, "memavail_kib"),
         "host_cpu_count": _uint(f[22], 1, 4096, "host_cpu_count"),
         "ownerpolicy": _enum(f[23], OWNER_POLICY, "ownerpolicy")}
    return h


def _parse_v(line, pol, seen):
    f = line.split("\t")
    want = 12 if pol == "no" else 13
    if len(f) != want or f[0] != "V":
        raise FeedError("v-fields")
    vm_id = f[2]
    if not RE_VMID.match(vm_id):
        raise FeedError("bad-vmid")
    if vm_id in seen:
        raise FeedError("dup-vmid")
    seen.add(vm_id)
    r = {"reconcile_class": _enum(f[1], RECONCILE, "reconcile_class"),
         "vm_id": vm_id,
         "vm_name": _text(f[3], LEN["vm_name"], "vm_name", allow_empty=False),
         "store_state": _text(f[4], LEN["store_state"], "store_state", allow_empty=False),
         "live_state": _enum(f[5], LIVE_STATE, "live_state"),
         "vm_class": _enum(f[6], VM_CLASS, "vm_class"),
         "base_flag": (f[7] if RE_BASEFLAG.match(f[7]) else _fail("bad-baseflag")),
         "created_epoch": _uint(f[8], 0, MAX_U63, "created_epoch"),
         "cpu": _dashint(f[9], 1000000, "cpu"),
         "ram_cur": _dashint(f[10], MAX_U63, "ram_cur"),
         "ram_max": _dashint(f[11], MAX_U63, "ram_max")}
    if pol != "no":
        od = f[12]
        if len(od) > LEN["owner_display"]:
            raise FeedError("too-long:owner_display")
        if od == "-":
            pass                                        # owner UNAVAILABLE sentinel (no store row / NSS fail)
        elif pol == "uid":
            _uint(od, 0, MAX_UID, "owner_uid")          # bounded numeric
        else:  # name-and-uid == "<uid>:<name>"; name opaque printable
            if ":" not in od:
                raise FeedError("owner-format")
            u, nm = od.split(":", 1)
            _uint(u, 0, MAX_UID, "owner_uid")
            _text(nm, LEN["owner_display"], "owner_name", allow_empty=False)
        r["owner_display"] = od
    return r


def _fail(reason):
    raise FeedError(reason)


_COUNTERS = ("c_absent", "c_uuid", "c_name", "c_untracked", "c_other", "c_ledger")

def _validate_frame(h, rows):
    """The ONE cross-field / freshness invariant check -- run by BOTH serialize and
    parse_validate so the two can never disagree. Header is already field-validated;
    rows are typed."""
    # (1) status<->stamp coupling: down => stamp 0 ; ok/stale => nonzero AND <= publish boottime.
    for st, ts, what in (("db_status", "db_boottime_ns", "db"),
                         ("libvirt_status", "libvirt_boottime_ns", "libvirt"),
                         ("stats_status", "stats_boottime_ns", "stats")):
        down = (h[st] == "down")
        if down != (h[ts] == 0):
            raise FeedError("stamp:%s" % what)
        if h[ts] > h["boottime_ns"]:          # a source cannot be sampled AFTER the publish
            raise FeedError("stamp-future:%s" % what)
    # (2) db down => no rows, no counters.
    if h["db_status"] == "down" and (h["row_count"] != 0 or rows):
        raise FeedError("dbdown-rows")
    # (3) anomaly counters are meaningful only when BOTH db and libvirt are ok (else masked -> 0).
    if (h["db_status"] != "ok" or h["libvirt_status"] != "ok") and any(h[c] for c in _COUNTERS):
        raise FeedError("anomaly-while-stale")
    lv_down = (h["libvirt_status"] == "down")
    # Either source not `ok` => cross-source reconcile is MASKED. Enforced HERE (shared validator)
    # so the publisher and viewer cannot diverge on masking: every row must be
    # `unreconciled` -- never absent/untracked/normal presented against a stale/absent source.
    reconcile_masked = (h["db_status"] != "ok" or h["libvirt_status"] != "ok")
    pol = h["ownerpolicy"]
    ss = h["stats_status"]
    n_elig = 0        # eligible (normal+running) rows
    n_present = 0     # eligible rows with a COMPLETE stats tuple
    n_absent = n_uuid = n_name = n_untracked = n_uuidbad = 0   # per-class tallies for the counters
    for r in rows:
        rc = r["reconcile_class"]
        ls = r["live_state"]
        # (4a) masked source => reconcile_class is `unreconciled`; (4a') EQUIVALENCE:
        # `unreconciled` is ONLY the masked state -- never emitted when both sources are ok.
        if reconcile_masked:
            if rc != "unreconciled":
                raise FeedError("mask-reconcile")
        elif rc == "unreconciled":
            raise FeedError("unmasked-unreconciled")
        # (4b) libvirt down (no live frame) => live_state is `unknown`; (4b') `unknown` is a
        # libvirt-unobservable SENTINEL only -- never emitted while libvirt is up.
        if lv_down:
            if ls != "unknown":
                raise FeedError("mask-livestate")
        elif ls == "unknown":
            raise FeedError("livestate-unknown")
        # (4c) reconcile_class <-> live_state matrix (base CONCEPT sec 5.2), only when unmasked:
        # normal/untracked are live-backed => a REAL state; absent/uuid/name/uuidbad have no
        # attributed live domain => `--`.
        if not reconcile_masked:
            if rc in ("normal", "untracked"):
                if ls not in LIVE_REAL:
                    raise FeedError("reconcile-livestate")
            elif ls != "--":                     # absent | uuid | name | uuidbad
                raise FeedError("reconcile-livestate")
        # (4d) UNTRACKED row PROJECTION: an untracked domain has NO store row, so every
        # store-derived field MUST be its unavailable sentinel -- a publisher can never attribute
        # store metadata or an owner to a live-only domain, so two publishers cannot diverge.
        if rc == "untracked":
            if r["vm_name"] != "--":
                raise FeedError("untracked-vm_name")
            if r["store_state"] != "unknown":    # `unknown` == store state absent (sec 5.1)
                raise FeedError("untracked-store_state")
            if r["vm_class"] != "--":
                raise FeedError("untracked-class")
            if r["base_flag"] != "unknown":
                raise FeedError("untracked-base")
            if r["created_epoch"] != 0:
                raise FeedError("untracked-created")
            if pol != "no" and r.get("owner_display") != "-":   # no store row => no owner
                raise FeedError("untracked-owner")
        # per-class tally (cross-checked against the header counters after the loop).
        if rc == "absent": n_absent += 1
        elif rc == "uuid": n_uuid += 1
        elif rc == "name": n_name += 1
        elif rc == "untracked": n_untracked += 1
        elif rc == "uuidbad": n_uuidbad += 1
        cpu_p = r["cpu"] is not None
        rc_p = r["ram_cur"] is not None
        rm_p = r["ram_max"] is not None
        present = cpu_p and rc_p and rm_p
        absent = not (cpu_p or rc_p or rm_p)
        # (5a) a stats tuple is ALL present or ALL '--' -- never mixed.
        if not (present or absent):
            raise FeedError("stats-tuple-mixed")
        eligible = (r["reconcile_class"] == "normal" and r["live_state"] == "running")
        # (5b) a non-eligible row cannot carry samples.
        if not eligible and present:
            raise FeedError("stats-noneligible")
        if eligible:
            n_elig += 1
            n_present += 1 if present else 0
        # (6) numeric relationships (only meaningful when present).
        if present:
            if r["cpu"] > h["host_cpu_count"] * 1000:
                raise FeedError("cpu-range")             # aggregate tenths <= ncpu*1000
            if r["ram_cur"] > r["ram_max"]:
                raise FeedError("ram-order")
    # (5c) stats_status <-> eligible-sample counts (exhaustive).
    if ss == "down":
        if n_present != 0:
            raise FeedError("statsdown-value")
    elif ss == "ok":
        if n_present != n_elig:                          # ok => EVERY eligible row present
            raise FeedError("statsok-missing")
    else:                                                # partial => some present AND some missing
        if n_elig == 0 or n_present == 0 or n_present == n_elig:
            raise FeedError("statspartial-bad")
    # (7) header anomaly counters cross-check the emitted rows. The feed enumerates
    # EVERY tracked VM (the 4096 cap FAILS acquisition, never truncates), so FIVE counters are exact
    # row derivations and the header can never contradict the rows: c_absent/c_uuid/c_name/c_untracked
    # == the count of V rows of that class, and c_ledger == the count of `uuidbad` rows (v1: a
    # DB/schema integrity failure sets db_status!=ok -> all counters 0, so the ONLY ledger anomaly that
    # coexists with db_status==ok is the per-row store-uuid-invalid one). c_other counts non-drvps-
    # shaped LIVE domains that are NEVER emitted as rows (a trusted producer count, frozen in the doc,
    # 0 when masked, overflow fails acquisition) -- the one counter not row-derivable.
    if h["c_absent"] != n_absent:
        raise FeedError("counter-absent")
    if h["c_uuid"] != n_uuid:
        raise FeedError("counter-uuid")
    if h["c_name"] != n_name:
        raise FeedError("counter-name")
    if h["c_untracked"] != n_untracked:
        raise FeedError("counter-untracked")
    if h["c_ledger"] != n_uuidbad:
        raise FeedError("counter-ledger")
