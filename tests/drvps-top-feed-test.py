#!/usr/bin/env python3
"""Tests the shared feed contract (tools/drvps_top_feed.py) AND emits the byte-exact canonical
fixtures + manifest into docs/drvps-top-share-fixtures/. Run: python3 tests/drvps-top-feed-test.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_top_feed as F  # noqa

FIXD = os.path.join(HERE, "..", "docs", "drvps-top-share-fixtures")
REGEN = "--regen" in sys.argv     # maintainer mode: rewrite committed fixtures; default = read-only compare
built = []                        # (name, bytes, verdict) collected in memory
npass = [0]; nfail = [0]


def ok(cond, msg):
    if cond: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", msg)


def valid_header(**over):
    h = dict(instance="pub-a1b2c3", seq=42, realtime_s=1783960000, boottime_ns=5300000000000,
             interval_ms=3000, db_status="ok", db_boottime_ns=5300000000000,
             libvirt_status="ok", libvirt_boottime_ns=5300000000000,
             stats_status="ok", stats_boottime_ns=5300000000000,
             c_absent=0, c_uuid=0, c_name=0, c_untracked=0, c_other=0, c_ledger=0,
             load1_milli=4880, memavail_kib=39000000, host_cpu_count=8, ownerpolicy="no")
    h.update(over); return h


def row(vm_id, **over):
    r = dict(reconcile_class="normal", vm_id=vm_id, vm_name="weftg-x-P05", store_state="running",
             live_state="running", vm_class="throwaway", base_flag="golden:fedora44@bc07c9f7",
             created_epoch=1783959000, cpu=3123, ram_cur=1572864, ram_max=1572864)
    r.update(over); return r


def emit(name, blob, verdict):
    built.append((name, blob, verdict))       # collect only; write/compare happens at the end


def expect_ok(name, header, rows):
    blob = F.serialize(header, rows)
    h2, r2 = F.parse_validate(blob)          # round-trips
    ok(h2["instance"] == header["instance"] and len(r2) == len(rows), "valid roundtrip " + name)
    emit(name, blob, "ACCEPT")
    return blob


def expect_reject(name, blob, reason):
    try:
        F.parse_validate(blob)
        ok(False, "should have rejected " + name); return
    except F.FeedError as e:
        ok(str(e) == reason, "%s -> reject EXACT '%s' (got '%s')" % (name, reason, e))
    emit(name, blob, "REJECT:" + reason)


def raw(header, rows):
    """Build feed BYTES WITHOUT validation (F.serialize would refuse a semantically-bad frame),
    so we can test that parse_validate REJECTS contradictory frames."""
    pol = header["ownerpolicy"]
    lines = [F._h_line(header, len(rows))] + [F._v_line(r, pol) for r in rows]
    lines.append("E\t%s\t%d\t%d" % (header["instance"], header["seq"], len(rows)))
    return ("\n".join(lines) + "\n").encode("ascii")


ID1 = "drvps-vm-b71deae19298de23"; ID2 = "drvps-vm-15685c946b87396b"
ID3 = "drvps-vm-a1a1a1a1a1a1a1a1"; ID4 = "drvps-vm-b2b2b2b2b2b2b2b2"
ID5 = "drvps-vm-c3c3c3c3c3c3c3c3"; ID6 = "drvps-vm-d4d4d4d4d4d4d4d4"
def anomrow(vm_id, rc, ls="--"):   # a non-eligible anomaly row: class rc, live_state ls, no samples
    return row(vm_id, reconcile_class=rc, live_state=ls, cpu=None, ram_cur=None, ram_max=None)
def untracked_row(vm_id, ls="running", **over):   # LIVE-only domain: store fields = unavailable sentinels
    r = row(vm_id, reconcile_class="untracked", live_state=ls, vm_name="--", store_state="unknown",
            vm_class="--", base_flag="unknown", created_epoch=0, cpu=None, ram_cur=None, ram_max=None)
    r.update(over); return r

# ---- VALID fixtures ----
V = expect_ok("valid-ownernone.feed", valid_header(),
              [row(ID1), row(ID2, vm_name="weftg-x-P06", base_flag="snapshot", cpu=71, ram_cur=1048576)])
expect_ok("valid-owneruid.feed", valid_header(ownerpolicy="uid"),
          [row(ID1, owner_display="1008"), row(ID2, owner_display="1099")])
expect_ok("valid-libvirt-down.feed",
          valid_header(libvirt_status="down", libvirt_boottime_ns=0, stats_status="down", stats_boottime_ns=0),
          [row(ID1, reconcile_class="unreconciled", live_state="unknown", cpu=None, ram_cur=None, ram_max=None)])
expect_ok("valid-stats-partial.feed", valid_header(stats_status="partial"),
          [row(ID1), row(ID2, cpu=None, ram_cur=None, ram_max=None)])
# db stale (retained frame) + libvirt ok: reconcile MASKED to unreconciled, live_state still real,
# stats down (no eligible rows). Proves the masked-but-valid path.
expect_ok("valid-db-stale.feed",
          valid_header(db_status="stale", stats_status="down", stats_boottime_ns=0),
          [row(ID1, reconcile_class="unreconciled", cpu=None, ram_cur=None, ram_max=None)])
# EVERY UNMASKED reconcile class in one valid frame (db+libvirt ok), with matching counters:
# normal(eligible,samples), untracked(live/real), absent/uuid/name/uuidbad (`--`). `unreconciled` is
# masked-only (covered by valid-libvirt-down / valid-db-stale). Proves the reconcile<->live matrix +
# counter equalities. c_other is the only non-row-derivable counter; c_ledger==#uuidbad.
expect_ok("valid-anomalies.feed",
          valid_header(c_absent=1, c_uuid=1, c_name=1, c_untracked=1, c_other=2, c_ledger=1),
          [row(ID1),
           untracked_row(ID2),
           anomrow(ID3, "absent"), anomrow(ID4, "uuid"),
           anomrow(ID5, "name"), anomrow(ID6, "uuidbad")])
# nostate = VIR_DOMAIN_NOSTATE is a REAL observed state live-backed classes accept it.
expect_ok("valid-nostate.feed",
          valid_header(stats_status="down", stats_boottime_ns=0, c_untracked=1),
          [row(ID1, live_state="nostate", cpu=None, ram_cur=None, ram_max=None),
           untracked_row(ID2, ls="nostate")])
expect_ok("valid-empty.feed", valid_header(), [])
expect_ok("valid-nothing-acquired.feed",
          valid_header(db_status="down", db_boottime_ns=0, libvirt_status="down", libvirt_boottime_ns=0,
                       stats_status="down", stats_boottime_ns=0), [])

# ---- INVALID fixtures (one condition each; byte-surgery on a valid feed) ----
def mutate(blob, old, new):
    assert old in blob, old
    return blob.replace(old, new, 1)

expect_reject("invalid-dup-id.feed", mutate(V, ID2.encode(), ID1.encode()), "dup-vmid")
expect_reject("invalid-bad-vmid.feed", mutate(V, ID1.encode(), b"drvps-vm-XYZ0000000000000"), "bad-vmid")
expect_reject("invalid-bad-livestate.feed", mutate(V, b"\trunning\tthrowaway", b"\tzombie\tthrowaway"), "bad-enum:live_state")
expect_reject("invalid-badnum-plus.feed", mutate(V, b"\t3123\t", b"\t+312\t"), "bad-number:cpu")
expect_reject("invalid-badnum-leadzero.feed", mutate(V, b"\t3123\t", b"\t0312\t"), "bad-number:cpu")
expect_reject("invalid-nul.feed", V[:20] + b"\x00" + V[20:], "nul")
expect_reject("invalid-cr.feed", V[:20] + b"\r" + V[20:], "cr")
expect_reject("invalid-nonascii.feed", V[:20] + b"\xff" + V[20:], "non-ascii")
expect_reject("invalid-no-final-newline.feed", V[:-1], "no-final-newline")
expect_reject("invalid-trailing.feed", V + b"garbage\n", "framing")
# a TAB embedded in a name would add a field -> caught as a field-count error (proves no injection)
expect_reject("invalid-tab-in-name.feed", mutate(V, b"weftg-x-P05", b"weftg\tINJECT"), "v-fields")
# short V line (drop the last numeric field of row 1)
expect_reject("invalid-short-v.feed", mutate(V, b"\t1572864\t1572864\nV", b"\t1572864\nV"), "v-fields")
# H with wrong field count (drop ownerpolicy)
expect_reject("invalid-h-fieldcount.feed", mutate(V, b"\tno\nV", b"\nV"), "h-fields")
# E row_count mismatch
expect_reject("invalid-count-mismatch.feed", mutate(V, b"\nE\tpub-a1b2c3\t42\t2\n", b"\nE\tpub-a1b2c3\t42\t3\n"), "rowcount-e")
# stamp invariant: db ok but stamp 0
expect_reject("invalid-stamp.feed",
              mutate(V, b"\tok\t5300000000000\tok\t5300000000000\tok", b"\tok\t0\tok\t5300000000000\tok"),
              "stamp:db")

# oversize by bytes (>262144): serialize() rightly REFUSES to emit one, so craft the blob
# directly to exercise the viewer's length-cap reject path (checked before parsing).
big = b"H\t" + b" " * F.MAX_BYTES
ok(len(big) > F.MAX_BYTES, "oversize blob built (%d bytes)" % len(big))
expect_reject("invalid-oversize.feed", big, "oversize")

# ---- name-and-uid owner policy ----
expect_ok("valid-owner-nameuid.feed", valid_header(ownerpolicy="name-and-uid"),
          [row(ID1, owner_display="1008:alice"), row(ID2, owner_display="1099:-")])
expect_reject("invalid-owner-noformat.feed",
              raw(valid_header(ownerpolicy="name-and-uid"), [row(ID1, owner_display="alice")]), "owner-format")
expect_reject("invalid-owner-uidrange.feed",
              raw(valid_header(ownerpolicy="uid"), [row(ID1, owner_display="99999999999")]), "range:owner_uid")

# ---- frame invariants (semantically-bad frames via raw()) ----
expect_reject("invalid-anomaly-while-stale.feed",
              raw(valid_header(db_status="stale", c_absent=1), [row(ID1)]), "anomaly-while-stale")
expect_reject("invalid-dbdown-rows.feed",
              raw(valid_header(db_status="down", db_boottime_ns=0), [row(ID1)]), "dbdown-rows")
expect_reject("invalid-statsdown-value.feed",
              raw(valid_header(stats_status="down", stats_boottime_ns=0), [row(ID1)]), "statsdown-value")
expect_reject("invalid-statsok-missing.feed",
              raw(valid_header(), [row(ID1, cpu=None, ram_cur=None, ram_max=None)]), "statsok-missing")
# masking is enforced in the shared validator either source not ok => reconcile
# unreconciled; libvirt down => live_state unknown; db stale + factual reconcile is REJECTED.
expect_reject("invalid-mask-reconcile.feed",
              raw(valid_header(libvirt_status="down", libvirt_boottime_ns=0, stats_status="down", stats_boottime_ns=0),
                  [row(ID1)]), "mask-reconcile")
expect_reject("invalid-mask-livestate.feed",
              raw(valid_header(libvirt_status="down", libvirt_boottime_ns=0, stats_status="down", stats_boottime_ns=0),
                  [row(ID1, reconcile_class="unreconciled")]), "mask-livestate")
expect_reject("invalid-dbstale-reconciled.feed",
              raw(valid_header(db_status="stale"),
                  [row(ID1, reconcile_class="absent", cpu=None, ram_cur=None, ram_max=None)]), "mask-reconcile")
expect_reject("invalid-stats-noneligible.feed",
              raw(valid_header(), [row(ID1, live_state="shutoff")]), "stats-noneligible")

# reconcile_class<->live_state matrix + counter cross-checks.
expect_reject("invalid-unmasked-unreconciled.feed",
              raw(valid_header(stats_status="down", stats_boottime_ns=0),
                  [row(ID1, reconcile_class="unreconciled", cpu=None, ram_cur=None, ram_max=None)]),
              "unmasked-unreconciled")
expect_reject("invalid-livestate-unknown.feed",
              raw(valid_header(stats_status="down", stats_boottime_ns=0),
                  [row(ID1, live_state="unknown", cpu=None, ram_cur=None, ram_max=None)]),
              "livestate-unknown")
expect_reject("invalid-absent-live-running.feed",
              raw(valid_header(c_absent=1), [anomrow(ID3, "absent", ls="running")]), "reconcile-livestate")
expect_reject("invalid-normal-no-live-state.feed",
              raw(valid_header(stats_status="down", stats_boottime_ns=0),
                  [row(ID1, live_state="--", cpu=None, ram_cur=None, ram_max=None)]), "reconcile-livestate")
expect_reject("invalid-counter-absent.feed",
              raw(valid_header(c_absent=5), [anomrow(ID3, "absent")]), "counter-absent")
expect_reject("invalid-counter-uuid.feed",
              raw(valid_header(c_uuid=3), [anomrow(ID4, "uuid")]), "counter-uuid")
expect_reject("invalid-counter-name.feed",
              raw(valid_header(c_name=3), [anomrow(ID5, "name")]), "counter-name")
expect_reject("invalid-counter-untracked.feed",
              raw(valid_header(c_untracked=3), [untracked_row(ID2)]), "counter-untracked")
expect_reject("invalid-counter-ledger.feed",
              raw(valid_header(c_ledger=0), [anomrow(ID6, "uuidbad")]), "counter-ledger")

# untracked row PROJECTION every store-derived field is an unavailable sentinel; the
# owner MUST be `-` under both owner policies (no store row => no owner).
UT_HDR = dict(c_untracked=1, stats_status="down", stats_boottime_ns=0)
expect_ok("valid-untracked-owner-uid.feed",
          valid_header(ownerpolicy="uid", **UT_HDR), [untracked_row(ID2, owner_display="-")])
expect_ok("valid-untracked-owner-nameuid.feed",
          valid_header(ownerpolicy="name-and-uid", **UT_HDR), [untracked_row(ID2, owner_display="-")])
expect_reject("invalid-untracked-owner.feed",
              raw(valid_header(ownerpolicy="uid", **UT_HDR), [untracked_row(ID2, owner_display="1008")]),
              "untracked-owner")
expect_reject("invalid-untracked-store.feed",
              raw(valid_header(c_untracked=1, stats_status="down", stats_boottime_ns=0),
                  [untracked_row(ID2, store_state="running")]), "untracked-store_state")
expect_reject("invalid-untracked-base.feed",
              raw(valid_header(c_untracked=1, stats_status="down", stats_boottime_ns=0),
                  [untracked_row(ID2, base_flag="golden:fedora44@bc07c9f7")]), "untracked-base")
expect_reject("invalid-untracked-vm_name.feed",
              raw(valid_header(c_untracked=1, stats_status="down", stats_boottime_ns=0),
                  [untracked_row(ID2, vm_name="weftg-x-P05")]), "untracked-vm_name")
expect_reject("invalid-untracked-class.feed",
              raw(valid_header(c_untracked=1, stats_status="down", stats_boottime_ns=0),
                  [untracked_row(ID2, vm_class="throwaway")]), "untracked-class")
expect_reject("invalid-untracked-created.feed",
              raw(valid_header(c_untracked=1, stats_status="down", stats_boottime_ns=0),
                  [untracked_row(ID2, created_epoch=1783959000)]), "untracked-created")
expect_reject("invalid-untracked-owner-nameuid.feed",
              raw(valid_header(ownerpolicy="name-and-uid", **UT_HDR),
                  [untracked_row(ID2, owner_display="1008:alice")]), "untracked-owner")
expect_reject("invalid-stamp-future.feed",
              raw(valid_header(db_boottime_ns=5300000000001), [row(ID1)]), "stamp-future:db")
expect_reject("invalid-cpu-range.feed",
              raw(valid_header(host_cpu_count=1), [row(ID1, cpu=2000)]), "cpu-range")
expect_reject("invalid-ram-order.feed",
              raw(valid_header(), [row(ID1, ram_cur=2000000, ram_max=1000000)]), "ram-order")
expect_reject("invalid-e-mismatch.feed", mutate(V, b"E\tpub-a1b2c3", b"E\tpub-XXXXXX"), "e-mismatch")
expect_reject("invalid-blank-line.feed", mutate(V, b"\nV", b"\n\nV"), "blank-line")
# huge numeric token must be a FeedError, not a raw Python ValueError
expect_reject("invalid-hugenum.feed", mutate(V, b"\t3123\t", b"\t" + b"9" * 4301 + b"\t"), "bad-number:cpu")

# ---- canonicalize() direct ----
ok(F.canonicalize(b"a\tb\x00c\x1bd", 10) == "a?b?c?d", "canon replaces tab/nul/esc")
ok(F.canonicalize(None, 3, "unknown") == "unk", "canon placeholder capped to maxlen")
ok(F.canonicalize(b"", 5) == "-", "canon empty -> placeholder")
ok(F.canonicalize(b"abcdef", 3) == "abc", "canon caps length")
try:
    F.canonicalize(b"x", 0); ok(False, "canon maxlen<1 should raise")
except F.FeedError:
    ok(True, "canon maxlen<1 raises")

# ---- stats state-machine contradictions (all-or-nothing tuple; ok/partial/down) ----
expect_reject("invalid-stats-tuple-mixed.feed", raw(valid_header(), [row(ID1, ram_max=None)]), "stats-tuple-mixed")
expect_reject("invalid-partial-all-present.feed", raw(valid_header(stats_status="partial"), [row(ID1), row(ID2)]), "statspartial-bad")
expect_reject("invalid-partial-all-missing.feed", raw(valid_header(stats_status="partial"), [row(ID1, cpu=None, ram_cur=None, ram_max=None)]), "statspartial-bad")
expect_reject("invalid-partial-zero-eligible.feed", raw(valid_header(stats_status="partial"), [row(ID1, live_state="shutoff", cpu=None, ram_cur=None, ram_max=None)]), "statspartial-bad")

# ---- make_base_flag()/canon_distro() (deterministic; malformed distro -> unknown) ----
ok(F.make_base_flag("golden", "fedora44", "bc07c9f7") == "golden:fedora44@bc07c9f7", "baseflag golden ok")
ok(F.make_base_flag("golden", b"Fedora-44", "bc07c9f7") == "unknown", "baseflag bad-distro -> unknown")
ok(F.make_base_flag("golden", "fedora44", "NOTHEX!!") == "unknown", "baseflag bad-hex -> unknown")
ok(F.make_base_flag("snapshot", "x", "y") == "snapshot", "baseflag snapshot opaque")
ok(F.make_base_flag("orphan", None, None) == "orphan", "baseflag orphan")
# raw sqlite bytes for EVERY component (kind/distro/short-id) (was: valid bytes -> unknown)
ok(F.make_base_flag(b"golden", b"fedora44", b"bc07c9f7") == "golden:fedora44@bc07c9f7", "baseflag all-bytes ok")
ok(F.make_base_flag(b"snapshot", None, None) == "snapshot", "baseflag bytes snapshot")
ok(F.make_base_flag("golden", "fedora44", b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8") == "unknown", "baseflag non-ascii hex -> unknown")
ok(F.make_base_flag(b"\xff", None, None) == "unknown", "baseflag non-ascii kind -> unknown")
ok(F.make_base_flag("golden", b"Fedora-44", "bc07c9f7") == "unknown", "baseflag bad-distro -> unknown")
ok(F.make_base_flag("golden", "fedora44", "NOTHEX!!") == "unknown", "baseflag bad-hex -> unknown")
ok(F.canon_distro(b"Ubuntu26") == "ubuntu26", "canon_distro lowercases")
ok(F.canon_distro(b"open-suse") is None, "canon_distro rejects dash")
ok(F.canon_distro(b"\xff\xfe") is None, "canon_distro non-ascii -> None")
# TOTAL for arbitrary input types -- never raises unsupported types -> unknown/orphan.
ok(F.make_base_flag("golden", 123, "bc07c9f7") == "unknown", "baseflag int distro -> unknown")
ok(F.make_base_flag("golden", "fedora44", 123) == "unknown", "baseflag int hex -> unknown")
ok(F.make_base_flag("golden", bytearray(b"fedora44"), bytearray(b"bc07c9f7")) == "golden:fedora44@bc07c9f7", "baseflag bytearray ok")
ok(F.make_base_flag(123, None, None) == "unknown", "baseflag int kind -> unknown")
ok(F.make_base_flag(None, None, None) == "orphan", "baseflag None kind -> orphan")
class _EvilStr(str):                     # overrides BOTH __str__ (returns self) AND .lower() (raises)
    def __str__(self): return self
    def lower(self): raise RuntimeError("boom")
ok(F.make_base_flag(_EvilStr("golden"), _EvilStr("Fedora44"), "bc07c9f7") == "golden:fedora44@bc07c9f7",
   "baseflag evil str-subclass total (kind+distro, no escape)")

# count_other(): the ONE deterministic c_other producer.
DRVPS_NAME = "drvps-vm-" + "a" * 16
ok(F.count_other([("web01", "u1")], set()) == 1, "count_other: non-drvps unclaimed -> 1")
ok(F.count_other([("web01", "u1")], {"u1"}) == 0, "count_other: claimed uuid excluded")
ok(F.count_other([(DRVPS_NAME, "u2")], set()) == 0, "count_other: drvps-shaped excluded (it is a row)")
ok(F.count_other([(None, "u3"), (b"\xff", "u4")], set()) == 2, "count_other: malformed/None name counted")
ok(F.count_other([("a", "u5"), ("b", "u6"), (DRVPS_NAME, "u7")], set()) == 2, "count_other: mixed")
ok(F.count_other([("x%d" % i, "u%d" % i) for i in range(65535)], set()) == 65535, "count_other: 65535 ok")
try:
    F.count_other([("x%d" % i, "u%d" % i) for i in range(65536)], set()); ok(False, "overflow should raise")
except F.FeedError as e:
    ok(str(e) == "c_other-overflow", "count_other: overflow -> FeedError (not saturate)")

# ---- REGEN (maintainer) OR READ-ONLY byte-compare vs the committed fixtures ----
MAN = os.path.join(FIXD, "MANIFEST.txt")
if REGEN:
    os.makedirs(FIXD, exist_ok=True)
    for name, blob, _ in built:
        with open(os.path.join(FIXD, name), "wb") as fh:
            fh.write(blob)
    with open(MAN, "w") as fh:
        fh.write("# drvps-top-share feed fixtures -- expected result per file (schema v1)\n")
        fh.write("\n".join("%-38s %s" % (n, v) for n, _, v in sorted(built)) + "\n")
    print("REGENERATED %d fixtures + manifest" % len(built))
else:
    committed = set(f for f in os.listdir(FIXD) if f.endswith(".feed"))
    names = set(n for n, _, _ in built)
    ok(committed == names, "committed .feed set == built (diff: %s)" % sorted(committed ^ names))
    man = {}
    for line in open(MAN):
        s = line.strip()
        if s and not s.startswith("#"):
            k, v = s.split(None, 1)
            ok(k not in man, "manifest duplicate record " + k)       # dup names must not silently overwrite
            man[k] = v
    ok(set(man) == names, "manifest key-set == built (diff: %s)" % sorted(set(man) ^ names))
    for name, blob, verdict in built:
        p = os.path.join(FIXD, name)
        if not os.path.exists(p):
            ok(False, "missing committed " + name); continue
        with open(p, "rb") as fh:
            ok(fh.read() == blob, "byte-stable " + name)
        ok(man.get(name) == verdict, "manifest %s == '%s' (got '%s')" % (name, verdict, man.get(name)))

print("-------------------------------------------")
print("drvps-top feed contract: PASS=%d FAIL=%d%s" % (npass[0], nfail[0], "  [REGEN]" if REGEN else ""))
sys.exit(1 if nfail[0] else 0)
