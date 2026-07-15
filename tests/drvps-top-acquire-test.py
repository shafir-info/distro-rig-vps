#!/usr/bin/env python3
"""Tests the drvps-top PUBLISHER live-acquisition + atomic-write I/O (tools/drvps_top_publish.py) through
the REAL code path against a real temp sqlite store (stdlib sqlite3) + a canned `virsh` seam. Proves:
the store-gate reproduces store_init's refusal set; reconcile classification matches the identity frame;
a store/libvirt failure fails closed to a valid degraded (db/libvirt down) frame -- NEVER a fabricated
empty rig; the atomic writer publishes a 0640 feed the VIEWER open protocol then reads. ASCII only."""
import os, sqlite3, stat, subprocess, sys, tempfile, shutil, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import drvps_top_publish as P  # noqa
import drvps_top_view as V     # noqa
import drvps_top_config as C   # noqa
import drvps_top_feed as F     # noqa

npass = [0]; nfail = [0]
def ok(c, m):
    if c: npass[0] += 1
    else: nfail[0] += 1; print("FAIL:", m)

UID, GID = os.getuid(), os.getgid()
CLOCK = {"realtime_s": 1783960000, "boottime_ns": 5300000000000, "interval_ms": 3000}
HOST = {"load1_milli": 4880, "memavail_kib": 39000000, "host_cpu_count": 8}
NORMAL_ID = "drvps-vm-%016x" % 0x1001
NORMAL_UUID = "11111111-1111-4111-8111-111111111111"
ABSENT_ID = "drvps-vm-%016x" % 0x1002
ABSENT_UUID = "22222222-2222-4222-8222-222222222222"


def build_db(path, *, full=True, drop_index=False, drop_trigger=False, bad_invariant=False):
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE images(artifact_id TEXT PRIMARY KEY, kind TEXT, name TEXT, provenance TEXT);
      CREATE TABLE snapshots(id TEXT PRIMARY KEY, name TEXT, parent_golden_id TEXT,
                             secret_bearing INT, validation_status TEXT, created_at INT, bundle_relpath TEXT);
      CREATE TABLE vms(id TEXT PRIMARY KEY, owner_uid INT, class TEXT, domain_uuid TEXT,
                       artifact_id TEXT, state TEXT, name TEXT, created_at INT, net TEXT, contract TEXT);
    """)
    if not drop_index:
        con.executescript("CREATE UNIQUE INDEX images_kind_name_uq ON images(kind,name);"
                          "CREATE UNIQUE INDEX snapshots_name_uq ON snapshots(name);")
    if not drop_trigger:
        for t in ("images_kind_ins", "images_kind_upd", "snapshots_ins", "snapshots_upd"):
            tbl = "images" if t.startswith("images") else "snapshots"
            con.execute("CREATE TRIGGER %s BEFORE INSERT ON %s BEGIN SELECT 1; END" % (t, tbl))
    gold = "drvps-raw-v1-10-" + "a" * 8
    snap = "drvps-snap-v1-" + "b" * 8
    con.execute("INSERT INTO images VALUES(?,?,?,?)", (gold, "golden", "g1", '{"distro":"fedora44"}'))
    con.execute("INSERT INTO images VALUES(?,?,?,?)", (snap, "snapshot", "s1", None))
    if not bad_invariant:                                  # bad_invariant: a snapshot IMAGE with NO snapshots row -> bijection break
        con.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?,?)", (snap, "s1", gold, 0, "ok", 1783959000, "x"))
    con.execute("INSERT INTO vms VALUES(?,?,?,?,?,?,?,?,?,?)",
                (NORMAL_ID, 1008, "throwaway", NORMAL_UUID, gold, "running", NORMAL_ID, 1783959000, "n", "c"))
    con.execute("INSERT INTO vms VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ABSENT_ID, 1008, "service", ABSENT_UUID, gold, "running", "svc", 1783959500, "n", "c"))
    con.execute("INSERT INTO vms(id,owner_uid,class,domain_uuid,artifact_id,state,name,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                ("drvps-vm-%016x" % 0x1003, 1008, "throwaway", "not-a-uuid", gold, "broken", "bad", 1783959600))
    con.commit(); con.close()


def canned_virsh(tmp, *, list_out=None, fail=False, domstats_fail=False):
    """A fake `virsh` dispatching on argv: list -> identity (or EXIT 1 if fail); domstats -> running+balloon
    (or EXIT 1 if domstats_fail -- to exercise a failed sample of a live-backed domain)."""
    p = os.path.join(tmp, "v_fail" if fail else ("v_dsf" if domstats_fail else "virsh"))
    default_list = " UUID                                  Name\n-----\n %s  %s\n" % (NORMAL_UUID, NORMAL_ID)
    listcase = "  list) exit 1;;\n" if fail else "  list) printf '%s'; exit 0;;\n" % (list_out if list_out is not None else default_list)
    dscase = "  domstats) exit 1;;\n" if domstats_fail else \
        "  domstats) printf 'Domain: x\\nstate.state=1\\ncpu.time=5000000000\\nballoon.current=1572864\\nballoon.maximum=1572864\\n'; exit 0;;\n"
    body = "#!/usr/bin/env bash\nfor a in \"$@\"; do case \"$a\" in\n" + listcase + dscase + "esac; done\nexit 0\n"
    open(p, "w").write(body); os.chmod(p, 0o755)
    return p


T = tempfile.mkdtemp()
try:
    db = os.path.join(T, "store.db"); build_db(db)
    virsh = canned_virsh(T)
    # 1. full acquisition -> a VALID frame (oracle: parse_validate) with the right reconcile classes
    blob, base1 = P.acquire_and_build("drvps-top", 1, db, virsh, CLOCK, HOST)
    h, rows = F.parse_validate(blob)
    ok(h["db_status"] == "ok" and h["libvirt_status"] == "ok", "all-ok sources")
    classes = {r["vm_id"]: r["reconcile_class"] for r in rows}
    ok(classes.get(NORMAL_ID) == "normal", "matched vm -> normal")
    ok(classes.get(ABSENT_ID) == "absent", "unmatched vm -> absent")
    ok(any(r["reconcile_class"] == "uuidbad" for r in rows), "invalid domain_uuid -> uuidbad")
    ok(h["c_absent"] == 1 and h["c_ledger"] == 1, "counters: absent 1, ledger(uuidbad) 1")
    nrow = next(r for r in rows if r["vm_id"] == NORMAL_ID)
    ok(nrow["live_state"] == "running", "normal row: live running (from domstats)")
    ok(nrow["vm_class"] == "throwaway", "sqlite class decoded (throwaway), not '--' (bytes-vs-str bug fixed)")
    ok(nrow["cpu"] is None and nrow["ram_cur"] is None, "single-shot: no cpu baseline -> stats '--' (complete-tuple rule)")

    # 1b. SECOND tick threads the baseline -> a complete cpu+ram stats tuple appears
    clk2 = dict(CLOCK, boottime_ns=CLOCK["boottime_ns"] + 3000000000)
    blob2, _ = P.acquire_and_build("drvps-top", 2, db, virsh, clk2, HOST, baseline=base1)
    h2b, rows2 = F.parse_validate(blob2)
    n2 = next(r for r in rows2 if r["vm_id"] == NORMAL_ID)
    ok(n2["cpu"] == 0 and n2["ram_cur"] == 1572864, "2nd tick: cpu computed (idle=0) + balloon ram present")

    # 2. STORE GATE: a missing unique index / trigger / column / invariant -> db down (status-only)
    for kw, label in ((dict(drop_index=True), "missing unique index"),
                      (dict(drop_trigger=True), "missing check trigger"),
                      (dict(bad_invariant=True), "snapshot/kind invariant violation")):
        d2 = os.path.join(T, "s_" + label.split()[1] + ".db"); build_db(d2, **kw)
        b2, _ = P.acquire_and_build("drvps-top", 1, d2, virsh, CLOCK, HOST)
        h2, _ = F.parse_validate(b2)
        ok(h2["db_status"] == "down", "store-gate: %s -> db down (fail closed)" % label)

    # 3. NEVER-EMPTY-ON-FAILURE: a virsh that FAILS (nonzero rc) -> libvirt down (masked), not a fake empty rig
    ev = canned_virsh(T, fail=True)
    be, _ = P.acquire_and_build("drvps-top", 1, db, ev, CLOCK, HOST)
    he, re = F.parse_validate(be)
    ok(he["libvirt_status"] == "down", "FAILED (nonzero-rc) virsh -> libvirt down")
    ok(all(r["reconcile_class"] == "unreconciled" and r["live_state"] == "unknown" for r in re),
       "libvirt down -> rows masked unreconciled/unknown (not fabricated absent)")
    # a rc-0 virsh with NO domains is a legitimate empty inventory (libvirt OK), NOT down
    ev0 = canned_virsh(T, list_out=" UUID  Name\n-----\n")
    b0, _ = P.acquire_and_build("drvps-top", 1, db, ev0, CLOCK, HOST)
    h0, r0 = F.parse_validate(b0)
    ok(h0["libvirt_status"] == "ok", "rc-0 empty virsh -> libvirt OK (0 domains, not down)")
    ok({rr["reconcile_class"] for rr in r0} <= {"absent", "uuidbad"}, "empty inventory -> store rows absent/uuidbad")

    # 3b. FAIL-CLOSED on a corrupt store: a malformed vm.id -> db down (never silently dropped)
    dbad = os.path.join(T, "badid.db"); build_db(dbad)
    cbad = sqlite3.connect(dbad)
    cbad.execute("INSERT INTO vms(id,owner_uid,class,domain_uuid,artifact_id,state,name,created_at) "
                 "VALUES('NOT-a-valid-vmid',1008,'throwaway','33333333-3333-4333-8333-333333333333','x','running','n',1)")
    cbad.commit(); cbad.close()
    bb, _ = P.acquire_and_build("drvps-top", 1, dbad, virsh, CLOCK, HOST)
    hbb, _ = F.parse_validate(bb)
    ok(hbb["db_status"] == "down", "malformed vm.id -> db down (fail closed, no silent drop)")

    # 3c. owner name-and-uid -> "<uid>:<name>" (or '-'); a valid frame the shared validator accepts
    bo, _ = P.acquire_and_build("drvps-top", 1, db, virsh, CLOCK, HOST, ownerpolicy="name-and-uid")
    ho, ro = F.parse_validate(bo)                          # parse_validate enforces the owner grammar
    no = next(r for r in ro if r["vm_id"] == NORMAL_ID)
    ok(no["owner_display"] == "-" or no["owner_display"].startswith("1008:"),
       "owner_display grammar <uid>:<name> (or '-' when NSS has no name for the uid)")

    # 3d. a FAILED domstats of the only live-backed normal -> stats NOT 'trivially ok' (down), never fabricated
    vdsf = canned_virsh(T, domstats_fail=True)
    bdf, _ = P.acquire_and_build("drvps-top", 1, db, vdsf, CLOCK, HOST)
    hdf, _ = F.parse_validate(bdf)
    ok(hdf["libvirt_status"] == "ok" and hdf["stats_status"] == "down",
       "failed domstats of the only normal -> libvirt ok BUT stats down (not trivially ok)")

    # 3e. an rc-0 domstats with an UNRECOGNIZED/empty state.state is a FAILED sample, not a fabricated nostate:ok
    vemp = os.path.join(T, "v_empty")
    open(vemp, "w").write("#!/usr/bin/env bash\nfor a in \"$@\"; do case \"$a\" in\n"
        "  list) printf ' UUID Name\\n-----\\n %s %s\\n'; exit 0;;\n  domstats) exit 0;;\nesac; done\nexit 0\n"
        % (NORMAL_UUID, NORMAL_ID)); os.chmod(vemp, 0o755)
    bem, _ = P.acquire_and_build("drvps-top", 1, db, vemp, CLOCK, HOST)
    hem, _ = F.parse_validate(bem)
    ok(hem["stats_status"] == "down", "rc-0 empty/unrecognized state -> failed sample -> stats down (not fabricated ok)")

    # 3f. MIXED: two normal domains, one sampled running (with a baseline -> cpu) + one failed -> a VALID partial
    dmix = os.path.join(T, "mix.db"); build_db(dmix)
    ID_B = "drvps-vm-%016x" % 0x2001; UUID_B = "44444444-4444-4444-8444-444444444444"
    cmx = sqlite3.connect(dmix)
    cmx.execute("INSERT INTO vms(id,owner_uid,class,domain_uuid,artifact_id,state,name,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)", (ID_B, 1008, "throwaway", UUID_B, "drvps-raw-v1-10-" + "a" * 8, "running", ID_B, 1))
    cmx.commit(); cmx.close()
    vmx = os.path.join(T, "v_mix")
    open(vmx, "w").write("#!/usr/bin/env bash\nop=''; last=''\nfor a in \"$@\"; do case \"$a\" in list) op=list;; domstats) op=domstats;; esac; last=\"$a\"; done\n"
        "if [ \"$op\" = list ]; then printf ' UUID Name\\n-----\\n %s %s\\n %s %s\\n'; exit 0; fi\n"
        "if [ \"$op\" = domstats ]; then case \"$last\" in\n"
        "  %s) printf 'state.state=1\\ncpu.time=5000000000\\nballoon.current=1572864\\nballoon.maximum=1572864\\n'; exit 0;;\n"
        "  *) exit 0;; esac\nfi\nexit 0\n" % (NORMAL_UUID, NORMAL_ID, UUID_B, ID_B, NORMAL_UUID)); os.chmod(vmx, 0o755)
    b1, base1 = P.acquire_and_build("drvps-top", 1, dmix, vmx, CLOCK, HOST)   # establish the baseline
    clk3 = dict(CLOCK, boottime_ns=CLOCK["boottime_ns"] + 3000000000)
    b2, _ = P.acquire_and_build("drvps-top", 2, dmix, vmx, clk3, HOST, baseline=base1)
    hmx, rmx = F.parse_validate(b2)                       # parse_validate REJECTS an invalid partial (statspartial-bad)
    ok(hmx["stats_status"] == "partial", "mixed sampled+failed normals -> a VALID partial frame (n_present<n_elig)")

    # 3g. an UNRECOGNIZED state (8) carrying valid cpu/ram, WITH a prior baseline: the metrics must NOT leak
    # (no tuple, no baseline update) -> stats down, never a false ok
    vun = os.path.join(T, "v_un")
    open(vun, "w").write("#!/usr/bin/env bash\nfor a in \"$@\"; do case \"$a\" in\n"
        "  list) printf ' UUID Name\\n-----\\n %s %s\\n'; exit 0;;\n"
        "  domstats) printf 'state.state=8\\ncpu.time=9000000000\\nballoon.current=1572864\\nballoon.maximum=1572864\\n'; exit 0;;\n"
        "esac; done\nexit 0\n" % (NORMAL_UUID, NORMAL_ID)); os.chmod(vun, 0o755)
    prior = {NORMAL_UUID: (4000000000, CLOCK["boottime_ns"] - 1000000000)}   # a prior baseline exists
    bun, base_after = P.acquire_and_build("drvps-top", 1, db, vun, CLOCK, HOST, baseline=prior)
    hun, run = F.parse_validate(bun)
    nun = next(r for r in run if r["vm_id"] == NORMAL_ID)
    ok(hun["stats_status"] == "down" and nun["cpu"] is None and nun["ram_cur"] is None and nun["ram_max"] is None,
       "unrecognized state w/ metrics -> no tuple leaked, stats down (not false ok)")
    ok(NORMAL_UUID not in base_after, "unrecognized state does NOT update the cpu baseline")

    # 4. ATOMIC WRITE (under the held single-publisher lock) -> a 0640 feed the VIEWER open protocol reads
    fdir = os.path.join(T, "run"); os.mkdir(fdir, 0o710); os.chmod(fdir, 0o710)
    dfd = P.open_feed_dir_locked(fdir)                    # take + HOLD the single-publisher lock
    P.write_feed(dfd, blob, UID, GID)
    feed = os.path.join(fdir, "feed")
    ok(os.path.exists(feed) and stat.S_IMODE(os.lstat(feed).st_mode) == 0o640 and os.lstat(feed).st_nlink == 1,
       "atomic write: feed present, mode 0640, nlink 1")
    conf = os.path.join(T, "viewer.conf")
    open(conf, "w").write("feed_dir=%s\nfeed_name=feed\nfeed_uid=%d\nfeed_gid=%d\n"
                          "feed_mode=0640\ndir_mode=0710\nmax_bytes=262144\n" % (fdir, UID, GID))
    os.chmod(conf, 0o644)
    cfg = C.load_config(path=conf, require_uid=UID, require_gid=GID)
    vh, vr = V.read_feed(cfg)
    ok(vh["seq"] == h["seq"] and len(vr) == len(rows), "viewer reads the published feed end-to-end")
    # a 2nd publisher is refused while the 1st holds the lock (single-publisher, HELD across the loop)
    try:
        P.open_feed_dir_locked(fdir); ok(False, "2nd publisher not blocked")
    except P.PublishError:
        ok(True, "2nd concurrent publisher -> PublishError (single-publisher flock held)")
    os.close(dfd)

    # 5. --once entry point emits a valid feed to stdout
    env = dict(os.environ, DR_VPS_DB=db, DR_VIRSH=virsh, DRVPS_TOP_INSTANCE="drvps-top")
    out = subprocess.run([sys.executable, "tools/drvps_top_publish.py", "--once"],
                         capture_output=True, env=env, cwd=os.path.join(HERE, ".."))
    okrc = out.returncode == 0
    try:
        oh, _ = F.parse_validate(out.stdout); okp = True
    except Exception:
        okp = False
    ok(okrc and okp, "--once: emits a valid feed to stdout (rc 0)")
finally:
    shutil.rmtree(T, ignore_errors=True)

print("-------------------------------------------")
print("drvps-top-acquire: PASS=%d FAIL=%d" % (npass[0], nfail[0]))
sys.exit(1 if nfail[0] else 0)
