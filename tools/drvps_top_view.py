#!/usr/bin/env python3
"""drvps-top VIEWER (CONCEPT-DRVPS-TOP-SHARE). The unprivileged member-facing dashboard: it reads the
ROOT-config trust anchor, opens the publisher's feed with the hostile-file protocol (sec 7.2/7.3:
O_NOFOLLOW/O_NONBLOCK + fstat-on-the-same-fd owner/mode/nlink/size + capped chunked read + NUL/range
reject), parses+validates via drvps_top_feed (the shared contract -- no reimplementation, no delimiter
re-injection), and renders a deterministic terminal frame. On ANY failure it keeps the last valid frame
and shows a fixed, locally-generated error (never echoes feed bytes). Does NO sqlite/virsh/NSS; the only
display syscall is CLOCK_BOOTTIME for freshness. ASCII only; Python 3.6+.

Test seams (env): DRVPS_TOP_CONFIG (config path), DR_TOP_CFG_UID/GID (the config file's required owner,
default root) -- so the suite can drive the REAL open protocol against a file it owns.
"""
from __future__ import annotations
import os
import select
import stat
import sys
import time

import drvps_top_config as C
import drvps_top_feed as F

STALE_MULT = 3
READ_CHUNK = 65536


def is_stale(header, now_boottime_ns):
    """Publisher-stale (C-§ freshness): boottime 0, a future/negative dt, or dt beyond STALE_MULT
    intervals. Overflow-safe integer math."""
    bt = header["boottime_ns"]
    if bt == 0:
        return True
    dt = now_boottime_ns - bt
    if dt < 0:
        return True
    return dt > STALE_MULT * header["interval_ms"] * 1000000


def _dur(secs) -> str:
    """A compact age. Negative (clock skew) or huge -> `--`; else the largest unit."""
    if secs < 0 or secs > 10 * 365 * 86400:
        return "--"
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= n:
            return "%d%s" % (secs // n, unit)
    return "%ds" % secs


def render_frame(header, rows, now_boottime_ns) -> str:
    stale = is_stale(header, now_boottime_ns)
    src = "db:%s libvirt:%s stats:%s" % (header["db_status"], header["libvirt_status"], header["stats_status"])
    L = ["drvps-top  seq=%d  %s%s" % (header["seq"], src, "  [STALE]" if stale else ""),
         "load %.2f/%d  memavail %d kB  anomalies: absent %d uuid %d name %d untracked %d other %d ledger %d"
         % (header["load1_milli"] / 1000.0, header["host_cpu_count"], header["memavail_kib"],
            header["c_absent"], header["c_uuid"], header["c_name"], header["c_untracked"],
            header["c_other"], header["c_ledger"]),
         "%-26s %-14s %-9s %-9s %-9s %-9s %-20s %6s %8s %-15s"
         % ("VM", "NAME", "RECON", "STORE", "LIVE", "CLASS", "BASE", "AGE", "CPU%", "RAM cur/max")]
    now_s = header["realtime_s"]
    for r in rows:
        cpu = "--" if r["cpu"] is None else "%.1f" % (r["cpu"] / 10.0)
        ram = "--" if r["ram_cur"] is None else "%d/%d" % (r["ram_cur"], r["ram_max"])
        age = "--" if r["created_epoch"] == 0 else _dur(now_s - r["created_epoch"])
        owner = ("  owner=%s" % r["owner_display"]) if "owner_display" in r else ""
        L.append("%-26s %-14s %-9s %-9s %-9s %-9s %-20s %6s %8s %-15s%s" % (
            r["vm_id"], r["vm_name"], r["reconcile_class"], r["store_state"], r["live_state"],
            r["vm_class"], r["base_flag"], age, cpu, ram, owner))
    if not rows:
        L.append("(no tracked VMs)")
    return "\n".join(L) + "\n"


# ---- hostile-file OPEN protocol (sec 7.2/7.3) -----------------------------------------------
def _read_capped(fd, cap):
    """Read to EOF in bounded chunks, enforcing the byte cap WHILE reading (not only st_size) and
    rejecting any NUL as we go. A file that grew past the cap since fstat is rejected."""
    chunks, total = [], 0
    while total <= cap:
        b = os.read(fd, min(READ_CHUNK, cap + 1 - total))
        if not b:
            break
        if b"\x00" in b:
            raise F.FeedError("nul")
        chunks.append(b)
        total += len(b)
    if total > cap:
        raise F.FeedError("oversize")
    return b"".join(chunks)


def read_feed(cfg):
    """One poll: open the feed with the sec-7.2/7.3 protocol against the numeric trust anchor `cfg`
    (never NSS, never the dir's current owner). Returns (header, rows) TYPED, or raises FeedError.
    No fd reuse; no stat-then-open (open then fstat the SAME fd)."""
    # O_PATH (traverse-only), NOT O_RDONLY: the runtime dir is 0710, so a drvpsctl group MEMBER (the intended
    # audience) has execute but not read on it -- O_RDONLY would EACCES. O_PATH grants traversal; fstat works on
    # the O_PATH fd and it is a valid dir_fd for the openat("feed") below (same fix class as the egress anchor).
    dfd = os.open(cfg["feed_dir"], os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        dst = os.fstat(dfd)
        if not stat.S_ISDIR(dst.st_mode):
            raise F.FeedError("dir-not-dir")
        if dst.st_uid != cfg["feed_uid"] or dst.st_gid != cfg["feed_gid"]:
            raise F.FeedError("dir-owner")
        if stat.S_IMODE(dst.st_mode) != cfg["dir_mode"]:
            raise F.FeedError("dir-mode")
        ffd = os.open(cfg["feed_name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd)
        try:
            fst = os.fstat(ffd)
            if not stat.S_ISREG(fst.st_mode):
                raise F.FeedError("feed-not-regular")
            if fst.st_uid != cfg["feed_uid"] or fst.st_gid != cfg["feed_gid"]:
                raise F.FeedError("feed-owner")
            if stat.S_IMODE(fst.st_mode) != cfg["feed_mode"]:
                raise F.FeedError("feed-mode")
            if fst.st_nlink != 1:
                raise F.FeedError("feed-nlink")
            if fst.st_size > cfg["max_bytes"]:
                raise F.FeedError("feed-oversize")
            blob = _read_capped(ffd, cfg["max_bytes"])
        finally:
            os.close(ffd)
    finally:
        os.close(dfd)
    return F.parse_validate(blob)                # only a fully-validated frame ever reaches the caller


# ---- entry point / poll loop ----------------------------------------------------------------
def _load_trust():
    return C.load_config(
        path=os.environ.get("DRVPS_TOP_CONFIG", "/etc/drvps-top/viewer.conf"),
        require_uid=int(os.environ.get("DR_TOP_CFG_UID", "0")),
        require_gid=int(os.environ.get("DR_TOP_CFG_GID", "0")))


def poll_once(cfg):
    """Read+render one frame to a string, or a FIXED local error line (never echoing feed bytes)."""
    try:
        header, rows = read_feed(cfg)
    except (F.FeedError, C.ConfigError, OSError) as e:
        # str(e) on FeedError/ConfigError is a fixed byte-free reason; OSError is errno/strerror only.
        reason = e.args[0] if (isinstance(e, (F.FeedError, C.ConfigError)) and e.args) else type(e).__name__
        return None, "drvps-top: no valid feed (%s)\n" % reason
    return (header, rows), render_frame(header, rows, time.clock_gettime_ns(time.CLOCK_BOOTTIME))


def run(cfg, once=False, out=None, max_polls=None):
    """Poll loop: render in place, keep the LAST valid frame on a bad poll, quit on 'q'/EOF. --once
    renders a single poll and returns its exit code (0 iff a valid frame was read)."""
    out = out or sys.stdout
    interval = 3.0
    last_good = None
    polls = 0
    while True:
        parsed, text = poll_once(cfg)
        if parsed is not None:
            last_good = text
            interval = 3.0
            body = text
        else:
            body = (last_good or "") + text        # keep last valid frame + a fixed error line
        if once:
            out.write(body)
            out.flush()
            return 0 if parsed is not None else 1
        out.write("\x1b[H\x1b[2J")                  # home + clear (in-place redraw)
        out.write(body)
        out.flush()
        polls += 1
        if max_polls is not None and polls >= max_polls:
            return 0
        # non-blocking wait for a quit key or the interval
        try:
            r, _, _ = select.select([sys.stdin], [], [], interval)
        except (OSError, ValueError):
            time.sleep(interval)
            continue
        if r:
            ch = sys.stdin.read(1)
            if ch == "" or ch in ("q", "Q"):
                return 0


def main(argv):
    once = "--once" in argv
    unknown = [a for a in argv if a not in ("--once",)]
    if unknown:
        sys.stderr.write("usage: drvps-top-view [--once]\n")
        return 2
    try:
        cfg = _load_trust()
    except (C.ConfigError, OSError) as e:
        reason = e.args[0] if (isinstance(e, C.ConfigError) and e.args) else type(e).__name__
        sys.stderr.write("drvps-top: cannot load trust config (%s)\n" % reason)
        return 3
    return run(cfg, once=once)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
