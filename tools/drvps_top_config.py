#!/usr/bin/env python3
"""drvps-top VIEWER trust config -- the frozen grammar for /etc/drvps-top/viewer.conf, the
ROOT-installed numeric trust anchor the unprivileged viewer uses to validate the feed's owner/
group/mode before reading it (design sec 7.3). Root-owned 0644. ASCII only.

The config is the ONLY trust source: never NSS, never the runtime dir's current owner. A single
strict parser here means every viewer accepts the identical trust anchor.
"""
from __future__ import annotations
import os, re, stat
import drvps_top_feed as F

KEYS = ("feed_dir", "feed_name", "feed_uid", "feed_gid", "feed_mode", "dir_mode", "max_bytes")
RE_DEC = re.compile(r"\A(0|[1-9][0-9]*)\Z")          # no leading zero / sign / space
RE_OCT = re.compile(r"\A0[0-7]{3}\Z")                # e.g. 0640, 0710
RE_BASENAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
RE_ABSPATH = re.compile(r"\A(/[A-Za-z0-9._-]+)+\Z")  # absolute, printable, segmented


class ConfigError(ValueError):
    """Raised on a malformed/insecure config; str(e) is a fixed reason."""


def _dec(v, hi, what):
    if len(v) > 20 or not RE_DEC.match(v):        # length cap FIRST -> no huge-digit int() cost
        raise ConfigError("bad-int:" + what)
    try:
        n = int(v)
    except ValueError:
        raise ConfigError("bad-int:" + what)
    if n > hi:
        raise ConfigError("range:" + what)
    return n


def _oct(v, what):
    if not RE_OCT.match(v):
        raise ConfigError("bad-mode:" + what)
    return int(v, 8)


def parse_config(text: str) -> dict:
    if not isinstance(text, str):
        raise ConfigError("not-text")
    if "\x00" in text or "\r" in text:
        raise ConfigError("bad-byte")
    if not all(0x20 <= ord(c) <= 0x7e or c == "\n" for c in text):
        raise ConfigError("non-ascii")
    if not text.endswith("\n"):
        raise ConfigError("no-final-newline")
    cfg = {}
    for ln in text.split("\n")[:-1]:
        if ln == "" or ln.startswith("#"):
            continue
        if "=" not in ln:
            raise ConfigError("syntax")
        k, v = ln.split("=", 1)
        if k not in KEYS:
            raise ConfigError("unknown-key:" + k)
        if k in cfg:
            raise ConfigError("dup-key:" + k)
        cfg[k] = v
    missing = [k for k in KEYS if k not in cfg]
    if missing:
        raise ConfigError("missing:" + ",".join(missing))
    if not RE_ABSPATH.match(cfg["feed_dir"]) or ".." in cfg["feed_dir"].split("/"):
        raise ConfigError("feed_dir")
    if not RE_BASENAME.match(cfg["feed_name"]) or cfg["feed_name"] in (".", ".."):
        raise ConfigError("feed_name")
    out = {
        "feed_dir": cfg["feed_dir"],
        "feed_name": cfg["feed_name"],
        "feed_uid": _dec(cfg["feed_uid"], F.MAX_UID, "feed_uid"),
        "feed_gid": _dec(cfg["feed_gid"], F.MAX_UID, "feed_gid"),
        "feed_mode": _oct(cfg["feed_mode"], "feed_mode"),
        "dir_mode": _oct(cfg["dir_mode"], "dir_mode"),
        "max_bytes": _dec(cfg["max_bytes"], F.MAX_BYTES, "max_bytes"),
    }
    # frozen invariants
    if out["max_bytes"] != F.MAX_BYTES:
        raise ConfigError("max_bytes-mismatch")     # must equal the schema constant
    if out["feed_mode"] != 0o640:
        raise ConfigError("feed_mode-value")
    if out["dir_mode"] != 0o710:
        raise ConfigError("dir_mode-value")
    return out


def load_config(path="/etc/drvps-top/viewer.conf", require_uid=0, require_gid=0) -> dict:
    """Open the ROOT config with the same hostile-file care as the feed: O_NOFOLLOW, fstat a
    regular root:root file with no group/world write, small cap. Then parse_config.
    (require_uid/require_gid default to root; the seam lets tests use a file they own.)"""
    # O_NONBLOCK so a hostile FIFO/device at `path` cannot BLOCK the open before fstat rejects it
    #; on the regular file we require, O_NONBLOCK is inert for the subsequent read.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError("config-not-regular")
        if st.st_uid != require_uid or st.st_gid != require_gid:
            raise ConfigError("config-not-root-owned")
        if st.st_mode & 0o022:
            raise ConfigError("config-group-world-writable")
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise ConfigError("config-setid")
        if st.st_size > 8192:
            raise ConfigError("config-too-large")
        data = os.read(fd, 8192)
        if len(data) != st.st_size:
            raise ConfigError("config-short-read")
    finally:
        os.close(fd)
    try:
        return parse_config(data.decode("ascii"))
    except UnicodeDecodeError:
        raise ConfigError("non-ascii")
