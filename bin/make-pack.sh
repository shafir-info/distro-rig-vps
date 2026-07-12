#!/usr/bin/env bash
# make-pack.sh [--profile full|agent]
#   full  (default) -- the WHOLE project tree (installer bin/, src/, etc/, tests/, ALL docs) minus VCS
#                      metadata, runtime state, images, and generated files -> ~/tmp/distro-rig-vps-<UTC>.tar.gz.
#                      Extract on the target host, chown root:drvpsctl, run bin/dr-vps-setup --yes (INSTALL-RUNBOOK).
#   agent           -- ONLY docs/AGENT-GUIDE.md, as a single-file handout for a `drvpsctl` AGENT who must NOT
#                      see the project source -> ~/tmp/drvps-agent-guide-<UTC>.md. The agent drives the rig via
#                      the host's installed bin/rigctl; this doc is all they need.
set -euo pipefail

# pwd -P resolves symlinks to the PHYSICAL path: if the checkout is reached through a directory symlink,
# a logical path would make tar archive the symlink entry (`link -> /real/...`) instead of traversing the
# tree -- shipping an empty pack and leaking the link target. -P makes basename/-C refer to the real dir.
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STAMP="$(date -u +%Y%m%d-%H%M)"
TMP_DIR="${HOME}/tmp"
mkdir -p "$TMP_DIR"

PROFILE=full
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) [ "$#" -ge 2 ] || { echo "make-pack: --profile needs a value (full|agent)" >&2; exit 2; }
               PROFILE="$2"; shift 2 ;;
    --profile=*) PROFILE="${1#--profile=}"; shift ;;
    -h|--help) echo "usage: make-pack.sh [--profile full|agent]"; exit 0 ;;
    *) echo "make-pack: unknown argument '$1' (usage: make-pack.sh [--profile full|agent])" >&2; exit 2 ;;
  esac
done

case "$PROFILE" in
  agent)
    GUIDE="$SRC_DIR/docs/AGENT-GUIDE.md"
    [ -f "$GUIDE" ] || { echo "make-pack: agent guide not found: $GUIDE" >&2; exit 1; }
    OUT="${TMP_DIR}/drvps-agent-guide-${STAMP}.md"
    # Publish atomically: stage a temp in the SAME dir as OUT, then rename (same-filesystem -> atomic). A
    # direct `install` to OUT could leave a truncated/zero-byte handout at the canonical path on ENOSPC or
    # interruption. 0644: a NON-SECRET handout meant to be read by the recipient (who is not in this
    # checkout's group); it names only rigctl verbs, never host internals/goldens/source.
    TMP_OUT=$(mktemp "${TMP_DIR}/.drvps-agent-guide.XXXXXX") || { echo "make-pack: mktemp failed" >&2; exit 1; }
    trap 'rm -f "$TMP_OUT"' EXIT   # never leave a partial temp handout on an install/mv failure
    install -m 0644 -T "$GUIDE" "$TMP_OUT"   # -T: TMP_OUT is the exact target file, never "install INTO a dir"
    mv -fT "$TMP_OUT" "$OUT"                  # -T + same-fs rename: OUT flips from absent to complete atomically
    echo "agent handout -> ${OUT} ($(du -h "$OUT" | cut -f1))"
    ;;
  full)
    NAME="distro-rig-vps-${STAMP}"
    OUT="${TMP_DIR}/${NAME}.tar.gz"
    # --mode='u=rwX,g=rX,o=' NORMALISES install modes in the archive: this checkout is umask-0077
    # (0700 dirs / 0600 files), but after root extracts + chown root:drvpsctl, the 'drvps' SERVICE USER and the
    # agent (BOTH in drvpsctl) must traverse + read + exec the tree (systemd ExecStart=$root/bin/... , User=drvps;
    # agents run bin/rigctl) or the watcher dies 203/EXEC. GROUP-only, no world bit ('o='): the driver source is
    # non-secret but there is no reason to expose it beyond drvpsctl. 'X' grants execute only to dirs + already-
    # executable files, so bin/* -> 0750, src/* -> 0640, dirs -> 0750.
    # The WHOLE project dir minus: VCS metadata, runtime state dirs, built images, and generated files. Patterns
    # use '*/' so they match at any depth under the archive prefix. The repo carries no secrets (the cache CA +
    # host/VM keys are generated at install time), so the full tree is transferable.
    # Stage the archive in TMP_DIR (the SAME filesystem as OUT), then rename into place. Two reasons:
    #  - Atomic publish: a same-filesystem `mv` is a rename, so OUT flips from absent to complete in one step;
    #    it can never be left truncated on ENOSPC/interruption (a cross-fs mv would degrade to copy+unlink).
    #  - "file changed as we read it": the temp carries a '.tar.gz' suffix and is matched by --exclude below,
    #    so even in an unusual checkout where TMP_DIR sits under SRC_DIR, tar will not try to read it.
    ARCH_TMP=$(mktemp "${TMP_DIR}/.make-pack.XXXXXX.tar.gz") || { echo "make-pack: mktemp failed" >&2; exit 1; }
    trap 'rm -f "$ARCH_TMP"' EXIT   # never leave a partial temp archive on a tar/mv failure
    # --owner/--group=0 + --numeric-owner NORMALISE ownership to 0/0: tar records the packager's uid/gid and
    # user/group NAMES, which (a) leak the source-host account identity and (b) are meaningless -- the
    # documented install performs chown root:drvpsctl after extraction. --mode already normalises modes.
    # The excludes are DEFENSE-IN-DEPTH on top of "build from a clean checkout": beyond VCS/build/image
    # artifacts they drop the rig's runtime spool (spool/requests/results), rotated logs (*.log.N), and any
    # stray credential a dirty checkout might carry (.env*, private keys, .ssh) so none is silently shipped.
    tar --mode='u=rwX,g=rX,o=' --owner=0 --group=0 --numeric-owner -czf "$ARCH_TMP" \
      --exclude-vcs \
      --exclude='*.tar.gz' \
      --exclude='*/__pycache__' --exclude='*.pyc' \
      --exclude='*/state' --exclude='*/pool' --exclude='*/seed' --exclude='*/snapshots' \
      --exclude='*/spool' --exclude='*/requests' --exclude='*/results' \
      --exclude='*.qcow2' --exclude='*.img' --exclude='*.iso' --exclude='*.db' \
      --exclude='*.log' --exclude='*.log.*' \
      --exclude='*/.env' --exclude='*/.env.*' --exclude='*/.ssh' \
      --exclude='*.pem' --exclude='*.key' \
      --exclude='*/id_rsa' --exclude='*/id_dsa' --exclude='*/id_ecdsa' --exclude='*/id_ed25519' \
      --exclude='*/keys' --exclude='*/secrets' --exclude='*/credentials' \
      --exclude='*~' --exclude='*.swp' \
      -C "$(dirname "$SRC_DIR")" \
      -- "$(basename "$SRC_DIR")"
    mv -fT "$ARCH_TMP" "$OUT"   # -T + same-fs rename: OUT is the exact target file, published atomically
    chmod 0600 "$OUT"
    echo "pack -> ${OUT} ($(du -h "$OUT" | cut -f1))"
    ;;
  *)
    echo "make-pack: unknown profile '$PROFILE' (full|agent)" >&2; exit 2 ;;
esac
