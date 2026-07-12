#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later (see LICENSE)
# Copyright (c) 2026 Alexander Shafir <alexander@shafir.info> - https://www.shafir.info
# Vibe-coded with Claude (Anthropic).
#
# Backup the distro-rig-vps project (source, docs, tests) into the append-only
# ~/BACKUPS dir. Maintainer utility -- not part of the installed product.
#
# Stage in $HOME/tmp, build a
# deterministic tar, sanity-check it, then mv into ~/BACKUPS (a rename across the same
# FS is allowed even when BACKUPS is chattr +a, which the operator sets manually as a
# one-shot sudo step). Runtime state + VM images/seeds are EXCLUDED: they are host-local,
# regenerable, large, and seeds may hold key material.
#
# Usage: ./tools/backup.sh [archive_name]
# Output: ~/BACKUPS/<archive_name>.tar.gz
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="$(basename "$PROJECT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE_NAME="${1:-${PROJECT_NAME}_${TIMESTAMP}}"

# Consolidated home-level backup dir (fleet convention), NOT a project-local subdir.
# Tarball names are project-prefixed (distro-rig-vps_*), so they coexist.
BACKUP_DIR="${HOME}/BACKUPS"
STAGE_DIR="${HOME}/tmp"

mkdir -p "$BACKUP_DIR"; chmod 0700 "$BACKUP_DIR" 2>/dev/null || true   # no-op once chattr +a is on
mkdir -p "$STAGE_DIR";  chmod 0700 "$STAGE_DIR"  2>/dev/null || true

STAGE="${STAGE_DIR}/${ARCHIVE_NAME}.tar.gz"
OUTPUT="${BACKUP_DIR}/${ARCHIVE_NAME}.tar.gz"

echo "Backing up ${PROJECT_NAME} ..."
echo "  Source:  ${PROJECT_DIR}"
echo "  Staged:  ${STAGE}"
echo "  Output:  ${OUTPUT}"

trap 'rm -f "$STAGE"' EXIT

tar -czf "$STAGE" \
    -C "$(dirname "$PROJECT_DIR")" \
    --exclude-vcs \
    --exclude="${PROJECT_NAME}/state" \
    --exclude="${PROJECT_NAME}/pool" \
    --exclude="${PROJECT_NAME}/seed" \
    --exclude="${PROJECT_NAME}/BACKUPS" \
    --exclude='*.qcow2' \
    --exclude='*.img' \
    --exclude='*.iso' \
    --exclude='*.db' \
    --exclude='*.log' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.tmp' \
    --exclude='*.swp' \
    --exclude='*.bak' \
    --exclude="${PROJECT_NAME}/spool" \
    --exclude="${PROJECT_NAME}/snapshots" \
    --exclude='*/requests' \
    --exclude='*/results' \
    --exclude='.env' --exclude='.env.*' --exclude='.ssh' \
    --exclude='*.pem' --exclude='*.key' \
    --exclude='id_rsa' --exclude='id_dsa' --exclude='id_ecdsa' --exclude='id_ed25519' \
    --exclude='*/keys' --exclude='*/secrets' --exclude='*/credentials' \
    "$PROJECT_NAME"

# Sanity: tarball is non-empty and includes the top-level CONCEPT.md. Use `grep -c`
# (not `grep -q`): under pipefail, grep -q SIGPIPEs tar early and fails the pipeline
# even when the file IS present; grep -c reads to EOF so tar drains cleanly.
HITS="$(tar -tzf "$STAGE" | grep -c "^${PROJECT_NAME}/CONCEPT.md$" || true)"
if [ "$HITS" -eq 0 ]; then
    echo "FATAL: tarball missing CONCEPT.md - aborting" >&2
    exit 2
fi

mv "$STAGE" "$OUTPUT"
trap - EXIT
chmod 0600 "$OUTPUT" 2>/dev/null || true

SIZE=$(du -h "$OUTPUT" | cut -f1)
ENTRIES=$(tar -tzf "$OUTPUT" | wc -l)
echo "Done. Archive size: ${SIZE}, entries: ${ENTRIES}"
echo ""
echo "To extract:"
echo "  mkdir -p /tmp/restore && cd /tmp/restore"
echo "  tar xzf ${OUTPUT}"
echo ""
echo "Note: ~/BACKUPS should be chattr +a (append-only) for ransomware"
echo "resistance. Operator-side, one-shot:"
echo "  sudo /usr/bin/chattr +a ${BACKUP_DIR}"
echo "Verify with: lsattr -d ${BACKUP_DIR}  (expect: -----a-----...)"
