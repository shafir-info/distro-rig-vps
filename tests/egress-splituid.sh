#!/usr/bin/env bash
# Split-UID (real root vs real drvps) egress-store boundary gate -- the standing regression the offline
# single-UID suites structurally cannot see (docs/EGRESS-STORE-ARCH-UPGRADE.md §9).
# Runs inside a disposable rootless container: provision + assert ownership as root, then exercise the
# cross-UID DAC as a REAL drvps user. No sudo, no shared-rig touch.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v podman >/dev/null || { echo "SKIP: podman not available"; exit 0; }
IMG="${DRVPS_SPLITUID_IMG:-registry.fedoraproject.org/fedora:latest}"
podman run --rm -v "$REPO":/repo:ro,Z "$IMG" bash /repo/tests/egress-splituid-inner.sh
