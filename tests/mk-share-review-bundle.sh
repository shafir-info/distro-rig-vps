#!/usr/bin/env bash
# Assemble the drvps-top-share CONTRACT review bundle for the external reviewer (reproducible; committed).
# Sources + docs + tests only -- no binaries, no fixtures blobs (the MANIFEST is the verdict ledger).
# Usage: tests/mk-share-review-bundle.sh [OUTDIR]   (default: $HOME/tmp)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${1:-$HOME/tmp}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$OUTDIR/drvps-top-share-$STAMP"
TAR="$WORK.tar.gz"

# numbered-name -> repo-relative source (order = what the reviewer reads first)
MAP=(
  "00-DESIGN.md:docs/CONCEPT-DRVPS-TOP-SHARE.md"
  "01-drvps_top_feed.py.txt:tools/drvps_top_feed.py"
  "02-drvps_top_config.py.txt:tools/drvps_top_config.py"
  "03-feed-test.py.txt:tests/drvps-top-feed-test.py"
  "04-config-test.py.txt:tests/drvps-top-config-test.py"
  "05-MANIFEST.txt:docs/drvps-top-share-fixtures/MANIFEST.txt"
)

FIXDIR="docs/drvps-top-share-fixtures"

rm -rf "$WORK"
mkdir -p "$WORK"
for pair in "${MAP[@]}"; do
  dst="${pair%%:*}"; src="${pair#*:}"
  [ -f "$REPO/$src" ] || { echo "missing source: $src" >&2; exit 1; }
  cp "$REPO/$src" "$WORK/$dst"
done

# The byte-exact .feed corpus is NORMATIVE (design sec 5) and the read-only test compares against it,
# so it MUST travel in the review bundle. Text fixtures, not binaries.
n_feed=0
mkdir -p "$WORK/06-fixtures"
for f in "$REPO/$FIXDIR"/*.feed; do
  [ -e "$f" ] || { echo "no .feed fixtures in $FIXDIR (run the feed test with --regen first)" >&2; exit 1; }
  cp "$f" "$WORK/06-fixtures/$(basename "$f")"
  n_feed=$((n_feed + 1))
done
echo "bundle: 6 sources/docs/tests + $n_feed .feed fixtures" >&2

tar -czf "$TAR" -C "$OUTDIR" "$(basename "$WORK")"
rm -rf "$WORK"
echo "$TAR"
