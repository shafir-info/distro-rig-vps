#!/usr/bin/env bash
# Shared bats helpers for distro-rig-vps. Each test sources this, which points the
# state dir at the test tmpdir and sources dr_vps_api.sh + the modules under test.
# ASCII only.

DR_VPS_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"

dr_vps_test_setup() {
  export DR_VPS_TEST_SEAMS=1          # honor DR_VPS_FACT_* only under tests
  export DR_VPS_SEED_GROUP="$(id -gn)"   # seed chgrp is fail-closed; use the agent's own group
  export DR_VPS_STATE_DIR="${BATS_TEST_TMPDIR}/state"
  export DR_VPS_POOL_DIR="${DR_VPS_STATE_DIR}/pool"
  export DR_VPS_SEED_DIR="${DR_VPS_STATE_DIR}/seed"
  export DR_VPS_DB="${DR_VPS_STATE_DIR}/store.db"
  export DR_VPS_TMP_DIR="${DR_VPS_STATE_DIR}/tmp"
  export DR_VPS_NET_STATE="${DR_VPS_STATE_DIR}/nft.applied"   # prod marker is /run (root-owned); tests use the temp state dir
  mkdir -p "$DR_VPS_STATE_DIR" "$DR_VPS_POOL_DIR" "$DR_VPS_SEED_DIR" "$DR_VPS_TMP_DIR"
}

# Source a module (and the api it depends on).
dr_vps_load() {
  # shellcheck source=/dev/null
  . "${DR_VPS_SRC}/$1"
}

# Install a fake nft: `nft -f -` saves the loaded ruleset; `nft list ruleset` replays it,
# so create_guard's LIVE generation check sees real applied/flushed/stale state.
dr_vps_fake_nft() {
  export FAKENFT_STATE="${BATS_TEST_TMPDIR}/nft.state"
  cat >"${BATS_TEST_TMPDIR}/fakenft" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -f)   cat >"${FAKENFT_STATE:-/dev/null}" ;;
  list) cat "${FAKENFT_STATE:-/dev/null}" 2>/dev/null || true ;;
esac
exit 0
EOF
  chmod +x "${BATS_TEST_TMPDIR}/fakenft"
  export DR_NFT="${BATS_TEST_TMPDIR}/fakenft"
}

# Make a tiny qcow2 of `size` bytes with the given on-disk content marker.
# Two qcow2 built from the SAME raw content but different cluster sizes have
# different qcow2 metadata yet identical logical content (the two-domain control).
dr_vps_mk_qcow2() {
  local out="$1" size="${2:-2097152}" cluster="${3:-65536}" marker="${4:-}"
  local raw="${BATS_TEST_TMPDIR}/mk.$$.$RANDOM.raw"
  head -c "$size" /dev/zero >"$raw"
  if [ -n "$marker" ]; then
    # poke a deterministic non-zero byte so different markers => different content
    printf '%s' "$marker" | dd of="$raw" bs=1 seek=4096 conv=notrunc status=none
  fi
  qemu-img convert -f raw -O qcow2 -o "cluster_size=${cluster}" "$raw" "$out"
  rm -f "$raw"
}
