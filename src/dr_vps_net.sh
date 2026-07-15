#!/usr/bin/env bash
# dr_vps_net.sh -- network safety, the `simulated` PRE-BOOT gate (Stage 5).
# Static/seamed half: render/load the REAL deny-by-default nftables ruleset from the
# config-driven fleet inventory, stamp an egress-generation, and REFUSE create unless
# the VM net is doctor-proven simulated/closed AND the ruleset is present + fresh.
# The LIVE "VM cannot reach fleet/gateway/host" reach-controls are Stage 8 (need a VM).
# ASCII only; bins run set -uo pipefail (code is also -e-safe).

# shellcheck source-path=SCRIPTDIR
# shellcheck source=dr_vps_api.sh
[ -n "${DR_VPS_API_SOURCED:-}" ] || . "$(dirname "${BASH_SOURCE[0]}")/dr_vps_api.sh"

_dr_vps_fleet() {  # path to the inventory; fail-closed if absent OR not valid JSON
  local f="$DR_VPS_FLEET_JSON"
  [ -f "$f" ] || { dr_vps_die "$DR_VPS_E_NOTFOUND" "fleet inventory not found: $f"; return $?; }
  jq -e . "$f" >/dev/null 2>&1 || { dr_vps_die "$DR_VPS_E_GENERIC" "fleet inventory is not valid JSON: $f"; return $?; }
  printf '%s' "$f"
}

# egress-generation = a content hash of the canonicalized inventory. Changing the
# inventory changes the generation, which makes already-born VMs policy-stale.
dr_vps_net_generation() {
  local f; f=$(_dr_vps_fleet) || return $?
  jq -S -c . "$f" | sha256sum | awk '{print substr($1,1,12)}'
}

# Render the `simulated` deny-by-default ruleset. The guest_in chain drops everything from
# the isolated bridge except DHCP + the cache/mocks; IPv6 is dropped; no MASQUERADE /
# libvirt default-NAT. Guest-to-guest L2 is NOT filtered HERE (nft is L3) -- it is enforced at the
# libvirt layer instead: every rig NIC is rendered with <port isolated='yes'/> (dr_vps_domain.sh), so
# the bridge blocks guest<->guest traffic. (There is still no per-VM source-IP anti-spoof L3 rule.)
# BASE-CHAIN COMPOSITION (DR-2): nft ACCEPTs do NOT compose across tables/base chains -- every base chain on a
# hook runs and a REJECT anywhere wins. On a firewalld-ACTIVE host this guest_in ACCEPT is overridden by
# firewalld's REJECT in drvps0's zone, so the host firewall must ALSO allow guest/24 -> cache_cidr:cache_port +
# mock_ports. dr-vps-setup's step_firewalld installs that as scoped permanent rich-rules (no-op off firewalld).
dr_vps_net_render() {  # [profile=simulated]
  local profile="${1:-simulated}" f cache_cidr cache_port mocks gen p
  [ "$profile" = simulated ] || { dr_vps_die "$DR_VPS_E_USAGE" "Phase 1 renders only 'simulated' (got '$profile')"; return $?; }
  f=$(_dr_vps_fleet) || return $?
  cache_cidr=$(jq -r '.simulated_allow.cache_cidr' "$f")
  cache_port=$(jq -r '.simulated_allow.cache_port' "$f")
  # VALIDATE every value before it is interpolated into nft syntax (no
  # malformed/valid JSON may inject nft rules). CIDR chars only + a slash; ports 1..65535.
  case "$cache_cidr" in ''|null|*[!0-9A-Fa-f.:/]*) dr_vps_die "$DR_VPS_E_GENERIC" "bad cache_cidr: $cache_cidr"; return $?;; esac
  [[ "$cache_cidr" == */* ]] || { dr_vps_die "$DR_VPS_E_GENERIC" "cache_cidr is not a CIDR: $cache_cidr"; return $?; }
  { [[ "$cache_port" =~ ^[0-9]+$ ]] && [ "$cache_port" -ge 1 ] && [ "$cache_port" -le 65535 ]; } || { dr_vps_die "$DR_VPS_E_GENERIC" "bad cache_port: $cache_port"; return $?; }
  for p in $(jq -r '.simulated_allow.mock_ports[]?' "$f"); do
    { [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; } || { dr_vps_die "$DR_VPS_E_GENERIC" "bad mock port: $p"; return $?; }
  done
  mocks=$(jq -r '.simulated_allow.mock_ports | map(tostring) | join(", ")' "$f")
  [ -n "$mocks" ] || { dr_vps_die "$DR_VPS_E_GENERIC" "fleet.simulated_allow.mock_ports empty"; return $?; }
  gen=$(dr_vps_net_generation) || return $?
  cat <<EOF
# drvps simulated egress (deny-by-default). The generation is a REAL nft rule comment
# (preserved by 'nft list ruleset'), NOT a '#' line comment (which nft drops). guest_in
# polices guest->host on the isolated bridge. forward uses policy ACCEPT + explicit drvps0
# drops: that isolates the sim net (no routing on/off it) WITHOUT clobbering the host's
# OTHER forwarded traffic (podman, libvirt default-NAT) -- nft runs ALL base chains on a
# hook, so a policy-drop here would override their accepts. Same for input (policy accept).
# IDEMPOTENT replace: 'add' the table (no-op if present) then delete it, so a re-apply
# REPLACES the ruleset in one atomic 'nft -f' transaction instead of APPENDING duplicates.
add table inet drvps_sim
delete table inet drvps_sim
table inet drvps_sim {
  chain guest_in {
    meta nfproto ipv6 drop
    ct state established,related accept comment "drvps-gen-${gen}"
    udp dport { 67, 68 } accept
    ip daddr ${cache_cidr} tcp dport ${cache_port} accept
    ip daddr ${cache_cidr} tcp dport { ${mocks} } accept
    drop
  }
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "drvps0" jump guest_in
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "drvps0" drop
    oifname "drvps0" drop
  }
}
EOF
}

# Load the ruleset (privileged; nft is seamed). Records the applied generation marker.
dr_vps_net_apply() {
  local rendered gen live
  rendered=$(dr_vps_net_render simulated) || return $?
  printf '%s\n' "$rendered" | "$DR_NFT" -f - 2>/dev/null \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "nft load failed"; return $?; }
  gen=$(dr_vps_net_generation) || return $?
  # LIVE verify in this PRIVILEGED context (the installer is root and CAN read nft): the
  # table, BOTH isolation drops, the guest-policing chain, and THIS generation must actually
  # be loaded. The rig user (drvps) cannot read nft, so this strong check happens HERE, at
  # apply time, and create_guard later trusts the marker we write next.
  live=$("$DR_NFT" list ruleset 2>/dev/null)
  { printf '%s' "$live" | grep -q "table inet drvps_sim" \
    && printf '%s' "$live" | grep -q "chain guest_in" \
    && printf '%s' "$live" | grep -q 'iifname "drvps0" drop' \
    && printf '%s' "$live" | grep -q 'oifname "drvps0" drop' \
    && printf '%s' "$live" | grep -q "drvps-gen-${gen}"; } \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "nft apply verify failed (table/rules/gen $gen not live)"; return $?; }
  # The marker dir is ROOT-owned + world-traversable (so the unprivileged rig user can READ
  # but not FORGE the marker). On tmpfs (/run) it vanishes on reboot -> create_guard fails
  # CLOSED until the boot egress oneshot re-applies (see drvps-egress.service).
  mkdir -p "$(dirname "$DR_VPS_NET_STATE")" \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot create egress-marker dir $(dirname "$DR_VPS_NET_STATE")"; return $?; }
  chmod 0755 "$(dirname "$DR_VPS_NET_STATE")" 2>/dev/null || true
  printf '%s\n' "$gen" >"$DR_VPS_NET_STATE" \
    || { dr_vps_die "$DR_VPS_E_GENERIC" "cannot write egress marker $DR_VPS_NET_STATE"; return $?; }
  # The installer runs root with umask 0077 -> 0600 root, which the rig user (drvps) can't
  # read. The marker is a non-secret generation hash; make it world-readable so create_guard
  # (drvps) can check it. (Fail-closed: if it stays unreadable, create_guard refuses anyway.)
  chmod 0644 "$DR_VPS_NET_STATE" 2>/dev/null || true
}

# PRE-BOOT create guard (24 on refusal). Two checks, both fail-closed:
#  (a) the net must be an ALLOWLISTED simulated network (config), not merely "not default"
#      -- a renamed NAT/bridged net must NOT pass;
#  (b) the applied-egress MARKER must carry the CURRENT generation. The rig user (drvps) cannot
#      read live nft (needs root), so the guard trusts the marker that net_apply wrote AFTER a
#      live root verification. The marker covers: never-applied (absent) and stale-after-inventory-
#      change (generation mismatch), and -- because it lives on tmpfs (/run) -- reboot (vanishes ->
#      fail closed). A RUNTIME flush of nft (root-only; the agent has no nft access) is NOT caught
#      at guard time, but is re-asserted + the marker re-validated by the drvps-egress.timer within
#      its interval (default 120s). That residual window is the price of not granting drvps nft read.
dr_vps_net_create_guard() {  # <net_name>
  local net="${1:-}" f curgen
  f=$(_dr_vps_fleet) || return $?
  [ -n "$net" ] || { dr_vps_die "$DR_VPS_E_EGRESS" "empty net"; return $?; }
  jq -e --arg n "$net" '(.simulated_networks // []) | index($n) != null' "$f" >/dev/null 2>&1 \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "net '$net' is not an allowlisted simulated network"; return $?; }
  curgen=$(dr_vps_net_generation) || return $?
  # The rig user (drvps) CANNOT read nft (needs root). Trust the marker that net_apply (root,
  # at install time) wrote AFTER loading the ruleset AND a live root verification of it.
  # Refuse if the marker is absent (egress never applied) or stale (inventory changed).
  local applied
  [ -r "$DR_VPS_NET_STATE" ] \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "no applied-egress marker ($DR_VPS_NET_STATE) -- run dr-vps-setup"; return $?; }
  applied=$(cat "$DR_VPS_NET_STATE" 2>/dev/null)
  [ "$applied" = "$curgen" ] \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "stale egress generation (applied '$applied' != current '$curgen') -- re-apply via dr-vps-setup"; return $?; }
  # network-shape proof -- FAIL CLOSED: an allowlisted net must NOT have a <forward> (NAT/routed) AND
  # must have <dhcp>. This is a CONFINEMENT gate, so "cannot inspect the network" (net-dumpxml fails
  # or returns empty) is a REFUSAL, not best-effort -- the agent (drvps, in the libvirt group) can
  # read net-dumpxml, so a failure here means a real problem, never a permission hedge.
  local netxml
  netxml=$("$DR_VIRSH" -c "$DR_LIBVIRT_URI" net-dumpxml "$net" 2>/dev/null) \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "cannot inspect libvirt network '$net' (net-dumpxml failed) -- refusing"; return $?; }
  [ -n "$netxml" ] \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "empty libvirt XML for network '$net' -- refusing"; return $?; }
  # STRUCTURAL proof via xmllint, NOT grep: a raw text match can be spoofed by a decoy element inside
  # <metadata> (e.g. a nested <bridge name='drvps0'/> under a custom-namespace stash) while the REAL
  # /network/bridge is some other bridge. Scope every check to the real /network/* elements; a parse
  # failure (or an unparseable XML) refuses closed.
  local nroot nfwd ndhcp nbr
  nroot=$(printf '%s' "$netxml" | "$DR_XMLLINT" --xpath "count(/network)" - 2>/dev/null)
  [ "$nroot" = 1 ] || { dr_vps_die "$DR_VPS_E_EGRESS" "net '$net' XML unparseable/no <network> root -- refusing"; return $?; }
  nfwd=$(printf '%s' "$netxml" | "$DR_XMLLINT" --xpath "count(/network/forward)" - 2>/dev/null)
  [ "${nfwd:-1}" = 0 ] || { dr_vps_die "$DR_VPS_E_EGRESS" "net '$net' has <forward> (NAT/routed) -- not isolated"; return $?; }
  ndhcp=$(printf '%s' "$netxml" | "$DR_XMLLINT" --xpath "count(/network/ip/dhcp)" - 2>/dev/null)
  { [ -n "$ndhcp" ] && [ "$ndhcp" -ge 1 ] 2>/dev/null; } || { dr_vps_die "$DR_VPS_E_EGRESS" "net '$net' lacks <dhcp> -- guests get no address"; return $?; }
  # The ENTIRE nft egress fence is interface-scoped on the LITERAL bridge 'drvps0' (iifname/oifname in
  # dr_vps_net_render + the live-verify in dr_vps_net_apply). A simnet on a DIFFERENT bridge passes
  # every other check while the host-port restriction + forward isolation silently never match -> the
  # untrusted guest could reach the host on ANY bridge-IP port. So the REAL /network/bridge MUST be
  # 'drvps0' (fail closed). drvps can read net-dumpxml, so this check is real.
  nbr=$(printf '%s' "$netxml" | "$DR_XMLLINT" --xpath "count(/network/bridge[@name='drvps0'])" - 2>/dev/null)
  [ "${nbr:-0}" = 1 ] \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "net '$net' real bridge is not 'drvps0' (a <metadata> decoy does not count) -- the nft egress fence would not apply"; return $?; }
}

# DNS policy: Phase 1 = no host/internal resolver; cache/mock names resolve via a seeded
# /etc/hosts only (never an implicit resolver leak).
dr_vps_net_dns_policy() {
  local f pol; f=$(_dr_vps_fleet) || return $?
  pol=$(jq -r '.dns' "$f")
  printf 'dns_policy=%s\n' "$pol"
  printf '# no nameserver; cache/mock hostnames via seeded /etc/hosts only\n'
}

# Proxy SSRF guard: only mirror-domain allowlist entries may be CONNECTed; else refuse 24.
dr_vps_proxy_allowlist_check() {  # <host>
  local host="${1:-}" f; f=$(_dr_vps_fleet) || return $?
  jq -e --arg h "$host" '.mirror_allowlist | index($h) != null' "$f" >/dev/null 2>&1 \
    || { dr_vps_die "$DR_VPS_E_EGRESS" "host not in mirror allowlist (SSRF refused): $host"; return $?; }
}
