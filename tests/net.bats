#!/usr/bin/env bats
# Stage 5 -- network safety (static pre-boot gate): render, generation, create-guard, SSRF.

load helpers

setup() {
  dr_vps_test_setup
  dr_vps_load dr_vps_api.sh
  dr_vps_load dr_vps_net.sh
  dr_vps_fake_nft                          # nft -f - saves; nft list ruleset replays
  cp "$DR_VPS_SRC/../etc/fleet.json" "$BATS_TEST_TMPDIR/fleet.json"
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/fleet.json"
  # fake virsh: create_guard's net-shape proof is FAIL-CLOSED, so the passing path needs net-dumpxml
  # to return an isolated+dhcp net. FV_NETRC lets a test force a net-dumpxml failure (indeterminate).
  export FV_NETRC="$BATS_TEST_TMPDIR/netrc"; echo 0 >"$FV_NETRC"
  cat >"$BATS_TEST_TMPDIR/fv" <<'EOF'
#!/usr/bin/env bash
case "$*" in *net-dumpxml*)
  [ "$(cat "${FV_NETRC:-/dev/null}" 2>/dev/null)" = 0 ] || exit 1
  printf "<network><name>simnet</name><bridge name='drvps0'/><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>\n" ;;
esac
exit 0
EOF
  chmod +x "$BATS_TEST_TMPDIR/fv"; export DR_VIRSH="$BATS_TEST_TMPDIR/fv"
}

@test "create_guard: FAIL CLOSED when libvirt cannot inspect the net (net-dumpxml fails -> 24)" {
  dr_vps_net_apply
  echo 1 >"$FV_NETRC"                       # net-dumpxml fails -> cannot prove the net shape
  run dr_vps_net_create_guard simnet
  [ "$status" -eq 24 ]                       # confinement gate REFUSES, never best-effort passes
}

_bump_inventory() { jq '.simulated_allow.cache_port=9999' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/t" && mv "$BATS_TEST_TMPDIR/t" "$DR_VPS_FLEET_JSON"; }

@test "render: guest-deny + drvps0 isolation; forward/input policy ACCEPT (no host collateral); no DNS/masquerade" {
  run dr_vps_net_render; [ "$status" -eq 0 ]
  [[ "$output" == *"chain guest_in"* ]]              # guest-policing chain (its last rule is drop)
  [[ "$output" == *'iifname "drvps0" drop'* ]]       # isolation: no routing on/off the sim net
  [[ "$output" == *'oifname "drvps0" drop'* ]]
  [[ "$output" == *"policy accept"* ]]               # forward+input accept -> host's other fwd untouched
  [[ "$output" == *"delete table inet drvps_sim"* ]] # M9: idempotent flush -> re-apply REPLACES, not appends
  [[ "$output" != *"policy drop"* ]]                 # REGRESSION GUARD: never policy-drop a shared hook
  [[ "$output" == *"nfproto ipv6 drop"* ]]
  [[ "$output" == *"tcp dport 3128 accept"* ]]
  [[ "$output" != *[Mm]asquerade* ]]
  [[ "$output" != *"dport 53"* ]]                    # NO DNS allowed
}

@test "create_guard: refuses a <forward>/no-<dhcp> net; passes isolated+dhcp (when libvirt answers)" {
  dr_vps_net_apply
  printf '#!/usr/bin/env bash\ncase "$*" in *net-dumpxml*) echo "<network><forward mode=\x27nat\x27/><ip><dhcp/></ip></network>";; esac\nexit 0\n' >"$BATS_TEST_TMPDIR/vnat"; chmod +x "$BATS_TEST_TMPDIR/vnat"
  DR_VIRSH="$BATS_TEST_TMPDIR/vnat" run dr_vps_net_create_guard simnet; [ "$status" -eq 24 ]
  printf '#!/usr/bin/env bash\ncase "$*" in *net-dumpxml*) echo "<network><ip/></network>";; esac\nexit 0\n' >"$BATS_TEST_TMPDIR/vnodhcp"; chmod +x "$BATS_TEST_TMPDIR/vnodhcp"
  DR_VIRSH="$BATS_TEST_TMPDIR/vnodhcp" run dr_vps_net_create_guard simnet; [ "$status" -eq 24 ]
  printf '#!/usr/bin/env bash\ncase "$*" in *net-dumpxml*) echo "<network><bridge name=\x27drvps0\x27/><ip><dhcp/></ip></network>";; esac\nexit 0\n' >"$BATS_TEST_TMPDIR/viso"; chmod +x "$BATS_TEST_TMPDIR/viso"
  DR_VIRSH="$BATS_TEST_TMPDIR/viso" run dr_vps_net_create_guard simnet; [ "$status" -eq 0 ]
  # WRONG-BRIDGE: isolated+dhcp but bridge != drvps0 -> the nft fence (iifname drvps0) would not apply -> refuse (24)
  printf '#!/usr/bin/env bash\ncase "$*" in *net-dumpxml*) echo "<network><bridge name=\x27virbr5\x27/><ip><dhcp/></ip></network>";; esac\nexit 0\n' >"$BATS_TEST_TMPDIR/vwbr"; chmod +x "$BATS_TEST_TMPDIR/vwbr"
  DR_VIRSH="$BATS_TEST_TMPDIR/vwbr" run dr_vps_net_create_guard simnet; [ "$status" -eq 24 ]
}

@test "render: only 'simulated' is supported in Phase 1" {
  run dr_vps_net_render open; [ "$status" -eq 2 ]
}

@test "generation: stable for same inventory, changes when inventory changes" {
  g1=$(dr_vps_net_generation)
  g1b=$(dr_vps_net_generation); [ "$g1" = "$g1b" ]
  _bump_inventory
  g2=$(dr_vps_net_generation); [ "$g1" != "$g2" ]
}

@test "apply: writes the generation marker matching current generation" {
  dr_vps_net_apply
  [ -f "$DR_VPS_NET_STATE" ]
  [ "$(cat "$DR_VPS_NET_STATE")" = "$(dr_vps_net_generation)" ]
}

@test "apply: the marker is published ATOMICALLY -- full bytes + 0644 BEFORE it becomes visible, via a same-dir rename" {
  # create_guard reads the marker UNLOCKED while the privileged timer rewrites it every ~120s. A
  # truncate-in-place write + late chmod let a concurrent create see an empty/partial/root-only
  # marker -> a false "stale marker" refusal. Shadow mv to capture the publish instant: the source
  # temp must ALREADY carry the complete generation and the world-readable mode, and the rename
  # must stay in the marker's own directory (same fs -> atomic; a cross-dir mv is a copy).
  local mvlog="$BATS_TEST_TMPDIR/mvlog"
  mkdir -p "$BATS_TEST_TMPDIR/shadow"
  cat >"$BATS_TEST_TMPDIR/shadow/mv" <<EOF
#!/usr/bin/env bash
args=(); for a in "\$@"; do case "\$a" in -*) ;; *) args+=("\$a");; esac; done
printf '%s|%s|%s|%s\n' "\$(cat "\${args[0]}")" "\$(stat -c %a "\${args[0]}")" \
  "\$(dirname "\${args[0]}")" "\$(dirname "\${args[1]}")" >>"$mvlog"
exec /usr/bin/mv "\$@"
EOF
  chmod +x "$BATS_TEST_TMPDIR/shadow/mv"
  PATH="$BATS_TEST_TMPDIR/shadow:$PATH" dr_vps_net_apply
  [ -s "$mvlog" ]                                              # the publish IS a rename, not in-place truncate
  local rec; rec=$(tail -1 "$mvlog")
  local c m sd dd; IFS='|' read -r c m sd dd <<<"$rec"
  [ "$c" = "$(dr_vps_net_generation)" ]                        # complete bytes BEFORE visibility
  [ "$m" = 644 ]                                               # world-readable BEFORE visibility (no 0600 window)
  [ "$sd" = "$dd" ]                                            # same-dir temp -> same-fs atomic rename
  [ "$(cat "$DR_VPS_NET_STATE")" = "$(dr_vps_net_generation)" ]
  [ "$(stat -c %a "$DR_VPS_NET_STATE")" = 644 ]
}

@test "apply: IDEMPOTENT -- add->delete->recreate render re-applies cleanly (twice)" {
  # `add table` is idempotent on real nft (validated: nftables v1.1.6 applies the render 3x, rule
  # count stays 2), so the periodic egress timer / --reapply-egress can re-assert without error.
  dr_vps_net_apply
  run dr_vps_net_apply
  [ "$status" -eq 0 ]
  run dr_vps_net_render
  [[ "$output" == *"add table inet drvps_sim"* ]]     # ensure-exists so the delete never errors
  [[ "$output" == *"delete table inet drvps_sim"* ]]  # then replace (no append/duplication)
}

@test "create_guard: the libvirt default-NAT net is refused (24)" {
  dr_vps_net_apply
  run dr_vps_net_create_guard default; [ "$status" -eq 24 ]
  run dr_vps_net_create_guard "";       [ "$status" -eq 24 ]
}

@test "create_guard: any NON-allowlisted net name is refused, not merely 'default' (24)" {
  dr_vps_net_apply
  run dr_vps_net_create_guard natnet;       [ "$status" -eq 24 ]   # a renamed NAT net must not pass
  run dr_vps_net_create_guard bridged-prod; [ "$status" -eq 24 ]
}

@test "create_guard: no applied-egress marker (never set up) is refused (24)" {
  run dr_vps_net_create_guard simnet; [ "$status" -eq 24 ]   # nothing applied -> no marker file
}

@test "create_guard: applied+fresh -> 0; STALE (inventory changed, not re-applied) -> 24" {
  dr_vps_net_apply
  run dr_vps_net_create_guard simnet; [ "$status" -eq 0 ]
  _bump_inventory                                            # bumps generation; live ruleset now stale
  run dr_vps_net_create_guard simnet; [ "$status" -eq 24 ]
  [[ "$output" == *stale* ]]
}

@test "fleet inventory invalid JSON -> fail-closed" {
  printf '{not json' >"$DR_VPS_FLEET_JSON"
  run dr_vps_net_generation; [ "$status" -ne 0 ]
}

@test "SSRF control: only mirror-allowlist hosts pass; arbitrary host refused (24)" {
  run dr_vps_proxy_allowlist_check mirrors.fedoraproject.org; [ "$status" -eq 0 ]
  run dr_vps_proxy_allowlist_check evil.example.com;          [ "$status" -eq 24 ]
}

@test "dns_policy: no internal resolver" {
  run dr_vps_net_dns_policy; [ "$status" -eq 0 ]
  [[ "$output" == *"no-internal"* ]]; [[ "$output" == *"no nameserver"* ]]
}

@test "fleet inventory missing -> fail-closed (not-found)" {
  export DR_VPS_FLEET_JSON="$BATS_TEST_TMPDIR/nope.json"
  run dr_vps_net_generation; [ "$status" -eq 14 ]
}

@test "render: the rendered ruleset PARSES on REAL nft (-c -f -); skips if nft can't init netlink" {
  command -v nft >/dev/null 2>&1 || skip "nft not installed"
  run dr_vps_net_render; [ "$status" -eq 0 ]
  local rendered="$output"
  # POSITIVE discriminator: a substring match on the error text ('protocol', 'netlink')
  # can misclassify a REAL render bug as an env-skip -- AND always-skips in rootless/CI. Instead probe
  # with a KNOWN-GOOD trivial ruleset: if THAT also fails to parse, nft genuinely can't init here (skip);
  # if the trivial one parses but ours does not, that is a REAL syntax error in the render (fail).
  if ! printf '%s\n' "$rendered" | nft -c -f - 2>"$BATS_TEST_TMPDIR/nfterr"; then
    if printf 'table inet drvps_probe { chain c { type filter hook input priority 0; } }\n' \
         | nft -c -f - 2>/dev/null; then
      cat "$BATS_TEST_TMPDIR/nfterr" >&2; false          # trivial ruleset parses -> OUR render is broken
    fi
    skip "nft -c cannot init netlink in this env (rootless/no NET_ADMIN) -- known-good probe also failed"
  fi
}

@test "create_guard: a <metadata> DECOY <bridge name=drvps0> cannot spoof the real bridge proof (24)" {
  dr_vps_net_apply
  cat >"$BATS_TEST_TMPDIR/vdecoy" <<'SH'
#!/usr/bin/env bash
case "$*" in *net-dumpxml*)
cat <<'XML'
<network><name>simnet</name><bridge name='virbr5'/><metadata><m:stash xmlns:m='urn:evil'><bridge xmlns='urn:evil' name='drvps0'/></m:stash></metadata><ip address='10.123.0.1'><dhcp><range start='10.123.0.10' end='10.123.0.250'/></dhcp></ip></network>
XML
;; esac
exit 0
SH
  chmod +x "$BATS_TEST_TMPDIR/vdecoy"
  DR_VIRSH="$BATS_TEST_TMPDIR/vdecoy" run dr_vps_net_create_guard simnet
  [ "$status" -eq 24 ]                       # real bridge is virbr5; the metadata drvps0 decoy must NOT count
}

# ---- S0 (service plane): fleet.json is hash-stable + forward-compatible ----

@test "S0: shipped etc/fleet.json carries NO service-plane keys (any key would policy-stale every VM)" {
  # dr_vps_net_generation hashes the WHOLE inventory, so S0 must NOT add reserved keys to the deployed file.
  run jq -e 'has("egress_profiles") or has("service_ports") or has("service_quota")' "$DR_VPS_SRC/../etc/fleet.json"
  [ "$status" -ne 0 ]                                  # expression is false -> jq -e exits nonzero
}

@test "S0: net_render + net_generation TOLERATE reserved service-plane keys if present (forward-compat)" {
  jq '.egress_profiles={} | .service_ports={} | .service_quota=3' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/t"
  mv "$BATS_TEST_TMPDIR/t" "$DR_VPS_FLEET_JSON"
  run dr_vps_net_render; [ "$status" -eq 0 ]           # unknown keys ignored -> render still works
  run dr_vps_net_generation; [ "$status" -eq 0 ]; [ -n "$output" ]
}

@test "S0: adding a service-plane key DOES bump the generation (documents why S0 leaves fleet.json untouched)" {
  g1=$(dr_vps_net_generation)
  jq '.service_quota=3' "$DR_VPS_FLEET_JSON" >"$BATS_TEST_TMPDIR/t"; mv "$BATS_TEST_TMPDIR/t" "$DR_VPS_FLEET_JSON"
  g2=$(dr_vps_net_generation)
  [ "$g1" != "$g2" ]
}
