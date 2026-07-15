#!/usr/bin/env bash
# DR-2: on a firewalld-ACTIVE host, dr-vps-setup's step_firewalld must open the guest->cache path in drvps0's
# zone with SCOPED permanent rich-rules (guest /24 -> cache_cidr, tcp cache_port + each mock_port from
# fleet.json), idempotent (query-before-add), + bind drvps0, + reload. Inactive firewalld -> a NO-OP.
# Drives step_firewalld via a MOCK firewall-cmd (DR_FIREWALL_CMD) that records its argv. ASCII only.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; fail=0
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
command -v jq >/dev/null 2>&1 || { echo "firewalld DR-2: SKIP (no jq)"; exit 0; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# a fleet.json with a cache endpoint + two mock ports
cat > "$T/fleet.json" <<'JSON'
{"simulated_allow":{"cache_cidr":"10.123.0.1/32","cache_port":3128,"mock_ports":[8443,9000]}}
JSON

# MOCK firewall-cmd: records argv to $LOG; --state active; get-zone-of-interface -> 'libvirt'; query-* -> not
# present (rc 1) so add-* runs; everything else rc 0.
MOCK="$T/fwmock"; LOG="$T/fwlog"
cat > "$MOCK" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$LOG"
for a in "\$@"; do case "\$a" in
  --state) exit 0;;
  --get-zone-of-interface=drvps0) echo libvirt; exit 0;;
  --query-rich-rule=*) exit 1;;      # not present -> triggers add
  --query-interface=drvps0) exit 1;; # not bound -> triggers add-interface
esac; done
exit 0
EOF
chmod +x "$MOCK"

# drive ONLY step_firewalld: source the setup with a guard so main() does not run, seam the env.
run_step() {
  DR_FIREWALL_CMD="$MOCK" DR_VPS_BRIDGE_IP="10.123.0.1" DR_VPS_SYS_STATE="$T" HERE="$REPO/bin" DRY_RUN=0 \
  bash -c '
    set -uo pipefail
    say(){ :; }
    HERE="'"$REPO"'/bin"; DR_VPS_SYS_STATE="'"$T"'"; DR_VPS_BRIDGE_IP="10.123.0.1"; DR_VPS_NET_NAME="drvps-simnet"; DRY_RUN=0
    # extract + eval just the step_firewalld function from the installer (no full sourcing / no main run)
    eval "$(awk "/^step_firewalld\\(\\) \\{/{p=1} p{print} p&&/^\\}$/{exit}" "'"$REPO"'/bin/dr-vps-setup")"
    step_firewalld
  '
}
run_step >/dev/null 2>&1

got="$(cat "$LOG" 2>/dev/null)"
ok "detected firewalld + queried drvps0 zone"     'printf "%s" "$got" | grep -q -- "--get-zone-of-interface=drvps0"'
ok "added a SCOPED rich-rule for the cache port 3128" \
   'printf "%s" "$got" | grep -q -- "--add-rich-rule=rule family=ipv4 source address=10.123.0.0/24 destination address=10.123.0.1/32 port port=3128 protocol=tcp accept"'
ok "added rich-rules for BOTH mock ports (8443, 9000)" \
   'printf "%s" "$got" | grep -q "port port=8443 protocol=tcp accept" && printf "%s" "$got" | grep -q "port port=9000 protocol=tcp accept"'
ok "rules are PERMANENT + zoned to drvps0's zone (libvirt)" 'printf "%s" "$got" | grep -q -- "--permanent --zone=libvirt --add-rich-rule"'
ok "query-BEFORE-add (idempotent)"                'printf "%s" "$got" | grep -q -- "--query-rich-rule="'
ok "binds drvps0 to the zone (survives --reload)" 'printf "%s" "$got" | grep -q -- "--add-interface=drvps0"'
ok "reloads firewalld"                            'printf "%s" "$got" | grep -qx -- "--reload"'
ok "NO blanket --add-service / --add-port (scoped only)" '! printf "%s" "$got" | grep -qE -- "--add-service|--add-port="'

# idempotent re-run: a mock that reports the rule ALREADY present -> NO add
MOCK2="$T/fwmock2"; LOG2="$T/fwlog2"
sed 's/--query-rich-rule=\*) exit 1;;/--query-rich-rule=*) exit 0;;/; s/--query-interface=drvps0) exit 1;;/--query-interface=drvps0) exit 0;;/; s#'"$LOG"'#'"$LOG2"'#' "$MOCK" > "$MOCK2"; chmod +x "$MOCK2"
DR_FIREWALL_CMD="$MOCK2" run_step >/dev/null 2>&1 || true
# re-run with the "already present" mock: run_step uses $MOCK; drive MOCK2 directly instead
DR_FIREWALL_CMD="$MOCK2" DR_VPS_BRIDGE_IP="10.123.0.1" DR_VPS_SYS_STATE="$T" bash -c '
  set -uo pipefail; say(){ :; }; HERE="'"$REPO"'/bin"; DR_VPS_SYS_STATE="'"$T"'"; DR_VPS_BRIDGE_IP="10.123.0.1"; DRY_RUN=0
  eval "$(awk "/^step_firewalld\\(\\) \\{/{p=1} p{print} p&&/^\\}$/{exit}" "'"$REPO"'/bin/dr-vps-setup")"
  step_firewalld' >/dev/null 2>&1 || true
ok "idempotent: rule already present -> NO --add-rich-rule" '! grep -q -- "--add-rich-rule" "$LOG2" 2>/dev/null'

# inactive firewalld (mock --state fails) -> a pure no-op (no rules touched)
MOCKX="$T/fwx"; LOGX="$T/fwxlog"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s"\nfor a in "$@"; do case "$a" in --state) exit 1;; esac; done\nexit 0\n' "$LOGX" > "$MOCKX"; chmod +x "$MOCKX"
DR_FIREWALL_CMD="$MOCKX" DR_VPS_BRIDGE_IP="10.123.0.1" DR_VPS_SYS_STATE="$T" bash -c '
  set -uo pipefail; say(){ :; }; HERE="'"$REPO"'/bin"; DR_VPS_SYS_STATE="'"$T"'"; DR_VPS_BRIDGE_IP="10.123.0.1"; DRY_RUN=0
  eval "$(awk "/^step_firewalld\\(\\) \\{/{p=1} p{print} p&&/^\\}$/{exit}" "'"$REPO"'/bin/dr-vps-setup")"
  step_firewalld' >/dev/null 2>&1 || true
ok "inactive firewalld -> no-op (never touches rules)" '! grep -q -- "--add-rich-rule\|--add-interface\|--reload" "$LOGX" 2>/dev/null'

echo "-------------------------------------------"
echo "firewalld DR-2: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
