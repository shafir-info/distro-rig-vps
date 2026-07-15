#!/usr/bin/env bash
# Unit tests for drvps-top pure reducers + raw parsers (Layer 1-2). No live rig.
# Run: bash tests/drvps-top-test.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRVPS_TOP_NO_ENV=1 DRVPS_TOP_COLOR=1
export DRVPS_TOP_NO_ENV DRVPS_TOP_COLOR
# shellcheck disable=SC1090
source "$HERE/../tools/drvps-top"

pass=0; fail=0
eq() { # <desc> <got> <want>
  if [ "$2" = "$3" ]; then pass=$((pass+1));
  else fail=$((fail+1)); printf 'FAIL: %s\n  got : [%s]\n  want: [%s]\n' "$1" "$2" "$3"; fi
}

# ---- short_id ----
eq "short_id vm"        "$(short_id drvps-vm-b71deae19298de23)"                 "b71deae1"
eq "short_id snap"      "$(short_id drvps-snap-v1-3758096384-a9f0e966caafc7e4)" "a9f0e966"
eq "short_id raw"       "$(short_id drvps-raw-v1-5368709120-bc07c9f78db03574)"  "bc07c9f7"

# ---- vm_shortname ----
eq "vm_shortname scen"  "$(vm_shortname weftg-20260712T195935Z-fC4Ted-P05)"     "weftg*P05"
eq "vm_shortname kc"    "$(vm_shortname kcgold-20260712T190348Z-27213)"         "kcgold"
eq "vm_shortname plain" "$(vm_shortname bare)"                                   "bare"

# ---- owner_label ----
eq "owner name+uid"     "$(owner_label 1007 alice)"                             "alice(1007)"
eq "owner uid only"     "$(owner_label 1099 '')"                                "1099"
eq "owner null"         "$(owner_label NULL '')"                                "operator"
eq "owner empty"        "$(owner_label '' '')"                                  "operator"

# ---- base_label ----
eq "base snap"          "$(base_label snapshot ubuntu26 drvps-snap-v1-x-a9f0e966caafc7e4)" "ubuntu26@snap:a9f0e966"
eq "base golden"        "$(base_label golden fedora44 drvps-raw-v1-x-bc07c9f78db03574)"    "fedora44@raw:bc07c9f7"
eq "base orphan"        "$(base_label snapshot ubuntu26 NULL)"                  "orphan:none"
eq "base distro?"       "$(base_label snapshot NULL drvps-snap-v1-x-a9f0e966caafc7e4)"     "distro?@snap:a9f0e966"

# ---- cpu_pct ----
eq "cpu increase"       "$(cpu_pct 1000000000 2000000000 0 1000000000)"         "100.0"   # 1s cpu in 1s wall = 100%
eq "cpu aggregate"      "$(cpu_pct 0 4000000000 0 1000000000)"                  "400.0"   # 4 vcpu busy
eq "cpu equal"          "$(cpu_pct 5000 5000 0 1000000000)"                     "0.0"
eq "cpu decrease"       "$(cpu_pct 2000000000 1000000000 0 1000000000)"         "--"      # reset/wrap
eq "cpu zero wall"      "$(cpu_pct 0 100 0 0)"                                  "--"
eq "cpu bad"            "$(cpu_pct '' 100 0 1000)"                              "--"

# ---- ram_fmt ----
eq "ram fmt"            "$(ram_fmt 1572864 1572864)"                            "1.5G/1.5G"
eq "ram absent"         "$(ram_fmt '' 1000)"                                    "--"

# ---- fmt_age (fixed now) ----
NOW=1000000
eq "age m/s"            "$(fmt_age $((NOW-252)) $NOW)"                          "4m12s"
eq "age h/m"            "$(fmt_age $((NOW-7380)) $NOW)"                         "2h3m"
eq "age future"         "$(fmt_age $((NOW+10)) $NOW)"                          "?"
eq "age null"           "$(fmt_age NULL $NOW)"                                 "?"

# ---- state_label ----
eq "state equal"        "$(state_label running running)"                       "running"
eq "state diff"         "$(state_label broken absent)"                         "broken/absent"

# ---- valid_uuid / is_vmid_shape ----
if valid_uuid "b71deae1-9298-de23-4a5b-0011deadbeef"; then eq "uuid ok" ok ok; else eq "uuid ok" bad ok; fi
if valid_uuid "not-a-uuid"; then eq "uuid bad" ok reject; else eq "uuid bad" reject reject; fi
if is_vmid_shape "drvps-vm-b71deae19298de23"; then eq "vmid ok" ok ok; else eq "vmid ok" bad ok; fi
if is_vmid_shape "kcgold-123"; then eq "vmid no" ok reject; else eq "vmid no" reject reject; fi

# ---- parse_list_uuid_name ----
LIST_FIX=' Id   Name                                UUID
--------------------------------------------------------------
 3    drvps-vm-b71deae19298de23           b71deae1-9298-de23-4a5b-0011deadbeef
 -    drvps-vm-15685c946b87396b           15685c94-6b87-396b-8c9d-0022cafef00d'
eq "parse list n1" "$(printf '%s\n' "$LIST_FIX" | parse_list_uuid_name | head -1)" "b71deae1-9298-de23-4a5b-0011deadbeef|drvps-vm-b71deae19298de23"
eq "parse list cnt" "$(printf '%s\n' "$LIST_FIX" | parse_list_uuid_name | wc -l | tr -d ' ')" "2"

# ---- parse_domstats ----
DS_FIX='Domain: drvps-vm-b71deae19298de23
  state.state=1
  cpu.time=123456789
  vcpu.current=4
  balloon.current=1572864
  balloon.maximum=1572864'
eq "parse domstats" "$(printf '%s\n' "$DS_FIX" | parse_domstats b71deae1-9298-de23-4a5b-0011deadbeef)" "1|123456789|4|1572864|1572864"
DS_MISS='Domain: x
  state.state=5'
eq "parse domstats miss" "$(printf '%s\n' "$DS_MISS" | parse_domstats anyuuid)" "5||||"

# ---- emit_inplace: flicker-free redraw (home + per-line clear-eol + trailing clear; NO full 2J) ----
ESC=$'\033'
FR="$(mktemp)"; printf 'aaa\nbb\nc\n' > "$FR"
EMIT="$(emit_inplace "$FR")"; rm -f "$FR"
eq "emit: home once"       "$(printf '%s' "$EMIT" | grep -oF "${ESC}[H"  | wc -l | tr -d ' ')" "1"
eq "emit: per-line clear"  "$(printf '%s' "$EMIT" | grep -oF "${ESC}[K"  | wc -l | tr -d ' ')" "3"
eq "emit: trailing clear"  "$(printf '%s' "$EMIT" | grep -oF "${ESC}[J"  | wc -l | tr -d ' ')" "1"
eq "emit: NO full 2J clear" "$(printf '%s' "$EMIT" | grep -oF "${ESC}[2J" | wc -l | tr -d ' ')" "0"

echo "-------------------------------------------"
echo "drvps-top unit: PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
