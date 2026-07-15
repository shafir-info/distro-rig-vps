#!/usr/bin/env bash
# LIVE squid parse gate (PLAN Task 1.8 capability + 1.10 release-gate, config-acceptance part): render
# a MIRROR-only and a SPLICE config via the ONE renderer, then run the REAL `squid -k parse` on them
# in FULL ISOLATION -- a temp CA + temp ssl_db/spool/coredump dirs, a private config, NO /etc write, NO
# root, NO shared-rig touch. Proves squid 7.x actually ACCEPTS every directive we emit
# (ssl::server_name --client-requested, dstdomain -n, conjunctive ssl_bump, on_unsupported_protocol,
# the internal-dst deny) -- which no config-text assertion can prove. A positive control (a bogus
# directive MUST fail) confirms the parser is really validating.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO/tools/drvps_egress_model.py"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0

command -v squid >/dev/null || { echo "SKIP: no squid binary"; exit 0; }
squid -v 2>&1 | grep -qi 'with-openssl' || { echo "SKIP: squid lacks ssl-bump (--with-openssl)"; exit 0; }
CERTGEN=""
for c in /usr/lib64/squid/security_file_certgen /usr/lib/squid/security_file_certgen /usr/libexec/squid/security_file_certgen; do
  [ -x "$c" ] && { CERTGEN="$c"; break; }
done
[ -n "$CERTGEN" ] || { echo "SKIP: no security_file_certgen"; exit 0; }

# a real ssl-bump CA (CA:TRUE) at the temp path
( umask 077; openssl req -new -newkey rsa:2048 -sha256 -days 2 -nodes -x509 \
    -subj "/CN=drvps-test-ca" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$T/ca.key" -out "$T/ca.crt" >/dev/null 2>&1 )
cat "$T/ca.crt" "$T/ca.key" > "$T/ca.pem"
mkdir -p "$T/spool" "$T/coredump"
"$CERTGEN" -c -s "$T/ssl_db" -M 4MB >/dev/null 2>&1 || true

# render, then RELOCATE the fixed /etc,/var paths to the temp sandbox (the renderer emits the real
# production paths by design; the test just points squid at a private copy so parse needs no root).
munge() { sed -e "s#/etc/squid/drvps-ca.pem#$T/ca.pem#" \
              -e "s#/var/lib/ssl_db#$T/ssl_db#" \
              -e "s#/var/spool/squid#$T/spool#g" \
              -e "s#coredump_dir .*#coredump_dir $T/coredump#" ; }

parse_ok() {  # <label> <conf>
  if squid -f "$2" -k parse >"$T/out" 2>&1; then echo "PASS  parse  $1"
  else echo "FAIL  parse  $1"; sed 's/^/    squid| /' "$T/out"; fail=1; fi
}
parse_reject() {  # <label> <conf>
  if squid -f "$2" -k parse >"$T/out" 2>&1; then echo "FAIL  control $1 (bogus config PARSED -- parser not validating)"; fail=1
  else echo "PASS  control $1 (bogus config rejected)"; fi
}

printf '{"mirror_allowlist":["deb.debian.org","archive.ubuntu.com"],"splice_allowlist":[{"host":"callback.crm.example","port":443}]}\n' > "$T/fleet_splice.json"
printf '{"mirror_allowlist":["deb.debian.org","archive.ubuntu.com"]}\n' > "$T/fleet_mirror.json"
printf '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":256,"maxobj_mb":64,"certgen_path":"%s"}\n' "$CERTGEN" > "$T/params.json"
printf '{"drvps_subnets":["10.123.0.0/24"],"host_ips":["192.0.2.10"],"fleet_public_ips":[],"block_cidrs":[]}\n' > "$T/hf.json"

python3 "$CLI" render --fleet "$T/fleet_mirror.json" --params "$T/params.json" --host-facts "$T/hf.json" | munge > "$T/mirror.conf"
python3 "$CLI" render --fleet "$T/fleet_splice.json" --params "$T/params.json" --host-facts "$T/hf.json" | munge > "$T/splice.conf"
parse_ok "mirror-only config"  "$T/mirror.conf"
parse_ok "SPLICE config"       "$T/splice.conf"
# positive control: inject a bogus directive
{ cat "$T/splice.conf"; echo "totally_not_a_squid_directive foo"; } > "$T/bogus.conf"
parse_reject "bogus directive" "$T/bogus.conf"

echo "-------------------------------------------"
echo "egress squid live-parse: $([ $fail = 0 ] && echo ALL-ACCEPTED || echo FAILURES)"
exit $fail
