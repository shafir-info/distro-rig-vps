#!/usr/bin/env bash
# LIVE behavioral release-gate (PLAN Task 1.10): run a REAL squid with a rendered SPLICE config inside
# an isolated user+net namespace (run me via: unshare -rn bash tests/egress-squid-behavioral.sh) and
# prove the SPLICE actually tunnels END-TO-END -- the client sees the ORIGIN's real cert, NOT a
# squid-signed one (no MITM). Fully isolated: private loopback, a local dnsmasq + TLS origin + squid,
# temp everything, no /etc write, no shared-rig touch. Origin+squid bind low ports as root-in-netns.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO/tools/drvps_egress_model.py"
T="$(mktemp -d)"; PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
fail=0
say(){ echo "$@"; }

command -v squid >/dev/null && command -v dnsmasq >/dev/null && command -v curl >/dev/null || { echo "SKIP: need squid+dnsmasq+curl"; exit 0; }
ip link set lo up 2>/dev/null || { echo "SKIP: cannot bring up lo (not in a net namespace? run via 'unshare -rn')"; exit 0; }
CERTGEN=""; for c in /usr/lib64/squid/security_file_certgen /usr/lib/squid/security_file_certgen /usr/libexec/squid/security_file_certgen; do [ -x "$c" ] && { CERTGEN="$c"; break; }; done
[ -n "$CERTGEN" ] || { echo "SKIP: no security_file_certgen"; exit 0; }

# --- ORIGIN CA + server cert for callback.crm.example (the real end-to-end cert) ---
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=origin-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -keyout "$T/oca.key" -out "$T/oca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=callback.crm.example" \
  -addext "subjectAltName=DNS:callback.crm.example" -keyout "$T/srv.key" -out "$T/srv.csr" >/dev/null 2>&1
openssl x509 -req -in "$T/srv.csr" -CA "$T/oca.crt" -CAkey "$T/oca.key" -CAcreateserial -days 2 \
  -extfile <(printf 'subjectAltName=DNS:callback.crm.example\n') -out "$T/srv.crt" >/dev/null 2>&1

# --- squid bump CA (distinct) ---
( umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=squid-bump-ca" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$T/sca.key" -out "$T/sca.crt" >/dev/null 2>&1 )
cat "$T/sca.crt" "$T/sca.key" > "$T/sca.pem"; mkdir -p "$T/spool" "$T/cd"; "$CERTGEN" -c -s "$T/ssl_db" -M 4MB >/dev/null 2>&1

# --- dnsmasq: callback.crm.example -> 127.0.0.1 ---
dnsmasq -k -p 53 --listen-address=127.0.0.1 --no-resolv --no-hosts \
  --address=/callback.crm.example/127.0.0.1 --address=/deb.debian.org/127.0.0.1 >/dev/null 2>&1 & PIDS+=($!)
# --- TLS origin on :443 presenting the ORIGIN cert ---
openssl s_server -accept 443 -cert "$T/srv.crt" -key "$T/srv.key" -www -quiet >/dev/null 2>&1 & PIDS+=($!)

# --- render splice config, relocate paths to the sandbox + point squid at the local resolver ---
printf '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"callback.crm.example","port":443}]}\n' > "$T/fleet.json"
printf '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"%s"}\n' "$CERTGEN" > "$T/params.json"
printf '{"drvps_subnets":[],"host_ips":[],"fleet_public_ips":[],"block_cidrs":[]}\n' > "$T/hf.json"
python3 "$CLI" render --fleet "$T/fleet.json" --params "$T/params.json" --host-facts "$T/hf.json" \
 | sed -e "s#/etc/squid/drvps-ca.pem#$T/sca.pem#" -e "s#/var/lib/ssl_db#$T/ssl_db#" \
       -e "s#/var/spool/squid#$T/spool#g" -e "s#coredump_dir .*#coredump_dir $T/cd#" > "$T/squid.conf"
{ echo "dns_nameservers 127.0.0.1"; echo "pid_filename $T/squid.pid"; echo "access_log stdio:$T/access.log";
  echo "cache_log stdio:$T/cache.log"; echo "cache_effective_user $(id -un)"; } >> "$T/squid.conf"

squid -N -f "$T/squid.conf" >/dev/null 2>&1 & PIDS+=($!)
# wait for the listener + origin
for i in $(seq 1 40); do
  { exec 3<>/dev/tcp/127.0.0.1/3128; } 2>/dev/null && { exec 3>&-; break; }
  sleep 0.25
done

# 1) SPLICE proof: through the proxy, the client validating the ORIGIN CA must SUCCEED (end-to-end cert)
if curl -s -o /dev/null -x http://127.0.0.1:3128 --cacert "$T/oca.crt" https://callback.crm.example/ ; then
  say "PASS  splice tunnels the ORIGIN cert (end-to-end, no MITM)"
else
  say "FAIL  splice: client could not validate the origin cert through the proxy"; fail=1
  sed 's/^/    access| /' "$T/access.log" 2>/dev/null | tail -5
fi
# 2) NO-MITM proof: validating against the SQUID bump CA must FAIL (squid never signed this tunnel)
if curl -s -o /dev/null -x http://127.0.0.1:3128 --cacert "$T/sca.pem" https://callback.crm.example/ ; then
  say "FAIL  splice presented a SQUID-signed cert (MITM!) -- not spliced"; fail=1
else
  say "PASS  squid-bump CA does NOT validate the spliced tunnel (confirms no MITM)"
fi

echo "-------------------------------------------"
echo "egress squid behavioral: $([ $fail = 0 ] && echo SPLICE-VERIFIED || echo FAILURES)"
exit $fail
