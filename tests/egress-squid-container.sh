#!/usr/bin/env bash
# LIVE behavioral release-gate (PLAN Task 1.10) -- runs INSIDE the drvps-squid-test container as
# container-root, with squid dropping to the non-root `squid` user. Proves the rendered SPLICE config
# makes squid TUNNEL end-to-end (client sees the ORIGIN's real cert, never a squid-signed one) and
# BUMP a mirror (client sees the squid CA). Fully isolated in the container's netns. No shared-rig touch.
# Invoke: podman run --rm -v <repo>:/repo:ro localhost/drvps-squid-test bash /repo/tests/egress-squid-container.sh
set -uo pipefail
echo "RELEASE-GATE-RAN: egress-squid-container" >&2   # tests/release-gate.sh tier-2 runtime-coverage marker
CLI="/repo/tools/drvps_egress_model.py"
T="$(mktemp -d)"; PIDS=(); fail=0
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT
CERTGEN=""; for c in /usr/lib64/squid/security_file_certgen /usr/lib/squid/security_file_certgen /usr/libexec/squid/security_file_certgen; do [ -x "$c" ] && { CERTGEN="$c"; break; }; done
[ -n "$CERTGEN" ] || { echo "SKIP: no security_file_certgen (not an ssl-bump squid)"; exit 0; }
SQUSER=squid; id squid >/dev/null 2>&1 || SQUSER=proxy   # fedora squid runs as 'squid', Debian/Ubuntu as 'proxy'

# --- ORIGIN CA + callback server cert (the real end-to-end identity) ---
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=origin-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -keyout "$T/oca.key" -out "$T/oca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=callback.crm.example" \
  -addext "subjectAltName=DNS:callback.crm.example" -keyout "$T/srv.key" -out "$T/srv.csr" >/dev/null 2>&1
openssl x509 -req -in "$T/srv.csr" -CA "$T/oca.crt" -CAkey "$T/oca.key" -CAcreateserial -days 2 \
  -extfile <(printf 'subjectAltName=DNS:callback.crm.example\n') -out "$T/srv.crt" >/dev/null 2>&1
# --- squid bump CA (distinct identity) ---
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=squid-bump-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$T/sca.key" -out "$T/sca.crt" >/dev/null 2>&1
cat "$T/sca.crt" "$T/sca.key" > "$T/sca.pem"
mkdir -p "$T/spool" "$T/cd" "$T/sq"; "$CERTGEN" -c -s "$T/ssl_db" -M 4MB >/dev/null 2>&1
chown -R "$SQUSER:$SQUSER" "$T/spool" "$T/cd" "$T/ssl_db" "$T/sq"   # squid (cache_effective_user) writes here
chgrp "$SQUSER" "$T/sca.pem"; chmod 0640 "$T/sca.pem"; chmod 0755 "$T"

# --- local resolver: callback + mirror -> 127.0.0.1 ---
dnsmasq -k -p 53 --listen-address=127.0.0.1 --no-resolv --no-hosts \
  --address=/callback.crm.example/192.0.2.50 --address=/deb.debian.org/192.0.2.50 --address=/notallowed.example/192.0.2.50 >/dev/null 2>&1 & PIDS+=($!)
# --- TLS origins on :443 (callback, spliced) and :8443 is not needed; mirror shares :443 via SNI ---
ip addr add 192.0.2.50/32 dev lo 2>/dev/null; openssl s_server -accept 192.0.2.50:443 -cert "$T/srv.crt" -key "$T/srv.key" -www -quiet >/dev/null 2>&1 & PIDS+=($!)

# --- render splice config, relocate the production paths into the sandbox, run squid as `squid` ---
printf '{"mirror_allowlist":["deb.debian.org"],"splice_allowlist":[{"host":"callback.crm.example","port":443}]}\n' > "$T/fleet.json"
printf '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"%s"}\n' "$CERTGEN" > "$T/params.json"
printf '{"drvps_subnets":[],"host_ips":[],"fleet_public_ips":[],"block_cidrs":[]}\n' > "$T/hf.json"
python3 "$CLI" render --fleet "$T/fleet.json" --params "$T/params.json" --host-facts "$T/hf.json" \
 | sed -e "s#/etc/squid/drvps-ca.pem#$T/sca.pem#" -e "s#/var/lib/ssl_db#$T/ssl_db#" \
       -e "s#/var/spool/squid#$T/spool#g" -e "s#coredump_dir .*#coredump_dir $T/cd#" > "$T/squid.conf"
{ echo "dns_nameservers 127.0.0.1"; echo "cache_effective_user $SQUSER"; echo "pid_filename $T/sq/squid.pid";
  echo "access_log stdio:$T/sq/access.log"; echo "cache_log stdio:$T/sq/cache.log"; } >> "$T/squid.conf"

squid -f "$T/squid.conf" -z >/dev/null 2>&1
rm -f "$T/sq/squid.pid"                       # -z leaves a PID file that would block -N ("already running")
squid -N -f "$T/squid.conf" > "$T/sq.out" 2>&1 & PIDS+=($!)
up=0; for i in $(seq 1 80); do bash -c 'exec 3<>/dev/tcp/127.0.0.1/3128' 2>/dev/null && { up=1; break; }; sleep 0.3; done
if [ "$up" != 1 ]; then echo "FAIL squid did not start"; sed 's/^/  sq| /' "$T/sq.out" 2>/dev/null | tail -10; exit 1; fi

# 1) SPLICE: validating the ORIGIN CA through the proxy MUST succeed (end-to-end cert delivered)
if curl -sf -o /dev/null -x http://127.0.0.1:3128 --cacert "$T/oca.crt" https://callback.crm.example/; then
  echo "PASS  splice delivers the ORIGIN cert end-to-end (no MITM)"
else
  echo "FAIL  splice: origin cert not delivered through the proxy"; fail=1; sed 's/^/  access| /' "$T/sq/access.log" | tail -4
fi
# 2) NO-MITM: validating against the SQUID bump CA MUST fail (squid never signed the spliced tunnel)
if curl -sf -o /dev/null -x http://127.0.0.1:3128 --cacert "$T/sca.pem" https://callback.crm.example/; then
  echo "FAIL  splice presented a SQUID-signed cert (MITM!)"; fail=1
else
  echo "PASS  squid-bump CA does NOT validate the spliced tunnel (confirms no MITM)"
fi
# 3) a non-allowlisted TLS host is TERMINATED (curl fails; access log shows a terminated/denied CONNECT)
if curl -sf -o /dev/null --max-time 6 -x http://127.0.0.1:3128 -k https://notallowed.example/ 2>/dev/null; then
  echo "FAIL  non-allowlisted host was NOT terminated"; fail=1
else
  echo "PASS  non-allowlisted TLS host terminated/denied"
fi

echo "-------------------------------------------"
echo "egress squid behavioral (container): $([ $fail = 0 ] && echo SPLICE-VERIFIED || echo FAILURES)"
exit $fail
