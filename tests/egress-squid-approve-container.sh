#!/usr/bin/env bash
# END-TO-END live workflow proof (PLAN Task 1.4/1.5/1.10 composed), HARDENED approve interface: a RUNNING
# squid starts mirror-only (a splice CONNECT is TERMINATED), a drvpsvc request is STAGED, the operator runs
# the approve tool (dry-run + YES -> atomic install + a FULL restart via the hook + a health check), and the
# SAME splice then TUNNELS end-to-end (no MITM). Real squid, disposable container. Invoke via podman
# --cap-add NET_ADMIN. Because the hardened CLI has NO runtime path seam, the
# operator step is driven at the PYTHON API level -- importing the tool and calling cmd_apply(Paths(
# test_root=T)); the Paths default restart hook is <T>/restart-hook. Production squid paths (/etc/squid/...)
# are used inside the container (which we own); the test-root holds the egress store + params + restart hook.
set -uo pipefail
CLI=/repo/tools/drvps_egress_model.py; APPROVE=/repo/bin/drvps-egress-approve
T="$(mktemp -d)"; fail=0
cleanup(){ [ -f "$T/sqpid" ] && kill "$(cat "$T/sqpid")" 2>/dev/null; }
trap cleanup EXIT
ok(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
CG=""; for c in /usr/lib64/squid/security_file_certgen /usr/lib/squid/security_file_certgen /usr/libexec/squid/security_file_certgen; do [ -x "$c" ] && { CG="$c"; break; }; done
[ -n "$CG" ] || { echo "SKIP: no security_file_certgen (not an ssl-bump squid)"; exit 0; }
SQUSER=squid; id squid >/dev/null 2>&1 || SQUSER=proxy   # fedora squid runs as 'squid', Debian/Ubuntu as 'proxy'

# origin CA + callback cert; squid bump CA at the PRODUCTION path
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=oca" -addext "basicConstraints=critical,CA:TRUE" -keyout "$T/oca.key" -out "$T/oca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=callback.crm.example" -addext "subjectAltName=DNS:callback.crm.example" -keyout "$T/srv.key" -out "$T/srv.csr" >/dev/null 2>&1
openssl x509 -req -in "$T/srv.csr" -CA "$T/oca.crt" -CAkey "$T/oca.key" -CAcreateserial -days 2 -extfile <(printf 'subjectAltName=DNS:callback.crm.example\n') -out "$T/srv.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=sca" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout "$T/sca.key" -out /etc/squid/drvps-ca.pem >/dev/null 2>&1
cat "$T/sca.key" >> /etc/squid/drvps-ca.pem; chgrp "$SQUSER" /etc/squid/drvps-ca.pem; chmod 0640 /etc/squid/drvps-ca.pem
install -d -o "$SQUSER" -g "$SQUSER" /var/lib/squid /var/spool/squid
ip addr add 192.0.2.50/32 dev lo 2>/dev/null
dnsmasq -k -p 53 --listen-address=127.0.0.1 --no-resolv --no-hosts --address=/callback.crm.example/192.0.2.50 --address=/deb.debian.org/192.0.2.50 >/dev/null 2>&1 &
openssl s_server -accept 192.0.2.50:443 -cert "$T/srv.crt" -key "$T/srv.key" -www -quiet >/dev/null 2>&1 &

# the restart hook the approve calls: copy the approve-written squid.conf into place, then FULL-restart squid
# (fresh ssl_db) -- ssl_bump changes need a real restart, not reconfigure. Health-checked by the approve.
cat > "$T/restart-hook" <<RST
#!/bin/bash
cp "$T/squid.conf" /etc/squid/squid.conf
{ echo "dns_nameservers 127.0.0.1"; echo "cache_effective_user $SQUSER"; } >> /etc/squid/squid.conf
[ -f "$T/sqpid" ] && kill "\$(cat "$T/sqpid")" 2>/dev/null; sleep 0.4
rm -rf /var/lib/ssl_db; $CG -c -s /var/lib/ssl_db -M 4MB >/dev/null 2>&1; chown -R "$SQUSER:$SQUSER" /var/lib/ssl_db /var/spool/squid
rm -f /run/squid.pid; squid -z >/dev/null 2>&1; rm -f /run/squid.pid; squid -N >/dev/null 2>&1 & echo \$! > "$T/sqpid"
for i in \$(seq 1 60); do bash -c "exec 3<>/dev/tcp/127.0.0.1/3128" 2>/dev/null && break; sleep 0.3; done
RST
chmod 0700 "$T/restart-hook"
ln -sf "$(command -v squid)" "$T/squid"                      # <test-root>/squid == the real squid (for parse)
printf '{"mirror_allowlist":["deb.debian.org"]}\n' > "$T/fleet.json"; chmod 0600 "$T/fleet.json"
printf '{"proxy_ip":"127.0.0.1","proxy_src":"127.0.0.0/8","cache_mb":128,"maxobj_mb":32,"certgen_path":"%s"}\n' "$CG" > "$T/params.json"
printf '{}\n' > "$T/hostfacts.json"

# start mirror-only via the same hook (it copies $T/squid.conf -> /etc/squid + restarts)
python3 "$CLI" render --fleet "$T/fleet.json" --params "$T/params.json" --host-facts "$T/hostfacts.json" > "$T/squid.conf"
"$T/restart-hook"

# 1) BEFORE approval: callback not allowlisted -> terminated
if curl -sf -o /dev/null --max-time 6 -x http://127.0.0.1:3128 --cacert "$T/oca.crt" https://callback.crm.example/ 2>/dev/null; then
  echo "FAIL  callback reachable BEFORE approval"; fail=1
else ok "before approval: callback CONNECT terminated" 'true'; fi

# 2) PROVISION the v2 store (as the root installer does) + STAGE a drvpsvc request (as the watcher would).
#    v2 dropped the owner sidecar: submit_request(pending_fd, owner_uid, op, host, port, ts). The ids map roots
#    BOTH principals at container-root so the hardened (seam-free) approve resolves its fixed identity WITHOUT a
#    `drvps` account inside the disposable container (production_ids' getpwnam is bypassed by an explicit ids=).
python3 - "$T" "$APPROVE" <<'PY'
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
T, approve = sys.argv[1], sys.argv[2]
sys.path.insert(0, "/repo/tools")
import drvps_egress_layout as L, drvps_egress_req as R
ldr = SourceFileLoader("approve", approve); spec = importlib.util.spec_from_loader("approve", ldr)
A = importlib.util.module_from_spec(spec); ldr.exec_module(A)
IDS = {L.ROOT: (0, 0), L.SVC: (0, 0)}
p = A.Paths(test_root=T, ids=IDS)
L.provision(p.base, IDS)
pf = R.open_ns(p.base, *L.NS_PENDING)
try:
    R.submit_request(pf, 1008, "add-splice", "callback.crm.example", 443, 1)
finally:
    os.close(pf)
PY

# 3) OPERATOR approves -> atomic install + restart hook + health check (import-level: no runtime CLI seam)
python3 - "$T" "$APPROVE" <<'PY' > "$T/approve.out" 2>&1
import importlib.util, io, sys
from importlib.machinery import SourceFileLoader
T, approve = sys.argv[1], sys.argv[2]
sys.path.insert(0, "/repo/tools")
import drvps_egress_layout as L
ldr = SourceFileLoader("approve", approve); spec = importlib.util.spec_from_loader("approve", ldr)
A = importlib.util.module_from_spec(spec); ldr.exec_module(A)
p = A.Paths(test_root=T, ids={L.ROOT: (0, 0), L.SVC: (0, 0)})   # same single-UID map as the stage above
sys.stdin = io.StringIO("YES\n")
sys.exit(A.cmd_apply(p, []))
PY
ok "approve applied (dry-run + YES + restart + healthy)" 'grep -q APPLIED "$T/approve.out"'

# 4) AFTER approval: the SAME splice TUNNELS the origin cert end-to-end; the squid CA does NOT validate it
if curl -sf -o /dev/null --max-time 8 -x http://127.0.0.1:3128 --cacert "$T/oca.crt" https://callback.crm.example/; then
  ok "after approval: splice TUNNELS the origin cert end-to-end" 'true'
else echo "FAIL  splice not reachable after approval"; sed 's/^/  approve| /' "$T/approve.out" | tail -4; fail=1; fi
if curl -sf -o /dev/null --max-time 8 -x http://127.0.0.1:3128 --cacert /etc/squid/drvps-ca.pem https://callback.crm.example/ 2>/dev/null; then
  echo "FAIL  post-approval tunnel was MITM'd"; fail=1
else ok "after approval: still no MITM (squid CA rejects)" 'true'; fi

echo "-------------------------------------------"
echo "egress approve end-to-end: $([ $fail = 0 ] && echo WORKFLOW-VERIFIED || echo FAILURES)"
exit $fail
