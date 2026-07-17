#!/usr/bin/env python3
"""drvps_rigctl.py -- Phase-2 watcher: the privilege gateway (runs as the unprivileged drvps).

Two parts (see CONCEPT.md, agent control loop):
  (a) decide(filename, raw, gate_fn, caps) -- PURE, exhaustively unit-tested: parse, schema-
      validate, reqid charset + filename==reqid, size caps, create-narrow, gate vm verbs.
  (b) a thin event loop: snapshot-claim (O_NOFOLLOW|O_NONBLOCK, fstat regular/nlink/size, read
      once), per-op flock, run the verb as a child in its own process group under a hard
      timeout with bounded output, write the result O_EXCL (no clobber on replay), structured
      audit (push/pull CONTENT excluded), and destroy/recreate preemption of an in-flight exec.

The agent's `cmd` is unrestricted (safe by guest confinement); EVERY other field is host-
touching and validated here. ASCII only.
"""
import os, sys, json, base64, subprocess, signal, time, stat, re, fcntl, tempfile, datetime, shutil, hashlib
import drvps_common   # shared REQID_RE + spool caps (one source of truth with the accepter; H-3)


def _cap_int(name, default, lo, hi):
    # convergence r2/r3: parse a numeric env cap DEFENSIVELY -- a malformed (hand-edited) value must NOT raise
    # ValueError and crash-loop the Restart=always watcher. The parse lives in drvps_common (the accepter's
    # spool caps use the same one) so accept/clamp behavior cannot drift between the two daemons; this
    # wrapper keeps the existing name at the 8 callsites.
    return drvps_common.cap_int(name, default, lo, hi)


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

REQID_RE = drvps_common.REQID_RE                 # shared with the accepter (one source of truth; H-3)
SAFE_NAME = re.compile(r'^[A-Za-z0-9_.-]{1,64}\Z')
# snapshot id-or-name: ids are `drvps-snap-v1-<vsize>-<64hex>` (~90 chars) and NAMES may contain ':' (see
# dr_vps_snapshot_rename's [A-Za-z0-9._:-]). The 64-char SAFE_NAME rejected the very ids `rigctl snapshot`
# returns. Wider charset + length, still no shell/path metacharacters (it becomes an argv element).
SAFE_SNAP = re.compile(r'^[A-Za-z0-9_.:-]{1,128}\Z')
JOB_RE = re.compile(r'^[0-9a-f]{16,64}\Z')               # async job id: opaque lowercase hex (no path/shell metachar)
TMP_RE = re.compile(r'^\.[A-Za-z0-9_-]{1,128}\.tmp\Z')   # the ACCEPTER's in-progress '.{reqid}.tmp' (preserve briefly)
# egress splice host: an argv-safety fence only (no leading '-', bounded length, no path/shell metachar). The
# AUTHORITATIVE FQDN validation (labels, IDN, wildcard/ip/url rejection) is canon_fqdn in drvps_egress_member.
EGRESS_HOST_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z')

# wait is GUESTEXEC, not lifecycle: it reaches the guest over SSH, so it must pass the full
# closed-shape + fresh-egress proof (a domain that passes identity but fails guestexec -- extra NIC,
# hostdev, host-path backend, stale egress -- must NOT be SSH-reachable via wait).
VM_VERBS = {"wait": "guestexec", "exec": "guestexec", "push": "guestexec", "pull": "guestexec",
            # exec-detach launches a guest command (over SSH) -> guestexec, like exec.
            "exec-detach": "guestexec",
            "recreate": "lifecycle", "destroy": "lifecycle", "status": "lifecycle",
            # inspect: read-only host-side facts; gates the LIVE virsh reads INTERNALLY (conditional, like
            # destroy) so it stays usable on broken/undefined VMs -> not pre-gated here (see below).
            "inspect": "lifecycle",
            # console-dump returns guest SERIAL OUTPUT to the agent (a guest->host data channel) -> guestexec
            "console-dump": "guestexec",
            # snapshot shuts the VM down + flattens host-side -> a lifecycle op (identity gate, NOT guestexec).
            "snapshot": "lifecycle"}
# snap-ls/snap-show/snap-rm operate on a SNAPSHOT artifact (or nothing), not a VM -> no per-VM gate; the
# daemon runs `dr-vps snap-*` as drvps and dr_vps_snapshot_rm is itself refcount-gated (agent owns snapshots).
# exec-status/exec-output/exec-errors are JOB-keyed (not vm-keyed): the daemon derives the vm from the host job
# meta and gates guestexec internally. They are OWNER-SCOPED reads (a client cannot poll/read another owner's job).
GLOBAL_VERBS = {"create", "list", "distros", "snap-ls", "snap-show", "snap-rm", "use", "version", "exec-status", "exec-output", "exec-errors",
                # egress: drvpsvc splice-destination register/query. No vm; owner-scoped (below); the store
                # logic (admit + caps + idempotency) is dr_vps_egress.sh -> drvps_egress_member.py.
                "egress"}
PREEMPT_VERBS = {"destroy", "recreate"}
# Lifecycle MUTATORS get the generous lifecycle_timeout (boot/flatten+boot can take minutes), NOT the tighter
# exec_timeout -- killing one mid-flight can orphan a domain / leave partial storage. `use` (clone-from-snap)
# flattens a multi-GB snapshot base then boots, so it belongs here exactly like `create` (owner-scoping).
LIFECYCLE = ("create", "use", "recreate", "destroy", "snapshot", "restore", "rollback")
# S4: verbs that may carry an OPTIONAL client idempotency key (mutators whose duplicate execution is
# costly/destructive). Reads never need one; exec/push/pull retries are reconciled in-guest (their
# effects aren't journalable host-side), so idem on them is an explicit reject, not a false promise.
IDEM_VERBS = {"create", "use", "recreate", "destroy", "snapshot", "snap-rm"}
PREEMPT_SCAN_S = 2.0                       # rate-limit the in-flight preempt rescan (anti-amplification)
MAX_PENDING = drvps_common.max_pending()         # spool flood cap (shared with the accepter; H-3)


def _reject(reqid, reason):
    return {"action": "reject", "reqid": reqid, "reason": reason}


def _intcap(v, lo, hi):
    # type-strict: reject bool (an int subclass -> int(True)==1) and non-ints (int("3")==3, int("0x10",...))
    # so a hand-planted spool field cannot pass LOOSER validation than owner_uid. Only a real JSON int counts.
    if not isinstance(v, int) or isinstance(v, bool):
        return None
    return v if lo <= v <= hi else None


def _okstr(s, maxlen):
    # argv-bound free-form string: must be a str, no NUL (Popen raises ValueError on a NUL),
    # and length-capped. cmd is unrestricted in CONTENT (safe by confinement) but not in form.
    return isinstance(s, str) and "\x00" not in s and 0 < len(s) <= maxlen


def decide(filename, raw, gate_fn, caps):
    """Pure decision. gate_fn(mode, vm) -> bool is injected (real gate in prod, stub in tests)."""
    if len(raw) > caps["req_max"]:
        return _reject(None, "oversize request")
    try:
        req = json.loads(raw)
    except Exception:
        return _reject(None, "bad json")
    if not isinstance(req, dict):
        return _reject(None, "request not an object")
    reqid = req.get("reqid")
    if not isinstance(reqid, str) or not REQID_RE.match(reqid):
        return _reject(None, "bad reqid")
    base = filename[:-5] if filename.endswith(".json") else filename
    if base != reqid:
        return _reject(reqid, "filename != reqid")
    op = req.get("op")
    if not isinstance(op, str) or (op not in VM_VERBS and op not in GLOBAL_VERBS):
        return _reject(reqid, "unknown verb")

    # OWNER SCOPING (snapshot verbs): the ingress accepter stamps owner_uid (from SO_PEERCRED) into the
    # request -- TRUSTED + UNFORGEABLE (the client cannot set it; the accepter overwrites any client value).
    # Threaded to dr-vps as --owner so list/show/rm/snapshot/use are scoped to the caller's OWN snapshots.
    # `use` (clone-from-snapshot) belongs here too: it RESOLVES a snapshot as the clone base, so running it
    # unscoped would let a caller boot a VM off ANOTHER owner's snapshot -- the exact confidentiality breach
    # the fail-closed rule prevents for the read verbs.
    OWNER_SCOPED_VERBS = ("snap-ls", "snap-show", "snap-rm", "snapshot", "use",
                          "exec-detach", "exec-status", "exec-output", "exec-errors",   # agent jobs are owner-tagged + owner-only
                          # S1a: VM ownership. create stamps the new row; the mutations/guest-reads below
                          # are refused (below) unless owner-verified. Reads (list/status/inspect/wait/
                          # distros/version) stay GLOBAL -- ids/names are non-secrets; payloads+lifecycle are.
                          "create", "destroy", "recreate", "exec", "push", "pull", "console-dump",
                          # egress: a member registers/queries only their OWN splice requests -- an unstamped
                          # egress request must NOT run unscoped (it would submit/read as uid 0 admin).
                          "egress")
    owner = req.get("owner_uid")
    owner_args = []
    if owner is not None:
        # accept ONLY a real, non-negative INTEGER uid. The accepter stamps owner_uid as the kernel SO_PEERCRED
        # uid (a JSON int), so anything else -- a bool (int subclass), a negative, or a STRING (incl. a
        # leading-zero "04001" or a unicode-digit string that str.isdigit() would bless, both of which would
        # mis-scope vs the canonical "4001") -- can only be a hand-planted drvps-only spool file: refuse it
        if not isinstance(owner, int) or isinstance(owner, bool) or owner < 0:
            return _reject(reqid, "bad owner_uid")
        owner_args = ["--owner", str(owner)]
    elif op in OWNER_SCOPED_VERBS:
        # FAIL CLOSED: an owner-scoped verb reaching the watcher WITHOUT the
        # ingress stamp must NOT run unscoped (admin). The accepter stamps EVERY socket request; an unstamped
        # one can only be a hand-planted request in the drvps-only spool or an accepter regression -- refuse it
        # rather than silently grant admin scope. (The operator's admin path is direct `dr-vps`, not the spool.)
        return _reject(reqid, "owner-scoped verb missing owner_uid")

    # S4 idempotency key: OPTIONAL, mutators only (explicit reject elsewhere -- silently ignoring it
    # would let a client BELIEVE a retry is safe when it is not). The key never reaches an argv and is
    # never a bare path segment (journal filenames append ".json"), but it is charset-fenced anyway.
    # req_sha binds the key to the request BODY minus the per-attempt reqid: a retry is only a retry
    # if it resends the SAME request -- same key + different body is key misuse, refused loop-side
    # (never silently answered with another request's recorded result). owner is guaranteed non-None
    # here: every IDEM_VERB is owner-scoped, so an unstamped one already failed closed above.
    idem = req.get("idem")
    idem_fields = {}
    if idem is not None:
        if op not in IDEM_VERBS:
            return _reject(reqid, "idem not supported for verb '%s'" % op)
        if not isinstance(idem, str) or not SAFE_NAME.match(idem):
            return _reject(reqid, "bad idem key")
        body = json.dumps({k: v for k, v in req.items() if k != "reqid"},
                          sort_keys=True, separators=(",", ":"))
        idem_fields = {"idem": idem, "owner_uid": owner,
                       "req_sha": hashlib.sha256(body.encode()).hexdigest()}

    if op == "create":
        name, distro = req.get("name"), req.get("distro")
        for val in (name, distro):
            if not isinstance(val, str) or not SAFE_NAME.match(val) or val.startswith("-"):
                return _reject(reqid, "bad name/distro")
        # DR-6 per-run network modes -- Stage 0 protocol contract. net_mode defaults to 'shared' (today's simnet
        # path, byte-for-byte unchanged: still --net caps["net"]). isolated/routed are ACCEPTED by the protocol
        # but NOT YET WIRED (net allocation + per-group bridge land in Stage 2) -> a CLEAN refusal, never a
        # silent fall-through to the shared net. net_group is a sanitized label (validated here so the contract
        # is set) but only consumed by the non-shared path.
        net_mode = req.get("net_mode", "shared")
        if not isinstance(net_mode, str) or net_mode not in ("shared", "isolated", "routed"):
            return _reject(reqid, "bad net_mode")
        net_group = req.get("net_group")
        if net_group is not None and (not isinstance(net_group, str) or not SAFE_NAME.match(net_group)
                                      or net_group.startswith("-")):
            return _reject(reqid, "bad net_group")
        if net_mode != "shared":
            return _reject(reqid, "net_mode '%s' not yet implemented (DR-6 Stage 2+)" % net_mode)
        argv = [caps["bin"], "create", name, distro, "--net", caps["net"],
                "--ssh-key", caps["pubkey"], "--project", "agent"]
        for k, lo, hi in (("ttl", 1, 8760), ("mem", 256, caps["mem_max"]), ("cpus", 1, caps["cpu_max"])):
            if k in req:
                n = _intcap(req[k], lo, hi)
                if n is None:
                    return _reject(reqid, "bad %s" % k)
                argv += ["--%s" % k, str(n)]
        argv += owner_args   # S1a: stamp the new VM row with the caller's owner_uid
        klass = req.get("class", "throwaway")   # S1b: default throwaway; membership+quota enforced dr-vps-side
        if klass not in ("throwaway", "service"):
            return _reject(reqid, "bad class")
        argv += ["--class", klass]
        return dict({"action": "run", "reqid": reqid, "op": op, "vm": None, "argv": argv,
                     "preempt": False}, **idem_fields)

    if op == "list":
        return {"action": "run", "reqid": reqid, "op": op, "vm": None,
                "argv": [caps["bin"], "list"], "preempt": False}

    if op == "version":
        # Ungated pure read (like list): no vm, no owner scoping -- reports which build the daemon runs.
        return {"action": "run", "reqid": reqid, "op": op, "vm": None,
                "argv": [caps["bin"], "version"], "preempt": False}

    if op == "distros":
        # Ungated pure read (like list/version): lists the registered GOLDEN library (id + distro +
        # built_at) so the agent can discover valid `create <distro>` values WITHOUT the golden store
        # being agent-readable on disk (state dir is drvps:qemu 0750). Metadata ONLY -- `dr-vps distros`
        # is dr_vps_image_ls, a kind='golden' SELECT: no file paths, no secrets, no mutation, and NOT
        # owner-scoped (goldens are global, already usable by every agent via create). It exposes strictly
        # LESS than the agent can already act on, so no confidentiality boundary is crossed.
        return {"action": "run", "reqid": reqid, "op": op, "vm": None,
                "argv": [caps["bin"], "distros"], "preempt": False}

    if op == "egress":
        # drvpsvc member self-service register/query of a splice destination. owner_args is guaranteed
        # non-empty (egress is OWNER_SCOPED, so an unstamped request already failed closed above), so
        # `dr-vps egress` runs owner-scoped. This branch only SHAPES + charset-fences the argv; the admit
        # gate + caps + idempotency + already-active/absent all live dr-vps-side (dr_vps_egress.sh ->
        # drvps_egress_member.py). No idem journal (member submit is natively idempotent per tuple).
        sub = req.get("egress_op")
        if sub not in ("add-splice", "remove-splice", "list", "status"):
            return _reject(reqid, "bad egress_op")
        argv = [caps["bin"], "egress", sub]
        if sub in ("add-splice", "remove-splice"):
            host = req.get("host")
            if not isinstance(host, str) or not EGRESS_HOST_RE.match(host):
                return _reject(reqid, "bad host")
            p = _intcap(req.get("port", 443), 1, 65535)
            if p is None:
                return _reject(reqid, "bad port")
            argv += [host, str(p)]
        elif sub == "status":
            # status is addressed by the ATTEMPT's reqid (a 32-hex nonce), NOT a host, so a remove
            # outcome is deliverable and the reason is returned.
            qreqid = req.get("qreqid")
            if not isinstance(qreqid, str) or not REQID_RE.match(qreqid):
                return _reject(reqid, "bad qreqid")
            argv += [qreqid]
        argv += owner_args
        return {"action": "run", "reqid": reqid, "op": op, "vm": None, "argv": argv, "preempt": False}

    if op == "snap-ls":
        return {"action": "run", "reqid": reqid, "op": op, "vm": None,
                "argv": [caps["bin"], "snap-ls"] + owner_args, "preempt": False}
    if op in ("snap-show", "snap-rm"):
        snap = req.get("snap")
        if not isinstance(snap, str) or not SAFE_SNAP.match(snap) or snap.startswith("-"):
            return _reject(reqid, "bad snap id")
        return dict({"action": "run", "reqid": reqid, "op": op, "vm": None,
                     "argv": [caps["bin"], op, snap] + owner_args, "preempt": False},
                    **idem_fields)   # S4: only snap-rm can carry idem (snap-show already rejected above)

    if op in ("exec-status", "exec-output", "exec-errors"):
        # JOB-keyed owner-scoped read: the daemon derives the vm from host job meta + gates guestexec internally.
        job = req.get("job")
        if not isinstance(job, str) or not JOB_RE.match(job):
            return _reject(reqid, "bad job id")
        return {"action": "run", "reqid": reqid, "op": op, "vm": None,
                "argv": [caps["bin"], op, job] + owner_args, "preempt": False}

    if op == "use":
        # Snapshot-enabled agent path: clone a NEW VM from the caller's OWN snapshot. owner_args is guaranteed
        # non-empty here (use is in OWNER_SCOPED_VERBS, so an unstamped request already failed closed above).
        # The envelope mirrors `create` EXACTLY -- project agent, rig net, agent pubkey, same ttl/mem/cpus caps.
        # --allow-secret-bearing is threaded ONLY by the explicitly-acked S6 service-class restore branch
        # below (authoritative gate stays dr-vps-side: DR_VPS_ALLOW_SECRET_RESTORE + 1:1 refcount); the
        # DEFAULT path never threads it, so a plain clone can never carry a secret-bearing base (machine-id
        # collisions; host keys regenerate per new instance-id regardless -- see CONCEPT-S6). The hardened
        # dr_vps_snapshot_use then owner-scopes the resolve and re-verifies ownership UNDER the per-content
        # lock (TOCTOU), so this branch only shapes the argv.
        name, snap = req.get("name"), req.get("snap")
        if not isinstance(name, str) or not SAFE_NAME.match(name) or name.startswith("-"):
            return _reject(reqid, "bad name")
        if not isinstance(snap, str) or not SAFE_SNAP.match(snap) or snap.startswith("-"):
            return _reject(reqid, "bad snap id")
        argv = [caps["bin"], "use", name, "--from-snap", snap] + owner_args + [
                "--net", caps["net"], "--ssh-key", caps["pubkey"], "--project", "agent"]
        for k, lo, hi in (("ttl", 1, 8760), ("mem", 256, caps["mem_max"]), ("cpus", 1, caps["cpu_max"])):
            if k in req:
                n = _intcap(req[k], lo, hi)
                if n is None:
                    return _reject(reqid, "bad %s" % k)
                argv += ["--%s" % k, str(n)]
        klass = req.get("class", "throwaway")   # S1b: a clone can be service-class too (membership+quota dr-vps-side)
        if klass not in ("throwaway", "service"):
            return _reject(reqid, "bad class")
        argv += ["--class", klass]
        # S6 (GATED): thread --allow-secret-bearing ONLY for a service-class restore with an explicit
        # restore_secrets ack. This just opens the argv door; the AUTHORITATIVE gate (the operator policy
        # flag DR_VPS_ALLOW_SECRET_RESTORE + the 1:1 refcount) is in dr_vps_snapshot_use. Never threaded
        # otherwise -- the default remains "the agent can never clone a secret-bearing base".
        if req.get("restore_secrets") is True:
            if klass != "service":
                return _reject(reqid, "restore_secrets requires class=service")
            argv += ["--allow-secret-bearing"]
        return dict({"action": "run", "reqid": reqid, "op": op, "vm": None, "argv": argv,
                     "preempt": False}, **idem_fields)

    vm = req.get("vm")
    if not isinstance(vm, str) or not SAFE_NAME.match(vm) or vm.startswith("-"):
        return _reject(reqid, "bad vm id")
    # destroy and status are NOT pre-gated by the watcher. destroy: `dr-vps destroy` is the
    # authoritative gate (store-row required + dominfo-conditional identity gate + path-fence) AND can
    # clear a no-domain broken VM, which the raw lifecycle gate would wrongly reject -- wedging the
    # AGENT's reset/destroy path. status: `dr-vps status` is an ungated pure store READ (no
    # virsh/ssh/scp), and the raw lifecycle gate (live domain required) would refuse it exactly on
    # broken/undefined VMs -- the state the agent most needs to inspect (same wedge class as destroy).
    # The vm-id charset is still validated above, so nothing unsafe reaches either verb.
    # inspect joins the exception: like status it must work on broken/undefined VMs (the state you most need
    # to diagnose); dr_vps_domain_inspect gates the LIVE virsh reads internally, so a foreign same-name domain
    # still cannot leak its facts. Its store-row read is as safe as status's.
    if op not in ("destroy", "status", "inspect") and not gate_fn(VM_VERBS[op], vm):
        # The gate is the only DYNAMIC pre-check -- its CURRENT verdict must not
        # mask a retried idem mutator's recorded answer (e.g. the first recreate broke the VM mid-
        # flight, so the retry's gate refuses; "rejected" would falsely tell the client nothing ever
        # ran). Carry the idem fields on the reject so the loop consults the journal first; a
        # genuinely FRESH key still gets this rejection verbatim.
        return dict(_reject(reqid, "gate refused"), op=op, vm=vm, **idem_fields)

    out = dict({"action": "run", "reqid": reqid, "op": op, "vm": vm,
                "preempt": op in PREEMPT_VERBS}, **idem_fields)   # S4: recreate/destroy/snapshot may carry idem
    if owner is not None:
        out["owner_uid"] = owner   # F1: carry the owner on EVERY VM-verb action (owner-aware preempt authz)
    if op == "exec":
        cmd = req.get("cmd")
        if not _okstr(cmd, 65536):
            return _reject(reqid, "bad cmd")
        out["argv"] = [caps["bin"], "exec", vm, cmd] + owner_args   # S1a: owner-scoped
    elif op == "exec-detach":
        cmd = req.get("cmd")
        if not _okstr(cmd, 65536):
            return _reject(reqid, "bad cmd")
        out["argv"] = [caps["bin"], "exec-detach", vm, cmd] + owner_args   # owner-stamped -> the job is owner-tagged
    elif op == "push":
        remote, b64 = req.get("remote"), req.get("content_b64")
        if not _okstr(remote, 4096) or not isinstance(b64, str):
            return _reject(reqid, "bad push args")
        try:
            data = base64.b64decode(b64, validate=True)
        except Exception:
            return _reject(reqid, "bad base64")
        if len(data) > caps["transfer_max"]:
            return _reject(reqid, "push too large")
        out["argv"] = [caps["bin"], "push", vm, "<TMP>", remote] + owner_args   # S1a: owner-scoped
        out["push_bytes"] = data
    elif op == "pull":
        remote = req.get("remote")
        if not _okstr(remote, 4096):
            return _reject(reqid, "bad remote")
        out["argv"] = [caps["bin"], "pull", vm, remote] + owner_args   # S1a: owner-scoped
    elif op == "console-dump":
        out["argv"] = [caps["bin"], "console-dump", vm, str(caps["console_max"])] + owner_args   # S1a: owner-scoped
    elif op == "snapshot":
        argv = [caps["bin"], "snapshot", vm]
        if req.get("keep_secrets") is True:
            argv.append("--keep-secrets")
        notes = req.get("notes")
        if notes is not None:
            if not _okstr(notes, 4096):
                return _reject(reqid, "bad notes")
            argv += ["--notes", notes]
        out["argv"] = argv + owner_args   # stamp the client's owner_uid onto the new snapshot
    else:  # wait / recreate / destroy / status
        out["argv"] = [caps["bin"], op, vm]
        if op == "wait":
            out["argv"].append(str(caps.get("wait_timeout", 300)))
        elif op in ("destroy", "recreate"):        # S1a: owner-scoped mutations (wait/status stay global reads)
            out["argv"] += owner_args
    return out


# ---------------------- loop primitives (the thin shell) -----------------------------------

def claim(reqdir, name, req_max):
    """Snapshot a request: O_NOFOLLOW|O_NONBLOCK (FIFO can't hang us before fstat), reject
    non-regular/hardlinked/oversize, read ONCE into memory (frozen), unlink original."""
    dfd = os.open(reqdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
        except PermissionError:
            # An unreadable request -- DON'T silently drop: a 'received' caller can be answered with
            # a rejection from the filename. Post-socket-refactor the drvps-owned accepter is the ONLY
            # writer (0600 is fine: same uid), so EACCES here means a permissions anomaly in the
            # drvps-only spool (partial install, manual meddling) -- near-dead defensive path.
            sys.stderr.write("drvps-rigctl: request %s unreadable (EACCES) -- spool permissions anomaly\n" % name)
            return "EACCES"
        except OSError:
            _unlink(dfd, name)   # symlink (ELOOP) or gone: drop it (unlink does not follow)
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > req_max:
                _unlink(dfd, name)
                return None
            data = os.read(fd, req_max + 1)
            if len(data) > req_max:
                _unlink(dfd, name)
                return None
        finally:
            os.close(fd)
        _unlink(dfd, name)
        return data
    finally:
        os.close(dfd)


def _unlink(dfd, name):
    try:
        os.unlink(name, dir_fd=dfd)
    except IsADirectoryError:
        try:                                 # a dir named X.json (poison) -> rmdir so it can't re-accumulate
            os.rmdir(name, dir_fd=dfd)
        except OSError:
            pass
    except OSError:
        pass


def _purge_nonregular(reqdir, name):
    """DELETE a NON-REGULAR requests/ entry. A legitimate request is ALWAYS a regular file (agents drop
    one via an atomic `.tmp`->`.json` rename), so a dir/symlink/fifo here is never a real request. Do
    NOT rename it into the drvps-private processing/ dir: an agent can `mkdir requests/x.json/` full of
    data, and moving that OUT of the agent's reach into un-GC'd private storage is an unbounded disk/
    inode DoS (the agent can no longer remove what it planted, and nothing sweeps processing/). The
    watcher OWNS the sticky requests/ dir, so it may unlink any child regardless of the child's perms.
    rmtree does NOT follow symlinks -- it unlinks the link itself, never the target. Best-effort +
    loud one-time operator warning; a delete race (entry vanished) is benign."""
    src = os.path.join(reqdir, name)
    try:
        st = os.lstat(src)                   # no follow
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(src, ignore_errors=True)
        else:
            os.unlink(src)                   # symlink/fifo/socket/dev: unlink, never follows
        sys.stderr.write("drvps-rigctl: PURGED non-request spool entry %r (non-regular; deleted, "
                         "not persisted -- operator: investigate)\n" % name)
    except OSError:
        pass


def _valid_owner(v):
    """A ready-to-ACL owner uid, or None. Same rule as decide()'s owner check: a real non-negative
    JSON int, never a bool/negative/string (an unattributable/hand-planted value grants nothing)."""
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        return None
    return v


def _owner_of(raw):
    """Extract the ingress-stamped owner uid from a raw request (for S5 result ACLs). Every socket
    request is SO_PEERCRED-stamped, so this is present on ALL verbs -- incl. the non-owner-scoped
    reads whose results must still reach ONLY the requester. None if absent/invalid (fail closed:
    the result is then written 0600 drvps-only, readable by no agent)."""
    try:
        req = json.loads(raw)
        return _valid_owner(req.get("owner_uid")) if isinstance(req, dict) else None
    except Exception:
        return None


def _apply_owner_acl(path, owner):
    """S5: grant the agent-owner (a DIFFERENT uid than drvps) read on a 0600 drvps-owned spool file
    via a POSIX ACL, so a co-tenant cannot read it but the requester can. BEST-EFFORT + loud: the
    launcher's start-time ACL probe is the real precondition (dr-vps doctor deliberately does NOT
    check it), so a failure here means a runtime spool-fs degrade -- the
    file stays 0600 (confidentiality intact), the cross-uid agent just can't read it (availability
    degrades, logged). NEVER raises: a Restart=always daemon must still publish the result."""
    try:
        # --set REPLACES the entire access ACL: a plain `-m` MODIFIES it, preserving any
        # inherited default entry (e.g. a default:user:<co-tenant>:r on results/) and RECALCULATING the
        # mask to r-- -- which would re-activate that co-tenant as an effective reader. Setting the exact
        # 5-entry ACL leaves ONLY drvps (rw) + the owner (r); no stray named user/group survives.
        subprocess.run(["setfacl", "--set", "u::rw-,u:%d:r--,g::---,m::r--,o::---" % owner, path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
    except Exception as ex:
        sys.stderr.write("drvps-rigctl: setfacl u:%d:r on %s FAILED (%s) -- result stays 0600 "
                         "drvps-only; a cross-uid agent will NOT read it. Check the spool fs is "
                         "mounted with 'acl' and the acl package is installed (the launcher probes "
                         "this at every start; 'dr-vps doctor' does NOT check it).\n"
                         % (owner, path, type(ex).__name__))


def write_result(spool, reqid, obj, result_max, owner=None, private=True):
    """Atomic + NO-CLOBBER: write a temp, then os.link to the final path (link fails if the
    result already exists -> a replayed/duplicate reqid can't overwrite a prior result).
    Trims the free-form stdout/stderr fields BEFORE serializing so the envelope stays valid JSON
    (never slices raw JSON bytes -- that could cut mid-string/mid-escape and break the contract).
    S5: when `private`, the result is 0600 drvps-owned + a POSIX ACL granting `owner` read (set on
    the temp BEFORE the link so the final never appears co-tenant-readable); legacy mode is 0640."""
    obj = dict(obj)
    result_max = max(result_max, 512)            # sane lower bound: never below the minimal envelope
    raw = json.dumps(obj).encode()
    while len(raw) > result_max:
        # 'reason' joins the trimmable set: reject envelopes carry NO stdout/stderr,
        # so a long reason (e.g. an idem body-mismatch naming a 64-char key on a 128-char reqid at
        # the 512-byte floor) used to fall through to the last-resort byte cut = invalid JSON.
        f = max(("stdout", "stderr", "reason"), key=lambda k: len(obj.get(k) or ""))
        cur = obj.get(f) or ""
        if not cur:
            # Nothing free-form left to trim (the bulk sits elsewhere, e.g. an over-cap content_b64
            # under a lowered result_max). The last resort must STAY valid JSON -- a raw byte cut
            # can split mid-string/mid-escape and hand every reader a broken envelope. Shrink to a
            # minimal truncated envelope: reqid/status/exit_code survive (each is small and fenced;
            # the 512-byte floor always fits them), the payload is dropped.
            obj = {k: obj[k] for k in ("reqid", "status", "exit_code") if k in obj}
            obj["truncated"] = True
            raw = json.dumps(obj).encode()
            break
        obj[f] = cur[: max(0, len(cur) - (len(raw) - result_max) - 32)]
        obj["truncated"] = True
        raw = json.dumps(obj).encode()
    rdir = os.path.join(spool, "results")
    final = os.path.join(rdir, reqid + ".json")
    fd, tmp = tempfile.mkstemp(dir=rdir, prefix="." + reqid + ".")
    try:
        drvps_common.write_all(fd, raw)   # write-all: never publish a short-written (truncated) result
        # 0600 private (S5): structurally ends the co-tenant group-read leak regardless of ACL; legacy
        # 0640 relies on the setgid drvpsctl dir for agent read (DR_VPS_RESULT_PRIVATE=0, trusted rig).
        os.fchmod(fd, 0o600 if private else 0o640)
        # NB: once _apply_owner_acl runs, ls/stat SHOW 0640 -- with an extended ACL the st_mode group
        # bits display the ACL MASK (r--), not the owning group's access (still group::---); getfacl
        # is authoritative. Same applies to mark_claimed's .claimed markers.
        os.fsync(fd)
    finally:
        os.close(fd)
    if private and owner is not None:
        _apply_owner_acl(tmp, owner)             # grant BEFORE publish: final is never ACL-less-and-visible
    try:
        os.link(tmp, final)
    except FileExistsError:
        pass
    finally:
        os.unlink(tmp)


def mark_claimed(spool, reqid, op=None, vm=None, owner=None, private=True):
    """Drop a claimed marker (op/vm/timestamp) so the agent's bounded wait can tell 'claimed, still
    running' from 'never picked up / lost'. S5: 0600 + owner ACL when private, legacy 0640 otherwise.
    The marker is ALSO the at-most-once TOMBSTONE the terminal-write guard relies on before any side
    effect, so it must be DURABLE (fsync file + parent dir) and its failure must be VISIBLE: returns
    True iff durably established, else False -- callers MUST refuse to execute / to authorize a preempt
    kill on False (a missing/undurable marker reopens the slot-poison + double-execution window)."""
    rdir = os.path.join(spool, "results")
    p = os.path.join(rdir, reqid + ".claimed")
    mode = 0o600 if private else 0o640
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd, mode)
            drvps_common.write_all(fd, json.dumps({"reqid": reqid, "op": op, "vm": vm, "claimed_at": _utcnow()}).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(rdir)                          # the marker's APPEARANCE must survive a crash too
    except OSError as ex:
        sys.stderr.write("drvps-rigctl: mark_claimed FAILED for %s (%s) -- refusing to proceed "
                         "without a durable tombstone\n" % (reqid, ex))
        return False
    if private and owner is not None:
        _apply_owner_acl(p, owner)
    return True


# ---------------------- S4 idempotency journal (spool/idem/<owner_uid>/<key>.json) ----------------
# Crash-ordering contract (honest, not magical):
#   1. in-progress is durable BEFORE the verb executes  -> a crash mid-verb leaves the marker, so a
#      retry answers INDETERMINATE (reconcile-by-type) instead of silently double-executing.
#   2. done+result is durable BEFORE write_result        -> a crash between them is RECOVERED by the
#      retry replaying the journal (the client's lost result is re-served under its new reqid).
#   The remaining window -- crash after the verb ran but before done is recorded -- stays
#   INDETERMINATE by design: idem SHRINKS the retry dance, it does not remove it.
# The journal is drvps-PRIVATE (0700 dirs / 0600 files): co-tenants must not read another owner's
# recorded results (results/ itself is hardened separately in S5). GC lives in the reaper
# (DR_VPS_IDEM_TTL_MIN; TTL-only -- the global count-cap was removed), under the same
# work-lock as this loop -- no race.

def _idem_path(spool, action):
    return os.path.join(spool, "idem", str(action["owner_uid"]), action["idem"] + ".json")


def _fsync_dir(path):
    dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _idem_write(spool, action, entry):
    """Durable atomic journal write: temp + fsync + os.replace + directory fsync (crash-ordering is
    the whole point -- the entry AND the rename must survive a host crash; newly created dirs get
    their PARENT fsynced too, else the first-ever entry for an owner could vanish with the power).
    Raises OSError on failure -- the caller decides the fail-closed consequence. The temp is
    unlinked on ANY failure (a leaked hidden temp would be invisible to the reaper's *.json GC).
    chmods force 0700/0600 regardless of the daemon's umask (never group-readable; see S5)."""
    root = os.path.join(spool, "idem")
    d = os.path.join(root, str(action["owner_uid"]))
    # Refuse a SYMLINKED journal root or owner dir (fail closed) so a planted link
    # can't redirect the journal outside the spool. The spool is drvps-only, so this defends against
    # filesystem damage / a partial install, not an active attacker (who would have to BE drvps); the
    # installer also pre-creates spool/idem as a real 0700 dir. Belt-and-suspenders, cheap.
    for _p in (root, d):
        try:
            if stat.S_ISLNK(os.lstat(_p).st_mode):
                raise OSError("idem journal path is a symlink (refused): %s" % _p)
        except FileNotFoundError:
            pass
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    os.chmod(d, 0o700)
    # UNCONDITIONAL parent fsyncs: a PRIOR watcher instance may have created these
    # dirs and died before ITS parent fsync -- existence in cache proves nothing about durability,
    # so "did I create it?" is the wrong gate. Two cheap fsyncs per journal write buy the invariant.
    _fsync_dir(spool)
    _fsync_dir(root)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + action["idem"] + ".")
    try:
        try:
            drvps_common.write_all(fd, json.dumps(entry).encode())
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, _idem_path(spool, action))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(d)


def _idem_owner_over_quota(caps, action):
    """F4: True if this action's owner already holds >= idem_owner_max journal entries. A per-owner
    WRITE quota: an over-quota owner is refused NEW keys (fail closed) instead of the rig-wide count
    cap evicting some OTHER owner's (possibly in-progress) protection. Existing keys age out via TTL;
    the client can retry without --idem to proceed. Only NEW keys are checked (a retry of an existing
    key resolves before idem_begin, so it never hits the quota)."""
    d = os.path.join(caps["spool"], "idem", str(action["owner_uid"]))
    try:
        n = sum(1 for e in os.listdir(d) if e.endswith(".json"))
    except OSError:
        return False                             # no dir yet -> zero entries
    return n >= caps.get("idem_owner_max", 1000)


def idem_begin(caps, action):
    """Record state=in-progress DURABLY. MUST be called before run_action; raises OSError on failure
    (caller then refuses to execute -- running without the marker breaks the crash contract)."""
    _idem_write(caps["spool"], action,
                {"state": "in-progress", "idem": action["idem"], "owner_uid": action["owner_uid"],
                 "reqid": action["reqid"], "op": action["op"], "req_sha": action["req_sha"],
                 "at": _utcnow()})


def idem_finish(caps, action, res):
    """Record state=done with the result envelope. Called AFTER run_action, BEFORE write_result."""
    _idem_write(caps["spool"], action,
                {"state": "done", "idem": action["idem"], "owner_uid": action["owner_uid"],
                 "reqid": action["reqid"], "op": action["op"], "req_sha": action["req_sha"],
                 "at": _utcnow(), "result": res})


def idem_resolve(caps, action):
    """LOOKUP for an idem-carrying action. Returns None when the verb should EXECUTE (fresh key),
    else the already-determined result envelope to publish INSTEAD of executing:
      - recorded done + same req_sha    -> replay the recorded result (idem_replayed/orig_reqid set)
      - in-progress + same req_sha      -> status=indeterminate (durably accepted, no completion record)
      - any entry with a DIFFERENT sha  -> rejected (key misuse: same key, different request)
      - unreadable/corrupt entry        -> status=indeterminate (fail toward reconcile, NEVER re-run)
    Pure lookup: never writes the journal."""
    p = _idem_path(caps["spool"], action)
    base = {"reqid": action["reqid"], "op": action.get("op"), "vm": action.get("vm"),
            "idem": action["idem"]}   # .get: a gate-refused REJECT carries idem but not the run shape
    _corrupt = dict(base, status="indeterminate", exit_code=1,
                    stderr="idem key '%s': journal entry unreadable/corrupt -- outcome unknown; "
                           "reconcile by type (list/status/snap-ls), then retry with a FRESH key"
                           % action["idem"])
    try:
        # O_NOFOLLOW + regular-file check: only a genuinely ABSENT pathname means
        # "fresh". A symlink (ELOOP -- dangling or not), a dir, or any other abnormal object at the
        # journal path is filesystem damage/tamper in the drvps-only spool -- fail CLOSED, never open.
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as ex:
        # A BLOCKED/abnormal journal path (ELOOP/ENOTDIR/EACCES/...) is an INFRA error, not a corrupt
        # entry: no prior attempt is in evidence, but we can't prove absence either -- refuse to run.
        detail = (getattr(ex, "strerror", None) or str(ex))[:200]
        return dict(base, status="error", exit_code=1,
                    stderr="watcher: idem journal unreadable (%s) -- refusing to execute or guess"
                           % detail)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return dict(base, status="error", exit_code=1,
                        stderr="watcher: idem journal entry is not a regular file -- refusing to "
                               "execute or guess")
        raw = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw += chunk
    except OSError:
        return _corrupt
    finally:
        os.close(fd)
    # STRICT schema before any classification: a malformed record (e.g. {}) must be
    # INDETERMINATE (a damaged record may still represent an executed attempt), and "key misuse" may
    # only be claimed against a WELL-FORMED entry whose hash genuinely differs.
    try:
        entry = json.loads(raw)
        if not isinstance(entry, dict):
            raise ValueError("not an object")
        sha, state = entry.get("req_sha"), entry.get("state")
        if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)) \
                or state not in ("in-progress", "done"):
            raise ValueError("bad shape")
    except Exception:
        return _corrupt
    if sha != action["req_sha"]:
        return dict(base, status="rejected",
                    reason="idem key '%s' was already used by a different request (body mismatch); "
                           "a retry must resend the identical request -- use a fresh key for new work"
                           % action["idem"])
    if state == "done":
        if not isinstance(entry.get("result"), dict):
            return _corrupt                      # done without a recorded result = damaged record
        res = dict(entry["result"])
        res["reqid"] = action["reqid"]          # address the RETRY's reqid (its own results/ slot)
        res["idem_replayed"] = True
        res["orig_reqid"] = entry.get("reqid")
        res["idem"] = action["idem"]
        return res
    return dict(base, status="indeterminate", exit_code=1,
                stderr="idem key '%s': a prior attempt was durably accepted but left no completion "
                       "record (journal in-progress) -- it may or may not have started. Outcome "
                       "unknown; reconcile by type (list/status/snap-ls), then retry with a FRESH key"
                       % action["idem"])


def safe_peek(reqdir, name, cap):
    """SAFE read for DETECTION only: O_NOFOLLOW|O_NONBLOCK (no symlink-follow, no FIFO hang),
    regular-file + size-cap, no unlink. Returns the parsed dict or None."""
    dfd = os.open(reqdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
                return None
            data = os.read(fd, cap + 1)
            if len(data) > cap:
                return None
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    try:
        return json.loads(data)
    except Exception:
        return None


def find_preempt(reqdir, vm, owner):
    """Filename of a pending, well-formed same-VM destroy/recreate BY THE SAME OWNER (safe scan), else
    None. A preempt KILLS the in-flight child, so only the op's OWN owner may trigger
    it -- a foreign owner's destroy of this vm must NOT cancel another owner's exec/push/pull (it is
    left in the spool to be processed normally, where dr-vps fails it on ownership). owner is the
    in-flight op's owner (a validated int); a None owner (unowned in-flight op) matches nothing."""
    if owner is None:
        return None
    try:
        ents = [n for n in os.listdir(reqdir) if n.endswith(".json")]
    except OSError:
        return None
    # Bound the per-scan MAGNITUDE, not just the frequency: peek at most the MAX_PENDING NEWEST by
    # mtime, so an agent flooding requests/ during its own exec can't amplify each 2s tick into GB of
    # reads. A legit preempt (destroy/recreate dropped to abort a stuck op) is among the newest.
    if len(ents) > MAX_PENDING:
        def _pmt(n):
            try:
                return os.stat(os.path.join(reqdir, n)).st_mtime
            except OSError:
                return 0.0
        ents = sorted(ents, key=_pmt, reverse=True)[:MAX_PENDING]
    for n in sorted(ents):
        req = safe_peek(reqdir, n, 65536)
        if not isinstance(req, dict) or req.get("op") not in PREEMPT_VERBS or req.get("vm") != vm:
            continue
        if _valid_owner(req.get("owner_uid")) != owner:   # F1: same-owner only (foreign destroy can't cancel)
            continue
        rid = req.get("reqid")
        if isinstance(rid, str) and REQID_RE.match(rid) and n[:-5] == rid:
            return n
    return None


def _result_exists(caps, reqid):
    """A reqid whose result OR .claimed marker already exists is a duplicate / in-flight op. Publishing
    a terminal envelope (reject / replay / indeterminate / error) into its slot would POISON it: an
    INVALID same-reqid candidate could inject a rejection that then no-clobbers the real op's result
    Every terminal-write site that did NOT just mark_claimed THIS reqid must consult
    this first and, on a hit, record 'duplicate' and skip the write."""
    rj = os.path.join(caps["spool"], "results", reqid + ".json")
    rc = os.path.join(caps["spool"], "results", reqid + ".claimed")
    return os.path.exists(rj) or os.path.exists(rc)


def try_claim_preempt(reqdir, vm, in_flight_owner, caps, gate_fn):
    """Find -> CLAIM -> decide()+gate-validate a same-VM, SAME-OWNER destroy/recreate BEFORE the caller
    kills the in-flight child (closes the peek/claim TOCTOU). Returns a validated action dict (already
    claimed) or None. If a candidate is claimed but invalid, its rejected result is recorded and
    None is returned, so the in-flight child keeps running. `in_flight_owner` is the owner of the op
    being supervised -- only that owner may preempt it (F1)."""
    name = find_preempt(reqdir, vm, in_flight_owner)
    if not name:
        return None
    raw = claim(reqdir, name, caps["req_max"])
    if raw is None or raw == "EACCES":
        return None                              # candidate vanished/unreadable -> do NOT kill the child
    owner = _owner_of(raw)                        # S5: ACL grantee for this rescue candidate's result
    priv = caps["result_private"]
    d = decide(name, raw, gate_fn, caps)
    # F2: tombstone check BEFORE any terminal write -- a duplicate/in-flight reqid (its result or
    # .claimed already exists) must neither have an envelope written into its slot NOR kill the child.
    # This precedes the reject branch (which used to poison the slot) and subsumes the old post-run
    # replay guard below.
    rid0 = d.get("reqid")
    if rid0 and _result_exists(caps, rid0):
        audit(caps["spool"], {"reqid": rid0, "op": d.get("op"), "vm": d.get("vm"), "status": "duplicate"})
        return None
    # F1 re-assert AFTER the claim (peek/claim owner TOCTOU): the agent could rename-over the candidate
    # between find_preempt's peek and this claim, so the CLAIMED content's owner may differ. Only the
    # in-flight op's OWN owner may preempt it; a mismatch must NOT kill the child (reject, keep going).
    if d.get("action") == "run" and d.get("owner_uid") != in_flight_owner:
        rid = d.get("reqid")
        if rid:
            rej = {"reqid": rid, "status": "rejected",
                   "reason": "preempt owner mismatch (only the in-flight op's owner may cancel it)"}
            write_result(caps["spool"], rid, rej, caps["result_max"], owner, priv)
            audit(caps["spool"], rej)
        return None
    if d.get("action") != "run":
        rid = d.get("reqid")
        if rid:
            # Mirror the main path: a gate-refused idem retry answers from
            # the journal, never a false "rejected" (see process_request).
            if d.get("idem"):
                env = idem_resolve(caps, d)
                if env is not None:
                    write_result(caps["spool"], rid, env, caps["result_max"], owner, priv)
                    audit(caps["spool"], env)
                    return None
            rej = {"reqid": rid, "status": "rejected", "reason": d.get("reason")}
            write_result(caps["spool"], rid, rej, caps["result_max"], owner, priv)
            audit(caps["spool"], rej)
        return None                              # invalid -> keep supervising the in-flight op
    # Re-assert AFTER the claim (peek/claim CONTENT TOCTOU): the agent could rename-over the request
    # between find_preempt's peek and this claim, so the CLAIMED content may be a different (still
    # gate-authorized) verb/vm. Only a destroy/recreate FOR THIS in-flight vm may preempt -- anything
    # else must NOT kill the child; reject it (agent isn't left hanging) and keep supervising.
    if d.get("op") not in PREEMPT_VERBS or d.get("vm") != vm:
        rid = d.get("reqid")
        if rid:
            rej = {"reqid": rid, "status": "rejected", "reason": "preempt content mismatch (op/vm changed after peek)"}
            write_result(caps["spool"], rid, rej, caps["result_max"], owner, priv)
            audit(caps["spool"], rej)
        return None
    # (The duplicate/replay guard -- a reqid that already has a RESULT or is CLAIMED must not preempt --
    # is enforced by the F2 _result_exists() tombstone check at the top of this function, before any
    # terminal write, so it can't be bypassed by the reject branch above.)
    # S4 idem check BEFORE the kill decision: a RETRIED destroy/recreate whose key is already
    # recorded (or indeterminate/misused) must NOT kill the in-flight op -- its answer is already
    # determined, so publish that answer and keep supervising the child.
    if d.get("idem"):
        env = idem_resolve(caps, d)
        if env is not None:
            write_result(caps["spool"], d["reqid"], env, caps["result_max"], owner, priv)
            audit(caps["spool"], env)
            return None
        # FRESH key: make in-progress durable BEFORE authorizing the kill -- the
        # kill is the rescue's first side effect, and a rescue that cannot be journaled must not
        # cost an in-flight op its life. On begin failure OR over-quota (F4): error result, child runs.
        if _idem_owner_over_quota(caps, d):
            err = {"reqid": d["reqid"], "op": d.get("op"), "vm": d.get("vm"), "idem": d["idem"],
                   "status": "error", "exit_code": 1,
                   "stderr": "watcher: idem journal quota exceeded for owner %s (>= %d keys) -- retire "
                             "old keys or wait for TTL; retry WITHOUT --idem to proceed now"
                             % (d["owner_uid"], caps.get("idem_owner_max", 1000))}
            write_result(caps["spool"], d["reqid"], err, caps["result_max"], owner, priv)
            audit(caps["spool"], err)
            return None
        try:
            idem_begin(caps, d)
        except OSError as ex:
            detail = (getattr(ex, "strerror", None) or str(ex))[:200]
            err = {"reqid": d["reqid"], "op": d.get("op"), "vm": d.get("vm"), "idem": d["idem"],
                   "status": "error", "exit_code": 1,
                   "stderr": "watcher: idem journal write failed (%s) -- refusing to execute "
                             "without a durable in-progress record" % detail}
            write_result(caps["spool"], d["reqid"], err, caps["result_max"], owner, priv)
            audit(caps["spool"], err)
            return None
        d["_idem_begun"] = True                  # _run_journaled must not begin twice
    # Durable trail BEFORE the child is killed: write .claimed + a 'received' audit here, since the
    # rescue request is already unlinked -- a crash between the kill and run_action would otherwise
    # leave the rescue with no marker, no audit, no result (mis-reported to the agent as 'lost').
    if not mark_claimed(caps["spool"], d["reqid"], d.get("op"), d.get("vm"), owner, priv):
        # M4: without a durable tombstone do NOT authorize the kill (the in-flight child keeps running).
        # The rescue's idem in-progress (if any) resolves a retry to indeterminate; best-effort error.
        err = {"reqid": d["reqid"], "op": d.get("op"), "vm": d.get("vm"), "status": "error", "exit_code": 1,
               "stderr": "watcher: could not durably record the preempt claimed marker -- not cancelling the in-flight op"}
        write_result(caps["spool"], d["reqid"], err, caps["result_max"], owner, priv)
        audit(caps["spool"], err)
        return None
    audit(caps["spool"], {"reqid": d["reqid"], "op": d.get("op"), "vm": d.get("vm"), "status": "received"})
    d["_acl_owner"] = owner                       # S5: process_request writes the rescue result with this owner
    return d


def supervise(p, timeout, out_cap, preempt_cb):
    """Run a started child to completion: bounded output, hard timeout, and -- only if a
    preempt_cb is given -- preemption. preempt_cb() returns an already-CLAIMED+validated rescue
    action (or None); we kill the child ONLY after such a claim. Returns
    (rc, out, err, status, rescue_action)."""
    out, err = bytearray(), bytearray()
    for s in (p.stdout, p.stderr):
        os.set_blocking(s.fileno(), False)
    start = time.monotonic()
    last_scan = 0.0
    status = "ok"
    rescue = None
    while True:
        for buf, s in ((out, p.stdout), (err, p.stderr)):
            try:
                chunk = s.read(65536)
            except Exception:
                chunk = b""
            if chunk and len(buf) < out_cap:
                buf.extend(chunk[: out_cap - len(buf)])
        rc = p.poll()
        if rc is not None:
            break
        now = time.monotonic()
        if now - start > timeout:
            _killpg(p); status = "timeout"; rc = 124; break
        # Rate-limit the preempt scan (it lists+parses the whole requests dir): every PREEMPT_SCAN_S,
        # not every 100ms, so an agent flooding 64KiB requests can't amplify it into GB of reads.
        if preempt_cb is not None and now - last_scan >= PREEMPT_SCAN_S:
            last_scan = now
            # A preempt scan that RAISES (e.g. write_result ENOSPC while publishing a
            # determined idem candidate's result) must NOT abort supervision and orphan the running
            # child. Swallow it, log, and keep supervising -- the candidate is retryable; the child isn't.
            try:
                act = preempt_cb()
            except Exception as ex:
                sys.stderr.write("drvps-rigctl: preempt scan raised (%s) -- keep supervising the child\n"
                                 % type(ex).__name__)
                act = None
            if act is not None:                  # rescue ALREADY claimed+validated
                # preempt_cb (gate + a durable idem fsync) can take real time; the
                # child may have COMPLETED during it. RE-POLL before killing -- a finished child must
                # keep its REAL exit (never a false "preempted"/130 that makes a controller retry a
                # non-idempotent op). The rescue still runs, but afterward as an ordinary queued action.
                rc = p.poll()
                if rc is not None:
                    rescue = act; break          # child done -> status stays "ok", real rc preserved
                _killpg(p); status = "preempted"; rc = 130; rescue = act; break
        time.sleep(0.1)
    try:
        o, e = p.communicate(timeout=2)
        if o and len(out) < out_cap: out.extend(o[: out_cap - len(out)])
        if e and len(err) < out_cap: err.extend(e[: out_cap - len(err)])
    except subprocess.TimeoutExpired:
        # The (SIGKILL'd) child is still draining/D-state: don't leak a zombie + pipe fds on this
        # Restart=always daemon. Re-kill the process group, reap with a longer wait, then force-close
        # the pipes so the fds are released even if the child never fully exits.
        _killpg(p)
        try:
            p.communicate(timeout=5)
        except Exception:
            pass
        for s in (p.stdout, p.stderr):
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        pass
    return rc, bytes(out), bytes(err), status, rescue


def _killpg(p):
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception:
        pass


def run_action(action, caps, gate_fn, allow_preempt):
    """Spawn the verb child (own session), supervise it (Popen failures -> error result, never a
    daemon crash). Preemption is enabled ONLY for guest-I/O ops (exec/push/pull) -- never for a
    lifecycle mutator (a destroy/recreate must not be killed mid-flight). Returns
    (result_envelope, rescue_action_or_None)."""
    argv = list(action["argv"])
    tmp = None
    p = None                                     # M2: reachable in except/finally for the fail-safe kill+reap
    rescue = None
    preempt_cb = None
    if allow_preempt and action["op"] in ("exec", "push", "pull") and action.get("vm"):
        reqdir = os.path.join(caps["spool"], "requests")
        vm = action["vm"]
        owner = action.get("owner_uid")   # F1: only THIS owner's destroy/recreate may preempt the op
        preempt_cb = lambda: try_claim_preempt(reqdir, vm, owner, caps, gate_fn)  # noqa: E731
    base = {"reqid": action["reqid"], "op": action["op"], "vm": action.get("vm")}
    started = _utcnow()
    # Lifecycle MUTATORS get a generous timeout (boot+cloud-init can take minutes): killing one
    # mid-flight can orphan a domain / leave partial storage, so they must not be hard-killed under
    # normal operation. exec/push/pull keep the tighter exec_timeout. (LIFECYCLE is module-level.)
    timeout = caps["lifecycle_timeout"] if action["op"] in LIFECYCLE else caps["exec_timeout"]
    try:
        # The push temp write is INSIDE the try: an mkstemp/os.write failure (ENOSPC,
        # a missing processing/ after a partial install) must yield a status=error RESULT, never an
        # uncaught exception that crashes the Restart=always daemon after the request was claimed.
        if action["op"] == "push":
            fd, tmp = tempfile.mkstemp(dir=os.path.join(caps["spool"], "processing"))
            try:
                drvps_common.write_all(fd, action["push_bytes"])   # write-all: never scp a truncated push temp
            finally:
                os.close(fd)
            argv = [tmp if a == "<TMP>" else a for a in argv]
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
        # The output read cap differs by verb. For PULL it MUST be transfer_max+1, NOT result_max//2
        #: with a small DR_VPS_RESULT_MAX_BYTES (result_max//2 < transfer_max), the
        # old cap truncated the payload BELOW transfer_max+1, so the over-cap check never fired and a
        # truncated file shipped as status=ok -- the exact silent-truncation C-3 set out to kill.
        # transfer_max+1 captures a full <=cap file AND lets len==transfer_max+1 signal over-cap.
        out_cap = (caps["transfer_max"] + 1) if action["op"] == "pull" \
            else (caps["console_max"] + 1) if action["op"] == "console-dump" \
            else caps["result_max"] // 2
        rc, out, err, status, rescue = supervise(p, timeout, out_cap, preempt_cb)
        res = dict(base, status=status, exit_code=rc, started_at=started, ended_at=_utcnow(),
                   stderr=err.decode("utf-8", "replace"))
        if action["op"] == "pull":
            # pull moves bytes as size-capped BASE64 through the result channel, so a
            # BINARY guest file survives intact (a utf-8 decode would mangle it) and an OVER-CAP
            # transfer is an EXPLICIT error, not a silent truncation. dr_vps_pull emits
            # `head -c transfer_max+1` bytes IN THE GUEST, so a length of transfer_max+1 means the
            # file was larger than the cap. rigctl base64-decodes content_b64 back to raw stdout.
            # content_b64 is attached ONLY on status==ok AND rc==0: a timed-out/preempted
            # pull carries NO partial payload, AND a guest-side FAILURE (missing/unreadable path -> head
            # exits nonzero with empty stdout, but supervise still marks status=ok for any child that
            # exits) must be an ERROR, not an empty-but-"ok" file that rigctl would decode as success.
            # The result-size guard below is unconditional on that ok+rc0 path (never emit content
            # write_result would raw-slice into invalid JSON, regardless of how the op ended).
            if status == "ok" and rc != 0:
                res["status"] = "error"
                res["stderr"] = ("pull: guest read failed (exit %d) -- missing/unreadable path? %s"
                                 % (rc, res.get("stderr") or "")).strip()
            elif status == "ok":
                if len(out) > caps["transfer_max"]:
                    res["status"] = "error"; res["exit_code"] = 1
                    res["stderr"] = "pull: file exceeds the %d-byte transfer cap" % caps["transfer_max"]
                else:
                    b64 = base64.b64encode(bytes(out)).decode("ascii")
                    if len(b64) + 1024 > caps["result_max"]:
                        res["status"] = "error"; res["exit_code"] = 1
                        res["stderr"] = ("pull: result (%d B base64) exceeds the %d-byte result cap -- "
                                         "raise DR_VPS_RESULT_MAX_BYTES" % (len(b64), caps["result_max"]))
                    else:
                        res["content_b64"] = b64
        elif action["op"] == "console-dump":
            # console-dump returns the UNTRUSTED persistent console-log tail. Move it as size-capped BASE64
            # (like pull) so binary/non-UTF8 boot output survives intact and a "no persistent log" (dr-vps
            # console-dump exits E_NOTFOUND=14 with a "recreate to enable" stderr) is an EXPLICIT error,
            # never an empty-as-success. bin/rigctl base64-decodes AND SANITIZES it for terminal display.
            # The tail is already byte-bounded in the guest-side helper (tail -c console_max); belt-and-
            # suspenders slice here too so the base64 can never overrun result_max on a misbehaving helper.
            if status == "ok" and rc != 0:
                res["status"] = "error"
                res["stderr"] = res.get("stderr") or ("console-dump: failed (exit %d)" % rc)
            elif status == "ok":
                b64 = base64.b64encode(bytes(out[:caps["console_max"]])).decode("ascii")
                if len(b64) + 1024 > caps["result_max"]:
                    res["status"] = "error"; res["exit_code"] = 1
                    res["stderr"] = ("console-dump: result (%d B base64) exceeds the %d-byte result cap -- "
                                     "raise DR_VPS_RESULT_MAX_BYTES" % (len(b64), caps["result_max"]))
                else:
                    res["content_b64"] = b64
        else:
            res["stdout"] = out.decode("utf-8", "replace")
    except Exception as ex:
        detail = (getattr(ex, "strerror", None) or str(ex))[:200]
        res = dict(base, status="error", exit_code=1, started_at=started, ended_at=_utcnow(),
                   stderr="watcher: %s: %s" % (type(ex).__name__, detail))
    finally:
        # Fail-safe: any post-Popen exceptional exit (incl. a preempt_cb that
        # escaped supervise, though supervise now catches that too) MUST NOT leave the started child
        # running against the guest after we release the flock. Kill its process group and REAP it.
        if p is not None and p.poll() is None:
            _killpg(p)
            try:
                p.communicate(timeout=5)
            except Exception:
                pass
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return res, rescue


AUDIT_MAX = _cap_int("DR_VPS_AUDIT_MAX_BYTES", 16 << 20, 1, 1 << 30)   # 16 MiB default; rotate to .1 (r3: defensive parse)


def audit(spool, entry):
    # EXCLUDE bulk/payload fields from the audit line: stdout/stderr (exec output), push_bytes (push
    # input), and content_b64 (pull output: it would otherwise append a base64 guest-file
    # payload per successful pull, bloating + fast-rotating audit.log against the stated contract).
    rec = {k: v for k, v in entry.items() if k not in ("stdout", "stderr", "push_bytes", "content_b64")}
    rec.setdefault("at", _utcnow())          # every audit line is timestamped (orderable vs journald/qemu/squid)
    path = os.path.join(spool, "audit.log")
    try:
        # SIZE-ROTATE: an agent submitting endless distinct reqids appends unboundedly (rejects are
        # cheap) and the reaper GC never covered audit.log -> rotate to audit.log.1 (keep 1 gen) so it
        # can't monotonically exhaust the spool partition.
        try:
            if os.path.getsize(path) >= AUDIT_MAX:
                os.replace(path, path + ".1")
        except OSError:
            pass
        with open(path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        sys.stderr.write("drvps-rigctl: AUDIT WRITE FAILED (audit going dark)\n")   # don't fail silently


def load_caps():
    # Fallback to the INSTALL location (matching bin/dr-vps-setup + bin/rigctl) -- a bare
    # os.environ[...] here would KeyError-crash-loop the watcher (Restart=always) on any upgrade
    # path where /etc/distro-rig-vps/env lacks the line (reproduced on a real host).
    sp = os.environ.get("DR_VPS_SPOOL_DIR", "/var/spool/distro-rig-vps")
    return {
        "spool": sp,
        "bin": os.environ.get("DR_VPS_BIN", "/opt/distro-rig-vps/bin/dr-vps"),
        "net": os.environ.get("DR_VPS_RIG_NET", "simnet"),
        "pubkey": os.environ.get("DR_VPS_SSH_KEY", "") + ".pub",
        "req_max": drvps_common.req_max_bytes(),                     # shared with the accepter (H-3)
        # r3: defensive parse (no ValueError crash-loop on a hand-edited env); lo=1 so legit small operator/
        # test overrides are NOT clamped, hi is a generous sanity envelope.
        "result_max": _cap_int("DR_VPS_RESULT_MAX_BYTES", 1048576, 1, 1 << 30),
        "transfer_max": _cap_int("DR_VPS_TRANSFER_MAX_BYTES", 262144, 1, 1 << 30),
        "exec_timeout": _cap_int("DR_VPS_EXEC_TIMEOUT", 300, 1, 604800),
        "lifecycle_timeout": _cap_int("DR_VPS_LIFECYCLE_TIMEOUT", 900, 1, 604800),  # boot+cloud-init headroom

        # console-dump tail cap: the api.sh knob is the single source of truth (observability Step 8).
        # convergence r1/r2: parse defensively (no ValueError crash-loop) + CLAMP to [1, 4 MiB] so a
        # negative/zero/malformed override can't produce nonsensical tail/slice limits (an over-large value
        # is also caught downstream by the result_max base64-size guard).
        "console_max": _cap_int("DR_VPS_CONSOLE_TAIL_MAX_BYTES", 65536, 1, 4194304),
        "mem_max": 16384, "cpu_max": 8, "wait_timeout": 300,
        # S0 (service plane): the OS group that gates the ABILITY to request class=service (S1b reads it;
        # membership alone opens nothing outward -- capabilities stay operator-registered). UNREAD this stage.
        "service_group": os.environ.get("DR_VPS_SERVICE_GROUP", "drvpsvc"),
        # Per-owner idem-journal write quota. Refusing an OVER-QUOTA owner a NEW key
        # (fail closed) prevents one owner's key churn from evicting ANOTHER owner's protection via the
        # rig-wide count cap. Generous default -- a legit owner rarely holds this many un-GC'd keys/TTL.
        "idem_owner_max": _cap_int("DR_VPS_IDEM_OWNER_MAX", 1000, 1, 1 << 20),
        # S5 private result store: when on (default), result files + .claimed markers are 0600 drvps-owned
        # + a POSIX ACL granting the requesting owner read (co-tenant leak fix; doctor gates fs-ACL support).
        # DR_VPS_RESULT_PRIVATE=0 restores the legacy 0640 group-readable behavior for a TRUSTED, single-
        # tenant / non-ACL-fs rig.
        "result_private": os.environ.get("DR_VPS_RESULT_PRIVATE", "1") != "0",
    }


def real_gate(mode, vm):
    bin_ = os.environ.get("DR_VPS_BIN", "/opt/distro-rig-vps/bin/dr-vps")
    try:
        return subprocess.run([bin_, "gate", mode, vm], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=60).returncode == 0
    except Exception:
        return False                          # gate uninvokable (bad bin / timeout) -> REFUSE (fail closed)


def process_request(name, caps, gate_fn, allow_preempt=True):
    reqdir = os.path.join(caps["spool"], "requests")
    raw = claim(reqdir, name, caps["req_max"])
    if raw == "EACCES":                          # unreadable request -> reject from the filename, then unlink
        rid = name[:-5] if name.endswith(".json") else name
        if REQID_RE.match(rid) and not _result_exists(caps, rid):   # M3: don't poison a claimed/finished slot
            rej = {"reqid": rid, "status": "rejected", "reason": "request unreadable by watcher (spool permissions anomaly -- operator: check requests/ ownership)"}
            # owner UNKNOWN (the request was unreadable) -> 0600 drvps-only, no ACL (fail closed).
            write_result(caps["spool"], rid, rej, caps["result_max"], None, caps["result_private"])
            audit(caps["spool"], rej)
        try:
            dfd = os.open(reqdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try: _unlink(dfd, name)
            finally: os.close(dfd)
        except OSError:
            pass
        return
    if raw is None:
        return
    owner = _owner_of(raw)                        # S5: the ACL grantee for THIS request's result/.claimed
    priv = caps["result_private"]
    d = decide(name, raw, gate_fn, caps)
    reqid = d.get("reqid")
    if d["action"] == "reject" or not reqid:
        if reqid:
            # F2: never write a rejection into a slot that already has a result/.claimed (a duplicate
            # of an in-flight/finished reqid) -- that would poison it (no-clobber hides the real result).
            if _result_exists(caps, reqid):
                audit(caps["spool"], {"reqid": reqid, "op": d.get("op"), "vm": d.get("vm"), "status": "duplicate"})
                return
            # A gate-refused reject carries the idem fields -- an already-
            # determined key answers from the journal (replay/indeterminate/misuse) instead of
            # reporting "rejected" (which the contract defines as 'never executed', a lie here).
            if d.get("idem"):
                env = idem_resolve(caps, d)
                if env is not None:
                    write_result(caps["spool"], reqid, env, caps["result_max"], owner, priv)
                    audit(caps["spool"], env)
                    return
            rej = {"reqid": reqid, "status": "rejected", "reason": d["reason"]}
            write_result(caps["spool"], reqid, rej, caps["result_max"], owner, priv)
            audit(caps["spool"], rej)
        return
    # Replay guard (F2 _result_exists): a re-dropped reqid that already has a RESULT *or* is already
    # CLAIMED must NOT re-execute the host verb (at-most-once). The .claimed check is essential: the
    # reaper's count-GC can prune an old <reqid>.json while its <reqid>.claimed is still present, and
    # results/ is group-LISTABLE, so an agent could otherwise resubmit that reqid to replay a (possibly
    # mutating) verb. write_result no-clobbers the result, but run_action would run.
    if _result_exists(caps, reqid):
        audit(caps["spool"], {"reqid": reqid, "op": d.get("op"), "vm": d.get("vm"), "status": "duplicate"})
        return
    if not mark_claimed(caps["spool"], reqid, d.get("op"), d.get("vm"), owner, priv):
        # M4: no durable tombstone -> refuse to execute (a same-reqid invalid candidate could otherwise
        # poison the slot, or a valid one kill+re-run). Best-effort error result; the key is NOT running.
        err = {"reqid": reqid, "op": d.get("op"), "vm": d.get("vm"), "status": "error", "exit_code": 1,
               "stderr": "watcher: could not durably record the claimed marker -- refusing to execute"}
        write_result(caps["spool"], reqid, err, caps["result_max"], owner, priv)
        audit(caps["spool"], err)
        return
    # Durable 'received' record BEFORE the (possibly mutating) verb runs, so a watcher crash mid-op
    # still leaves a trail (the request file is already unlinked by claim()).
    audit(caps["spool"], {"reqid": reqid, "op": d.get("op"), "vm": d.get("vm"), "status": "received"})
    # S4: an idem-carrying action may already be DETERMINED (replay / indeterminate / key misuse) --
    # publish that answer INSTEAD of executing.
    if d.get("idem"):
        env = idem_resolve(caps, d)
        if env is not None:
            write_result(caps["spool"], reqid, env, caps["result_max"], owner, priv)
            audit(caps["spool"], env)
            return
    res, rescue = _run_journaled(d, caps, gate_fn, allow_preempt)
    write_result(caps["spool"], reqid, res, caps["result_max"], owner, priv)
    audit(caps["spool"], res)
    # The rescue (if any) was ALREADY claimed + decide()+gate-validated inside the preempt path
    # BEFORE the child was killed (and its idem key, if any, resolved to FRESH there -- a replayed/
    # indeterminate rescue never kills the child). Run it NOW under the SAME held lock, no preemption.
    if rescue is not None:
        # .claimed + 'received' were already written in try_claim_preempt (before the kill).
        rres, _ = _run_journaled(rescue, caps, gate_fn, allow_preempt=False)
        write_result(caps["spool"], rescue["reqid"], rres, caps["result_max"],
                     rescue.get("_acl_owner"), priv)   # S5: the rescue's OWN owner (a different request)
        audit(caps["spool"], rres)


def _run_journaled(action, caps, gate_fn, allow_preempt):
    """run_action wrapped in the S4 idem crash-ordering (no-op for non-idem actions):
    in-progress durable BEFORE the verb, done+result durable AFTER it (before the caller publishes).
    An in-progress write failure REFUSES to execute (fail closed -- running without the marker would
    reopen the silent-double-execution window). A done write failure still DELIVERS the result (the
    verb DID run; withholding it helps nobody) -- the entry stays in-progress, so a later retry gets
    INDETERMINATE and reconciles: honest, never a silent re-run."""
    if not action.get("idem"):
        return run_action(action, caps, gate_fn, allow_preempt)
    base = {"reqid": action["reqid"], "op": action["op"], "vm": action.get("vm"),
            "idem": action["idem"]}
    if not action.get("_idem_begun"):            # a preempt rescue was already begun pre-kill (M3)
        if _idem_owner_over_quota(caps, action):
            return dict(base, status="error", exit_code=1,
                        stderr="watcher: idem journal quota exceeded for owner %s (>= %d keys) -- "
                               "retire old keys or wait for TTL; retry WITHOUT --idem to proceed now"
                               % (action["owner_uid"], caps.get("idem_owner_max", 1000))), None
        try:
            idem_begin(caps, action)
        except OSError as ex:
            detail = (getattr(ex, "strerror", None) or str(ex))[:200]
            return dict(base, status="error", exit_code=1,
                        stderr="watcher: idem journal write failed (%s) -- refusing to execute without "
                               "a durable in-progress record" % detail), None
    res, rescue = run_action(action, caps, gate_fn, allow_preempt)
    try:
        idem_finish(caps, action, res)
    except OSError as ex:
        sys.stderr.write("drvps-rigctl: idem journal finish FAILED for %s/%s (%s) -- entry stays "
                         "in-progress; a retry will report INDETERMINATE\n"
                         % (action["owner_uid"], action["idem"], ex))
    return res, rescue


def main(argv):
    # test hook: `decide <filename> ok|refuse` reads a request on stdin, prints the decision.
    if argv and argv[0] == "decide":
        filename = argv[1]
        gate = (lambda m, v: argv[2] == "ok") if len(argv) > 2 else (lambda m, v: True)
        caps = {"req_max": drvps_common.req_max_bytes(),
                "transfer_max": 1 << 18, "bin": "dr-vps", "net": "simnet",
                "pubkey": "/k.pub", "mem_max": 16384, "cpu_max": 8, "console_max": 65536, "wait_timeout": 300,
                "service_group": os.environ.get("DR_VPS_SERVICE_GROUP", "drvpsvc")}
        d = decide(filename, sys.stdin.buffer.read(), gate, caps)
        if isinstance(d.get("push_bytes"), (bytes, bytearray)):   # not JSON-serializable; redact for the hook
            d = dict(d, push_bytes="<%d bytes>" % len(d["push_bytes"]))
        print(json.dumps(d))
        return 0
    caps = load_caps()
    reqdir = os.path.join(caps["spool"], "requests")
    lock = os.open(os.path.join(caps["spool"], ".lock"), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    once = "--once" in argv
    rdfd = os.open(reqdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    while True:
        try:
            allents = os.listdir(reqdir)
        except OSError:
            allents = []
        # Classify with lstat (NEVER follows symlinks). Only REGULAR FILES can be valid requests or
        # consume a flood-cap slot: a `.json` DIRECTORY (poison) or a dangling `.tmp` SYMLINK would
        # otherwise wedge the cap / evade the sweep. Non-regular entries are DELETED (never a real
        # request). lstat's own mtime (no follow, no raise on a dangling link) ages the temp files.
        entries = []
        now = time.time()
        for n in allents:
            try:
                st = os.lstat(os.path.join(reqdir, n))
            except OSError:
                continue                          # vanished mid-listing
            if not stat.S_ISREG(st.st_mode):
                _purge_nonregular(reqdir, n)   # dir / symlink / fifo / etc. -> DELETED (never persisted)
                continue
            if n.endswith(".json"):
                entries.append(n)
            elif TMP_RE.match(n):                # an in-progress '.{reqid}.tmp' rigctl temp: keep only briefly
                if now - st.st_mtime > 5:
                    _unlink(rdfd, n)
            else:
                _unlink(rdfd, n)                  # regular non-request junk -> unlink immediately
        # Order by ARRIVAL (mtime), not lexicographically, so a '0...'-named flood can't starve
        # other requesters; fall back to name order if a stat races.
        def _mt(n):
            try:
                return os.stat(os.path.join(reqdir, n)).st_mtime
            except OSError:
                return 0.0
        names = sorted(entries, key=lambda n: (_mt(n), n))   # arrival, then name (deterministic tiebreak)
        # M7 spool flood cap: above MAX_PENDING, reject the NEWEST surplus (claim+rejected result)
        # so the agent learns and the spool drains instead of exhausting inodes/disk.
        if len(names) > MAX_PENDING:
            for name in names[MAX_PENDING:]:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    raw = claim(reqdir, name, caps["req_max"])
                    rid = name[:-5]
                    if raw == "EACCES":
                        _unlink(rdfd, name)     # unreadable AND over-cap surplus -> drop now, don't let it linger
                    elif raw is not None and REQID_RE.match(rid):
                        # Tombstone guard here too: a duplicate reqid in the
                        # over-cap surplus must not write a rejection into an already-claimed/finished
                        # slot (no-clobber would then hide the real op's result).
                        if _result_exists(caps, rid):
                            audit(caps["spool"], {"reqid": rid, "status": "duplicate"})
                        else:
                            rej = {"reqid": rid, "status": "rejected", "reason": "spool over capacity"}
                            write_result(caps["spool"], rid, rej, caps["result_max"],
                                         _owner_of(raw), caps["result_private"])   # S5: ACL to the requester
                            audit(caps["spool"], rej)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
            names = names[:MAX_PENDING]
        for name in names:
            fcntl.flock(lock, fcntl.LOCK_EX)        # per-op lock (D11); reaper interleaves
            try:
                process_request(name, caps, real_gate)
            except Exception as ex:                 # noqa: BLE001 -- Restart=always daemon MUST NOT die
                # A per-request bug/OSError must not crash the watcher and lose the claimed-request
                # state for every OTHER pending request. Log to the journal + continue.
                sys.stderr.write("drvps-rigctl: request %s aborted: %s: %s\n"
                                 % (name, type(ex).__name__, str(ex)[:200]))
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
            # Re-cap MID-PASS: a long op (up to lifecycle_timeout) is a window in which the agent can
            # flood requests/. If it grew past the cap during this op, break to the top to re-list +
            # reject the surplus -- so requests/ can't grow unbounded between once-per-pass cap checks.
            try:
                if len(os.listdir(reqdir)) > MAX_PENDING:
                    break
            except OSError:
                pass
        if once:
            return 0
        _wait(reqdir)


def _wait(reqdir):
    iw = os.environ.get("DR_INOTIFYWAIT", "inotifywait")
    try:
        subprocess.run([iw, "-q", "-t", "5", "-e", "create,moved_to", reqdir],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        time.sleep(2)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
