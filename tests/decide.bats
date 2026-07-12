#!/usr/bin/env bats
# Stage 3a (Phase 2) -- the watcher's PURE decide() security table. Driven via the python
# `decide` hook with an injected gate stub (ok|refuse). This is where the gateway decisions live.

load helpers

W="src/drvps_rigctl.py"

# _d <filename> <gate ok|refuse> <json> -> sets $output to the decision JSON; $status from python
_d() { run python3 "${DR_VPS_SRC}/../${W}" decide "$1" "$2" <<<"$3"; }

@test "decide: valid create -> run (watcher fixes net/key/project)" {
  _d c1.json ok '{"reqid":"c1","op":"create","name":"myvm","distro":"fedora44","owner_uid":4001}'
  [[ "$output" == *'"action": "run"'* ]]
  [[ "$output" == *'--net'* && "$output" == *'simnet'* && "$output" == *'--project'* ]]
}

@test "decide: distros -> run (ungated global read, argv is 'dr-vps distros', no owner scoping)" {
  _d d1.json ok '{"reqid":"d1","op":"distros"}'
  [[ "$output" == *'"action": "run"'* ]]
  [[ "$output" == *'"distros"'* ]]
  [[ "$output" != *'--owner'* ]]
}

@test "decide: distros runs even when the gate stub refuses (no vm, no gate)" {
  _d d2.json refuse '{"reqid":"d2","op":"distros"}'
  [[ "$output" == *'"action": "run"'* ]]
}

@test "decide: create without a name -> reject" {
  _d c2.json ok '{"reqid":"c2","op":"create","owner_uid":4001}'
  [[ "$output" == *'"action": "reject"'* ]]
}

@test "decide: oversize request -> reject (watcher-side cap; tiny DR_VPS_REQ_MAX_BYTES override)" {
  export DR_VPS_REQ_MAX_BYTES=32
  big=$(printf 'x%.0s' {1..64})
  _d c2b.json ok "{\"reqid\":\"c2b\",\"op\":\"list\",\"pad\":\"$big\"}"
  [[ "$output" == *'"action": "reject"'* && "$output" == *'oversize request'* ]]
}

@test "decide: bad json -> reject" {
  _d c3.json ok 'not json at all'
  [[ "$output" == *'"action": "reject"'* && "$output" == *'bad json'* ]]
}

@test "decide: bad reqid charset -> reject" {
  _d 'c4.json' ok '{"reqid":"../etc/x","op":"list"}'
  [[ "$output" == *'reject'* && "$output" == *'bad reqid'* ]]
}

@test "decide: filename != reqid -> reject (the binding)" {
  _d other.json ok '{"reqid":"c5","op":"list"}'
  [[ "$output" == *'reject'* && "$output" == *'filename != reqid'* ]]
}

@test "decide: unknown verb -> reject" {
  _d c6.json ok '{"reqid":"c6","op":"rm-rf-host"}'
  [[ "$output" == *'reject'* && "$output" == *'unknown verb'* ]]
}

@test "decide: leading-dash vm id -> reject (never reaches gate)" {
  _d c7.json ok '{"reqid":"c7","op":"destroy","vm":"-rf","owner_uid":4001}'
  [[ "$output" == *'reject'* && "$output" == *'bad vm id'* ]]
}

@test "decide: gate refuses -> reject" {
  _d c8.json refuse '{"reqid":"c8","op":"exec","vm":"vm1","cmd":"id","owner_uid":4001}'
  [[ "$output" == *'reject'* && "$output" == *'gate refused'* ]]
}

@test "decide: destroy is NOT pre-gated -> run even when the gate refuses (dr-vps destroy is authoritative)" {
  _d c8b.json refuse '{"reqid":"c8b","op":"destroy","vm":"vm1","owner_uid":4001}'
  [[ "$output" == *'run'* ]]                         # reaches dr-vps destroy (which can clear a no-domain broken VM)
  [[ "$output" != *'gate refused'* ]]
}

@test "decide: status is NOT pre-gated -> run even when the gate refuses (pure store read; a broken/undefined VM must stay inspectable)" {
  _d c8c.json refuse '{"reqid":"c8c","op":"status","vm":"vm1"}'
  [[ "$output" == *'run'* ]]                         # reaches `dr-vps status` (ungated store read)
  [[ "$output" != *'gate refused'* ]]
}

@test "decide: exec with gate ok -> run (cmd unrestricted)" {
  _d c9.json ok '{"reqid":"c9","op":"exec","vm":"vm1","cmd":"rm -rf / ; :(){ :|:& };:","owner_uid":4001}'
  [[ "$output" == *'"action": "run"'* && "$output" == *'"op": "exec"'* ]]
}

@test "decide: create with a bad (dash) name -> reject" {
  _d c10.json ok '{"reqid":"c10","op":"create","name":"-x","distro":"fedora44","owner_uid":4001}'
  [[ "$output" == *'reject'* ]]
}

@test "decide: push with a too-large payload -> reject" {
  # 400KB of 'A' base64'd exceeds the 256KiB transfer cap
  b64=$(head -c 400000 /dev/zero | base64 | tr -d '\n')
  _d c11.json ok "{\"reqid\":\"c11\",\"op\":\"push\",\"vm\":\"vm1\",\"remote\":\"/tmp/x\",\"content_b64\":\"$b64\",\"owner_uid\":4001}"
  [[ "$output" == *'reject'* && "$output" == *'too large'* ]]
}

# ---- use-verb lifecycle timeout + type-strict caps ----------

@test "decide: 'use' is a module-level LIFECYCLE mutator (gets 900s lifecycle timeout, not 300s exec)" {
  # a clone-from-snap flattens a multi-GB base then boots -> must not be hard-killed at the tighter exec cap.
  run python3 -c "import sys; sys.path.insert(0,'${DR_VPS_SRC}'); import drvps_rigctl as m; print('use' in m.LIFECYCLE and 'create' in m.LIFECYCLE and 'exec' not in m.LIFECYCLE)"
  [ "$status" -eq 0 ]; [ "$output" = True ]
}

@test "decide: use/create ttl/mem/cpus are TYPE-STRICT -- a JSON bool is rejected, not coerced to 1" {
  # int(True)==1 would silently run --cpus 1; _intcap must reject bool + non-int (hand-planted spool only).
  _d a1.json ok '{"reqid":"a1","op":"use","name":"svcg-x","snap":"drvps-snap-v1-1-abc","owner_uid":4030,"cpus":true}'
  [[ "$output" == *'reject'* && "$output" == *'bad cpus'* ]]
  _d a2.json ok '{"reqid":"a2","op":"create","name":"myvm","distro":"fedora44","ttl":true,"owner_uid":4001}'
  [[ "$output" == *'reject'* && "$output" == *'bad ttl'* ]]
  _d a3.json ok '{"reqid":"a3","op":"create","name":"myvm","distro":"fedora44","mem":"512","owner_uid":4001}'
  [[ "$output" == *'reject'* && "$output" == *'bad mem'* ]]
}

@test "decide (S1a): create/destroy/recreate/exec/push/pull/console-dump WITHOUT owner_uid -> REJECTED (fail-closed)" {
  for spec in \
    'create|"name":"v","distro":"fedora44"' \
    'destroy|"vm":"drvps-vm-abc"' \
    'recreate|"vm":"drvps-vm-abc"' \
    'exec|"vm":"drvps-vm-abc","cmd":"id"' \
    'pull|"vm":"drvps-vm-abc","remote":"/f"' \
    'console-dump|"vm":"drvps-vm-abc"' \
    'push|"vm":"drvps-vm-abc","remote":"/f","content_b64":"QQ=="' ; do
    op="${spec%%|*}"; rest="${spec#*|}"
    _d z.json ok "{\"reqid\":\"z\",\"op\":\"$op\",$rest}"
    [[ "$output" == *'"action": "reject"'* && "$output" == *'owner'* ]] || { echo "op=$op NOT fail-closed: $output"; false; }
  done
}

@test "decide (S1a): reads (list/status/inspect/wait) do NOT require owner_uid + get NO --owner" {
  for op in list status inspect wait; do
    _d z.json ok "{\"reqid\":\"z\",\"op\":\"$op\",\"vm\":\"drvps-vm-abc\"}"
    [[ "$output" == *'"action": "run"'* && "$output" != *'--owner'* ]] || { echo "read op=$op wrong: $output"; false; }
  done
}

@test "decide (S1b): create/use thread --class; default throwaway; bad class rejected" {
  _d z.json ok '{"reqid":"z","op":"create","name":"n","distro":"fedora44","owner_uid":7,"class":"service"}'
  [[ "$output" == *'--class'* && "$output" == *'service'* ]]
  _d z.json ok '{"reqid":"z","op":"create","name":"n","distro":"fedora44","owner_uid":7}'
  [[ "$output" == *'--class'* && "$output" == *'throwaway'* ]]           # default when absent
  _d z.json ok '{"reqid":"z","op":"create","name":"n","distro":"fedora44","owner_uid":7,"class":"bogus"}'
  [[ "$output" == *'reject'* && "$output" == *'bad class'* ]]
  _d z.json ok '{"reqid":"z","op":"use","name":"n","snap":"drvps-snap-v1-1-abc","owner_uid":7,"class":"service"}'
  [[ "$output" == *'--class'* && "$output" == *'service'* ]]
}

# ---- S4 idempotency keys: decide()-level validation (pure; the journal itself is loop-side) ----

@test "decide: S4 -- a valid idem on create is ACCEPTED and carried on the action (idem + owner_uid)" {
  _d i1.json ok '{"reqid":"i1","op":"create","name":"myvm","distro":"fedora44","owner_uid":4001,"idem":"deploy-1"}'
  [[ "$output" == *'"action": "run"'* ]]
  [[ "$output" == *'"idem": "deploy-1"'* ]]
  [[ "$output" == *'"owner_uid": 4001'* ]]
}

@test "decide: S4 -- idem is accepted on ALL six mutators (create/use/recreate/destroy/snapshot/snap-rm)" {
  _d i2.json ok '{"reqid":"i2","op":"use","name":"v","snap":"drvps-snap-v1-1-abc","owner_uid":4001,"idem":"k"}'
  [[ "$output" == *'"action": "run"'* && "$output" == *'"idem": "k"'* ]]
  _d i3.json ok '{"reqid":"i3","op":"recreate","vm":"vm1","owner_uid":4001,"idem":"k"}'
  [[ "$output" == *'"action": "run"'* && "$output" == *'"idem": "k"'* ]]
  _d i4.json ok '{"reqid":"i4","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"k"}'
  [[ "$output" == *'"action": "run"'* && "$output" == *'"idem": "k"'* ]]
  _d i5.json ok '{"reqid":"i5","op":"snapshot","vm":"vm1","owner_uid":4001,"idem":"k"}'
  [[ "$output" == *'"action": "run"'* && "$output" == *'"idem": "k"'* ]]
  _d i6.json ok '{"reqid":"i6","op":"snap-rm","snap":"drvps-snap-v1-1-abc","owner_uid":4001,"idem":"k"}'
  [[ "$output" == *'"action": "run"'* && "$output" == *'"idem": "k"'* ]]
}

@test "decide: S4 -- idem on a NON-mutator (exec/list/wait) is REJECTED (explicit contract, never silently ignored)" {
  _d i7.json ok '{"reqid":"i7","op":"exec","vm":"vm1","cmd":"true","owner_uid":4001,"idem":"k"}'
  [[ "$output" == *'reject'* && "$output" == *'idem not supported'* ]]
  _d i8.json ok '{"reqid":"i8","op":"list","idem":"k"}'
  [[ "$output" == *'reject'* && "$output" == *'idem not supported'* ]]
  _d i9.json ok '{"reqid":"i9","op":"wait","vm":"vm1","idem":"k"}'
  [[ "$output" == *'reject'* && "$output" == *'idem not supported'* ]]
}

@test "decide: S4 -- a hostile idem key (bad charset / over-length / non-string) is REJECTED" {
  _d iA.json ok '{"reqid":"iA","op":"destroy","vm":"vm1","owner_uid":4001,"idem":"../etc/x"}'
  [[ "$output" == *'reject'* && "$output" == *'bad idem'* ]]
  big=$(printf 'k%.0s' {1..65})
  _d iB.json ok "{\"reqid\":\"iB\",\"op\":\"destroy\",\"vm\":\"vm1\",\"owner_uid\":4001,\"idem\":\"$big\"}"
  [[ "$output" == *'reject'* && "$output" == *'bad idem'* ]]
  _d iC.json ok '{"reqid":"iC","op":"destroy","vm":"vm1","owner_uid":4001,"idem":7}'
  [[ "$output" == *'reject'* && "$output" == *'bad idem'* ]]
}

# ---- S6: use --restore-secrets threads --allow-secret-bearing ONLY for a service-class restore ----
@test "decide: S6 -- use with restore_secrets + class service -> argv threads --allow-secret-bearing" {
  _d s6a.json ok '{"reqid":"s6a","op":"use","name":"v","snap":"drvps-snap-v1-1-abc","owner_uid":4001,"class":"service","restore_secrets":true}'
  [[ "$output" == *'"action": "run"'* ]]
  [[ "$output" == *'allow-secret-bearing'* ]]
}

@test "decide: S6 -- use with restore_secrets but NOT class service -> REJECTED (never threads the bypass)" {
  _d s6b.json ok '{"reqid":"s6b","op":"use","name":"v","snap":"drvps-snap-v1-1-abc","owner_uid":4001,"restore_secrets":true}'
  [[ "$output" == *'reject'* ]]
  [[ "$output" == *'service'* ]]
  [[ "$output" != *'allow-secret-bearing'* ]]
}

@test "decide: S6 -- a normal use (no restore_secrets) NEVER threads --allow-secret-bearing (regression)" {
  _d s6c.json ok '{"reqid":"s6c","op":"use","name":"v","snap":"drvps-snap-v1-1-abc","owner_uid":4001,"class":"service"}'
  [[ "$output" == *'"action": "run"'* ]]
  [[ "$output" != *'allow-secret-bearing'* ]]
}
