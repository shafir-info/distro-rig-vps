# drvps-top-share canonical feed fixtures (schema v1)

The SOURCE OF TRUTH for the feed schema (CONCEPT-DRVPS-TOP-SHARE.md sec 5/5.1). Both the Python
publisher and the Python viewer are tested against these. `.feed` files are TAB-separated
(0x09), LF-terminated, printable-ASCII 0x20..0x7e only. Below each field is enumerated with a
concrete value so the field COUNT/ORDER is unambiguous. `<TAB>` = a single 0x09.

## Canonical VALID feed -- `valid-ownernone.feed` (ownerpolicy=no)
H record -- EXACTLY 24 fields incl the `H` tag:
```
H  ver=1                 (literal token order below; shown key=value only for clarity)
 1 H
 2 1                     ver (==1)
 3 pub-a1b2c3            instance  [A-Za-z0-9_-]{1,32}
 4 42                    seq       0..2^63-1, monotonic per run
 5 1783960000            realtime_s (display only)
 6 5300000000000         boottime_ns (publish boottime; drives staleness)
 7 3000                  interval_ms 100..3600000
 8 ok                    db_status     {ok,stale,down}
 9 5300000000000         db_boottime_ns (0 iff db_status=down)
10 ok                    libvirt_status {ok,stale,down}
11 5300000000000         libvirt_boottime_ns (0 iff down)
12 ok                    stats_status   {ok,partial,down}
13 5300000000000         stats_boottime_ns (0 iff down)
14 2                     row_count 0..4096 (== #V lines == E.row_count)
15 0  16 0  17 0  18 0  19 0  20 0   c_absent c_uuid c_name c_untracked c_other c_ledger (0..65535)
21 4880                  load1_milli 0..1000000
22 39000000              memavail_kib
23 8                     host_cpu_count 1..4096
24 no                    ownerpolicy {no,uid,name-and-uid}
```
V record -- EXACTLY 12 fields incl the `V` tag (13 iff ownerpolicy!=no):
```
 1 V
 2 normal                reconcile_class {normal,absent,uuid,name,untracked,uuidbad,unreconciled}
 3 drvps-vm-b71deae19298de23   vm_id  ^drvps-vm-[0-9a-f]{16}$  NON-EMPTY, FRAME-UNIQUE
 4 weftg-x-P05           vm_name  sanitized, <=64, never empty ('-' placeholder if empty)
 5 running               store_state  OPAQUE bounded text <=16 (or 'unknown')
 6 running               live_state {running,paused,shutoff,crashed,blocked,shutdown,pmsuspended,unknown,--}
 7 throwaway             class {throwaway,service,--}
 8 golden:fedora44@bc07c9f7   base_flag ^(golden:[a-z0-9]{1,16}@[0-9a-f]{8}|snapshot|orphan|unknown)$
 9 1783959000            created_epoch 0..2^63
10 3123                  cpu_tenths 0..1000000 | '--'   (3123 = 312.3%)
11 1572864               ram_cur_kib 0..2^63 | '--'
12 1572864               ram_max_kib 0..2^63 | '--'
```
Row 2 (snapshot-backed, opaque base): `V normal drvps-vm-15685c946b87396b weftg-x-P06 running running throwaway snapshot 1783959100 71 1048576 1572864`
E record -- EXACTLY 4 fields incl `E`: `E  pub-a1b2c3  42  2`  (instance+seq == H; row_count == #V)

## Other VALID fixtures
- `valid-owneruid.feed` (ownerpolicy=uid): H field 24 = `uid`; each V has a 13th field
  owner_display = a numeric uid (e.g. `1008`), <=64.
- `valid-libvirt-down.feed`: H libvirt_status=down, libvirt_boottime_ns=0, stats_status=down,
  stats_boottime_ns=0; every V: reconcile_class=`unreconciled`, live_state=`unknown`,
  cpu/ram all `--`; c_* counters all 0 (anomalies not asserted while a source is not ok).
- `valid-stats-partial.feed`: db+libvirt ok; stats_status=partial; some V rows cpu/ram=`--`.
- `valid-empty.feed`: no VMs -> row_count=0, no V lines, `E ... 0`. (A rig with zero VMs; all
  statuses may be `ok`.)
- `valid-nothing-acquired.feed`: status-only -> db_status=down, libvirt_status=down,
  stats_status=down, row_count=0. Viewer shows "acquiring / down", NOT "empty rig".

## INVALID fixtures (viewer MUST reject -> keep last frame + fixed error; publisher MUST never emit)
- `invalid-dup-id.feed`        two V rows with the same vm_id.
- `invalid-count-mismatch.feed` E.row_count != actual #V lines (or != H.row_count).
- `invalid-instance-mismatch.feed` E.instance/seq != H.
- `invalid-bad-vmid.feed`      vm_id not matching `^drvps-vm-[0-9a-f]{16}$`.
- `invalid-bad-livestate.feed` live_state token outside the enum.
- `invalid-short-v.feed`       a V line with 11 fields under ownerpolicy=no (wrong count).
- `invalid-h-field-count.feed` H with != 24 fields.
- `invalid-badnum.feed`        cpu_tenths=`+3` (leading +) / `03` (leading zero) / `1e3` (exponent).
- `invalid-oversize.feed`      > 262144 bytes (or > 4096 V rows).
- `invalid-nul.feed`           contains a NUL byte.
- `invalid-cr.feed`            contains a CR (0x0d).
- `invalid-nonascii.feed`      contains a byte outside 0x20..0x7e.
- `invalid-tab-in-name.feed`   a vm_name containing an embedded TAB (would shift fields) -- proves
                               the publisher's canonicalizer (`?`) prevents this at the source.
- `invalid-esc-in-name.feed`   a vm_name containing ESC (0x1b) -- proves it cannot move the cursor.
- `invalid-trailing.feed`      bytes after the E line / missing final `\n` / a blank line.

## Notes
- Numeric grammar: `0` or `[1-9][0-9]*`; no `+`/leading-zero/whitespace/exponent; `--` is the only
  non-numeric in cpu/ram_*. base_flag distro component is itself sanitized [a-z0-9]{1,16}.
- AGE is computed by the VIEWER from H.realtime_s - V.created_epoch (publisher never pre-computes).
- load shown by the viewer as load1_milli/1000 over host_cpu_count.
- A hostile feed is a TEST artifact via ${DRVPS_TOP_FEED}; production feeds come only from the
  trusted publisher through the sec-7.3 config-anchored fstat gate.
