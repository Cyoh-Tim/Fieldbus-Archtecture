# Fuzz harness audit — 2026-09-29

내부 게이트. **인증이 아니다** (≠ PI / ODVA / Modbus.org / Mitsubishi / ISASecure).
PROFINET **CC-B RT Class 1 only** (IRT / CC-C 없음). SLMP **Binary 3E only**.
PREEMPT_RT 없음.

Follow-up to the v0.2.0 1h campaign (`fuzz_longrun_20260929.md`) and the
stateful `fuzz_eip_io` fix (`fuzz_eip_io_harness_20260929.md`, squash
`3835459`). Baseline is that 1h run on the old harnesses:

| Target | 1h cov | 1h ft | llvm-cov lines (protocol src, `-runs=0` on that corpus) |
|--------|-------:|------:|---------------------------------------------------------|
| `fuzz_mb_adu` | 186 | 399 | `mb_stack.c` **30.23%** (`handle_pdu` 97.96%) |
| `fuzz_slmp_request` | 268 | 545 | `slmp_stack.c` **25.56%** (`handle_request` 96.39%) |
| `fuzz_eip_encap` | 320 | 386 | encap 72.40% / cip 17.54% / **cm 0%** / sec 1.98% |

libFuzzer `cov`/`ft` are 8-bit edge counters in the current binary (harness
+ stack). llvm-cov is source line coverage of the protocol `.c` files.

## Why they plateaued

### `fuzz_mb_adu`

`mb_stack_handle_adu` parses **one** MBAP ADU. The 1h corpus already drove
every implemented FC (01–06, 0F, 10, 16, 17) plus exception builders —
`handle_pdu` was **97.96% lines / 98.94% regions** before this change.
libFuzzer’s 186 edges were the PDU handler saturating, not missing FCs.

Unreachable from this harness (and still unreachable): TCP listen / accept /
idle-drop / `serve_client` reassembly, and the whole client role
(`mb_stack_client_*`). Those are ~70% of `mb_stack.c`. FC **0x08 diagnostics**
and **0x2B MEI** have no `case` — they are the `default` illegal-function
path (intentionally wrapped as seeds).

### `fuzz_slmp_request`

`slmp_stack_handle_request` only accepts **batch** `0x0401` / `0x1401` with
sub `0x0000` (word) or `0x0001` (bit). Random `0x0403` / `0x1402` and monitor
registration (`0x0801`) are parsed then rejected with `SLMP_END_CMD` — there
is no handler to reach. The 1h corpus already hit `handle_request` at
**96.39% lines**. Remaining file coverage is TCP client/server/poll and
encode helpers used by the client role. ASCII / 4E: `slmp_stack_create`
refuses them (product constraint).

### `fuzz_eip_encap`

This one was a **real reachability hole**, same class as `fuzz_eip_io`.
The old harness stitched a RegisterSession handle into `SendRRData`, but
almost never emitted a valid CIP path (`0x20` class / `0x24` instance /
`0x30` attr). `eip_cip_route_auth` ran, then `handle_object` fell through
to `PATH_DEST`. **`eip_cm.c` 0%**, Identity/Assembly/QoS/LLDP/Security Get
and Set barely touched, HMAC unused. Encaps `ListInterfaces` and
`SendUnitData` have no `case` (invalid-cmd). CIP service `0x0A` is
`ATTR_READONLY` status, not Multiple Service Packet. `Unconnected Send`
`0x52` is defined but not handled (service-not-supported on CM).

## Harness changes

Input **byte 0 `mod 8`** selects a mode (legacy SHA units still run as raw
when the first byte happens to be 0). Dictionaries:
`tests/fuzz/dict/{mb_adu,slmp_request,eip_encap}.dict`. Named seeds
`tests/fuzz/corpus/*/mode*.bin`. Weekly `fuzz-weekly.yml` already glob-picks
those dicts. Per-PR `fuzz` job stays **~60 s** and now passes the new dicts.

| Target | modes |
|--------|--------|
| `fuzz_mb_adu` | 0 raw/multi-ADU stream · 1 wrap implemented FC · 2 FC 0x16/0x17 · 3 illegal FC (0x08/0x2B/…) · 4 exceptions · 5 unit/proto mismatch · 6 write-then-read · 7 packed multi-ADU |
| `fuzz_slmp_request` | 0 raw · 1 batch word read (D/W/R/ZR/…) · 2 batch word write · 3 bit r/w · 4 random/monitor → `END_CMD` · 5 bad device/sub · 6 qty overflow / short write · 7 write-then-read |
| `fuzz_eip_encap` | 0 raw + session stitch · 1 GetAttr Single (Identity/MR/Assembly/TCPIP/QoS/Port/Security/LLDP) · 2 GetAttr All / Reset / 0x52 / 0x0A · 3 SetAttr · 4 FO / Large FO / Close · 5 ListIdentity/Services/Interfaces/NOP · 6 Unregister / SendUnitData · 7 `protection_mode=1` + `security_class=1` HMAC |

Three Adapter stacks for Encaps: open, `protection_mode=1`, integrity
class 1 + PSK.

## 30 min campaign (ASan/UBSan libFuzzer)

clang 18, `-fsanitize=fuzzer,address,undefined`, `-dict=…`, parallel,
2026-09-29 ~07:34–08:05 UTC. **No crash / timeout / OOM** (empty artifact dir).

| Target | Time | execs | exec/s | cov before (1h) | cov after | ft before | ft after | crashes |
|--------|-----:|------:|-------:|----------------:|----------:|----------:|---------:|--------:|
| `fuzz_mb_adu` | 1801 s | 5.333e8 | 296097 | 186 | **342** | 399 | **1368** | 0 |
| `fuzz_slmp_request` | 1801 s | 6.667e8 | 370199 | 268 | **321** | 545 | **735** | 0 |
| `fuzz_eip_encap` | 1801 s | 1.942e8 | 107832 | 320 | **1070** | 386 | **1861** | 0 |

Merge onto committed seeds (`-merge=1`, SHA units renamed `*.bin`):
mb +271 files / +989 features / +102 edges; slmp +107 / +492 / +137;
eip +100 / +295 / +210.

`cov`/`ft` include the new harness CFG. For Modbus/SLMP that is most of the
jump — the PDU functions were already maxed. For Encaps the jump is stack
code (`eip_cm` + `eip_cip` Get/Set/FO).

## llvm-cov line coverage (protocol sources)

Same method as baseline: coverage-mapped fuzzer, `-runs=0` on the corpus.

### Modbus (`stacks/modbus/src/mb_stack.c`)

| | Lines | `handle_pdu` lines |
|--|------:|-------------------:|
| before | 30.23% (309/1022) | 97.96% |
| after | 30.23% (309/1022) | 97.96% |

Remaining: TCP server/client, `poll`, map `read_*`/`write_*` APIs, destroy.
Not reachable without sockets or extra harness entry points.

### SLMP (`stacks/slmp/src/slmp_stack.c`)

| | Lines | `handle_request` lines |
|--|------:|-----------------------:|
| before | 25.56% (261/1021) | 96.39% |
| after | 25.56% (261/1021) | 96.39% |

Remaining: TCP, client encode (`slmp_stack_read_bytes` 0% — batch path uses
word/bit APIs), ASCII/4E create-fail (out of scope). Random/monitor stay
`SLMP_END_CMD` by design.

### EtherNet/IP (`stacks/ethernetip/src/`)

| File | before lines | after lines |
|------|-------------:|------------:|
| `eip_encap.c` | 72.40% | **82.20%** |
| `eip_cip.c` | 17.54% | **79.43%** (`handle_object` 11.68% → 83.48%) |
| `eip_cm.c` | 0.00% | **75.00%** (all 9 functions hit) |
| `eip_sec.c` | 1.98% | **17.23%** (UCMM HMAC; TLS still 0%) |
| `eip_crypto.c` | 0.00% | **100%** |
| `eip_path_asm.c` | 38.40% | 46.41% |
| `eip_stack.c` | 13.96% | 15.84% |
| `eip_io.c` | 0.00% | 0.00% (this target is Encaps, not UDP I/O) |
| `eip_lldp.c` | 0.00% | 0.00% (TX on poll; not Encaps) |
| **TOTAL** | 19.73% | **45.21%** |

`eip_cip_route` (unauth) still 0% — Encaps always passes session+secure auth
flags. TLS (`security_class=2`) and originator `eip_client.c` not in this
binary’s object set / not driven.

## PROFINET (note only — harnesses unchanged)

`-runs=0` on current corpora, same gaps as the 1h report:

**`fuzz_pn_eth`** (libFuzzer ~386 cov): `pn_dcp.c` 80.70%, `pn_eth.c` 26.53%,
`pn_stack.c` 28.86%, **`pn_rt.c` 3.36%**. Frames must match the station MAC
or DCP multicast (`01:0E:CF:00:00:00`) and Ethertype `0x8892`. RTC1 is only
dispatched when dest MAC is ours **and** an AR exists — the harness never
Connects, so cyclic RT stays dark. `security_class=0` → DCP Set HMAC
(`pn_sec.c` / `pn_crypto.c`) 0%. LLDP/SNMP TX not injected.

**`fuzz_pn_rpc`** (libFuzzer ~464 cov): `pn_rpc.c` 77.36%, `pn_record.c`
34.29%, **`pn_sec.c` 0%**. No Connect → Write/PrmEnd → ApplicationReady
state machine in the harness (the 1h corpus already stumbled into some
record/RPC paths). Security Class 1 HMAC Connect is untested because the
stack is created with `security_class=0`. CC-C / IRT remain out of scope.

## Bugs

None. No crash reproducers, no stack fix, no new unit tests.

## Local gates

- `ctest --test-dir build -LE soak_ci`: **84/84**
- ASan+UBSan `ctest --test-dir build-san`: **85/85** (incl. `soak_ci`)

## CI

Per-PR `fuzz` job: ~60 s/target + new dicts. Weekly campaign unchanged
except it will pick up `mb_adu.dict` / `slmp_request.dict` / `eip_encap.dict`
automatically.
