# PROFINET fuzz harness (stateful AR / RTC1 / Sec1) — 2026-09-29

내부 게이트. **인증이 아니다** (≠ PI / ODVA / ISASecure).
PROFINET **CC-B RT Class 1 only** (IRT / CC-C 없음). PREEMPT_RT 없음.
No PI test-tool code.

Follow-up to the v0.2.0 1h campaign (`fuzz_longrun_20260929.md`) and the
harness audit (`fuzz_harness_audit_20260929.md`, squash `d1d47003`). Same
pattern as `fuzz_eip_io`: a valid prefix first, then the leftover bytes as
the fuzzed request.

## Why pn_rt ≈ 3% and pn_sec = 0%

The old harnesses called `pn_stack_handle_rpc` / `pn_stack_handle_eth` on a
mock Device with **no AR**.

- RTC1 (`pn_rt_on_frame`) only runs when dest MAC is the station MAC, an AR
  is up, and FrameID equals `AR.out_frame_id`. Without Connect + IOCR the
  cyclic path stayed dark (`pn_rt.c` **3.36%** lines).
- DCP Set HMAC and Connect HMAC (`pn_sec.c`) need `security_class>=1` and a
  PSK. The old stacks were created with class 0 → **0%**.
- Write / PrmEnd / ApplicationReady / Release never ran as a sequence.

1h libFuzzer (old harness): `fuzz_pn_eth` cov=386 ft=975; `fuzz_pn_rpc`
cov=464 ft=1310.

## Harness

`tests/fuzz/fuzz_pn_rpc.c` and `fuzz_pn_eth.c` keep three stacks:

| stack | `security_class` | `enforce_security_class` | PSK |
|-------|-----------------:|-------------------------:|-----|
| `g_open` | 0 (lab unsigned) | 0 | no |
| `g_sec` | 1 | 0 | yes (`0x11`×32) |
| `g_enf` | 1 | 1 | yes |

Connect body is AR UUID + IOCR INPUT/OUTPUT (send clock / reduction /
data-hold / FrameID 0x8001/0x8002) + AlarmCR + ExpectedSubmodule. HMAC is
over the blocks excluding `PN_BLOCK_SEC_INT` (same recipe as CTT, not a PI
tool clone). DCP HMAC is over the unsigned payload, then option `0xF0/0x01`.

Input **byte 0 `mod 8`** selects the stage. Remaining bytes mutate IOCR
fields / HMAC / the follow-up PDU.

### `fuzz_pn_rpc`

| mode | action |
|------|--------|
| 0 | raw `handle_rpc` (legacy corpus) |
| 1 | Connect (mutated IOCR) then leftover bytes as the next RPC |
| 2 | Write parameter record (I&M / 0x8000) |
| 3 | Read I&M |
| 4 | Write → PrmEnd → queued ApplicationReady |
| 5 | PrmEnd + ApplicationReady control + raw follow-up |
| 6 | Release then re-Connect |
| 7 | `g_sec` / `g_enf`: HMAC missing / bad / ok Connect + Write + PrmEnd |

### `fuzz_pn_eth`

| mode | action |
|------|--------|
| 0 | dest-MAC stitch (station unicast or DCP MC `01:0E:CF:00:00:00`) |
| 1 | DCP Identify All on multicast |
| 2 | Identify name + Get + unsigned Set / IP / Signal + Hello |
| 3 | DCP Set HMAC on `g_sec`/`g_enf` (missing / bad / ok) |
| 4 | AR + RTC1 O→T (FrameID 0x8002, dest = station MAC) + poll |
| 5 | PrmEnd + RTC1 + poll (produce / watchdog) |
| 6 | Alarm TX High/Low + inject Alarm High/Low looking frames |
| 7 | stitch + RTC1 + signed DCP Set on both Sec1 stacks |

Seeds: `tests/fuzz/corpus/{pn_rpc,pn_eth}/mode*.bin` (plus the 1h SHA
units). Dictionaries: `tests/fuzz/dict/pn_rpc.dict`, `pn_eth.dict`.

Per-PR `fuzz` job stays **~60 s** and now passes those dicts. Weekly
`fuzz-weekly.yml` already glob-picks `tests/fuzz/dict/${corpus}.dict`.

## Local run (ASan/UBSan libFuzzer)

clang 18.1.3, `-fsanitize=fuzzer,address,undefined`, `-dict=…`,
`-max_total_time=1800`, `-timeout=5`. Parallel on a 4-core VM.
2026-09-29 12:04:29–12:34:30 UTC. **No crash / timeout / OOM** (empty
artifact dirs). Stack `LOG_*` filtered from the campaign logs (otherwise
PrmEnd/DCP Set floods stderr).

| Target | Time | execs | exec/s | cov before (1h) | cov after | ft before | ft after | crashes |
|--------|-----:|------:|-------:|----------------:|----------:|----------:|---------:|--------:|
| `fuzz_pn_eth` | 1801 s | 8.040e7 | 44643 | 386 | **1181** | 975 | **2424** | 0 |
| `fuzz_pn_rpc` | 1801 s | 1.944e8 | 107925 | 464 | **826** | 1310 | **1896** | 0 |

libFuzzer `cov`/`ft` are 8-bit edge counters in the **current** binary
(harness + stack). The jump is mostly newly reachable stack edges
(Connect/IOCR, RTC1 consume/produce, HMAC, alarm TX), plus harness modes.

20 s smoke already sat at eth cov=1144 / rpc cov=807 — the 30 min campaign
added features more than raw edges (eth ft 2239→2424, rpc ft 1500→1896).

## llvm-cov line coverage (`stacks/profinet/src`)

Same method as the audit: coverage-mapped fuzzer,
`-fprofile-instr-generate -fcoverage-mapping`, `-runs=0` on the corpus.
**Before** = old harness + 1h corpus (`fuzz_harness_audit_20260929.md`).
**After** = this harness + merged corpus.

### `fuzz_pn_eth`

| File | before lines | after lines |
|------|-------------:|------------:|
| `pn_rt.c` | **3.36%** | **60.50%** (72/119). `pn_rt_on_frame` 90.48%; `pn_rt_send_if_due` 74%. `pn_ar_abort` still 0% — data-hold abort needs wall-clock silence after PrmEnd, not a single `poll`. |
| `pn_sec.c` | **0.00%** | **73.33%** (33/45). All 3 functions hit (`pn_sec_hmac` / `pn_sec_ok` / `pn_alarm_send_dummy`). |
| `pn_dcp.c` | 80.70% | **94.87%** (462/487). `pn_dcp_on_frame` / `pn_dcp_verify_set` 100%; `dcp_require_integrity` 100%. Remaining: delayed Identify TX, some `wr_*` overflow branches. |
| `pn_rpc.c` | (eth did not Connect) | 50.91% (Connect + PrmEnd from the ETH harness prefix) |
| `pn_stack.c` | 28.86% | 47.97% |
| **TOTAL** (protocol `.c`) | — | **58.45%** |

### `fuzz_pn_rpc`

| File | before lines | after lines |
|------|-------------:|------------:|
| `pn_rpc.c` | 77.36% | **83.88%** (463/552). `pn_rpc_handle` 90.05%; `parse_ar_iocr` **100%** lines; `verify_connect_sec` 80.43%; `queue_app_ready` 100%. Unreachable: `pn_rpc_poll` / `flush_pending_rpc` (UDP `sendto`, not mock). |
| `pn_sec.c` | **0.00%** | **22.22%** (HMAC only; alarm TX is ETH). |
| `pn_record.c` | 34.29% | **85.71%** |
| `pn_rt.c` / `pn_dcp.c` | n/a | 0% (this target does not inject Ethernet frames) |
| **TOTAL** | — | 42.10% |

### Combined (both profiles)

Union of the two `-runs=0` runs, so one number for “did any PN fuzzer hit
this file”:

| File | combined lines |
|------|---------------:|
| `pn_rt.c` | **60.50%** |
| `pn_sec.c` | **73.33%** |
| `pn_rpc.c` | **84.60%** |
| `pn_dcp.c` | **94.87%** |
| protocol src TOTAL | **73.84%** (1482/2007) |

## Minimized corpus merge

Grown units merged onto the committed seeds (`-merge=1`). SHA names without
an extension were renamed to `*.bin` (gitignore keeps only `*.bin`). Named
`mode*.bin` / `dcp_*.bin` / `hdr.bin` seeds kept.

| Target | git seeds (this PR, pre-campaign) | merge new files | new features | new edges | `*.bin` after |
|--------|----------------------------------:|----------------:|-------------:|----------:|--------------:|
| `pn_rpc` | 202 | 48 unique vs dest (295 `.bin` newly tracked, incl. 20 s smoke SHA) | 302 | 10 | 497 |
| `pn_eth` | 169 | 82 unique vs dest (223 `.bin` newly tracked) | 201 | 52 | 392 |

## Bugs

None. No crash reproducers, no stack fix, no new unit tests.

Remaining by design / out of harness scope:

- `pn_ar_abort` (CMI / data-hold timeout) — needs real time, not libFuzzer
  iterations.
- `pn_rpc_poll`, AF_PACKET `pn_eth_open`, SNMP, IRT / CC-C.
- `strip_sec_cb` in `pn_rpc.c` is unused (Connect HMAC walks blocks inline).

## Local gates

- `ctest --test-dir build -LE soak_ci`: **84/84**
- ASan+UBSan `ctest --test-dir build-san`: **85/85** (incl. `soak_ci`)

## CI

Per-PR `fuzz` job: ~60 s/target + `pn_eth.dict` / `pn_rpc.dict`. Weekly
campaign unchanged (already glob-picks those dicts).
