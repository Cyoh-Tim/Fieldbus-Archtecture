# fuzz_eip_io harness + weekly CI — 2026-09-29

내부 게이트. **인증이 아니다.** PROFINET CC-B RT1 only. PREEMPT_RT 없음.

## Why cov=38

The v0.2.0 long-run (`fuzz_longrun_20260929.md`) left `fuzz_eip_io` at
**cov=38 / ft=154** after 3600 s (~1.28e9 execs). The harness called
`eip_stack_handle_io` on a mock Adapter that never `RegisterSession` /
`Forward Open`. `eip_io_handle_udp` parsed CPF items, then looked up
`o2t_conn_id` in an empty Class 1 table → `-ENOENT`. Consume, produce,
watchdog, and CM close paths were unreachable.

## Harness

`tests/fuzz/fuzz_eip_io.c` now keeps a live exclusive-owner Class 1
connection (assemblies 100/101/150, 8+8 bytes). Input byte 0 selects:

| mode | action |
|------|--------|
| 0 | stitch live O→T id into CPF, else wrap seq+image |
| 1 | always wrap a well-formed Class 1 frame |
| 2 | raw `handle_io` (legacy seeds / miss path) |
| 3 | SendRR with registered session |
| 4 | Forward Close then re-open |
| 5 | `eip_stack_poll` (produce); `0xff` → 1 µs RPI + watchdog |
| 6 | other Encaps (Register / Unregister / SendUnit) |
| 7 | Large Forward Open + I/O |

Seeds: `tests/fuzz/corpus/eip_io/mode*.bin` (plus existing `seq_data.bin`).
Dictionary: `tests/fuzz/dict/eip_io.dict`.

## Local run (ASan/UBSan libFuzzer)

clang 18, `-fsanitize=fuzzer,address,undefined`, `-dict=tests/fuzz/dict/eip_io.dict`.

| | Time | execs | cov | ft | crashes |
|--|------|------:|----:|---:|--------:|
| before (v0.2.0 1h) | 3600 s | 1.277e9 | 38 | 154 | 0 |
| after 20 s smoke | 20 s | 2.58e6 | **1147** | **2704** | 0 |
| after 45 min | *running* | | | | |

20 s already leaves the 38-edge plateau (FO + consume + poll/produce).

## Weekly CI

`.github/workflows/fuzz-weekly.yml`: cron Sunday 23:00 KST (`0 14 * * 0` UTC)
+ `workflow_dispatch`. Matrix of the 6 targets, ~1 h each, seed
`tests/fuzz/corpus/`, upload grown corpus (always) and crash artifacts
(on failure). Job fails on libFuzzer crash. PR `fuzz` job stays ~60 s.
