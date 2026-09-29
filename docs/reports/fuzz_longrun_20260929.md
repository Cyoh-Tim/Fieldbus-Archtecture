# libFuzzer long-run — 2026-09-29

내부 게이트. **인증이 아니다** (≠ PI / ODVA / Modbus.org / Mitsubishi / ISASecure).
PROFINET **CC-B RT Class 1 only** (IRT / CC-C 없음). PREEMPT_RT 없음.

Campaign on `v0.2.0` / `main` @ `93ce7ec` (CI green). Same CMake as the CI
`fuzz` job: clang 18.1.3, `-fsanitize=fuzzer,address,undefined`,
`-timeout=5`, seed corpora under `tests/fuzz/corpus/` (committed `.bin` +
`python3 tests/fuzz/gen_corpus.py`). Six targets in parallel on a 4-core
VM, `-max_total_time=3600` each. No code change on the tag.

## Results

Wall clock **3600 s** per target (01:32:32–02:32:33 UTC). All exit 0.
**No crash, timeout, or OOM** (empty `artifact_prefix` dirs).

| Target | Duration | execs | exec/s | cov | ft | corp (end) | crashes |
|--------|----------|------:|-------:|----:|---:|------------|--------:|
| `fuzz_mb_adu` | 3600 s | 1.939e9 | 538593 | 186 | 399 | 108/1546b | 0 |
| `fuzz_slmp_request` | 3600 s | 1.380e9 | 383314 | 268 | 545 | 138/3842b | 0 |
| `fuzz_eip_encap` | 3600 s | 1.197e9 | 332476 | 320 | 386 | 58/2420b | 0 |
| `fuzz_eip_io` | 3600 s | 1.277e9 | 354567 | 38 | 154 | 33/2197b | 0 |
| `fuzz_pn_eth` | 3600 s | 7.119e8 | 197694 | 386 | 975 | 194/16Kb | 0 |
| `fuzz_pn_rpc` | 3600 s | 6.491e8 | 180242 | 464 | 1310 | 226/66Kb | 0 |

`cov`/`ft`/`corp` are libFuzzer DONE-line counters (ASan RSS peak 480–573 Mb).

### vs 180 s local run (G9, 2026-09-28)

| Target | cov 180 s | cov 3600 s | Δ cov |
|--------|----------:|-----------:|------:|
| `fuzz_mb_adu` | 186 | 186 | 0 |
| `fuzz_slmp_request` | 268 | 268 | 0 |
| `fuzz_eip_encap` | 160 | 320 | +160 |
| `fuzz_eip_io` | 38 | 38 | 0 |
| `fuzz_pn_eth` | 248 | 386 | +138 |
| `fuzz_pn_rpc` | 415 | 464 | +49 |

`eip_encap` / `pn_eth` / `pn_rpc` grew edge coverage. `mb_adu` / `slmp_request`
/ `eip_io` plateaued on edges but still added feature units and reduced
inputs (useful CI seeds).

## Minimized corpus merge

Grown units were merged onto the committed seeds (`-merge=1`). New files
are SHA-named `*.bin` (gitignore keeps only `*.bin`). Original named seeds
(`fc03.bin`, `ndr_u32max.bin`, …) unchanged.

| Target | seeds before | new files | new features | new edges (vs seeds) | files after |
|--------|-------------:|----------:|-------------:|---------------------:|------------:|
| `mb_adu` | 3 | 94 | 335 | 130 | 97 |
| `slmp_request` | 4 | 110 | 465 | 158 | 114 |
| `eip_encap` | 4 | 47 | 252 | 195 | 51 |
| `eip_io` | 2 | 30 | 121 | 6 | 32 |
| `pn_eth` | 4 | 153 | 733 | 170 | 157 |
| `pn_rpc` | 4 | 187 | 1076 | 243 | 191 |

`v0.2.0` remains `93ce7ec`. No stack fix in this follow-up (nothing to
promote to v0.2.1).
