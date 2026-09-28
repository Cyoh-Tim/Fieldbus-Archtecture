# IEC 62443 coding-level security fixes — 2026-09-28

내부 게이트. **인증이 아니다** (≠ PI / ODVA / Modbus.org / Mitsubishi / ISASecure).
제품 잠금: PROFINET **CC-B RT Class 1 only** (IRT / CC-C permanent non-goal),
SLMP **Binary 3E only**, PREEMPT_RT 없음, 라이선스 Bundle 복제 없음.

대상 요구: IEC 62443-4-1 SI-2 / SVV-3; 62443-4-2 CR 3.5, CR 7.1, CR 7.2, CR 2.1.
위치는 리뷰 리드이며, 각 결함은 코드에서 재확인했다.

## Summary

| ID | Sev | Area | Fix | Regression test | 62443 |
|----|-----|------|-----|-----------------|-------|
| G1 | HIGH | SLMP batch qty / subcmd / device | Bound qty to Binary 3E max; reject unknown subcommand/device; stack array `SLMP_QTY_WORD_MAX` | `test_slmp_stack` (`test_handle_qty_and_unknown`) | 4-1 SI-2; 4-2 CR 3.5, 7.1, 7.2 |
| G2 | MED | EIP Forward Open resource | Arm Class1 watchdog at FO; reject duplicate triad; validate assembly path + o2t/t2o size | `test_eip_stack` (`test_g2_watchdog_dup_path_size`); `ctt_eip_class1_watchdog` | 4-1 SI-2; 4-2 CR 3.5, 7.1, 7.2 |
| G3 | MED | PN IODWriteReq header | `parse_write_req` requires body `blen >= 34` before reading record-data length | `test_pn_rpc` (`test_write_short_block`) | 4-1 SI-2; 4-2 CR 3.5 |
| G4 | MED | PN RPC AR ownership | Reject Connect from another controller while AR up; same sender IP / CMInitiatorObjectUUID may replace; CMI timeout until controller liveness (O→T or PrmEnd/ApplReady), then data-hold (IOCR factor or 3×cycle) on O→T | `test_pn_rpc` (`test_ar_ownership`, `test_ar_timeout_and_replace`, `test_cmi_ignores_own_tx`); `ctt_pn_rpc_cm_without_ar` | 4-1 SI-2; 4-2 CR 2.1, 3.5, 7.1 |
| G5 | MED | EIP Encaps / uninit | `cip_len < 2` reject; SendRR session must be registered **and owned by this TCP/TLS connection** (status `0x64`); drop session on close; unguessable handles; zero-init + check `eip_encap_process` | `test_eip_stack` (`test_g5_encap_session_and_cip_len`, `test_g5_session_owner_and_close`) | 4-1 SI-2; 4-2 CR 2.1, 3.5, 7.2 |
| G9 | — | Fuzz + hardening | libFuzzer harnesses + seed corpora; clang CI ~60 s/target; `-fstack-protector-strong`; `-D_FORTIFY_SOURCE=2` with opt. Fuzz found PN NDR `UINT32_MAX` wrap (fixed) | `.github/workflows/ci.yml` `fuzz` / `sanitizers`; `test_ndr_huge_args_len` | 4-1 SVV-3; 4-2 CR 3.5, 7.1 |

**Out of scope for this PR** (tracked, not fixed here):

| ID | Topic |
|----|--------|
| G6 | Unauthenticated CIP state-changing services (Identity Reset / Set_Attribute without CIP Security Class) |
| G7 | TCP idle timeouts / per-IP connection limits; SLMP non-blocking recv hardening |
| G8 | DCP Set hardening (beyond existing ident/Set.Res path) |

---

## G1 — SLMP batch write/read quantity and unknown codes

**Root cause.** `slmp_stack_handle_request()` copied `qty` words into
`uint16_t words[SLMP_PAYLOAD_MAX/2]` (960). Request cap is 2048 bytes, so a
word write with `qty ≈ 1013` overflowed the stack. Unknown subcommands were
treated as word units; unknown device codes allocated a new map.

**Fix.** Binary 3E limits: word 1–960, bit 1–7168. `qty == 0` or `qty > max`
→ end code `0xC051`. Unknown command/subcommand → `0xC050`. Unknown device
code → `0xC056` (no `map_ensure`). Local arrays sized `SLMP_QTY_WORD_MAX`.

**Test.** `test_slmp_stack` / `test_handle_qty_and_unknown`: qty 0, word 1013,
word read 961, bit 7169, sub `0x0002`, device `0xEE`, spec-max 960 write OK.

**62443.** SI-2 (defensive copy bounds); CR 3.5 (input validation);
CR 7.1 / 7.2 (DoS / stack memory).

---

## G2 — EtherNet/IP Forward Open occupancy

**Root cause.** Class1 watchdog skipped the first timeout while `last_rx_ns == 0`.
A Forward Open with no subsequent IO never armed, so slots in `EIP_CLASS1_CONN_MAX`
stayed occupied. Empty connection path was accepted; duplicate
(connection serial + vendor + originator serial) allocated another slot;
o2t/t2o sizes were not checked against configured assemblies.

**Fix.** Set `last_rx_ns = now` at FO. Reject empty/non-matching assembly path
(`CIP_STATUS_PATH_DEST`). Reject size unless equal to assembly size or size+2
(seq count). Reject duplicate triad (`CIP_STATUS_CONN_FAILURE` / ext `0x0100`).
CTT / `sw_master.py` send a 4-word exclusive-owner path
(`20 04 / 24 cfg / 2C o2t / 2C t2o`). SendRR now requires a registered session,
so CTT `ensure_session()` runs before FO.

**Test.** `test_g2_watchdog_dup_path_size`: dup triad, bad T→O instance, o2t=99,
FO with RPI 100 µs / TM=0 and no IO times out. Existing
`ctt_eip_class1_watchdog` still covers IO-then-silence.

**62443.** CR 3.5 (path/size); CR 7.1 / 7.2 (connection resource reclaim).

---

## G3 — PROFINET IODWriteReq short block

**Root cause.** `parse_write_req()` used `blen >= 30` but read `body+30..33`
(record data length, 4 bytes) → 4-byte OOB on a 30-byte body.

**Fix.** Require `blen >= 34` (seq 2 + ARUUID 16 + API 4 + slot 2 + subslot 2
+ pad 2 + index 2 + dlen 4). Clamp `dlen` to remaining body.

**Test.** `test_pn_rpc` / `test_write_short_block`: 30-byte Write after Connect
is rejected; I&M1 record unchanged.

**62443.** SI-2 / CR 3.5 (length-before-read).

---

## G4 — PROFINET RPC AR ownership

**Root cause.** Connect overwrote `s->ar` while an AR was established.
Release / Control / Write / Read did not check ARUUID or the sender.

**Fix.** Connect while `ar.established` from a **different** controller
returns a PNIO error PDU and keeps the existing AR. A Connect from the
**same** controller (matching sender IPv4, or matching
`CMInitiatorObjectUUID` when present in ARBlockReq) aborts and replaces
the AR so a restarted IO controller is not locked out. Subsequent
Release/Control/Write (and Read **if** an AR is up) require matching
ARUUID and sender IPv4 (`owner_ip` from Connect).
`src_ip == 0` or `owner_ip == 0` skips the IP check so CTT mock
(`pn_stack_handle_rpc` → `src_ip=0`) still works; live UDP `recvfrom` passes
`ntohl(sin_addr)`. Read without an AR remains allowed (device records).
Write without AR stays fail-closed (`ctt_pn_rpc_cm_without_ar`).

**Lifetime.** A controller that vanishes without Release no longer holds
the AR forever. `pn_ar_watchdog()` (from `pn_stack_poll`) keys off
**controller** activity, not the device's own RTC1 transmit:

- Until the controller shows liveness (O→T RTC1 received, or PrmEnd /
  ApplicationReady completed): CMI activity timeout **2 s** without owner
  RPC (Connect/Control/Read/Write) aborts the AR. Device TX does not
  clear this timer.
- After liveness: data-hold on O→T silence. Multiplier is IOCR
  `DataHoldFactor`, else `WatchdogFactor`, else **3 × `cycle_us`**.
- Same-controller Connect (sender IP / CMInitiatorObjectUUID) may replace
  an established AR at any time.

CTT mock soak does not send O→T. `step_soak` issues a periodic IODRead
so the 2 s CMI timer stays fresh (`soak_ci` / nightly). After PrmEnd,
`io_cycle` injects an O→T RTC1 each poll so data-hold sees controller IO.
That is tester traffic, not a stack exception.

**Test.** `test_ar_ownership`: second Connect from another IP, Control/Release
wrong IP or UUID, matching Control/Write/Release.
`test_ar_timeout_and_replace`: other-IP Connect while AR is up is rejected;
after a simulated CMI timeout a new Connect succeeds; data-hold after
`saw_rt` also aborts.
`test_cmi_ignores_own_tx`: Connect, device RTC1 TX, no O→T; backdated CMI
aborts the AR; a different IP may Connect.

**62443.** CR 2.1 (authorization of established AR); CR 3.5; CR 7.1 / 7.2
(AR reclaim).

---

## G5 — EIP Encaps CIP length, session, uninitialized response

**Root cause.** `handle_sendrr` / `eip_sec_check_ucmm` read `cip[0]` when the
Unconnected Data item length was 0. SendRR did not require a registered
session. `service_tcp_client` read `resp+4` after a failed `eip_encap_process`.

**Fix.** Reject `cip_len < 2`. SendRR / UnregisterSession require a session
that is registered **and bound to this TCP/TLS connection** (`owner_id`);
mismatch → Encaps status `0x64` (`EIP_ENCAP_STATUS_INVALID_SESSION`).
RegisterSession stores `(handle, owner_id)`; one session per connection
(re-Register returns the existing handle). Handles are
`counter XOR per-boot secret` via `getrandom(2)` (never 0), not a
predictable 1,2,3 sequence. TCP `service_tcp_client` and TLS `tls_drop`
call `eip_encap_drop_owner` so a disconnect reclaims the table slot.
Mock / CTT `eip_stack_handle_encap` uses `EIP_ENCAP_OWNER_MOCK`; tests
that need a second peer use `eip_stack_handle_encap_owned`. TCP/TLS paths
`memset` the response and only parse/send when `rc == 0 && resp_len` is
sufficient. Failed process clears `*resp_len`.

**Test.** `test_g5_encap_session_and_cip_len`: SendRR with handle `0x11111111`
→ `0x64`; empty CIP item; truncated Encaps → `-EINVAL` and `resp_len == 0`.
`test_g5_session_owner_and_close`: foreign SendRR/Unregister `0x64`; drop
owner reclaims slot; table full at `EIP_CLASS3_SESSIONS_MAX`; handles not
sequential 1,2.

**62443.** CR 2.1 (session); CR 3.5; CR 7.1 / 7.2 (no uninit use; no
session-table DoS).

---

## G9 — libFuzzer harnesses and compile hardening

Harnesses (clang `-fsanitize=fuzzer,address,undefined`):

| Target | Entry |
|--------|--------|
| `fuzz_mb_adu` | `mb_stack_handle_adu` |
| `fuzz_slmp_request` | `slmp_stack_handle_request` |
| `fuzz_eip_encap` | `eip_stack_handle_encap` (stitches registered session onto SendRR) |
| `fuzz_eip_io` | `eip_stack_handle_io` |
| `fuzz_pn_eth` | `pn_stack_handle_eth` |
| `fuzz_pn_rpc` | `pn_stack_handle_rpc` |

Seeds: `python3 tests/fuzz/gen_corpus.py` → `tests/fuzz/corpus/<name>/`.
CI job `fuzz` (~60 s per target). Default compile: `-fstack-protector-strong`;
non-Debug / non-sanitizer / non-fuzzer: `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2`
(RelWithDebInfo default so FORTIFY has `-O2`).

### Local fuzz runs

clang 18, `-fsanitize=fuzzer,address,undefined`, stack libs built with
`-fsanitize=fuzzer-no-link`. 180 s per target, seed corpora under
`tests/fuzz/corpus/`. Parallel on this VM (2026-09-28).

| Target | Time | exec | cov | result |
|--------|------|------|-----|--------|
| `fuzz_mb_adu` | 180 s | 97.7e6 | 186 | OK, no crash |
| `fuzz_slmp_request` | 180 s | 76.5e6 | 268 | OK, no crash |
| `fuzz_eip_encap` | 180 s | 51.4e6 | 160 | OK, no crash |
| `fuzz_eip_io` | 180 s | 87.8e6 | 38 | OK, no crash |
| `fuzz_pn_eth` | 180 s | 49.3e6 | 248 | OK, no crash |
| `fuzz_pn_rpc` | 180 s | 47.5e6 | 415 | OK after fix below |

**Crash found locally (fixed in this PR):** `fuzz_pn_rpc` ASan SEGV
(`crash-1df26b21…`). `ndr_blocks()` used `if (20 + n > len)` with
`n == UINT32_MAX`, which wraps so a 4 GiB block window was accepted and
`walk_blocks` read off the stub. Fix: `if (n > len - 20)`. Regression:
`test_pn_rpc` / `test_ndr_huge_args_len`; seed
`tests/fuzz/corpus/pn_rpc/ndr_u32max.bin`.

No other fuzzer crashes in the 180 s runs.

### Verification (this session)

| Gate | Result |
|------|--------|
| `ctest` daemon+CTT+API (93 tests, incl. `soak_ci`) | pass |
| ASan+UBSan `ctest` (84 tests, `BUILD_DAEMON=OFF`, incl. `soak_ci`) | pass |
| libFuzzer 180 s × 6 targets | pass after NDR wrap fix |
| Bugbot G5/G4 follow-up: `ctest` 93/93, ASan 84/84, fuzz ~30 s × 6 | pass |

Unguessable Encaps session handles can contain `0xD4`/`0x00` in the header;
CTT and unit tests now scan Forward Open replies **after** the 24-byte
Encaps header so they do not treat the session field as a CIP reply.

---

## Verification commands

```
cmake -S . -B build -DBUILD_DAEMON=ON -DBUILD_CTT=ON
cmake --build build -j
ctest --test-dir build --output-on-failure          # includes soak_ci

cmake -S . -B build-san -DENABLE_SANITIZERS=ON -DBUILD_DAEMON=OFF -DBUILD_CTT=ON
cmake --build build-san -j
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-san --output-on-failure

cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang \
  -DBUILD_DAEMON=OFF -DBUILD_CTT=OFF -DBUILD_FUZZERS=ON \
  -DENABLE_PN_TESTS=OFF -DENABLE_EIP_TESTS=OFF \
  -DENABLE_MB_TESTS=OFF -DENABLE_SLMP_TESTS=OFF
cmake --build build-fuzz
python3 tests/fuzz/gen_corpus.py
# each target a few minutes locally; CI uses 60s
```
