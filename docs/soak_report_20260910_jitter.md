# Mock soak jitter — 2026-09-10 (absolute-time waits)

내부 mock soak. **인증 evidence 가 아니다.**

> **이 문서는 PI / ODVA / Modbus.org / Mitsubishi / CODESYS 인증 결과가 아니다.**
> DUT = in-repo `stacks/{modbus,slmp,ethernetip,profinet}/`. mock transport.
> PREEMPT_RT / isolcpus / `CAP_NET_RAW` / IRT / CC-C 없음.
> µs 공차 **주장하지 않음.** 소프트 예산: `late` @ 1.5×cycle = 0.

베이스라인: [`docs/soak_report_20260909.md`](soak_report_20260909.md) (같은 클래스 공유 VM, 8 ms, `--seconds 300`).

원본 JSON: [`docs/reports/soak_20260910/`](reports/soak_20260910/).

---

## 1. 무엇을 바꿨나

| 이전 (2026-09-09) | 이번 |
|-------------------|------|
| soak 루프 `nanosleep(cycle_ms)` 상대 대기 (일 끝나면 또 8 ms) | `CLOCK_MONOTONIC` + `clock_nanosleep(TIMER_ABSTIME)` (`tools/ctt/cycle_clock.c`, `core/scheduler.c` 와 같은 계열) |
| 한 슬롯이 늦으면 그리드 따라잡느라 3–4 ms 짧은 슬롯이 생김 | 이전이 주기/4 보다 늦으면 **now+period 로 재동기** (짧은 catch-up 없음) |
| PN soak `sleep_ms(1)` poll + DUT `last = now` | CTT 는 cycle 절대대기, DUT RTC1/EIP Class1 은 `next += period` |
| soak 루프마다 YAML 파싱 / SLMP `calloc` | 요청 템플릿 재사용, handle_request 는 스택 버퍼 |

소프트 게이트: nightly YAML 은 `late=0` 을 **목표**로 적되, 공유 VM 한 샘플 스파이크로 5 min 스크립트가 깨지지 않게 하드 `max_late: 0` 은 두지 않음. `soak_short` CI 는 기존 `max_late: 8` 유지.

---

## 2. 환경

| 항목 | 값 |
|------|-----|
| 작성 UTC | 2026-09-09T22:12:29Z (KST 2026-09-10 07:12) |
| Host | Linux 6.12.94+ `PREEMPT_DYNAMIC` (**PREEMPT_RT 아님**) x86_64 |
| CPU | 4× Intel Xeon, 1 thread/core (공유 VM) |
| 하네스 | `68de906` (`cursor/soak-abs-jitter-4215`) |
| Transport | **mock only** |
| 실행 | `tests/run_mock_soak.sh --skip-configure --skip-build --seconds 300` 순차 |

스냅샷: [`environment.txt`](reports/soak_20260910/environment.txt).

실제 timed soak wall: **2026-09-09T21:52:29Z → 22:12:29Z** (20분). 로컬 `ctest -LE soak_ci` 82/82 PASS. GitHub CI (`test` / `daemon` / `mock-flow`) green on `68de906`.

---

## 3. Before / after (`--seconds 300`, cycle 8 ms)

`late` = dt > 12 ms (1.5×). `missed` = dt > 20 ms (2.5×).
`jitter_max` = max `|dt − 8 ms|`. histogram: `<4, <8, <12, <16, <20, ≥20` ms.

8 ms × 300 s = **37500** 사이클이 이론상 상한.

### 3.1 한눈에

| Protocol | run | verdict | cycles | avg period | min | max | jitter_max | late | missed |
|----------|-----|---------|--------|------------|-----|-----|------------|------|--------|
| Modbus TCP | 09 | pass | 37016 | 8.105 ms | 8.021 | 10.357 | **2.36 ms** | 0 | 0 |
| Modbus TCP | 10 | pass | **37500** | **8.000 ms** | 6.678 | 11.090 | 3.09 ms | **0** | **0** |
| SLMP 3E | 09 | pass | 37017 | 8.105 ms | 8.024 | 9.938 | **1.94 ms** | 0 | 0 |
| SLMP 3E | 10 | pass | **37500** | **8.000 ms** | 7.064 | 10.565 | 2.57 ms | **0** | **0** |
| EtherNet/IP | 09 | pass | 36999 | 8.108 ms | 8.021 | 10.362 | **2.36 ms** | 0 | 0 |
| EtherNet/IP | 10 | pass | **37500** | **8.000 ms** | 7.367 | 10.508 | 2.51 ms | **0** | **0** |
| PROFINET RT1 | 09 | pass | 34602 | 8.670 ms | 8.000 | 9.236 | **1.24 ms** | 0 | 0 |
| PROFINET RT1 | 10 | pass | **37501** | **8.000 ms** | 7.620 | 11.574 | 3.57 ms | **0** | **0** |

histogram 09: 전 샘플이 `<12` ms 버킷 (실제로는 **전부 ≥8.02 ms** — 상대 sleep 이 일을 8 ms 위에 쌓음).
histogram 10: `<8` / `<12` 가 거의 반반 (7.x ms 와 8.x ms 가 8 ms 그리드 주위).

### 3.2 좋아진 것 (측정 가능)

1. **드리프트 제거.** 평균 주기 8.105–8.670 ms → **8.000 ms**. 300 s 안에 이론 사이클 수에 도달 (PN 은 1 ms poll + `last=now` 때문에 34602 였음 → 37501).
2. **소프트 예산 유지.** 네 프로토콜 모두 `late=0`, `missed=0`, unexpected/drop=0, verdict pass. 크래시 없음.
3. **조용한 구간.** 같은 바이너리 `--seconds 2` 스모크: `jitter_max` **0.15–0.21 ms**, avg 8.000 ms. 상대 루프의 “항상 8.1 ms+” 와 다름.

### 3.3 좋아지지 않은 것 (정직)

**5 min `jitter_max` 는 줄지 않았다** (2.5–3.6 ms vs 베이스 1.2–2.4 ms).

원인은 스케줄러 드리프트가 아니라 **공유 VM 한두 번의 수 ms preemption** 이다. 상대 sleep 은 최솟값이 항상 ≥8.02 ms 라서 `|dt−8|` 의 최댓값이 “긴 쪽만” (≈2 ms) 이었다. 절대시각은 그리드에 붙으므로 최솟값이 7 ms 대로 내려갈 수 있고, 같은 클래스의 11 ms 스파이크가 `jitter_max` 를 그대로 지배한다. 이는 PREEMPT_RT 없이 없앨 수 있는 양이 아니다.

`jitter_max` 만 보면 회귀처럼 보이지만, **평균·사이클 수·late=0** 이 이번 작업의 실제 이득이다. 인증 공차로 읽지 말 것.

중간 시도 (그리드 catch-up): SLMP 300 s 에서 late=1 (`dt=12.28 ms`) + 3.7 ms 짧은 슬롯이 나와 `jitter_max` 가 더 나빠졌다. 재동기 정책으로 그 짧은 슬롯은 없앴고, 본문 수치는 그 이후 런이다.

---

## 4. 프로토콜별 (after)

공통: mock, `cycle_us: 8000`, duration ≈ 300.00 s, unexpected=0, drops=0.

| Protocol | tc | rtc1_frames | period min / max / avg | jitter_max | hist `<8` / `<12` |
|----------|----|-------------|------------------------|------------|-------------------|
| Modbus TCP | MB-T-CYC-012 | 37500 | 6.678 / 11.090 / 8.000 ms | 3.090 ms | 19084 / 18415 |
| SLMP 3E | SLMP-3E-CYC-012 | 37500 | 7.064 / 10.565 / 8.000 ms | 2.565 ms | 19052 / 18447 |
| EtherNet/IP | EIP-A-CYC-012 | 37500 | 7.367 / 10.508 / 8.000 ms | 2.508 ms | 18911 / 18588 |
| PROFINET RT1 | PN-B-CYC-012 | 37501 | 7.620 / 11.574 / 8.000 ms | 3.574 ms | 19009 / 18491 |

PN 은 이제 MB/SLMP/EIP 와 같은 8 ms 절대 대기를 쓰므로 사이클 수를 직접 비교해도 된다 (09 리포트의 “1 ms poll 이라 비교 금지” 는 이 런부터 해당 없음). 여전히 **CC-B RT1 / 비동기 cyclic** 이지 IRT 가 아니다.

---

## 5. 결론

장비 없는 mock timed soak 는 절대시각 대기로 **평균 주기를 8.000 ms 에 잠그고**, 네 프로토콜 모두 **late/missed=0** 으로 pass 했다. 같은 호스트에서 상대 `sleep_ms` 가 쌓던 ~0.1 ms/사이클 드리프트는 사라졌다.

**최악 `jitter_max` 는 이 VM 의 수 ms 잡음이 지배**한다. PREEMPT_RT 없이 더 줄이려면 isolcpus/전용 머신이지, 이 PR 의 범위가 아니다.

**PI / ODVA / Modbus.org / Mitsubishi / CODESYS 인증으로 제출하지 말 것.**
