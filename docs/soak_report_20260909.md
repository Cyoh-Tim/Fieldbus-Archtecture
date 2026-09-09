# 장비 없는 자체 스택 soak 리포트 — 2026-09-09

내부 mock soak. **인증 evidence 가 아니다.**

> **이 문서는 PI / ODVA / Modbus.org / Mitsubishi / CODESYS 인증 결과가 아니다.**
> DUT = in-repo `stacks/{modbus,slmp,ethernetip,profinet}/` (자체 스택).
> 구매 스텁, 공식 Bundle/CT 텍스트, CODESYS 컨트롤러, 실 NIC, `CAP_NET_RAW` 를 쓰지 않았다.
> PROFINET **CC-C / IRT 는 켜지 않았다** (permanent non-goal).

| 항목 | 값 |
|------|-----|
| 작성 UTC | 2026-09-09T15:30:00Z (Asia/Seoul = UTC+9 → 2026-09-10 00:30 KST) |
| 브랜치 | `cursor/mock-soak-report-90be` |
| 하네스 커밋 | `0f721acf08d4f5396efc569283785399a5f21aa2` |
| 리포트 커밋 | 이 파일과 같은 PR |

원본 `ctt-report/v1` JSON: [`docs/reports/soak_20260909/`](reports/soak_20260909/).

---

## 1. 범위 (Scope)

| 한 것 | 하지 않은 것 |
|--------|----------------|
| in-process CTT mock (`--transport=mock`) | 공식 PI Test Bundle / ODVA CT / Modbus.org / Mitsubishi 랩 |
| Modbus TCP FC03 soak (`mb_stack_handle_adu`) | 라이브 TCP `:502` (기본 CI 에 없음) |
| SLMP Binary 3E batch read soak | ASCII / 4E, 라이브 TCP `:5000` |
| EtherNet/IP Adapter Class 1 produce soak | ODVA CT, CIP TLS mock 미연결, AF_PACKET |
| PROFINET CC-B RT Class 1 RTC1 soak | IRT / CC-C / PTCP, Alarm Ack 상태머신 |
| `examples/run_mock_flow.sh` 스모크 | CODESYS PLC, 실 하드웨어 랩 |

보드 (`docs/ctt_board.html`) 배지는 “시나리오가 기본 `ctest -LE soak_ci` 에 등록되는가” 이지, 이 soak 실행 결과가 아니다.

---

## 2. Duration 정직 표 (truncation)

선호안은 프로토콜당 **~2시간** 연속 soak (YAML `duration_s: 3600`, `--seconds 7200` 로 2h).
4×2h **순차** = 8h 는 클라우드 에이전트 한 세션에 넣기 어렵다.
병렬 2h 는 스케줄러 jitter 를 섞으므로 쓰지 않았다.

| 계획 | 실제 | 이유 |
|------|------|------|
| 2h × 4 sequential | **하지 않음** | 8h wall; 세션 한 번에 비현실 |
| 30 min × 4 sequential (`--seconds 1800`) | **시작 후 중단** | Modbus 만 ~4분 돌다 사용자 지시로 kill. 미완료 데이터를 30min 결과로 쓰지 않음 |
| **5 min × 4 sequential (`--seconds 300`)** | **이 리포트의 본문** | 세션 안에서 리포트를 닫기 위해 추가 단축 |

실제 timed soak wall:

- 시작: **2026-09-09T15:09:56Z**
- 종료: **2026-09-09T15:29:56Z**
- 합계: **20분 0초** (프로토콜당 요청 300s, JSON `duration_ms` ≈ 300000–300006)

`cycle_us: 8000`. mock soft bound. **PREEMPT_RT 아님**, µs IRT / 인증 공차 **주장하지 않음**.

---

## 3. 환경

| 항목 | 값 |
|------|-----|
| Host | Linux 6.12.94+ `PREEMPT_DYNAMIC` (PREEMPT_RT 아님) x86_64 |
| CPU | 4× Intel Xeon, 1 thread/core |
| RAM | 16398384 kB (~16 GiB) |
| CC | Ubuntu clang 18.1.3 |
| CMake | 3.28.3 |
| OpenSSL | 3.0.13 |
| CTT 빌드 | `cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON -DENABLE_PN_TESTS=ON -DENABLE_EIP_TESTS=ON -DENABLE_MB_TESTS=ON -DENABLE_SLMP_TESTS=ON` |
| Mock-flow 빌드 | `BUILD_DIR=build-mock` (daemon + API + CTT) |
| Transport | **mock only** |
| 커널 실시간 | 미적용. 스케줄러 에이징 여유(8ms 사이클, 최대 편차 0.1ms 기록)와 **직접 비교하지 않음** — 이 런은 공유 VM |

스냅샷: [`docs/reports/soak_20260909/environment.txt`](reports/soak_20260909/environment.txt).

---

## 4. 베이스라인 (이 세션, timed soak 이전)

모두 **내부 mock**. 인증 아님.

| 단계 | 시각 (UTC) | 결과 |
|------|------------|------|
| 2s duration smoke (`--seconds 2` × 4 nightly YAML) | 15:02:20–15:02:28 | **PASS** (MB/SLMP/EIP rtc1=247, PN rtc1=231) |
| `examples/run_mock_flow.sh` (`BUILD_DIR=build-mock`) | 15:04:26–15:04:33 | **PASS** — fake sensor `fb_write_*`/`fb_read_*` + `ctest -LE soak_ci -L <proto>` |
| `ctest -L soak_ci` (PN 30s, `PN-B-CYC-011`) | ~15:05 | **PASS** (30.00 s) |
| GitHub CI on `0f721ac` (PR #30 harness) | ~15:06 | **10/10 green** |

`run_mock_flow.sh` 요약:

- Modbus / SLMP / EIP: `connected=1`, barcode/temperature readback OK
- PROFINET: `connected=0` **기대값** (AR 없는 mock process image). `fb_read_*` 는 로컬 이미지
- CTT 게이트: MB 14, SLMP 11, EIP 19, PN 33 tests, **0 failed** (PN `soak_ci` 는 `-LE` 로 이 스크립트에서 제외)

크래시/재시작: 베이스라인·5min soak 모두 **프로세스 한 번으로 종료 코드 0**. watchdog 재기동 없음.

---

## 5. 프로토콜별 timed soak (`--seconds 300`)

공통: `tests/run_mock_soak.sh --seconds 300 --transport=mock`.
순차 실행 (jitter 를 프로토콜 간에 섞지 않음).
`metrics.rtc1_frames` 는 프로토콜마다 재사용 카운터다 (MB=성공 ADU, SLMP=성공 batch, EIP=Class1 produce, PN=RTC1).

`late` = inter-arrival `> 1.5 × cycle_us` (12 ms). `missed` = `> 2.5 × cycle_us` (20 ms).
histogram buckets: `<4, <8, <12, <16, <20, ≥20` ms.

8 ms 슬립 루프의 이론상 상한은 300 s / 8 ms = **37500** 사이클. 실제 카운트는 핸들+슬립 오버헤드로 조금 낮다. PN soak 는 1 ms poll + DUT produce 라 카운트가 다르다.

### 5.1 Modbus TCP — `MB-T-CYC-012`

| 필드 | 값 |
|------|-----|
| DUT | `stacks/modbus/` server, `handle_adu`, unit_id=1, FC03 holding qty=2 |
| 연결 | mock inject. **TCP `:502` 없음**. “connected” = 스택 핸들 유효 |
| 시각 | 15:09:56Z → 15:14:56Z |
| `duration_ms` | 300005 |
| verdict | **pass**, failures=0 |
| rtc1_frames (ok ADU) | 37016 |
| unexpected / ar_drops | 0 / 0 |
| late / missed | 0 / 0 |
| period min / max / avg | 8.021 ms / 10.357 ms / 8.105 ms |
| jitter_max | 2.357 ms (`\|dt − 8 ms\|`) |
| hist `<12 ms` | 37015 / 37015 samples |
| crash/restart | 없음 |

이상 없음. max period 10.4 ms < late 임계 12 ms.

원본: [`modbus.json`](reports/soak_20260909/modbus.json).

### 5.2 SLMP Binary 3E — `SLMP-3E-CYC-012`

| 필드 | 값 |
|------|-----|
| DUT | `stacks/slmp/` Binary 3E, batch read D0 word×1 |
| 연결 | mock `handle_request`. **TCP `:5000` 없음** |
| 시각 | 15:14:56Z → 15:19:56Z |
| `duration_ms` | 300006 |
| verdict | **pass**, failures=0 |
| rtc1_frames (ok batch) | 37017 |
| unexpected / ar_drops | 0 / 0 |
| late / missed | 0 / 0 |
| period min / max / avg | 8.024 ms / 9.938 ms / 8.105 ms |
| jitter_max | 1.938 ms |
| hist `<12 ms` | 37016 / 37016 |
| crash/restart | 없음 |

원본: [`slmp.json`](reports/soak_20260909/slmp.json).

### 5.3 EtherNet/IP Adapter Class 1 — `EIP-A-CYC-012`

| 필드 | 값 |
|------|-----|
| DUT | `stacks/ethernetip/` mock, Forward Open → Class1 soak |
| health | YAML `expect.class1: up`. `ar_drops=0` → soak 동안 Class1 **유지** |
| 시각 | 15:19:56Z → 15:24:56Z |
| `duration_ms` | 300001 |
| verdict | **pass**, failures=0 |
| rtc1_frames (Class1 produce) | 36999 |
| unexpected / ar_drops | 0 / 0 |
| late / missed | 0 / 0 |
| period min / max / avg | 8.021 ms / 10.362 ms / 8.108 ms |
| jitter_max | 2.362 ms |
| hist `<12 ms` | 36998 / 36998 |
| crash/restart | 없음 |

ODVA CT 타이밍·µs 공차 **아님**. Security Class 2 TLS 는 이 soak 에 없음.

원본: [`ethernetip.json`](reports/soak_20260909/ethernetip.json).

### 5.4 PROFINET CC-B RT Class 1 — `PN-B-CYC-012`

| 필드 | 값 |
|------|-----|
| DUT | `stacks/profinet/` CC-B RT1, `rpc_connect` → RTC1 soak, IRT 없음 |
| health | Connect 후 AR up (`in_fid=0x8001 out_fid=0x8002`). `ar_drops=0` |
| 시각 | 15:24:56Z → 15:29:56Z |
| `duration_ms` | 300000 |
| verdict | **pass**, failures=0 |
| rtc1_frames | 34602 |
| unexpected / ar_drops | 0 / 0 |
| late / missed | 0 / 0 |
| period min / max / avg | 8.000 ms / 9.236 ms / 8.670 ms |
| jitter_max | 1.236 ms |
| hist `<12 ms` | 34601 / 34601 |
| crash/restart | 없음 |

PN 플러그인 soak 는 1 ms poll + DUT cyclic produce 이다. MB/SLMP/EIP 의 `sleep_ms(8)` 요청 루프와 카운트를 직접 비교하지 말 것.
추가로 `ctest -L soak_ci` 30s (`PN-B-CYC-011`) 도 이 세션에서 PASS.

원본: [`profinet.json`](reports/soak_20260909/profinet.json).

### 5.5 한눈에

| Protocol | verdict | wall | cycles (`rtc1_frames`) | unexpected | drops | late | missed | jitter_max | period max |
|----------|---------|------|------------------------|------------|-------|------|--------|------------|------------|
| Modbus TCP | pass | 300.005 s | 37016 | 0 | 0 | 0 | 0 | 2.36 ms | 10.36 ms |
| SLMP 3E | pass | 300.006 s | 37017 | 0 | 0 | 0 | 0 | 1.94 ms | 9.94 ms |
| EtherNet/IP | pass | 300.001 s | 36999 | 0 | 0 | 0 | 0 | 2.36 ms | 10.36 ms |
| PROFINET RT1 | pass | 300.000 s | 34602 | 0 | 0 | 0 | 0 | 1.24 ms | 9.24 ms |

이상(anomaly): **없음** (fail, drop, unexpected, late, missed, crash 모두 0).
jitter 수 ms 는 mock + 비-RT 커널에서 예상 범위. 인증 공차로 읽지 말 것.

---

## 6. CTT 보드와 비교

보드 생성 시각 `2026-09-09T15:01:07Z` (이 soak 하네스 커밋 기준):

| 배지 | 개수 | 의미 |
|------|------|------|
| pass | 72 | 기본 mock CI (`ctest -LE soak_ci`) 등록 YAML |
| skip | 7 | `soak_ci` / `nightly/` / lab |
| gap | 9 | DUT-not-implemented / not yet |
| out_of_scope | 13 | CC-C/IRT, 공식 랩, RTU, ASCII/4E 등 |
| 시나리오 YAML | 77 | rglob (nightly 포함) |

이번 soak 가 보드 배지를 바꾸지 않는다. nightly YAML 은 **skip** (CMake GLOB 밖) 으로 남는다. 이 리포트는 skip 시나리오를 **수동 mock 으로 돌린 실행 기록**이다.

프로토콜별 보드 (참고):

| 프로토콜 | pass | skip | gap | oos |
|----------|------|------|-----|-----|
| PROFINET | 31 | 4 | 2 | 3 |
| EtherNet/IP | 18 | 1 | 4 | 1 |
| Modbus TCP | 13 | 1 | 2 | 3 |
| SLMP | 10 | 1 | 1 | (표는 `docs/ctt_board_data.json`) |

5 min soak **PASS** ≠ 보드 pass 배지. 보드는 CI 등록 여부다.

---

## 7. 남은 갭 (이 soak 가 닫지 않은 것)

스택/하네스 매트릭스와 동일. **가짜 pass 하지 않음.**

| 갭 | 상태 |
|----|------|
| PROFINET Alarm Ack / 풀 상태머신 | dummy TX (`PN-B-ALM-*`)만. DUT Ack 없음 |
| Modbus FC08 Diagnostics / FC11/12 / MEI (FC43) | DUT not implemented. illegal FC 고정 |
| 라이브 TCP `:502` / `:5000` in default CI | inject 훅만. 루프백은 데몬/`fake_sensor` 포트 |
| EIP CIP Security TLS (Class 2) mock | 스택 있으나 CTT 미연결 |
| EIP ListInterfaces, Originator tag R/W | not yet |
| PN Fast Start-Up / MRP | DUT not implemented |
| 하드웨어 랩 | `tests/run_ctt_lab.sh` 는 `CAP_NET_RAW`. **이 런에서 실행하지 않음** |
| CODESYS / 공인 랩 | 범위 밖. 주장하지 않음 |
| 2h×4 (또는 30min×4) 연속 soak | **이 세션에서 수행하지 않음.** 재실행: `tests/run_mock_soak.sh --seconds 7200` |

재실행 (장비 없이):

```
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON \
  -DENABLE_PN_TESTS=ON -DENABLE_EIP_TESTS=ON -DENABLE_MB_TESTS=ON -DENABLE_SLMP_TESTS=ON
cmake --build build --target ctt
tests/run_mock_soak.sh --skip-configure --skip-build --seconds 1800 --report-dir docs/reports/soak_manual
```

---

## 8. 결론

자체 스택 네 프로토콜의 **장비 없는 mock timed soak** 는 `--seconds 300` 순차 20분 wall 에서 모두 **pass** 였다.
크래시 없음, unexpected/drop/late/missed = 0, Class1/AR 유지.

이것은 **내부 신뢰성 샘플**이다. 2h×4 와 30min×4 는 이 세션에서 완료하지 못했다.
**PI / ODVA / Modbus.org / Mitsubishi / CODESYS 인증으로 제출하지 말 것.**
