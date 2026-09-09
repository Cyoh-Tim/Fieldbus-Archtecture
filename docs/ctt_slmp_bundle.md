# SLMP Binary 3E internal bundle v1

내부 CTT를 **bundle-grade 게이트**로 키우기 위한 SLMP 카탈로그·리포트
매핑이다. **Mitsubishi 공식 인증 / 유료 랩 텍스트를 복제하지 않는다.**
카테고리와 TC ID 는 이 저장소의 내부 라벨이다.

> **내부 bundle-grade 게이트 ≠ Mitsubishi 인증.**
> CTT green, 이 문서의 pass, `ctt-report/v1` 리포트는 공인 랩 evidence 가
> 아니다.

범위: Binary **3E** 일괄 읽기(`0x0401`) / 쓰기(`0x1401`). DUT = `stacks/slmp/`.
**ASCII / 4E 는 영구 비목표** (create 거절만 고정). `adapters/slmp/` 데몬
어댑터는 CTT DUT가 아니다.

도구는 하나다. `tools/ctt` + `tests/scenarios/slmp/*.yaml`.
두 번째 CTT 바이너리를 만들지 않는다. 리포트는 PN/EIP/Modbus 와 같은
`ctt --report` (`ctt-report/v1`).

## 1. 여섯 기둥 (pillars)

PN · EIP · Modbus 와 같다. 프로토콜 프레임만 플러그인에 둔다.

| # | 기둥 | 이 PR (SLMP-3E-v1 wave 1) |
|---|------|---------------------------|
| 1 | **TC 카탈로그 / ID 스킴** | `SLMP-3E-<AREA>-NNN`. YAML `id:` / `suite:`. 보드 `bundle_id` |
| 2 | **Cyclic / jitter / drop 하네스** | batch read soak 주기를 공통 `ctt_metrics_*` 에 넣는다. `SLMP-3E-CYC-002` 가 기본 CI 에서 48 사이클 |
| 3 | **Map lifetime** | batch write → read → overwrite → 재기록 (`SLMP-3E-CM-002`, D word + M bit) |
| 4 | **Negative / boundary** | ASCII/4E 거절, truncated 3E, short write, OOB `0xC056` |
| 5 | **mock / lab 프로파일** | 기본 CI = `handle_request` inject. `:5000` 실소켓은 gap |
| 6 | **리포트 스키마** | `ctt --report` → `ctt-report/v1`. SLMP `tc_id` / `metrics.rtc1_frames`(성공 batch 카운트) |

## 2. ID 스킴

```
SLMP-3E-<AREA>-NNN
```

| 부분 | 의미 |
|------|------|
| `SLMP` | 프로토콜 (PN `PN-B-…`, EIP `EIP-A-…`, Modbus `MB-T-…`) |
| `3E` | 제품 프로파일 Binary 3E (ASCII/4E 아님) |
| `AREA` | `DEV` `ENC` `CM` `CYC` `NEG` |
| `NNN` | 영역 안 안정 번호. 한 번 붙이면 바꾸지 않는다 |

YAML (runner·보드가 읽음):

```yaml
name: batch_cyclic_metrics   # ctest stem / 보드 row id
id: SLMP-3E-CYC-002          # 카탈로그 TC ID (bundle_id)
suite: SLMP-3E-v1
protocol: slmp
```

`bundle_id:` 키도 허용한다 (`id:` 보다 우선). 공통 runner 는 3E 프레임을
해석하지 않고 이 필드를 리포트에 복사한다.

## 3. 카탈로그 (SLMP-3E-v1)

커버: **mock** = 기본 `ctest -LE soak_ci` (`-L slmp`). **gap** = DUT
미구현 또는 CTT 훅 없음 (가짜 pass 금지). **oos** = 영구 비목표 (ASCII/4E /
공식 랩).

### 3.1 시나리오 ↔ 기존 `docs/ctt_slmp_matrix.md`

이미 있던 YAML 에 ID 를 붙이고, wave 1 에서 **두껍게** 만든 것만 새 파일이다.

| TC ID | YAML | 기둥 | mock CI | 매트릭스 카테고리 | wave 1 |
|-------|------|------|---------|-------------------|--------|
| SLMP-3E-DEV-001 | `device_table.yaml` | catalog | pass | Device code 표 | ID only (D/M/ZR/X/Y/W + unknown) |
| SLMP-3E-ENC-001 | `encode_batch_read.yaml` | catalog | pass | 3E encode | ID only (`0x0401`/`0x1401`) |
| SLMP-3E-CM-001 | `batch_read_write_loopback.yaml` | CM | pass | Batch R/W + bits + ASCII + X hex | ID only |
| SLMP-3E-CM-002 | `batch_lifetime.yaml` | **lifetime** | pass | Batch write/read lifetime | **new** D word + M bit overwrite |
| SLMP-3E-CYC-001 | `soak_short.yaml` | cyclic | pass | batch read soak | **thickened** 32×8ms + late/missed/jitter |
| SLMP-3E-CYC-002 | `batch_cyclic_metrics.yaml` | **cyclic** | pass | Batch metrics | wave 1 48×8ms |
| SLMP-3E-CYC-003 | `batch_cycle_4ms.yaml` | **cyclic** | pass | Batch 4 ms metrics | **wave 2** 48×4ms |
| SLMP-3E-NEG-001 | `reject_non_3e.yaml` | NEG | pass | ASCII/4E/unknown cmd | ID only |
| SLMP-3E-NEG-002 | `frame_malformed.yaml` | **NEG** | pass | Truncated 3E / short write | **new** fail closed |
| SLMP-3E-NEG-003 | `oob_batch_read.yaml` | **NEG** | pass | OOB batch | **new** read+write end `0xC056`, map 유지 |

### 3.2 이미 커버 vs 다음에 두껍게

Wave 1 이 메운 갭:

- Soak 가 iteration 카운트만 있었음 → **cycle_us 대비 late/missed/jitter** + 48 사이클 기본 CI
- loopback 스모크에 overwrite 가 없음 → **D word + M bit lifetime**
- ASCII/4E 거절만 있고 truncated/OOB 없음 → **fail-closed + `0xC056`**

Wave 2: 4 ms batch 메트릭 (`SLMP-3E-CYC-003`). Map lifetime·NEG 는 wave 1 으로 충분.

아직 얇음 (다음 wave, 이 PR 에서 가짜 pass 하지 않음):

| 주제 | 상태 |
|------|------|
| Live TCP :5000 in default CI | inject 훅. `test_slmp_stack` localhost TCP 는 단위 경로. **gap** |
| Random R/W `0x0403`/`0x1402` | DUT 는 end `0xC050`. 제품 비목표. NEG-001 에 고정 |
| Remote RUN/STOP / type name | **DUT not implemented**. 가짜 pass 금지 |
| Lab 프로파일 3E jitter | mock soft ms. AF_PACKET SLMP 미연결 |

## 4. 명시적 범위 밖 / 갭

| ID / 라벨 | 커버 | 이유 |
|-----------|------|------|
| Live TCP :5000 default CI | **gap** | `slmp_stack_handle_request` inject |
| Random R/W / remote control | **oos** / gap | 제품 범위 밖. unknown cmd 는 `0xC050` |
| **3E ASCII / 4E** | **oos** | `slmp_stack_create` 거절만 |
| **Mitsubishi 공식 인증** | **oos** | 공인 랩. 이 하네스가 대체하지 않음 |
| 공식 TC 번호·공인 랩 판정 | **oos** | 라이선스 텍스트를 재구성하지 않음 |

## 5. Cyclic / timing 하네스

공통 `ctt_metrics_t` (`tools/ctt/ctt.h`). PN RTC1 과 **같은 키**.
SLMP 플러그인은 성공 batch read 인터벌을 `ctt_metrics_note_period` 에 넣는다.
`metrics.rtc1_frames` 는 여기서 성공 batch 카운트다 (PN FrameID 가 아님).

| 필드 | SLMP 의미 |
|------|-----------|
| `rtc1_frames` | 성공 batch (end `0x0000`) 카운트 |
| `cycle_ns` | `device.cycle_us` (기본 soak YAML 은 8000 µs) |
| `late_cycles` | inter-arrival `> 1.5 * cycle_ns` 이고 `≤ 2.5 * cycle_ns` |
| `missed_cycles` | inter-arrival `> 2.5 * cycle_ns` 에서 `floor(dt/cycle) - 1` |
| `jitter_max_ns` | `max \|dt - cycle_ns\|` |

`soak` `expect:` (플러그인 소유):

- `min_ok`, `unexpected_frames`
- `max_late`, `max_missed`, `jitter_max_ms`, `min_period_samples`, `period_max_ms`

기본 CI 의 두꺼운 테스트는 `SLMP-3E-CYC-002` (48 사이클, mock, 서브초~1.5s).
**Mitsubishi 공인 타이밍·µs 공차를 주장하지 않는다.**

## 6. 리포트 스키마 (`ctt-report/v1`)

```
./build/ctt --scenario tests/scenarios/slmp/batch_cyclic_metrics.yaml \
    --report /tmp/slmp-3e-cyc-002.json
```

PN/EIP/MB 와 같은 필드. `suite_id` = `SLMP-3E-v1`, `tc_id` = `SLMP-3E-CYC-002`.
스키마 스모크: `ctest -R ctt_report_schema_slmp_v1`.

## 7. 프로파일

| 프로파일 | 언제 | 라벨 |
|----------|------|------|
| mock | 기본 PR CI | `slmp` (`ctest -L slmp`) |
| soak_ci / nightly | (없음) | SLMP wave 1 에 30s/1h soak YAML 없음. PN 라벨만 |
| lab | TCP :5000 AF_PACKET | **미연결**. `slmp_stack_handle_request` inject 만 |

보드(`docs/ctt_board.html`) 배지는 이 분류를 따른다. **bundle-grade 게이트가
Mitsubishi 인증이 아니다** 는 배너에 고정한다.

## 8. 관련 문서

- [`docs/ctt.md`](ctt.md) — 하네스 설계
- [`docs/ctt_slmp_matrix.md`](ctt_slmp_matrix.md) — 3E 내부 매핑 (인증 아님)
- [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) — Modbus 같은 기둥
- [`docs/ctt_pn_bundle.md`](ctt_pn_bundle.md) — PN 기둥 (이식 원본)
- [`docs/ctt_eip_bundle.md`](ctt_eip_bundle.md) — EIP 기둥
- [`docs/ctt_board.md`](ctt_board.md) / [`ctt_board.html`](ctt_board.html)
- [`tools/ctt/README.md`](../tools/ctt/README.md)
- [`docs/slmp_stack.md`](slmp_stack.md)
