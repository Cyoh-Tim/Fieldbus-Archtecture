# Modbus TCP internal bundle v1

내부 CTT를 **bundle-grade 게이트**로 키우기 위한 Modbus TCP 카탈로그·리포트
매핑이다. **Modbus.org 공식 conformance / 유료 랩 텍스트를 복제하지 않는다.**
카테고리와 TC ID 는 이 저장소의 내부 라벨이다.

> **내부 bundle-grade 게이트 ≠ Modbus.org 인증.**
> CTT green, 이 문서의 pass, `ctt-report/v1` 리포트는 공인 랩 evidence 가
> 아니다.

범위: **Modbus TCP 서버** (`stacks/modbus/`, `mb_stack_handle_adu`).
libmodbus 없음. **RTU / serial / UDP 는 영구 비목표.** DUT = in-repo 스택.
`adapters/modbus/` 데몬 어댑터는 CTT DUT가 아니다.

도구는 하나다. `tools/ctt` + `tests/scenarios/modbus/*.yaml`.
두 번째 CTT 바이너리를 만들지 않는다. 리포트는 PN/EIP 과 같은
`ctt --report` (`ctt-report/v1`).

## 1. 여섯 기둥 (pillars)

PN (`docs/ctt_pn_bundle.md`) · EIP (`docs/ctt_eip_bundle.md`) 과 같다.
프로토콜 프레임만 플러그인에 둔다. SLMP 는 [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md).

| # | 기둥 | 이 PR (MB-T-v1 wave 1) |
|---|------|------------------------|
| 1 | **TC 카탈로그 / ID 스킴** | `MB-T-<AREA>-NNN`. YAML `id:` / `suite:`. 보드 `bundle_id` |
| 2 | **Cyclic / jitter / drop 하네스** | FC03 soak 주기를 공통 `ctt_metrics_*` 에 넣는다. `MB-T-CYC-002` 가 기본 CI 에서 48 사이클 |
| 3 | **Map lifetime** | FC16 write → FC03 → 잘못된 unit → overwrite → 재기록 (`MB-T-CM-001`). Coil `MB-T-CM-002` |
| 4 | **Negative / boundary** | OOB 주소, illegal value/FC, truncated MBAP, proto≠0. 맵은 그대로 |
| 5 | **mock / lab 프로파일** | 기본 CI = `handle_adu` inject. `:502` 실소켓은 gap. RTU 는 oos |
| 6 | **리포트 스키마** | `ctt --report` → `ctt-report/v1`. MB `tc_id` / `metrics.rtc1_frames`(성공 ADU 카운트) |

## 2. ID 스킴

```
MB-T-<AREA>-NNN
```

| 부분 | 의미 |
|------|------|
| `MB` | 프로토콜 (PN 은 `PN-B-…`, EIP 는 `EIP-A-…`, SLMP 는 `SLMP-3E-…`) |
| `T` | 제품 프로파일 TCP 서버 (RTU 아님) |
| `AREA` | `FC` `CM` `CYC` `NEG` |
| `NNN` | 영역 안 안정 번호. 한 번 붙이면 바꾸지 않는다 |

YAML (runner·보드가 읽음):

```yaml
name: fc03_cyclic_metrics   # ctest stem / 보드 row id
id: MB-T-CYC-002            # 카탈로그 TC ID (bundle_id)
suite: MB-T-v1
protocol: modbus_tcp
```

`bundle_id:` 키도 허용한다 (`id:` 보다 우선). 공통 runner 는 MBAP/PDU 를
해석하지 않고 이 필드를 리포트에 복사한다.

## 3. 카탈로그 (MB-T-v1)

커버: **mock** = 기본 `ctest -LE soak_ci` (`-L modbus`). **gap** = DUT
미구현 또는 CTT 훅 없음 (가짜 pass 금지). **oos** = 영구 비목표 (공식 랩 / RTU).

### 3.1 시나리오 ↔ 기존 `docs/ctt_modbus_matrix.md`

이미 있던 YAML 에 ID 를 붙이고, wave 1 에서 **두껍게** 만든 것만 새 파일이다.

| TC ID | YAML | 기둥 | mock CI | 매트릭스 카테고리 | wave 1 |
|-------|------|------|---------|-------------------|--------|
| MB-T-FC-001 | `fc03_read_holding.yaml` | catalog | pass | FC03 Holding | ID + map_check |
| MB-T-FC-002 | `fc05_write_single_coil.yaml` | catalog | pass | FC05 Coil | ID only |
| MB-T-FC-003 | `fc22_mask_write.yaml` | catalog | pass | FC22 Mask Write | ID only |
| MB-T-FC-004 | `fc_server_matrix.yaml` | catalog | pass | FC01–04, 06, 0F, 10, 16, 17, bulk 125, illegal FC, wrong unit | ID only |
| MB-T-FC-005 | `string_bytes.yaml` | catalog | pass | Packed ASCII | ID only |
| MB-T-CM-001 | `holding_lifetime.yaml` | **lifetime** | pass | Holding write/read lifetime | **new** FC16→FC03→wrong unit→overwrite |
| MB-T-CM-002 | `coil_lifetime.yaml` | **lifetime** | pass | Coil write/read lifetime | **new** FC05→FC01→overwrite |
| MB-T-CYC-001 | `soak_short.yaml` | cyclic | pass | FC03 soak | **thickened** 32×8ms + late/missed/jitter |
| MB-T-CYC-002 | `fc03_cyclic_metrics.yaml` | **cyclic** | pass | FC03 metrics | wave 1 48×8ms |
| MB-T-CYC-003 | `fc03_cycle_4ms.yaml` | **cyclic** | pass | FC03 4 ms metrics | **wave 2** 48×4ms |
| MB-T-NEG-001 | `exception_illegal_address.yaml` | **NEG** | pass | Exception 0x02 | **thickened** Holding/Coil OOB, qty=0, illegal FC |
| MB-T-NEG-002 | `adu_malformed.yaml` | **NEG** | pass | Truncated / bad MBAP | **new** fail closed |
| MB-T-NEG-003 | `exception_illegal_value.yaml` | **NEG** | pass | Exception 0x03 | **new** bad coil value / short PDU |

### 3.2 이미 커버 vs 다음에 두껍게

Wave 1 이 메운 갭:

- Soak 가 iteration 카운트만 있었음 → **cycle_us 대비 late/missed/jitter** + 48 사이클 기본 CI
- FC16/FC03 스모크에 overwrite / wrong-unit 이 없음 → **Holding + Coil lifetime**
- Exception 은 Holding OOB 한 장 → **Coil OOB / qty=0 / illegal FC / illegal value**
- truncated MBAP / proto≠0 없음 → **fail-closed TCs** (`mb_stack_handle_adu` `-EINVAL`)

Wave 2: 4 ms FC03 메트릭 (`MB-T-CYC-003`). Holding/Coil lifetime·NEG 는 wave 1 으로 충분.

아직 얇음 (다음 wave, 이 PR 에서 가짜 pass 하지 않음):

| 주제 | 상태 |
|------|------|
| Live TCP :502 in default CI | inject 훅만. 실 소켓은 데몬 경로. **gap** |
| FC08 Diagnostics / FC11/12 comms event | DUT 미구현. YAML 없음 = gap |
| FC20/21 file record | **DUT not implemented**. 가짜 pass 금지 |
| Slave ID / MEI (FC43) | 미구현. illegal FC 로만 고정 |
| Lab 프로파일 TCP jitter | mock soft ms. AF_PACKET Modbus 미연결 |

## 4. 명시적 범위 밖 / 갭

| ID / 라벨 | 커버 | 이유 |
|-----------|------|------|
| Live TCP :502 default CI | **gap** | `mb_stack_handle_adu` inject. 실 소켓 soak 는 데몬 경로 |
| FC08 / FC20 / FC21 / MEI | **gap** | DUT 미구현 또는 illegal FC 만 |
| **Modbus RTU / serial / UDP** | **oos** | TCP only |
| **공식 Modbus.org conformance lab** | **oos** | 유료/랩. 이 하네스가 대체하지 않음 |
| 공식 TC 번호·공인 랩 판정 | **oos** | 라이선스 텍스트를 재구성하지 않음 |

## 5. Cyclic / timing 하네스

공통 `ctt_metrics_t` (`tools/ctt/ctt.h`). PN RTC1 과 **같은 키**.
Modbus 플러그인은 성공 FC03 ADU 인터벌을 `ctt_metrics_note_period` 에 넣는다.
`metrics.rtc1_frames` 는 여기서 성공 ADU 카운트다 (PN FrameID 가 아님).

| 필드 | Modbus 의미 |
|------|-------------|
| `rtc1_frames` | 성공 ADU 카운트 (exception 아님) |
| `cycle_ns` | `device.cycle_us` (기본 soak YAML 은 8000 µs) |
| `late_cycles` | inter-arrival `> 1.5 * cycle_ns` 이고 `≤ 2.5 * cycle_ns` |
| `missed_cycles` | inter-arrival `> 2.5 * cycle_ns` 에서 `floor(dt/cycle) - 1` |
| `jitter_max_ns` | `max \|dt - cycle_ns\|` |

`soak` `expect:` (플러그인 소유):

- `min_ok`, `unexpected_frames`
- `max_late`, `max_missed`, `jitter_max_ms`, `min_period_samples`, `period_max_ms`

기본 CI 의 두꺼운 테스트는 `MB-T-CYC-002` (48 사이클, mock, 서브초~1.5s).
**Modbus.org 타이밍·µs 공차를 주장하지 않는다.**

## 6. 리포트 스키마 (`ctt-report/v1`)

```
./build/ctt --scenario tests/scenarios/modbus/fc03_cyclic_metrics.yaml \
    --report /tmp/mb-t-cyc-002.json
```

PN/EIP 과 같은 필드. `suite_id` = `MB-T-v1`, `tc_id` = `MB-T-CYC-002`.
스키마 스모크: `ctest -R ctt_report_schema_mb_v1`.

## 7. 프로파일

| 프로파일 | 언제 | 라벨 |
|----------|------|------|
| mock | 기본 PR CI | `modbus` (`ctest -L modbus`) |
| soak_ci / nightly | (없음) | MB wave 1 에 30s/1h soak YAML 없음. PN 라벨만 |
| lab | TCP :502 AF_PACKET | **미연결**. `mb_stack_handle_adu` inject 만 |

보드(`docs/ctt_board.html`) 배지는 이 분류를 따른다. **bundle-grade 게이트가
Modbus.org 인증이 아니다** 는 배너에 고정한다.

## 8. 관련 문서

- [`docs/ctt.md`](ctt.md) — 하네스 설계
- [`docs/ctt_modbus_matrix.md`](ctt_modbus_matrix.md) — FC 내부 매핑 (인증 아님)
- [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) — SLMP 같은 기둥
- [`docs/ctt_pn_bundle.md`](ctt_pn_bundle.md) — PN 기둥 (이식 원본)
- [`docs/ctt_eip_bundle.md`](ctt_eip_bundle.md) — EIP 기둥
- [`docs/ctt_board.md`](ctt_board.md) / [`ctt_board.html`](ctt_board.html)
- [`tools/ctt/README.md`](../tools/ctt/README.md)
- [`docs/modbus_stack.md`](modbus_stack.md)
