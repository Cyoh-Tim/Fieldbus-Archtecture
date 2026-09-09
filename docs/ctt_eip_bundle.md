# EtherNet/IP internal bundle v1 (Adapter Class 1)

내부 CTT를 **bundle-grade 게이트**로 키우기 위한 EIP 카탈로그·리포트
매핑이다. **공식 ODVA Conformance Test (CT) / Spec 테스트 케이스 텍스트를
복제하지 않는다.** 카테고리와 TC ID 는 이 저장소의 내부 라벨이다.

> **내부 bundle-grade 게이트 ≠ ODVA 인증.**
> CTT green, 이 문서의 pass, `ctt-report/v1` 리포트는 공인 랩 evidence 가
> 아니다. 공식 ODVA CT 실행·Declaration of Conformity 는 멤버십+공인 랩
> 제품 프로세스다.

범위: EtherNet/IP **Adapter Class 1** + UCMM + Security Class 1 lab profile
(HMAC CPF `0x00C1` — 이 저장소 프로파일, ODVA CIP Security item 사칭 아님).
DUT = in-repo `stacks/ethernetip/` 자체 스택. `adapters/ethernetip/` 데몬
어댑터와 구매 ODVA CT 소프트웨어는 DUT 가 아니다.

도구는 하나다. `tools/ctt` 플러그인 + `tests/scenarios/ethernetip/*.yaml`.
두 번째 CTT 바이너리를 만들지 않는다. 리포트는 PN 과 같은
`ctt --report` (`ctt-report/v1`).

## 1. 여섯 기둥 (pillars)

PN (`docs/ctt_pn_bundle.md`) 과 같다. 프로토콜 프레임만 플러그인에 둔다.
Modbus [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) · SLMP
[`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) 가 같은 기둥을 쓴다.

| # | 기둥 | 이 PR (EIP-A-v1 wave 1) |
|---|------|-------------------------|
| 1 | **TC 카탈로그 / ID 스킴** | `EIP-A-<AREA>-NNN`. YAML `id:` / `suite:`. 보드 `bundle_id` |
| 2 | **Cyclic IO / jitter / drop 하네스** | Class1 produce 주기를 공통 `ctt_metrics_*` 에 넣는다. `EIP-A-CYC-002` 가 기본 CI 에서 48 사이클 |
| 3 | **Connection lifetime** | Forward Open → IO → Forward Close → 재-Open → IO (`EIP-A-CM-002`) |
| 4 | **Negative / boundary** | HMAC 불량, truncated Encaps, unknown cmd, FO 없이 IO |
| 5 | **mock / golden / lab 프로파일** | 기본 CI = mock inject. EIP AF_PACKET/CIP TCP 는 미연결. soak 라벨 없음 (PN 과 달리 30s soak YAML 없음) |
| 6 | **리포트 스키마** | `ctt --report` → `ctt-report/v1`. EIP `tc_id` / `metrics.rtc1_frames`(Class1 produce 카운트) |

## 2. ID 스킴

```
EIP-A-<AREA>-NNN
```

| 부분 | 의미 |
|------|------|
| `EIP` | 프로토콜 (PN 은 `PN-B-…`, Modbus `MB-T-…`, SLMP `SLMP-3E-…`) |
| `A` | 제품 프로파일 Adapter Class 1 + Sec1 lab |
| `AREA` | `ENC` `ID` `CM` `CYC` `NEG` `SEC` `QOS` `ACD` `NBR` |
| `NNN` | 영역 안 안정 번호. 한 번 붙이면 바꾸지 않는다 |

YAML (runner·보드가 읽음):

```yaml
name: class1_cyclic_metrics   # ctest stem / 보드 row id
id: EIP-A-CYC-002             # 카탈로그 TC ID (bundle_id)
suite: EIP-A-v1
protocol: ethernetip
```

`bundle_id:` 키도 허용한다 (`id:` 보다 우선). 공통 runner 는 CIP 프레임을
해석하지 않고 이 필드를 리포트에 복사한다.

## 3. 카탈로그 (EIP-A-v1)

커버: **mock** = 기본 `ctest -LE soak_ci` (`-L ethernetip`). **gap** = DUT
미구현 또는 CTT 훅 없음 (가짜 pass 금지). **oos** = 영구 비목표 (공식 CT).

### 3.1 시나리오 ↔ 기존 `docs/ctt_odva_matrix.md`

이미 있던 YAML 에 ID 를 붙이고, wave 1 에서 **두껍게** 만든 것만 새 파일이다.

| TC ID | YAML | 기둥 | mock CI | 매트릭스 카테고리 | wave 1 |
|-------|------|------|---------|-------------------|--------|
| EIP-A-ENC-001 | `register_session.yaml` | catalog | pass | Encapsulation RegisterSession | ID only |
| EIP-A-ENC-002 | `list_identity.yaml` | catalog | pass | ListIdentity + Protection Mode | ID only |
| EIP-A-ID-001 | `identity_get.yaml` | catalog | pass | Identity Get_Attribute_Single | ID only |
| EIP-A-CM-001 | `assembly_fo_io.yaml` | CM | pass | Assembly + FO + Class 1 IO | ID only (단축) |
| EIP-A-CM-002 | `class1_lifetime.yaml` | **lifetime** | pass | FO lifetime + Close | **new** FO→IO→Close→re-Open |
| EIP-A-CYC-001 | `class1_watchdog.yaml` | cyclic | pass | Class 1 watchdog + RT stats | ID only |
| EIP-A-CYC-002 | `class1_cyclic_metrics.yaml` | **cyclic** | pass | Class1 metrics | **new** 48 cycles, late/missed/jitter vs `rpi_us`/`cycle_us` |
| EIP-A-SEC-001 | `sec_integrity_fo.yaml` | SEC | pass | Sec1 unsigned reject + HMAC accept | ID only |
| EIP-A-NEG-001 | `fo_bad_hmac.yaml` | **NEG** | pass | FO reject (bad HMAC) | **new** |
| EIP-A-NEG-002 | `encap_malformed.yaml` | **NEG** | pass | truncated Encaps / unknown cmd | **new** |
| EIP-A-NEG-003 | `io_without_fo.yaml` | **NEG** | pass | no FO ⇒ no Class1 produce | **new** |
| EIP-A-QOS-001 | `qos_dscp.yaml` | catalog | pass | QoS Object DSCP defaults | ID only |
| EIP-A-ACD-001 | `acd_identity_state.yaml` | catalog | pass | ACD + Identity state | ID only |
| EIP-A-NBR-001 | `lldp_mgmt.yaml` | catalog | pass | LLDP Management TX | ID only |

### 3.2 이미 커버 vs 다음에 두껍게

Wave 1 이 메운 갭:

- Cyclic 이 watchdog(타임아웃) 만 있었음 → **cycle/RPI 대비 late/missed/jitter** + 48 사이클 기본 CI
- FO+IO 스모크에 Close/재연결이 없음 → **Class1 lifetime**
- Sec1 reject 는 integrity **부재** 만 (`EIP-A-SEC-001`) → **HMAC 불량**
- truncated Encaps / unknown cmd / FO 없이 IO 없음 → **fail-closed TCs**
- DUT Encaps 가 claimed length 초과를 clamp 하던 경로 → **거부** (`-EINVAL`)

아직 얇음 (다음 wave, 이 PR 에서 가짜 pass 하지 않음):

| 주제 | 상태 |
|------|------|
| Encapsulation ListServices | DUT 핸들러는 있음. CTT YAML 없음 = **gap** |
| Encapsulation ListInterfaces | **DUT not implemented** (default 은 unsupported status). gap |
| Large Forward Open | DUT `0x5B` 경로 있음. CTT 는 standard FO 만. gap |
| Originator UCMM tag R/W | Adapter DUT 경로. 시나리오 없음 = 미커버 |
| Ethernet Link / Port objects | DUT 객체는 있음. CTT YAML 없음 = gap |
| CIP Security TLS (Class 2) port 2221 | 스택은 있으나 CTT mock 미연결. gap |
| Lab 프로파일 Class1 jitter | mock soft ms. EIP AF_PACKET 은 CIP TCP 미연결 |

## 4. 명시적 범위 밖 / 갭

| ID / 라벨 | 커버 | 이유 |
|-----------|------|------|
| ListServices / ListInterfaces YAML | **gap** | 시나리오 없음. ListInterfaces 는 DUT 미구현. 가짜 pass 금지 |
| Large Forward Open CTT | **gap** | 표준 FO+Close 만 wave 1 |
| Originator tag R/W | **gap** | Adapter DUT 가 아님 |
| CIP Security TLS Class 2 mock | **gap** | DUT-not-wired-to-CTT |
| Ethernet Link / Port CTT | **gap** | 객체만 있고 시나리오 없음 |
| **공식 ODVA CT 실행 / DoC** | **oos** | 멤버십 + 공인 랩. 이 하네스가 대체하지 않음 |
| 공식 CT 버전·TC 번호·판정 절차 | **oos** | 라이선스 텍스트를 재구성하지 않음 |

## 5. Cyclic / timing 하네스

공통 `ctt_metrics_t` (`tools/ctt/ctt.h`). PN RTC1 과 **같은 키**.
EIP 플러그인은 Class1 T→O produce 인터벌을 `ctt_metrics_note_period` 에 넣는다.
`metrics.rtc1_frames` 는 여기서 Class1 produce 카운트다 (PN FrameID 가 아님).

| 필드 | EIP 의미 |
|------|----------|
| `rtc1_frames` | Class1 produce 카운트 (SEQ_ADDR CPF) |
| `cycle_ns` | `device.cycle_us` 가 있으면 그 값, 아니면 `device.rpi_us` (기본 8000 µs) |
| `late_cycles` | inter-arrival `> 1.5 * cycle_ns` 이고 `≤ 2.5 * cycle_ns` |
| `missed_cycles` | inter-arrival `> 2.5 * cycle_ns` 에서 `floor(dt/cycle) - 1` |
| `jitter_max_ns` | `max \|dt - cycle_ns\|` |
| `ar_drops` | `require_class1` 인데 Class1 이 내려간 경우 |

`io_cycle` `expect:` (플러그인 소유):

- `min_frames`, `max_frames`, `period_max_ms`
- `max_late`, `max_missed`, `jitter_max_ms`, `min_period_samples`
- `class1: up` / `down`
- `require_class1: false` — FO 없이 돌리고 produce 가 나오면 fail (NEG)

기본 CI 의 두꺼운 테스트는 `EIP-A-CYC-002` (48 사이클, mock, 서브초~1.5s).
**ODVA CT 타이밍·µs 공차를 주장하지 않는다.**

## 6. 리포트 스키마 (`ctt-report/v1`)

```
./build/ctt --scenario tests/scenarios/ethernetip/class1_cyclic_metrics.yaml \
    --report /tmp/eip-a-cyc-002.json
```

PN 과 같은 필드. `suite_id` = `EIP-A-v1`, `tc_id` = `EIP-A-CYC-002`.
스키마 스모크: `ctest -R ctt_report_schema_eip_v1`.

## 7. 프로파일

| 프로파일 | 언제 | 라벨 |
|----------|------|------|
| mock | 기본 PR CI | `ethernetip` (`ctest -L ethernetip`) |
| soak_ci / nightly | (없음) | EIP wave 1 에 30s/1h soak YAML 없음. PN 라벨만 |
| lab | CIP TCP AF_PACKET | **미연결**. `eip_cfg_t.mock` inject 만 |

보드(`docs/ctt_board.html`) 배지는 이 분류를 따른다. **bundle-grade 게이트가
ODVA 인증이 아니다** 는 배너에 고정한다.

## 8. 같은 기둥 (Modbus / SLMP landed)

MB-T-v1 [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) (`MB-T-*`).
SLMP-3E-v1 [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) (`SLMP-3E-*`).
CC-Link / EtherCAT 은 사양 확정 전 비목표.

1. **카탈로그** — YAML `id:` / `suite:`, 기존 매트릭스에 내부 매핑
   (공식 인증 번호 복사 금지).
2. **Cyclic 하네스** — 공통 `ctt_metrics_*`. 주기를 `ctt_metrics_note_period` 에 넣는다.
3. **Lifetime** — 세션/맵 재기록. 있는 훅을 두껍게.
4. **NEG** — truncated / unknown. DUT 가 실제로 거부하는 것만. 미구현은 gap.
5. **프로파일** — mock 기본 CI.
6. **리포트** — `--report` 는 프로토콜 무관.

`core/` 에 프로토콜 분기를 넣지 않는다.

## 9. 관련 문서

- [`docs/ctt.md`](ctt.md) — 하네스 설계
- [`docs/ctt_odva_matrix.md`](ctt_odva_matrix.md) — Adapter 내부 매핑 (인증 아님)
- [`docs/ctt_pn_bundle.md`](ctt_pn_bundle.md) — PN 기둥 (이식 원본)
- [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) — Modbus TCP 기둥
- [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) — SLMP 3E 기둥
- [`docs/ctt_board.md`](ctt_board.md) / [`ctt_board.html`](ctt_board.html)
- [`tools/ctt/README.md`](../tools/ctt/README.md)
- [`docs/ethernetip_stack.md`](ethernetip_stack.md)
