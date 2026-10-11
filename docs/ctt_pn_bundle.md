# PROFINET internal bundle v1 (CC-B + RT Class 1)

내부 CTT를 **bundle-grade 게이트**로 키우기 위한 로드맵·TC 카탈로그·리포트
스키마다. **공식 PI Test Bundle / ART 테스트 케이스 텍스트를 복제하지 않는다.**
카테고리와 TC ID 는 이 저장소의 내부 라벨이다.

> **내부 bundle-grade 게이트 ≠ PI 인증.**
> CTT green, 이 문서의 pass, `ctt-report/v1` 리포트는 공인 랩 evidence 가
> 아니다. 공식 PI Test Bundle 실행·DoC 는 멤버십+공인 랩 제품 프로세스다.

범위: PROFINET **CC-B Device + RT Class 1** (CC-A 기능 중 CC-B 가 쓰는 것
포함: DCP, CM, RTC1, Alarm, Record, LLDP/SNMP, Security Class 1 lab profile).
**CC-C / IRT / RT Class 3 / PTCP 는 영구 비목표** — TC 를 만들지 않는다.

도구는 하나다. `tools/ctt` 플러그인 + `tests/scenarios/profinet/*.yaml`.
두 번째 CTT 바이너리를 만들지 않는다.

## 1. 여섯 기둥 (pillars)

EIP → Modbus → SLMP 로 이식할 때도 같은 기둥을 쓴다. 프로토콜 프레임만
플러그인에 둔다.

| # | 기둥 | 이 PR (PN-B-v1 wave 1) |
|---|------|------------------------|
| 1 | **TC 카탈로그 / ID 스킴** | `PN-B-<AREA>-NNN`. YAML `id:` / `suite:`. 보드 `bundle_id` |
| 2 | **Cyclic IO / jitter / drop 하네스** | `io_cycle`·`soak` 가 `cycle_us` 대비 late / missed / jitter_max 를 잰다. `PN-B-CYC-002` 가 기본 CI 에서 48 사이클 |
| 3 | **Connection lifetime** | Connect → IO → Release → 재Connect → IO (`PN-B-CM-003`) |
| 4 | **Negative / boundary** | HMAC 불량, truncated RPC, unknown op, AR 없이 IO, unknown record |
| 5 | **mock / golden / lab 프로파일** | 기본 CI = mock. golden 은 기존 DCP/Alarm. lab = `af_packet` opt-in. soak_ci / nightly 는 라벨 |
| 6 | **리포트 스키마** | `ctt --report file.json\|.md` → `ctt-report/v1` |

## 2. ID 스킴

```
PN-B-<AREA>-NNN
```

| 부분 | 의미 |
|------|------|
| `PN` | 프로토콜 (EIP `EIP-A-…`, Modbus `MB-T-…`, SLMP `SLMP-3E-…`) |
| `B` | 제품 프로파일 CC-B + RTC1 |
| `AREA` | `DCP` `CM` `CYC` `NEG` `SEC` `ALM` `REC` `NBR` |
| `NNN` | 영역 안 안정 번호. 한 번 붙이면 바꾸지 않는다 |

YAML (runner·보드가 읽음):

```yaml
name: rtc1_cyclic_metrics   # ctest stem / 보드 row id
id: PN-B-CYC-002            # 카탈로그 TC ID (bundle_id)
suite: PN-B-v1
protocol: profinet
```

`bundle_id:` 키도 허용한다 (`id:` 보다 우선). 공통 runner 는 프레임을 해석하지
않고 이 필드를 리포트에 복사한다.

## 3. 카탈로그 (PN-B-v1)

커버: **mock** = 기본 `ctest -LE soak_ci`. **soak** = `-L soak_ci` 또는 수동.
**gap** = DUT 미구현 (가짜 pass 금지). **oos** = 영구 비목표.

### 3.1 시나리오 ↔ 기존 `docs/ctt_pi_matrix.md`

이미 있던 YAML 에 ID 를 붙이고, wave 1 에서 **두껍게** 만든 것만 새 파일이다.

| TC ID | YAML | 기둥 | mock CI | 매트릭스 카테고리 | wave 1 |
|-------|------|------|---------|-------------------|--------|
| PN-B-DCP-001 | `dcp_identify_name_of_station.yaml` | catalog | pass + golden | DCP Identify | ID only |
| PN-B-DCP-002 | `dcp_get.yaml` | catalog | pass + golden | DCP Get | ID only |
| PN-B-DCP-003 | `dcp_hello.yaml` | catalog | pass + golden | DCP Hello TX | ID only |
| PN-B-DCP-004 | `dcp_signal.yaml` | catalog | pass + golden | DCP Signal | ID only |
| PN-B-DCP-005 | `dcp_set_ip.yaml` | catalog | pass + golden | DCP Set IP + Hello | ID only |
| PN-B-SEC-001 | `dcp_set_sec_class1.yaml` | NEG/SEC | pass + golden | DCP Set + Sec1 | ID only |
| PN-B-CM-001 | `rpc_connect_sec1_integrity.yaml` | CM | pass | CM Connect + Sec1 | ID only |
| PN-B-CM-002 | `rpc_release.yaml` | CM | pass | CM Release | ID only (IO 없는 단축) |
| PN-B-CM-003 | `rpc_ar_lifetime.yaml` | **lifetime** | pass | CM lifetime | wave 1 Connect→IO→Release→reconnect |
| PN-B-CM-004 | `rpc_write_prmend_appready.yaml` | CM | pass | Write / PrmEnd / AppReady | ID only |
| PN-B-CM-005 | `rpc_ar_replace.yaml` | **lifetime** | pass | CM single-AR replace | **wave 2** Connect→IO→Connect→IO |
| PN-B-CM-006 | `rpc_ar_lifetime_cm.yaml` | **lifetime** | pass | CM lifetime + PrmEnd | **wave 2** Connect→Write→PrmEnd→IO→Release |
| PN-B-CYC-001 | `rtc1_io_cycle_smoke.yaml` | cyclic | pass | RTC1 cyclic smoke | ID only |
| PN-B-CYC-002 | `rtc1_cyclic_metrics.yaml` | **cyclic** | pass | RTC1 metrics | wave 1 48 cycles, late/missed/jitter vs `cycle_us` |
| PN-B-CYC-003 | `rtc1_cycle_payload.yaml` | **cyclic** | pass | RTC1 payload + CC | **wave 2** input payload, cycle_counter, output consume |
| PN-B-CYC-004 | `rtc1_cycle_4ms.yaml` | **cyclic** | pass | RTC1 4 ms metrics | **wave 2** `cycle_us: 4000`, mock soft bound |
| PN-B-CYC-010 | `soak_short.yaml` | cyclic | pass | RTC1 soak 회귀 | **thickened** late/missed/jitter asserts |
| PN-B-CYC-011 | `soak_ci.yaml` | cyclic | skip (`soak_ci`) | 30s soak | ID only |
| PN-B-CYC-012 | `nightly/soak_nightly.yaml` | cyclic | skip (GLOB 밖) | 1h soak | ID only |
| PN-B-NEG-001 | `rpc_connect_without_integrity.yaml` | NEG | pass | Connect reject (no block) | ID only |
| PN-B-NEG-002 | `rpc_connect_bad_hmac.yaml` | **NEG** | pass | Connect reject (bad HMAC) | **new** |
| PN-B-NEG-003 | `rpc_malformed.yaml` | **NEG** | pass | truncated / unknown op | **new** |
| PN-B-NEG-004 | `io_without_ar.yaml` | **NEG** | pass | no AR ⇒ no RTC1 | **new** |
| PN-B-NEG-005 | `record_unknown_index.yaml` | **NEG** | pass | unknown record empty | wave 1 |
| PN-B-NEG-006 | `dcp_set_name_boundary.yaml` | **NEG** | pass | NameOfStation DNS/PN rules | **wave 2** 240 DNS-label accept; 260 / 64-label / IP / `port-xyz` reject |
| PN-B-NEG-007 | `dcp_malformed.yaml` | **NEG** | pass | truncated / unknown DCP | **wave 2** name unchanged |
| PN-B-NEG-008 | `rpc_cm_without_ar.yaml` | **NEG** | pass | CM/Alarm/output without AR | **wave 2** Control fail-closed |
| PN-B-NEG-009 | `rpc_connect_cycle_below_minimum.yaml` | **NEG** | pass | Connect reject (cycle below minimum) | 8 ms device, SCF=32 RR=4, `DB 81 02 0B`, no RTC1 |
| PN-B-ALM-001 | `alarm_tx.yaml` | catalog | pass | Alarm High | ID only |
| PN-B-ALM-002 | `alarm_low.yaml` | catalog | pass + golden | Alarm Low | ID only |
| PN-B-REC-001 | `record_read_im0.yaml` | catalog | pass | I&M0 | ID only |
| PN-B-REC-002 | `record_read_im1_4.yaml` | catalog | pass | I&M1–4 | ID only |
| PN-B-NBR-001 | `lldp.yaml` | catalog | pass | LLDP (CC-B) | ID only |
| PN-B-NBR-002 | `snmp_get_sysname.yaml` | catalog | pass | SNMP sysName | ID only |

### 3.2 이미 커버 vs 다음에 두껍게

Wave 1 이 메운 갭:

- Cyclic 이 smoke(16 프레임, `period_max_ms`) 만 있었음 → **cycle_us 대비 late/missed/jitter** + 48 사이클 기본 CI
- Release 시나리오에 IO 가 없음 → **AR lifetime + 재연결**
- Sec1 reject 는 integrity **부재** 만 → **HMAC 불량**
- malformed CM / AR 없이 cyclic / unknown record 없음 → **fail-closed TCs**

Wave 2 (이 PR) 가 메운 갭:

- 단일 AR 재 Connect / 전체 CM 경로 lifetime (`PN-B-CM-005`, `PN-B-CM-006`)
- RTC1 **payload + cycle_counter + output consume** (`PN-B-CYC-003`) 과 **4 ms** 메트릭 (`PN-B-CYC-004`)
- DCP 이름 DNS/PN 규칙 경계 / truncated DCP / AR 없이 Control·Alarm·output (`PN-B-NEG-006`–`008`). Control without AR 는 DUT 가 AR 을 올리지 않도록 fail-closed

아직 얇음 (다음 wave, 가짜 pass 하지 않음):

| 주제 | 상태 |
|------|------|
| Alarm 풀 상태머신 / Ack | dummy TX 만 (`PN-B-ALM-*`). DUT 에 Ack/상태머신 없음 — 다음 wave (스택 작업) |
| Record 인덱스 맵 (GSDML 전 구간) | I&M0–4 + unknown empty. 추가 인덱스는 DUT 가 비면 gap |
| CM 다중 AR / 동시 Connect | 스택 **단일 AR** (`PN-B-CM-005` 가 replace 를 고정). 동시 AR 은 DUT 미구현 = gap |
| Lab 프로파일 RTC1 jitter | mock soft ms. 랩은 `tests/run_ctt_lab.sh` (opt-in) |

## 4. 명시적 범위 밖 / 갭

| ID / 라벨 | 커버 | 이유 |
|-----------|------|------|
| PN-B-FSU-* | **gap** | Fast Start-Up: **DUT not implemented**. CTT 가 pass 하지 않음 |
| PN-B-MRP-* | **gap** | MRP: **DUT not implemented**. 풀 MRP 스택 비목표. 가짜 pass 금지 |
| 스위치/VLAN/멀티캐스트 스트레스 | N/A (harness) | mock 단일 스레드. Device DUT 기능 아님 |
| **IRT / PTCP / RT Class 3 / CC-C** | **oos** | 시나리오·TODO·매핑 없음. 영구 비목표 |
| 공식 PI Test Bundle 실행 / 인증 리포트 | **oos** | 공인 랩. 이 하네스가 대체하지 않음 |
| 공식 Bundle TC 번호·판정 절차 | **oos** | 라이선스 텍스트를 재구성하지 않음 |

## 5. Cyclic / timing 하네스

공통 `ctt_metrics_t` (`tools/ctt/ctt.h`):

| 필드 | 의미 |
|------|------|
| `rtc1_frames` | 사이클 카운트 (RTC1 FrameID `0x8000–0xBBFF`) |
| `cycle_ns` | `device.cycle_us` (기본 8000 µs) |
| `late_cycles` | inter-arrival `> 1.5 * cycle_ns` 이고 `≤ 2.5 * cycle_ns` |
| `missed_cycles` | inter-arrival `> 2.5 * cycle_ns` 에서 `floor(dt/cycle) - 1` |
| `jitter_max_ns` | `max \|dt - cycle_ns\|` |
| `jitter_hist[]` | 기존 coarse ms 버킷 `<4,<8,<12,<16,<20,>=20` |
| `unexpected_frames` / `ar_drops` | soak 경로 |

`io_cycle` / `soak` `expect:` (플러그인 소유):

- `min_frames`, `max_frames`, `period_max_ms` (기존)
- `max_late`, `max_missed`, `jitter_max_ms`, `min_period_samples`
- `require_ar: false` — AR 없이 돌리고 RTC1 이 나오면 fail (NEG)
- `contains` — RTC1 프로세스 이미지에 바이트열
- `cycle_counter: increasing` — Frame CycleCounter 가 증가 (wrap 허용, stall/점프 거부)

기본 CI 의 두꺼운 테스트는 `PN-B-CYC-002` (48 사이클, 8 ms) 과 `PN-B-CYC-004` (4 ms).
`PN-B-CYC-003` 은 payload / cycle_counter / output consume.
30s / 1h 는 기존처럼 `-L soak_ci` / nightly. **IRT µs 를 주장하지 않는다.**

## 6. 리포트 스키마 (`ctt-report/v1`)

```
./build/ctt --scenario tests/scenarios/profinet/rtc1_cyclic_metrics.yaml \
    --report /tmp/pn-b-cyc-002.json
# or: --report /tmp/pn-b-cyc-002.md
# env: CTT_REPORT=/tmp/out.json
```

JSON 최소 필드:

| 키 | 설명 |
|----|------|
| `schema` | `"ctt-report/v1"` |
| `disclaimer` | internal gate ≠ certification |
| `suite_id` | YAML `suite:` (`PN-B-v1`) |
| `tc_id` | YAML `id:` / `bundle_id:` |
| `name` / `protocol` / `scenario` / `transport` | 실행 식별 |
| `verdict` | `pass` \| `fail` |
| `failures` / `duration_ms` | 카운트, 벽시계 |
| `metrics.*` | rtc1 / late / missed / unexpected / ar_drops / period_* / jitter_* / cycle_ns |

EIP/Modbus/SLMP 도 같은 runner 플래그를 쓴다. 메트릭 키 이름은 공통이고,
플러그인이 채운 값만 공통 키로 실린다 (PN 의 `rtc1_frames` 는 EIP Class1 에서
재사용할 수 있음).

스키마 스모크: `ctest -R ctt_report_schema_v1` (`tools/ctt/check_report_schema.py`).

## 7. 프로파일

| 프로파일 | 언제 | 라벨 |
|----------|------|------|
| mock | 기본 PR CI | (없음) / `golden` |
| soak_ci | 30s, workflow_dispatch `soak=true` | `soak_ci` (`ctest -LE soak_ci` 로 제외) |
| nightly | 1h (또는 `--seconds`), 수동 | CMake GLOB 밖. `tests/run_mock_soak.sh` |
| lab | veth AF_PACKET | `tests/run_ctt_lab.sh`, CAP_NET_RAW |

보드(`docs/ctt_board.html`) 배지는 이 분류를 따른다. **bundle-grade 게이트가
PI 인증이 아니다** 는 배너에 고정한다.

## 8. 같은 기둥 (EIP / Modbus / SLMP landed)

EIP-A-v1 [`docs/ctt_eip_bundle.md`](ctt_eip_bundle.md) (`EIP-A-*`).
Modbus MB-T-v1 [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) (`MB-T-*`).
SLMP SLMP-3E-v1 [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) (`SLMP-3E-*`).
공통 `ctt_metrics_*` / `--report`. CC-Link / EtherCAT 은 사양 확정 전 비목표.

1. **카탈로그** — YAML `id:` / `suite:`, 기존 매트릭스에 내부 매핑
   (공식 인증 번호 복사 금지).
2. **Cyclic 하네스** — 공통 `ctt_metrics_*`. 주기를 `ctt_metrics_note_period` 에 넣는다.
3. **Lifetime** — 세션/맵 재기록. 있는 훅을 두껍게.
4. **NEG** — truncated / unknown 을 플러그인 액션으로. DUT 미구현은 gap.
5. **프로파일** — mock 기본 CI, soak 라벨, lab 은 별도.
6. **리포트** — `--report` 는 프로토콜 무관. `tc_id` 만 카탈로그.

`core/` 에 프로토콜 분기를 넣지 않는다.

## 9. 관련 문서

- [`docs/ctt.md`](ctt.md) — 하네스 설계
- [`docs/ctt_pi_matrix.md`](ctt_pi_matrix.md) — CC-A/B 내부 매핑 (인증 아님)
- [`docs/ctt_board.md`](ctt_board.md) / [`ctt_board.html`](ctt_board.html)
- [`tools/ctt/README.md`](../tools/ctt/README.md)
- [`docs/ctt_odva_matrix.md`](ctt_odva_matrix.md) — EIP 내부 매핑. 이식됨: [`docs/ctt_eip_bundle.md`](ctt_eip_bundle.md)
- [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) · [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md)
