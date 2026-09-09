# CTT ↔ PI Test Bundle 매핑 (CC-A / CC-B only)

내부 하네스 **준비도** 표다. PI Conformance 인증 evidence 가 아니다.
공식 PI Test Bundle 문서/툴 접근을 가정하지 않는다. 카테고리 이름은
공개 CC-A/CC-B 기능 묶음에 맞춘 **내부 라벨** 이다.
내부 TC ID (`PN-B-…`) 와 bundle-grade 로드맵은
[`docs/ctt_pn_bundle.md`](ctt_pn_bundle.md).
**내부 bundle-grade 게이트 ≠ PI 인증.**

범위: PROFINET **CC-A 기능 중 CC-B Device 가 쓰는 것 + CC-B neighbor
(LLDP/SNMP)**. **CC-C / IRT / RT Class 3 행은 만들지 않는다** (영구 비목표).

커버 열:

| 값 | 의미 |
|----|------|
| mock | `./build/ctt --transport=mock` / 기본 `ctest` |
| lab | `tests/run_ctt_lab.sh` / `--transport=af_packet` 로 의미 있음 |
| DUT not implemented | 스택에 기능이 없음. CTT 하네스 공백이 아님 |
| N/A (CC-C) | 제품·CTT 범위 밖. 계획하지 않음 |
| N/A | 이 DUT 프로파일과 무관 |

## 시나리오 → 카테고리

| YAML (`tests/scenarios/profinet/`) | 내부 카테고리 (CC-A/B) | mock | lab | 비고 |
|-------------------------------------|-------------------------|------|-----|------|
| `dcp_identify_name_of_station.yaml` | DCP Identify | mock + **golden replay** | Identify on veth | `PN-B-DCP-001`. FrameID `0xFEFF` |
| `dcp_get.yaml` | DCP Get | mock + golden | Get on veth | `PN-B-DCP-002` |
| `dcp_hello.yaml` | DCP Hello TX | mock + golden | Hello on veth | `PN-B-DCP-003` |
| `dcp_signal.yaml` | DCP Signal | mock + golden | Set Signal on veth | `PN-B-DCP-004` |
| `dcp_set_ip.yaml` | DCP Set IP + Hello | mock + golden | Set IP + Hello on veth | `PN-B-DCP-005` |
| `dcp_set_sec_class1.yaml` | DCP Set + Security lab profile | mock + golden (accept) | Ethernet Set 가능, HMAC 동일 | `PN-B-SEC-001`. option `0xF0` 은 이 저장소 프로파일 |
| `rpc_connect_without_integrity.yaml` | CM Connect reject (Sec1) | mock | **UDP 34964** when `device.ip` set | `PN-B-NEG-001` |
| `rpc_connect_bad_hmac.yaml` | CM Connect reject (bad HMAC) | mock | UDP | `PN-B-NEG-002`. block 있음, MAC 불량 |
| `rpc_malformed.yaml` | CM truncated / unknown op | mock | UDP | `PN-B-NEG-003`. fail closed |
| `rpc_connect_sec1_integrity.yaml` | CM Connect + Sec1 integrity | mock | UDP + 이후 RTC1 은 veth | `PN-B-CM-001`. block `0x0E01` |
| `rpc_release.yaml` | CM Release | mock | UDP | `PN-B-CM-002` |
| `rpc_ar_lifetime.yaml` | CM lifetime + reconnect | mock | UDP | `PN-B-CM-003`. Connect→IO→Release→Connect |
| `rpc_write_prmend_appready.yaml` | CM Write / ParameterEnd / ApplicationReady | mock | UDP CODESYS-like | `PN-B-CM-004` |
| `rtc1_io_cycle_smoke.yaml` | RTC1 cyclic IO (CC-A/B) | mock | UDP Connect + RTC1 on veth | `PN-B-CYC-001`. IRT 아님. soft ms bound |
| `rtc1_cyclic_metrics.yaml` | RTC1 cyclic metrics | mock | 권장하지 않음 (기본 CI) | `PN-B-CYC-002`. late/missed/jitter vs `cycle_us` |
| `io_without_ar.yaml` | RTC1 without AR | mock | — | `PN-B-NEG-004`. no cyclic if AR down |
| `alarm_tx.yaml` | Alarm High TX | mock | TX on veth (AR 후) | `PN-B-ALM-001`. dummy TX |
| `alarm_low.yaml` | Alarm Low TX | mock + golden | TX on veth | `PN-B-ALM-002`. FrameID `0xFE01` |
| `record_read_im0.yaml` | Record / I&M0 | mock | UDP | `PN-B-REC-001`. index `0xAFF0` |
| `record_read_im1_4.yaml` | Record / I&M1–4 | mock | UDP | `PN-B-REC-002`. `0xAFF1`–`0xAFF4` |
| `record_unknown_index.yaml` | Record unknown index | mock | UDP | `PN-B-NEG-005`. empty, not I&M0 leak |
| `lldp.yaml` | LLDP (CC-B) | mock | veth 가능 | `PN-B-NBR-001`. ethertype `0x88CC` |
| `snmp_get_sysname.yaml` | SNMP (CC-B) | mock (`handle_snmp`) | **UDP 161** when `device.ip` set | `PN-B-NBR-002` |
| `soak_short.yaml` | RTC1 soak (내부) | mock (`ctest`) | 권장하지 않음 | `PN-B-CYC-010`. 회귀 길이 + metrics |
| `soak_ci.yaml` | RTC1 soak 30s | mock (`-L soak_ci`) | 수동 | `PN-B-CYC-011`. PR 기본 게이트 제외 |
| `nightly/soak_nightly.yaml` | soak 1h | 수동 mock | 수동 | `PN-B-CYC-012`. ctest 미등록 |

## Bundle 스타일 카테고리 (시나리오가 없는 것)

| 카테고리 | 커버 | 메모 |
|----------|------|------|
| Fast Start-Up | **DUT not implemented** | 스택에 FSU 훅 없음. CTT 갭이 아님. 이 PR 에서 FSU 스택을 만들지 않음 |
| MRP (CC-B 옵션) | **DUT not implemented** | MRP 미디어 리던던시 없음. CTT 갭이 아님. 풀 MRP 스택 비목표 |
| 스위치/VLAN/멀티캐스트 스트레스 | N/A (harness) | mock 단일 스레드. Device DUT 기능이 아님 |
| **IRT / PTCP / RT Class 3 / CC-C** | **N/A (CC-C)** | 시나리오·TODO·매핑 없음 |
| PI 인증 리포트 / 공식 Bundle 실행 | N/A | 공인 랩. 이 하네스가 대체하지 않음 |

## Security lab profile

Security Class 1 HMAC 은 이 저장소 프로파일이다 (`docs/profinet_stack.md`).
PI 할당 option/block 코드를 사칭하지 않는다. 매트릭스의 “security lab
profile” 은 DCP Set `0xF0/0x01` 과 Connect block `0x0E01` 회귀를 뜻한다.

## EtherNet/IP / ODVA CT

EIP 플러그인은 구현됨 (`tools/ctt/proto/ethernetip/`, DUT `stacks/ethernetip/`).
내부 카테고리 표는 [`docs/ctt_odva_matrix.md`](ctt_odva_matrix.md).
공식 ODVA CT 는 멤버십+공인 랩. CTT green 이 인증을 대체하지 않는다.

내부 bundle-grade 카탈로그: [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md)
(`MB-T-*`), [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) (`SLMP-3E-*`).
공식 인증이 아니다.

- `docs/ctt_modbus_matrix.md` — TCP FC, 공식 Modbus.org 인증 아님
- `docs/ctt_slmp_matrix.md` — Binary 3E batch, Mitsubishi 공식 인증 아님

## 이 표가 말해 주지 않는 것

- CTT green 을 PI 인증서 대신 제출하지 말 것
- Bundle 버전·TC 번호·공식 판정 절차
- CC-C 적합성
