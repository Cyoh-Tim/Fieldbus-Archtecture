# CTT ↔ PI Test Bundle 매핑 (CC-A / CC-B only)

내부 하네스 **준비도** 표다. PI Conformance 인증 evidence 가 아니다.
공식 PI Test Bundle 문서/툴 접근을 가정하지 않는다. 카테고리 이름은
공개 CC-A/CC-B 기능 묶음에 맞춘 **내부 라벨** 이다.

범위: PROFINET **CC-A 기능 중 CC-B Device 가 쓰는 것 + CC-B neighbor
(LLDP/SNMP)**. **CC-C / IRT / RT Class 3 행은 만들지 않는다** (영구 비목표).

커버 열:

| 값 | 의미 |
|----|------|
| mock | `./build/ctt --transport=mock` / 기본 `ctest` |
| lab | `tests/run_ctt_lab.sh` / `--transport=af_packet` 로 의미 있음 |
| not yet | YAML·훅이 아직 없음. 후속 하네스 작업 |
| N/A (CC-C) | 제품·CTT 범위 밖. 계획하지 않음 |
| N/A | 이 DUT 프로파일과 무관 |

## 시나리오 → 카테고리

| YAML (`tests/scenarios/profinet/`) | 내부 카테고리 (CC-A/B) | mock | lab | 비고 |
|-------------------------------------|-------------------------|------|-----|------|
| `dcp_identify_name_of_station.yaml` | DCP Identify | mock + **golden replay** | Identify on veth | FrameID `0xFEFF`, NameOfStation |
| `dcp_set_sec_class1.yaml` | DCP Set + Security lab profile | mock + golden (accept) | Ethernet Set 가능, HMAC 동일 | option `0xF0` 은 이 저장소 프로파일 |
| `rpc_connect_without_integrity.yaml` | CM Connect reject (Sec1) | mock | RPC 는 in-process 훅 | 실 UDP 34964 아님 |
| `rpc_connect_sec1_integrity.yaml` | CM Connect + Sec1 integrity | mock | 훅 + 이후 RTC1 은 veth 가능 | block `0x0E01` |
| `rtc1_io_cycle_smoke.yaml` | RTC1 cyclic IO (CC-A/B) | mock | Connect 훅 + RTC1 on veth | IRT 아님. soft ms bound |
| `rpc_release.yaml` | CM Release | mock | 훅 | |
| `alarm_tx.yaml` | Alarm High TX | mock | TX on veth (AR 후) | dummy TX, 풀 상태머신 아님 |
| `record_read_im0.yaml` | Record / I&M0 | mock | 훅 | index `0xAFF0` |
| `lldp.yaml` | LLDP (CC-B) | mock | veth 가능 | ethertype `0x88CC` |
| `snmp_get_sysname.yaml` | SNMP (CC-B) | mock | **not yet** on wire | `handle_snmp`, UDP 161 아님 |
| `soak_short.yaml` | RTC1 soak (내부) | mock (`ctest`) | 권장하지 않음 | 회귀 길이 |
| `soak_ci.yaml` | RTC1 soak 30s | mock (`-L soak_ci`) | 수동 | PR 기본 게이트 제외 |
| `nightly/soak_nightly.yaml` | soak 1h | 수동 mock | 수동 | ctest 미등록 |

## Bundle 스타일 카테고리 (시나리오가 없는 것)

| 카테고리 | 커버 | 메모 |
|----------|------|------|
| DCP Get / Hello / Signal / Set IP | not yet | Identify/Set Name 만 있음 |
| CM Write / ParameterEnd / ApplicationReady | not yet | Connect/Release/Read 만 |
| Alarm Low / 진단 상태머신 | not yet | High dummy TX 만 |
| I&M1–4 / 기타 record index | not yet | I&M0 만 |
| Fast Start-Up | not yet | DUT 미구현 |
| MRP (CC-B 옵션) | not yet | DUT 미구현 |
| 실 UDP RPC (CM) / SNMP :161 | not yet | lab 문서화, CTT stub 미연결 |
| 스위치/VLAN/멀티캐스트 스트레스 | not yet | mock 단일 스레드 |
| **IRT / PTCP / RT Class 3 / CC-C** | **N/A (CC-C)** | 시나리오·TODO·매핑 없음 |
| PI 인증 리포트 / 공식 Bundle 실행 | N/A | 공인 랩. 이 하네스가 대체하지 않음 |

## Security lab profile

Security Class 1 HMAC 은 이 저장소 프로파일이다 (`docs/profinet_stack.md`).
PI 할당 option/block 코드를 사칭하지 않는다. 매트릭스의 “security lab
profile” 은 DCP Set `0xF0/0x01` 과 Connect block `0x0E01` 회귀를 뜻한다.

## EtherNet/IP / ODVA CT (stub)

EIP 플러그인은 **예약**이다 (`tools/ctt/proto/ethernetip/`, PR #4 merge 후).
ODVA CT 카테고리 매핑은 플러그인이 생긴 뒤에 이 문서에 짧은 표를 추가한다.
지금은 행을 만들지 않는다. Modbus / SLMP 플러그인도 이 페이즈에 없다.

## 이 표가 말해 주지 않는 것

- CTT green 을 PI 인증서 대신 제출하지 말 것
- Bundle 버전·TC 번호·공식 판정 절차
- CC-C 적합성
