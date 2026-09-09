# CTT ↔ ODVA CT-style mapping (internal)

내부 하네스 **준비도** 표다. ODVA Conformance Test (CT) **인증 evidence 가
아니다**. 공식 CT 실행·Declaration of Conformity 는 ODVA 멤버십과 공인 랩이
필요하다. 카테고리 이름은 공개 EtherNet/IP Adapter 기능 묶음에 맞춘
**내부 라벨** 이다.

DUT: self-implemented `stacks/ethernetip/` (Adapter Class 1 + UCMM + Sec 1/2
lab profile). `adapters/ethernetip/` 구매 스택 스텁은 DUT 가 아니다.

커버 열:

| 값 | 의미 |
|----|------|
| mock | `./build/ctt --transport=mock` / `ctest -L ethernetip` |
| C unit | `test_eip_crypto` / residual `test_eip_stack` |
| not yet | YAML·훅이 아직 없음 |
| N/A | 공식 CT 랩 / 멤버십 전용 |

## 시나리오 → 카테고리

| YAML (`tests/scenarios/ethernetip/`) | 내부 카테고리 | mock | 비고 |
|--------------------------------------|---------------|------|------|
| `register_session.yaml` | Encapsulation RegisterSession | mock | session handle ≠ 0 |
| `list_identity.yaml` | ListIdentity + Identity Protection Mode | mock | vendor / product name |
| `identity_get.yaml` | Identity Get_Attribute_Single | mock | vendor_id |
| `assembly_fo_io.yaml` | Assembly + Forward Open + Class 1 IO | mock | consume O→T |
| `sec_integrity_fo.yaml` | Security Class 1 integrity (lab profile) | mock | unsigned FO 거부, HMAC 수락. CPF item `0x00C1` 은 이 저장소 프로파일 |
| `qos_dscp.yaml` | QoS Object DSCP defaults | mock | Explicit 0x1B / Scheduled 0x2F |
| `acd_identity_state.yaml` | ACD + Identity state | mock | MinorRF / TCP/IP ACD Status |
| `lldp_mgmt.yaml` | LLDP Management (0x109) TX | mock | ethertype 0x88CC |
| `class1_watchdog.yaml` | Class 1 watchdog + RT stats | mock | timeout after first IO |

## CT-style categories without a scenario yet

| 카테고리 | 커버 | 메모 |
|----------|------|------|
| Encapsulation ListServices / ListInterfaces | not yet | ListIdentity / RegisterSession 만 |
| Large Forward Open / Forward Close | not yet | standard FO + IO 만 |
| Originator UCMM tag R/W | not yet | Adapter DUT 경로 |
| CIP Security TLS (Class 2) port 2221 | not yet | 스택은 있으나 CTT mock 미연결 |
| Ethernet Link / Port objects | not yet | DUT 객체는 있음 |
| Official ODVA CT lab execution / DoC | N/A | 멤버십 + 공인 랩. 이 하네스가 대체하지 않음 |

## Security lab profile

Security Class 1 HMAC 은 이 저장소 프로파일이다 (`docs/ethernetip_stack.md`).
ODVA CIP Security 할당 item 코드를 사칭하지 않는다. 매트릭스의 “integrity”
은 mutating UCMM / Forward Open 에 CPF `0x00C1` HMAC 이 없으면 거부하는
회귀를 뜻한다.

## 이 표가 말해 주지 않는 것

- CTT green 을 ODVA 인증서 대신 제출하지 말 것
- 공식 CT 버전·TC 번호·판정 절차
- 멤버십 없이 공인 랩에 들어가는 것
