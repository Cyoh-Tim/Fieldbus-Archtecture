# CTT ↔ ODVA CT-style mapping (internal)

내부 하네스 **준비도** 표다. ODVA Conformance Test (CT) **인증 evidence 가
아니다**. 공식 CT 실행·Declaration of Conformity 는 ODVA 멤버십과 공인 랩이
필요하다. 카테고리 이름은 공개 EtherNet/IP Adapter 기능 묶음에 맞춘
**내부 라벨** 이다.

DUT: self-implemented `stacks/ethernetip/` (Adapter Class 1 + UCMM + Sec 1/2
lab profile). `adapters/ethernetip/` 데몬 어댑터는 DUT 가 아니다.

내부 bundle-grade 카탈로그·여섯 기둥: [`docs/ctt_eip_bundle.md`](ctt_eip_bundle.md)
(`EIP-A-*`, **≠ ODVA 인증**).

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
| `register_session.yaml` | Encapsulation RegisterSession | mock | session handle ≠ 0. `EIP-A-ENC-001` |
| `list_identity.yaml` | ListIdentity + Identity Protection Mode | mock | vendor / product name. `EIP-A-ENC-002` |
| `identity_get.yaml` | Identity Get_Attribute_Single | mock | vendor_id. `EIP-A-ID-001` |
| `assembly_fo_io.yaml` | Assembly + Forward Open + Class 1 IO | mock | consume O→T. `EIP-A-CM-001` |
| `class1_lifetime.yaml` | Forward Open lifetime + Forward Close | mock | FO→IO→Close→re-Open. `EIP-A-CM-002` |
| `class1_lifetime_dual.yaml` | two Class 1 connections | mock | FO A+B, Close A, B stays. `EIP-A-CM-003` |
| `class1_cyclic_metrics.yaml` | Class 1 cyclic metrics | mock | 48 cycles, late/missed/jitter vs RPI. `EIP-A-CYC-002` |
| `class1_cycle_4ms.yaml` | Class 1 4 ms metrics | mock | `rpi_us: 4000`. `EIP-A-CYC-003` |
| `sec_integrity_fo.yaml` | Security Class 1 integrity (lab profile) | mock | unsigned FO 거부, HMAC 수락. CPF item `0x00C1` 은 이 저장소 프로파일. `EIP-A-SEC-001` |
| `fo_bad_hmac.yaml` | Security Class 1 reject (bad HMAC) | mock | item 있음, MAC 불량. `EIP-A-NEG-001` |
| `encap_malformed.yaml` | Encapsulation truncated / unknown cmd | mock | fail closed. `EIP-A-NEG-002` |
| `io_without_fo.yaml` | Class 1 reject (no FO) | mock | produce 없음. `EIP-A-NEG-003` |
| `qos_dscp.yaml` | QoS Object DSCP defaults | mock | Explicit 0x1B / Scheduled 0x2F. `EIP-A-QOS-001` |
| `acd_identity_state.yaml` | ACD + Identity state | mock | MinorRF / TCP/IP ACD Status. `EIP-A-ACD-001` |
| `lldp_mgmt.yaml` | LLDP Management (0x109) TX | mock | ethertype 0x88CC. `EIP-A-NBR-001` |
| `class1_watchdog.yaml` | Class 1 watchdog + RT stats | mock | timeout after first IO. `EIP-A-CYC-001` |

## CT-style categories without a scenario yet

| 카테고리 | 커버 | 메모 |
|----------|------|------|
| Encapsulation ListServices / ListInterfaces | not yet | ListIdentity / RegisterSession 만. ListServices DUT 핸들러는 있으나 CTT YAML 없음. ListInterfaces **DUT not implemented** |
| Large Forward Open | not yet | standard FO + Close + dual conn (`EIP-A-CM-002`/`003`) |
| Originator UCMM tag R/W | not yet | Adapter DUT 경로 |
| CIP Security TLS (Class 2) port 2221 | not yet | 스택은 있으나 CTT mock 미연결 |
| Ethernet Link / Port objects | not yet | DUT 객체는 있음 |
| Official ODVA CT lab execution / DoC | N/A | 멤버십 + 공인 랩. 이 하네스가 대체하지 않음 |

## Security lab profile

Security Class 1 HMAC 은 이 저장소 프로파일이다 (`docs/ethernetip_stack.md`).
ODVA CIP Security 할당 item 코드를 사칭하지 않는다. 매트릭스의 “integrity”
은 mutating UCMM / Forward Open 에 CPF `0x00C1` HMAC 이 없으면 거부하는
회귀를 뜻한다. HMAC 불량은 `EIP-A-NEG-001`.

## 이 표가 말해 주지 않는 것

- CTT green 을 ODVA 인증서 대신 제출하지 말 것
- 공식 CT 버전·TC 번호·판정 절차
- 멤버십 없이 공인 랩에 들어가는 것
