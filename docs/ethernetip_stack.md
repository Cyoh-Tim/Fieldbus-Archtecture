# EtherNet/IP stack (Fieldbus Architecture)

자체 구현 **Adapter(Device/target)** + 선택적 **Originator**.
입문자용 설명·코드 예시는 [`ethernetip_guide.md`](ethernetip_guide.md).
SOC 초안: [`ethernetip_soc.md`](ethernetip_soc.md).

공식 **ODVA DoC는 멤버십 + 공인 CT 랩** 제품 프로세스다. 스택은 CT21/23 계열
**ship 준비**(객체·EDS·보안·LLDP·ACD·QoS·Class1 워치독)까지 포함한다.

## 범위

| 항목 | 상태 |
|------|------|
| Encapsulation TCP 44818 | RegisterSession, ListIdentity/Services, SendRRData |
| CIP objects | Identity(+Reset/Protection/ACD state), Assembly, CM, Msg Router, QoS(DSCP), Port, TCP/IP(+ACD), Ethernet Link, 0x5E 자체 보안 프로파일 속성, LLDP Management(0x109) |
| Class 1 I/O | UDP 2222, FO/Large FO/Close, RPI produce, **watchdog timeout** |
| LLDP | TX + Management Object (수신/Data Table 없음 — 단일 포트 어댑터 경로) |
| ACD | TCP/IP status + Identity Minor Recoverable Fault (CT23 guidance) |
| 자체 보안 프로파일 `security_class` 1 | HMAC-SHA256 PSK, CPF item `0x00C1` |
| 자체 보안 프로파일 `security_class` 2 | + TLS-PSK TCP 2221 (ODVA CIP Security 아님) |
| Real-time | poll budget, RPI paced TX, poll>7ms warn (ms-class RT, not IRT) |
| EDS | `stacks/ethernetip/eds/FieldbusSensor.eds` |
| ODVA DoC | 제품 프로세스 |

## 보안

자체 보안 프로파일 (HMAC 무결성 / TLS-PSK, ODVA CIP Security 아님, 인증 주장 아님).

config 키 이름은 `security_class` 다. `EIP_SECURITY_CLASS_*` 도 그대로다.
ODVA Vol 8 (TLS/DTLS, 객체 0x5D/0x5E/0x5F 의 표준 속성, ListIdentity 0x0086) 이 아니다.
`security_class` ≥ 1 이면 표준 Originator 의 Forward Open 은 MAC 이 없어 거절된다.
0x5E Get 속성은 이 프로파일의 값이고, ODVA EtherNet/IP Security Object 속성이 아니다.

| `security_class` | 동작 |
|------------------|------|
| 0 | 끔 (랩) |
| 1 | HMAC 무결성. mutating UCMM/Forward Open 에 MAC 없으면 거부 |
| 2 | 1 + TLS-PSK TCP 2221. 평문 44818 은 열려 있고 UDP I/O 는 보호하지 않음 |

`psk_hex`: 64 hex chars. 랩 키를 제품에 두지 말 것.

## Real-time notes

- 데몬 `cycle_ms` 기본 8ms. PREEMPT_RT 없이도 편차 ~0.1ms 관측(설계 문서).
- `eip_stack_poll` 은 TCP/UDP 처리량에 **예산**을 둬 사이클 초과를 완화한다.
- Class 1 은 RPI 미도래 시 송신하지 않으며, O→T 공백이 워치독을 넘기면 연결 해제.
- IRT / CIP Sync / 마이크로초 동기화는 범위 밖.

## Config keys (추가)

```json
"lldp_enable": true,
"lldp_tx_interval_sec": 30,
"acd_enable": true,
"iface": "eth0",
"security_class": 1,
"psk_hex": "…",
"protection_mode": 0,
"idle_timeout_ms": 60000,
"max_conn_per_ip": 4
```

| 키 | 기본 | 설명 |
|----|------|------|
| `idle_timeout_ms` | 60000 | TCP(및 TLS) 유휴 연결 해제. `0` 도 기본값 |
| `max_conn_per_ip` | 4 | 소스 IPv4 당 동시 연결 상한. `0` 도 기본값 |
| `protection_mode` | 0 | Identity attr 17. 비0 이면 Reset/Set_Attribute Privilege `0x0F` |

## 실행

```
./build/test_eip_stack
./build/test_eip_crypto
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
ctest --test-dir build --output-on-failure -L ethernetip
./build/multiproto_daemon config/example.ethernetip.json
```
