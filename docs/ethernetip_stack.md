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
| CIP objects | Identity(+Reset/Protection/ACD state), Assembly, CM, Msg Router, QoS(DSCP), Port, TCP/IP(+ACD), Ethernet Link, EIP Security, LLDP Management(0x109) |
| Class 1 I/O | UDP 2222, FO/Large FO/Close, RPI produce, **watchdog timeout** |
| LLDP | TX + Management Object (수신/Data Table 없음 — 단일 포트 어댑터 경로) |
| ACD | TCP/IP status + Identity Minor Recoverable Fault (CT23 guidance) |
| Security Class 1 | HMAC-SHA256 PSK integrity item `0x00C1` |
| Security Class 2 | + TLS-PSK TCP 2221 |
| Real-time | poll budget, RPI paced TX, poll>7ms warn (ms-class RT, not IRT) |
| EDS | `stacks/ethernetip/eds/FieldbusSensor.eds` |
| ODVA DoC | 제품 프로세스 |

## Security

| `security_class` | 동작 |
|------------------|------|
| 0 | 랩 open |
| 1 | Integrity. mutating UCMM/FO에 MAC 없으면 거부 |
| 2 | 1 + TLS 2221 |

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
