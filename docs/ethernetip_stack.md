# EtherNet/IP stack (Fieldbus Architecture)

자체 구현 **Adapter(Device/target)** 스택 + 선택적 **Originator(client)** explicit 메시징.
`stacks/ethernetip/` in-tree. 구매 SDK 불필요.

공식 **ODVA Declaration of Conformity는 멤버십 + 공인 CT 랩**에서 나온다.
이 스택은 CT/CIP Security 경로에 맞춰 객체·EDS·보안 프로필을 갖춘 **인증 가능(certification-ready)** 구현이다.
스택 바이너리만으로 인증서가 발급되지는 않는다. SOC 초안: [`ethernetip_soc.md`](ethernetip_soc.md).

## 왜 자체 구현인가

| 선택지 | 판단 |
|--------|------|
| 구매 스택 (`third_party/`) | 저장소 미배치 시 빌드/검증 불가 |
| OpENer 등 오픈소스 | 상용 ODVA 라이선스/멤버십 이슈, 커스터마이즈 비용 |
| **자체 스택** | PROFINET과 동일 패턴 + CT용 객체/EDS/보안을 직접 맞춤 |

PROFINET(PI)보다 ODVA CT 접근이 덜 폐쇄적이라는 업계 인식이 있으나, Vendor ID·멤버십·랩 비용은 제품 측 책임이다.

## 범위

| 항목 | 상태 |
|------|------|
| Encapsulation TCP 44818 | RegisterSession, ListIdentity/Services, SendRRData |
| CIP objects (CT-facing) | Identity(+Reset/Protection Mode), Assembly, CM, Msg Router, QoS, Port, TCP/IP, Ethernet Link, EIP Security |
| Class 1 cyclic I/O | UDP 2222, Forward Open/Close, Large FO |
| Security Class 1 | HMAC-SHA256 PSK integrity (mutating UCMM / FO) |
| Security Class 2 | Class 1 + TLS PSK listen on TCP 2221 |
| EDS | `stacks/ethernetip/eds/FieldbusSensor.eds` |
| Originator explicit | Get/Set Attribute, ANSI tag path |
| Full CIP Security CT suite / DTLS I/O | 제품 확장 (기반만 제공) |
| ODVA DoC | 제품 프로세스 (멤버십+랩) |

## Security 프로필 (이 저장소)

PI/ODVA 옵션 코드를 사칭하지 않는다. Fieldbus 프로필이다.

| `security_class` | 동작 |
|------------------|------|
| 0 | 랩/개발 open |
| 1 | Integrity. PSK 필수. Forward Open / Set / Reset / Close 에 CPF integrity item `0x00C1`(32B HMAC) 없으면 거부 |
| 2 | 1 + TCP `secure_tcp_port`(기본 2221) TLS-PSK 세션에서 encapsulation 처리 |

- 키: `protocol_params.psk_hex` (64 hex chars = 32 bytes). 랩 키를 제품에 두지 말 것
- ListIdentity / Get_Attribute(조회) 는 탐색용으로 MAC 불필요
- Identity `protection_mode` (attr 17) config/`Set_Attribute` 지원

## 용량

- Assembly 최대 2048B × 64, Class1 32, TCP 32, TLS 16
- 포인트 테이블 heap 동적 확장
- `input_size` / `output_size` 로 process image 확장

## Config

```json
"protocol_params": {
  "role": "server",
  "bind_ip": "0.0.0.0",
  "port": 44818,
  "udp_io_port": 2222,
  "secure_tcp_port": 2221,
  "security_class": 1,
  "psk_hex": "1111111111111111111111111111111111111111111111111111111111111111",
  "input_assembly": 150,
  "output_assembly": 101,
  "input_size": 512,
  "output_size": 128
}
```

예제: `config/example.ethernetip.json`

## 실행

```
./build/test_eip_stack
./build/multiproto_daemon config/example.ethernetip.json
```

실기: `mock` off, Vendor ID를 ODVA 할당 값으로 교체, EDS/SOC 확정 후 CT 랩 일정.
