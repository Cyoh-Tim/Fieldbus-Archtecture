# EtherNet/IP stack (Fieldbus Architecture)

자체 구현 **Adapter(Device/target)** 스택 + 선택적 **Originator(client)** explicit 메시징.
구매 벤더 SDK / OpENer 없이 `stacks/ethernetip/` 에 둔다.
ODVA 인증 제품이 아니다.

## 왜 자체 구현인가

| 선택지 | 판단 |
|--------|------|
| 구매 스택 (`third_party/`) | 저장소에 미배치. 라이선스 코드 없이는 빌드/검증 불가 |
| OpENer 등 오픈소스 | 상용 시 ODVA 멤버십/라이선스 이슈, 의존성·용량 커스터마이즈가 무거움 |
| **자체 스택** | PROFINET과 동일 패턴. 센서 process image / 포인트 매핑 확장성을 직접 제어 |

`third_party/ethernetip_stack/` 자리는 향후 벤더 스택으로 교체할 때를 위해 남겨 둔다.
어댑터 공개 API(`ethernetip_adapter_create`)와 config 스키마는 스택 교체와 무관하게 유지한다.

## 범위

| 항목 | 상태 |
|------|------|
| Encapsulation TCP 44818 | RegisterSession, ListIdentity/Services, SendRRData |
| CIP objects | Identity, Assembly, Connection Manager, TCP/IP(최소), Ethernet Link(최소) |
| Class 1 cyclic I/O | UDP 2222, Forward Open/Close, Sequenced Address + Connected Data |
| Large Forward Open | 지원 |
| Originator explicit | Get/Set Attribute Single, ANSI symbolic tag path |
| Logix 전체 태그 모델 / CIP Security | 미구현 |
| ODVA 인증 | 아님 |

## 용량 (센서 확장용)

헤더 `eip_types.h` 기본값:

- Assembly 인스턴스 최대 64, 인스턴스당 최대 2048 bytes
- Class 1 연결 32, TCP 세션 32
- 어댑터 포인트 테이블은 heap 동적 확장 (초기 256, 필요 시 배가)

`protocol_params.input_size` / `output_size` 로 process image 를 키운다.
포인트 `byte_offset+length` 가 더 크면 init 시 자동 확장한다(상한 `EIP_ASSEMBLY_SIZE_MAX`).

## Config

예제: `config/example.ethernetip.json`

```json
"protocol_params": {
  "role": "server",
  "bind_ip": "0.0.0.0",
  "port": 44818,
  "udp_io_port": 2222,
  "input_assembly": 150,
  "output_assembly": 101,
  "input_size": 512,
  "output_size": 128,
  "rpi_us": 8000
}
```

포인트 주소 (`address.ethernetip`):

- Assembly 오프셋 (권장, cyclic): `{ "assembly": 150, "byte_offset": 0, "length": 32 }`
- 태그 심볼: `{ "tag": "Sensor1.Barcode" }` (어댑터에서는 input assembly 매핑)
- CIP 경로 (originator): `{ "class_id": 4, "instance": 150, "attribute": 3 }`

`access: read` → 센서가 채우는 input (T→O)  
`access: write` → 스캐너가 쓰는 output (O→T)

## 실행

```
./build/test_eip_stack
./build/multiproto_daemon config/example.ethernetip.json
```

실기 연동 시 `protocol_params.mock` 을 끄고 `bind_ip`/어셈블리 번호를 PLC 가이드에 맞춘다.
TCP 44818 / UDP 2222 방화벽을 연다.
