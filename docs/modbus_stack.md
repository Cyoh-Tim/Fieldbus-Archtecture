# Modbus TCP stack (Fieldbus Architecture)

자체 구현 Modbus TCP 스택. **기본 역할은 서버(슬레이브)**.
PROFINET Device 스택과 같은 배포 모델이다 — PLC/스캐너가 마스터로 접속한다.

libmodbus 등 외부 라이브러리는 쓰지 않는다. (`stacks/modbus/`)

## 왜 자체 구현인가

| 선택지 | 판단 |
|--------|------|
| libmodbus | LGPL 의존, 서버/사이클 모델이 프레임워크와 어긋나기 쉽고, 환경에 패키지 필수 |
| 자체 스택 | PROFINET과 동일한 `stacks/` + thin adapter 구조, 의존성 0, 서버 맵이 process image처럼 동작 |

## 범위

| 항목 | 상태 |
|------|------|
| TCP server (slave) | listen + 다중 마스터(최대 4) |
| TCP client (master) | 선택 — `protocol_params.role: "client"` |
| Holding / Input / Coil / Discrete | 로컬 맵 + PDU |
| 주소 offset / byte_offset / bit / quantity | config |
| scale / offset / byte_order / word_order | config |
| 인증/암호화 | 없음 (표준 Modbus TCP) |

## 프레임워크 규칙 (프로토콜을 몰라도 되는 부분)

PROFINET과 **같은 access 의미**를 쓴다.

| `access` | 의미 | 앱 API | PLC 동작 |
|----------|------|--------|----------|
| `read` | PLC가 읽는 센서 값 | `write_point` 로 맵에 게시 | Holding/Input/Coil 읽기 |
| `write` | PLC가 쓰는 명령 | `read_point` 로 맵에서 조회 | Coil/Holding 쓰기 |

### 주소 (`address.modbus`)

가이드에 적힌 숫자를 그대로 넣는다. 스택이 정규화한다.

| 필드 | 의미 | 예 |
|------|------|----|
| `register_type` | holding / input / coil / discrete | `"holding"` |
| `start` | 가이드 주소 또는 0-based | `40001` |
| `offset` | start 에 더할 레지스터/비트 오프셋 | `16` → 실제 40017 |
| `byte_offset` | 멀티바이트 창 안의 바이트 위치 | 문자열 일부 슬라이스 |
| `quantity` | 레지스터/비트 개수 (생략 시 타입으로 추론) | `2` |
| `bit` | holding/input 워드 안의 비트(0..15) | `3` |
| `zero_based` | true 면 40001 정규화 생략 | `false` |

| 가이드 표기 | `register_type` | `start` 예 | 내부 베이스 |
|-------------|-----------------|-----------|-------------|
| 4xxxx Holding | `holding` | `40001` | 0 |
| 3xxxx Input | `input` | `30001` | 0 |
| 1xxxx Discrete | `discrete` | `10001` | 0 |
| Coil 1 | `coil` | `1` | 0 |

### 값 변환 (포인트 공통)

| 필드 | 의미 |
|------|------|
| `data_type` | uint16 / int16 / uint32 / int32 / float32 / bool / string |
| `scale`, `offset` | `eng = raw * scale + offset` (설정 시 read는 float32 eng 반환) |
| `byte_order` | `big` (기본) / `little` |
| `word_order` | 32비트: `ab` (기본) / `ba` (워드 스왑, CDAB) |
| `length` | 문자열 바이트 수 |

문자열은 레지스터당 2바이트(빅엔디안)로 팩한다. `length: 32` → Holding 16워드.

## 설정 예

```json
{
  "protocol": "modbus_tcp",
  "device": { "name": "barcode_sensor_1", "role": "server" },
  "cycle_ms": 8,
  "protocol_params": {
    "role": "server",
    "ip": "0.0.0.0",
    "port": 502,
    "unit_id": 1
  },
  "points": [
    {
      "name": "temperature",
      "access": "read",
      "data_type": "uint16",
      "scale": 0.1,
      "offset": 0.0,
      "byte_order": "big",
      "address": {
        "modbus": {
          "register_type": "holding",
          "start": 40001,
          "offset": 16
        }
      }
    },
    {
      "name": "trigger",
      "access": "write",
      "data_type": "bool",
      "address": { "modbus": { "register_type": "coil", "start": 1 } }
    }
  ]
}
```

`device.role` 은 문서용이고, 어댑터가 읽는 값은 `protocol_params.role` 이다
(코어는 protocol_params만 어댑터에 전달). 생략 시 **server**.

## 실행

```
./build/multiproto_daemon config/example.modbus.json
./build/test_mb_stack
```

포트 502는 권한이 필요할 수 있다. 랩에서는 `port: 1502` 로 바꿔도 된다.

## 점대점 매핑

- `poll_cycle`: 서버는 accept/요청 처리. 클라이언트는 등록 포인트를 일괄 읽어 캐시.
- `read_point` / `write_point`: 로컬 맵 + scale/byte_order 변환.
