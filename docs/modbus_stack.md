# Modbus TCP stack — 센서 범용 매핑

자체 구현 Modbus TCP. 기본 역할 **server(슬레이브)**.
통신 가이드 문서의 표기를 최대한 그대로 config 에 넣을 수 있게 했다.

## 지원 요약

| 구분 | 지원 |
|------|------|
| 역할 | server(slave) / client(master) |
| PDU | FC 01–06, 15, 16, **22 mask**, **23 read/write** |
| 영역 | holding / input / coil / discrete (+ 별칭 4x,3x,hr,ir …) |
| 주소 | Modicon(40001), PDU/0-based, start+offset, byte_offset, bit/bit_count |
| 타입 | uint8/16/32/64, int*, float32/64, bool, string/ascii, raw, bcd16/32 |
| 엔디안 | ABCD / BADC / CDAB / DCBA (+ byte_order/word_order) |
| 스케일 | eng = raw * scale + offset |
| 문자열 | chars_per_register 1\|2, string_swap, trim_null |

## access (PROFINET과 동일)

| access | 의미 |
|--------|------|
| read | PLC가 읽는 값 → 앱 `write_point` |
| write | PLC가 쓰는 값 → 앱 `read_point` |
| readwrite | 양쪽 |

## address.modbus 필드 (별칭 포함)

| 필드 | 별칭 | 설명 |
|------|------|------|
| register_type | type, area, table | holding\|hr\|4x / input\|ir\|3x / coil\|0x / discrete\|1x |
| start | address, register, addr, reg | `40001` 숫자 또는 문자열 |
| offset | reg_offset | start 에 더함 |
| byte_offset | byteOffset, data_offset | 멀티바이트 창 내 위치 |
| quantity | count, qty | 레지스터/비트 수 |
| bit | bit_offset, bit_index | 워드 내 비트 |
| bit_count | bits, bit_length | 연속 비트 수 |
| zero_based | address_base=zero\|pdu | 정규화 생략 |

## 포인트 공통

| 필드 | 별칭 | 설명 |
|------|------|------|
| data_type | datatype | u16, REAL, float, ascii, bcd16 … |
| scale | gain | |
| offset | | 엔지니어링 오프셋 |
| endian | endianness | ABCD\|BADC\|CDAB\|DCBA |
| byte_order / word_order | | endian 대신 조합 가능 |
| chars_per_register | | 1 또는 2 |
| string_swap / trim_null | | 문자열 팩킹 |

## protocol_params

```json
{
  "role": "server",
  "ip": "0.0.0.0",
  "port": 502,
  "unit_id": 1,
  "unit_id_any": false,
  "max_clients": 4,
  "client_timeout_ms": 200,
  "n_holding": 10000,
  "n_input": 10000,
  "n_coil": 10000,
  "n_discrete": 10000
}
```

## 예: 가이드가 제각각인 센서들

```json
{
  "points": [
    {
      "name": "temp_c",
      "access": "read",
      "data_type": "uint16",
      "scale": 0.1,
      "address": { "modbus": { "type": "4x", "address": "40001", "offset": 16 } }
    },
    {
      "name": "pressure",
      "access": "read",
      "data_type": "float",
      "endian": "CDAB",
      "address": { "modbus": { "register_type": "input", "start": 30010 } }
    },
    {
      "name": "serial",
      "access": "read",
      "data_type": "ascii",
      "length": 16,
      "chars_per_register": 2,
      "address": { "modbus": { "type": "holding", "start": 40100 } }
    },
    {
      "name": "alarm",
      "access": "write",
      "data_type": "bool",
      "address": { "modbus": { "type": "hr", "start": 40200, "bit": 3 } }
    }
  ]
}
```

## 실행

```
./build/multiproto_daemon config/example.modbus.json
./build/test_mb_stack
./build/test_mb_adapter
```
