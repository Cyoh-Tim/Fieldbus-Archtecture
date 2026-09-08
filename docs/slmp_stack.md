# SLMP stack — 센서 범용 매핑

자체 구현 SLMP / MC Protocol. 기본 역할 **client**(센서 → PLC).
Binary **3E** 프레임(Mitsubishi SLMP Reference Manual).
통신 가이드 문서의 디바이스 코드·주소를 최대한 그대로 config에 넣을 수 있게 했다.

## 지원 요약

| 구분 | 지원 |
|------|------|
| 역할 | client(기본) / server(lab simulator) |
| 프레임 | Binary 3E (ASCII/4E 예약) |
| 커맨드 | 디바이스 일괄 읽기(0x0401) / 일괄 쓰기(0x1401) |
| 단위 | word / bit |
| 디바이스 | D/W/R/ZR/SD/TN/CN/Z …, M/X/Y/B/L/F/V/S/SM/SB/TS/TC/… + raw `0xA8` |
| 주소 | 숫자, `"100"`, `"D100"`, hex 디바이스 `"X1A"` / `"1A"` |
| 타입 | uint8/16/32/64, int*, float32/64, bool, string/ascii, raw, bcd16/32 |
| 엔디안 | ABCD / BADC / CDAB / DCBA (+ byte_order/word_order) |
| 스케일 | eng = raw * scale + offset |
| 문자열 | chars_per_word 1\|2, string_swap, trim_null |

## access (Modbus/PROFINET과 동일 — PLC 관점)

| access | 의미 (client 역할) |
|--------|---------------------|
| read | PLC가 읽는 값 → 앱 `write_point` → PLC에 batch write |
| write | PLC가 쓰는 값 → 앱 `read_point` / `poll_cycle` → PLC에서 batch read |
| readwrite | 양쪽 |

## address.slmp 필드 (별칭 포함)

| 필드 | 별칭 | 설명 |
|------|------|------|
| device_code | device, dev, soft_device | `D`/`M`/`X`/`ZR`/`0xA8` … |
| start | address, addr, head, register | 숫자 또는 `"D100"` / `"X1A"` |
| offset | reg_offset | start에 더함 |
| byte_offset | byteOffset, data_offset | 멀티워드 창 내 위치 |
| quantity | count, qty | 워드/비트 수 |
| bit | bit_offset, bit_index | 워드 내 비트 |
| bit_count | bits, bit_length | 연속 비트 수 |
| unit | access_unit | `word` \| `bit` |

## protocol_params

```json
{
  "role": "client",
  "plc_ip": "192.168.0.20",
  "port": 5000,
  "network_no": 0,
  "pc_no": 255,
  "dest_module_io": 1023,
  "dest_multidrop": 0,
  "monitoring_timer": 16,
  "timeout_ms": 1000,
  "frame": "3E"
}
```

서버(시뮬레이터) 예:

```json
{
  "role": "server",
  "bind_ip": "0.0.0.0",
  "port": 5000,
  "max_clients": 4,
  "map_words": 4096,
  "map_bits": 8192
}
```

## 예: 가이드가 제각각인 센서들

```json
{
  "points": [
    {
      "name": "barcode_value",
      "access": "read",
      "data_type": "string",
      "length": 32,
      "address": { "slmp": { "device_code": "D", "start": 100 } }
    },
    {
      "name": "temp_c",
      "access": "read",
      "data_type": "uint16",
      "scale": 0.1,
      "address": { "slmp": { "device": "D", "address": "110" } }
    },
    {
      "name": "pressure",
      "access": "read",
      "data_type": "float",
      "endian": "CDAB",
      "address": { "slmp": { "device_code": "D", "start": 200, "quantity": 2 } }
    },
    {
      "name": "plc_trigger",
      "access": "write",
      "data_type": "bool",
      "address": { "slmp": { "device_code": "M", "start": 10, "unit": "bit" } }
    },
    {
      "name": "input_x",
      "access": "write",
      "data_type": "bool",
      "address": { "slmp": { "device_code": "X", "start": "1A", "unit": "bit" } }
    }
  ]
}
```

## 스펙 근거

Binary 3E 요청/응답 레이아웃·커맨드·디바이스 코드는 Mitsubishi
**SLMP Reference Manual**(Binary communication, 3E frame)에 공개된 형식을 따른다.
특정 PLC 가이드의 디바이스 표·주소 체계는 config의 `device_code`/`start`로
반영하며, 코드 수정 없이 확장한다. ASCII·4E는 `frame` 값으로 자리만 예약.

## 실행

```
./build/multiproto_daemon config/example.slmp.json
./build/test_slmp_stack
./build/test_slmp_adapter
```
