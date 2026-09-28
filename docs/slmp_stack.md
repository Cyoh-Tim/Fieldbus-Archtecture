# SLMP stack (Fieldbus Architecture)

자체 구현 SLMP 클라이언트 스택. PLC를 대신 돌리는 컨트롤러가 아니다.
기본은 **센서가 PLC 메모리에 쓰고/읽는 쪽**(TCP client). Binary **3E** 만.

이 문서는 SLMP를 처음 보는 사람이 `config/example.slmp.json` 과
`stacks/slmp/` / `adapters/slmp/` 코드를 읽고 동작을 따라갈 수 있게 쓴다.

---

## 0. 한 줄로

Mitsubishi PLC가 쓰는 Ethernet 메시지 프로토콜이다. 예전 이름은 MC Protocol.
이 데몬에서는 센서가 PLC에 TCP로 접속해 **디바이스 메모리**(D100, M10, X1A …)를
일괄 읽기/쓰기한다.

PROFINET이 “사이클마다 프로세스 이미지 교환”이라면,
SLMP는 “필요할 때(또는 폴링마다) 특정 주소 구간을 요청/응답”이다.

---

## 1. 범위

| 항목 | 상태 |
|------|------|
| Binary 3E 프레임 | 구현 (`0x0050` 요청 / `0x00D0` 응답) |
| 역할 | **client**(기본, 센서→PLC) / **server**(랩 시뮬레이터) |
| 커맨드 | 디바이스 일괄 읽기 `0x0401`, 일괄 쓰기 `0x1401` |
| 단위 | word / bit |
| 디바이스 | D/W/R/ZR/SD/…, M/X/Y/B/… + raw `0xA8` |
| 값 매핑 | uint/int/float/bool/string/raw/BCD, 엔디안, scale/offset |
| Binary 4E | 예약만 (`frame` enum). 미구현 |
| ASCII 프레임 | 예약만. 미구현 |
| 랜덤 읽기/쓰기 커맨드 | 상수만 정의. 어댑터 경로는 일괄(batch) |
| 벤더 인증 제품 | 아님. 공개 SLMP Reference Manual(Binary 3E) 기준 |

---

## 2. 왜 이 프로젝트에 SLMP가 있나

`docs/design.md` 기준으로 센서는 프로토콜마다 역할이 다르다.

| 프로토콜 | 이 데몬의 기본 자세 |
|----------|---------------------|
| Modbus TCP | 센서가 **서버**(PLC가 읽어감) |
| PROFINET | 센서가 **Device**(컨트롤러가 cyclic IO) |
| SLMP | 센서가 **클라이언트**(센서가 PLC 메모리에 씀/읽음) |

예: 바코드 센서를 Mitsubishi PLC의 `D100`에 넣고 싶다.
PLC 가이드에 “D100부터 32워드, ASCII”라고만 있으면 → config에 그대로 적는다.
프로토콜 바이트열은 `stacks/slmp`가 만들고, 문자열 팩킹은 `adapters/slmp`가 한다.

---

## 3. 꼭 알 개념 (프로토콜 지식 최소치)

### 3.1 디바이스(device)

PLC 안 메모리 구역의 이름이다. 가이드 문서에 `D`, `M`, `X`, `Y` 로 나온다.

| 기호 | 흔한 의미 | 기본 단위 | 이 스택 코드 |
|------|-----------|-----------|--------------|
| D | 데이터 레지스터 | word(16bit) | `SLMP_DEV_D` = `0xA8` |
| W | 링크 레지스터 | word | `0xB4` |
| R / ZR | 파일 레지스터 | word | `0xAF` / `0xB0` |
| M | 내부 릴레이 | bit | `0x90` |
| X | 입력 | bit (주소가 흔히 **hex**) | `0x9C` |
| Y | 출력 | bit (hex) | `0x9D` |
| B | 링크 릴레이 | bit (hex) | `0xA0` |

가이드에 `D100` = 디바이스 D, 선두 주소 100.
`X1A` = 디바이스 X, 선두 주소 0x1A.

config에서는:

```json
{ "device_code": "D", "start": 100 }
{ "device_code": "X", "start": "1A", "unit": "bit" }
{ "device_code": "0xA8", "start": 100 }
```

이름→코드 변환: `slmp_device_code_from_name()` (`stacks/slmp/src/slmp_stack.c`).

### 3.2 word vs bit

- **word**: 16비트 한 칸. D/W 는 보통 word.
- **bit**: ON/OFF 한 칸. M/X/Y 는 보통 bit.
- 같은 M이라도 가이드가 “워드 단위로 묶어 읽어라”면 `unit: "word"` 로 둘 수 있다.

와이어에서:

- word 일괄: 포인트당 2바이트, **리틀엔디안**
- bit 일괄: 포인트당 1바이트 (`0x00` / `0x01`)

어댑터 안 캐시 윈도우는 워드를 **빅엔디안 바이트열**로 들고,
PLC로 나갈 때만 LE로 바꾼다 (`slmp_encode_batch_write`).

### 3.3 요청 / 응답 (Binary 3E)

한 번의 읽기/쓰기 = TCP로 프레임 하나 보내고, 응답 하나 받는다.
이 스택은 **한 트랜잭션이 끝날 때까지 다음을 안 보낸다.**

요청 뼈대 (`slmp_encode_batch_read` / `_write`):

```
서브헤더 0x0050
network_no, pc_no
dest_module_io (기본 0x03FF = CPU)
dest_multidrop
요청 데이터 길이
monitoring_timer
command / subcommand
선두 디바이스(3바이트) + 디바이스 코드(1) + 점수(2)
(+ 쓰기면 데이터)
```

응답:

```
서브헤더 0x00D0
… 주소 에코 …
응답 길이
end code (0 = 성공)
(+ 읽기면 데이터)
```

`end code != 0` 이면 `LOG_WARN` 후 실패 반환.

### 3.4 3E vs 4E (왜 4E를 안 했는지)

| | 3E | 4E |
|---|----|----|
| 차이 | 기본 헤더 | 3E + **시리얼 번호**로 요청/응답 짝 맞춤 |
| 이 스택 | 구현 | 미구현(예약) |

지금 모델은 “보내고 응답 대기” 한 줄이라 시리얼이 필요 없다.
가이드가 4E만 허용하거나 병렬 요청을 열면 그때 `frame: "4E"` 경로를 추가하면 된다.

---

## 4. 이 저장소에서의 역할 분리

```
config/example.slmp.json
        │
        ▼
adapters/slmp/slmp_adapter.c   ← JSON 파싱, access/타입/엔디안/스케일
adapters/slmp/slmp_codec.c     ← 숫자·문자열·비트 필드 변환
        │
        ▼
stacks/slmp/src/slmp_stack.c   ← TCP, Binary 3E, 디바이스 맵, batch R/W
```

| 계층 | 책임 | 모르는 것 |
|------|------|-----------|
| 코어 `core/` | 스케줄러, 어댑터 선택 | SLMP 프레임·디바이스 |
| 어댑터 | 포인트 ↔ 워드/비트 창 | 소켓 세부(스택에 위임) |
| 스택 | 프레임·TCP·맵 | JSON / scale / float |

공개 API는 어댑터 하나만: `slmp_adapter_create()` (`adapters/slmp/slmp_adapter.h`).

---

## 5. access (PROFINET/Modbus와 같은 PLC 관점)

헷갈리기 쉬운 부분이다. **PLC 입장**으로 적는다.

| `access` | 의미 | client에서 실제로 하는 일 |
|----------|------|---------------------------|
| `read` | PLC가 읽는 값(센서가 제공) | 앱 `write_point` → PLC에 **batch write** |
| `write` | PLC가 쓰는 값(센서가 소비) | `poll_cycle` / `read_point` → PLC에서 **batch read** |
| `readwrite` | 양쪽 | 위 둘 다 |

`config/example.slmp.json` 의 `barcode_value` 는 `access: "read"` 다.
바코드를 PLC D100에 **넣는** 값이므로, 앱이 `write_point("barcode_value", …)` 하면
어댑터가 PLC로 일괄 쓰기를 보낸다.

`plc_trigger` 는 `access: "write"` — PLC M10을 센서가 **읽어** 트리거로 쓴다.
`poll_cycle` 이 이런 포인트를 주기적으로 batch read 해 캐시에 넣는다.

---

## 6. 예제 config 해설 (`config/example.slmp.json`)

```json
{
  "protocol": "slmp",
  "device": { "name": "barcode_sensor_1", "role": "client" },
  "cycle_ms": 8,
  "protocol_params": {
    "role": "client",
    "plc_ip": "192.168.0.20",
    "port": 5000,
    "network_no": 0,
    "pc_no": 255,
    "dest_module_io": 1023,
    "monitoring_timer": 16,
    "timeout_ms": 1000,
    "frame": "3E"
  },
  "points": [ … ]
}
```

### 6.1 protocol_params

| 필드 | 의미 | 기본/비고 |
|------|------|-----------|
| `role` | `client` \| `server` | 기본 client. `server` 는 랩 시뮬 |
| `plc_ip` | PLC 주소 | client 필수. 별칭 `ip`/`host` |
| `port` | TCP 포트 | 흔히 5000 |
| `network_no` | 네트워크 번호 | 자국 0 |
| `pc_no` | PC 번호 | `255` = 자국 (`0xFF`) |
| `dest_module_io` | 대상 모듈 I/O | `1023` = `0x03FF` CPU |
| `dest_multidrop` | 멀티드롭 국번 | 보통 0 |
| `monitoring_timer` | 대기 시간 | **250ms 단위**. 16 → 4초 |
| `timeout_ms` | 소켓 I/O 타임아웃 | 기본 1000 |
| `frame` | 프레임 종류 | `"3E"` 만 동작. 그 외 거절 |
| `bind_ip` / `max_clients` | server 전용 | 시뮬 리슨 |
| `idle_timeout_ms` | server 전용 | 유휴 TCP 해제. 기본 60000 |
| `max_conn_per_ip` | server 전용 | 소스 IPv4 당 상한. 기본 4 |
| `map_words` / `map_bits` | 로컬 맵 크기 | 서버/캐시 용량 |

### 6.2 points 예시가 하는 일

| name | access | 가이드를 이렇게 읽은 것 | 동작 |
|------|--------|-------------------------|------|
| `barcode_value` | read | D100, ASCII 32자 | 앱 write → D100.. 에 문자열 팩킹 후 PLC write |
| `temperature` | read | D110, u16, 스케일 0.1 | eng↔raw 변환 후 D110 write |
| `pressure` | read | D200, float, 워드스왑(CDAB) | 2워드, 엔디안 적용 |
| `plc_trigger` | write | M10 비트 | poll 시 M10 batch read |
| `alarm_bit` | write | D300 의 bit3 | 워드 읽어 비트 마스킹 |
| `input_x` | write | X1A (hex 비트) | `start: "1A"`, `unit: "bit"` |

주소 필드 별칭(가이드 표기가 제각각일 때):

| 필드 | 별칭 |
|------|------|
| `device_code` | `device`, `dev`, `soft_device` |
| `start` | `address`, `addr`, `head`, `register` |
| `quantity` | `count`, `qty` |
| `offset` | `reg_offset` (start에 더함) |
| `bit` | `bit_offset`, `bit_index` |
| `unit` | `access_unit` (`word`\|`bit`) |

`start` 에 `"D100"` / `"X1A"` 처럼 디바이스+주소를 한 문자열로 넣어도 파서가 분리한다
(`parse_device_head` in `slmp_adapter.c`).

---

## 7. 값 변환 (어댑터 codec)

PLC 가이드는 “raw 255 = 25.5℃”, “float가 CDAB” 같이 제각각이다.
그건 스택이 아니라 `slmp_codec` + 포인트 필드가 담당한다.

| 필드 | 역할 |
|------|------|
| `data_type` | `uint16`/`float`/`string`/`bool`/… + 별칭 `u16`/`REAL`/`ascii` |
| `scale` / `offset` | eng = raw * scale + offset |
| `endian` | `ABCD`/`BADC`/`CDAB`/`DCBA` (또는 byte_order+word_order) |
| `length` | 문자열/raw 바이트 수 |
| `chars_per_word` | 문자열을 워드에 1자 또는 2자 |
| `string_swap` / `trim_null` | 문자 스왑 / 널 이후 절단 |
| `bit` / `bit_count` | 워드 안 비트필드 |

앱 ↔ 와이어 경로:

1. `write_point` — 앱 바이트 → (스케일) → canonical → endian/string pack → 워드 창 → (client면) batch write
2. `read_point` — (필요 시 batch read) → 워드 창 → unpack → (스케일) → 앱 바이트

---

## 8. 런타임 흐름

```
main
  → adapter_registry "slmp" → slmp_adapter_create()
  → init(protocol_params, points)   # JSON 파싱, stack create, map ensure
  → connect()                       # client: TCP connect / server: listen
  → 매 cycle_ms:
        poll_cycle()
          → slmp_stack_poll()       # server면 accept/요청 처리
          → access=write 포인트들 remote batch read → 로컬 캐시
  → 앱/상위 로직이 read_point / write_point 호출
```

client 연결 실패 시 `connect()` 가 음수 errno 스타일로 실패한다.
실 PLC 없이 `example.slmp.json` 을 띄우면 `plc_ip` 타임아웃이 정상이다.

랩에서 PLC 없이 프레임/매핑만 검증하려면:

- 단위 테스트가 server 맵 + `handle_request` / loopback 사용
- 또는 config `role: "server"` 로 시뮬 리슨 후 다른 클라이언트로 접속

---

## 9. 실행

빌드 후:

```
./build/multiproto_daemon config/example.slmp.json
./build/test_slmp_stack
./build/test_slmp_adapter
```

| 테스트 | 검증 내용 |
|--------|-----------|
| `test_slmp_stack` | 디바이스 테이블, 3E encode, handle_request R/W, TCP client↔server |
| `test_slmp_adapter` | string/scale/endian/bit/hex(X1A) 매핑 round-trip |

`plc_ip` / `port` 는 대상 PLC 이더넷 설정과 맞출 것.
PLC 쪽 SLMP(또는 MC) Binary, 포트(자주 5000), 방화벽 허용이 필요하다.

---

## 10. 코드 지도

| 경로 | 내용 |
|------|------|
| `stacks/slmp/include/slmp_types.h` | 서브헤더·커맨드·디바이스 코드 상수 |
| `stacks/slmp/include/slmp_stack.h` | 스택 API |
| `stacks/slmp/src/slmp_stack.c` | 프레임, TCP, 맵, batch, server poll |
| `adapters/slmp/slmp_adapter.c` | config → 포인트 → read/write/poll |
| `adapters/slmp/slmp_codec.c` | 엔디안·숫자·문자열·BCD·비트필드 |
| `config/example.slmp.json` | 센서 매핑 예 |
| `tests/test_slmp_*.c` | 스택/어댑터 단위 테스트 |

---

## 11. 스펙 근거 / 하지 않는 것

- 프레임·커맨드·디바이스 코드: Mitsubishi **SLMP Reference Manual** Binary communication, **3E** frame.
- 특정 PLC 통신 가이드의 “D100에 바코드” 같은 **주소표**는 config로만 반영한다. 코어/스택에 기종 분기를 넣지 않는다.
- Binary 4E, ASCII, 랜덤 접근 커맨드 상용 경로, 멀티 트랜잭션 파이프라인: 없음.
- 인증·적합 시험 통과를 보장하는 제품 스택이 아니다.
