# Modbus TCP stack (Fieldbus Architecture)

자체 구현 Modbus TCP 스택. **기본 역할은 서버(슬레이브/디바이스)** 이다.
PLC·스캐너가 마스터로 접속하는 모델이며, PROFINET Device 스택과 같은 배포 형태다.

이 문서는 Modbus를 **전혀 모르는 사람**이 `config/example.modbus.json` 과
`stacks/modbus/`, `adapters/modbus/` 코드만 보고도 “무엇을 어디에 적으면
동작하는지” 이해하도록 쓰였다. 프로토콜 이론서가 아니라 **이 저장소 프로파일**이다.

---

## 0. 한 줄로

> 센서/장치가 Modbus TCP로 **포트(기본 502)를 열고 기다리고**, PLC가 접속해서
> 레지스터·코일을 읽고 쓴다. 사용자는 통신 가이드의 주소만 JSON `points`에 옮긴다.

libmodbus 등 외부 라이브러리는 쓰지 않는다.

---

## 1. Modbus가 뭔가 (사전 지식 0)

공장 장비끼리 “이 주소의 값을 읽어라 / 써라” 라고 주고하는 **아주 단순한** 산업용
프로토콜이다.

| 용어 | 이 프로젝트에서 | 비유 |
|------|-----------------|------|
| Master (클라이언트) | 보통 **PLC** | 질문하는 쪽 |
| Slave / Server | **이 데몬**(센서 쪽) | 답하는 쪽 |
| Register / Coil | 숫자·비트 저장칸 | 편지함 칸 번호 |
| Function Code (FC) | 읽기/쓰기 명령 종류 | “읽기 요청”, “쓰기 요청” |

TCP 버전이 **Modbus TCP**다. 이 스택은 TCP만 다룬다 (시리얼 RTU 케이블은 없음).

### 왜 “D 레지스터”가 아닌가

미쓰비시 PLC 가이드에 나오는 **D/M/X/Y** 는 SLMP·CC-Link 쪽 표기다.
Modbus에는 그런 이름이 없고, 아래 **네 칸**만 있다.

| 영역 | config `register_type` | 가이드에 자주 보이는 표기 | 의미 |
|------|------------------------|---------------------------|------|
| Holding | `holding` / `hr` / `4x` | 40001, 4xxxx | 16비트, 읽기·쓰기 |
| Input | `input` / `ir` / `3x` | 30001, 3xxxx | 16비트, 보통 읽기 전용 |
| Coil | `coil` / `0x` | 00001, coil 1 | 1비트, 읽기·쓰기 |
| Discrete | `discrete` / `di` / `1x` | 10001 | 1비트, 보통 읽기 전용 |

가이드에 “Holding Register 40017” 이라고 나오면 → `type: holding`, `start: 40001`,
`offset: 16` (또는 `start: 40017`) 로 적으면 된다.

---

## 2. 이 저장소에서의 역할

```
  PLC (Master)  ----TCP:502---->  multiproto_daemon (Slave/Server)
                                      │
                                      ├─ adapters/modbus/   JSON ↔ 주소 매핑
                                      └─ stacks/modbus/     실제 TCP + PDU 처리
```

- **코어**(`core/`)는 Modbus를 모른다. `protocol: "modbus_tcp"` 만 보고 어댑터를 고른다.
- **어댑터**는 통신 가이드 표기(40001, CDAB, scale 0.1 …)를 해석한다.
- **스택**은 소켓·프레임(FC)만 처리하고, “온도가 뭔지”는 모른다.

PROFINET과 같이:

| 계층 | 경로 |
|------|------|
| 스택 | `stacks/modbus/` |
| 어댑터 | `adapters/modbus/` |
| 예제 설정 | `config/example.modbus.json` |
| 단위 테스트 | `tests/test_mb_stack.c`, `tests/test_mb_adapter.c` |
| 장시간 검증 | `tests/mb_reliability_harness.py` |

---

## 3. 범위 (이 스택이 하는 일 / 안 하는 일)

| 항목 | 상태 |
|------|------|
| Modbus TCP 서버(슬레이브) | 기본. listen + 다중 마스터(최대 8) |
| Modbus TCP 클라이언트(마스터) | 선택 (`protocol_params.role: "client"`) |
| FC 01, 02, 03, 04, 05, 06, 15, 16 | 지원 |
| FC 22 Mask Write, FC 23 Read/Write | 지원 |
| Holding / Input / Coil / Discrete | 로컬 맵 |
| 주소 별칭·offset·bit·endian·scale | 어댑터 config |
| Modbus RTU (시리얼) | 없음 |
| 암호화/인증 | 없음 (표준 Modbus TCP) |
| 공식 인증 제품 | 아님. 동작하는 스택 프로파일 |

---

## 4. access 의미 (PROFINET과 동일 — 가장 중요)

프레임워크를 쓰는 사람은 **PLC 관점**만 기억하면 된다.

| `access` | 의미 | 앱이 할 일 | PLC가 하는 일 |
|----------|------|------------|---------------|
| `read` | PLC가 **읽는** 센서 값 | `write_point` 로 맵에 게시 | Holding/Input/Coil 읽기 |
| `write` | PLC가 **쓰는** 명령 | `read_point` 로 맵에서 조회 | Coil/Holding 쓰기 |
| `readwrite` | 양쪽 | 둘 다 | 둘 다 |

예: 바코드 문자열은 PLC가 읽어 가므로 `access: "read"`.
트리거 비트는 PLC가 켜므로 `access: "write"`.

---

## 5. 주소 적는 법 (가이드 → JSON)

`address.modbus` 에 적는다. 코어는 이 내용을 해석하지 않는다.

### 5.1 필드와 별칭

| 필드 | 별칭 | 설명 |
|------|------|------|
| `register_type` | `type`, `area`, `table` | holding / input / coil / discrete (+ 4x, hr, 3x …) |
| `start` | `address`, `register`, `addr`, `reg` | `40001` 숫자 **또는** `"40001"` 문자열 |
| `offset` | `reg_offset` | start 에 더할 레지스터/비트 오프셋 |
| `byte_offset` | `byteOffset`, `data_offset` | 여러 바이트 값 안의 시작 위치 |
| `quantity` | `count`, `qty` | 레지스터/비트 개수 (생략 시 타입으로 추론) |
| `bit` | `bit_offset`, `bit_index` | Holding/Input 워드 안의 비트(0..15) |
| `bit_count` | `bits`, `bit_length` | 연속 비트 수 (최대 32) |
| `zero_based` | `address_base: "zero"|"pdu"` | true면 40001 정규화 안 함 |

### 5.2 주소 정규화 (몰라도 됨 — 스택이 함)

| 가이드에 적힌 것 | 내부 0-based 주소 |
|------------------|-------------------|
| Holding 40001 | 0 |
| Holding 40017 | 16 |
| Input 30001 | 0 |
| Coil 1 | 0 |
| Discrete 10001 | 0 |
| `zero_based: true` + `start: 16` | 16 (그대로) |

실무 팁: 가이드가 “베이스 40001, 오프셋 16” 이면

```json
"address": { "modbus": { "type": "4x", "address": "40001", "offset": 16 } }
```

또는 그냥 `"start": 40017` 도 된다.

---

## 6. 값 타입·스케일·엔디안

포인트 **공통** 필드 (프로토콜과 무관한 프레임워크 필드 + Modbus 팩킹).

| 필드 | 별칭 | 설명 |
|------|------|------|
| `data_type` | `datatype` | uint8/16/32/64, int*, float32/64, bool, string/ascii, raw, bcd16/32 (+ `u16`, `REAL` …) |
| `length` | | 문자열·raw 바이트 길이 |
| `scale` / `gain` | | 엔지니어링 환산 |
| `offset` | | `eng = raw * scale + offset` |
| `endian` | `endianness` | `ABCD` / `BADC` / `CDAB` / `DCBA` |
| `byte_order` / `word_order` | | endian 대신 조합해도 됨 |
| `chars_per_register` | | 문자열: 레지스터당 1 또는 2문자 |
| `string_swap` / `trim_null` | | 문자 순서·널 트림 |

### 스케일 예

가이드: “온도는 Holding uint16, 0.1 ℃ 단위”

```json
{
  "name": "temperature",
  "access": "read",
  "data_type": "uint16",
  "scale": 0.1,
  "offset": 0.0,
  "address": { "modbus": { "type": "holding", "start": 40017 } }
}
```

레지스터에 255가 있으면 엔지니어링 값은 25.5다. (`scale`/`offset`이 기본이 아니면
`read_point`는 float32 엔지니어링 값을 돌려준다.)

### 엔디안 예

32비트 float가 PLC마다 바이트 순서가 다르다. 가이드에 **CDAB** 라고 나오면:

```json
"data_type": "float",
"endian": "CDAB"
```

네 가지(`ABCD`/`BADC`/`CDAB`/`DCBA`)만 기억하면 대부분의 센서 가이드를 커버한다.

### 문자열

기본은 레지스터당 **2문자**(하이바이트·로우바이트). `length: 32` → Holding 16워드.

```json
"data_type": "string",
"length": 32,
"chars_per_register": 2
```

---

## 7. protocol_params (연결)

```json
{
  "role": "server",
  "ip": "0.0.0.0",
  "port": 502,
  "unit_id": 1,
  "unit_id_any": false,
  "max_clients": 4,
  "client_timeout_ms": 200
}
```

| 필드 | 설명 |
|------|------|
| `role` | `server`(기본) 또는 `client`/`master` |
| `ip` | server면 bind 주소, client면 원격 슬레이브 IP |
| `bind_ip` | server 전용 listen 주소 (선택) |
| `port` | 기본 502. 랩에서는 1502 등 비특권 포트 권장 |
| `unit_id` | 슬레이브 번호(보통 1) |
| `unit_id_any` | true면 아무 unit id 요청에 응답 |
| `max_clients` | 동시 마스터 수 (1..8) |
| `client_timeout_ms` | client 역할 응답 대기 |
| `n_holding` 등 | 맵 크기 (생략 시 넉넉한 기본값) |

참고: 최상위 `device.role` 은 문서/공통 스키마용이고, 어댑터가 실제로 읽는 값은
`protocol_params.role` 이다 (코어가 protocol_params만 넘기기 때문).

---

## 8. 예제 설정 전체 읽기 (`config/example.modbus.json`)

의도를 문장으로 풀면:

1. **barcode_value** (`access: read`, holding 40001, string 32)  
   → 앱이 바코드를 맵에 쓰면 PLC가 Holding을 읽어 감.
2. **temperature** (`access: read`, 40001+offset 16, uint16×0.1)  
   → 온도 raw를 게시, 스케일로 ℃.
3. **pressure** (`access: read`, input 30001, float CDAB)  
   → Input 레지스터에 float.
4. **trigger** (`access: write`, coil 1)  
   → PLC가 코일을 킴 → 앱이 `read_point`로 감지.
5. **alarm_bit** / **status_nibble**  
   → Holding 워드 안의 비트·니블.

그대로 실행:

```
./build/multiproto_daemon config/example.modbus.json
```

(예제는 포트 **1502**. 실제 현장 502는 권한이 필요할 수 있다.)

---

## 9. 통신 가이드만 보고 config 채우는 절차

1. 가이드에서 **영역** 확인 → `holding` / `input` / `coil` / `discrete`.
2. **시작 주소**를 `start`(또는 `address`)에 그대로 기입. 오프셋이 있으면 `offset`.
3. **데이터 형** → `data_type`. float면 `endian`도 가이드 표기 그대로.
4. “×0.1” 같은 환산 → `scale` / `offset`.
5. PLC가 읽는 값이면 `access: "read"`, PLC가 쓰는 값이면 `access: "write"`.
6. `protocol` 을 `"modbus_tcp"` 로 두고 데몬 실행.

코드 수정은 필요 없다.

---

## 10. 코드 구조 (읽기용 지도)

```
stacks/modbus/
  include/mb_stack.h    # 스택 API (create/start/poll/read/write)
  include/mb_types.h    # FC 번호, 영역 enum
  src/mb_stack.c        # TCP listen/accept, PDU, 로컬 맵

adapters/modbus/
  modbus_adapter.c      # JSON 파싱, 주소 정규화, scale/endian
  modbus_codec.c        # 엔디안·BCD·문자열 팩킹
  modbus_adapter.h      # 공개 API: modbus_adapter_create()
```

런타임 흐름:

1. `main` → config의 `protocol` → `modbus_adapter_create`
2. `init(protocol_params, points)` → 맵·포인트 준비
3. `connect` → listen(또는 client connect)
4. 스케줄러가 `poll_cycle` (서버: 요청 처리 / 클라이언트: 원격 폴링)
5. 앱/`read_point`·`write_point` → 로컬 맵 (± 변환)

---

## 11. 실행·테스트

빌드 (libmodbus **불필요**):

```
mkdir -p build && cd build
cmake ..
make
```

실행:

```
./build/multiproto_daemon config/example.modbus.json
./build/test_mb_stack
./build/test_mb_adapter
```

장시간 신뢰성 (FC 전 구간 + multi-master + soak):

```
python3 tests/mb_reliability_harness.py --soak-seconds 1200
```

시드된 테스트 서버만 띄울 때:

```
./build/mb_seeded_server --port 1602
```

---

## 12. 점대점 매핑 요약 (PROFINET 문서의 “점대점”에 대응)

| 개념 | PROFINET | Modbus (이 스택) |
|------|----------|------------------|
| 장치 역할 | Device | TCP Server(Slave) |
| PLC가 읽는 데이터 | input image + `access: read` | Holding/Input/Coil 맵 + `access: read` |
| PLC가 쓰는 데이터 | output image + `access: write` | Coil/Holding 맵 + `access: write` |
| 주소 | `byte_offset` 등 | `start` + `offset` + `bit` … |
| 사이클 | `pn_stack_poll` | `mb_stack_poll` / `poll_cycle` |

---

## 13. 자주 하는 실수

| 증상 | 점검 |
|------|------|
| PLC가 연결 안 됨 | `ip`/`port`, 방화벽, 포트 502 권한, `unit_id` |
| 값이 항상 0 | `access: read` 인데 앱이 `write_point`를 안 함 |
| 숫자가 이상함 | `endian`(CDAB 등), `scale` |
| 주소가 한 칸씩 밀림 | Modicon(40001) vs 0-based(`zero_based`) 혼동 |
| D100 같은 주소를 적음 | 그건 Modbus가 아님 → SLMP `device_code` |

---

## 14. 관련 파일

| 파일 | 용도 |
|------|------|
| `docs/design.md` | 멀티프로토콜 전체 설계 |
| `docs/profinet_stack.md` | PROFINET (같은 패턴의 형제 문서) |
| `config/example.modbus.json` | 바로 실행 가능한 예제 |
| `config/test.modbus.reliability.json` | 신뢰성 하니스용 |
| `config/config.schema.json` | JSON 스키마 |
