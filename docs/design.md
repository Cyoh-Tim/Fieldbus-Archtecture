# 멀티프로토콜 필드버스 데몬 구현 프롬프트

## 0. 배경
- 대상: Modbus, SLMP, CC-Link, EtherNet/IP, PROFINET (추후 EtherCAT 등 추가 예정)
- 런타임에는 **한 번에 하나의 프로토콜만** 활성화되어 통신을 수행한다. 프로토콜 선택은 배포 시점의 설정(config)으로 결정된다.
- 이 다섯(추후 확장 포함) 프로토콜을 위한 **개별 프로그램을 따로 만들지 않고, 하나의 프로젝트/하나의 바이너리(데몬)**로 통합한다.
- Profinet, EtherNet/IP는 **상용 스택을 이미 구매**한 상태이므로, 자체 구현이 아니라 해당 SDK를 래핑하는 어댑터를 만든다. Modbus(libmodbus), SLMP(자체 디코더)는 오픈소스/자체 구현으로 처리한다. CC-Link, EtherCAT은 아직 미정 — 인터페이스만 비워두고 후속 어댑터로 추가할 수 있는 구조를 지금 만들어야 한다.
- **PROFINET 성능 등급 제약**: 타깃이 A-core(Cortex-A급 애플리케이션 프로세서)이고 IRT 전용 ASIC(하드웨어 타임스탬핑/동기 스위칭을 지원하는 칩)이 없으므로, **IRT(Isochronous Real-Time)급은 애초에 목표 범위 밖**이다. PROFINET 어댑터는 **RT(Real-Time) 등급**까지만 보장하는 것으로 설계·문서화하고, 구매한 스택의 스펙도 RT 등급 지원 여부 기준으로 확인해야 한다. 동기 정밀도가 필요한 응용에는 이 데몬을 쓸 수 없다는 점을 config/README에 명시할 것.
- **핵심 요구사항**: 담당자가 Modbus/SLMP/CC-Link/EtherNet-IP/PROFINET에 대한 사전 지식이 전혀 없어도, 대상 PLC/상위 시스템의 "통신 가이드 문서"(레지스터 맵, 디바이스 코드 표 등)만 보고 JSON 설정 파일을 채우면 데몬이 그대로 동작해야 한다. 즉 **프로토콜 지식은 어댑터 코드 안에 캡슐화되고, 사용자는 데이터 매핑만 기술**한다.

## 1. 아키텍처 원칙
1. **코어(Core) / 어댑터(Adapter) 분리**
   - 코어: 설정 로더, 포인트 레지스트리, 폴링/사이클 스케줄러, 로깅, 상태 관리. 프로토콜을 전혀 모른다.
   - 어댑터: 프로토콜별 플러그인. `ProtocolAdapter` 인터페이스만 구현하면 코어에 등록 가능.
2. **팩토리 + 레지스트리 패턴**
   - `config.json`의 `"protocol"` 필드 값(`"modbus_tcp"`, `"slmp"`, `"cclink"`, `"ethernetip"`, `"profinet"`, `"ethercat"` …)으로 어댑터를 동적 선택.
   - 새 프로토콜 추가 시 코어 수정 없이 어댑터 파일 추가 + 레지스트리에 1줄 등록만으로 확장되어야 한다(Open-Closed 원칙).
3. **포인트(Point) 추상화**
   - 실제 데이터(바코드 값, 트리거, 상태 비트 등)는 프로토콜에 무관한 "포인트" 단위로 코어에서 관리한다.
   - 어댑터는 포인트를 프로토콜 고유 주소 체계로 매핑해 읽기/쓰기만 수행한다.
4. **역할(role) 다양성**
   - 센서는 프로토콜에 따라 서버/슬레이브(Modbus TCP)일 수도, 클라이언트(SLMP에서 센서가 PLC에 씀)일 수도 있다. 어댑터는 `role: server|client`를 지원해야 한다.

```
             ┌────────────────────────────┐
             │        Core Daemon         │
             │  - Config Loader           │
             │  - Point Registry          │
             │  - Cycle Scheduler (~8ms)  │
             │  - Logger / Health         │
             └──────────────┬─────────────┘
                             │ ProtocolAdapter interface
        ┌───────────┬───────┼───────┬─────────────┬───────────┐
   ┌────▼───┐  ┌────▼───┐ ┌─▼────┐ ┌▼──────────┐ ┌▼─────────┐
   │ Modbus │  │  SLMP  │ │CClink│ │EtherNet/IP │ │ PROFINET │  ...(EtherCAT 등 추후)
   │libmodbus│ │ 자체구현│ │(TBD) │ │(구매 스택) │ │(구매 스택)│
   └────────┘  └────────┘ └──────┘ └───────────┘ └──────────┘
```

## 2. ProtocolAdapter 인터페이스 (의사코드)
```
interface ProtocolAdapter {
    init(protocol_config: object, points: list<Point>) -> void
    connect() -> Result
    disconnect() -> void
    poll_cycle() -> void        // 코어 스케줄러가 cycle_ms 주기로 호출
    read_point(point_id) -> Value
    write_point(point_id, value) -> Result
    health() -> {connected: bool, last_error: string|null}
}
```
- 각 어댑터는 위 인터페이스만 만족하면 되고, 내부적으로 PROFINET/EtherNet-IP는 구매 스택의 콜백/폴링 모델을 이 인터페이스 뒤로 감춘다(어댑터가 "번역기" 역할).
- CC-Link, EtherCAT은 지금은 `NotImplementedAdapter`(스텁)로 등록해 두고, 레지스트리 구조상 자리만 확보한다.

## 3. Config(JSON) 설계
### 3.1 최상위 구조
```json
{
  "protocol": "modbus_tcp",
  "device": {
    "name": "barcode_sensor_1",
    "role": "server"
  },
  "cycle_ms": 8,
  "protocol_params": { "...": "프로토콜별 파라미터 (아래 4장 참고)" },
  "points": [ /* 4장의 포인트 매핑 배열 */ ]
}
```
- `protocol`: 어댑터 선택 키. 이 값 하나로 어떤 어댑터를 로드할지 결정.
- `protocol_params`: 프로토콜마다 필요한 연결 정보(IP/포트, 스테이션 번호, GSDML 이름 등)만 담는 자유 객체. 코어는 이 내용을 해석하지 않고 그대로 어댑터에 넘긴다.
- `points`: 포인트(=실제 읽고 쓰려는 값) 목록. **사용자가 프로토콜 가이드 문서를 보고 채우는 부분**이 바로 여기다.

### 3.2 포인트(point) 스키마 — "지식 없이도 채울 수 있는" 핵심 부분
```json
{
  "name": "barcode_value",
  "access": "read",
  "data_type": "string",
  "length": 32,
  "scale": 1.0,
  "offset": 0.0,
  "byte_order": "big",
  "address": {
    "modbus": { "register_type": "holding", "start": 40001 },
    "slmp":   { "device_code": "D", "start": 100 },
    "cclink": { "device_code": "D", "start": 100 },
    "ethernetip": { "tag": "Sensor1.Barcode" },
    "profinet": { "slot": 1, "subslot": 1, "index": 1 }
  }
}
```
- `address` 객체 안에 **가능한 모든 프로토콜의 주소 표현을 미리 다 넣어둘 필요는 없다** — 실제로는 `protocol` 필드에서 선택된 프로토콜의 키만 사용된다. 하지만 이렇게 프로토콜별 서브키로 구조를 통일해두면:
  - 나중에 같은 센서를 다른 프로토콜로 바꿔 배포할 때 `points` 정의를 재사용하기 쉽고,
  - 사용자는 "이 필드에 PLC 가이드 문서에서 본 레지스터 주소/디바이스 코드/태그 이름을 그대로 적으면 된다"는 하나의 규칙만 기억하면 된다.
- `data_type`, `byte_order`, `scale`, `offset`, `length`는 프로토콜 공통 개념(워드 순서, 스케일링, 문자열 길이)이라 코어의 "값 변환 레이어"에서 처리하고, 어댑터는 raw byte만 주고받는다. 이렇게 하면 "16비트 정수인데 스케일 0.1을 곱해야 한다" 같은 가이드 문서 내용도 사용자가 코드 수정 없이 config만으로 반영 가능하다.

### 3.3 protocol_params 예시 (프로토콜별)
```json
// modbus_tcp
{ "ip": "192.168.0.10", "port": 502, "unit_id": 1 }

// slmp (센서가 클라이언트로서 PLC에 씀)
{ "plc_ip": "192.168.0.20", "port": 5000, "network_no": 0, "pc_no": 255, "frame": "3E" }

// cclink (추후 확정 시 이 자리만 채우면 됨)
{ "station_no": 1 }

// ethernetip (구매 스택 파라미터에 맞춰 조정)
{ "ip": "192.168.0.30", "assembly_instance": 100 }

// profinet (구매 스택 파라미터에 맞춰 조정)
{ "device_name": "sensor1.profinet-device", "gsdml": "GSDML-Vxx-Sensor1.xml" }
```

## 4. 프로토콜별 구현 메모
| 프로토콜 | 구현 방식 | 역할 | 비고 |
|---|---|---|---|
| Modbus | libmodbus 래핑 | 서버(슬레이브) | holding/input register, coil, discrete input 매핑 지원 |
| SLMP | 자체 디코더/인코더 | 클라이언트 | 3E 프레임 기준, 디바이스 코드(D/M/X/Y 등) 파싱 |
| CC-Link | 스텁 → 추후 구현 | TBD | 인터페이스 자리만 확보, `NotImplementedAdapter` |
| EtherNet/IP | 구매 스택(Pyramid 등) 래핑 | 서버/클라이언트 (스택 지원 범위에 따름) | 어댑터가 스택의 콜백 모델을 poll_cycle로 흡수 |
| PROFINET | 자체 Device 스택 `stacks/profinet/` | 디바이스(슬레이브) | CC-B + RT Class 1 + Security Class 1(HMAC). IRT 없음. PI 인증 아님. 상세는 `docs/profinet_stack.md` |
| EtherCAT(추후) | 미정 | TBD | 인터페이스만 남겨둠 |

## 5. 비기능 요구사항
- 기준 사이클: 8ms. **에이징 테스트(1~2시간) 결과 PREEMPT_RT 없이도 최대 지연 편차 0.1ms로 확인** — 일반 타이머 기반 스케줄러로 충분한 것으로 판단, PREEMPT_RT는 현재 요구되지 않음(장기 운용/부하 조건 변화 시 재검증 여지는 남겨둠). 지연 측정 로그는 계속 남겨 회귀를 감지할 것.
- **실시간 등급 한계 명시**: 본 데몬은 A-core 기반 소프트웨어 스택으로 동작하며 IRT급 하드웨어(전용 ASIC)가 없다. PROFINET을 포함한 모든 프로토콜에서 마이크로초 단위 동기 정밀도는 보장 대상이 아니며, 밀리초 단위 폴링/사이클 기반 RT급 통신만 지원 범위로 삼는다. 이 한계는 설계 문서와 README에 고정적으로 명시해 향후 오해(예: IRT 응용 요구 유입)를 방지한다.
- 연결 끊김/재연결: 어댑터별 `health()` 상태를 코어가 주기적으로 확인, 재연결 로직은 어댑터 내부 책임.
- 로깅: 코어에서 통일된 포맷(타임스탬프, 프로토콜, 포인트명, 값, 에러)으로 출력.
- 설정 검증: 데몬 기동 시 config.json을 스키마 검증(JSON Schema)하여, `points`의 `address`에 선택된 `protocol` 키가 없으면 기동 실패 + 명확한 에러 메시지(사용자가 어떤 필드를 빠뜨렸는지 바로 알 수 있게).

## 6. 구현 우선순위(제안)
1. 코어(Config Loader, Point Registry, Scheduler, Logger) + `ProtocolAdapter` 인터페이스 정의
2. Modbus 어댑터 (libmodbus, 서버) — 가장 단순하므로 코어 검증용으로 먼저
3. SLMP 어댑터 (자체 디코더, 클라이언트)
4. EtherNet/IP 어댑터 (구매 스택 래핑)
5. PROFINET 어댑터 (구매 스택 래핑)
6. CC-Link / EtherCAT 스텁 어댑터 등록 (레지스트리 확장성 검증용)

## 7. Claude Code 등 구현 에이전트에게 넘길 때의 지시문 예시
> "위 설계에 따라 [언어: C/C++/Rust/Python 중 택1] 로 코어 데몬과 Modbus 어댑터부터 구현해줘. ProtocolAdapter 인터페이스는 추상클래스/트레이트로 만들고, config.json 스키마는 3장 구조를 그대로 따르되 JSON Schema 파일도 함께 생성해줘. 사이클 스케줄러는 cycle_ms 파라미터를 받아 동작하고, 지연 발생 시 경고 로그를 남기게 해줘."
