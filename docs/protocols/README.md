# 산업 프로토콜 입문 + 이 저장소 구조 분석

이 폴더는 **산업용 통신 프로토콜을 처음 접하는 사람**이 네 프로토콜
(Modbus TCP, SLMP, EtherNet/IP, PROFINET)을 바닥부터 이해하고, 직접 스택을
구현할 수 있을 만큼 자세히 설명하는 문서 모음이다.

- 이 문서(README)는 네 문서가 공통으로 깔고 가는 **기초 개념**과 이 저장소의
  **전체 구조 분석**을 다룬다.
- 프로토콜별 상세 문서는 바이트 단위 프레임 포맷, 상태 기계, 구현 로드맵,
  이 저장소 코드 지도까지 다룬다.

| 순서 | 문서 | 난이도 | 한 줄 요약 |
|---|---|---|---|
| 1 | [`modbus.md`](modbus.md) | ★☆☆☆ | TCP 위에서 "레지스터 N개 읽어 줘/써 줘" 를 주고받는 가장 단순한 요청-응답 프로토콜 |
| 2 | [`slmp.md`](slmp.md) | ★★☆☆ | 미쓰비시 PLC 의 메모리(D100, M0 …)를 TCP/UDP 로 직접 읽고 쓰는 요청-응답 프로토콜 |
| 3 | [`ethernetip.md`](ethernetip.md) | ★★★☆ | 객체 모델(CIP) + 연결 수립(Forward Open) + UDP 주기 I/O 로 이루어진 Rockwell 계열 프로토콜 |
| 4 | [`profinet.md`](profinet.md) | ★★★★ | IP 를 우회하는 L2 실시간 프레임 + DCE/RPC 연결 설정 + 이름 기반 주소 할당을 쓰는 Siemens 계열 프로토콜 |

**읽는 순서는 위 표 순서를 권한다.** 뒤로 갈수록 앞 문서의 개념(요청-응답,
바이트 순서, 레지스터/디바이스 메모리, 주기 통신)을 전제로 한다.

> 이 문서들은 학습·구현용 자료다. 공식 사양서(Modbus.org, Mitsubishi,
> ODVA, PI)를 대체하지 않으며, 이 저장소의 CTT 통과는 **인증이 아니다.**

---

## 1. "산업 프로토콜"이란 무엇인가 — 0단계

### 1.1 공장에서 벌어지는 일

컨베이어 벨트 위로 상자가 지나가고, 바코드 센서가 상자의 바코드를 읽고,
어떤 기계가 그 결과에 따라 상자를 왼쪽 또는 오른쪽으로 밀어낸다고 하자.

```
 [바코드 센서] ──"ABC123 읽음"──▶ [PLC] ──"왼쪽으로 밀어"──▶ [밀대 모터]
                                   ▲
                                   │ "지금 상태 보여 줘"
                                [HMI 화면 / SCADA]
```

- **PLC(Programmable Logic Controller)**: 공장의 두뇌 역할을 하는 산업용 컴퓨터.
  수 ms 주기로 "입력 읽기 → 프로그램 실행 → 출력 쓰기" 를 끝없이 반복한다
  (이 반복을 **스캔(scan)** 이라 부른다).
- **필드 디바이스(field device)**: 센서, 액추에이터, 인버터, 로봇 같은 현장 장비.
- **HMI / SCADA**: 사람이 보는 화면과 감시·기록 시스템.

이 장비들이 서로 데이터를 주고받는 약속이 **산업 프로토콜**이다.
옛날에는 전용 케이블(RS-485 등)을 쓰는 **필드버스(fieldbus)** 였고,
지금은 대부분 일반 이더넷 케이블 위에서 동작하는 **산업 이더넷(Industrial Ethernet)** 이다.
이 저장소의 네 프로토콜은 모두 산업 이더넷이다.

### 1.2 일반 IT 통신과 무엇이 다른가

| 관점 | 웹/IT 통신 | 산업 통신 |
|---|---|---|
| 데이터 | 문서, 이미지, JSON | 몇 바이트~수백 바이트의 **숫자·비트** (온도 253, 스위치 ON) |
| 통신 모양 | 필요할 때 요청 | **정해진 주기(예: 8ms)로 끝없이 반복** 하는 경우가 많음 |
| 중요한 것 | 처리량(throughput) | **결정성(determinism)**: 매번 제시간에 도착하는가 |
| 늦으면 | 조금 느린 페이지 | 기계가 멈추거나(안전 정지) 불량품 |
| 주소 | URL, 파일 경로 | "레지스터 40001", "D100", "Assembly 100", "Slot 1 / Subslot 1" |
| 장비 수명 | 수 년 | 10~20년. 오래된 방식과의 **호환성**이 매우 중요 |

**지터(jitter)** 는 "주기가 얼마나 흔들리는가"다. 8ms 주기라면 실제 간격이
7.9ms, 8.1ms, 8.0ms … 로 흔들리는데, 이 흔들림 폭이 작을수록 좋다.
이 저장소는 8ms 기준 1~2시간 에이징에서 최대 편차 0.1ms 를 목표로 한다
([`../design.md`](../design.md) 5장).

### 1.3 누가 누구에게 말을 거나 — 역할 이름

프로토콜마다 이름이 다르지만 구조는 같다: **묻는 쪽(주도)** 과 **답하는 쪽**.

| 프로토콜 | 주도하는 쪽 | 답하는 쪽 | 이 저장소의 기본 역할 |
|---|---|---|---|
| Modbus TCP | Client (옛 이름 Master) | Server (옛 이름 Slave) | **Server** (PLC 가 우리를 읽음) + Client 옵션 |
| SLMP | 외부 기기(Client) | PLC(Server) | **Client** (우리가 PLC 메모리에 씀) + 시뮬 Server |
| EtherNet/IP | Scanner / Originator | Adapter / Target | **Adapter** (+ Originator explicit) |
| PROFINET | IO Controller | IO Device | **IO Device** |

**핵심 직관**: "센서"는 대개 답하는 쪽(Server/Adapter/Device)이고, PLC 는 묻는
쪽이다. 단, SLMP 처럼 센서가 PLC 메모리에 **직접 쓰러 가는** 구조도 있다.

### 1.4 통신의 두 가지 모양

1. **요청-응답(request/response, polling)** — "D100 부터 10워드 줘" → "여기 있어".
   Modbus, SLMP 가 이것뿐이다. EtherNet/IP 의 *explicit messaging*, PROFINET
   의 *record read/write* 도 이 모양이다. 설정·진단·가끔 읽는 값에 쓴다.
2. **주기 교환(cyclic, implicit, producer/consumer)** — 연결을 한 번 맺은 뒤,
   양쪽이 **요청 없이** 정해진 주기마다 입력/출력 데이터 묶음을 계속 던진다.
   EtherNet/IP *Class 1 I/O*, PROFINET *RT cyclic* 이 이것이다. 매 사이클
   바뀌는 값(센서값, 모터 명령)에 쓴다. 상대가 일정 시간 안 보내면
   **워치독(watchdog)** 이 끊김으로 판단한다.

```
요청-응답:   A ──req──▶ B        주기 교환:   A ══data══▶ B  (매 RPI/사이클)
             A ◀──rsp── B                     A ◀══data══ B  (요청 없이 계속)
```

### 1.5 주소 체계 — 각자 다른 "메모리 지도"

모든 프로토콜은 결국 "상대방 메모리의 어느 칸"을 가리키는 방법이 필요하다.

| 프로토콜 | 주소의 모양 | 예 |
|---|---|---|
| Modbus | 4종 테이블 × 16비트 번호 | Holding Register 0 (관행 표기 "40001") |
| SLMP | 디바이스 종류 + 번호 | `D100`(데이터 레지스터 100번), `M0`(내부 릴레이), `X1F`(16진) |
| EtherNet/IP | 객체 경로 (Class/Instance/Attribute) | Assembly(0x04) 인스턴스 100 의 데이터 |
| PROFINET | API / Slot / Subslot (+ Index) | Slot 1 / Subslot 1 의 입력 4바이트 |

이 저장소의 사용자는 이 차이를 몰라도 되도록, config 의 `points[].address.<프로토콜>`
에 **PLC 통신 가이드 문서에 적힌 주소를 그대로** 적으면 된다
([`../design.md`](../design.md) 3.2).

### 1.6 바이트 순서 — 가장 흔한 버그 원인

16비트 값 `0x1234` 를 네트워크로 보낼 때:

- **빅 엔디안(big-endian)**: `12 34` 순서 (큰 자리 먼저). Modbus, PROFINET.
- **리틀 엔디안(little-endian)**: `34 12` 순서 (작은 자리 먼저). SLMP(Binary),
  EtherNet/IP(CIP), 그리고 x86/대부분의 ARM CPU 메모리.

32비트 값(`float`, `int32`)을 16비트 레지스터 두 개에 나눠 담을 때는
**워드 순서(word order)** 까지 장비마다 다르다 (`ABCD`, `CDAB`, `BADC`, `DCBA`).
네 문서 모두 이 부분을 예제와 함께 따로 설명한다.

### 1.7 인증 생태계

| 프로토콜 | 관리 단체 | 적합성 시험 |
|---|---|---|
| Modbus | Modbus Organization | Modbus.org conformance test |
| SLMP | Mitsubishi / CLPA | 파트너 제품 검증 |
| EtherNet/IP | ODVA | ODVA conformance test + Declaration of Conformity |
| PROFINET | PI (PROFIBUS & PROFINET International) | PI 인증 시험소 (ART tester 등) |

이 저장소의 `tools/ctt/` (Controller Test Tool)는 **내부 회귀 게이트**다.
CTT green ≠ 인증.

---

## 2. 네트워크 기초 요약 (네 문서 공통)

### 2.1 계층

```
 ┌───────────────────────────────────────────────┐
 │ 응용 계층: Modbus PDU / SLMP / CIP / PNIO      │  ← 우리가 구현하는 부분
 ├───────────────────────────────────────────────┤
 │ 전송 계층: TCP (신뢰, 스트림) / UDP (데이터그램) │  ← OS 소켓이 해 줌
 ├───────────────────────────────────────────────┤
 │ 네트워크 계층: IP (주소 192.168.0.10)            │  ← OS
 ├───────────────────────────────────────────────┤
 │ 링크 계층: Ethernet (MAC 주소, EtherType)        │  ← OS / NIC
 └───────────────────────────────────────────────┘
       ▲ PROFINET RT 와 DCP 는 IP/TCP/UDP 를 건너뛰고 이 층에 직접 올라탄다
```

- **TCP** 는 "바이트의 강물"이다. 보낸 쪽이 100바이트 메시지 2개를 보내도
  받는 쪽은 150바이트 + 50바이트로 받을 수 있다. 그래서 TCP 위 프로토콜은
  **헤더의 길이 필드로 메시지 경계를 스스로 찾아야** 한다 (Modbus MBAP 의
  Length, SLMP 의 Request data length, EtherNet/IP 의 Encapsulation Length).
- **UDP** 는 "봉투"다. 한 번 보낸 것이 한 덩어리로 도착하거나 아예 사라진다.
  주기 I/O 는 늦게 도착한 옛 데이터보다 새 데이터가 중요하므로 UDP 를 쓴다.
- **Raw Ethernet (AF_PACKET)** 은 봉투조차 없이 이더넷 프레임을 직접 만든다.
  PROFINET 은 EtherType `0x8892` 로 이렇게 한다. Linux 에서는 `CAP_NET_RAW`
  권한이 필요하다.

### 2.2 네 프로토콜이 쓰는 포트/타입

| 프로토콜 | 전송 | 포트 / 타입 |
|---|---|---|
| Modbus TCP | TCP | 502 (이 저장소 예제는 권한 문제로 1502) |
| SLMP | TCP 또는 UDP | PLC 설정에서 지정 (예: 5000~5010 등, 고정값 아님) |
| EtherNet/IP | TCP + UDP | TCP 44818 (explicit), UDP 44818 (ListIdentity), UDP 2222 (Class 1 I/O) |
| PROFINET | Raw Eth + UDP | EtherType 0x8892 (RT, DCP), 0x88CC (LLDP), UDP 34964 (RPC), UDP 161 (SNMP) |

### 2.3 16진수와 바이트 표기

문서들의 프레임 예제는 `50 00 00 FF FF 03 00 ...` 처럼 바이트를 16진 두 자리로
나열한다. 한 바이트는 0x00~0xFF (0~255). 16비트 값은 2바이트, 32비트 값은
4바이트다. Wireshark 에서 같은 모양으로 볼 수 있다.

---

## 3. 네 프로토콜 한눈 비교

| 항목 | Modbus TCP | SLMP (3E Binary) | EtherNet/IP | PROFINET IO (RT1) |
|---|---|---|---|---|
| 출신 | Modicon(현 Schneider), 1979 시리얼 → 1999 TCP | Mitsubishi (MC 프로토콜 계열) | Rockwell / ODVA, CIP 기반 | Siemens / PI, PROFIBUS 후속 |
| 통신 모양 | 요청-응답만 | 요청-응답만 | explicit(요청-응답) + implicit(주기) | record(요청-응답) + RT(주기) |
| 전송 | TCP | TCP/UDP | TCP + UDP | L2 Ethernet + UDP |
| 바이트 순서 | Big | Little | Little | Big (RPC 는 drep 에 따라) |
| 주소 | 테이블 + 번호 | 디바이스코드 + 번호 | Class/Instance/Attribute | API/Slot/Subslot/Index |
| 연결 수립 | TCP 연결이 전부 | TCP 연결(또는 없음, UDP) | RegisterSession → Forward Open | DCP 이름/IP → RPC Connect → PrmEnd → AppReady |
| 장치 기술 파일 | 없음 | 없음 | EDS | GSDML (XML) |
| 장치 탐색 | 없음 | 없음(일부 제품 전용 기능) | ListIdentity (UDP 브로드캐스트) | DCP Identify (L2 멀티캐스트) |
| 보안 | 없음 (Modbus/TCP Security 별도 사양) | 없음 | CIP Security | PROFINET Security Class 1~3 |
| 이 저장소 스택 크기 | ~1.2k 줄 | ~1.2k 줄 | ~3.5k 줄 | ~2.5k 줄 |

---

## 4. 이 저장소의 구조 분석

### 4.1 한 문장 요약

**한 프로세스는 config 한 개로 프로토콜 한 개를 고른다.** 앱은 프로토콜을
모르는 "포인트 이름" API 만 쓰고, 어댑터가 포인트를 프로토콜 주소로 번역하며,
자체 구현 스택이 실제 바이트를 주고받는다.

### 4.2 계층도

```
 ┌────────────────────────────────────────────────────────────────────┐
 │ 앱 (examples/fb_api_demo.c, fake_sensor_app.c, 고객 앱)              │
 │   fb_write_f32(rt, "temperature", 25.5f)                           │
 └───────────────┬────────────────────────────────────────────────────┘
                 │ include/fb_api.h  (프로토콜 타입 없음, 포인트 이름만)
 ┌───────────────▼────────────────────────────────────────────────────┐
 │ core/                                                              │
 │  fb_api.c         세션, 타입 변환, mutex, 사이클 루프, reload       │
 │  config_loader.c  config.json → protocol / cycle_ms / 원문 JSON      │
 │  adapter_registry.c  "modbus_tcp" → modbus_adapter_create …         │
 │  logger.h         LOG_INFO/WARN/ERROR                               │
 └───────────────┬────────────────────────────────────────────────────┘
                 │ include/protocol_adapter.h  (함수 포인터 9개)
 ┌───────────────▼────────────────────────────────────────────────────┐
 │ adapters/<proto>/  protocol_params·points 를 cJSON 으로 직접 파싱,   │
 │                    포인트 ↔ 레지스터/디바이스/Assembly/Slot 매핑     │
 └───────────────┬────────────────────────────────────────────────────┘
                 │ stacks/<proto>/include/*.h
 ┌───────────────▼────────────────────────────────────────────────────┐
 │ stacks/modbus  stacks/slmp  stacks/ethernetip  stacks/profinet      │
 │   프레임 인코딩/디코딩, 소켓, 상태 기계, I/O 이미지                  │
 └───────────────┬────────────────────────────────────────────────────┘
                 ▼  TCP / UDP / AF_PACKET
```

스택은 **cJSON 도 어댑터도 모른다** (`BUILD_DAEMON=OFF` 로 스택 + CTT 만 빌드 가능,
[`../../CMakeLists.txt`](../../CMakeLists.txt) 45–90행). 그래서 CTT 가 스택을
직접 DUT(시험 대상)로 쓸 수 있다.

### 4.3 기동부터 한 사이클까지

1. `multiproto_daemon config.json` → [`core/main.c`](../../core/main.c) 가
   `fb_open()` → `fb_run()` 만 호출 (데몬은 fb_api 의 얇은 클라이언트).
2. `fb_open` → `config_load()` ([`core/config_loader.c`](../../core/config_loader.c)):
   `protocol`, `device`, `cycle_ms` 만 해석하고 `protocol_params`/`points` 는
   **문자열 그대로** 보관.
3. `adapter_registry_lookup(protocol)` → 생성자 → `init(params_json, points_json)`
   → `connect()` ([`core/fb_api.c`](../../core/fb_api.c) `session_build`/`session_connect`).
4. `fb_run` → `run_cycle_loop` ([`core/fb_api.c`](../../core/fb_api.c) 739행):
   `CLOCK_MONOTONIC` 절대시간 `clock_nanosleep` 으로 `cycle_ms` 마다
   **mutex 를 잡고** `adapter->poll_cycle()` 호출.
5. 각 어댑터의 `poll_cycle` 은 스택의 `*_stack_poll()` 을 부른다. 이 한 번의
   호출 안에서 소켓 수신(non-blocking) 처리, 타임아웃 검사, 주기 송신이 모두 일어난다.
6. 앱의 `fb_read_*`/`fb_write_*` 는 같은 mutex 아래에서 `read_point`/`write_point`
   로 스택의 I/O 이미지(레지스터 뱅크, Assembly 버퍼, PN 입력/출력 버퍼)를 읽고 쓴다.

**실행 모델은 "단일 사이클 스레드 + 협조적 폴링"** 이다. 스택들은 자체 스레드를
만들지 않는다 (`pthread_create` 는 `core/fb_api.c` 의 선택적 `fb_start()` 뿐).
스택 내부 mutex(`pn_stack.c` `io_lock`, `eip_stack.c` `lock`)는 I/O 이미지 보호용이다.

### 4.4 config 가 흐르는 길

```
config.json ─┬─ protocol ──────────▶ registry 선택
             ├─ cycle_ms ──────────▶ 사이클 루프 주기
             ├─ device.* ──────────▶ health 표시
             ├─ protocol_params ───▶ (문자열) ─▶ adapter.init 이 cJSON 파싱
             └─ points ────────────┬▶ (문자열) ─▶ adapter.init 이 주소 매핑 파싱
                                   └▶ core/fb_api.c parse_points_meta:
                                      name/access/data_type/length/scale/offset
                                      만 읽어 앱 API 타입 결정
```

### 4.5 테스트·검증 인프라

| 구성 | 위치 | 역할 |
|---|---|---|
| 스택 단위 테스트 | `tests/test_*_stack.c`, `test_pn_*.c`, `test_eip_*.c` | 인코딩/디코딩, 경계값 |
| 어댑터 테스트 | `tests/test_mb_adapter.c`, `test_slmp_adapter.c` | config → 매핑 |
| CTT | `tools/ctt/` + `tests/scenarios/<proto>/*.yaml` | 컨트롤러 흉내 시나리오, mock Ethernet, pcap |
| Golden | `tests/golden/profinet/` | 기대 바이트열 고정 |
| Fuzz | `tests/fuzz/` (libFuzzer, 코퍼스 `mb_adu`, `slmp_request`, `eip_encap`, `eip_io`, `pn_rpc`, `pn_eth`) | 파서 견고성 |
| Soak | `tests/run_mock_soak.sh`, `examples/run_sw_master_soak.sh` | 장시간 지터·안정성 |

### 4.6 구조 분석에서 발견한 점 (관찰 사항, 수정은 별도 논의)

아래는 코드를 읽으며 확인한 사항이다. 프로토콜별 문서에도 해당 스택 관점의
관찰이 따로 정리돼 있다.

1. **`core/scheduler.c` 는 빌드되지만 호출되지 않는다.** 실제 사이클 루프는
   `core/fb_api.c` 의 `run_cycle_loop` (739행)이며, 로직이 `scheduler_run`
   ([`core/scheduler.c`](../../core/scheduler.c) 28행)과 사실상 중복이다.
   [`../../CLAUDE.md`](../../CLAUDE.md) 는 스케줄러 회귀 판단 기준 파일로
   `core/scheduler.c` 를 지목하므로, 문서와 실제 경로가 어긋나 있다.
2. **사이클 초과 감지는 ms 단위 절삭이다.** `timespec_diff_ms` 가 ns 를
   `/1000000` 으로 버리므로, 사이클 로그로는 0.1ms 수준의 지터를 볼 수 없고
   `elapsed > cycle_ms` (정수 ms) 초과만 경고된다. 0.1ms 지터 수치는 CTT 쪽
   측정(`tools/ctt/cycle_clock.c`)에 의존한다.
3. **주기 송신의 시간 해상도 = `cycle_ms`.** PROFINET RT 송신
   (`pn_rt_send_if_due`, [`stacks/profinet/src/pn_rt.c`](../../stacks/profinet/src/pn_rt.c) 93행)과
   EtherNet/IP Class 1 생산(`eip_io_produce`,
   [`stacks/ethernetip/src/eip_io.c`](../../stacks/ethernetip/src/eip_io.c) 105행)은
   "기한이 됐으면 보낸다" 방식이지만, 호출 자체가 `poll_cycle` 에서만 일어난다.
   따라서 컨트롤러가 RPI/사이클을 `cycle_ms` 보다 짧게 잡으면 실제 송신 간격은
   `cycle_ms` 로 늘어나고, 상대 워치독 여유가 줄어든다. 컨트롤러 설정은
   `cycle_ms` 이상으로 맞춰야 한다.
4. **PROFINET RT 송신 주기가 협상값이 아니라 config 값이다.** `pn_rt_send_if_due`
   는 `cfg.cycle_us` (어댑터 기본 8000µs, `protocol_params.cycle_us`)를 쓰고,
   Connect 에서 받은 `send_clock_factor × reduction_ratio` 는 수신 워치독에만 쓴다
   (`pn_ar_watchdog`, 같은 파일 28–60행). 사양상 디바이스는 IOCR 에 협상된
   주기로 송신해야 하므로, 컨트롤러 설정과 `cycle_us` 가 다르면 불일치가 난다.
5. **사이클 루프는 `poll_cycle` 전체를 런타임 mutex 안에서 실행한다.** Modbus/SLMP
   **클라이언트** 모드에서는 `poll_cycle` 안에서 포인트마다 동기 요청을 보내고
   응답을 기다린다 (`mb_poll_cycle`, [`adapters/modbus/modbus_adapter.c`](../../adapters/modbus/modbus_adapter.c) 549행;
   `slmp_poll_cycle`, [`adapters/slmp/slmp_adapter.c`](../../adapters/slmp/slmp_adapter.c) 699행).
   상대가 응답하지 않으면 `타임아웃(200ms / 1000ms) × 포인트 수` 동안 사이클이
   밀리고, 그동안 앱의 `fb_read_*`/`fb_write_*` 도 mutex 에서 대기한다.
6. **코어가 포인트 메타데이터 일부를 해석한다.** `parse_points_meta`
   ([`core/fb_api.c`](../../core/fb_api.c) 299행)가 `data_type`/`access`/`length`/
   `scale`/`offset` 을 읽어 앱 API 타입을 정한다. [`../../CLAUDE.md`](../../CLAUDE.md)
   의 "코어는 points 를 해석하지 않는다" 원칙, [`../design.md`](../design.md) 3.2 의
   "스케일은 코어 값 변환 레이어", `include/fb_api.h` · [`../app_api.md`](../app_api.md)
   의 "scale/offset 은 어댑터가 적용" 세 문서의 설명이 서로 다르다. 주소(`address`)
   는 코어가 보지 않으므로 핵심 원칙은 지켜지지만, 문서 정합성은 맞출 필요가 있다.
7. **`core/config_loader.c` 의 소소한 규칙 위반.** 오류를 `fprintf(stderr, …)`
   로 직접 출력한다 (CLAUDE.md: `LOG_ERROR`/`LOG_WARN` 사용). 또 `#define
   _POSIX_C_SOURCE` 가 첫 `#include` 뒤(3행)에 있어, `strdup` 등의 선언 노출이
   컴파일러/libc 설정에 따라 달라질 수 있다.

---

## 5. 네 문서의 공통 구성

각 프로토콜 문서는 다음 순서를 따른다. 필요한 부분만 골라 읽어도 되게 썼다.

1. 읽는 법과 선행 지식
2. 왜 이 프로토콜이 존재하나 (역사, 누가 쓰나)
3. 용어 사전
4. 전체 그림 (계층, 시퀀스 다이어그램)
5. 데이터 모델 (주소 체계)
6. 프레임 포맷 (바이트 단위 표 + 필드별로 해설한 hex 예제)
7. 동작과 상태 기계, 타이밍
8. 에러 처리와 제한값
9. **직접 구현하기** (단계별 로드맵, 각 단계 검증 방법, 의사코드)
10. 이 저장소 구현 지도 (파일/함수 ↔ 개념)
11. 테스트와 디버깅 (단위 테스트, CTT, fuzz, Wireshark)
12. 함정과 보안
13. 인증과 참고 사양
