# Controller Test Tool (CTT)

저장소 내부용 PROFINET IO Device 테스트 하네스 설계.
구현 코드는 후속 PR. 이 문서는 범위·인터페이스·시나리오·페이즈만 고정한다.

대상 DUT: `stacks/profinet/` (CC-B + RT Class 1 + Security Class 1 HMAC).
CTT 역할: **Controller stub + DCP station**. Device 스택을 대체하지 않는다.

## 0. 배경 / 목표

자체 구현 Device 스택은 상용 벤더가 사내에 두는 것과 같은 **자동 시나리오 하네스**가 필요하다.
랩의 CODESYS 점대점과, 이후 PI Test Bundle 접근 이전에 회귀를 잡는다.

목표:

- 선언적 시나리오(`tests/scenarios/*.yaml`)로 프로토콜 행동을 고정한다.
- mock Ethernet 위에서 golden frame / assert / soak 를 돌린다.
- PR마다 CI가 기존 행동을 잃지 않았는지 확인한다.
- 새 프로토콜 동작은 랩 메모만이 아니라 시나리오와 함께 들어온다.

비목표 (Phase 1–2):

- 전체 PI conformance / certification evidence
- IRT / RT Class 3
- EtherCAT 또는 다른 프로토콜 하네스
- 상용 테스트 시스템(PI Test Bundle 실기, 벤더 CTT 제품) 구매·연동

범위:

- DUT = 이 저장소의 PROFINET IO Device
- CTT = in-process Controller + DCP Identify/Set 스테이션
- 단위 CI 경로에는 실제 NIC가 없다

## 1. 아키텍처

```
  scenarios/*.yaml  →  ctt runner  →  Controller stub
                              ↕ bidirectional mock eth (or later: real AF_PACKET/veth)
                         pn_stack (DUT)  [existing pn_eth_ops_t inject]
                              ↓
                         asserts / golden / metrics
```

기존 훅을 재사용한다. 새 DUT API를 만들지 않는다.

| 훅 | 위치 | CTT에서의 역할 |
|----|------|----------------|
| `pn_eth_ops_t` (`send` / `recv` / `ctx`) | `stacks/profinet/include/pn_stack.h` | mock eth 링 연결. `send` = Device TX → Controller RX |
| `pn_stack_set_eth_ops` | 동일 | AF_PACKET 대신 위 ops 설치. `iface=mock` 이면 이미 raw socket을 열지 않음 |
| `pn_stack_handle_eth` | 동일 | Controller TX 프레임을 Device RX로 주입 (DCP / RTC1) |
| `pn_stack_handle_rpc` | 동일 | CM Connect/Release 등 UDP RPC 주입. Ethernet이 아님 |
| `pn_stack_poll` | 동일 | Device RX dequeue + `pn_rt_send_if_due` (RTC1) + LLDP 주기 |
| `pn_stack_ar_up` / `pn_stack_cfg` | 동일 | expect: AR 상태, NameOfStation |

현재 `tests/test_pn_stack.c` 는 TX capture만 한다 (`send` 콜백, `recv = NULL`).
CTT는 같은 ops를 **양방향 링**으로 바꾼다.

구성 요소 (구현 위치는 후속 PR):

- `tools/ctt/` — runner + Controller stub + mock eth ring + assert helper
- `tests/scenarios/` — 선언적 YAML
- `tests/golden/` — 선택적 binary/hex golden frame
- `tests/test_*.c` — 스택 전체가 필요 없는 crypto/parser 단위 테스트. HMAC RFC4231은 여기에 남긴다

Runner는 YAML을 읽고 DUT를 `pn_stack_create` / `pn_stack_start` 한 뒤 step을 순서대로 실행한다.
Controller stub은 DCP·Connect·RTC1 프레임을 조립하고, DUT TX를 파싱해 assert한다.

RPC는 지금 Device 쪽이 UDP 34964이다. Phase 1 mock에서는 `pn_stack_handle_rpc` 를 Controller API로 감싼다.
Ethernet 링과 RPC 주입은 같은 시나리오 안에서 섞어 쓸 수 있어야 한다 (Identify 후 Connect 후 IO cycle).

## 2. Mock eth

In-process 양방향 링. 단위/CI 경로에 실제 NIC·`CAP_NET_RAW`·root가 없다.

```
  Controller TX queue  ──inject──▶  Device RX
       ▲                              │
       │                         pn_eth_ops.send
       │                              ▼
  Controller RX queue  ◀────────  Device TX
```

동작:

- Controller `send_eth(frame)` → Device RX 큐. runner가 `pn_stack_handle_eth` 로 즉시 넣거나, `recv` ops가 `pn_stack_poll` 에서 pop
- Device `pn_eth_send` → `eth_ops.send` → Controller RX 큐. runner가 Identify.Res / RTC1 입력 프레임을 검사
- 큐는 고정 길이 링 (`PN_FRAME_MAX`, 수십 슬롯). overflow 는 시나리오 실패 (unexpected drop)
- 타임스탬프는 `CLOCK_MONOTONIC` (스택의 `pn_now_ns` 와 동일 계열). mock에서 µs 스케줄은 보장하지 않음

나중에 같은 Controller API를 AF_PACKET / veth 어댑터로 바꾼다 (lab profile).
시나리오 YAML은 그대로 두고 transport만 교체한다.

RPC는 Phase 1에서 링을 거치지 않는다. `pn_stack_handle_rpc(pdu, …, resp, …)` 왕복.
Phase 3 lab profile에서만 실제 UDP를 쓴다.

## 3. 시나리오 스키마

최소 필드:

```
name: string
tags: [string]
device:
  station_name: string
  security_class: 0 | 1
  psk_hex: string          # 64 hex chars, Sec Class 1
  iface: mock              # CI 기본값
  cycle_us: 8000           # optional, 스택 기본과 동일
steps:
  - action: ...
    expect: ...
```

Step `action` (Phase 1 필수 + Phase 2 예약):

| action | 의미 | expect 예 |
|--------|------|-----------|
| `dcp_identify` | FrameID `0xFEFE` Identify.Req (멀티캐스트 `01:0E:CF:00:00:00`) | Identify.Res FrameID `0xFEFF`, NameOfStation |
| `dcp_set` | FrameID `0xFEFD` Set.Req. `signed: true` 이면 option `0xF0` / sub `0x01` HMAC | `accept` 또는 `reject`, 변경된 `station_name` |
| `rpc_connect` | CM Connect. `integrity: true` 이면 block type `0x0E01` | `ar: up` 또는 `rejected` |
| `io_cycle` | AR 이후 RTC1. `count`, `cycle_ms` | 프레임 개수, 주기 상한 (ms, soft) |
| `soak` | `duration_s` 또는 `iterations` | unexpected frame = 0, AR drop = 0 |
| `rpc_release` | Phase 2 | AR down |
| `alarm` / `record_read` / `lldp` / `snmp_get` | Phase 2 | 해당 PDU |

HMAC 단위 테스트는 YAML이 아니다. `tests/test_pn_crypto.c` (또는 기존 `test_pn_stack.c`의 `test_hmac`)에 남긴다.

아래 예시는 현재 `tests/test_pn_stack.c` 세 케이스를 옮긴 것이다. HMAC는 제외.

### 3.1 DCP Identify — `test_dcp_identify` 대응

```yaml
name: dcp_identify_name_of_station
tags: [dcp, identify, migrate]
device:
  station_name: sensor-line1
  security_class: 0
  iface: mock
steps:
  - action: dcp_identify
    xid: 0x11223344
    expect:
      ethertype: 0x8892
      frame_id: 0xFEFF          # PN_FRAMEID_DCP_ID_RES
      service: identify
      status: success           # PN_DCP_RESP_SUCCESS
      name_of_station: sensor-line1
```

### 3.2 Security Class 1 DCP Set — `test_dcp_set_sec` 대응

```yaml
name: dcp_set_sec_class1
tags: [dcp, set, security, migrate]
device:
  station_name: old-name
  security_class: 1
  psk_hex: "1111111111111111111111111111111111111111111111111111111111111111"
  iface: mock
steps:
  - action: dcp_set
    signed: false
    name_of_station: new-name
    xid: 0xAABBCCDD
    expect:
      result: reject
      station_name: old-name    # DUT cfg 불변
  - action: dcp_set
    signed: true                # HMAC over unsigned DCP body, option 0xF0/0x01
    name_of_station: new-name
    xid: 0xAABBCCDD
    expect:
      result: accept
      station_name: new-name
```

### 3.3 Connect without integrity — `test_connect_sec` 대응

```yaml
name: rpc_connect_without_integrity
tags: [rpc, connect, security, migrate]
device:
  security_class: 1
  psk_hex: "2222222222222222222222222222222222222222222222222222222222222222"
  iface: mock
steps:
  - action: rpc_connect
    integrity: false            # block 0x0E01 없음
    expect:
      rpc_response: true        # 스택은 RPC 응답을 돌려줌
      ar: rejected              # pn_stack_ar_up() == 0
```

### 3.4 Phase 1 신규: RTC1 IO cycle smoke

기존 단위 테스트에 없는 경로. Connect 수락 후 Device가 cyclic input을 내는지 확인한다.
`security_class: 0` 으로 서명 없이 AR을 올려 스모크만 본다 (Sec1 Connect + integrity는 Phase 2).

```yaml
name: rtc1_io_cycle_smoke
tags: [rtc1, smoke]
device:
  station_name: sensor-line1
  security_class: 0
  iface: mock
  cycle_us: 8000
  input_len: 32
  output_len: 8
steps:
  - action: rpc_connect
    integrity: false
    expect:
      ar: up
      in_frame_id: 0x8001       # 스택 기본값 (IOCR 미지정 시)
      out_frame_id: 0x8002
  - action: io_cycle
    count: 16
    cycle_ms: 8
    expect:
      min_frames: 16
      period_max_ms: 20         # mock soft bound. IRT/µs 아님
      ethertype: 0x8892
```

Golden은 선택이다. 바이트 단위 고정이 필요한 step만 `golden: tests/golden/dcp_identify_res.bin` 을 붙인다.
FrameID·NameOfStation 같은 필드 assert가 기본이다.

## 4. Phase 계획

### Phase 1 — PR gate foundation

구현 후속 PR에서:

- 양방향 mock eth + 최소 Controller stub (DCP Identify/Set, Connect accept/reject)
- `test_pn_stack.c` 의 DCP Identify / Sec1 DCP Set / Connect without integrity 를 YAML로 이전
- HMAC RFC4231 단위 테스트는 `tests/test_*.c` 에 유지
- RTC1 IO cycle smoke 시나리오 1개 추가
- `ctest` + GitHub Actions (ubuntu). 전체 데몬 빌드면 `libmodbus-dev` / cJSON. pn_stack 전용 타깃이 더 단순하면 그걸 PR job으로 써도 된다

현재 CMake는 `ENABLE_PN_TESTS` 로 `test_pn_stack` 실행파일만 만든다. `enable_testing()` / `add_test()` 가 없고 `.github/` 도 없다.
Phase 1이 이 공백을 메운다. **이 문서 PR에서는 workflow/CMake를 추가하지 않는다.**

성공 실행 예 (구현 후):

```
ctest --output-on-failure
# 또는
./build/ctt --scenario tests/scenarios/dcp_identify_name_of_station.yaml
```

### Phase 2 — 시나리오 라이브러리 + soak

- Release, Alarm TX, Record Data (I&M0 `0xAFF0`), LLDP, SNMP GET(sysName)
- Security Class 1 Connect + integrity block `0x0E01`
- 메트릭: cycle jitter histogram, unexpected frame count, AR drop
- Nightly soak 1–2시간. CI에는 짧은 soak(수분)를 optional job으로

### Phase 3 — 랩 / golden / PI 매핑

- lab runner profile: veth 또는 CODESYS가 붙은 실제 링크. 가능하면 같은 YAML
- PCAP capture/replay → `tests/golden/` 회귀
- 시나리오 ↔ PI Test Bundle 카테고리 문서 매트릭스. Bundle 접근 전까지 문서만

## 5. 디렉터리 레이아웃 (제안)

구현 시 목표 트리. 지금 PR에 디렉터리를 만들지 않는다.

```
tools/ctt/                  # runner, controller stub, mock eth, asserts
tests/scenarios/            # YAML
tests/golden/               # optional frames
tests/test_pn_crypto.c      # HMAC 등 thin unit (이름 가칭)
tests/test_pn_stack.c       # Phase 1 이후: 이전되지 않은 잔여 또는 삭제
tests/dcp_probe.c           # 수동 랩. CMake 타깃 아님 (현상 유지)
tests/pn_device_run.c       # 수동 랩. CMake 타깃 아님 (현상 유지)
.github/workflows/ci.yml    # Phase 1
docs/ctt.md                 # 이 문서
```

`tools/ctt` 는 코어/어댑터와 분리한다. `core/` 에 프로토콜 분기를 넣지 않는다.
DUT는 계속 `stacks/profinet/` 만 사용한다.

## 6. 성공 기준

Phase 1:

- 매 PR에서 `ctest` (또는 `./build/ctt --scenario …`) 가 CI에서 green
- 기존 네 행동 중 HMAC·Identify.Res FrameID·Sec1 DCP Set·Connect without integrity 가 빠지지 않음
- RTC1 smoke 시나리오가 새로 통과
- mock 경로에 AF_PACKET / sudo 가 없음

신뢰성 문화:

- 새 프로토콜 동작은 시나리오와 함께 랜딩한다. 랩에서만 확인한 메모로 끝내지 않는다
- 실패 로그는 step 이름, TX/RX FrameID, expect vs actual 을 남긴다 (`printf` 금지, `LOG_*`)

## 7. 기존 코드와의 관계

### 지금 커버리지 (`tests/test_pn_stack.c`)

CMake `ENABLE_PN_TESTS=ON` (기본) 일 때 `./build/test_pn_stack`. `ctest` 등록은 없다.

| 함수 | 내용 | CTT 이전 |
|------|------|----------|
| `test_hmac` | HMAC-SHA256 RFC4231 case 1 (`pn_hmac_sha256`) | **단위 테스트로 유지** |
| `test_dcp_identify` | Identify.Res FrameID `0xFEFF`, service Identify, NameOfStation `sensor-line1` | YAML 3.1 |
| `test_dcp_set_sec` | Sec Class 1: unsigned Set 거부, signed Set 로 NameOfStation 갱신 | YAML 3.2 |
| `test_connect_sec` | Sec Class 1: integrity 없는 Connect → RPC 응답은 있으나 `pn_stack_ar_up()==0` | YAML 3.3 |

없는 것: RTC1 사이클, Release, Alarm, Record, LLDP, SNMP, Sec1 Connect 성공 경로.

### 수동 랩 도구 (CMake 타깃 아님)

| 파일 | 역할 |
|------|------|
| `tests/dcp_probe.c` | AF_PACKET 으로 Identify.Req 송신, Identify.Res + `sensor-line1` 대기. veth 점대점 |
| `tests/pn_device_run.c` | `pn_stack` 을 실제 iface 에서 짧게 poll. unsigned lab Device |

둘 다 `sudo` / `CAP_NET_RAW` 가 필요하다. CI 게이트가 아니다. Phase 3 lab profile이 이 역할을 흡수할 수 있다.

### CI

저장소에 `.github/` 가 없다. 자동 테스트는 로컬 `./build/test_pn_stack` 뿐이다.
Phase 1 workflow가 첫 PR 게이트가 된다.

전체 `multiproto_daemon` 링크는 `libmodbus` 가 `REQUIRED` 다. pn_stack 테스트만 돌릴 거면
`pn_stack` + `ctt` 타깃만 빌드하는 옵션을 Phase 1에서 검토한다.

## 8. 리스크 / 제약

- 타깃은 A-core, IRT ASIC 없음. CTT timing assert 는 mock에서 **ms 스케일 soft bound** 다. 하드 리얼타임은 랩 soak에서만 본다
- 8ms 사이클 에이징(코어 스케줄러, PREEMPT_RT 없이 최대 편차 0.1ms)은 데몬 스케줄러 수치다. mock eth jitter와 혼동하지 말 것
- CTT green ≠ PI 인증. 내부 신뢰도일 뿐 인증 증거로 제출하지 않는다. CRA/CE 도 제품 프로세스다
- Security Class 1 의 DCP option `0xF0` / Connect block `0x0E01` 은 이 저장소 프로파일이다. PI 할당 코드를 사칭하지 않는다 (`docs/profinet_stack.md`)
- mock은 큐 깊이·단일 스레드 가정이다. 실제 스위치/멀티캐스트/VLAN 태깅 이상은 Phase 3
- Controller stub이 너무 두꺼워지면 DUT 버그를 stub이 가린다. stub은 프레임 조립/파싱만, 상태 머신은 시나리오 step에 둔다
