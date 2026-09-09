# Controller Test Tool (CTT)

저장소 내부용 **통합** 필드버스 테스트 하네스 설계.
이 통합 트리에서 Phase 1–3 + PN fill + Modbus/SLMP/EIP 플러그인이 구현된다.

**결정: 도구는 하나, 프로토콜은 플러그인.**
프로토콜마다 별도 툴을 두지 않고, PN+EIP 프레임 로직을 하나의 stub에 섞지도 않는다.

Phase 1 DUT: `stacks/profinet/` — **CC-B + RT Class 1** + Security Class 1 HMAC.
**CC-C (IRT / RT Class 3) 는 이 제품·CTT에서 영구 제외**다. 후속 페이즈로 올리지 않는다.
PN 플러그인 역할: **Controller stub + DCP station** (RT Class 1). Device 스택을 대체하지 않는다.

EtherNet/IP 플러그인 DUT는 자체 스택 `stacks/ethernetip/` 이다.
`adapters/ethernetip/` 데몬 어댑터는 CTT DUT가 아니다.

Modbus TCP DUT는 `stacks/modbus/` (`protocol: modbus_tcp`). SLMP DUT는
`stacks/slmp/` Binary 3E (`protocol: slmp`). ASCII·4E 는 CTT DUT가 아니다.

## 0. 배경 / 목표

자체 구현 스택(지금 PROFINET, 곧 EtherNet/IP)은 상용 벤더가 사내에 두는 것과 같은 **자동 시나리오 하네스**가 필요하다.
랩(CODESYS / EIP Scanner)과, 이후 PI·ODVA 공인 랩 접근 이전에 회귀를 잡는다.

PROFINET DUT 목표는 **Conformance Class B (CC-B) + RT Class 1** 뿐이다.
**CC-C / IRT / RT Class 3 는 제품·도구 범위에서 영원히 빠진다.** CC-C 시나리오, 랩 매핑, PI Test Bundle CC-C 카테고리를 계획하지 않는다. Phase 3로도 키우지 않는다.

목표:

- 선언적 시나리오(`tests/scenarios/<protocol>/*.yaml`)로 프로토콜 행동을 고정한다
- 공통 runner가 `protocol:` 필드로 플러그인을 고른다
- mock transport 위에서 golden / assert / soak 를 돌린다
- PR마다 CI가 기존 행동을 잃지 않았는지 확인한다
- 새 프로토콜 동작은 랩 메모만이 아니라 시나리오와 함께 들어온다

영구 비목표 (페이즈와 무관):

- **PROFINET CC-C** 및 그에 묶인 **IRT / RT Class 3** (시나리오·랩·PI Bundle CC-C 매핑 전부)
- 전체 PI / ODVA conformance를 CTT green만으로 대체하는 것, 인증 evidence

비목표 (Phase 1–2):

- EtherCAT, 그리고 Modbus / SLMP / CC-Link 플러그인 구현
- 상용 테스트 시스템 구매·연동
- **프로토콜별 완전 분리 툴** (`tools/ctt_pn` 제품 + `tools/ctt_eip` 제품처럼 CI·YAML 스키마·리포트를 복제)
- **모놀리식 mixed stub** (한 파일에 DCP와 CIP 프레임을 함께 조립)

범위:

- CTT = 공통 runner + 프로토콜 플러그인. CI 엔트리는 `./build/ctt` 하나
- Phase 1 DUT = PROFINET IO Device (**CC-B + RT Class 1**). CTT PN 플러그인 = in-process Controller + DCP. IRT Controller가 아니다
- EtherNet/IP 플러그인 = Scanner/Originator stub. DUT = `stacks/ethernetip/` 자체 스택
- 플러그인 슬롯 패턴은 이후 프로토콜에도 열 수 있다. **지금 구현 범위는 PN + EIP + Modbus TCP + SLMP 3E**
- 단위 CI 경로에는 실제 NIC가 없다

## 1. 아키텍처

```
  tests/scenarios/<proto>/*.yaml     protocol: profinet | ethernetip | modbus_tcp | slmp
                 │
                 ▼
           tools/ctt/   공통 runner / report / soak / CI
                 │  plugin select
        ┌────────┼────────┬──────────────┐
        ▼        ▼        ▼              ▼
  proto/profinet/ proto/ethernetip/ proto/modbus/  proto/slmp/
  Controller      Scanner stub      TCP client     3E client stub
        ↕                 ↕     mock / in-process inject
   pn_stack DUT        eip_stack     mb_stack         slmp_stack
        └────────┬────────┴──────────────┘
                 ▼
          asserts / golden / metrics
```

공통과 플러그인을 나눈다.

| 공통 (`tools/ctt/`) | 플러그인 (`tools/ctt/proto/<name>/`) |
|---------------------|--------------------------------------|
| YAML 로드, step 루프, 실패 리포트 | 프레임 조립/파싱 |
| assert helper, soak, 메트릭 버킷 | 프로토콜별 expect 필드 |
| ctest / CI 엔트리 | DUT 훅 (`pn_*` vs `eip_*`) |
| mock-transport **개념** (양방향 링, 나중에 실 NIC 어댑터) | 그 링에 DUT send/recv를 묶는 코드 |

기각한 두 대안:

1. `tools/pn_ctt` + `tools/eip_ctt` 완전 분리 — CI 워크플로·시나리오 스키마·soak 리포트가 갈라진다
2. `tools/ctt/stub.c` 하나에 PN DCP와 EIP Encapsulation을 섞음 — 훅과 expect가 교차 오염된다

선택적 빌드 플래그(`ctt_pn` / `ctt_eip` 바이너리)는 나중에 허용한다.
저장소와 문서는 계속 **도구 하나**다. 플러그인 소스와 `tests/scenarios/<proto>/` 를 복제하지 않는다.

### 1.1 PROFINET 플러그인 — 기존 DUT 훅

DUT·stub 모두 **CC-B + RT Class 1**. IRT 동기·RT Class 3 프레임을 다루지 않는다.
새 DUT API를 만들지 않는다. 훅은 `stacks/profinet/include/pn_stack.h`.

| 훅 | CTT에서의 역할 |
|----|----------------|
| `pn_eth_ops_t` (`send` / `recv` / `ctx`) | mock eth 링. `send` = Device TX → Controller RX |
| `pn_stack_set_eth_ops` | AF_PACKET 대신 ops 설치. `iface=mock` 이면 raw socket을 열지 않음 |
| `pn_stack_handle_eth` | Controller TX → Device RX (DCP / RTC1) |
| `pn_stack_handle_rpc` | CM Connect/Release 등 UDP RPC 주입. Ethernet이 아님 |
| `pn_stack_poll` | Device RX dequeue + `pn_rt_send_if_due` + LLDP 주기 |
| `pn_stack_ar_up` / `pn_stack_cfg` | expect: AR, NameOfStation |

현재 `tests/test_pn_stack.c` 는 TX capture만 한다 (`send` 콜백, `recv = NULL`).
PN 플러그인은 같은 ops를 **양방향 링**으로 바꾼다.

RPC는 Device 쪽 UDP 34964. Phase 1 mock은 `pn_stack_handle_rpc` 를 Controller API로 감싼다.
Ethernet 링과 RPC 주입은 같은 시나리오에서 섞는다 (Identify → Connect → IO cycle).

### 1.2 EtherNet/IP 플러그인 — DUT 훅

DUT = `stacks/ethernetip/` 자체 Adapter 스택. `adapters/ethernetip/` 데몬 어댑터는
CTT DUT가 아니다. 훅은 `stacks/ethernetip/include/eip_stack.h`.

| 훅 | CTT에서의 역할 |
|----|----------------|
| `eip_cfg_t.mock` | 소켓 없이 start/poll. CI 기본값 |
| `eip_stack_set_transport_ops` | DUT UDP/TCP TX → Controller RX 링 |
| `eip_stack_handle_encap` | Scanner TX Encapsulation → Adapter RX |
| `eip_stack_handle_io` | Class 1 UDP IO 주입 (O→T) |
| `eip_stack_class1_up` / `eip_stack_rt_stats` | expect: Class 1, watchdog |
| `eip_stack_acd_conflict` / `eip_stack_lldp_frame` | ACD / LLDP TX |

플러그인 = Scanner/Originator stub + EIP step actions.
`test_eip_stack` 의 중요 케이스는 `tests/scenarios/ethernetip/*.yaml` 로 이전.
HMAC RFC4231 은 `tests/test_eip_crypto.c`. 잔여 `tests/test_eip_stack.c` 는
DUT 단위 경로로 유지.

구매 스택을 CTT DUT로 쓰지 않는다.

### 1.3 Modbus TCP / SLMP Binary 3E 플러그인

DUT 는 자체 스택이다. 공통 runner 는 `protocol:` 만 고른다.

| 플러그인 | protocol: | DUT | inject 훅 | 범위 밖 |
|----------|-----------|-----|-----------|---------|
| `proto/modbus/` | `modbus_tcp` | `stacks/modbus/` | `mb_stack_handle_adu` | RTU, Modbus.org 공인 랩 |
| `proto/slmp/` | `slmp` | `stacks/slmp/` | `slmp_stack_handle_request` | ASCII, 4E, Mitsubishi 공식 인증 |

시나리오 디렉터리는 `tests/scenarios/modbus/` · `tests/scenarios/slmp/`.
내부 매트릭스: `docs/ctt_modbus_matrix.md`, `docs/ctt_slmp_matrix.md`.

구성 요소:

- `tools/ctt/` — 공통 runner, report, soak, mock-transport, CI 엔트리
- `tools/ctt/proto/profinet/` — Controller stub + PN step actions (CC-B / RTC1 only)
- `tools/ctt/proto/ethernetip/` — Scanner stub + EIP steps
- `tools/ctt/proto/modbus/` — Modbus TCP client stub (`mb_stack_handle_adu`)
- `tools/ctt/proto/slmp/` — SLMP Binary 3E stub (`slmp_stack_handle_request`)
- `tests/scenarios/profinet/` · `ethernetip/` · `modbus/` · `slmp/`
- `tests/golden/` — 선택적 binary/hex. 프로토콜별 서브디리 권장
- `tests/test_*.c` — 스택 전체가 필요 없는 crypto/parser. HMAC RFC4231은 여기

## 2. Mock eth

공통 개념: in-process 양방향 링. 단위/CI 경로에 실제 NIC·`CAP_NET_RAW`·root가 없다.
프로토콜 코덱은 플러그인에 둔다. 링은 바이트 프레임만 옮긴다.

Phase 1 실현 (PN):

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

나중에 같은 공통 transport API를 AF_PACKET / veth 어댑터로 바꾼다 (lab profile).
시나리오 YAML은 그대로 두고 transport만 교체한다.

PN RPC는 Phase 1에서 링을 거치지 않는다. `pn_stack_handle_rpc(pdu, …, resp, …)` 왕복.
Phase 3 lab profile에서만 실제 UDP를 쓴다.

EIP 플러그인은 같은 링 개념에 `eip_*` inject를 묶는다. PN 프레임 파서를 공유하지 않는다.

## 3. 시나리오 스키마

공통 필드. `protocol` 로 플러그인을 고른다.

```
name: string
protocol: profinet | ethernetip | modbus_tcp | slmp
tags: [string]
device:
  # 플러그인별. 아래는 profinet
  station_name: string
  station_name: string
  security_class: 0 | 1
  psk_hex: string          # 64 hex chars, Sec Class 1
  iface: mock              # CI 기본값
  cycle_us: 8000           # optional, 스택 기본과 동일
steps:
  - action: ...            # 플러그인이 해석
    expect: ...
```

`device` / `action` / `expect` 키는 플러그인 소유다. 공통 runner는 모르는 키를 플러그인에 넘긴다.
디렉터리는 `tests/scenarios/<protocol>/` 과 `protocol:` 필드를 맞춘다.

### 3.1 PROFINET step actions (Phase 1 필수 + Phase 2 예약)

| action | 의미 | expect 예 |
|--------|------|-----------|
| `dcp_identify` | FrameID `0xFEFE` Identify.Req (멀티캐스트 `01:0E:CF:00:00:00`) | Identify.Res FrameID `0xFEFF`, NameOfStation |
| `dcp_set` | FrameID `0xFEFD` Set.Req. `signed: true` 이면 option `0xF0` / sub `0x01` HMAC | `accept` 또는 `reject`, 변경된 `station_name` |
| `rpc_connect` | CM Connect. `integrity: true` 이면 block type `0x0E01` | `ar: up` 또는 `rejected` |
| `io_cycle` | AR 이후 RTC1 (비동기 cyclic). `count`, `cycle_ms`. IRT/CC-C 스텝 없음 | 프레임 개수, 주기 상한 (ms, soft) |
| `soak` | `duration_s` 또는 `iterations` | unexpected frame = 0, AR drop = 0 |
| `rpc_release` | Phase 2 | AR down |
| `alarm` / `record_read` / `lldp` / `snmp_get` | Phase 2 | 해당 PDU |

HMAC 단위 테스트는 YAML이 아니다. `tests/test_pn_crypto.c` (또는 기존 `test_pn_stack.c`의 `test_hmac`)에 남긴다.

### 3.6 EtherNet/IP step actions

PN 테이블에 CIP 액션을 넣지 않는다. EIP 플러그인 소유.

| action | 의미 | expect 예 |
|--------|------|-----------|
| `register_session` | Encapsulation `0x0065` | `session_handle: nonzero` |
| `list_identity` | Encapsulation `0x0063` | vendor_id, product_name |
| `get_attr` | UCMM Get_Attribute_Single | `cip_status`, `u8`/`u16`/`u32`, vendor_id |
| `write_input` / `read_input` / `read_output` | Assembly process image | ASCII `data` 또는 `u8` |
| `forward_open` | CM Forward Open. `integrity: true` 이면 CPF `0x00C1` HMAC | `class1: up` 또는 `privilege: true` |
| `class1_io` | UDP Class 1 O→T | consumed `u8` |
| `io_cycle` | Class 1 consume + produce | `min_frames` |
| `acd_conflict` | `eip_stack_acd_conflict` | 이후 Identity state / TCP/IP ACD |
| `lldp` | `eip_stack_lldp_frame` | ethertype `0x88CC` |
| `watchdog` | sleep + `eip_stack_poll` | `class1: down`, `timeouts_min` |
| `poll` | DUT `eip_stack_poll` | (없음) |

아래 예시는 현재 `tests/test_pn_stack.c` 세 케이스를 옮긴 것이다. HMAC는 제외.

### 3.2 DCP Identify — `test_dcp_identify` 대응

```yaml
name: dcp_identify_name_of_station
protocol: profinet
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

### 3.3 Security Class 1 DCP Set — `test_dcp_set_sec` 대응

```yaml
name: dcp_set_sec_class1
protocol: profinet
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

### 3.4 Connect without integrity — `test_connect_sec` 대응

```yaml
name: rpc_connect_without_integrity
protocol: profinet
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

### 3.5 Phase 1 신규: RTC1 IO cycle smoke

기존 단위 테스트에 없는 경로. Connect 수락 후 Device가 cyclic input을 내는지 확인한다.
`security_class: 0` 으로 서명 없이 AR을 올려 스모크만 본다 (Sec1 Connect + integrity는 Phase 2).

```yaml
name: rtc1_io_cycle_smoke
protocol: profinet
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

Golden은 선택이다. 바이트 단위 고정이 필요한 step만 `golden: tests/golden/profinet/dcp_identify_res.pcap` 을 붙인다.
FrameID·NameOfStation 같은 필드 assert가 기본이다. mock 에서 full-frame 비교.
`--transport=af_packet` 에서는 MAC/패딩 때문에 golden 을 skip 한다.


## 4. Phase 계획

### Phase 1 — 공통 runner + PROFINET 플러그인 (CC-B / RTC1)

main에 있는 DUT는 `stacks/profinet/` 뿐이다. 구현 후속 PR에서:

- 공통 runner (YAML, report, mock-transport, ctest/CI 엔트리)
- `tools/ctt/proto/profinet/` — 양방향 mock eth + 최소 Controller stub (DCP Identify/Set, Connect accept/reject)
- `test_pn_stack.c` 의 DCP Identify / Sec1 DCP Set / Connect without integrity 를 `tests/scenarios/profinet/` 로 이전
- HMAC RFC4231 단위 테스트는 `tests/test_*.c` 에 유지
- RTC1 IO cycle smoke 시나리오 1개
- `ctest` + GitHub Actions (ubuntu). CTT PR job 은 `BUILD_DAEMON=OFF`.
  데몬 빌드는 libmodbus 없이 cJSON(+FetchContent) + OpenSSL.
- EtherNet/IP 플러그인은 **아직 구현하지 않는다** (슬롯만 문서/디렉터리 예약)

현재 CMake는 `ENABLE_PN_TESTS` 로 `test_pn_stack` 실행파일만 만든다. `enable_testing()` / `add_test()` 가 없고 `.github/` 도 없다.
Phase 1이 이 공백을 메운다. **이 문서 PR에서는 workflow/CMake를 추가하지 않는다.**

성공 실행 예 (구현 후):

```
ctest --output-on-failure
# 또는
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
```

### EtherNet/IP 플러그인 (이 트리)

- DUT = `stacks/ethernetip/` 자체 스택. 구매 스택 스텁은 대상 아님
- `tools/ctt/proto/ethernetip/` Scanner/Originator stub
- `tests/scenarios/ethernetip/*.yaml` — register / identity / assembly+FO+IO /
  Sec1 FO reject/accept / QoS / ACD / LLDP / watchdog / ListIdentity
- HMAC 단위 테스트 `tests/test_eip_crypto.c`. 잔여 `tests/test_eip_stack.c`
- 같은 `./build/ctt` 엔트리. `protocol: ethernetip`
- CI: `ctest -L ethernetip` (mock, no NIC). `libssl-dev` 필요
- 내부 매핑: `docs/ctt_odva_matrix.md` (공식 CT 아님)

```
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
ctest --test-dir build --output-on-failure -L ethernetip
```

### Phase 2 — 시나리오 라이브러리 + soak

PROFINET (Phase 1 플러그인 위, **CC-B / RTC1만**). 구현 상태 (이 트리):

| 시나리오 | YAML | 비고 |
|----------|------|------|
| Release | `rpc_release.yaml` | `pn_stack_handle_rpc` OP_RELEASE → AR down |
| Alarm TX | `alarm_tx.yaml` | DUT `pn_stack_send_alarm` FrameID `0xFC01` |
| Record I&M0 | `record_read_im0.yaml` | RPC Read, index `0xAFF0` |
| Record I&M1–4 | `record_read_im1_4.yaml` | `0xAFF1`–`0xAFF4` |
| CM Write / PrmEnd / AppReady | `rpc_write_prmend_appready.yaml` | CODESYS-like Control |
| DCP Get / Hello / Signal / Set IP | `dcp_get.yaml` 등 | golden replay |
| Alarm Low | `alarm_low.yaml` | FrameID `0xFE01` |
| LLDP | `lldp.yaml` | `pn_stack_send_lldp`, ethertype `0x88CC` |
| SNMP GET sysName | `snmp_get_sysname.yaml` | mock `handle_snmp`; lab UDP 161 when `device.ip` |
| Sec1 Connect success | `rpc_connect_sec1_integrity.yaml` | integrity block `0x0E01`, AR up + short IO |
| Soak (short) | `soak_short.yaml` | iterations; default `ctest` |
| Soak (30s) | `soak_ci.yaml` | `ctest -L soak_ci`; PR 기본 게이트에서 제외 |
| Soak (1–2h) | `nightly/soak_nightly.yaml` | ctest 미등록. workflow comment / 수동 |

메트릭: unexpected frame, AR drop, cycle period histogram (`LOG_INFO`).

IRT 동기, PTCP, RT Class 3, CC-C 전용 시나리오는 추가하지 않는다.
EtherNet/IP / Modbus / SLMP 플러그인은 이 페이즈에 넣지 않는다.

EtherNet/IP (이 트리, mock):

- register / identity / assembly / ForwardOpen / security / QoS / ACD / LLDP / watchdog / ListIdentity 시나리오 (`tests/scenarios/ethernetip/`)

공통:

- 메트릭: cycle jitter histogram, unexpected frame count, AR/session drop
- Nightly soak 1–2시간. CI에는 짧은 soak(수분)를 optional job으로

Modbus / SLMP / CC-Link 플러그인은 이 페이즈에 넣지 않는다.

### Phase 3 — 랩 / golden / 인증 매핑

구현 상태 (이 트리, **CC-B / RTC1 only**. CC-C 없음):

| 항목 | 상태 |
|------|------|
| Lab transport | `--transport=mock\|af_packet --iface --dut-iface`. 같은 YAML. 기본은 mock |
| veth 스크립트 | `tests/run_ctt_lab.sh` (DCP/LLDP/Alarm/RTC1 on wire; CM/SNMP UDP when `device.ip`) |
| CODESYS | CI 없음. `tests/codesys_manual_lab.sh` + `docs/ctt_lab.md`. `pn_device_run` / `dcp_probe` |
| Golden capture | `--capture <dir>` + `tests/regen_ctt_goldens.sh` |
| Golden replay | YAML `golden: tests/golden/profinet/…` mock `ctest` (`-L golden`) |
| PI 매핑 | `docs/ctt_pi_matrix.md` CC-A/B only. 내부 준비도. Bundle 접근 없음 |
| ODVA | `docs/ctt_odva_matrix.md` 내부 매핑. 공식 CT 아님 |
| default CI | mock `ctest` (Phase 1+2 + golden replay). lab 은 workflow_dispatch |

남은 갭 (인증·멤버십·DUT 부재 — 하네스가 메우지 않음):

- 공식 PI Test Bundle 실행·evidence — 공인 랩 / PI membership
- 공식 ODVA CT 랩 실행 — 멤버십. CTT green 이 인증을 대체하지 않음
- 공식 Modbus.org / Mitsubishi 인증 — 멤버십·공인 랩. CTT green 이 대체하지 않음
- CODESYS Windows Development System 은 CI 에 없음 (`tests/codesys_manual_lab.sh`)
- MRP / Fast Start-Up — **DUT not implemented** (풀 스택을 이 페이즈에서 만들지 않음)

## 5. 디렉터리 레이아웃

```
tools/ctt/                       # 공통 runner, report, soak, mock-transport, CI
  proto/profinet/                # Controller stub + PN steps (CC-B / RTC1, no IRT)
  proto/ethernetip/              # Scanner stub + EIP steps (self stack DUT)
  proto/modbus/                  # Modbus TCP client stub (self stack)
  proto/slmp/                    # SLMP Binary 3E stub (no 4E/ASCII)
tests/scenarios/
  profinet/                      # protocol: profinet
  ethernetip/                    # protocol: ethernetip
  modbus/                        # protocol: modbus_tcp
  slmp/                          # protocol: slmp
tests/golden/
  profinet/                  # mock PCAP goldens (Phase 3)
  ethernetip/                # (none yet)

tests/test_pn_crypto.c           # HMAC RFC4231
tests/test_eip_crypto.c          # HMAC RFC4231
tests/test_eip_stack.c           # residual DUT unit (YAML 이 CTT 경로)
tests/dcp_probe.c                # 수동 랩. BUILD_PN_LAB_TOOLS
tests/pn_device_run.c            # 수동 랩. BUILD_PN_LAB_TOOLS
tests/run_ctt_lab.sh             # Phase 3 veth AF_PACKET (not default ctest)
.github/workflows/ci.yml         # Phase 1–3 mock ctest; lab via workflow_dispatch
docs/ctt.md                      # 이 문서
docs/ctt_board.html              # 시나리오 현황 보드 (인증 아님). 재생성: tools/ctt/gen_board_data.py
docs/ctt_lab.md                  # Phase 3 lab / veth / CODESYS
docs/ctt_pi_matrix.md            # CC-A/B 내부 매핑 (인증 evidence 아님)
docs/ctt_odva_matrix.md          # EIP 내부 CT-style 매핑 (공식 CT 아님)
docs/ctt_modbus_matrix.md        # Modbus TCP FC (공식 Modbus.org 아님)
docs/ctt_slmp_matrix.md          # SLMP Binary 3E (Mitsubishi 공식 인증 아님)

```

`tools/ctt` 는 코어/어댑터와 분리한다. `core/` 에 프로토콜 분기를 넣지 않는다.
PN DUT는 `stacks/profinet/`. EIP DUT는 `stacks/ethernetip/`.
Modbus DUT는 `stacks/modbus/`. SLMP DUT는 `stacks/slmp/`.

## 6. 성공 기준

Phase 1:

- 매 PR에서 `ctest` (또는 `./build/ctt --scenario tests/scenarios/profinet/…`) 가 CI에서 green
- 기존 네 행동 중 HMAC·Identify.Res FrameID·Sec1 DCP Set·Connect without integrity 가 빠지지 않음
- RTC1 smoke 시나리오가 새로 통과 (CC-B cyclic. IRT/CC-C 시나리오 없음)
- mock 경로에 AF_PACKET / sudo 가 없음
- runner는 `protocol:` 으로 플러그인을 고른다. Phase 1에서 구현된 플러그인은 profinet 하나

Phase 2 (PROFINET, 이 트리):

- Release, Alarm TX, I&M0 record, LLDP, SNMP sysName, Sec1 Connect **success** (`integrity: true`) 시나리오가 mock에서 green
- `soak_short` 가 기본 `ctest`에 포함. `soak_ci` (30s) 는 `-LE soak_ci` 로 PR 게이트에서 제외
- 메트릭(unexpected / AR drop / period histogram)을 `LOG_INFO` 로 남김
- 이 페이즈의 PN 범위만. CC-C / IRT 시나리오 없음. (통합 트리에서는 EIP/Modbus/SLMP 플러그인이 같은 runner 에 있음)

Phase 3 (하네스, 이 트리):

- 같은 YAML 이 `--transport=mock` (기본 `ctest`) 과 `--transport=af_packet` 에서 돈다
- mock golden replay (`dcp_identify_res.pcap`, Sec1 Set accept) 가 기본 CI 에 포함
- `tests/run_ctt_lab.sh` + `docs/ctt_lab.md` + `docs/ctt_pi_matrix.md`
- default CI 에 sudo/AF_PACKET 없음. lab 은 workflow_dispatch
- CC-C 시나리오/매핑 없음. 공식 PI Bundle / ODVA CT 실행 없음

EIP 플러그인 (이 트리):

- `protocol: ethernetip` 시나리오가 같은 ctt 엔트리에서 green (`ctest -L ethernetip`)
- `test_eip_stack` 에서 옮긴 행동이 빠지지 않음
- DUT 는 자체 스택. 구매 스택 스텁 아님

Modbus TCP / SLMP 플러그인 (이 트리):

- `protocol: modbus_tcp` / `protocol: slmp` 시나리오가 같은 `./build/ctt` 에서 green
- DUT 는 `stacks/modbus/` · `stacks/slmp/` (libmodbus / ASCII·4E 아님)

신뢰성 문화:

- 새 프로토콜 동작은 해당 플러그인 시나리오와 함께 랜딩한다
- 실패 로그는 protocol, step 이름, TX/RX 식별자, expect vs actual (`printf` 금지, `LOG_*`)

## 7. 기존 코드와의 관계

### PROFINET — `tests/test_pn_stack.c`

CMake `ENABLE_PN_TESTS=ON` (기본) 일 때 `./build/test_pn_stack`. `ctest` 등록은 없다.

| 함수 | 내용 | CTT 이전 |
|------|------|----------|
| `test_hmac` | HMAC-SHA256 RFC4231 case 1 (`pn_hmac_sha256`) | **단위 테스트로 유지** |
| `test_dcp_identify` | Identify.Res FrameID `0xFEFF`, service Identify, NameOfStation `sensor-line1` | YAML 3.2 |
| `test_dcp_set_sec` | Sec Class 1: unsigned Set 거부, signed Set 로 NameOfStation 갱신 | YAML 3.3 |
| `test_connect_sec` | Sec Class 1: integrity 없는 Connect → RPC 응답은 있으나 `pn_stack_ar_up()==0` | YAML 3.4 |

없는 것 (CC-B, Phase 3 랩): 실 NIC / AF_PACKET, PI Test Bundle 매핑.
의도적으로 없는 것: IRT / PTCP / RT Class 3 / CC-C. 갭이 아니라 제품 범위 밖이다.

### EtherNet/IP

| 위치 | 상태 | CTT |
|------|------|-----|
| `adapters/ethernetip/` | 자체 스택 연결 (데몬). 구매 스텁 아님 | DUT 아님 |
| `stacks/ethernetip/` | Adapter Class 1, UCMM, Sec 1/2, LLDP/ACD/QoS | **DUT** |
| `tests/scenarios/ethernetip/` | YAML (register … ListIdentity) | `ctest -L ethernetip` |
| `tests/test_eip_crypto.c` | HMAC RFC4231 | 단위 테스트 |
| `tests/test_eip_stack.c` | 잔여 DUT 단위 | `ENABLE_EIP_TESTS` |

### 수동 랩 도구 (CMake 타깃 아님)

| 파일 | 역할 |
|------|------|
| `tests/dcp_probe.c` | AF_PACKET 으로 Identify.Req 송신, Identify.Res + `sensor-line1` 대기. veth 점대점 |
| `tests/pn_device_run.c` | `pn_stack` 을 실제 iface 에서 짧게 poll. unsigned lab Device |

둘 다 `sudo` / `CAP_NET_RAW` 가 필요하다. CI 게이트가 아니다. Phase 3 lab profile이 이 역할을 흡수할 수 있다.

### CI

`.github/workflows/ci.yml` 이 mock `ctest` 게이트다. CTT job 은 공통 `./build/ctt`
(`BUILD_DAEMON=OFF`). 프로토콜별 workflow 를 복제하지 않는다.
`libssl-dev` 는 EIP 스택용. 데몬(`BUILD_DAEMON=ON`)은 libmodbus 없이 cJSON 만 필요하다.

## 8. 리스크 / 제약

- 타깃은 A-core이며 IRT 전용 ASIC(하드웨어 타임스탬프·동기 스위치)이 없다. **CC-C / IRT / RT Class 3 는 이 하드웨어에서 불가하고, 제품·CTT 범위 밖이다.** 시나리오·랩 매핑·PI Bundle CC-C를 후속 페이즈로 넣지 않는다
- CTT timing assert 는 mock에서 **ms 스케일 soft bound** 다. 하드 리얼타임(µs IRT)을 mock이나 A-core 랩 soak로 주장하지 않는다
- 8ms 사이클 에이징(코어 스케줄러, PREEMPT_RT 없이 최대 편차 0.1ms)은 데몬 스케줄러 수치다. mock eth jitter·IRT 동기 정밀도와 혼동하지 말 것
- CTT green ≠ PI / ODVA 인증. 내부 신뢰도일 뿐 인증 증거로 제출하지 않는다. 장래에 PI 랩을 가더라도 대상은 CC-B(및 해당 CC-A)이지 CC-C가 아니다. CRA/CE 도 제품 프로세스다
- Security Class 1 의 DCP option `0xF0` / Connect block `0x0E01` 은 이 저장소 프로파일이다. PI 할당 코드를 사칭하지 않는다 (`docs/profinet_stack.md`)
- mock은 큐 깊이·단일 스레드 가정이다. 실제 스위치/멀티캐스트/VLAN 태깅 이상은 Phase 3
- 플러그인 stub이 너무 두꺼워지면 DUT 버그를 stub이 가린다. stub은 프레임 조립/파싱만, 상태 머신은 시나리오 step에 둔다
- 공통 runner가 `if (protocol == profinet)` 로 프레임을 다루기 시작하면 플러그인 경계 위반이다. 그건 `proto/<name>/` 으로 옮긴다
- EIP 플러그인을 구매 스택 스텁에 붙이면 시나리오가 공허해진다. DUT는 `stacks/ethernetip/` 자체 스택이다
