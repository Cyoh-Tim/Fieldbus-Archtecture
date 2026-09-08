# PROFINET 가이드 — 이 저장소 소스로 읽기

이 문서는 PROFINET 스펙을 처음부터 외우지 않은 사람을 위해 썼다.
공장에서 PLC와 센서가 어떻게 이름을 바꾸고, 연결을 맺고, 8 ms마다
데이터를 주고받는지부터 설명한다. 예는 전부 **이 저장소에 실제로 있는
코드**다. 추측한 프레임 포맷이나 “나중에 넣을 기능”은 예로 쓰지 않는다.

읽는 순서:

1. [이 문서가 하는 일](#1-이-문서가-하는-일)
2. [한 줄로 이해하기](#2-한-줄로-이해하기)
3. [공장 비유](#3-공장-비유)
4. [Controller 와 Device](#4-controller-와-device)
5. [이 저장소에서 코드가 놓인 곳](#5-이-저장소에서-코드가-놓인-곳)
6. [용어 사전](#6-용어-사전)
7. [통신이 쓰는 길](#7-통신이-쓰는-길)
8. [한 연결의 하루](#8-한-연결의-하루)
9. [이더넷 프레임](#9-이더넷-프레임)
10. [DCP — 이름과 주소를 찾는 방송](#10-dcp--이름과-주소를-찾는-방송)
11. [CM — 연결을 맺는 계약](#11-cm--연결을-맺는-계약)
12. [RTC1 — 주기 데이터](#12-rtc1--주기-데이터)
13. [프로세스 이미지와 JSON 포인트](#13-프로세스-이미지와-json-포인트)
14. [레코드 — 명찰과 포트 정보](#14-레코드--명찰과-포트-정보)
15. [알람과 진단](#15-알람과-진단)
16. [LLDP — 이웃 소개](#16-lldp--이웃-소개)
17. [SNMP — 토폴로지용 읽기](#17-snmp--토폴로지용-읽기)
18. [Security Class 1 서브셋과 HMAC](#18-security-class-1-서브셋과-hmac)
19. [GSDML — 장치에 붙는 설명서](#19-gsdml--장치에-붙는-설명서)
20. [코어는 프로토콜을 모른다](#20-코어는-프로토콜을-모른다)
21. [설정 파일](#21-설정-파일)
22. [테스트로 확인하는 법](#22-테스트로-확인하는-법)
23. [이 스택이 하지 않는 것](#23-이-스택이-하지-않는-것)
24. [소스 파일 지도](#24-소스-파일-지도)
25. [자주 나오는 오해](#25-자주-나오는-오해)
26. [더 읽을 문서](#26-더-읽을-문서)

---

## 1. 이 문서가 하는 일

하는 일:

- PROFINET IO **Device**(센서/액추에이터 쪽)가 무엇을 위해 어떤 패킷을
  주고받는지, 이 코드와 맞춰 설명한다.
- 엔지니어링 툴(TIA, CODESYS)이 “Scan for Devices” 를 눌렀을 때 이
  프로세스가 왜 응답하는지 설명한다.
- 랩에서 검증한 범위와 **인증이 아닌 것**을 구분한다.

하지 않는 일:

- PI(PROFIBUS & PROFINET International) 인증서나 CRA 적합 선언을 대신하지
  않는다.
- 공식 ART / SPIRTA / ETS 시험소 절차를 설명하지 않는다.
- Controller(PLC 쪽 스캐너) 구현을 설명하지 않는다. 이 저장소에는 없다.
- IRT(등시성 실시간, RT Class 3) 를 설명하지 않는다. 구현하지 않았고
  Connect 에서 거절한다.

스펙의 권위는 PI 문서에 있다. 이 문서는 **이 랩 스택이 무엇을 실제로
하는지**의 해설이다.

---

## 2. 한 줄로 이해하기

PROFINET 은 공장 이더넷 위에서 PLC와 현장 장치가 **이름을 맞추고,
계약을 맺은 뒤, 짧은 주기로 입출력 바이트를 주고받는** 방법이다.

이 저장소의 프로세스는 현장 장치(Device)다. PLC가 먼저 말을 걸고, 이
코드가 응답한다. 주기 데이터의 최소 주기는 **8 ms** 다.

```
  PLC (Controller)                          이 프로세스 (Device)
  ────────────────                          ────────────────────
  “이름이 sensor-line1 인 사람?”   ──DCP──►  “저요. IP는 192.168.10.2”
  “이 모듈 구성으로 연결하자”      ──RPC──►  “AR 만들었습니다”
  “파라미터 끝”                    ──RPC──►  “준비됐습니다 (AppReady)”
  8 ms마다 출력 8바이트            ◄─RTC1─►  8 ms마다 입력 32바이트
```

JSON 설정만 보면 사용자는 이렇게 적는다.

```json
"protocol": "profinet",
"protocol_params": { "device_name": "sensor-line1", "iface": "eth0" },
"points": [
  { "name": "barcode_value", "access": "read",  "address": { "profinet": { "byte_offset": 0, "length": 32 } } },
  { "name": "trigger",       "access": "write", "address": { "profinet": { "byte_offset": 0, "length": 1 } } }
]
```

코어는 `protocol` 문자열만 보고 어댑터를 고른다. 프레임 포맷은 코어가
모른다. 해석은 `adapters/profinet/` 과 `stacks/profinet/` 안에만 있다.

---

## 3. 공장 비유

컨베이어 위에 바코드 센서가 있다고 하자.

- **센서가 읽는 값**(바코드 문자열)은 PLC가 계속 받아가야 한다. PROFINET
  에서는 이것을 **입력(input)** 이라고 한다. 장치 → 컨트롤러.
- **PLC가 센서에 주는 명령**(트리거 비트)은 **출력(output)** 이다.
  컨트롤러 → 장치.
- 입출력 방향은 “사람이 보기 편한 쪽”이 아니라 **컨트롤러 기준**이다.
  처음 볼 때 가장 헷갈리는 지점이다.

이 스택의 랩 기본값은 입력 32바이트, 출력 8바이트다. GSDML의 슬롯 1
모듈과 `config/example.profinet.json` 이 같은 크기를 말한다.

이름을 정하는 일(스테이션 네임), IP를 정하는 일, “이제부터 8 ms마다
이 바이트를 교환하자”는 계약은 전부 주기 데이터보다 **먼저** 일어난다.
주기가 돌기 전에 이름이 틀리면 PLC는 장치를 찾지 못한다.

---

## 4. Controller 와 Device

| 역할 | 현장에서의 이름 | 이 저장소 |
|------|-----------------|-----------|
| **Controller** | PLC, SoftPLC, PN 컨트롤러 | 없음. 테스트 시뮬레이터만 있음 |
| **Device** | 센서, 드라이브, IO 모듈 | `stacks/profinet` 전부 |

CODESYS Control SL 을 이 VM에 깔아도, **빈 런타임은 PN Controller 가
아니다.** Windows Development System 에서 GSDML을 넣고 IEC 앱을
다운로드해야 컨트롤러가 된다. 랩에서 같은 순서를 재현하는 프로그램은
`tests/pn_codesys_beta.c` 이지, CODESYS 바이너리가 아니다.

Device 가 하는 일의 핵심은 세 가지다.

1. 누가 부르면 이름/IP로 대답한다 (DCP).
2. 컨트롤러가 제안한 모듈 구성으로 연결을 받는다 (CM / RPC).
3. 합의한 주기로 입출력 프레임을 보낸다 (RTC1).

---

## 5. 이 저장소에서 코드가 놓인 곳

```
adapters/profinet/          데몬이 보는 플러그인. protocol_adapter.h 만 구현
stacks/profinet/include/    공개 헤더 (pn_stack.h) 와 내부 헤더
stacks/profinet/src/        DCP, RPC, RTC1, SNMP, LLDP, 알람, 레코드
stacks/profinet/gsdml/      엔지니어링 툴이 읽는 장치 설명서
config/example.profinet.json 데몬 설정 예
tests/test_pn_stack.c       이더넷 없이 단위 테스트
tests/pn_pi_pretest.c       veth 위 랩 프리테스트
tests/pn_codesys_beta.c     CODESYS 와 같은 CM 순서
```

공개 생성자는 하나다.

```327:341:adapters/profinet/profinet_adapter.c
protocol_adapter_t *profinet_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
    a->name = "profinet";
    a->init = pn_init;
    a->connect = pn_connect;
    a->disconnect = pn_disconnect;
    a->poll_cycle = pn_poll_cycle;
    a->read_point = pn_read_point;
    a->write_point = pn_write_point;
    a->health = pn_health;
    a->destroy = pn_destroy;
    return a;
}
```

스택 자체도 생성자는 `pn_stack_create()` 하나다. 테스트는 실제 NIC 없이
`pn_stack_set_eth_ops()` 로 가짜 이더넷을 끼운다.

---

## 6. 용어 사전

처음 보면 약어가 많다. 이 스택에서 쓰는 뜻만 적는다.

| 말 | 쉬운 뜻 | 이 코드에서 |
|----|---------|-------------|
| **AR** | Application Relation. 컨트롤러와 장치 사이의 “이번 연결” | `pn_ar_t`, `s->ar` |
| **DAP** | Device Access Point. 슬롯 0 에 고정된 장치 본체 | GSDML `DeviceAccessPointItem` |
| **DCP** | 이름/IP를 찾고 쓰는 링크 계층 프로토콜 | `pn_dcp.c` |
| **NameOfStation** | 네트워크에서 부르는 이름. DNS처럼 점으로 구분 | `cfg.station_name` |
| **CM** | Context Management. 연결·파라미터·해제 | `pn_rpc.c` |
| **RPC** | CM 이 타는 UDP 원격 호출. 포트 34964 | `PN_RPC_PORT` |
| **Connect** | AR 을 만들자는 첫 RPC | `OP_CONNECT` |
| **PrmEnd** | 파라미터 쓰기 끝 | `PN_CM_W_APPRDY` 로 전이 |
| **ApplicationReady** | 장치가 “이제 주기 데이터 됩니다” | 장치가 먼저 req, 컨트롤러 ACK |
| **DATAEX** | 주기 입출력이 도는 상태 | `PN_CM_DATAEX` |
| **RTC1** | Real-Time Class 1. 비동기 주기 IO | `pn_rt.c` |
| **IRT / RT Class 3** | 하드웨어 시각 동기 주기. **미구현** | Connect 거부 |
| **IOCR** | IO Communication Relation. 입력 CR / 출력 CR 각각 하나 | `pn_iocr_t` |
| **C_SDU** | 주기 프레임 안의 사용자 데이터+상태 | `build_input_csdu()` |
| **IOPS** | IO Object Provider Status. 데이터가 유효한가 | `PN_IOPS_GOOD` = `0x80` |
| **FrameID** | 주기/알람/DCP 를 구분하는 16비트 | 입력 `0x8123`, 출력 `0x8000` (이 랩) |
| **SendClock** | 기본 틱. 32 × 31.25 µs = 1 ms | GSDML `SendClock="32"` |
| **ReductionRatio** | 몇 틱마다 보낼지. 8 → 8 ms | GSDML `8 16 … 512` |
| **GSDML** | 장치를 툴에 알려 주는 XML | `gsdml/*.xml` |
| **PDEV** | 인터페이스(0x8000)·포트(0x8001) 서브모듈 | 슬롯 0 |
| **I&M** | Identification & Maintenance. 명찰 레코드 | `pn_record.c` |
| **LLDP** | 스위치/이웃이 누구인지 알리는 이더넷 | `pn_lldp.c` |
| **SNMP** | 토폴로지·카운터 조회 (UDP 161) | `pn_snmp.c` |
| **CC-A / B / C** | Conformance Class. 누적 기능 묶음 | 이 스택은 랩 CC-B 서브셋, CC-C 없음 |
| **SC1** | Security Class 1. DCP/SNMP 하드닝 | 랩 서브셋만. 인증 아님 |
| **VendorID** | PI가 제조사에 할당하는 ID | 랩은 `0xABCD` (할당 아님) |

CM 상태 머신은 네 값이다.

```94:97:stacks/profinet/include/pn_types.h
#define PN_CM_OFFLINE         0
#define PN_CM_CONNECTED       1
#define PN_CM_W_APPRDY        2
#define PN_CM_DATAEX          3
```

`pn_stack_ar_up()` 은 **DATAEX 일 때만** 1 이다. Connect 만 끝난
`CONNECTED` 는 아직 주기 데이터가 없다.

```455:458:stacks/profinet/src/pn_stack.c
int pn_stack_ar_up(const pn_stack_t *s)
{
    return s && s->ar.established && s->ar.cm_state == PN_CM_DATAEX;
}
```

---

## 7. 통신이 쓰는 길

한 프로토콜이 아니라 **여러 종류의 패킷이 같은 NIC 를 공유**한다.

```
이더넷 프레임
├─ EtherType 0x8892  PROFINET
│   ├─ FrameID 0xFEFE/FF  DCP Identify
│   ├─ FrameID 0xFEFD     DCP Get/Set
│   ├─ FrameID 0xFEFC     DCP Hello
│   ├─ FrameID 0xFC01/FE01 알람 RTA
│   └─ FrameID 0x8000/8123  RTC1 주기 IO (이 랩의 할당)
├─ EtherType 0x88CC  LLDP
├─ EtherType 0x88E3  MRP (이 스택은 무시)
├─ UDP/34964         CM RPC
└─ UDP/161           SNMP
```

상수는 `pn_types.h` 에 모여 있다.

```7:17:stacks/profinet/include/pn_types.h
#define PN_ETHTYPE_PN         0x8892u
#define PN_ETHTYPE_LLDP       0x88CCu
#define PN_ETHTYPE_VLAN       0x8100u
#define PN_ETHTYPE_MRP        0x88E3u

#define PN_FRAMEID_DCP_HELLO  0xFEFCu
#define PN_FRAMEID_DCP_GETSET 0xFEFDu
#define PN_FRAMEID_DCP_ID_REQ 0xFEFEu
#define PN_FRAMEID_DCP_ID_RES 0xFEFFu
#define PN_FRAMEID_ALARM_HIGH 0xFC01u
#define PN_FRAMEID_ALARM_LOW  0xFE01u
```

수신 분기는 `pn_stack_handle_eth()` 한곳이다. 이더넷을 열어 보고
EtherType → FrameID 순으로 넘긴다. MRP(`0x88E3`) 는 CC-B 옵션 링
리던던시인데 구현하지 않아서 **버리기만** 한다. 그래서 랩에서 MRP
이더타입을 쏟아도 RTC1 이 죽지 않는다.

```335:370:stacks/profinet/src/pn_stack.c
int pn_stack_handle_eth(pn_stack_t *s, const uint8_t *frame, size_t len)
{
    /* ... parse ... */
    if (et == PN_ETHTYPE_PN && plen >= 2) {
        uint16_t fid = pn_rd_be16(payload);
        if (fid == PN_FRAMEID_DCP_ID_REQ || fid == PN_FRAMEID_DCP_GETSET ||
            fid == PN_FRAMEID_DCP_HELLO) {
            if (ours || dcp_mc) {
                pn_dcp_on_frame(s, src, payload, plen);
            }
        } else if (fid == PN_FRAMEID_ALARM_HIGH || fid == PN_FRAMEID_ALARM_LOW) {
            if (ours) {
                pn_alarm_on_frame(s, payload, plen);
            }
        } else if (ours) {
            pn_rt_on_frame(s, payload, plen);
        }
        return 0;
    }
    if (et == PN_ETHTYPE_LLDP) {
        pn_lldp_on_frame(s, src, payload, plen);
        return 0;
    }
    if (et == PN_ETHTYPE_MRP) {
        return 0;
    }
    return 0;
}
```

데몬의 `poll_cycle` 은 이 함수를 여러 번 돌리고, RPC/SNMP UDP, RTC
워치독, 알람, LLDP/Hello 타이머를 이어서 돈다. **주기 IO 의 시계는
여기 있지 않다.** 아래 RTC1 장을 본다.

---

## 8. 한 연결의 하루

시간 순으로 보면 이렇다. 랩 프리테스트(`tests/pn_pi_pretest.c`) 와
CODESYS 베타(`tests/pn_codesys_beta.c`) 가 같은 순서를 탄다.

```
 0. 프로세스 기동
    pn_stack_start()
      · AF_PACKET 오픈
      · UDP 34964 / 161 바인드
      · RTC1 스레드 시작 (아직 보낼 AR 없음)
      · LLDP 한 장, DCP Hello 한 장

 1. 컨트롤러가 장치를 찾음          DCP Identify (멀티캐스트)
    장치가 Identify.Res             이름, MAC, IP, DeviceID

 2. (엔지니어링) 이름 지정          DCP Set NameOfStation
    AR 이 없으므로 허용             Nominate

 3. SNMP Get sysName 등             토폴로지. Set 은 거절

 4. Connect.req                     UDP 34964
    장치가 Connect.res              AR UUID, IOCR FrameID, AlarmCR
    상태 = CONNECTED                아직 DATAEX 아님

 5. Write / WriteMultiple           I&M, PDEV Adjust 등 파라미터
    Read                            I&M0, RealIdent, PDPort …

 6. PrmEnd                          파라미터 끝
    상태 = W_APPRDY
    장치가 ApplicationReady.req     장치가 먼저 보냄
    컨트롤러 ACK                    그제야 DATAEX

 7. RTC1 주기                       입력 프레임 송신, 출력 프레임 수신
    알람이 있으면 RTA

 8. Release                         AR 삭제, 주기 중단
    다시 Connect 가능
```

기동 코드:

```268:305:stacks/profinet/src/pn_stack.c
int pn_stack_start(pn_stack_t *s)
{
    int rc = pn_eth_open(s);
    /* ... UDP bind 34964 / 161 ... */
    s->running = 1;
    pn_rt_thread_start(s);
    LOG_INFO("pn_stack",
             "start RT1 sec=%d name=%s iface=%s in=%u out=%u cycle=%uus",
             s->cfg.security_class, s->cfg.station_name,
             s->cfg.iface[0] ? s->cfg.iface : "mock", s->cfg.input_len,
             s->cfg.output_len, s->cfg.cycle_us);
    pn_lldp_send(s);
    pn_dcp_send_hello(s);
    /* ... */
    return 0;
}
```

ApplicationReady 는 컨트롤러가 보내는 것이 아니라 **장치가 보낸 요청을
컨트롤러가 ACK** 한다. `pn_rpc.c` 는 PrmEnd 를 받은 뒤 `W_APPRDY` 로
바꾸고, ACK 를 받으면 `enter_dataex()` 한다.

```804:809:stacks/profinet/src/pn_rpc.c
    if (ptype == RPC_PT_RESPONSE) {
        if (s->ar.cm_state == PN_CM_W_APPRDY) {
            enter_dataex(s);
            *out_len = 0;
            return 0;
        }
```

이게 왜 중요하냐면, “Connect 가 성공했다”와 “8 ms 데이터가 돈다”는
다른 사건이기 때문이다. 헬스 체크 `pn_health()` 는 `pn_stack_ar_up()`
이라서 DATAEX 전엔 `connected=0` 이다.

---

## 9. 이더넷 프레임

PROFINET 실시간 프레임은 TCP 가 아니다. 이더넷 헤더 뒤에 EtherType
`0x8892` 와 FrameID 가 온다.

```
  6바이트 dst MAC | 6바이트 src MAC | 2바이트 EtherType
  [옵션: VLAN 태그 0x8100 + TCI]
  2바이트 FrameID | 나머지 페이로드
```

조립은 `pn_eth_build()` / `pn_eth_build_vlan()` 이다. `tci == 0xFFFF`
이면 태그를 붙이지 않는다.

```47:67:stacks/profinet/src/pn_eth.c
size_t pn_eth_build_vlan(uint8_t *out, size_t cap, const uint8_t dst[6],
                         const uint8_t src[6], uint16_t tci, uint16_t ethertype,
                         const uint8_t *payload, size_t plen)
{
    int tagged = (tci != 0xFFFFu);
    size_t hdr = tagged ? 18u : 14u;
    /* dst, src, (VLAN,) ethertype, payload */
    return hdr + plen;
}
```

실제 NIC 에서는 Linux `AF_PACKET` 소켓으로 raw 프레임을 넣고 뺀다.
단위 테스트는 그 소켓 대신 `pn_eth_ops_t` 콜백을 끼워, `send()` 가
캡처 버퍼에 프레임을 쌓게 한다.

시계는 `CLOCK_MONOTONIC` 나노초다.

```32:37:stacks/profinet/src/pn_eth.c
uint64_t pn_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
```

코어 스케줄러의 `cycle_ms`(보통 8) 와 이 시계는 **다른 물건**이다.
코어 주기는 “어댑터 poll 을 얼마나 자주 부를지”이고, RTC1 주기는
Connect 가 정한 SendClock × ReductionRatio 이다.

---

## 10. DCP — 이름과 주소를 찾는 방송

### 10.1 왜 방송인가

장치가 아직 IP가 없거나, PLC가 IP를 모를 수 있다. DCP 는 이더넷
멀티캐스트 `01:0E:CF:00:00:00` 으로 “이름 있는 사람?” 하고 묻는다.
TCP/IP 스택이 필요 없다.

Identify 요청 필터:

- **AllSelector** (`option 0xFF`) — 이 링크의 모든 PN 장치
- **NameOfStation** — 이름이 일치할 때만
- **DeviceID** — VendorID+DeviceID 가 일치할 때만

응답에는 장치 타입, 이름, Vendor/Device ID, 역할, IP, MAC 이 들어간다.
`build_identify_blocks()` 가 그 블록을 쌓는다.

### 10.2 Get 과 Set

- **Get**: 지금 이름/IP 를 읽어 간다. AR 과 무관하게 응답한다.
- **Set**: 이름 또는 IP 를 바꾼다. **AR 이 있으면 거절**한다 (SC1 서브셋).
  AR 이 없을 때만 적용한다. CODESYS “Nominate” 와 랩 프리테스트의
  Set Name 은 Connect **전** 이라 통과한다.

거절 조건:

```221:229:stacks/profinet/src/pn_dcp.c
static int dcp_ar_write_protect(const pn_stack_t *s)
{
    return s->ar.cm_state != PN_CM_OFFLINE;
}

static int dcp_is_name_or_ip(uint8_t opt, uint8_t sub)
{
    return (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_NAME) ||
           (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM);
}
```

거절할 때 이름/IP 를 바꾸지 않고, Set 응답 블록에 BlockError `0x05`
(SET not possible by local reasons) 를 넣는다. Identify/Get 은 그대로다.

### 10.3 Hello

기동 직후, 그리고 AR 이 없을 때 1초마다 Hello 를 보낸다. “나 여기
있어요” 광고다. AR 이 DATAEX 로 올라가면 Hello 를 멈춘다
(`pn_stack_poll()` 의 `!s->ar.established` 조건).

### 10.4 DCP 헤더

```
FrameID | ServiceID | ServiceType | Xid(4) | ResponseDelay(2) | DCPDataLength(2)
블록들: Option, Suboption, DCPBlockLength, 데이터, (홀수면 패드 1바이트)
```

`parse_hdr()` 가 이 12바이트를 읽는다. Identify = ServiceID `0x05`,
Get `0x03`, Set `0x04`, Hello `0x06`.

---

## 11. CM — 연결을 맺는 계약

DCP 가 “누구세요?”라면 CM 은 “앞으로 이렇게 일합시다” 계약서다.
UDP 포트 **34964** 위에 DCE/RPC 헤더가 있고, 그 안에 PNIO 블록이
줄줄이 붙는다.

### 11.1 Connect 가 가져오는 것

컨트롤러 Connect.req 안의 블록 예:

| 블록 | 타입 | 내용 |
|------|------|------|
| ARBlockReq | `0x0101` | AR UUID, 세션 키, 컨트롤러 MAC |
| IOCRBlockReq | `0x0102` | 입력 또는 출력 CR. RT 클래스, FrameID, SendClock, ReductionRatio, 데이터 길이 |
| AlarmCRBlockReq | `0x0103` | 알람 채널 타임아웃/재시도 |
| ExpectedSubmodule | `0x0104` | 슬롯/서브슬롯/모듈 Ident, IO 길이 |

이 스택은 IOCR 의 RT 클래스가 **3**(IRT) 이면 연결 자체를 거절한다.

```216:218:stacks/profinet/src/pn_rpc.c
            /* CC-C IRT: RT_CLASS_3 / IRT FrameID range. Not a CC-B feature.
             * Lab CC-B is RT Class 1 + SNMP; reject rather than enter DATAEX. */
            if (rt >= PN_RT_CLASS_3) {
```

Connect.res 에는 ARServerBlock(스테이션 이름), IOCRBlockRes(장치가 고른
FrameID), AlarmCRBlockRes 가 돌아간다. 랩에서 장치가 고르는 값은 대략
입력 FrameID `0x8123`, 출력 FrameID `0x8000` 이다.

성공하면 상태는 `CONNECTED`, `established` 는 아직 0 이다.

```855:860:stacks/profinet/src/pn_rpc.c
        finalize_ar(s);
        uint8_t blocks_res[512];
        size_t bn = build_connect_res_blocks(s, blocks_res, sizeof(blocks_res));
        so = ndr_wrap(stub_out, blocks_res, bn, le);
        s->ar.cm_state = PN_CM_CONNECTED;
        s->ar.established = 0;
```

### 11.2 Write / Read / WriteMultiple

Connect 다음 PLC는 레코드를 쓴다. I&M1 태그, 포트 Adjust, CheckNeighbors
같은 것이다. 인덱스는 `pn_types.h` 의 `PN_INDEX_*` 다.

WriteMultiple (`0xE040`) 은 여러 Write 를 한 RPC 에 담는다. CODESYS 는
이걸 쓰고, 랩 프리테스트도 세 개의 IODWriteRes 를 기대한다.

### 11.3 PrmEnd → ApplicationReady → DATAEX

PrmEnd 는 “파라미터 더 없음”이다. 장치는 ApplicationReady.req 를
컨트롤러 IP/포트로 **먼저** 보낸다 (`rpc_tx_pending`). 컨트롤러 ACK
(RPC response) 가 오면 `enter_dataex()`:

- `cm_state = DATAEX`
- `established = 1`
- `next_rt_ns = 0` 이라서 첫 주기 프레임을 곧 보낸다

### 11.4 Release

Release RPC 는 `pn_ar_reset()` 이다. 주기 송신 중단, 입출력 이미지
클리어, 알람 상태 리셋. 그 다음 다시 Connect 할 수 있다. 프리테스트의
`LAB-CM-RECONNECT` 가 그 경로다.

### 11.5 엔디안

RPC 헤더는 little-endian 인 경우가 많다(`drep` 플래그). PNIO 블록
내용은 big-endian 이다. `pn_rpc.c` 의 `rd16(..., le)` 와
`pn_rd_be16()` 이 섞여 있는 이유다. 직접 패킷을 볼 때 헷갈리기 쉬운
지점이다.

---

## 12. RTC1 — 주기 데이터

### 12.1 주기는 누가 정하나

공식:

```
주기(ns) = SendClockFactor × ReductionRatio × 31250
```

31.25 µs 가 PROFINET 의 기본 틱이다. GSDML 은 `SendClock="32"` 이라
틱이 1 ms 이고, ReductionRatio 8 이면 **8 ms** 다. 허용 RR 은
`8 16 32 64 128 256 512` → **8 ms ~ 512 ms**.

```77:95:stacks/profinet/src/pn_stack.c
uint64_t pn_ar_cycle_ns(const pn_ar_t *ar, uint32_t fallback_us)
{
    uint64_t sc = ar->send_clock_factor ? ar->send_clock_factor
                                       : PN_SENDCLOCK_DEFAULT;
    uint64_t ns = 0;
    if (ar->reduction_ratio != 0) {
        ns = sc * (uint64_t)ar->reduction_ratio * 31250ull;
    }
    if (ns == 0) {
        uint32_t us = fallback_us ? fallback_us : PN_CYCLE_MIN_US;
        ns = (uint64_t)us * 1000ull;
    }
    /* clamp 8 ms .. 512 ms */
    return ns;
}
```

`protocol_params.cycle_us` 는 Connect 가 RR 을 안 줄 때의 **fallback**
이다. 코어 `cycle_ms` 는 어댑터 poll 주기일 뿐, 이 격자(grid)가 아니다.

### 12.2 절대 격자

예전 구현은 “지금 보내고, 8 ms 잔다”여서 송신 자체가 늦으면 다음
주기도 밀렸다. 지금은 `CLOCK_MONOTONIC` 절대 시각 `next_rt_ns` 에
맞춘다. 늦은 사이클은 **한꺼번에 보내지 않고 건너뛴다.**

```105:118:stacks/profinet/src/pn_rt.c
static void pn_rt_advance_next(pn_stack_t *s, uint64_t now, uint64_t period)
{
    if (s->next_rt_ns == 0) {
        s->next_rt_ns = now + period;
        return;
    }
    s->next_rt_ns += period;
    /* Missed cycles are skipped, not burst, so the absolute grid is kept. */
    while (s->next_rt_ns <= now) {
        s->next_rt_ns += period;
    }
}
```

실제 NIC 에서는 전용 스레드 `pn-rtc1` 가 기한을 지킨다. 기한 직전
최대 1 ms 스핀, sleep 은 1 ms 조각이라 `pn_stack_stop()` 이 512 ms
주기에 묶이지 않는다. mock 이더넷(단위 테스트)은 스레드 없이
`pn_stack_poll()` → `pn_rt_send_if_due()` 다.

### 12.3 입력 프레임 모양

장치가 컨트롤러로 보내는 주기 프레임(입력 CR):

```
Ethernet | FrameID(장치가 고른 in_frame_id)
         | C_SDU (입력 바이트 + IOPS 0x80)
         | CycleCounter (송신 후에만 +1)
         | DataStatus (Primary | Valid | Run)
         | TransferStatus 0
```

```205:248:stacks/profinet/src/pn_rt.c
static int pn_rt_build_frame(pn_stack_t *s, uint8_t *frame, size_t cap,
                             size_t *out_len)
{
    /* FrameID, C_SDU, CycleCounter, DataStatus, TransferStatus */
}
static void pn_rt_emit(pn_stack_t *s, const uint8_t *frame, size_t flen)
{
    /* send, then cycle_counter++ */
}
```

컨트롤러가 장치로 보내는 출력 CR 은 `pn_rt_on_frame()` 이
`out_frame_id` 로 걸러 `output_image` 에 복사한다.

### 12.4 워치독

출력 CR 이 일정 시간(주기 × WatchdogFactor, 기본 3) 안 오면 AR 을
내린다. 케이블을 뽑은 것과 같다.

```305:322:stacks/profinet/src/pn_rt.c
void pn_rt_watchdog(pn_stack_t *s)
{
    /* ... */
    if (pn_now_ns() - last_cpm <= wd) {
        return;
    }
    LOG_WARN("pn_rt", "output CR watchdog expired — AR down");
    pn_ar_reset(s);
}
```

### 12.5 IOPS

`0x80` 은 “이 객체 데이터가 좋다”. 장치가 입력을 채울 때 데이터 뒤에
이 바이트를 붙인다. 컨트롤러는 이 비트가 없으면 값을 쓰지 않는 것이
정상이다.

### 12.6 지터에 대한 혼동

문서 어딘가의 **0.1 ms** 는 코어 스케줄러 에이징 테스트이지, RTC1
송신 격자가 아니다. RTC1 은 위 절대 격자로 맞춰 이 VM 에서 8 ms 평균
8000 µs, late_max 수 µs 대다. 수신 쪽 테스트 프로그램의 `select()`
간격은 장치 주기보다 지저분할 수 있다. 장치 주기를 보려면 TX 로그
`pn_rt TX grid mean=...` 를 본다.

---

## 13. 프로세스 이미지와 JSON 포인트

스택 안에는 두 개의 바이트 배열이 있다.

- `input_image` — 장치가 채우고, RTC1 이 컨트롤러로 실어 나른다
- `output_image` — RTC1 이 컨트롤러 프레임에서 복사하고, 앱이 읽는다

JSON 포인트의 `access` 가 이 배열을 고른다.

```268:301:adapters/profinet/profinet_adapter.c
static int pn_read_point(...)
{
    if (strcmp(pt->access, "write") == 0) {
        return pn_stack_read_output(ctx->stack, (size_t)pt->byte_offset,
                                    out->data, n);
    }
    return pn_stack_read_input(ctx->stack, (size_t)pt->byte_offset, out->data,
                               n);
}

static int pn_write_point(...)
{
    return pn_stack_write_input(ctx->stack, (size_t)pt->byte_offset, value->data,
                                n);
}
```

즉:

- 앱이 바코드 값을 **쓰면** → `write_point` → `input_image` → PLC가 읽음
- 앱이 트리거를 **읽으면** → `read_point` + `access: write` → `output_image`
  (PLC가 써 둔 값)

`address.profinet.byte_offset` 은 그 배열 안의 오프셋이다. 슬롯/서브슬롯
숫자는 GSDML·Connect ExpectedSubmodule 과 맞추기 위한 메타데이터이고,
코어는 해석하지 않는다.

이미지 접근은 `io_lock` 으로 RTC1 스레드와 poll 스레드가 같은 바이트를
찢지 않게 한다.

---

## 14. 레코드 — 명찰과 포트 정보

주기 데이터와 별개로, PLC는 “너는 누구냐 / 포트가 어떻게 생겼냐”를
레코드 인덱스로 읽는다. `pn_record.c` 가 Read/Write 를 처리한다.

자주 나오는 인덱스:

| 인덱스 | 이름 | 의미 |
|--------|------|------|
| `0xAFF0` | I&M0 | 주문 번호, 하드웨어/소프트웨어 리비전 (읽기) |
| `0xAFF1`–`AFF4` | I&M1–4 | 기능 태그, 위치, 날짜, 설명, 서명 (쓰기 가능) |
| `0x800A` | ChannelDiagnosis | 채널 진단 |
| `0x802A` | PDPortDataReal | 포트 실제 상태, 이웃 |
| `0x8080` | PDInterfaceDataReal | 인터페이스, 스테이션 이름 |
| `0xF000` | RealIdentification | 실제 모듈/서브모듈 Ident |

슬롯 0 은 DAP + 인터페이스 서브슬롯 `0x8000`(32768) + 포트 `0x8001`
(32769) 이다. 슬롯 1 이 32/8 바이트 IO 모듈이다. Connect 의
ExpectedSubmodule 이 이와 다르면 ModuleDiff 가 나갈 수 있다. 랩
테스트는 맞춰서 ModuleDiff 가 없기를 기대한다.

I&M0 의 OrderID 는 GSDML `OrderNumber` (`FB-ARCH-PN-DEV`) 와 같아야
CODESYS 카탈로그가 장치를 알아본다.

---

## 15. 알람과 진단

고장이 나면 주기 데이터만으로는 부족하다. AlarmCR 이 Connect 때 열리고,
장치는 RTA(Real-Time Acyclic) 프레임으로 “나타났다 / 사라졌다 /
프로세스 알람”을 보낸다.

유휴 AR 에는 진단이 없다. 테스트나 앱이 `pn_stack_diag_appear()` 를
부를 때만 appear RTA 가 나간다. 프리테스트는 `PN_INJECT_DIAG=1` 로
DATAEX 직후 한 장을 넣는다.

컨트롤러는 RTA Data 에 ACK 를 보낸다. ACK 가 없으면 타임아웃 후
재전송한다 (`alarm_timeout_ns`, `alarm_max_retry`).

진단 레코드 `0x800A` / `0x8010` / `0x8011` 은 그 상태를 나중에
읽어 가는 창구다.

---

## 16. LLDP — 이웃 소개

스위치와 PLC는 누가 어느 포트에 꽂혔는지 알아야 한다. LLDP
(EtherType `0x88CC`) 로 자기 MAC, 포트 이름 `port-001`, 시스템 이름,
TTL 20초, PROFINET OUI TLV 를 보낸다.

기동 시 한 장, 이후 5초마다 (`pn_stack_poll()`). 남이 보낸 LLDP 는
`pn_lldp_on_frame()` 이 파싱해 `lldp_rem_name` 등에 넣는다. SNMP
LLDP-MIB 와 PDPortDataReal 의 peer chassis 가 이 캐시를 읽는다.

CC-B 토폴로지가 “SNMP만”이 아니라 **LLDP + SNMP + PDEV** 인 이유다.

---

## 17. SNMP — 토폴로지용 읽기

UDP 161, 커뮤니티 `"public"`, SNMPv1 스타일이다. 엔지니어링 툴이
장치 트리와 카운터를 그릴 때 Get 한다.

이 스택이 열어 둔 것(일부):

- MIB-II system, interfaces, at, ip, icmp, tcp, udp, snmp
- ifXTable
- LLDP-MIB loc/rem/stats
- LLDP-EXT-PNO delay

Get / GetNext / GetBulk 는 된다. **Set 은 항상 거절**한다
(`readOnly` = 4). sysLocation 을 바꿔도 값이 바뀌지 않는다.

```607:613:stacks/profinet/src/pn_snmp.c
static int leaf_writable(int id)
{
    /* RFC 1213 lists sysContact/sysName/sysLocation as writable.
     * PI SC1 keeps SNMP read-only (Get still served for CC-B topology). */
    (void)id;
    return 0;
}
```

커뮤니티가 `public` 이 아니면 패킷을 버린다 (`-EPERM`). SNMPv3 는 없다.

---

## 18. Security Class 1 서브셋과 HMAC

두 개가 이름만 비슷하고 **다른 기능**이다.

### 18.1 랩 SC1 서브셋 (기본으로 켜짐)

PI Security Class 1 의 공개 설명은 “암호로 페이로드를 잠그지 않고,
관리 평면을 단단히”에 가깝다.

이 스택이 구현한 것:

| 항목 | 동작 |
|------|------|
| DCP Set Name/IP | AR 가 있으면 거절, AR 가 끝나면 다시 쓰기 가능 |
| DCP Identify/Get | 항상 응답 |
| SNMP | Get 계열만. Set 은 readOnly |
| GSDX 서명 | **안 함.** 제조사 PKI / 툴 검증. GSDML 2.35 XML 만 제공 |

이건 PI 인증 SC1 이 아니고, GSDML 2.4x 의
`DCP_FeaturesSupported=RejectDCPSet` 도 넣지 않았다. CODESYS Device
Repository 가 2.35 를 열게 하기 위해서다. 런타임은 그래도 AR 중
쓰기를 막는다.

### 18.2 `security_class: 1` HMAC (별도 랩 옵션)

설정이 1 이면 DCP Set 에 option `0xF0` / HMAC-SHA256 32바이트가 있어야
하고, Connect 에 블록 `0x0E01` 이 있어야 한다. TIA/CODESYS 는 이
블록을 보내지 않는다. 실험용 점대점 프로파일이다. **PI SC1 이 아니다.**

기본 설정은 `security_class: 0` 이다. HMAC 없이 DCP Set(AR 없을 때)과
Connect 를 받는다.

---

## 19. GSDML — 장치에 붙는 설명서

GSDML 은 펌웨어가 아니다. 엔지니어링 툴이 “이 장치는 슬롯이 어떻게
생겼고, 최소 주기가 얼마고, SNMP 를 말하는가”를 읽는 XML 이다.

이 저장소 파일:

`stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`

CODESYS: **Tools → Device Repository → Install**. TIA 도 GSD 설치
대화상자에 같은 XML 을 넣는다.

중요한 속성:

| 속성 | 값 | 뜻 |
|------|-----|-----|
| VendorID / DeviceID | `0xABCD` / `0x0001` | 랩용. PI 할당 아님 |
| MinDeviceInterval | 256 | 256 × 31.25 µs = 8 ms |
| SupportedRT_Classes | RT_CLASS_1 | IRT 선언 없음 |
| IsochroneModeSupported | false | CC-C 아님 |
| ReductionRatio | 8 16 … 512 | 8–512 ms |
| SupportedProtocols | SNMP;LLDP | CC-B 토폴로지 |
| NumberOfAR | 1 | 컨트롤러 하나 |
| 슬롯 1 DataItem | 32 / 8 바이트 | 프로세스 이미지 |

`RT_CLASS_3` 문자열과 `MediaRedundancy` 는 파일에 없다. 풀테스트가
그 부재를 검사한다.

VendorID `0xABCD` 로 필드에 제품을 팔 수 없다. PI 에 제조사 ID 를
받아야 한다. 이 값은 랩에서 충돌을 피하려고 고른 자리 표시다.

---

## 20. 코어는 프로토콜을 모른다

설계 규칙: `core/*.c` 에 `if (protocol == profinet)` 을 넣지 않는다.
레지스트리에 생성자 한 줄만 있다.

```25:31:core/adapter_registry.c
static const registry_entry_t k_registry[] = {
    {"modbus_tcp", modbus_adapter_create},
    {"slmp", slmp_adapter_create},
    {"cclink", cclink_adapter_create},         /* 현재 스텁(NotImplemented) */
    {"ethernetip", ethernetip_adapter_create}, /* 구매 스택 래핑 */
    {"profinet", profinet_adapter_create},     /* 자체 Device 스택, RT Class 1 / 랩 CC-B */
};
```

공통 인터페이스는 `include/protocol_adapter.h` 다. init / connect /
poll_cycle / read_point / write_point / health / destroy.

어댑터 `init` 이 `protocol_params` JSON 을 **직접** cJSON 으로 파싱한다.
코어는 문자열을 통째로 넘길 뿐이다.

`poll_cycle` 은 `pn_stack_poll()` 한 줄이다. 여기서 DCP/RPC/SNMP 를
처리하고, RTC1 전용 스레드가 없을 때(테스트 mock)만 주기 송신을 돕는다.

---

## 21. 설정 파일

예: `config/example.profinet.json`.

| 필드 | 누가 읽나 | 뜻 |
|------|-----------|-----|
| `protocol` | 코어 | `"profinet"` 이면 이 어댑터 |
| `cycle_ms` | 코어 스케줄러 | poll_cycle 주기. RTC1 격자 아님 |
| `protocol_params.iface` | 어댑터 | `eth0` 또는 테스트용 `mock` |
| `device_name` | 어댑터 | NameOfStation |
| `vendor_id` / `device_id` | 어댑터 | DCP DeviceID. 43981 = 0xABCD |
| `ip` / `netmask` / `gateway` | 어댑터 | 초기 IPv4. DCP Set 이 AR 없을 때 덮어씀 |
| `apply_os_ip` | 어댑터 | true 면 커널 주소에도 적용 (권한 필요) |
| `input_len` / `output_len` | 어댑터 | 프로세스 이미지 크기 |
| `cycle_us` | 어댑터 | Connect 가 RR 생략 시 RTC1 fallback |
| `security_class` | 어댑터 | 0 = HMAC 없음(기본), 1 = HMAC 필수 |
| `points[].access` | 어댑터 | `read` = 입력 이미지, `write` = 출력 이미지 |
| `points[].address.profinet.byte_offset` | 어댑터 | 이미지 오프셋 |

실행:

```
sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/multiproto_daemon
./build/multiproto_daemon config/example.profinet.json
```

`apply_os_ip: true` 면 `CAP_NET_ADMIN` 도 필요하다.

---

## 22. 테스트로 확인하는 법

```
cmake --build build --target test_pn_stack pn_device_run pn_pi_pretest pn_codesys_beta
./build/test_pn_stack
bash tests/run_pn_fulltest.sh
bash tests/run_pn_codesys_beta.sh
```

| 명령 | 무엇을 보나 | 무엇이 아닌가 |
|------|-------------|---------------|
| `test_pn_stack` | mock 이더넷. DCP/CM/RTC1/SNMP/IRT 거부/SC1 | 실제 NIC |
| `run_pn_fulltest.sh` | veth 위 랩 프리테스트 + GSDML well-formed | PI ART/PITL |
| `run_pn_codesys_beta.sh` | CODESYS 와 같은 CM 순서, 8 ms 지터 | CODESYS 바이너리 |

프리테스트가 확인하는 SC1 동작 예:

- Connect **전** Set Name → 성공 (`LAB-DCP-SET-NAME`)
- Connect **후** Set Name → BlockError 0x05, 이름 유지 (`LAB-DCP-SET-AR-LOCK`)
- Identify 는 AR 중에도 원래 이름 (`LAB-DCP-IDENT-AR`)
- SNMP Set sysLocation → 값이 안 바뀜 (`LAB-SNMP-SET-SYSLOC`)

IRT Connect 는 `LAB-CM-NO-IRT` 로 **거절되는 것**을 통과로 친다.
구현이 없어서가 아니라, CC-C 를 열지 않기로 했기 때문이다.

---

## 23. 이 스택이 하지 않는 것

| 하지 않음 | 이유 |
|-----------|------|
| Controller / 스캐너 | 이 프로세스는 Device |
| RT Class 3 / IRT / PTCP / SPIRTA | 타깃에 IRT ASIC 없음. Connect 거부 |
| MRP 링 | CC-B 옵션. `0x88E3` 무시 |
| AR 2개 이상 | GSDML `NumberOfAR=1` |
| Fast Start-Up CM | GSDML 에 클레임하지 않음 |
| SNMPv3 | SC1 서브셋은 v1 Get + Set 차단 |
| GSDX 서명 / PI PKI | 제조사 인증서 프로세스 |
| PI 인증 / ART / ETS | 회원·Windows 시험소 |
| VendorID 공식 할당 | `0xABCD` 는 랩 자리 표시 |
| 공유 디바이스, 시스템 리던던시 | 범위 밖 |

“SNMP 가 되니 CC-C 다”, “알람이 되니 IRT 다” 같은 말은 이 코드와
맞지 않는다. 클래스는 누적이고, IRT 는 C 전용이다.

---

## 24. 소스 파일 지도

| 파일 | 한 줄 |
|------|--------|
| `include/pn_stack.h` | 공개 API, 범위 주석 |
| `include/pn_types.h` | FrameID, 블록 타입, 인덱스, CM 상태 |
| `include/pn_internal.h` | `pn_stack` / `pn_ar_t` 내부 상태 |
| `include/pn_endian.h` | 빅엔디안 읽기/쓰기 |
| `src/pn_stack.c` | create/start/poll, 이더넷 분기, 이미지 API |
| `src/pn_eth.c` | AF_PACKET, 프레임 조립, OS IP, 시계 |
| `src/pn_dcp.c` | Identify/Get/Set/Hello, AR 중 쓰기 보호 |
| `src/pn_rpc.c` | Connect/Write/Read/PrmEnd/AppReady/Release |
| `src/pn_rt.c` | RTC1 격자, 전용 스레드, 워치독 |
| `src/pn_record.c` | I&M, RealIdent, PDEV, 진단 레코드 |
| `src/pn_alarm.c` | AlarmCR, RTA Data/ACK |
| `src/pn_lldp.c` | LLDP 송신/이웃 파싱 |
| `src/pn_snmp.c` | SNMPv1 Get 계열, Set 거부 |
| `src/pn_sec.c` / `pn_crypto.c` | 랩 HMAC-SHA256 (PI SC1 아님) |
| `gsdml/*.xml` | 툴이 읽는 장치 설명 |
| `adapters/profinet/*.c` | JSON → `pn_cfg_t`, 포인트 ↔ 이미지 |

상태를 따라가려면 `struct pn_stack` (`pn_internal.h`) 부터 보면 된다.
AR, 이미지, 소켓 fd, RTC 시각, LLDP 캐시, SNMP 카운터, 알람 시퀀스가
한 구조체에 있다.

---

## 25. 자주 나오는 오해

**Q. `cycle_ms: 8` 을 16 으로 바꾸면 RTC1 이 16 ms 가 되나?**  
A. 아니다. 그건 코어가 `poll_cycle` 을 부르는 주기. RTC1 은 Connect 의
ReductionRatio. GSDML/툴에서 RR 16 을 고르면 16 ms 가 된다.

**Q. `security_class: 1` 이 PI Security Class 1 인가?**  
A. 아니다. HMAC 랩 옵션이다. PI SC1 서브셋(DCP/SNMP 하드닝)은
`security_class` 와 무관하게 항상 켜져 있다.

**Q. SNMP Set 이 실패하면 CC-B 가 깨지나?**  
A. CC-B 토폴로지에 필요한 것은 Get(과 LLDP). SC1 은 Set 을 기본
잠근다. 이 스택은 Get 을 유지하고 Set 만 거절한다.

**Q. AR 중에 장치 이름을 바꿀 수 있나?**  
A. 이 스택은 거절한다. 이름을 바꾸려면 Release 로 AR 를 내린 뒤 DCP
Set 하거나, 처음부터 Nominate 를 Connect 전에 한다.

**Q. 이 코드로 PI 인증을 받나?**  
A. 받지 않는다. 랩 프리테스트는 공개 테스트 번들 Readme 의 그룹을
재현한 것이다. 공식 ART/ETS 는 회원·Windows 도구다.

**Q. VendorID 0xABCD 로 제품을 등록하나?**  
A. 안 된다. PI 가 제조사에 할당한 ID 가 필요하다.

**Q. input_len 을 JSON 에서만 키우면 되나?**  
A. 주기 데이터 길이는 Connect ExpectedSubmodule / IOCR 과 GSDML
DataItem Length 가 맞아야 PLC가 기대한 크기로 붙는다. JSON 만 키우면
이미지는 커져도 컨트롤러 매핑이 깨진다.

**Q. 왜 단위 테스트는 이더넷이 없나?**  
A. `pn_stack_set_eth_ops()` 가 send/recv 를 메모리로 바꾼다. CI 와
개발 PC 에서 cap_net_raw 없이 CM/DCP/RTC 상태머신을 돌리기 위해서다.
와이어 검증은 veth 풀테스트가 맡는다.

---

## 26. 더 읽을 문서

| 문서 | 내용 |
|------|------|
| [`docs/profinet_stack.md`](../../docs/profinet_stack.md) | 랩 범위 표, CC-A/B/C 구분, 인증이 아닌 것 |
| [`docs/codesys_beta.md`](../../docs/codesys_beta.md) | CODESYS 2시간 데모, Device Repository |
| [`docs/design.md`](../../docs/design.md) | 멀티프로토콜 데몬 전체 설계. PROFINET 은 이후 자체 스택으로 구현됨 |
| [`include/pn_stack.h`](include/pn_stack.h) | 구현 범위가 주석으로 적힌 공개 헤더 |
| PI 7.312 (회원) | 공식 Security Class 1 가이드라인 |
| IEC 61158-6-10 | DCP/PNIO PDU 바이너리 (공식 텍스트) |

이 폴더의 코드가 위 공식 문서와 충돌하면 공식 문서가 이긴다. 이
가이드는 그 공식 문서를 이 랩 구현에 투영한 해설이다.
