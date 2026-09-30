# PROFINET IO Device 완전 입문 — Conformance Class B · RT Class 1 · (이 저장소의) Security Class 1

> 이 문서는 산업용 통신을 처음 보는 사람이 **PROFINET IO Device 스택을 직접 만들 수 있고**,
> 동시에 이 저장소의 자체 스택(`stacks/profinet/`)을 **이해·유지보수**할 수 있도록 쓴 기술 입문서다.
>
> - 범위: IO **Device**(IO 장치) 쪽, Conformance Class **B**, **RT Class 1**, 이 저장소가 "Security Class 1"
>   이라고 부르는 HMAC 프로파일. **IRT / RT Class 3 / Conformance Class C 는 영구 비목표**다
>   ([CLAUDE.md](../../CLAUDE.md), [docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 4장).
> - 기준 코드: 이 문서를 쓴 시점의 `stacks/profinet/`, `adapters/profinet/`. 인용은 `경로:줄` 형식이다.
> - 이 문서는 **PI 인증 문서가 아니다.** 사양 원문(IEC 61158-5-10 / 61158-6-10 등)은 유료이고 이 저장소에
>   없다. 사양 세부값 중 원문 대조가 필요한 곳은 **[사양 확인 필요]** 로 표시했다.

---

## 목차

- [0. 이 문서 읽는 법 + 선행 지식](#0-이-문서-읽는-법--선행-지식)
- [1. 왜 이 프로토콜이 존재하나](#1-왜-이-프로토콜이-존재하나)
- [2. 용어 사전](#2-용어-사전)
- [3. 전체 그림](#3-전체-그림)
- [4. 데이터 모델](#4-데이터-모델)
- [5. 프레임 포맷](#5-프레임-포맷)
- [6. 동작과 상태](#6-동작과-상태)
- [7. SNMP / I&M / 진단](#7-snmp--im--진단)
- [8. Security Class 1](#8-security-class-1)
- [9. 에러 처리와 제한값](#9-에러-처리와-제한값)
- [10. 직접 구현하기](#10-직접-구현하기)
- [11. 이 저장소의 구현 지도](#11-이-저장소의-구현-지도)
- [12. 테스트와 디버깅](#12-테스트와-디버깅)
- [13. 흔한 함정과 보안 고려사항](#13-흔한-함정과-보안-고려사항)
- [14. 인증/적합성](#14-인증적합성)
- [15. 참고 사양 문헌](#15-참고-사양-문헌)
- [부록 A. 구현 체크리스트](#부록-a-구현-체크리스트)
- [부록 B. hex 예제 모음](#부록-b-hex-예제-모음)
- [부록 C. 블록 타입 표](#부록-c-블록-타입-표)
- [부록 D. PNIO 에러 코드 표](#부록-d-pnio-에러-코드-표)
- [부록 E. 이 문서의 검증 기록](#부록-e-이-문서의-검증-기록)

---

## 0. 이 문서 읽는 법 + 선행 지식

### 0.1 세 가지 읽기 경로

| 당신이… | 읽을 곳 |
|---------|---------|
| PROFINET 이 뭔지 감만 잡고 싶다 | 0장 → 1장 → 3장 → 6.1 |
| 스택을 **처음부터** 구현하려 한다 | 0~6장 전부 → 9장 → 10장 → 부록 A |
| **이 저장소**를 고치거나 리뷰한다 | 3.4 → 11장(특히 11.5 사양-저장소 차이) → 12장 → 5장의 "이 저장소" 단락 |

### 0.2 이 문서의 표기

| 표기 | 의미 |
|------|------|
| `0x8892` | 16진수(hex). `0x` 뒤 두 글자가 1바이트 |
| `fe fd` | hex dump 안의 바이트 나열. 왼쪽이 먼저 전송되는 바이트 |
| BE / LE | Big-Endian / Little-Endian (0.3 참고) |
| **[검증: 하네스]** | 이 저장소 스택에 실제 바이트를 넣어 돌려본 출력 (부록 E) |
| **[검증: golden]** | `tests/golden/profinet/*.pcap` 에 커밋된 실제 바이트 |
| **[검증: scapy]** | 독립 구현(scapy `contrib/pnio*`)으로 생성하거나 역파싱해 필드 배치를 교차 확인 |
| **[사양 확인 필요]** | 필자가 IEC 원문으로 확인하지 못한 세부값. 구현 전에 원문 대조 필수 |
| **[차이]** | 이 저장소 코드가 사양(또는 실제 컨트롤러 동작)과 다른 지점. 수정 제안이 아니라 **기록** |

### 0.3 비트, 바이트, hex, 엔디안

- 1바이트 = 8비트 = hex 두 글자(`00`~`ff`). 비트 번호는 **최하위 비트가 bit 0** (값 `0x01`).
- 2바이트 이상의 정수를 바이트로 풀어 쓰는 순서를 **엔디안(endianness)** 이라 한다.
  - **Big-Endian (BE, 네트워크 바이트 순서)**: 큰 자리부터. `0x8892` → `88 92`.
  - **Little-Endian (LE)**: 작은 자리부터. `0x8892` → `92 88`. x86/ARM CPU 메모리가 보통 이 방식.
- PROFINET 은 **거의 모든 필드가 BE** 다. 예외는 **DCE/RPC 헤더와 NDR 헤더** — 이들은 요청 패킷의
  `drep`(Data Representation) 바이트가 정하는 엔디안을 따르며, 실무에서는 대부분 LE 다(5.d).
  이것이 PROFINET 파서를 처음 짤 때 가장 흔한 실수다.

이 저장소는 엔디안 변환을 한 헤더에 모았다: `pn_rd_be16/32`, `pn_wr_be16/32`, `pn_rd_le16/32`,
`pn_wr_le16/32`, 그리고 상수 시간 비교 `pn_ct_eq` ([pn_endian.h:7-64](../../stacks/profinet/include/pn_endian.h)).

### 0.4 이더넷 프레임 — "봉투"

이더넷(Ethernet)은 같은 스위치/케이블에 붙은 장치끼리 주고받는 **2계층(L2, 데이터링크)** 프로토콜이다.
택배로 비유하면 **이더넷 프레임은 봉투**, 안의 내용물이 상위 프로토콜이다.

```
 0                6               12      14                          끝-4    끝
 +----------------+----------------+-------+---------------------------+--------+
 | 목적지 MAC (6) | 출발지 MAC (6) | EType | 페이로드 (46 ~ 1500 바이트) | FCS(4) |
 +----------------+----------------+-------+---------------------------+--------+
```

| 필드 | 크기 | 의미 |
|------|------|------|
| Destination MAC | 6 | 받을 장치의 하드웨어 주소 |
| Source MAC | 6 | 보낸 장치의 하드웨어 주소 |
| EtherType | 2 (BE) | 페이로드가 무슨 프로토콜인지. `0x0800`=IPv4, `0x0806`=ARP, `0x8100`=VLAN 태그, **`0x8892`=PROFINET**, `0x88CC`=LLDP |
| Payload | 46~1500 | 내용물. 46바이트보다 짧으면 0으로 **패딩(padding)** 해서 맞춘다 |
| FCS | 4 | CRC32 체크섬. 보통 NIC(랜카드) 하드웨어가 붙이고 떼므로 소프트웨어는 보지 않는다 |

- 최소 프레임: FCS 포함 64바이트 = FCS 제외 **60바이트**. 최대: FCS 제외 1514 (VLAN 태그 포함 시 1518).
  이 저장소는 버퍼 한계를 `PN_FRAME_MAX 1518` 로 둔다 ([pn_types.h:82](../../stacks/profinet/include/pn_types.h)).
- 소프트웨어가 60바이트보다 짧은 프레임을 보내면 대개 NIC 드라이버가 패딩을 붙인다. 그러나 **veth
  같은 가상 인터페이스는 패딩하지 않는다.** 이 저장소의 golden 파일에 34바이트짜리 DCP 응답이 있는
  이유다(5.b). 실 NIC 에서는 60바이트로 늘어난다.

### 0.5 MAC 주소

- 48비트. `02:fb:00:00:00:01` 처럼 쓴다.
- 첫 바이트의 **bit 0 = 1** 이면 **멀티캐스트**(여러 장치가 동시에 받는 주소), 0 이면 유니캐스트.
- 첫 바이트의 **bit 1 = 1** 이면 **로컬 관리(locally administered)** 주소 — 제조사가 할당한 게 아니라
  사람이 임의로 정한 주소. 이 저장소 기본값 `02:FB:00:00:00:01` 이 이것이다
  ([pn_stack.c:66-75](../../stacks/profinet/src/pn_stack.c)).
- PROFINET 이 쓰는 주요 멀티캐스트 주소:

| 주소 | 용도 | 근거 |
|------|------|------|
| `01:0E:CF:00:00:00` | DCP Identify 요청 | 이 저장소 `k_dcp_mc` ([pn_dcp.c:10](../../stacks/profinet/src/pn_dcp.c)) |
| `01:0E:CF:00:00:01` | DCP Hello | [사양 확인 필요] — 널리 쓰이는 값. **[차이]** 이 저장소는 Hello 도 `…:00` 으로 보냄 (11.5) |
| `01:80:C2:00:00:0E` | LLDP (IEEE 802.1AB, 브리지를 넘지 않는 주소) | [pn_lldp.c:24](../../stacks/profinet/src/pn_lldp.c) |

`01:0E:CF` 는 PNO(PROFIBUS Nutzerorganisation)의 OUI(조직 식별자) `00:0E:CF` 에 멀티캐스트 비트를 켠 것이다.

### 0.6 VLAN 태그(IEEE 802.1Q)와 우선순위(PCP)

스위치는 기본적으로 도착 순서대로 프레임을 내보낸다. 사무실 트래픽(대용량 파일 복사)과 공장 제어
트래픽이 한 스위치를 쓰면, 제어 프레임이 줄 서서 기다리다 늦을 수 있다. 그래서 프레임에
**"급행" 스티커**를 붙이는데, 그게 VLAN 태그의 **PCP(Priority Code Point)** 다.

```
 ... | Src MAC (6) | 0x8100 (TPID) | TCI (2) | 원래 EtherType (2) | payload ...
                                  |
                   TCI = PCP(3비트) | DEI(1비트) | VID(12비트)
```

- `TCI = 0xC000` → PCP=6, DEI=0, VID=0. VID=0 은 "VLAN 은 안 쓰고 우선순위만 쓴다"는 뜻(priority tag).
- PROFINET RT 프레임은 보통 **PCP 6** 을 쓴다. 컨트롤러는 Connect 요청의 `IOCRTagHeader`(보통
  `0xC000`)로 이 값을 알려준다(5.d). Alarm CR 도 `AlarmCRTagHeaderHigh/Low` 로 알려준다(예: `0xC000`/`0xA000`
  → PCP 6/5). [사양 확인 필요: RT_CLASS_1 에서 태그가 필수인지, 장치가 태그 없이 보내도 되는지]
- **이 저장소**: 수신 시 VLAN 태그를 벗겨낸다 ([pn_eth.c:62-68](../../stacks/profinet/src/pn_eth.c)).
  송신은 항상 **태그 없이** 보낸다 ([pn_eth.c:37-49](../../stacks/profinet/src/pn_eth.c)). `IOCRTagHeader` 는
  파싱하지 않는다. **[차이]**

### 0.7 PROFINET 은 IP 를 건너뛴다 — EtherType `0x8892`

웹 브라우저의 데이터는 `이더넷 → IP → TCP → HTTP` 처럼 여러 겹의 봉투에 담긴다. 겹마다 헤더를 붙이고
해석하는 비용이 들고, OS 네트워크 스택을 통과하면서 지연이 흔들린다(jitter).

PROFINET 의 **실시간(RT) 데이터와 DCP** 는 이더넷 봉투에 **바로** 담긴다. EtherType `0x8892` 가
"안에 PROFINET 이 들어 있음"을 표시하고, 페이로드 첫 2바이트 **Frame ID** 가 무슨 종류의 PROFINET
프레임인지 알려준다(5.a). IP 주소도, 포트도, TCP 재전송도 없다. 빠르고 단순한 대신 **같은 L2
네트워크(라우터를 넘지 않는 범위)** 에서만 동작한다.

반면 **연결 설정(Connect)·파라미터 쓰기·읽기** 같은 "느려도 되는" 일은 **UDP/IP 위의 DCE/RPC** 로 한다.
그래서 PROFINET IO Device 는 **두 개의 문**을 열어 둔다: raw 이더넷(0x8892)과 UDP 34964.

### 0.8 raw socket / AF_PACKET / CAP_NET_RAW

일반 프로그램은 `socket(AF_INET, SOCK_DGRAM, 0)` 으로 UDP 를 쓴다 — OS 가 IP/UDP 헤더를 알아서 붙인다.
EtherType `0x8892` 프레임을 직접 만들려면 Linux 의 **`AF_PACKET` raw 소켓**을 써야 한다:

```c
int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));   /* 모든 EtherType 수신 */
/* SIOCGIFINDEX 로 인터페이스 번호를 얻고 bind(sockaddr_ll{ifindex}) */
/* send: 14바이트 이더넷 헤더부터 직접 쓴 버퍼를 sendto()               */
```

- 이 권한은 root 이거나 **`CAP_NET_RAW`** capability 가 있어야 한다. 이 저장소는 실패 시
  `"AF_PACKET socket 실패: ... (CAP_NET_RAW 필요)"` 를 로그로 남긴다 ([pn_eth.c:85-90](../../stacks/profinet/src/pn_eth.c)).
- SNMP 가 쓰는 UDP 161 은 1024 미만 포트라 **`CAP_NET_BIND_SERVICE`** 가 필요하다. 문서화된 실행법:
  `sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/multiproto_daemon`
  ([docs/profinet_stack.md:41](../profinet_stack.md)).
- 이 저장소는 테스트용으로 raw 소켓 대신 콜백을 끼울 수 있다(`pn_eth_ops_t`, iface=`"mock"`)
  ([pn_stack.h:47-51](../../stacks/profinet/include/pn_stack.h), [pn_eth.c:75-83](../../stacks/profinet/src/pn_eth.c)).
  그래서 CI 에서는 sudo 없이 전체 스택을 돈다.

### 0.9 UDP 와 포트

UDP 는 "편지 한 통 = 데이터그램 한 개"인 비연결형 프로토콜이다. 순서·도착 보장이 없어 PROFINET 은
그 위에 DCE/RPC 의 시퀀스 번호·재시도 규칙을 얹는다. 쓰는 포트:

| 포트 | 용도 |
|------|------|
| UDP **34964** (`0x8894`) | PNIO CM(Context Management) RPC 서버 + RPC Endpoint Mapper. 이 저장소 `PN_RPC_PORT` ([pn_types.h:46](../../stacks/profinet/include/pn_types.h)) |
| UDP **161** | SNMP 에이전트 ([pn_types.h:47](../../stacks/profinet/include/pn_types.h)) |
| UDP 34962 / 34963 (`0x8892`/`0x8893`) | RT_CLASS_UDP (IP 로 라우팅되는 RT) — CC-B RT1 Device 범위 밖 [사양 확인 필요] |

### 0.10 DCE/RPC 개념 — "원격 함수 호출 봉투"

RPC(Remote Procedure Call)는 "다른 컴퓨터의 함수를 부르는" 추상화다. **DCE/RPC** 는 1990년대 OSF 가
표준화한 RPC 방식으로, Windows(MSRPC)에서도 쓰인다. PROFINET CM 은 그중 **connectionless(CL, UDP 기반)**
변형을 쓴다. 핵심 개념:

| 개념 | 비유 | PROFINET 에서 |
|------|------|---------------|
| **Interface UUID** | 어느 "API 묶음"을 부르나 | PNIO Device 인터페이스 `DEA00001-6C97-11D1-8271-00A02442DF7D` |
| **Object UUID** | 어느 "객체(장치 인스턴스)"에게 | `DEA00000-6C97-11D1-8271-<Instance><DeviceID><VendorID>` |
| **opnum** | 함수 번호 | 0 Connect, 1 Release, 2 Read, 3 Write, 4 Control, 5 ReadImplicit |
| **Activity UUID + sequence** | 대화 식별 + 몇 번째 호출인가 | 재전송 판별용 |
| **NDR** (Network Data Representation) | 인자 직렬화 규칙 | PNIO 는 "바이트 배열 하나"만 넘기므로 5×uint32 헤더 + 블록들 |
| **drep** | 인자 엔디안 표시 | 첫 바이트 상위 니블 `1`=LE, `0`=BE |

UUID(16바이트)는 문자열로 `DEA00001-6C97-11D1-8271-00A02442DF7D` 처럼 쓰지만, **와이어에서는 앞 세 필드
(4+2+2바이트)를 drep 엔디안으로** 쓰고 뒤 8바이트는 그대로 쓴다. LE 이면:

```
DEA00001-6C97-11D1-8271-00A02442DF7D
  → 01 00 a0 de  97 6c  d1 11  82 71 00 a0 24 42 df 7d
```

이 저장소도 이 형태를 상수로 갖고 있다 (`k_pnio_if`, [pn_rpc.c:25-27](../../stacks/profinet/src/pn_rpc.c)) —
다만 **정의만 하고 비교에 쓰지는 않는다**(11.5).

### 0.11 이 문서의 예제 환경

| 항목 | 값 |
|------|----|
| 컨트롤러 MAC | `00:11:22:33:44:55` (CTT mock 과 동일) |
| 디바이스 MAC | `02:fb:00:00:00:01` (스택 기본값) |
| NameOfStation | `sensor-line1` |
| VendorID / DeviceID | `0xABCD` / `0x0001` ([gsdml:21](../../stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml)) |
| IP | `192.168.0.10/24`, GW `192.168.0.1` ([config/example.profinet.json](../../config/example.profinet.json)) |
| IO | 입력 32바이트(Device→Controller), 출력 8바이트(Controller→Device), slot 1 / subslot 1 |
| ARUUID | `a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf` (CTT `fill_connect_aruuid` 와 동일) |

---

## 1. 왜 이 프로토콜이 존재하나

### 1.1 공장 비유

공장 라인을 떠올리자. 컨베이어 위 제품을 **센서**(바코드 리더, 온도계, 근접 스위치)가 읽고, **PLC**
(Programmable Logic Controller, 공장용 제어 컴퓨터)가 그 값을 보고 판단해 **액추에이터**(모터, 밸브,
경광등)를 움직인다. PLC 는 이 일을 **정해진 주기(예: 1ms, 8ms)** 로 끝없이 반복한다 — "입력 읽기 →
프로그램 실행 → 출력 쓰기". 이것을 **스캔 사이클(scan cycle)** 이라 한다.

센서/액추에이터가 PLC 에서 멀리 있으면 선을 한 가닥씩 끌어오는 대신 **통신 선 하나**로 묶는다. 이 공장용
통신망을 **필드버스(fieldbus)** 라고 부른다. 요구 사항은 사무실 네트워크와 다르다:

- **결정성(determinism)**: 평균이 빠른 것보다 "항상 N ms 안에 온다"가 중요하다.
- **감시**: 선이 끊기면 수십 ms 안에 알아채고 출력을 안전 상태로 둬야 한다.
- **기술자 친화**: 장치를 교체해도 이름만 맞추면 다시 동작해야 한다.

### 1.2 PROFIBUS → PROFINET, Siemens 와 PI

- **PROFIBUS**(1989~)는 Siemens 등이 만든 RS-485 기반 필드버스다. 매우 널리 쓰였다.
- **PROFINET**(2003~)은 그 후속으로, **표준 이더넷** 위에 같은 개념(주기 IO, 파라미터, 알람, 진단)을
  얹었다. "PROFIBUS 의 모델을 이더넷으로 옮긴 것"이라 PROFIBUS 용어(slot, index, I&M 등)가 그대로 남아
  있다.
- 사양은 **PI (PROFIBUS & PROFINET International)** 와 각국 지부(독일 PNO 등)가 관리하고, 국제 표준으로는
  **IEC 61158 (Type 10)** 과 **IEC 61784-2 (CPF 3)** 에 들어가 있다(15장).

### 1.3 역할: IO Controller / IO Device / IO Supervisor

| 역할 | 비유 | 하는 일 | 이 저장소 |
|------|------|---------|-----------|
| **IO Controller** | 지휘자 | 보통 PLC. 장치에 연결(AR)을 요청하고, 출력 데이터를 보내고, 입력 데이터를 받는다 | 없음 (CTT 가 테스트용 흉내만) |
| **IO Device** | 연주자 | 센서/액추에이터 쪽. 연결을 **받아들이고**, 입력을 보내고 출력을 받는다 | **이것을 구현** |
| **IO Supervisor** | 조율사 | 엔지니어링 툴/HMI. 이름 지정, 진단 읽기, 시운전 | 없음 (DCP Set 을 받는 쪽으로서만 상호작용) |

이 저장소 스택 헤더 주석: "PROFINET IO Device stack … This is a working Device-side stack, not a PI-certified
product." ([pn_stack.h:9-20](../../stacks/profinet/include/pn_stack.h)).

### 1.4 실시간 등급: NRT / RT / IRT / TSN

| 등급 | 전송 | 전형적 주기 | 필요 하드웨어 | 이 저장소 |
|------|------|-------------|---------------|-----------|
| NRT (Non-Real-Time) | UDP/IP (RPC) | 수십~수백 ms | 없음 | CM RPC 에 사용 |
| **RT_CLASS_1** (RT) | 이더넷 직접 (`0x8892`), 우선순위 태그 | 1~512 ms (보통 1~32ms) | 표준 NIC, 표준 스위치 | **구현** |
| RT_CLASS_UDP | UDP/IP 위 RT | ms 단위 | 없음 | 없음 |
| RT_CLASS_2 | 동기/비동기 혼합(레거시) | — | 전용 | 없음 |
| **RT_CLASS_3 (IRT)** | 시간 동기(PTCP) + 예약 대역 | 31.25µs~ms, 지터 <1µs | **전용 ASIC 스위치** | **영구 비목표** |
| TSN | IEEE 802.1 TSN 위 PROFINET | — | TSN 스위치 | 없음 |

> 주의: RT_CLASS_2 / RT_CLASS_UDP / TSN 의 세부 정의·연혁은 [사양 확인 필요]. 이 문서에서 중요한 것은
> "RT_CLASS_1 = 표준 하드웨어, 동기 없음, ms 급" 이라는 점뿐이다.

### 1.5 Conformance Class (CC) A / B / C / D

Conformance Class 는 "이 장치가 어느 기능 묶음을 반드시 지원하는가"를 뜻한다. 대략적인 구분
([사양 확인 필요] — PI "PROFINET Conformance Classes" 가이드라인 원문 대조):

| CC | 요지 | 핵심 기능 |
|----|------|-----------|
| **CC-A** | 기본 | RT_CLASS_1 주기 IO, 레코드 읽기/쓰기, 알람, DCP, LLDP(이웃 정보), I&M0 |
| **CC-B** | + 네트워크 진단/관리 | CC-A + **SNMP**(MIB-II, LLDP-MIB)로 토폴로지·포트 진단. 선택: 시스템 이중화(CC-B(PA)), MRP 등 |
| **CC-C** | + 동기 | CC-B + **IRT**(RT_CLASS_3), PTCP 시간 동기, 대역 예약, 등시(isochronous) 모드 |
| CC-D | TSN | TSN 기반 |

이 저장소의 주장: "Conformance Class B functions: DCP (Identify/Get/Set/Hello/Signal), cyclic RTC1,
record (I&M0–4), alarm TX (High/Low), LLDP, minimal SNMP" ([pn_stack.h:12-16](../../stacks/profinet/include/pn_stack.h)).
상수로 `PN_CONFORMANCE_CLASS_B 2`, `PN_RT_CLASS_1 1`, `PN_SECURITY_CLASS_1 1` 이 있다
([pn_types.h:87-89](../../stacks/profinet/include/pn_types.h)). 실제로 "CC-B 수준으로 동작하는가"는 11.5 의
차이 목록과 함께 봐야 한다 — 이 저장소 문서도 스스로를 "internal bundle-grade gate ≠ PI 인증"이라 적는다
([docs/ctt_pn_bundle.md:7-10](../ctt_pn_bundle.md)).

### 1.6 왜 이 저장소는 IRT 를 하지 않나

1. **하드웨어**: IRT 는 "모든 스위치 포트가 31.25µs 격자에 맞춰 예약된 시간에만 프레임을 흘리는" 방식이다.
   이것은 컷스루(cut-through) + 시간 동기 스위치 ASIC(예: ERTEC 류)이 있어야 가능하다. 범용 Linux 보드의
   NIC 로는 불가능하다.
2. **시간 동기(PTCP)**: 나노초~마이크로초 단위 클럭 동기가 필요하다.
3. **OS 지터**: 이 저장소는 PREEMPT_RT 없는 Linux 에서 8ms 주기, 최대 편차 0.1ms 를 측정했다
   ([CLAUDE.md](../../CLAUDE.md) "테스트 관련 메모"). RT_CLASS_1 에는 충분하지만 IRT 요구(µs 이하)와는
   자릿수가 다르다.
4. **정책**: 저장소 규칙이 "IRT / CC-C 는 켜지 않는다 (permanent non-goal)" 로 못박고 있다
   ([CLAUDE.md](../../CLAUDE.md) 우선순위 5, [docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 4장).

---

## 2. 용어 사전

| 용어 | 풀이 | 한 줄 설명 | 이 저장소 |
|------|------|-----------|-----------|
| **AR** | Application Relation | 컨트롤러 1대와 디바이스 1대 사이의 "논리적 연결". 전화 통화 한 건. ARUUID 로 식별 | `pn_ar_t` 1개 (단일 AR) ([pn_internal.h:16-36](../../stacks/profinet/include/pn_internal.h)) |
| **ARUUID** | AR 식별 UUID | 컨트롤러가 Connect 때 정함. 이후 Read/Write/Control 이 이 값을 들고 온다 | `ar.uuid` |
| **ARType** | AR 종류 | `0x0001` IOCARSingle(일반), `0x0006` IOSAR(Supervisor) 등 | 응답에 `0x0001` 고정 ([pn_rpc.c:349](../../stacks/profinet/src/pn_rpc.c)) |
| **CR** | Communication Relation | AR 안의 "채널". IO CR(주기 데이터), Alarm CR(알람), Record 는 CR 없이 RPC | — |
| **IOCR** | IO Communication Relation | 한 방향 주기 데이터 흐름 하나. **Input CR**(Device→Controller), **Output CR**(Controller→Device) | `in_frame_id`/`out_frame_id` |
| **Alarm CR** | 알람용 CR | 알람을 확인응답(ACK)과 함께 신뢰성 있게 전달하는 채널 (RTA) | 파싱 안 함, 응답만 |
| **API** | Application Process Identifier | 32비트. 장치 안의 "응용 영역" 번호. 보통 `0` (기본). 프로파일(예: PROFIdrive)마다 다른 API 를 쓰기도 | 무시 |
| **Slot** | 슬롯 | 모듈을 꽂는 자리. slot 0 은 보통 DAP | 무시 |
| **Subslot** | 서브슬롯 | 모듈 안의 서브모듈 자리. `0x8000` 인터페이스, `0x8001..` 포트 | 무시 |
| **Module / Submodule** | 모듈 / 서브모듈 | 실제 IO 를 가진 단위는 서브모듈. ModuleIdentNumber/SubmoduleIdentNumber 로 종류 식별 | GSDML 에만 |
| **DAP** | Device Access Point | slot 0 의 "장치 자체"를 나타내는 모듈. 인터페이스·포트 서브모듈을 품는다 | GSDML `DAP1` |
| **GSDML** | General Station Description Markup Language | 장치의 기능·모듈·타이밍을 기술한 XML. 엔지니어링 툴(TIA Portal, CODESYS)이 읽는다 | [gsdml/](../../stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml) |
| **NameOfStation** | 스테이션 이름 | 사람이 붙이는 DNS 형식 이름(`sensor-line1`). 컨트롤러는 **IP 가 아니라 이 이름으로** 장치를 찾는다 | `cfg.station_name` |
| **DCP** | Discovery and Configuration Protocol | L2 에서 장치 찾기(Identify), 이름/IP 설정(Set), 조회(Get), LED 깜빡임(Signal) | [pn_dcp.c](../../stacks/profinet/src/pn_dcp.c) |
| **LLDP** | Link Layer Discovery Protocol (IEEE 802.1AB) | "내 이웃 포트는 누구"를 알리는 주기 방송. 토폴로지 파악용 | [pn_lldp.c](../../stacks/profinet/src/pn_lldp.c) |
| **CM** | Context Management | Connect/Release/Read/Write/Control 을 처리하는 RPC 계층 | [pn_rpc.c](../../stacks/profinet/src/pn_rpc.c) |
| **Frame ID** | 프레임 식별자 | `0x8892` 페이로드 첫 2바이트(BE). 프레임 종류와 IOCR 을 식별 | [pn_types.h:11-16](../../stacks/profinet/include/pn_types.h) |
| **C_SDU** | Cyclic Service Data Unit | RT 프레임 안의 IO 데이터 + IOPS/IOCS 묶음. 최소 40바이트 | — |
| **APDU Status** | — | RT 프레임 끝 4바이트: CycleCounter(2) + DataStatus(1) + TransferStatus(1) | [pn_rt.c:126-130](../../stacks/profinet/src/pn_rt.c) |
| **Cycle Counter** | 사이클 카운터 | 송신 시각을 31.25µs 단위로 나타내는 16비트 값 [사양 확인 필요: 증분 규칙] | +1 씩 증가 **[차이]** |
| **Data Status** | 데이터 상태 바이트 | Primary/Backup, DataValid, ProviderState(Run/Stop), 문제표시 등 비트 | `0x25` 송신 **[차이]** |
| **Transfer Status** | 전송 상태 | RT_CLASS_1 에서는 0 [사양 확인 필요] | `0` |
| **IOPS** | IO Provider Status | "내가 보낸 이 데이터는 유효하다/아니다" (데이터 뒤 1바이트) | `0x80` 고정 |
| **IOCS** | IO Consumer Status | "네가 보낸 데이터를 나는 잘 받아 쓰고 있다/아니다" (반대 방향 프레임에 실음) | 송신 안 함 **[차이]** |
| **Send Clock Factor (SCF)** | 송신 클럭 배수 | 기본 주기 = SCF × 31.25µs. SCF=32 → 1ms | `ar.send_clock_factor` |
| **Reduction Ratio (RR)** | 감속비 | 실제 갱신 주기 = 기본 주기 × RR | `ar.reduction_ratio` |
| **Watchdog Factor** | 워치독 배수 | 소비자 감시 시간 = 갱신 주기 × WF | DataHold 대체값으로 사용 |
| **Data Hold Factor** | 데이터 유지 배수 | 데이터가 안 오면 이 시간 후 "대체값/AR 중단" | `ar.data_hold_factor` |
| **Record data** | 레코드 | 주기 데이터가 아닌 "필요할 때 읽고 쓰는" 데이터. (API, slot, subslot, **index**) 로 주소 지정 | [pn_record.c](../../stacks/profinet/src/pn_record.c) |
| **Index** | 레코드 번호 | 16비트. `0xAFF0`=I&M0 등 | [pn_types.h:66-70](../../stacks/profinet/include/pn_types.h) |
| **PrmEnd** | Parameter End | 컨트롤러 → 디바이스: "파라미터 다 썼다" (Control 요청) | `PN_CONTROL_PRM_END` |
| **ApplicationReady** | 응용 준비 완료 | **디바이스 → 컨트롤러**: "파라미터 적용 끝, 데이터 교환 시작 가능" (디바이스가 거는 RPC 요청) | `queue_app_ready` ([pn_rpc.c:441](../../stacks/profinet/src/pn_rpc.c)) |
| **I&M0..4** | Identification & Maintenance | 제조사·주문번호·시리얼(I&M0), 태그·위치(I&M1), 설치일(I&M2), 설명(I&M3), 서명(I&M4) | [pn_record.c:25-100](../../stacks/profinet/src/pn_record.c) |
| **Alarm** | 알람 | 진단 발생/해소, 플러그/풀 등 이벤트 통지. High/Low 우선순위 | 더미 송신만 |
| **RTA** | Real-Time Acyclic | 알람을 실어 나르는 ACK 기반 L2 프로토콜 | 헤더 흉내만 |
| **Session Key** | 세션 키 | AR 마다 증가하는 16비트 값. Connect 에서 받아 Control 에 되돌림 | `ar.session_key` |
| **CMInitiator** | CM 개시자 | Connect 를 보낸 쪽(=컨트롤러). ObjectUUID·MAC·ActivityTimeoutFactor 를 알림 | `initiator_mac/uuid` |
| **CMI Activity Timeout** | — | Connect 후 컨트롤러가 조용하면 AR 을 버리는 시간. 사양은 `CMInitiatorActivityTimeoutFactor × 100ms` [사양 확인 필요] | **2초 고정** ([pn_internal.h:48](../../stacks/profinet/include/pn_internal.h)) |
| **EPM** | Endpoint Mapper | "이 인터페이스 UUID 는 어느 포트?" 를 알려주는 DCE/RPC 표준 서비스 | 없음 |
| **Security Class 1/2/3** | PI 보안 등급 | 8장 참고. 이 저장소의 "Class 1" 은 **자체 HMAC 프로파일** | [pn_sec.c](../../stacks/profinet/src/pn_sec.c) |
| **PSK** | Pre-Shared Key | 미리 나눠 가진 비밀 키. 이 저장소는 32바이트 | `cfg.psk` |

---

## 3. 전체 그림

### 3.1 두 개의 길: L2 RT 경로 vs UDP/RPC 경로

```
            IO Controller (PLC)                                  IO Device (이 저장소)
   +-------------------------------------+            +----------------------------------------+
   | 응용 (PLC 프로그램)                  |            | 응용 (fieldbus 데몬 / fb_api)           |
   +-----------------+-------------------+            +-------------------+--------------------+
   | CM (DCE/RPC)    | RT / DCP / Alarm  |            | CM: pn_rpc.c      | RT: pn_rt.c        |
   | Record R/W      | (주기·탐색·알람)   |            | Record: pn_record | DCP: pn_dcp.c      |
   +-----------------+                   |            +-------------------+ Alarm: pn_sec.c(*) |
   | UDP 34964       |                   |            | UDP 34964/161     | LLDP: pn_lldp.c    |
   | IPv4            |                   |            | (pn_udp_open)     |                    |
   +-----------------+-------------------+            +-------------------+--------------------+
   | Ethernet  EtherType 0x0800 | 0x8892 |  <=====>   | 0x0800 (OS 커널)  | 0x8892/0x88CC      |
   |                            | 0x88CC |            |                   | AF_PACKET (pn_eth) |
   +-------------------------------------+            +----------------------------------------+
   (*) 알람 더미 송신 함수 pn_alarm_send_dummy 가 pn_sec.c 안에 있다 (pn_sec.c:30)
```

- **왼쪽 기둥(UDP/RPC)**: 연결 수립, 파라미터, 제어. 느려도 되고 신뢰성(재시도)이 중요.
- **오른쪽 기둥(L2)**: 주기 데이터(RT), 장치 탐색(DCP), 알람(RTA), 이웃 광고(LLDP). IP 가 없어도 동작한다 —
  그래서 **IP 가 아직 없는 새 장치도 DCP 로 찾고 IP 를 줄 수 있다.**

### 3.2 부팅부터 사이클릭 교환까지 — 전체 시퀀스

```
 Controller / Engineering tool                                         IO Device
 ------------------------------                                         ---------
      |                                                                   | 전원 ON: LLDP 광고 시작 (5초마다)
      |                                                                   |
 (1)  |--- DCP Identify.req (멀티캐스트 01:0E:CF:00:00:00, 필터=이름) ---->|
      |<-- DCP Identify.res (유니캐스트, 이름/ID/역할/IP/MAC 블록) --------| ResponseDelay 만큼 흩어서 응답
      |                                                                   |
 (2)  |--- DCP Set.req (IP 파라미터, [NameOfStation]) ------------------->| (시운전 시 이름 지정은 보통 툴이)
      |<-- DCP Set.res (Control/Response 블록, BlockError=0) -------------|
      |                                                                   |
 (3)  |--- [RPC EPM Lookup] (UDP 34964, 선택) ---------------------------->| 인터페이스→포트 조회
      |                                                                   |
 (4)  |=== RPC Connect.req (opnum 0) =====================================>| AR 생성: ARBlockReq,
      |    ARBlockReq + IOCRBlockReq(in) + IOCRBlockReq(out)              | IOCRBlockReq x2,
      |    + AlarmCRBlockReq + ExpectedSubmoduleBlockReq ...              | AlarmCR, 기대 구성 비교
      |<== RPC Connect.res: ARBlockRes, IOCRBlockRes x2, AlarmCRBlockRes,-|
      |    [ModuleDiffBlock]                                              |
      |                                                                   |
      |<~~~~~~~~~~~~ RT 주기 프레임 양방향 시작 (FrameID 0x8xxx) ~~~~~~~~~~~>| (아직 데이터는 "무효"일 수 있음)
      |                                                                   |
 (5)  |=== RPC Write.req (opnum 3) x N (파라미터 레코드) =================>|
      |<== RPC Write.res =================================================|
      |                                                                   |
 (6)  |=== RPC Control.req (opnum 4, IODControlReq: PrmEnd) =============>|
      |<== RPC Control.res (ControlCommand=Done) =========================|
      |                                                                   | 파라미터 적용
 (7)  |<== RPC Control.req (디바이스가 클라이언트!, IOXControlReq: AppReady)|
      |=== RPC Control.res (Done) =======================================>|
      |                                                                   |
 (8)  |<~~~~~~~~~~ RT: IOPS/IOCS=GOOD, DataStatus=Valid+Run ~~~~~~~~~~~~~~>| 정상 운전
      |<-- Alarm (RTA DATA) --------------------------------------------- | 이벤트 발생 시
      |--- Alarm ACK --------------------------------------------------->|
```

핵심 포인트 세 가지:

1. **이름이 주소다.** 컨트롤러 프로젝트에는 "slot 구성 + NameOfStation" 이 들어 있고, 컨트롤러는 DCP
   Identify(이름 필터)로 그 이름의 MAC 을 찾은 뒤, 필요하면 DCP Set 으로 **프로젝트에 적힌 IP 를 장치에 준다**.
2. **Connect 한 번에 모든 계약이 들어 있다.** 몇 바이트를 몇 ms 마다, 어느 Frame ID 로, 어느 우선순위로,
   몇 번 놓치면 끊을지 — 전부 Connect 요청의 블록들에 있다.
3. **ApplicationReady 는 방향이 반대다.** PrmEnd 까지는 컨트롤러가 묻고 디바이스가 답하지만,
   ApplicationReady 는 **디바이스가 RPC 클라이언트가 되어** 컨트롤러의 RPC 서버를 부른다.
   (인터페이스 UUID 도 Controller 인터페이스 `DEA00002-…` 를 쓴다 [사양 확인 필요: 목적지 포트].)

### 3.3 해제 / Release / Abort

```
 정상 해제                                      비정상 해제(Abort)
 ---------                                      ------------------
 Controller          Device                      Controller          Device
    |== Release.req (opnum 1,                      |  (케이블 뽑힘 / 전원 OFF / 프로그램 정지)
    |   IODReleaseBlockReq 0x0114) ==>|            |                    | RT 수신 끊김
    |<== Release.res (0x8114, Done) ==|            |                    | data-hold 시간 경과
    |   RT 중지                         |            |                    | → AR abort, 출력은 안전값
    |                                   |            |<-- (사양상) RTA ERR / 재연결 대기
```

- 정상 Release 는 블록 타입 `0x0114`(ReleaseBlockReq)로 온다 [검증: scapy 블록 표].
- 디바이스 쪽 Abort 는 사양상 Alarm CR 로 ERR-RTA-PDU 를 보내 알리는 것이 원칙이다 [사양 확인 필요].
- **이 저장소**: Release 는 `0x0101`(ARBlockReq) 등 **다른 블록 안의 ARUUID** 로만 수락하고, 표준
  `0x0114` 블록은 인식하지 못해 **거부(무응답)** 한다 **[차이, 검증: 하네스]** (5.d.9). Abort 는 조용히 AR 을
  지운다 ([pn_rt.c:8-20](../../stacks/profinet/src/pn_rt.c)).

### 3.4 이 저장소에서 실제로 코드가 도는 길

```
 core (프로토콜 모름)                   adapters/profinet               stacks/profinet
 -------------------                   -----------------               ---------------
 main() → fb_open() → adapter->init ──> pn_init(): JSON 파싱 ─────────> pn_stack_create()
          fb_run()  → adapter->connect → pn_connect() ─────────────────> pn_stack_start()
                                                                           ├ pn_eth_open (AF_PACKET 또는 mock)
                                                                           ├ pn_udp_open(34964), (161)
                                                                           └ pn_lldp_send
 run_cycle_loop (cycle_ms 마다, 절대시각 sleep)
    └ poll_locked → adapter->poll_cycle → pn_poll_cycle() ──────────────> pn_stack_poll()
                                                                           ├ 최대 16 프레임 수신 → pn_stack_handle_eth
                                                                           │     ├ DCP(FEFE/FEFD/FEFC) → pn_dcp_on_frame
                                                                           │     └ 내 MAC → pn_rt_on_frame (O→T 출력)
                                                                           ├ pn_rpc_poll   (UDP 34964, 1 데이터그램)
                                                                           ├ pn_snmp_poll  (UDP 161)
                                                                           ├ pn_dcp_poll   (지연된 Identify.res)
                                                                           ├ pn_ar_watchdog (CMI / data-hold)
                                                                           ├ pn_rt_send_if_due (입력 RT 송신)
                                                                           └ 5초마다 pn_lldp_send
 fb_read_point/write_point → adapter->read_point/write_point → pn_stack_read_output / read_input / write_input
```

근거: [core/main.c:24-41](../../core/main.c), [core/fb_api.c:729-785](../../core/fb_api.c) (run_cycle_loop),
[adapters/profinet/profinet_adapter.c:114-297](../../adapters/profinet/profinet_adapter.c),
[pn_stack.c:109-137, 238-266](../../stacks/profinet/src/pn_stack.c).
코어는 PROFINET 을 전혀 모른다 — `core/adapter_registry.c:30` 에 생성자 한 줄이 등록돼 있을 뿐이다.

**중요한 결과**: 스택은 스레드를 따로 두지 않는다. RT 송신도, 수신 감시도, RPC 처리도 **코어가
`cycle_ms` 마다 부르는 `poll_cycle` 안에서만** 일어난다. 따라서 실제 RT 송신 주기는
`max(cfg.cycle_us, cycle_ms)` 에 가깝고, RPC 는 poll 당 **데이터그램 1개**만 처리한다
([pn_rpc.c:689-713](../../stacks/profinet/src/pn_rpc.c)). 6.3 과 13장에서 다시 다룬다.

---

## 4. 데이터 모델

### 4.1 주소 체계: API → Slot → Subslot → Index

PROFINET 장치는 **서랍장이 여러 개 있는 건물**처럼 생각하면 된다.

```
 Device (건물)
  └─ API 0 (동: 보통 하나뿐)
      ├─ Slot 0  (층: DAP — 장치 자체)
      │    ├─ Subslot 0x0001   DAP 서브모듈 (I&M0 등 장치 정보)
      │    ├─ Subslot 0x8000   Interface 서브모듈 (이더넷 인터페이스)
      │    └─ Subslot 0x8001   Port 1 서브모듈 (포트별 진단)
      └─ Slot 1  (층: IO 모듈)
           └─ Subslot 0x0001   IO 서브모듈 (입력 32B, 출력 8B)
                 ├─ 주기 데이터: Input 32B / Output 8B  (RT 프레임 안의 위치 = FrameOffset)
                 └─ 레코드: Index 0x0001(파라미터), 0xAFF0..0xAFF4(I&M) ...  (서랍)
```

- **주기 데이터**는 (API, slot, subslot) 로 식별되고 RT 프레임의 어느 바이트에 놓이는지는 Connect 요청의
  `IODataObjectFrameOffset`/`IOCSFrameOffset` 이 정한다(4.4).
- **레코드(비주기 데이터)** 는 (API, slot, subslot, **index**) 4-튜플로 식별되고 RPC Read/Write 로 접근한다.
- 서브슬롯 번호 `0x8000`–`0x8FFF` 는 인터페이스/포트용 예약 범위다(`0x8000` = 인터페이스, `0x8001`=포트1 …)
  [사양 확인 필요: 다중 인터페이스일 때 `0x8100` 등].

주요 레코드 인덱스 범위 (대략, [사양 확인 필요]):

| 범위 | 대상 | 예 |
|------|------|----|
| `0x0000`–`0x7FFF` | 제조사 정의 (GSDML 의 `ParameterRecordDataItem Index`) | 이 GSDML 의 `Index="1"` |
| `0x8000`–`0xAFFF` | 서브슬롯 단위 시스템 레코드 | `0x8028` RecordInputDataObjectElement, `0x8029` RecordOutputDataObjectElement, `0xAFF0`–`0xAFFF` I&M0–15 |
| `0xB000`–`0xBFFF`, `0xC000`–`0xCFFF` | 슬롯 단위 | — |
| `0xE000`–`0xEFFF` | AR 단위 | `0xE040` WriteMultiple |
| `0xF000`–`0xFFFF` | API / 장치 단위 | `0xF840` I&M0FilterData |

**이 저장소**: `pn_record_read`/`pn_record_write` 는 slot/subslot 을 `(void)` 로 무시하고 index 만 본다
([pn_record.c:28-29, 106-107](../../stacks/profinet/src/pn_record.c)). I&M0–4 외의 인덱스 읽기는 4바이트 0 을
돌려주고, 쓰기는 무조건 성공이다 ([pn_record.c:94-100, 162-163](../../stacks/profinet/src/pn_record.c)).

### 4.2 모듈 / 서브모듈 / DAP

- **모듈(Module)** 은 물리적/논리적 "카드", **서브모듈(Submodule)** 은 그 안에서 실제 IO 를 가진 단위다.
  컨트롤러는 Connect 요청의 **ExpectedSubmoduleBlockReq** 로 "slot 1 에 ModuleIdent 0x10 이, subslot 1 에
  SubmoduleIdent 0x11(입력 32/출력 8)이 있어야 한다"고 말한다. 디바이스는 실제 구성과 비교해 다르면
  **ModuleDiffBlock**(`0x8104`)으로 알려준다 [사양 확인 필요: 차이 없을 때 생략 가능 여부].
- **DAP**(Device Access Point)는 slot 0 의 특수 모듈이다. 장치 자체의 식별(I&M0), 인터페이스(0x8000),
  포트(0x8001…) 서브모듈을 가진다. GSDML 에 `DeviceAccessPointItem` 으로 기술된다.

**이 저장소**: ExpectedSubmoduleBlockReq(`0x0104`) 를 **파싱하지 않는다** — `parse_ar_iocr` 는
`0x0101`/`0x0102` 만 본다 ([pn_rpc.c:234-278](../../stacks/profinet/src/pn_rpc.c)). 그래서 어떤 구성으로
연결해 와도 비교 없이 수락하고, ModuleDiffBlock 도 보내지 않는다. 장치는 사실상 "하나의 입력 이미지 +
하나의 출력 이미지"다 ([pn_internal.h:67-68](../../stacks/profinet/include/pn_internal.h)).

### 4.3 입력/출력 방향 — 헷갈리지 말 것

PROFINET 의 **Input/Output 은 컨트롤러 관점**이다.

| 이름 | 방향 | 누가 Provider(송신자) | 이 저장소 이름 |
|------|------|------------------------|----------------|
| **Input** (Input CR) | Device → Controller | Device | `input_image`, `cfg.input_len`, `ar.in_frame_id` |
| **Output** (Output CR) | Controller → Device | Controller | `output_image`, `cfg.output_len`, `ar.out_frame_id` |

이 저장소 코드 주석도 같다: `uint16_t input_len; /* device -> controller */`
([pn_stack.h:41-42](../../stacks/profinet/include/pn_stack.h)). 코드 곳곳의 "O→T"(Originator→Target, EtherNet/IP
용어)는 Controller→Device 출력 방향을 뜻한다 ([pn_internal.h:23-24, 38-45](../../stacks/profinet/include/pn_internal.h)).

### 4.4 C_SDU 레이아웃과 IOPS/IOCS 배치

RT 프레임 한 개는 한 IOCR 의 **C_SDU** 를 싣는다. C_SDU 는 여러 서브모듈의 데이터와 상태 바이트를
정해진 오프셋에 나열한 것이다. 규칙:

- 각 **데이터 오브젝트**(서브모듈의 이 방향 데이터) 뒤에 **IOPS 1바이트**가 붙는다 (Provider 가 보증).
- 반대 방향 데이터에 대한 **IOCS 1바이트**들도 이 프레임에 실린다 (Consumer 가 보증).
- 각 위치는 Connect 요청의 `IODataObjectFrameOffset` / `IOCSFrameOffset` 이 정한다.
- C_SDU 길이 = IOCRBlockReq 의 `DataLength`. RT_CLASS_1 은 **최소 40바이트**, 최대 1440바이트
  [검증: scapy `pnio.py` 의 min(1440, …) 와 기본값 40].
- 남는 자리는 0 으로 패딩한다.

예: 서브모듈 하나(slot1/subslot1), 입력 32바이트 + 출력 8바이트 (이 문서 5.d 의 Connect 예제와 동일):

```
 Input CR  (Device → Controller), DataLength=40, FrameID 0x8001
 offset:  0 ............ 31 | 32   | 33   | 34 .. 39
          입력 데이터 32B    | IOPS | IOCS | 패딩(0)
                              ^      ^
                              |      +-- "컨트롤러가 보낸 출력 8B 를 나는 잘 소비 중" (IOCSFrameOffset=33)
                              +--------- "이 입력 32B 는 유효"                     (IODataObjectFrameOffset=0 → IOPS 는 데이터 직후)

 Output CR (Controller → Device), DataLength=40, FrameID 0x8002
 offset:  0 ... 7 | 8    | 9    | 10 .. 39
          출력 8B  | IOPS | IOCS | 패딩(0)
                                ^-- "디바이스가 보낸 입력 32B 를 컨트롤러가 잘 소비 중" (IOCSFrameOffset=9)
```

IOPS/IOCS 값 (1바이트): **`0x80` = GOOD**, `0x00` = BAD. 세부 비트(DataState bit7, Instance bit5-6, Extension
bit0)는 [사양 확인 필요]. 실무에서는 `0x80`/`0x00` 두 값을 쓴다.

**이 저장소의 레이아웃 [차이, 검증: 하네스]**:

- 송신(입력): `[FrameID][입력 data_len][IOPS=0x80][CycleCounter][DataStatus][TransferStatus]`
  ([pn_rt.c:119-130](../../stacks/profinet/src/pn_rt.c)). 컨트롤러 출력에 대한 **IOCS 가 없고**, C_SDU 를
  **40바이트로 패딩하지 않으며**, `IODataObjectFrameOffset` 을 무시한다. 입력 32B 이면 C_SDU=33B,
  이더넷 프레임 53바이트다(5.e).
- 수신(출력): `payload + 2` 부터 `min(out_data_len, cfg.output_len)` 바이트를 그대로 출력 이미지로 복사한다
  ([pn_rt.c:79-88](../../stacks/profinet/src/pn_rt.c)). 서브모듈이 하나이고 출력이 오프셋 0 이면 우연히
  맞는다. IOPS/DataStatus 는 보지 않는다.
- `out_data_len`/`in_data_len` 을 `DataLength - 1` 로 계산한다 ([pn_rpc.c:271, 274](../../stacks/profinet/src/pn_rpc.c)).
  표준 컨트롤러는 DataLength ≥ 40 을 보내므로 결과는 39 이고, 이후 `cfg.*_len` 으로 잘려 쓰인다.

### 4.5 GSDML — 장치 설명서 XML

GSDML 은 **엔지니어링 툴에게 주는 장치 카탈로그**다. PLC 프로그래머는 TIA Portal/CODESYS 에 GSDML 을
import 하고, 카탈로그에서 모듈을 끌어다 슬롯에 놓고, 주기(update time)와 이름을 정한다. 툴은 그 결과로
Connect 요청 내용을 만든다. 즉 **GSDML 과 스택 구현이 어긋나면 Connect 가 실패**한다.

이 저장소 파일 [`stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`](../../stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml)
을 한 줄씩 읽어 보자.

| 줄 | 요소 | 의미 |
|----|------|------|
| 7 | `<ISO15745Profile xmlns=".../GSDML/2003/11/DeviceProfile">` | GSDML 은 ISO 15745 장치 프로파일 틀을 따른다 |
| 8-19 | `ProfileHeader` | 형식 정보 (고정 문구) |
| 21 | `DeviceIdentity VendorID="0xABCD" DeviceID="0x0001"` | **DCP DeviceID 블록과 반드시 같아야** 한다. VendorID 는 PI 가 발급 — `0xABCD` 는 자리표시자 |
| 26 | `Family MainFamily="I/O"` | 카탈로그 분류 |
| 30-33 | `DeviceAccessPointItem ID="DAP1" PhysicalSlots="0..1" ModuleIdentNumber="0x00000001" MinDeviceInterval="32" DNS_CompatibleName="fb-arch-pn" FixedInSlots="0" ...` | DAP. 슬롯 0..1 사용. **`MinDeviceInterval=32` → 32×31.25µs = 1ms 까지 허용**한다는 뜻. `DNS_CompatibleName` 은 기본 NameOfStation 후보 |
| 34-41 | `ModuleInfo` | 이름·주문번호(`FB-ARCH-PN-DEV`)·HW/SW 버전 — I&M0 와 일치시키는 게 좋다 |
| 42-44 | `SubslotList` | subslot 1 에 텍스트 부여 |
| 45-49 | `SystemDefinedSubmoduleList` → `SubmoduleItem ... SubslotNumber="32768"` | 32768 = `0x8000` 인터페이스 서브모듈 |
| 53-74 | `ModuleItem ID="MOD_IO" ModuleIdentNumber="0x00000010"` → `VirtualSubmoduleItem SubmoduleIdentNumber="0x00000011" FixedInSubslots="1"` | IO 모듈. `IOData` 에 Input 32B / Output 8B (`OctetString`) |
| 69-71 | `RecordDataList` → `ParameterRecordDataItem Index="1" Length="0"` | 파라미터 레코드 index 1. 컨트롤러가 PrmEnd 전에 Write 한다 |
| 76-87 | `ExternalTextList` | TextId → 사람 읽는 문자열 |

파일 머리 주석 스스로 "Minimal GSDML … Import is a starting point for engineering; expect to extend before a
real PLC project." 라고 한다 (줄 2-6). 실제 툴 import 전에 보강이 필요해 보이는 곳 **[사양 확인 필요 —
GSDML Specification V2.35 및 PI GSDML Checker 로 검증할 것]**:

- 인터페이스/포트는 보통 `InterfaceSubmoduleItem`(0x8000)과 `PortSubmoduleItem`(0x8001) 로 기술하고, 그 안에
  `ApplicationRelations`/`TimingProperties`(SendClock, ReductionRatio) 등을 둔다. 이 파일은 일반
  `SubmoduleItem` 하나뿐이고 포트가 없다.
- DAP 에 `UseableModules`(어느 슬롯에 어느 모듈을 꽂을 수 있나)가 없어 툴이 `MOD_IO` 를 slot 1 에 놓지
  못할 수 있다.
- `CertificationInfo`(ConformanceClass="B" 등), `IOConfigData`, DAP 의 subslot 1 서브모듈 정의가 없다.
- 파일명 관례는 `GSDML-V<ver>-<Vendor>-<Device>-<YYYYMMDD>.xml` (날짜 포함).
- `Length="0"` 파라미터 레코드는 툴이 거부할 수 있다.
- **타이밍**: `MinDeviceInterval=32`(1ms)는 이 스택이 실제로 보내는 주기(`cycle_us`, 기본 8ms)와 맞지 않는다.
  툴이 1ms 를 고르면 디바이스는 8ms 마다 보내고 컨트롤러 워치독이 끊는다(13장). 8ms 에 맞추려면 256 이 맞다.

### 4.6 이 저장소의 실제 모델 요약

```
 pn_stack_t
   ├ input_image [PN_IO_MAX=256]   ← 앱이 pn_stack_write_input() 으로 채움 → RT 송신
   ├ output_image[PN_IO_MAX=256]   ← RT 수신이 채움 → 앱이 pn_stack_read_output() 으로 읽음
   ├ io_lock (pthread mutex)       ← 두 이미지 보호
   └ ar (단일 AR)
```

([pn_internal.h:56-95](../../stacks/profinet/include/pn_internal.h), [pn_stack.c:273-305](../../stacks/profinet/src/pn_stack.c)).
slot/subslot/index 개념은 GSDML 과 config 에만 있고, 스택 안에서는 **바이트 오프셋 하나**로 평탄화된다(11.3).

---

## 5. 프레임 포맷

### 5.a 이더넷 헤더와 Frame ID

모든 `0x8892` 프레임은 다음 모양이다:

```
 +----------+----------+-----------------+--------+--------------------------------+
 | DstMAC 6 | SrcMAC 6 | [0x8100 TCI] 4  | 0x8892 | FrameID(2, BE) | 나머지 ...     |
 +----------+----------+-----------------+--------+--------------------------------+
                         (VLAN 태그는 선택)
```

Frame ID 범위 (IEC 61158-6-10 기준으로 널리 쓰이는 값; 세부 경계는 [사양 확인 필요]):

| Frame ID | 용도 | 이 저장소 |
|----------|------|-----------|
| `0x0000`–`0x00FF` | 시간 동기(PTCP) 등 | 없음 |
| `0x0100`–`0x0FFF` | RT_CLASS_3 (IRT) | **영구 비목표** |
| `0x8000`–`0xBFFF` | **RT_CLASS_1** (그중 `0xBC00`–`0xBFFF` 는 멀티캐스트용으로 알려짐) | 기본 `0x8001`(in)/`0x8002`(out). CTT 는 `0x8000–0xBBFF` 를 RTC1 로 분류 ([pn_plugin.c:1018](../../tools/ctt/proto/profinet/pn_plugin.c)) |
| `0xC000`–`0xFBFF` | RT_CLASS_UDP | 없음 |
| `0xFC01` | Alarm High (RTA) | `PN_FRAMEID_ALARM_HIGH` |
| `0xFE01` | Alarm Low (RTA) | `PN_FRAMEID_ALARM_LOW` |
| `0xFEFC` | DCP Hello | `PN_FRAMEID_DCP_HELLO` |
| `0xFEFD` | DCP Get/Set | `PN_FRAMEID_DCP_GETSET` |
| `0xFEFE` | DCP Identify 요청 | `PN_FRAMEID_DCP_ID_REQ` |
| `0xFEFF` | DCP Identify 응답 | `PN_FRAMEID_DCP_ID_RES` |
| `0xFF00`–`0xFF4x` | PTCP announce/delay 등 | 없음 |
| `0xFF80`–`0xFF8F` | 단편화(fragmentation) | 없음 |

상수 정의: [pn_types.h:7-16](../../stacks/profinet/include/pn_types.h). 수신 분기: DCP 세 종류(FEFE/FEFD/FEFC)는
"내 MAC 이거나 DCP 멀티캐스트"면 DCP 로, 나머지 `0x8892` 는 "내 MAC 일 때만" RT 로 보낸다
([pn_stack.c:154-180](../../stacks/profinet/src/pn_stack.c)). LLDP(`0x88CC`) 수신은 무시한다(line 176-178).

### 5.b DCP (Discovery and Configuration Protocol)

#### 5.b.1 DCP 헤더

```
 offset(페이로드 기준)
  0  FrameID          2  FEFE / FEFF / FEFD / FEFC
  2  ServiceID        1  3=Get 4=Set 5=Identify 6=Hello
  3  ServiceType      1  0=Request 1=Response Success 5=Response "Request not supported"
  4  Xid              4  트랜잭션 ID (요청자가 정하고 응답이 그대로 되돌림)
  8  ResponseDelay    2  Identify.req 에서는 ResponseDelayFactor, 그 외는 Reserved(0)
 10  DCPDataLength    2  뒤따르는 블록들의 총 길이 (패딩 포함)
 12  Blocks ...
```

이 저장소 파서: `parse_hdr` ([pn_dcp.c:65-86](../../stacks/profinet/src/pn_dcp.c)) — 12바이트 미만이거나
`12 + DCPDataLength > 길이` 면 버린다. ServiceType 이 Request(0)가 아니면 무시한다 ([pn_dcp.c:507-509](../../stacks/profinet/src/pn_dcp.c)).

#### 5.b.2 DCP 블록

```
  Option(1) | Suboption(1) | DCPBlockLength(2) | 값 (DCPBlockLength 바이트) | [패딩 1바이트: 길이가 홀수면]
```

**중요한 비대칭** — 값 부분의 앞머리가 요청/응답에 따라 다르다:

| 어디에 쓰이는 블록 | 값 앞에 붙는 2바이트 | 비고 |
|--------------------|----------------------|------|
| Identify.req 의 **필터** 블록 | 없음 | 값 그대로 (이름 문자열 등) |
| **Set.req** 블록 | **BlockQualifier** (2) | `0x0000`=임시, `0x0001`=영구 저장 [검증: scapy] |
| **Identify.res / Get.res / Hello.req** 블록 | **BlockInfo** (2) | IP 블록이면 IP 상태(`0x0001`=IP set 등), 그 외 `0x0000` [검증: scapy] |
| Set.res 의 Control/Response 블록 (Get.res 오류 시에도) | 없음 | `Option, Suboption, BlockError` (3바이트) |

Option/Suboption 표 [검증: scapy `pnio_dcp.py` 상수 표와 일치]:

| Option | 이름 | Suboption |
|--------|------|-----------|
| `0x01` | IP | `0x01` MAC Address, `0x02` IP Parameter(IP/mask/GW 12B), `0x03` Full IP Suite(+DNS) |
| `0x02` | Device Properties | `0x01` Manufacturer specific (TypeOfStation 문자열), `0x02` **NameOfStation**, `0x03` **DeviceID**(Vendor 2B + Device 2B), `0x04` **DeviceRole**, `0x05` DeviceOptions(지원하는 opt/sub 쌍 목록), `0x06` AliasName, `0x07` DeviceInstance, `0x08` OEM DeviceID |
| `0x03` | DHCP | DHCP 옵션 번호 그대로 (`0x3D` client id 등) |
| `0x05` | Control | `0x01` Start, `0x02` End (transaction), `0x03` **Signal**, `0x04` **Response**, `0x05` Reset Factory Settings, `0x06` Reset to Factory |
| `0x06` | Device Initiative | `0x01` |
| `0x80`–`0xFE` | 제조사 정의 | 이 저장소의 보안 블록 `0xF0/0x01` 이 여기 |
| `0xFF` | All Selector | `0xFF` (Identify "모두 응답하라") |

DeviceRole 값: bit0=IO-Device(`0x01`), bit1=IO-Controller(`0x02`), bit2=IO-Multidevice, bit3=PN-Supervisor
[검증: scapy 역할 표는 `0x01`="IO Device", `0x02`="IO Controller"; 비트 정의 전체는 사양 확인 필요].

BlockError(Set.res 의 Control/Response 블록) [검증: scapy]:

| 값 | 의미 |
|----|------|
| `0x00` | OK |
| `0x01` | Option not supported |
| `0x02` | Suboption not supported or no DataSet available |
| `0x03` | Suboption not set |
| `0x04` | Resource Error |
| `0x05` | SET not possible by local reasons |
| `0x06` | In operation, SET not possible |

#### 5.b.3 Identify 요청 — 필터

Identify 는 **멀티캐스트** `01:0E:CF:00:00:00` 으로 보내고, 필터 블록 **전부가 맞는** 장치만 응답한다
(AND). 필터 예: All Selector(`FF FF 00 00`), NameOfStation, DeviceID, TypeOfStation, DeviceRole.

예제 1 — "모두 응답하라" (ResponseDelayFactor=1) **[검증: 하네스]**:

```
 0000  01 0e cf 00 00 00  00 11 22 33 44 55  88 92  fe fe
 0010  05 00  00 00 12 34  00 01  00 04  ff ff 00 00
```

| 바이트 | 필드 | 값 |
|--------|------|----|
| `01 0e cf 00 00 00` | Dst | DCP Identify 멀티캐스트 |
| `00 11 22 33 44 55` | Src | 컨트롤러 |
| `88 92` | EtherType | PROFINET |
| `fe fe` | FrameID | Identify.req |
| `05` / `00` | ServiceID / Type | Identify / Request |
| `00 00 12 34` | Xid | 0x1234 |
| `00 01` | ResponseDelayFactor | 1 (분산 없음) |
| `00 04` | DCPDataLength | 4 |
| `ff ff 00 00` | 블록 | All Selector, 길이 0 |

(30바이트 — 실 NIC 에서는 60바이트로 패딩된다.)

예제 2 — 이름 필터 `sensor-line1` **[검증: 하네스]**:

```
 0000  01 0e cf 00 00 00 00 11 22 33 44 55 88 92 fe fe
 0010  05 00 00 00 12 35 00 00 00 10 02 02 00 0c 73 65
 0020  6e 73 6f 72 2d 6c 69 6e 65 31
```

필터 블록 `02 02 00 0c` + `sensor-line1`(12바이트, BlockInfo/Qualifier 없음).

이 저장소 필터 처리 `ident_filters_match` ([pn_dcp.c:336-379](../../stacks/profinet/src/pn_dcp.c)): All/Name/DeviceID/
TypeOfStation/DeviceRole 를 비교하고, **모르는 필터가 하나라도 있으면 응답하지 않는다**. DeviceRole 필터는
`0x02` 와 비교한다(line 370) — 아래 [차이] 참고.

#### 5.b.4 Identify 응답 — 이 저장소 vs 사양 형태

**이 저장소가 실제로 보내는 바이트** **[검증: golden `dcp_identify_res.pcap`, 하네스]**:

```
 0000  00 11 22 33 44 55 02 fb 00 00 00 01 88 92 fe ff
 0010  05 01 11 22 33 44 00 00 00 56 02 01 00 12 46 69
 0020  65 6c 64 62 75 73 20 50 4e 20 44 65 76 69 63 65
 0030  02 02 00 0c 73 65 6e 73 6f 72 2d 6c 69 6e 65 31
 0040  02 03 00 04 ab cd 00 01 02 04 00 01 02 00 01 02
 0050  00 0c 00 00 00 00 00 00 00 00 00 00 00 00 01 01
 0060  00 06 02 fb 00 00 00 01 02 05 00 04 01 02 02 02
```

| 위치 | 바이트 | 해석 (이 저장소 의도) |
|------|--------|----------------------|
| 0x0e | `fe ff` | Identify.res |
| 0x10 | `05 01` | Identify / Response Success |
| 0x12 | `11 22 33 44` | Xid (요청 그대로) |
| 0x16 | `00 00` | Reserved |
| 0x18 | `00 56` | DCPDataLength = 86 |
| 0x1a | `02 01 00 12` + "Fieldbus PN Device" | TypeOfStation (18B) |
| 0x30 | `02 02 00 0c` + "sensor-line1" | NameOfStation (12B) |
| 0x40 | `02 03 00 04 ab cd 00 01` | DeviceID: Vendor 0xABCD, Device 0x0001 |
| 0x48 | `02 04 00 01 02 00` | DeviceRole = `0x02` + 패딩 1B |
| 0x4e | `01 02 00 0c` + 12×`00` | IP Parameter (IP 미설정이라 0.0.0.0) |
| 0x5e | `01 01 00 06 02 fb 00 00 00 01` | MAC |
| 0x68 | `02 05 00 04 01 02 02 02` | DeviceOptions: (IP,IPParam), (Dev,Name) |

코드: `build_identify_blocks` ([pn_dcp.c:381-409](../../stacks/profinet/src/pn_dcp.c)), `wr_block` ([pn_dcp.c:55-63](../../stacks/profinet/src/pn_dcp.c)).

**사양 형태의 같은 응답** (BlockInfo 포함, DeviceRole=`0x01`, IP 설정 상태) — 손으로 만들고 **scapy 로 역파싱해
모든 블록이 정상 해석됨을 확인** [검증: scapy]:

```
 0000  00 11 22 33 44 55 02 fb 00 00 00 01 88 92 fe ff
 0010  05 01 00 00 12 34 00 00 00 72 02 01 00 14 00 00
 0020  46 69 65 6c 64 62 75 73 20 50 4e 20 44 65 76 69
 0030  63 65 02 02 00 0e 00 00 73 65 6e 73 6f 72 2d 6c
 0040  69 6e 65 31 02 03 00 06 00 00 ab cd 00 01 02 04
 0050  00 04 00 00 01 00 02 05 00 14 00 00 01 01 01 02
 0060  02 01 02 02 02 03 02 04 02 05 05 03 05 04 01 01
 0070  00 08 00 00 02 fb 00 00 00 01 01 02 00 0e 00 01
 0080  c0 a8 00 0a ff ff ff 00 c0 a8 00 01
```

| 블록 | 바이트 | 설명 |
|------|--------|------|
| TypeOfStation | `02 01 00 14 00 00` + 18B | 길이 = 2(BlockInfo) + 18 |
| NameOfStation | `02 02 00 0e 00 00` + 12B | 길이 14 |
| DeviceID | `02 03 00 06 00 00 ab cd 00 01` | |
| DeviceRole | `02 04 00 04 00 00 01 00` | BlockInfo, **RoleDetails=0x01 (IO-Device)**, reserved |
| DeviceOptions | `02 05 00 14 00 00` + 9쌍 | 지원 opt/sub 목록 |
| MAC | `01 01 00 08 00 00 02 fb 00 00 00 01` | |
| IP Parameter | `01 02 00 0e 00 01 c0 a8 00 0a ff ff ff 00 c0 a8 00 01` | **BlockInfo=0x0001 "IP set"** + IP/mask/GW |

> **[차이, 검증: scapy]** 이 저장소 응답에는 **BlockInfo 2바이트가 없다.** 사양대로 파싱하는 도구(Wireshark,
> scapy, 실제 컨트롤러)는 이름의 첫 두 글자를 BlockInfo 로 먹어 `nsor-line1` 로 읽고, 이후 블록 경계가
> 무너진다 — scapy 로 이 저장소의 Identify.res 를 역파싱하면 실제로 `name_of_station=b'nsor-line1'`,
> `vendor_id=0x1, device_id=0x204` 처럼 깨진다(부록 E). 또한 **DeviceRole 을 `0x02`(IO-Controller)** 로 보낸다.
> CTT 는 같은 저장소의 비표준 형태를 기대하도록 짜여 있어 green 이다. 실 컨트롤러와 붙이기 전 최우선
> 수정 후보다.

#### 5.b.5 ResponseDelay — 응답 흩뿌리기

공장에 같은 종류 장치가 200대 있으면 Identify-All 한 번에 200개 응답이 동시에 몰린다. 그래서 요청이
`ResponseDelayFactor` 를 주면 장치는 **0 ~ (factor−1) × 10ms** 사이에서 자기 몫의 지연 후 응답한다.
사양은 지연 값을 장치별로 퍼지게 하라고만 요구한다 [사양 확인 필요: 정확한 산식과 factor 0/1 의미].

이 저장소: `slots = (MAC[4]<<8 | MAC[5]) % factor`, 지연 = `slots × 10ms`
([pn_dcp.c:435-444](../../stacks/profinet/src/pn_dcp.c)). 지연이 0 이 아니면 대기열(1건)에 넣고 `pn_dcp_poll`
이 시각이 되면 보낸다 ([pn_dcp.c:454-478](../../stacks/profinet/src/pn_dcp.c)). 대기 중 두 번째 Identify 가 오면
첫 번째를 **덮어쓴다**(대기열 1칸). 단위 테스트: MAC `…:00:01`, factor 2 → 10ms 후 응답
([tests/test_pn_dcp.c:210-217](../../tests/test_pn_dcp.c)).

#### 5.b.6 Set — 이름/IP 설정 (유니캐스트)

예제 3 — NameOfStation 을 `press-7` 로, 영구 저장 **[검증: 하네스, scapy]**:

```
 요청 (컨트롤러 → 디바이스, 40B)
 0000  02 fb 00 00 00 01 00 11 22 33 44 55 88 92 fe fd
 0010  04 00 00 00 00 42 00 00 00 0e 02 02 00 09 00 01
 0020  70 72 65 73 73 2d 37 00
```

| 바이트 | 의미 |
|--------|------|
| `fe fd` | Get/Set FrameID |
| `04 00` | Set / Request |
| `00 00 00 42` | Xid |
| `00 00` | Reserved |
| `00 0e` | DCPDataLength = 14 (4 + 9 + 패딩 1) |
| `02 02 00 09` | NameOfStation, 길이 9 |
| `00 01` | **BlockQualifier = 영구 저장** |
| `70 72 65 73 73 2d 37` | "press-7" |
| `00` | 홀수 길이 패딩 (DCPBlockLength 에는 포함 안 됨, DCPDataLength 에는 포함) |

```
 응답 (디바이스 → 컨트롤러, 34B — 실 NIC 에선 60B 로 패딩)
 0000  00 11 22 33 44 55 02 fb 00 00 00 01 88 92 fe fd
 0010  04 01 00 00 00 42 00 00 00 08 05 04 00 03 02 02
 0020  00 00
```

`05 04 00 03` = Control/Response 블록 길이 3, `02 02` = 어떤 블록에 대한 답인지(NameOfStation),
`00` = BlockError OK, 마지막 `00` 은 패딩.

**사양상 응답 규칙**: Set.req 에 블록이 여러 개면 **블록마다** Control/Response 블록을 하나씩 돌려준다
[사양 확인 필요]. **[차이]** 이 저장소는 요청에 몇 개가 있든 **하나만** 돌려주며, "Signal 이 있으면 Signal,
아니면 IP 가 있으면 IP, 아니면 Name" 으로 대표를 고른다 ([pn_dcp.c:545-563](../../stacks/profinet/src/pn_dcp.c)).
또한 Control/ResetToFactory 처럼 **적용하지 않은 블록에도 성공(Name OK)** 을 답한다(`apply_blocks` 는
Name/IP/Signal 만 처리, [pn_dcp.c:251-290](../../stacks/profinet/src/pn_dcp.c)).

예제 4 — IP 파라미터 설정 후 Hello **[검증: 하네스]**:

```
 요청 (44B)
 0000  02 fb 00 00 00 01 00 11 22 33 44 55 88 92 fe fd
 0010  04 00 00 00 00 43 00 00 00 12 01 02 00 0e 00 01
 0020  c0 a8 00 14 ff ff ff 00 c0 a8 00 01
       └IP 192.168.0.20┘└mask /24 ┘└GW 192.168.0.1┘
 응답
 0010  04 01 00 00 00 43 00 00 00 08 05 04 00 03 01 02 00 00
 이어서 Hello (FEFC, 108B, 목적지 01:0e:cf:00:00:00) — Identify 블록과 같은 내용
```

- 이 저장소는 IP 를 `cfg.ip/netmask/gateway` 변수에만 저장한다 ([pn_dcp.c:277-284](../../stacks/profinet/src/pn_dcp.c)).
  `pn_cfg_t.apply_os_ip` 필드는 선언만 있고 어디서도 쓰지 않는다 ([pn_stack.h:44](../../stacks/profinet/include/pn_stack.h))
  → **OS 인터페이스 IP 는 바뀌지 않는다.** 문서도 "스택은 기본적으로 OS 주소를 바꾸지 않는다"고 적는다
  ([docs/profinet_stack.md:45](../profinet_stack.md)). 컨트롤러가 새 IP 로 RPC 를 보내면 OS 가 받지 못한다(13장).
- Set IP 뒤에 Hello 를 보내는 것은 이 저장소 고유 동작이다 ([pn_dcp.c:564-567](../../stacks/profinet/src/pn_dcp.c)).
  사양의 Hello 는 Fast Start-Up(FSU) 에서 **전원 투입 직후** 장치가 "나 여기 있다"고 알리는 용도이며,
  목적지는 `01:0E:CF:00:00:01` 이다 [사양 확인 필요]. **[차이]**

예제 5 — Signal(LED 깜빡임) **[검증: 하네스]**:

```
 요청:  … fe fd 04 00 00 00 00 44 00 00 00 08 05 03 00 04 00 00 01 00
                                            └Control/Signal 길이4┘└Qualifier 0┘└SignalValue 0x0100┘
 응답:  … fe fd 04 01 00 00 00 44 00 00 00 08 05 04 00 03 05 03 00 00
```

이 저장소는 로그만 남긴다: `"DCP Signal accepted (LED flash stub)"` ([pn_dcp.c:285-286](../../stacks/profinet/src/pn_dcp.c)).
실제 장치는 약 3초 동안 2Hz 로 LED 를 깜빡여야 한다 [사양 확인 필요].

#### 5.b.7 Get

```
 요청 (Name 만 요청):  fe fd 03 00 00 00 00 45 00 00 00 02 02 02
```

Get.req 의 블록은 "Option, Suboption" 2바이트 쌍의 목록이다. 사양상 응답은 **요청한 것만** 담는다.
**[차이, 검증: 하네스]** 이 저장소는 무엇을 요청하든 Identify 블록 전체를 돌려준다 ([pn_dcp.c:520-526](../../stacks/profinet/src/pn_dcp.c)).

#### 5.b.8 Set 실패 응답과 NameOfStation 규칙

이름 규칙 위반 또는 보안 검증 실패 시 이 저장소는 `send_set_not_possible` 로 응답한다
([pn_dcp.c:480-494](../../stacks/profinet/src/pn_dcp.c)):

```
 … fe fd 04 05 aa bb cc dd 00 00 00 08 05 04 00 03 f0 01 03 00     (HMAC 실패 예) [검증: 하네스]
            ^^ ServiceType=5 "Request not supported"      ^^ BlockError=3
```

**[차이]** 사양상 Set 을 이해했지만 값을 못 쓴 경우는 ServiceType=Success(1) + BlockError(예: `0x05` "SET not
possible by local reasons")가 자연스럽다 [사양 확인 필요]. ServiceType=5 는 "서비스 자체를 모른다"는 뜻이다.
코드 주석은 BlockError `0x03` 을 "set not possible" 이라 부르지만 표준 의미는 "Suboption not set" 이다.

NameOfStation 규칙 (`pn_dcp_name_ok`, [pn_dcp.c:93-161](../../stacks/profinet/src/pn_dcp.c)):

- 1~240자, 라벨(`.` 사이) 1~63자, 문자 `a-z 0-9 -`, 라벨 앞뒤 `-` 금지, 빈 라벨·끝 `.` 금지.
- `n.n.n.n` (각 0~255) 형태 금지 (IP 주소와 혼동 방지).
- `port-xyz`(3자리 소문자 hex) 또는 `port-xyz-…` 로 시작 금지 (포트 이름 예약).
- 경계 테스트: [tests/scenarios/profinet/dcp_set_name_boundary.yaml](../../tests/scenarios/profinet/dcp_set_name_boundary.yaml),
  [tests/test_pn_dcp.c:121-158](../../tests/test_pn_dcp.c).
- 길이 0 이름(이름 지우기)은 거부한다 ([pn_dcp.c:327](../../stacks/profinet/src/pn_dcp.c)). 사양상 빈 이름 설정이
  허용되는지는 [사양 확인 필요].

### 5.c LLDP (IEEE 802.1AB)

LLDP 는 "나는 누구고 이 포트는 무엇"을 이웃에게 5초마다 알리는 L2 방송이다. 스위치와 장치의 LLDP 정보를
모으면 컨트롤러/툴이 **토폴로지(누가 어느 포트에 꽂혀 있나)** 를 그릴 수 있다. PROFINET 은 이를 이용해
"장치 교체 시 이름 자동 부여" 같은 기능을 한다.

TLV 형식: `헤더 2바이트 = Type(상위 7비트) << 9 | Length(하위 9비트)`, 이어서 Length 바이트 값.

이 저장소가 보내는 LLDPDU (이름 `line-b01`) **[검증: 하네스]**:

```
 0000  01 80 c2 00 00 0e 02 fb 00 00 00 01 88 cc 02 09
 0010  07 6c 69 6e 65 2d 62 30 31 04 07 03 02 fb 00 00
 0020  00 01 06 02 00 14 0a 08 6c 69 6e 65 2d 62 30 31
 0030  fe 0a 00 0c cf 05 02 fb 00 00 00 01 00 00
```

| 바이트 | TLV | 값 |
|--------|-----|----|
| `02 09` `07` "line-b01" | Type 1 Chassis ID, len 9 | subtype 7 (locally assigned) = NameOfStation |
| `04 07` `03` MAC | Type 2 Port ID, len 7 | subtype 3 (MAC address) |
| `06 02 00 14` | Type 3 TTL | 20초 |
| `0a 08` "line-b01" | Type 5 System Name | |
| `fe 0a 00 0c cf 05` MAC | Type 127 조직 정의, len 10 | OUI `00-0C-CF`, subtype 5 (chassis MAC 의도) |
| `00 00` | Type 0 End of LLDPDU | |

코드: [pn_lldp.c:22-63](../../stacks/profinet/src/pn_lldp.c). 송신 주기 5초 ([pn_stack.c:261-265](../../stacks/profinet/src/pn_stack.c)).

PROFINET 이 기대하는 LLDP 요소와 비교 ([사양 확인 필요 — IEC 61158-6-10 LLDP 절]):

| 요소 | 사양 기대 | 이 저장소 |
|------|-----------|-----------|
| Chassis ID | NameOfStation (subtype 7) | 동일 |
| Port ID | subtype 7, `port-001` (구버전은 `port-001.<station>`) | **subtype 3 MAC [차이]** |
| TTL / 주기 | 20초 / 5초 | 동일 |
| PNO 조직 TLV | OUI **`00-0E-CF`**: subtype 1 PNIO Delay, 2 Port Status, 5 Chassis MAC, 6 PTCP status 등 | **OUI 가 `00-0C-CF` 로 오타 [차이]** ([pn_lldp.c:46-50](../../stacks/profinet/src/pn_lldp.c)) |
| IEEE 802.3 조직 TLV | OUI `00-12-0F` subtype 1 MAC/PHY Config/Status | **없음 [차이]** |
| Management Address TLV (8) | IP 주소 | **없음** |
| LLDP 수신 / 이웃 테이블 | CC-B 토폴로지·SNMP LLDP-MIB 에 필요 | **수신 무시** ([pn_stack.c:176-178](../../stacks/profinet/src/pn_stack.c)) |

### 5.d DCE/RPC over UDP 34964

#### 5.d.1 RPC 헤더 (connectionless, 80바이트)

| off | 크기 | 필드 | 예제 값 | 설명 |
|-----|------|------|---------|------|
| 0 | 1 | rpc_vers | `04` | CL DCE/RPC 는 **4** |
| 1 | 1 | ptype | `00` | 0 request, 1 ping, 2 response, 3 fault, 4 working, 5 nocall, 6 reject, 7 ack, … |
| 2 | 1 | flags1 | `20` | `0x02` last frag, `0x04` frag, `0x08` no fack, `0x10` maybe, `0x20` **idempotent**, `0x40` broadcast |
| 3 | 1 | flags2 | `00` | |
| 4 | 3 | drep | `10 00 00` | 첫 바이트 상위 니블 1 = **LE 정수**, 하위 니블 0 = ASCII; 둘째 바이트 0 = IEEE float |
| 7 | 1 | serial_hi | `00` | |
| 8 | 16 | object UUID | `DEA00000-6C97-11D1-8271-0001 0001 ABCD` | PNIO 객체: 마지막 6바이트 = Instance(2) DeviceID(2) VendorID(2) |
| 24 | 16 | interface UUID | `DEA00001-…-00A02442DF7D` | Device 인터페이스 (Controller=`DEA00002`, Supervisor=`DEA00003`, ParameterServer=`DEA00004`) |
| 40 | 16 | activity UUID | 임의 | 호출자 대화 ID |
| 56 | 4 | server boot time | | |
| 60 | 4 | interface version | `01 00 00 00` | 1 |
| 64 | 4 | sequence number | | 같은 activity 내 호출 번호 |
| 68 | 2 | **opnum** | `00 00` | 0 Connect, 1 Release, 2 Read, 3 Write, 4 Control, 5 ReadImplicit |
| 70 | 2 | interface hint | `ff ff` | |
| 72 | 2 | activity hint | `ff ff` | |
| 74 | 2 | **fragment length** | | 스텁(이 헤더 뒤) 길이 |
| 76 | 2 | fragment number | | |
| 78 | 1 | auth proto | `00` | |
| 79 | 1 | serial_lo | | |

(이 표의 오프셋·UUID·opnum 은 scapy `DceRpc4` 가 하네스 바이트를 같은 값으로 해석함을 확인 [검증: scapy].)

**이 저장소**: `RPC_HDR 80`, `opnum = LE16 @68`, `fragment length = LE16 @74` 만 읽는다
([pn_rpc.c:13, 489-495](../../stacks/profinet/src/pn_rpc.c)). **[차이]**

- `drep` 을 보지 않고 항상 LE 로 가정한다. BE drep 요청은 opnum/길이가 뒤집혀 읽힌다.
- rpc_vers, interface UUID, object UUID 를 검사하지 않는다. 그래서 **EPM Lookup**(인터페이스
  `E1AF8308-5D1F-11C9-91A4-08002B14A0FA`, opnum 2 = `ept_lookup`)이 오면 **PNIO Read 로 오인**해
  I&M0 바이트를 돌려준다(코드 경로상; 11.5).
- 응답은 요청 헤더 80바이트를 **통째로 복사**한 뒤 ptype=2, fragment length 만 고친다
  ([pn_rpc.c:384-395](../../stacks/profinet/src/pn_rpc.c)). activity/sequence 가 유지되므로 대체로 무방하다.
- `RPC_PT_REJECT` 를 4 로 정의했지만(사양상 4 = working, 6 = reject) 쓰이지 않는다 ([pn_rpc.c:16](../../stacks/profinet/src/pn_rpc.c)).
- 단편화(frag 플래그), ping/working/nocall, 중복 요청 재응답을 처리하지 않는다. 큰 Connect(모듈 수십 개)는
  단편화될 수 있다 [사양 확인 필요: PNIO 최대 RPC 크기].

#### 5.d.2 NDR 헤더 — 요청과 응답이 다르다

```
 요청 스텁 (20B + 블록들)                         응답 스텁 (20B + 블록들)
 +--------------------+                          +--------------------+
 | ArgsMaximum   (4)  |  호출자가 받을 수 있는 최대  | PNIOStatus    (4)  |  <-- 응답에만 있다! 0 = OK
 | ArgsLength    (4)  |  실제 인자 길이             | ArgsLength    (4)  |
 | MaximumCount  (4)  |  NDR 배열 최대              | MaximumCount  (4)  |
 | Offset        (4)  |  0                         | Offset        (4)  |
 | ActualCount   (4)  |  = ArgsLength              | ActualCount   (4)  |
 +--------------------+                          +--------------------+
   정수들은 drep 엔디안(보통 LE)                    PNIOStatus 는 4개의 1바이트 필드 (9.1)
```

[검증: scapy — `PNIOServiceReqPDU` = args_max + NDRData, `PNIOServiceResPDU` = status + NDRData.
scapy 는 status 를 drep 엔디안 정수로 다루지만, Wireshark·p-net 등은 ErrorCode/ErrorDecode/ErrorCode1/ErrorCode2
네 바이트로 다룬다. 값 0 은 어느 쪽이든 같다. [사양 확인 필요: PNIOStatus 인코딩]]

**[차이, 검증: 하네스 + scapy]** 이 저장소는 응답에도 요청과 같은 `ndr_wrap` 을 쓴다:
`n, n, n, 0, n` ([pn_rpc.c:415-424](../../stacks/profinet/src/pn_rpc.c)). 즉 **PNIOStatus 자리에 인자 길이가**
들어간다. 아래 Connect 응답에서 `48 00 00 00`(72) 이 그것이고, scapy 는 이를 `status = 72`(오류)로 읽었다.
표준 컨트롤러는 이 응답을 **실패**로 볼 것이다. 이 저장소의 CTT·단위 테스트·퍼저는 모두 같은 `ndr_wrap`
을 복사해 쓰므로 이 불일치를 잡지 못한다 ([tests/test_pn_rpc.c:43-52](../../tests/test_pn_rpc.c),
[pn_plugin.c:814-823](../../tools/ctt/proto/profinet/pn_plugin.c)).

수신 쪽 `ndr_blocks` 는 `min(ArgsLength, ActualCount)` 를 쓰고, 스텁을 넘지 않도록 자른다 — 퍼저가 찾은
정수 래핑 버그의 수정 주석이 있다 ([pn_rpc.c:397-413](../../stacks/profinet/src/pn_rpc.c)).

#### 5.d.3 PNIO 블록 헤더

```
  BlockType (2, BE) | BlockLength (2, BE) | BlockVersionHigh (1) | BlockVersionLow (1) | 본문 ...
                      └ BlockLength = 버전 2바이트 + 본문 길이 (타입·길이 4바이트는 제외)
```

- 블록 내부의 모든 정수는 **BE** 다(NDR/RPC 헤더와 달리 drep 무관).
- 버전은 대부분 `1.0`(`01 00`). 일부 블록은 `1.1` 등 [사양 확인 필요].
- 이 저장소 워커 `walk_blocks`: 6바이트 이상 남았고 `BlockLength ≥ 2` 이고 `off+4+BlockLength ≤ n` 일 때만
  콜백, 이후 **짝수 경계로 정렬** ([pn_rpc.c:29-52](../../stacks/profinet/src/pn_rpc.c)). 짝수 정렬 규칙이 모든
  블록에 적용되는지는 [사양 확인 필요] — 대부분의 PNIO 블록은 본문 안에 자체 패딩 필드를 둔다.

#### 5.d.4 Connect 요청 — 전체 예제 (362바이트)

5.4 의 IO 구성(slot1/subslot1, 입력 32 / 출력 8, 32ms)을 요청하는 Connect. 필자가 IEC 필드 순서대로 만들고,
**scapy 로 역파싱해 모든 필드가 의도대로 읽히는 것**과 **이 저장소가 수락해 AR 을 세우는 것**을 확인했다
[검증: 하네스 + scapy].

```
 0000  04 00 20 00 10 00 00 00 00 00 a0 de 97 6c d1 11   RPC 헤더
 0010  82 71 00 01 00 01 ab cd 01 00 a0 de 97 6c d1 11
 0020  82 71 00 a0 24 42 df 7d 10 11 12 13 14 15 16 17
 0030  18 19 1a 1b 1c 1d 1e 1f 00 00 00 00 01 00 00 00
 0040  00 00 00 00 00 00 ff ff ff ff 1a 01 00 00 00 00
 0050  00 04 00 00 06 01 00 00 00 04 00 00 00 00 00 00   NDR 요청 헤더
 0060  06 01 00 00 01 01 00 3a 01 00 00 01 a0 a1 a2 a3   ARBlockReq ...
 0070  a4 a5 a6 a7 a8 a9 aa ab ac ad ae af 00 01 00 11
 0080  22 33 44 55 c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb
 0090  cc cd ce cf 00 00 00 11 02 58 88 92 00 04 70 6c
 00a0  63 31 01 02 00 3e 01 00 00 01 00 01 88 92 00 00   IOCRBlockReq (Input) ...
 00b0  00 01 00 28 80 01 00 20 00 20 00 01 00 00 ff ff
 00c0  ff ff 00 03 00 03 c0 00 00 00 00 00 00 00 00 01
 00d0  00 00 00 00 00 01 00 01 00 01 00 00 00 01 00 01
 00e0  00 01 00 21 01 02 00 3e 01 00 00 02 00 02 88 92   IOCRBlockReq (Output) ...
 00f0  00 00 00 01 00 28 80 02 00 20 00 20 00 01 00 00
 0100  ff ff ff ff 00 03 00 03 c0 00 00 00 00 00 00 00
 0110  00 01 00 00 00 00 00 01 00 01 00 01 00 00 00 01
 0120  00 01 00 01 00 09 01 03 00 16 01 00 00 01 88 92   AlarmCRBlockReq ...
 0130  00 00 00 00 00 01 00 03 00 01 00 c8 c0 00 a0 00
 0140  01 04 00 26 01 00 00 01 00 00 00 00 00 01 00 00   ExpectedSubmoduleBlockReq ...
 0150  00 10 00 00 00 01 00 01 00 00 00 11 00 03 00 01
 0160  00 20 01 01 00 02 00 08 01 01
```

**RPC 헤더 (0x00–0x4F)**: `04` vers, `00` request, `20` idempotent, `10 00 00` drep LE, object UUID
`DEA00000-6C97-11D1-8271-0001-0001ABCD`(instance 1, device 1, vendor ABCD), interface `DEA00001-…`, activity
`13121110-…`, if_vers 1, seq 0, **opnum 0 (Connect) @0x44**, fraglen `1a 01` = 282 @0x4A.

**NDR (0x50–0x63)**: ArgsMaximum `00 04 00 00`=1024, ArgsLength `06 01 00 00`=262, MaximumCount 1024, Offset 0,
ActualCount 262.

**ARBlockReq (0x64, 타입 `0x0101`, 길이 58)**:

| off | 바이트 | 필드 | 값/의미 |
|-----|--------|------|---------|
| 0x64 | `01 01 00 3a 01 00` | 헤더 | ARBlockReq, len 58, v1.0 |
| 0x6a | `00 01` | ARType | IOCARSingle |
| 0x6c | `a0 … af` | ARUUID | 이 AR 의 ID |
| 0x7c | `00 01` | SessionKey | 1 |
| 0x7e | `00 11 22 33 44 55` | CMInitiatorMacAdd | **RT 입력 프레임의 목적지 MAC** |
| 0x84 | `c0 … cf` | CMInitiatorObjectUUID | 컨트롤러 객체 UUID (같은 컨트롤러 판별용) |
| 0x94 | `00 00 00 11` | ARProperties | bit0-2 State=1(Active), bit4 ParameterizationServer=CM Initiator; StartupMode(bit30)=0 Legacy [검증: scapy 비트 해석] |
| 0x98 | `02 58` | CMInitiatorActivityTimeoutFactor | 600 × 100ms = 60초 [사양 확인 필요: 단위] |
| 0x9a | `88 92` | CMInitiatorUDPRTPort | `0x8892` (L2 RT 사용 표시) |
| 0x9c | `00 04` + "plc1" | StationNameLength + CMInitiatorStationName | 컨트롤러 이름 |

**IOCRBlockReq — Input (0xA2, `0x0102`, 길이 62)**:

| 본문 off | 바이트 | 필드 | 값 |
|----------|--------|------|----|
| 0 | `00 01` | IOCRType | 1 = Input CR (Output=2, MC Provider=3, MC Consumer=4) |
| 2 | `00 01` | IOCRReference | 1 |
| 4 | `88 92` | LT | EtherType |
| 6 | `00 00 00 01` | IOCRProperties | RTClass=1 (bit0-3) |
| 10 | `00 28` | **DataLength** | 40 (C_SDU 길이) |
| 12 | `80 01` | **FrameID** | 0x8001 |
| 14 | `00 20` | **SendClockFactor** | 32 → 1ms |
| 16 | `00 20` | **ReductionRatio** | 32 → 32ms |
| 18 | `00 01` | Phase | 1 |
| 20 | `00 00` | Sequence | 0 |
| 22 | `ff ff ff ff` | FrameSendOffset | best effort |
| 26 | `00 03` | **WatchdogFactor** | 3 |
| 28 | `00 03` | **DataHoldFactor** | 3 |
| 30 | `c0 00` | IOCRTagHeader | PCP 6, VID 0 |
| 32 | `00 ×6` | IOCRMulticastMACAdd | (유니캐스트라 0) |
| 38 | `00 01` | NumberOfAPIs | 1 |
| 40 | `00 00 00 00` | API | 0 |
| 44 | `00 01` | NumberOfIODataObjects | 1 |
| 46 | `00 01 00 01 00 00` | Slot 1, Subslot 1, FrameOffset 0 | 입력 데이터 위치 |
| 52 | `00 01` | NumberOfIOCS | 1 |
| 54 | `00 01 00 01 00 21` | Slot 1, Subslot 1, IOCSFrameOffset 33 | 출력에 대한 IOCS 위치 |

**IOCRBlockReq — Output (0xE4)**: 같은 구조, IOCRType 2, Reference 2, FrameID `0x8002`, IOCS 오프셋 9.

**AlarmCRBlockReq (0x126, `0x0103`, 길이 22)**: AlarmCRType `00 01`, LT `88 92`, AlarmCRProperties `00 00 00 00`
(priority/transport=RTA_CLASS_1), RTATimeoutFactor `00 01`(×100ms), RTARetries `00 03`, **LocalAlarmReference
`00 01`**(컨트롤러의 알람 엔드포인트 — 디바이스 알람의 목적지), MaxAlarmDataLength `00 c8`=200,
TagHeaderHigh `c0 00`, TagHeaderLow `a0 00` [검증: scapy].

**ExpectedSubmoduleBlockReq (0x140, `0x0104`, 길이 38)**: NumberOfAPIs 1 → API 0, Slot 1, ModuleIdentNumber
`0x00000010`, ModuleProperties 0, NumberOfSubmodules 1 → Subslot 1, SubmoduleIdentNumber `0x00000011`,
SubmoduleProperties `00 03`(Type=INPUT_OUTPUT), DataDescription×2: `00 01 00 20 01 01`(Input, 32B, IOCS 길이1,
IOPS 길이1), `00 02 00 08 01 01`(Output, 8B) [검증: scapy].

실 컨트롤러 Connect 에는 보통 DAP(slot 0, subslot 1/0x8000/0x8001)도 ExpectedSubmodule 에 들어가고,
ARRPCBlockReq, PrmServer, IR/SR Info, ARVendorBlock 등이 붙을 수 있다 [사양 확인 필요].

**이 저장소가 이 요청에서 실제로 읽는 것** (`parse_ar_iocr`, [pn_rpc.c:234-278](../../stacks/profinet/src/pn_rpc.c)):
ARUUID, SessionKey, InitiatorMAC, (본문 42바이트 이상이면) InitiatorObjectUUID; IOCR 에서 Type, DataLength(−1),
FrameID, 그리고 **Output CR 에서만** SCF/RR/WatchdogFactor/DataHoldFactor. 하네스 결과:
`in_fid=8001 out_fid=8002 in_len=39 out_len=39 scf=32 rr=32 dh=3`.

#### 5.d.5 Connect 응답 — 이 저장소 (172바이트) **[검증: 하네스 + scapy]**

```
 0000  04 02 20 00 10 00 00 00 00 00 a0 de 97 6c d1 11   RPC 헤더 (ptype=2 response)
 0010  82 71 00 01 00 01 ab cd 01 00 a0 de 97 6c d1 11
 0020  82 71 00 a0 24 42 df 7d 10 11 12 13 14 15 16 17
 0030  18 19 1a 1b 1c 1d 1e 1f 00 00 00 00 01 00 00 00
 0040  00 00 00 00 00 00 ff ff ff ff 5c 00 00 00 00 00
 0050  48 00 00 00 48 00 00 00 48 00 00 00 00 00 00 00   NDR: "PNIOStatus" 자리 = 0x48 (!)
 0060  48 00 00 00 81 01 00 1e 01 00 00 01 a0 a1 a2 a3   ARBlockRes
 0070  a4 a5 a6 a7 a8 a9 aa ab ac ad ae af 00 01 02 fb
 0080  00 00 00 01 88 94 81 02 00 08 01 00 00 01 00 01   ... ResponderUDPRTPort=0x8894 | IOCRBlockRes(in)
 0090  80 01 81 02 00 08 01 00 00 02 00 02 80 02 81 03   IOCRBlockRes(out) | AlarmCRBlockRes
 00a0  00 0a 01 00 00 01 00 01 00 c8 00 a0
```

| 블록 | 사양 형태 | 이 저장소 | 판정 |
|------|-----------|-----------|------|
| NDR 첫 4바이트 | PNIOStatus `00 00 00 00` | `48 00 00 00` | **[차이]** 컨트롤러는 오류로 해석 |
| ARBlockRes `0x8101` | ARType, ARUUID, SessionKey, CMResponderMacAdd, **CMResponderUDPRTPort=`0x8892`** | 포트에 `0x8894`(34964) | **[차이]** ([pn_rpc.c:353](../../stacks/profinet/src/pn_rpc.c)); scapy 기본값도 `0x8892` |
| IOCRBlockRes `0x8102` ×2 | IOCRType, IOCRReference(요청 값), FrameID | Reference 를 1/2 로 고정 | 요청이 1/2 면 우연히 일치 |
| AlarmCRBlockRes `0x8103` | AlarmCRType, **LocalAlarmReference(디바이스 것)**, MaxAlarmDataLength — 본문 6바이트 | 본문 8바이트(`00 01 00 01 00 c8 00 a0`) | **[차이]** 여분 2바이트; scapy 가 `Raw b'\x00\xa0'` 로 남김 |
| ModuleDiffBlock `0x8104` | 구성 차이가 있으면 | 없음 | 비교 자체를 안 함 |
| ARRPCBlockRes 등 | 요청에 따라 | 없음 | |

코드: `build_connect_res_blocks` ([pn_rpc.c:344-382](../../stacks/profinet/src/pn_rpc.c)).

#### 5.d.6 Record Write — IODWriteReqHeader 는 64바이트 고정

사양 형태 **[검증: scapy `IODWriteReq`: 헤더 뒤 RWPadding 24바이트]**:

```
 IODWriteReqHeader (BlockType 0x0008, BlockLength 60 → 헤더 전체 64B)
   SeqNumber(2) ARUUID(16) API(4) Slot(2) Subslot(2) Padding(2) Index(2) RecordDataLength(4) RWPadding(24)
 RecordData (RecordDataLength 바이트)   ← 블록 "밖", 헤더 뒤에 이어짐
```

I&M1 쓰기 예 (slot 0, subslot 1, index `0xAFF1`, 54바이트) — 스텁 부분 **[검증: 하네스]**:

```
 0060  .. .. .. .. 00 08 00 3c 01 00 00 01 a0 a1 a2 a3   IODWriteReqHeader, len 60
 0070  a4 a5 a6 a7 a8 a9 aa ab ac ad ae af 00 00 00 00   ARUUID | API 0
 0080  00 00 00 01 00 00 af f1 00 00 00 36 00 00 00 00   slot 0 | subslot 1 | pad | index AFF1 | len 54 | RWPadding...
 0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00a0  00 00 00 00 54 41 47 2d 46 55 4e 43 20 20 20 20   RecordData: "TAG-FUNC" + 공백...
 ...
```

**[차이, 검증: 하네스]** 이 저장소 `parse_write_req` 는 데이터가 RecordDataLength **바로 뒤(본문 +34)** 에 있다고
가정하고, 블록 길이 안에서만 찾는다 ([pn_rpc.c:120-140](../../stacks/profinet/src/pn_rpc.c)). 위 사양 형태 요청을
넣으면 24바이트 RWPadding(0) 을 데이터로 읽어 **I&M1 을 0 으로 덮어쓴다**(하네스: `im1_function=''`, 로그
`len=24`). CTT/테스트는 "헤더 본문 안에 데이터를 넣는" 비표준 형태를 쓰므로 통과한다
([pn_plugin.c:1440-1452](../../tools/ctt/proto/profinet/pn_plugin.c)).

Write 응답 사양 형태(`IODWriteResHeader` `0x8008`, 64B) [검증: scapy 생성]:

```
 80 08 00 3c 01 00 | 00 01 | a0..af | 00 00 00 00 | 00 00 | 00 01 | 00 00 | af f1 | 00 00 00 36
 | AdditionalValue1 00 00 | AdditionalValue2 00 00 | PNIOStatus 00 00 00 00 | RWPadding 16×00
```

이 저장소는 헤더 블록 없이 4바이트 0 만 돌려준다 (`so = ndr_wrap(stub_out, z, 4)`, [pn_rpc.c:679-680](../../stacks/profinet/src/pn_rpc.c)).

#### 5.d.7 Record Read

요청: `IODReadReqHeader`(`0x0009`, 64B) — Write 와 같은 앞부분, RecordDataLength = **최대 읽을 길이**,
그 뒤 (ReadImplicit 용) TargetARUUID 16B + RWPadding 8B [사양 확인 필요: scapy 는 RWPadding 24B 로 뭉뚱그림].

응답 사양 형태: `IODReadResHeader`(`0x8009`, 64B: …, RecordDataLength(실제), AdditionalValue1/2, RWPadding 20B)
+ 레코드 데이터. I&M0 레코드 데이터는 **자체 BlockHeader(`0x0020`)를 가진 블록**이다 [검증: scapy 생성]:

```
 00 20 00 38 01 00 | ab cd | "FB-ARCH-PN-DEV      "(20) | "SN00000000000001"(16)
 | 00 01 (HW rev) | 56 01 00 00 ("V1.0.0") | 00 00 (RevCounter) | f6 00 (ProfileID) | 00 01 (ProfileSpecificType)
 | 01 01 (I&M version 1.1) | 00 1e (I&M1..4 지원)
```

이 저장소 응답 스텁 (I&M0 읽기) **[검증: 하네스]**:

```
 0050  36 00 00 00 36 00 00 00 36 00 00 00 00 00 00 00   NDR (PNIOStatus 자리 = 54)
 0060  36 00 00 00 ab cd 46 42 2d 41 52 43 48 2d 50 4e   I&M0 54바이트 raw (BlockHeader 없음,
 0070  2d 44 45 56 20 20 20 20 20 00 53 4e 30 30 30 30    IODReadResHeader 없음)
 0080  30 30 30 30 30 30 30 30 30 31 00 01 56 01 00 00
 0090  00 00 f6 00 00 01 01 01 00 1e
```

**[차이]** IODReadResHeader 와 I&M0 BlockHeader 가 없고, OrderID 20바이트의 마지막이 공백 대신 `00`
(C 문자열 NUL; [pn_record.c:38](../../stacks/profinet/src/pn_record.c)). 필드 **순서와 길이**는 사양과 같다.

#### 5.d.8 Control — PrmEnd (컨트롤러→디바이스) 와 ApplicationReady (디바이스→컨트롤러)

IODControlReq 본문 [검증: scapy `IODControlReq`]:

```
  Reserved(2) | ARUUID(16) | SessionKey(2) | AlarmSequenceNumber/Reserved(2) | ControlCommand(2) | ControlBlockProperties(2)
```

ControlCommand 비트: bit0 **PrmEnd**, bit1 **ApplicationReady**, bit2 Release, bit3 **Done**, bit4 ReadyForCompanion,
bit5 ReadyForRT_CLASS_3, bit6 PrmBegin [검증: scapy 비트 필드].

블록 타입과 방향:

| BlockType | 이름 | 방향 | 명령 |
|-----------|------|------|------|
| `0x0110` | IODControlReq (Connect) | Controller → Device | PrmEnd |
| `0x8110` | IODControlRes | Device → Controller | **Done** |
| `0x0111` | IODControlReq (Plug) | Controller → Device | PrmEnd (플러그 알람 후) |
| `0x0112` | IOXControlReq (Connect) | **Device → Controller** | **ApplicationReady** |
| `0x8112` | IOXControlRes | Controller → Device | Done |
| `0x0114` / `0x8114` | ReleaseBlockReq / Res | Controller → Device / 응답 | Release / Done |
| `0x0118` / `0x8118` | PrmBegin Req / Res | | PrmBegin |

(scapy 블록 표와 `IODControlReq.post_build` 의 타입 선택 규칙으로 교차 확인 [검증: scapy].)

PrmEnd 요청 블록 (하네스 입력) 과 **이 저장소의 응답** **[검증: 하네스 + scapy]**:

```
 요청 블록: 01 10 00 1c 01 00 | 00 00 | a0..af | 00 01 | 00 00 | 00 01 | 00 00
                                                SessKey  AlmSeq  PrmEnd   props
 이 저장소: 01 11 00 1c 01 00 | 00 00 | a0..af | 00 01 | 00 00 | 00 01 | 00 00
 사양 형태: 81 10 00 1c 01 00 | 00 00 | a0..af | 00 01 | 00 00 | 00 08 | 00 00    (scapy 생성)
```

**[차이]** 응답 블록 타입을 `0x0111`(`PN_BLOCK_CONTROL_RES`, [pn_types.h:57](../../stacks/profinet/include/pn_types.h))로
보낸다 — 사양에서 `0x0111` 은 "Plug 용 PrmEnd **요청**"이다(scapy 는 실제로 `IODBlockReq_plug` 로 해석). 또
명령을 Done(`0x0008`)이 아니라 요청 명령 그대로 되돌린다 ([pn_rpc.c:605-613](../../stacks/profinet/src/pn_rpc.c)).

ApplicationReady — **디바이스가 RPC 요청을 만든다**. 이 저장소가 만드는 PDU **[검증: 하네스]**:

```
 0000  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   rpc_vers=1 (!), object/interface/activity UUID 전부 0
 ...
 0040  00 00 00 00 04 00 00 00 00 00 34 00 00 00 00 00   opnum 4 (Control), fraglen 52
 0050  20 00 00 00 20 00 00 00 20 00 00 00 00 00 00 00
 0060  20 00 00 00 01 10 00 1c 01 00 00 00 a0 a1 a2 a3   블록 0x0110 (!)
 0070  a4 a5 a6 a7 a8 a9 aa ab ac ad ae af 00 01 00 00
 0080  00 02 00 00                                        ApplicationReady
```

사양 형태 요점 [사양 확인 필요 포함]:

- RPC: rpc_vers 4, ptype request, **interface UUID = Controller 인터페이스 `DEA00002-6C97-11D1-8271-00A02442DF7D`**,
  object UUID = Connect 의 `CMInitiatorObjectUUID`, 새 activity UUID, opnum 4.
- 블록: **`0x0112` IOXControlReq**, ControlCommand=ApplicationReady (scapy 생성 예:
  `01 12 00 1c 01 00 00 00 a0..af 00 01 00 00 00 02 00 00`).
- 목적지: 컨트롤러 IP 의 RPC 서버 포트 [사양 확인 필요: 34964 고정인지, 다른 규칙인지]. 컨트롤러가
  `0x8112`(Done)로 답할 때까지 재시도.
- NDR 요청 헤더(ArgsMaximum…)가 붙는다.

**[차이]** 이 저장소는 rpc_vers=1, UUID 0, 블록 `0x0110` 으로 만들고 ([pn_rpc.c:426-457](../../stacks/profinet/src/pn_rpc.c)),
**마지막으로 RPC 를 받은 주소:포트(=컨트롤러의 임시 클라이언트 포트)** 로 한 번 보낸다(재시도·응답 확인 없음,
[pn_rpc.c:469-477, 703-712](../../stacks/profinet/src/pn_rpc.c)). 그리고 **보내기도 전에** `ar.app_ready=1` 로 둔다.

#### 5.d.9 Release

사양: opnum 1, 블록 `0x0114` ReleaseBlockReq (Control 과 같은 본문, ControlCommand=Release `0x0004`),
응답 `0x8114` ControlCommand=Done.

**[차이, 검증: 하네스]** 이 저장소는 ARUUID 를 `parse_uuid_any` 로 찾는데, 이 함수는 `0x0101/0x0110/0x0009/0x0008`
블록만 본다 ([pn_rpc.c:157-172](../../stacks/profinet/src/pn_rpc.c)). `0x0114` 는 못 찾고, 대체 경로로 "스텁+20 의 16바이트를
raw UUID 로" 읽는데(line 566-570) 그 자리는 블록 헤더라 UUID 가 틀리고 → `-EPERM` → **응답 없음, AR 유지**.
하네스: `Release(0x0114) rc=-1 ar=1`, CTT 형태(`0x0101` 블록) `rc=0 ar=0`. 실 컨트롤러의 정상 해제는 결국
data-hold/CMI 타임아웃으로만 정리된다. 응답은 4바이트 0 이다([pn_rpc.c:578-579](../../stacks/profinet/src/pn_rpc.c)).

### 5.e RT Class 1 주기 프레임

#### 5.e.1 구조

```
 +--------+--------+[VLAN 0x8100 TCI]+--------+-----------+----------------------------+---------+----------+----------+
 | Dst 6  | Src 6  |   (보통 PCP 6)   | 0x8892 | FrameID 2 | C_SDU (DataLength, ≥40)    | CycleCnt| DataStat | TransStat|
 |        |        |                  |        |  0x8xxx   | 데이터+IOPS+IOCS+패딩       |   2     |    1     |    1     |
 +--------+--------+------------------+--------+-----------+----------------------------+---------+----------+----------+
                                                                                        |<---- APDU Status 4B ------->|
```

- Dst: Input CR 은 **CMInitiatorMacAdd**(컨트롤러), Output CR 은 디바이스 MAC.
- 이 저장소 송신 목적지: `ar.initiator_mac` ([pn_rt.c:132-136](../../stacks/profinet/src/pn_rt.c)). 맞다.

#### 5.e.2 DataStatus 비트 [검증: scapy `dataStatus` 플래그 정의, 기본값 `0x35`]

| bit | 이름 | 1 의 의미 | 0 의 의미 |
|-----|------|-----------|-----------|
| 0 | State | Primary | Backup |
| 1 | Redundancy | (이중화 관련) | — |
| 2 | DataValid | 유효 | 무효 |
| 3 | reserved | | |
| 4 | **ProviderState** | **Run** | **Stop** |
| 5 | StationProblemIndicator | 정상 (no problem) | 문제 감지 |
| 6 | reserved | | |
| 7 | Ignore | 평가하지 말 것 | 평가 |

정상 운전값은 **`0x35`** = Primary | DataValid | Run | NoProblem.

**[차이, 검증: 하네스 + scapy]** 이 저장소는 `PN_DATASTATUS_RUN` 을 `0x20` 으로 정의해
([pn_types.h:76-78](../../stacks/profinet/include/pn_types.h)) `0x01|0x04|0x20 = 0x25` 를 보낸다
([pn_rt.c:128-129](../../stacks/profinet/src/pn_rt.c)). scapy 해석: `primary+validData+no_problem` — **Run 비트가 없다**,
즉 "Provider **Stop**". 컨트롤러는 입력을 "정지 상태 제공자"로 볼 수 있다. 수정은 `0x10` 비트 추가(=`0x35`)지만,
이 문서는 기록만 한다.

TransferStatus: RT_CLASS_1 에서는 `0x00` [사양 확인 필요].

#### 5.e.3 CycleCounter

16비트, 31.25µs 단위의 송신 시각. 한 프레임마다 **SCF × RR** 만큼 증가하는 것이 일반적 해석이다
(예: 1ms 주기면 +32) [사양 확인 필요]. 수신 측은 값이 멈추거나 되돌아가면 "오래된 프레임"으로 판단할 수 있다.
**[차이]** 이 저장소는 프레임마다 `+1` ([pn_rt.c:126](../../stacks/profinet/src/pn_rt.c)). CTT 의 `cycle_counter: increasing`
검사는 증가 여부만 본다 ([docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 5장).

#### 5.e.4 예제

이 저장소의 입력 프레임 (입력 이미지 = `00 01 … 1f`) **[검증: 하네스 + scapy]**:

```
 0000  00 11 22 33 44 55 02 fb 00 00 00 01 88 92 80 01
 0010  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f     입력 32B
 0020  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
 0030  80 00 00 25 00                                      IOPS=80 | CycleCounter=0000 | DataStatus=25 | Transfer=00
```

총 53바이트: C_SDU 33B(<40), IOCS 없음, 패딩 없음, 태그 없음.

사양 형태의 출력 프레임 (컨트롤러→디바이스, 5.4 레이아웃) — 이 저장소가 정상 소비함 **[검증: 하네스]**:

```
 0000  02 fb 00 00 00 01 00 11 22 33 44 55 88 92 80 02
 0010  b0 b1 b2 b3 b4 b5 b6 b7 80 80 00 00 00 00 00 00     출력 8B | IOPS | IOCS | 패딩...
 0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 0030  00 00 00 00 00 00 00 00 04 00 35 00                 CycleCounter=0x0400 | DataStatus=0x35 | 00
```

하네스: 이 프레임을 넣은 뒤 `output_image = b0 b1 b2 b3 b4 b5 b6 b7`.
최소 길이 검사는 `2 + data_len + 1 + 4 ≤ payload` 뿐이다 ([pn_rt.c:83](../../stacks/profinet/src/pn_rt.c)).

### 5.f Alarm (RTA) 프레임

알람은 "놓치면 안 되는" 이벤트라 **ACK 기반**의 RTA(Real-Time Acyclic) 프로토콜로 보낸다.

```
 FrameID (FC01 High / FE01 Low)
 AlarmDstEndpoint (2)   ← 상대의 LocalAlarmReference (Connect 의 AlarmCRBlockReq)
 AlarmSrcEndpoint (2)   ← 나의 LocalAlarmReference (AlarmCRBlockRes 로 알려준 값)
 PDUType (1)            ← 하위 니블 Type: 1 DATA, 2 NACK, 3 ACK, 4 ERR; 상위 니블 Version (1)
 AddFlags (1)           ← WindowSize(하위 니블)=1, TACK 비트 [사양 확인 필요: 비트 위치]
 SendSeqNum (2)         ← 0x0000~0x7FFF 순환 [사양 확인 필요: 초기값]
 AckSeqNum (2)
 VarPartLen (2)         ← 뒤따르는 블록 길이
 AlarmNotification 블록 (0x0001 High / 0x0002 Low):
   AlarmType(2) API(4) Slot(2) Subslot(2) ModuleIdentNumber(4) SubmoduleIdentNumber(4) AlarmSpecifier(2) [USI(2)+데이터]
```

[검증: scapy `PNIORealTimeAcyclicPDUHeader`, `AlarmNotificationPDU` 필드 순서]

scapy 로 만든 사양 형태 예 (Diagnosis 알람, slot1/subslot1; VarPartLen 은 26 = `00 1a` 로 채워야 함 — scapy 가
자동 계산하지 않아 아래 덤프에는 `00 00` 으로 나옴):

```
 fc 01 | 00 01 | 00 02 | 11 | 11 | 00 00 | ff ff | 00 1a
 | 00 01 00 16 01 00 | 00 01 (Diagnosis) | 00 00 00 00 | 00 01 | 00 01 | 00 00 00 10 | 00 00 00 11 | 00 00
```

AlarmType 대표값 [사양 확인 필요]: `0x0001` Diagnosis, `0x0002` Process, `0x0003` Pull, `0x0004` Plug, `0x0005` Status,
`0x0006` Update, `0x000C` Diagnosis disappears. USI `0x8000` = ChannelDiagnosis, `0x8002` ExtChannelDiagnosis,
`0x0000`–`0x7FFF` 제조사 정의.

이 저장소의 알람 (**더미**) **[검증: golden `alarm_low.pcap`, 하네스]**:

```
 0000  00 11 22 33 44 55 02 fb 00 00 00 01 88 92 fc 01
 0010  00 01 00 01 01 00 00 01 00 00 00 0c 00 01 00 00
 0020  00 01 80 00 00 00 00 00 00 00 00 00 00 00
```

`dst=1, src=1, PDUType=0x01(버전 니블 0), AddFlags=0, SendSeq=1, AckSeq=0, VarPartLen=12`, 그 뒤 `00 01 00 00 00 01 80 00`
+ 0 패딩. 코드 주석대로 "Minimal RTA AlarmNotification. Not a full PI alarm state machine."
([pn_sec.c:39-52](../../stacks/profinet/src/pn_sec.c)). 사양 파서로 보면 블록 헤더(`00 01` 타입, 길이 `00 00`)부터
깨진다. ACK 수신·재전송·시퀀스 관리·엔드포인트 협상이 없다 — [docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 3.2 도
"dummy TX 만"이라 명시한다. 코드 주석의 "manufacturer-specific USI" 는 `0x8000` 인데, 이 값은 표준 ChannelDiagnosis
USI 다.

---

## 6. 동작과 상태

### 6.1 Device 상태 기계 (AR 수립 단계)

사양 수준의 일반적 흐름(CMDEV 상태기계의 단순화, [사양 확인 필요 — IEC 61158-6-10 CMDEV]):

```
            +-----------+   Connect.req 수락     +-------------+  Write.req*    +-------------+
  전원 ON → |  W_CIND   | --------------------> |  W_PRMEND   | -------------> |  W_PRMEND   |
 (이름/IP)  | (AR 없음) |   Connect.res 송신     | RT 시작      |                |             |
            +-----------+   provider/consumer   +-------------+                +------+------+
                 ^           시작                                                     | PrmEnd.req
                 |                                                                    v
                 |                                                             +-------------+
                 |   Release / Abort / 타임아웃                                  |  W_ARDY     | 파라미터 적용
                 +<------------------------------------------------------------+ (Done 응답) |
                 |                                                             +------+------+
                 |                                                                    | AppReady.req 송신
                 |                                                                    v
                 |                                                             +-------------+
                 |                                                             | W_ARDY_CNF  |
                 |                                                             +------+------+
                 |                                                                    | AppReady.res(Done) 수신
                 |                                                                    v
                 |                                                             +-------------+
                 +<---------------------- Release / Abort / data-hold 만료 ---- |    DATA     | 정상 교환
                                                                               +-------------+
```

**이 저장소의 상태 표현** — 상태기계가 아니라 플래그 모음이다 ([pn_internal.h:16-36](../../stacks/profinet/include/pn_internal.h)):

| 플래그 | 켜지는 곳 | 의미 |
|--------|-----------|------|
| `established` | Connect 수락 ([pn_rpc.c:538](../../stacks/profinet/src/pn_rpc.c)), Control 처리 시 재설정 ([pn_rpc.c:614](../../stacks/profinet/src/pn_rpc.c)) | AR 존재. `pn_stack_ar_up()` 이 이 값을 돌려준다 |
| `prm_end` | PrmEnd 수신 ([pn_rpc.c:617](../../stacks/profinet/src/pn_rpc.c)) | |
| `app_ready` | PrmEnd 직후 AppReady 요청을 **큐에 넣을 때** ([pn_rpc.c:455](../../stacks/profinet/src/pn_rpc.c)), 또는 AppReady 명령 수신 시 | 컨트롤러 확인과 무관 |
| `saw_rt` | 일치하는 출력 RT 프레임 첫 수신 ([pn_rt.c:89](../../stacks/profinet/src/pn_rt.c)) | 컨트롤러 생존 증거 |

- RT 송신은 `established` 가 되는 즉시 시작한다 (`s->last_rt_ns = 0` → 다음 poll 에서 바로 송신,
  [pn_rpc.c:545](../../stacks/profinet/src/pn_rpc.c), [pn_rt.c:105](../../stacks/profinet/src/pn_rt.c)).
- W_ARDY_CNF 에 해당하는 "컨트롤러의 AppReady 응답 대기"가 없다.
- 어댑터의 `health()` 는 `established` 를 `connected` 로 보고한다 ([profinet_adapter.c:299-306](../../adapters/profinet/profinet_adapter.c)).

### 6.2 타이밍 계산

```
 SendClock      = SendClockFactor × 31.25 µs
 UpdateTime     = SendClock × ReductionRatio               (= 이 IOCR 의 프레임 간격)
 WatchdogTime   = UpdateTime × WatchdogFactor
 DataHoldTime   = UpdateTime × DataHoldFactor              (이 시간 동안 새 데이터가 없으면 소비자가 반응)
```

| SCF | RR | UpdateTime | ×3 (WDF/DHF=3) | 비고 |
|-----|----|------------|----------------|------|
| 32 | 1 | 1 ms | 3 ms | 흔한 기본값. 이 저장소 A-core Linux 에는 가혹 |
| 32 | 2 | 2 ms | 6 ms | |
| 32 | 4 | 4 ms | 12 ms | CTT `rtc1_cycle_4ms.yaml` 이 가정하는 주기 |
| 32 | 8 | **8 ms** | **24 ms** | **이 저장소 기본 `cycle_us=8000` 과 맞는 값** |
| 32 | 32 | 32 ms | 96 ms | 이 문서 Connect 예제, `test_data_hold_iocr_cycle` |
| 32 | 128 | 128 ms | 384 ms | |

- RT_CLASS_1 의 RR 은 2의 거듭제곱(1…512), SCF 는 장치가 GSDML 에서 지원한다고 밝힌 값 중에서 고른다
  [사양 확인 필요: 허용 범위와 DataHoldTime 상한].
- **Phase / Sequence / FrameSendOffset** 은 RR>1 일 때 여러 IOCR 의 송신 시점을 흩는 값이다. RT_CLASS_1 에서
  FrameSendOffset `0xFFFFFFFF` 는 "최선 노력"이다.
- **양방향이 독립**이다. 디바이스는 **Input CR 의** SCF×RR 로 **보내야** 하고, **Output CR 의** SCF×RR×DHF 로
  컨트롤러를 **감시**한다. 컨트롤러는 그 반대.

**이 저장소** — 두 방향이 다른 시계를 쓴다:

| 방향 | 사용 주기 | 근거 |
|------|-----------|------|
| 송신(Input CR) | **`cfg.cycle_us`** (Connect 의 Input CR SCF/RR 무시) | [pn_rt.c:99-102](../../stacks/profinet/src/pn_rt.c) |
| 감시(Output CR) | Output CR 의 SCF×RR×31.25µs×(DHF, 없으면 WDF, 없으면 3) | [pn_rt.c:56-60](../../stacks/profinet/src/pn_rt.c), [pn_rpc.c:257-269](../../stacks/profinet/src/pn_rpc.c) |

즉 **`cycle_us` 와 컨트롤러 프로젝트의 update time 을 사람이 일치시켜야 한다.** 컨트롤러가 1ms 를 요구했는데
디바이스가 8ms 마다 보내면, 컨트롤러 워치독(예: 3ms)이 끊는다.

### 6.3 사이클릭 송신 스케줄링

좋은 주기 송신기의 요건: (1) **절대 시각 기준**으로 다음 송신 시각을 잡아 오차가 누적되지 않게, (2) 늦었을 때
밀린 프레임을 **몰아서(burst) 보내지 않게**.

이 저장소 `pn_rt_send_if_due` ([pn_rt.c:93-148](../../stacks/profinet/src/pn_rt.c)):

```c
if (last_rt_ns != 0 && now < last_rt_ns) return;     /* 아직 때가 아님 */
... 프레임 송신 ...
if (last_rt_ns == 0)        last_rt_ns = now + period; /* 첫 송신: 위상 고정 */
else {
    last_rt_ns += period;                              /* 절대 위상 유지 */
    if (last_rt_ns <= now) last_rt_ns = now + period;  /* 밀렸으면 재동기, 몰아보내기 없음 */
}
```

`last_rt_ns` 는 이름과 달리 "다음 송신 예정 시각"이다 ([pn_internal.h:70](../../stacks/profinet/include/pn_internal.h)).
이 함수는 `pn_stack_poll` 안에서만 불리고, poll 은 코어가 `cycle_ms` 마다 부른다. 따라서:

- `cycle_us` < `cycle_ms×1000` 이면 실제 주기는 poll 주기로 끌려 내려간다(poll 당 최대 1프레임).
- poll 이 주기에 딱 맞춰 오지 않으면 `now < last_rt_ns` 로 한 번 건너뛰어 **주기가 2배**가 될 수 있다
  (poll 과 송신 예정 시각이 같은 주기에서 미세하게 어긋나는 경우). CTT 가 `late_cycles`/`missed_cycles` 를
  재는 이유다 ([docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 5장). 8ms 에이징 결과 최대 편차 0.1ms
  ([CLAUDE.md](../../CLAUDE.md)).

### 6.4 수신 감시, 타임아웃, AR abort

사양상 디바이스가 감시할 것:

1. **Output CR data-hold**: DataHoldTime 동안 유효한 출력 프레임이 없으면 출력을 대체값(안전값)으로 두고,
   AR 을 중단(abort)한다 [사양 확인 필요: 대체값 동작과 abort 의 순서].
2. **CMI activity**: Connect 후 컨트롤러가 PrmEnd 까지 가지 않고 사라지면
   `CMInitiatorActivityTimeoutFactor × 100ms` 뒤 AR 을 버린다 [사양 확인 필요].
3. **RPC 재시도/Alarm ACK 타임아웃**: RTATimeoutFactor × 100ms 등.

이 저장소 `pn_ar_watchdog` ([pn_rt.c:28-67](../../stacks/profinet/src/pn_rt.c)):

```
 if (!established) return
 live = saw_rt || prm_end || app_ready                  # "컨트롤러가 살아 있음" 증거 (자기 송신은 제외)
 if (!live):
     if now - last_cmi_ns > 2 s:  abort("CMI activity timeout")
     return
 if (SCF == 0 || RR == 0):                              # Output CR 시계를 모름
     base = max(last_cmi_ns, last_rt_rx_ns)
     if now - base > 2 s: abort("CMI activity timeout")
     return
 hold = SCF × RR × 31.25µs × (DHF | WDF | 3)
 base = saw_rt ? last_rt_rx_ns : last_cmi_ns
 if now - base > hold: abort("RT data-hold timer expired")
```

- `last_cmi_ns` 는 Connect, Read/Write/Control 수신 때 갱신된다 (`ar_touch_cmi`, [pn_rpc.c:200-203](../../stacks/profinet/src/pn_rpc.c)).
- 2초는 상수 `PN_CMI_ACTIVITY_TIMEOUT_NS` ([pn_internal.h:48](../../stacks/profinet/include/pn_internal.h)) —
  Connect 의 ActivityTimeoutFactor 를 쓰지 않는다 **[차이]**. 실 컨트롤러가 Connect 후 파라미터 쓰기에 2초 넘게
  걸리면(모듈 많을 때) AR 이 중간에 사라질 수 있다.
- abort 는 AR 구조체를 0 으로 지울 뿐 ([pn_rt.c:8-20](../../stacks/profinet/src/pn_rt.c)) 컨트롤러에 알리지 않고,
  **출력 이미지를 안전값으로 바꾸지도 않는다** — 앱은 마지막 출력값을 계속 읽는다(13장).
- 감시 해상도는 poll 주기다. data-hold 24ms 에 poll 8ms 면 최대 ~32ms 후 감지.
- 설계 의도는 헤더 주석에 정리돼 있다 ([pn_internal.h:38-45](../../stacks/profinet/include/pn_internal.h)), 단위
  테스트: `test_data_hold_iocr_cycle`, `test_no_iocr_clock_still_reclaims`, `test_cmi_ignores_own_tx`
  ([tests/test_pn_rpc.c:444-588](../../tests/test_pn_rpc.c)).

### 6.5 IOPS / IOCS 의 의미

| 상황 | 누가 무엇을 | 받는 쪽이 할 일 |
|------|-------------|-----------------|
| 센서 고장 | Device 가 입력 IOPS=BAD | 컨트롤러는 그 입력을 쓰지 않음 (대체값) |
| PLC STOP | Controller 가 출력 IOPS=BAD, DataStatus ProviderState=Stop | Device 는 출력을 안전 상태로 |
| Device 가 출력을 못 씀 | Device 가 (입력 프레임 안의) 출력용 IOCS=BAD | 컨트롤러 진단 |
| 컨트롤러가 입력을 못 씀 | Controller 가 (출력 프레임 안의) 입력용 IOCS=BAD | Device 진단 |

**이 저장소**: 송신 IOPS 는 항상 `0x80`, IOCS 는 보내지 않고, 수신한 IOPS/IOCS/DataStatus 는 보지 않는다
([pn_rt.c:69-91, 125](../../stacks/profinet/src/pn_rt.c)). 앱이 "출력이 유효한가"를 알 방법은 `pn_stack_ar_up()` 뿐이다.

### 6.6 재연결과 AR 교체

- 사양: 한 장치는 여러 AR(예: IOCAR + Supervisor AR)을 가질 수 있고, 장치가 지원하는 AR 수는 GSDML 에 적는다
  [사양 확인 필요].
- 이 저장소: **단일 AR**. AR 이 있을 때 새 Connect 가 오면
  - 같은 컨트롤러(같은 송신 IP 또는 같은 CMInitiatorObjectUUID)면 **교체** ("same-controller Connect replaces
    established AR", [pn_rpc.c:522-544](../../stacks/profinet/src/pn_rpc.c)),
  - 아니면 거부 (에러 응답, 9.4).
- 거부된 Connect 는 기존 AR 을 건드리지 않는다 — 임시 구조체에 파싱 후 마지막에 대입
  ([pn_rpc.c:506-544](../../stacks/profinet/src/pn_rpc.c), 테스트 `test_connect_reject_keeps_ar`).
- Release/Control/Read/Write 는 AR 이 있으면 **송신 IP 가 AR 소유자와 같고**, 블록 안의 ARUUID 가 같아야 한다
  (`ar_owner_ok`, `ar_uuid_ok`, [pn_rpc.c:174-214](../../stacks/profinet/src/pn_rpc.c)). mock 경로는 IP=0 이라 IP 검사 생략.
- CTT 시나리오: `rpc_ar_lifetime.yaml`(Connect→IO→Release→재Connect), `rpc_ar_replace.yaml`.

### 6.7 NameOfStation 저장과 초기화

- 사양: BlockQualifier=1(영구) 로 Set 된 이름/IP 는 **전원이 꺼져도 유지**돼야 한다(비휘발 저장).
  "Reset to Factory"(Control 0x05/0x06) 는 이름·IP·I&M1-4 등을 공장값으로 되돌린다 [사양 확인 필요: 대상 목록].
  AR 이 살아 있는 동안의 Set 처리(거부 여부)도 규칙이 있다 [사양 확인 필요].
- **이 저장소**: 이름/IP 는 `cfg` (RAM) 에만 있고 재시작하면 config JSON 값으로 돌아간다. BlockQualifier 는 무시
  ([pn_dcp.c:263-265](../../stacks/profinet/src/pn_dcp.c) 는 앞 2바이트를 건너뛸 뿐). Reset to Factory 미구현. AR 중에도 Set 허용.

### 6.8 Signal (깜빡임)

기술자가 캐비닛 앞에서 "어느 게 `press-7` 이지?" 할 때 툴에서 Signal 을 보내면 해당 장치 LED 가 깜빡인다.
이 저장소는 로그만 남기는 스텁이다 ([pn_dcp.c:285-286](../../stacks/profinet/src/pn_dcp.c)). 구현하려면 GPIO/LED
훅을 어댑터 인터페이스 밖(예: 스택 콜백)으로 노출해야 한다.

### 6.9 Hello 와 Fast Start-Up

FSU(Fast Start-Up)는 도구 교체가 잦은 로봇 셀 등에서 전원 투입 후 수백 ms 안에 AR 을 세우는 옵션 기능이다.
장치는 켜지자마자 DCP Hello 를 보내고, 컨트롤러는 Identify 없이 바로 Connect 한다. 이 저장소는 FSU 미구현
([docs/ctt_pi_matrix.md](../ctt_pi_matrix.md) "Fast Start-Up: DUT not implemented") 이지만 Hello 송신 함수는 있다
(`pn_dcp_send_hello`, [pn_dcp.c:574-585](../../stacks/profinet/src/pn_dcp.c)) — Set IP 후와 CTT 에서만 호출된다.

---

## 7. SNMP / I&M / 진단

### 7.1 SNMP — CC-B 의 네트워크 진단

CC-B 는 SNMP 에이전트(v1)로 MIB-II(system, interfaces), LLDP-MIB(로컬/원격 이웃 정보), PNO 확장 MIB 을
제공해 **툴이 토폴로지와 포트 상태를 읽게** 하는 것을 요구한다 [사양 확인 필요: 필수 객체 목록].

**이 저장소** (`pn_snmp_handle`, [pn_snmp.c:53-106](../../stacks/profinet/src/pn_snmp.c)): **요청을 해석하지 않는다**
(`(void)req; (void)len;`). 무엇이 오든 같은 GetResponse 를 만든다 **[검증: 하네스]**:

```
 30 2d                                  SEQUENCE, 45B
    02 01 00                            version = 0 (SNMPv1)
    04 06 70 75 62 6c 69 63             community "public"
    a2 20                               GetResponse-PDU
       02 01 01                         request-id = 1 (고정!)
       02 01 00                         error-status 0
       02 01 00                         error-index 0
       30 15 30 13                      VarBindList / VarBind
          06 08 2b 06 01 02 01 01 05 00 OID 1.3.6.1.2.1.1.5.0 (sysName.0)
          04 07 70 72 65 73 73 2d 37    OCTET STRING "press-7" (현재 NameOfStation)
```

**[차이]** request-id 를 요청에서 복사하지 않으므로 일반 SNMP 매니저(net-snmp 등)는 응답을 자기 요청과 짝지을 수
없어 버린다. 요청한 OID 가 무엇이든 sysName 을 돌려주므로 GetNext 워크는 끝나지 않는다. BER 길이는 1바이트형만
쓴다(255 초과 불가, [pn_snmp.c:10-19](../../stacks/profinet/src/pn_snmp.c)). CTT `snmp_get_sysname.yaml` 은 이 동작을 고정한다.

### 7.2 I&M (Identification & Maintenance)

| 레코드 | Index | 내용 (바이트) | 쓰기 | 이 저장소 |
|--------|-------|---------------|------|-----------|
| **I&M0** | `0xAFF0` | VendorID 2, OrderID 20, SerialNumber 16, HardwareRevision 2, SoftwareRevision 4(`'V'`,x,y,z), RevisionCounter 2, ProfileID 2, ProfileSpecificType 2, IM_Version 2(major,minor), IM_Supported 2 = **54** | 읽기 전용 | 고정값 ([pn_record.c:34-56](../../stacks/profinet/src/pn_record.c)) |
| I&M1 | `0xAFF1` | TagFunction 32 + TagLocation 22 = 54 | R/W | RAM, 공백 초기화 |
| I&M2 | `0xAFF2` | InstallationDate 16 (`"YYYY-MM-DD hh:mm"`) | R/W | RAM |
| I&M3 | `0xAFF3` | Descriptor 54 | R/W | RAM |
| I&M4 | `0xAFF4` | Signature 54 (바이너리) | R/W | RAM, 0 초기화 |

- 레코드로 주고받을 때 각 I&M 데이터는 BlockHeader(`0x0020`~`0x0024`, 버전 1.0)로 감싼다 [검증: scapy `IM0Block`..`IM4Block`].
- IM_Supported 비트 1~4 = I&M1~4 지원. 이 저장소 `0x001E` 는 I&M1–4 모두 지원 표시.
- ProfileID `0xF600` = Generic Device [사양 확인 필요], IM_Version `0x0101` = 1.1.
- I&M0 은 모든 PROFINET 장치 필수, I&M1–3 은 CC-B 등에서 요구될 수 있음, 값은 **비휘발 저장** [사양 확인 필요].
- 이 저장소 쓰기 경로는 "앞에 6바이트 BlockHeader(타입 `0x0020`~`0x0030`)가 있으면 떼고" 저장한다
  (`im_payload`, [pn_record.c:12-23](../../stacks/profinet/src/pn_record.c)). 읽기는 헤더 없이 raw 를 준다.
- 컨트롤러/툴은 `0xF840` I&M0FilterData 로 "어느 서브모듈이 I&M 을 갖나"를 먼저 읽는 경우가 많다 [사양 확인 필요].
  이 저장소는 모르는 인덱스에 4바이트 0 을 준다.

### 7.3 진단 (Diagnosis)

PROFINET 진단은 (1) **Diagnosis 알람**(AlarmType 1, USI 0x8000 ChannelDiagnosis: 채널 번호·에러 타입)으로 "지금
생겼다/사라졌다"를 푸시하고, (2) **진단 레코드**(예: `0x800A` 등 [사양 확인 필요])로 현재 목록을 읽게 하며, (3)
RT DataStatus 의 StationProblemIndicator 로 "뭔가 있음"을 알린다.

이 저장소: 진단 레코드·ChannelDiagnosis·진단 상태 관리 **미구현**. 알람은 더미 송신 API(`pn_stack_send_alarm`,
`pn_stack_send_alarm_ex`, [pn_stack.c:194-202](../../stacks/profinet/src/pn_stack.c))뿐이고 어댑터는 이를 호출하지 않는다.

---

## 8. Security Class 1

### 8.1 PI 의 PROFINET Security Class 1 / 2 / 3

PI 는 PROFINET 보안을 단계로 정의한다 (IEC 62443 방법론 기반). 대략 [사양 확인 필요 — PI "PROFINET Security"
사양/가이드라인 원문 대조]:

| Class | 목표 | 대표 수단 |
|-------|------|-----------|
| **Class 1** | **견고성(robustness)** — 암호 없이 오조작·손쉬운 공격 줄이기 | 서명/해시된 GSDML, DCP 설정 **쓰기 보호(read-only 모드)**, SNMP 기본 community 제한/비활성, 네트워크 부하 견고성(Netload class) |
| **Class 2** | **무결성 + 진위성(integrity & authenticity)** | 인증서 기반 인증, 주기/비주기/알람 통신 무결성 보호 |
| **Class 3** | + **기밀성(confidentiality)** | 암호화 |

### 8.2 이 저장소의 "Security Class 1" — 자체 HMAC 프로파일

이 저장소는 "Security Class 1" 이라는 이름으로 **HMAC-SHA256 PSK 무결성**을 DCP Set 과 CM Connect 에 요구한다.
문서 스스로 "PI 옵션 코드를 사칭하지 않는다. 이 저장소 프로파일이다" 라고 밝힌다
([docs/profinet_stack.md:16-30](../profinet_stack.md), [docs/ctt_pi_matrix.md](../ctt_pi_matrix.md) "Security lab profile").

| 항목 | 값 | 근거 |
|------|----|------|
| 알고리즘 | HMAC-SHA256 (자체 구현, RFC 4231 case 1 테스트) | [pn_crypto.c:134-167](../../stacks/profinet/src/pn_crypto.c), [tests/test_pn_crypto.c](../../tests/test_pn_crypto.c) |
| 키 | 32바이트 PSK, `protocol_params.psk_hex` (64 hex) | [profinet_adapter.c:46-61, 172-183](../../adapters/profinet/profinet_adapter.c) |
| 태그 | 32바이트, 상수 시간 비교 `pn_ct_eq` | [pn_sec.c:20-28](../../stacks/profinet/src/pn_sec.c), [pn_endian.h:57-64](../../stacks/profinet/include/pn_endian.h) |
| DCP Set | Option `0xF0` / Suboption `0x01`, 길이 32 블록 필수 | [pn_types.h:32-34](../../stacks/profinet/include/pn_types.h), [pn_dcp.c:164-249](../../stacks/profinet/src/pn_dcp.c) |
| CM Connect | BlockType `0x0E01`, 본문 = AlgID(2) + HMAC(32) | [pn_types.h:61](../../stacks/profinet/include/pn_types.h), [pn_rpc.c:280-326](../../stacks/profinet/src/pn_rpc.c) |
| 서명 안 함 | DCP Identify/Get, Hello, Read/Write/Control/Release RPC, RT, Alarm, LLDP, SNMP | 코드상 검증 경로 없음 |
| 켜는 법 | `security_class: 1` + `psk_hex` (어댑터 기본값이 1!), 또는 `enforce_security_class: true`, 또는 CMake `-DPN_ENFORCE_SECURITY_CLASS=ON` | [profinet_adapter.c:124, 161-171, 199-204](../../adapters/profinet/profinet_adapter.c), [pn_stack.c:54-65](../../stacks/profinet/src/pn_stack.c), [CMakeLists.txt:14-15, 60-61](../../CMakeLists.txt) |

주의: 어댑터는 `security_class` 를 명시하지 않으면 **1** 로 두고, 그때 `psk_hex` 가 없으면 init 이 `-EINVAL` 로
실패한다 ([profinet_adapter.c:124, 199-204](../../adapters/profinet/profinet_adapter.c)).

#### 8.2.1 DCP Set 서명 범위 (정확히)

송신자(툴/CTT)는:

1. 보안 블록 **없이** DCP PDU 를 만든다: `FrameID … DCPDataLength(보안 블록 제외 길이) + 블록들(패딩 포함)`.
2. 그 바이트 전체(FrameID 부터 마지막 블록 패딩까지, **이더넷 헤더 제외**)에 HMAC-SHA256(PSK) 을 계산.
3. `F0 01 00 20 <32B 태그>` 블록을 덧붙이고 DCPDataLength 를 늘린다.

(CTT 구현: [pn_plugin.c:455-469](../../tools/ctt/proto/profinet/pn_plugin.c).)

수신자(`extract_hmac_and_body`, [pn_dcp.c:164-225](../../stacks/profinet/src/pn_dcp.c))는 보안 블록을 빼고 헤더를
다시 쓰며(DCPDataLength 를 "보안 블록 제외"로 재계산) 같은 바이트열을 복원해 HMAC 을 비교한다. 보안 블록은
블록 목록 **어디에 있어도** 된다(빼고 나머지를 순서대로 이어 붙임).

예제 — 이름 `line-b01` 을 서명해 설정, PSK = `0x11` × 32 **[검증: 하네스]**:

```
 0000  02 fb 00 00 00 01 00 11 22 33 44 55 88 92 fe fd
 0010  04 00 aa bb cc dd 00 00 00 32 02 02 00 0a 00 01     DCPDataLength=50 | Name 블록(Qualifier 1)
 0020  6c 69 6e 65 2d 62 30 31 f0 01 00 20 6a 86 91 b9     "line-b01" | 보안 블록 F0/01 len 32
 0030  c4 15 41 06 76 16 64 af 16 7b 4d 67 d5 9c 0a 8e
 0040  9c 9d 79 26 6f 29 5c 9d 45 b8 95 97
```

HMAC 입력(26바이트) = `fe fd 04 00 aa bb cc dd 00 00 00 0e 02 02 00 0a 00 01 6c 69 6e 65 2d 62 30 31`
(DCPDataLength 가 `00 0e` 인 점에 주의). 응답은 성공(`… 05 04 00 03 02 02 00 00`). 태그 1비트만 바꿔도
ServiceType 5 + BlockError 3 으로 거부된다(5.b.8).

#### 8.2.2 Connect 서명 범위

`verify_connect_sec` 는 NDR 뒤 블록 영역을 걸으며 `0x0E01` 블록을 뺀 **나머지 블록 바이트(각 블록의 짝수 패딩
포함)를 순서대로 이어 붙인 것**에 HMAC 을 계산한다. RPC 헤더·NDR 헤더는 포함하지 않는다. 태그 위치는 본문 길이에
따라 `off+8`(ver 2 + alg 2 뒤) 또는 `off+6` 이다 ([pn_rpc.c:300-307](../../stacks/profinet/src/pn_rpc.c)).

예제 — ARBlockReq(32B) 하나에 서명, PSK `0x11`×32 **[검증: 하네스]**:

```
 블록들 (NDR 뒤):
 01 01 00 1c 01 00 00 01 a0 a1 … af 00 01 00 11 22 33 44 55     ARBlockReq (HMAC 입력 = 이 32바이트)
 0e 01 00 24 01 00 00 01 b0 f5 6f de 7e b8 49 e4 ea ac 18 8f     Integrity 블록: ver 1.0, AlgID 1,
 f4 00 71 ab 29 f5 32 10 f9 ec 47 bf 74 f7 06 85 56 cc 95 1e     HMAC-SHA256
```

서명 없는 Connect 는 `"Security Class 1: Connect 에 integrity block 없음"` 로그 후 에러 응답(9.4), AR 미수립.

### 8.3 위협 관점의 한계 (이 저장소 프로파일)

| 위협 | 막는가 | 설명 |
|------|--------|------|
| 누군가 툴로 이름/IP 를 바꿈 | O (PSK 모르면) | DCP Set 서명 필수 |
| 무단 Connect 로 출력 장악 | 부분 | Connect 는 서명 필수. 그러나… |
| **재전송(replay)** | **X** | nonce/카운터/시각이 없다. 캡처한 서명 Set/Connect 를 나중에 그대로 다시 보내면 통과. Xid 는 HMAC 에 들어가지만 중복 검사가 없다 |
| Write/Control/Release 위조 | **X** (IP 검사만) | RPC 는 Connect 외 서명 없음. ARUUID 는 평문으로 보이고, 소유자 IP 검사는 UDP 출발지 위조로 우회 가능 |
| **RT 출력 위조** | **X** | 출력 프레임에 인증 없음. 같은 L2 에서 FrameID 와 MAC 만 맞추면 출력 이미지를 바꿀 수 있다 |
| 도청 | X | 암호화 없음 (Class 3 영역) |
| 키 관리 | 약함 | 모든 장치·툴이 같은 PSK 를 공유하는 구조. 예제 config 의 `1111…` 키를 제품에 두면 안 된다 ([docs/profinet_stack.md:22](../profinet_stack.md)) |
| 상호운용 | X | `0xF0` DCP 옵션과 `0x0E01` 블록은 표준 컨트롤러가 보내지 않는다 → `security_class: 1` 이면 TIA/CODESYS 는 이름 설정도 Connect 도 못 한다. 그래서 CODESYS 예제 config 는 `security_class: 0` 이다 ([config/example.codesys.profinet.json](../../config/example.codesys.profinet.json) `_comment`) |

### 8.4 PI 정의와의 관계

| 관점 | PI Security Class 1 | 이 저장소 "Security Class 1" |
|------|---------------------|------------------------------|
| 성격 | 견고성(암호 없음) 기능 모음 | **암호학적 무결성**(성격상 Class 2 쪽) 의 축소판 |
| DCP | Set 쓰기 보호 모드 | Set 에 HMAC 요구 |
| GSDML 무결성 | 요구 | 없음 |
| SNMP | 기본 community 제한 | `"public"` 고정 응답 |
| 상호운용 | 표준 | 비표준(자체 옵션/블록) |
| 인증 | PI 시험 대상 | 해당 없음 |

즉 **이름은 같지만 다른 것**이다. 제품 문서에서 "PROFINET Security Class 1 준수"라고 쓰면 안 된다.
CRA/CE 등 규제 대응도 "제품 프로세스이지 컴파일 플래그가 아니다" ([pn_stack.h:18-19](../../stacks/profinet/include/pn_stack.h)).

---

## 9. 에러 처리와 제한값

### 9.1 PNIOStatus 구조

RPC 응답(및 일부 블록, RTA ERR)은 4바이트 **PNIOStatus** 로 결과를 알린다:

```
  ErrorCode (1) | ErrorDecode (1) | ErrorCode1 (1) | ErrorCode2 (1)
   어느 서비스?    해석 규칙          원인 분류          세부/필드 번호
```

`00 00 00 00` = 성공. ErrorDecode 가 ErrorCode1/2 의 해석 방법을 정한다:

| ErrorDecode | 이름 | ErrorCode1 / ErrorCode2 |
|-------------|------|--------------------------|
| `0x80` | **PNIORW** | 레코드 읽기/쓰기 오류. ErrorCode1 = (ErrorClass<<4)\|ErrorCode (PROFIBUS DPV1 계열), ErrorCode2 = 사용자 정의 |
| `0x81` | **PNIO** | 프로토콜 오류. ErrorCode1 = 문제 블록/계층, ErrorCode2 = 문제 필드 번호 또는 사유 |
| `0x82` | Manufacturer specific | 제조사 정의 |

### 9.2 대표값

(전체 표는 부록 D. 아래 값들은 널리 쓰이는 값이나 최종 구현 전 IEC 61158-6-10 표로 재확인할 것 [사양 확인 필요].)

| 상황 | PNIOStatus |
|------|------------|
| Connect: ARBlockReq 의 필드 n 이 잘못됨 | `DB 81 01 nn` |
| Connect: IOCRBlockReq 오류 | `DB 81 02 nn` |
| Connect: ExpectedSubmoduleBlockReq 오류 | `DB 81 03 nn` |
| Connect: AlarmCRBlockReq 오류 | `DB 81 04 nn` |
| Connect: AR 자원 부족(이미 AR 있음) | `DB 81 40 04` (CMRPC, Out of AR resources) |
| Read: 잘못된 index | `DE 80 B0 00` |
| Read: 잘못된 slot/subslot | `DE 80 B2 00` |
| Write: 길이 오류 | `DF 80 B1 00` |
| Write: 접근 거부 | `DF 80 B6 00` |
| Control: 상태 충돌 | `DD 81 …` |

### 9.3 DCP 의 오류 표현

DCP 는 PNIOStatus 가 아니라 Set.res 의 Control/Response 블록 **BlockError**(5.b.2 표)와 ServiceType 으로 알린다.
Identify 필터 불일치는 **무응답**이 정답이다(멀티캐스트에 "아니오"를 보내지 않는다).

### 9.4 이 저장소의 오류 동작

| 상황 | 동작 | 근거 |
|------|------|------|
| RPC 80바이트 미만 / ptype≠request | 무응답 (`-EINVAL`) | [pn_rpc.c:482-488](../../stacks/profinet/src/pn_rpc.c) |
| 알 수 없는 opnum (5 ReadImplicit 포함) | 무응답 (`-ENOSYS`) | [pn_rpc.c:681-683](../../stacks/profinet/src/pn_rpc.c) |
| Connect: Sec1 검증 실패 / 다른 컨트롤러의 AR 존재 | **에러 응답**: 스텁 = `04 00 00 00 ×3, 0, 04` + `81 00 00 00` | `reply_pnio_err` [pn_rpc.c:459-467](../../stacks/profinet/src/pn_rpc.c) |
| Control/Write: AR 없음 | 무응답, "fail closed" | [pn_rpc.c:582-585, 661-664](../../stacks/profinet/src/pn_rpc.c) |
| Release/Control/Read/Write: IP·ARUUID 불일치 | 무응답 (`-EPERM`) | [pn_rpc.c:555-574, 586-604, 638-645, 665-672](../../stacks/profinet/src/pn_rpc.c) |
| 모르는 레코드 index 읽기 | 성공 + 4바이트 0 | [pn_record.c:94-100](../../stacks/profinet/src/pn_record.c), CTT `record_unknown_index.yaml` |
| DCP 헤더 파싱 실패 / 응답 타입 | 무시 | [pn_dcp.c:503-509](../../stacks/profinet/src/pn_dcp.c) |
| DCP Set 서명 실패 / 이름 규칙 위반 | ServiceType 5 + BlockError 3 | [pn_dcp.c:528-540](../../stacks/profinet/src/pn_dcp.c) |

Connect 에러 응답 **[검증: 하네스]** (NDR 이후):

```
 0050  04 00 00 00 04 00 00 00 04 00 00 00 00 00 00 00
 0060  04 00 00 00 81 00 00 00
```

**[차이]** 사양 파서에는 PNIOStatus=`04 00 00 00`(의미 없는 값)과 길이 4 의 데이터 `81 00 00 00` 로 보인다.
사양 형태라면 PNIOStatus 자리에 `DB 81 xx yy` 가 오고 블록이 없어야 한다. 무응답(`-EPERM`)은 컨트롤러 입장에서
RPC 타임아웃·재시도로 이어진다 — 즉 오류 원인을 알려주지 못한다.

### 9.5 제한값

| 항목 | 이 저장소 | 사양/일반 | 근거 |
|------|-----------|-----------|------|
| IO 이미지 (방향별) | **256 B** (`PN_IO_MAX`) | C_SDU 40~1440 B | [pn_types.h:81](../../stacks/profinet/include/pn_types.h), [pn_stack.c:39-44](../../stacks/profinet/src/pn_stack.c) |
| 기본 입력/출력 길이 | 32 / 8 | GSDML 과 일치 | [pn_stack.c:33-38](../../stacks/profinet/src/pn_stack.c) |
| NameOfStation | 240 | 240 | [pn_types.h:80](../../stacks/profinet/include/pn_types.h) |
| 프레임 버퍼 | 1518 | 이더넷+VLAN | [pn_types.h:82](../../stacks/profinet/include/pn_types.h) |
| RPC 수신/응답 버퍼 | 2048 | 단편화 없음 가정 | [pn_rpc.c:497, 694-705](../../stacks/profinet/src/pn_rpc.c) |
| Connect 응답 블록 | 512 | | [pn_rpc.c:546](../../stacks/profinet/src/pn_rpc.c) |
| Connect HMAC 재조립 | 2048 | | [pn_rpc.c:287](../../stacks/profinet/src/pn_rpc.c) |
| 레코드 읽기 버퍼 | 256 | | [pn_rpc.c:625](../../stacks/profinet/src/pn_rpc.c) |
| 동시 AR | **1** | 장치별 (GSDML) | `pn_ar_t ar` |
| poll 당 이더넷 프레임 | 16 | | [pn_stack.c:244-254](../../stacks/profinet/src/pn_stack.c) |
| poll 당 RPC 데이터그램 | 1 | | [pn_rpc.c:697-712](../../stacks/profinet/src/pn_rpc.c) |
| 지연 Identify 대기열 | 1 | | [pn_internal.h:90-94](../../stacks/profinet/include/pn_internal.h) |
| LLDP 주기 / TTL | 5 s / 20 s | 5 s / 20 s | [pn_stack.c:261-265](../../stacks/profinet/src/pn_stack.c), [pn_lldp.c:40](../../stacks/profinet/src/pn_lldp.c) |
| CMI 활동 타임아웃 | 2 s 고정 | Factor × 100 ms | [pn_internal.h:48](../../stacks/profinet/include/pn_internal.h) |
| 기본 data-hold 배수 | 3 | Connect 값 | [pn_internal.h:47](../../stacks/profinet/include/pn_internal.h) |
| 어댑터 포인트 수 | 64 | — | [profinet_adapter.c:13](../../adapters/profinet/profinet_adapter.c) |
| PSK / HMAC | 32 / 32 B | — | [pn_types.h:83-84](../../stacks/profinet/include/pn_types.h) |

`PN_TXQ_MAX`, `last_rpc_resp[_len]`, `start_ns` 는 정의돼 있지만 실질적으로 쓰이지 않는다(`last_rpc_resp` 는 죽은
콜백 `strip_sec_cb` 에서만 참조, [pn_rpc.c:216-232, 379](../../stacks/profinet/src/pn_rpc.c)).

---

## 10. 직접 구현하기

이 장은 "빈 디렉토리에서 CC-B / RT Class 1 IO Device 를 만드는" 순서다. 각 마일스톤은 **검증 방법**과 함께
적었다. 이 저장소 구조를 참고하되, 11.5 의 차이는 **처음부터 사양대로** 하는 것을 권한다.

### 10.1 모듈 분해

```
 pn_eth      raw 소켓 열기/송수신, 이더넷/VLAN 헤더 파싱·생성, 시간 함수
 pn_dcp      DCP 파서/응답기, NameOfStation 규칙, 영구 저장 훅
 pn_lldp     LLDP 송신(+ 수신·이웃 테이블: CC-B)
 pn_rpc      DCE/RPC CL 헤더, NDR, EPM, 블록 워커, CM 상태기계(Connect/Write/Read/Control/Release)
 pn_ar       AR/IOCR/AlarmCR 모델, 기대 구성 비교, 타이밍 파라미터
 pn_rt       RT 프레임 송신(스케줄러) / 수신(소비자 감시)
 pn_alarm    RTA 송수신, 시퀀스·ACK·재전송, AlarmNotification 빌더
 pn_record   레코드 디스패치 (I&M, 파라미터, 진단, 제조사)
 pn_snmp     SNMPv1 에이전트 + MIB (system, interfaces, LLDP)
 pn_nv       비휘발 저장 (이름, IP, I&M1-4)
 pn_app API  입력 쓰기/출력 읽기, IOPS 설정, 파라미터 콜백, 알람 요청, LED 콜백
```

이 저장소는 `pn_ar`/`pn_alarm`/`pn_nv` 가 따로 없고 `pn_rpc.c`/`pn_rt.c`/`pn_sec.c` 에 섞여 있다(11.1).

### 10.2 마일스톤 로드맵

| # | 목표 | 할 일 | 검증 |
|---|------|-------|------|
| M0 | 개발 환경 | 두 개의 NIC(또는 veth 쌍), Wireshark, `CAP_NET_RAW`. 실 컨트롤러가 있으면 PLC + 스위치 | `ip link add ctl type veth peer name dut` 후 양쪽에서 `tcpdump -e -i dut ether proto 0x8892` |
| M1 | raw 송수신 | `AF_PACKET` 소켓, `0x8892` 필터, VLAN 태그 벗기기, 60바이트 패딩 | 임의 프레임을 보내 반대편 tcpdump 에서 보이기 |
| M2 | DCP Identify 응답 | 헤더 파서, 필터(All/Name/DeviceID), **BlockInfo 포함** 응답, ResponseDelay | Wireshark `pn_dcp` 에서 필드 경고 없이 해석, TIA "Accessible devices"/CODESYS 스캔에 장치 표시 |
| M3 | DCP Set/Get/Signal | Set Name/IP(+Qualifier), 블록마다 Response, BlockError, 규칙 검사, 비휘발 저장, 실제 OS IP 적용 | 툴로 "Assign name"/"Assign IP" → 재부팅 후 유지, Get 이 요청한 것만 응답 |
| M4 | LLDP | Chassis=NameOfStation, Port=`port-001`, TTL 20, 802.3 MAC/PHY TLV, PNO TLV(OUI 00-0E-CF) | Wireshark `lldp` 정상, 스위치/툴 토폴로지 뷰 |
| M5 | RPC 골격 | UDP 34964, CL 헤더 파싱(**drep 존중**), 인터페이스/객체 UUID 검사, NDR 요청/응답(**PNIOStatus**), 중복 요청 재응답, EPM Lookup | Wireshark `dcerpc`/`pn_io` 해석, 툴의 "Online diagnostics" 가 EPM 후 Read 성공 |
| M6 | Connect | ARBlockReq, IOCRBlockReq×2, AlarmCRBlockReq, ExpectedSubmoduleBlockReq 파싱·검증, 구성 비교, 응답(ARBlockRes/IOCRBlockRes/AlarmCRBlockRes/ModuleDiffBlock), 오류 시 `DB 81 xx yy` | PLC 가 Connect 후 "모듈 불일치" 없이 다음 단계로 감 |
| M7 | Records | IODWrite/ReadReqHeader(64B) 정확히, 파라미터 레코드 콜백, I&M0-4(BlockHeader), 오류 `DE/DF 80 xx` | 툴에서 I&M 읽기/쓰기, 파라미터 변경 반영 |
| M8 | PrmEnd / AppReady | `0x0110`→`0x8110 Done`, 그 다음 **디바이스가** `0x0112` IOXControlReq 로 Controller 인터페이스 호출, 재시도, `0x8112` 확인 | PLC 진단 버퍼에 오류 없이 "데이터 교환" 상태 |
| M9 | RT 송수신 | Input CR 주기로 송신(C_SDU 레이아웃·IOPS/IOCS·패딩·CycleCounter·DataStatus 0x35), Output CR 소비(IOPS/DataStatus 해석) | Wireshark `pn_rt` 에서 주기·카운터·상태 정상, PLC 에서 입력값 변화 보임 |
| M10 | 워치독 | Output CR data-hold, CMI 활동 타임아웃(Connect 값), 출력 대체값, abort 시 RTA ERR | 케이블 뽑기 → DHT 내 출력 안전값, 재연결 자동 |
| M11 | Release | `0x0114` → `0x8114 Done`, 자원 정리 | PLC 정지/다운로드 후 깔끔한 재연결 |
| M12 | Alarm | RTA DATA/ACK/ERR, 시퀀스, 재전송, AlarmNotification(Diagnosis/Process), AlarmAck | PLC 가 진단 알람 표시, ACK 왕복 |
| M13 | SNMP | 요청 파싱, request-id 에코, Get/GetNext, MIB-II system/interfaces, LLDP-MIB | `snmpwalk -v1 -c public <ip>` 정상 |
| M14 | GSDML | 장치와 1:1 일치(VendorID/DeviceID, 모듈/서브모듈 ident, IO 길이, 타이밍, 지원 기능), PI GSDML Checker 통과 | TIA/CODESYS import 경고 없음 |
| M15 | 보안/견고성 | Netload 부하 시험, 악성 입력 퍼징, (선택) DCP 쓰기 보호 | 퍼저 장시간 무크래시, 부하 중 RT 유지 |

### 10.3 파서 요령

1. **길이는 항상 두 번 검사**: "선언된 길이 ≤ 실제 남은 길이" 그리고 "필드를 읽기 전에 그 필드가 버퍼 안에".
   이 저장소 퍼저가 실제로 찾은 버그 두 개가 좋은 교재다:
   - ARBlockReq 에서 ARType(2바이트)을 빼먹어 MAC 을 본문 밖 2바이트까지 읽음 → 경계를 `2+16+2+6` 로 수정
     ([pn_rpc.c:238-241](../../stacks/profinet/src/pn_rpc.c) 주석).
   - `20 + n > len` 에서 `n = UINT32_MAX` 가 래핑 → `n > len - 20` 으로 수정 ([pn_rpc.c:406-410](../../stacks/profinet/src/pn_rpc.c) 주석).
2. **엔디안 규칙을 층별로 고정**하라: RPC/NDR 정수 = drep, 블록 안 = BE, UUID 앞 3필드 = drep.
3. **블록 워커는 한 번만 짠다**: `(type, body, body_len)` 콜백 방식. 모르는 블록은 건너뛰되, 필수 블록 누락은
   PNIOStatus 로 보고.
4. **DCP 패딩**: DCPBlockLength 는 패딩을 포함하지 않고 DCPDataLength 는 포함한다. 워커는
   `4 + len + (len & 1)` 로 전진 ([pn_dcp.c:258](../../stacks/profinet/src/pn_dcp.c)).
5. **요청/응답 비대칭**(BlockQualifier vs BlockInfo, NDR ArgsMaximum vs PNIOStatus)을 타입으로 구분하라.
6. 테스트 벡터는 **다른 구현**에서 가져와라 — 자기 빌더로 만든 요청을 자기 파서로 검증하면 이 저장소처럼
   구조적 오해가 CI 를 그대로 통과한다(12.8).

블록 워커 예 (안전한 형태):

```c
typedef int (*blk_cb)(uint16_t type, const uint8_t *body, size_t body_len, void *u);

/* PNIO 블록 열 순회. 잘못된 길이는 -EBADMSG. */
static int pn_walk_blocks(const uint8_t *p, size_t n, blk_cb cb, void *u)
{
    size_t off = 0;
    while (n - off >= 6) {                         /* type(2) len(2) ver(2) */
        uint16_t type = pn_rd_be16(p + off);
        uint16_t blen = pn_rd_be16(p + off + 2);   /* = 2(version) + body */
        if (blen < 2 || blen > n - off - 4)
            return -EBADMSG;
        int rc = cb(type, p + off + 6, (size_t)blen - 2, u);
        if (rc)
            return rc;
        off += 4u + blen;
    }
    return off == n ? 0 : -EBADMSG;                /* 꼬리 쓰레기 거부 */
}
```

### 10.4 타이머/스레드 설계

RT_CLASS_1 이라도 **주기 송신은 전용 스레드**가 좋다. 이 저장소처럼 "응용 poll 안에서 송신"하면 RPC 처리나 앱
코드가 늦을 때 RT 가 같이 늦는다.

```
 [RT 스레드, SCHED_FIFO 높은 우선순위]      [CM 스레드, 보통 우선순위]        [앱 스레드]
   clock_nanosleep(ABSTIME, next)             UDP 34964 recv (블록킹)         입력 쓰기 / 출력 읽기
   입력 이미지 스냅샷(짧은 락/더블버퍼)         Connect/Write/Control/Release    (락 또는 lock-free
   RT 프레임 송신                               AppReady 송신·재시도              더블 버퍼)
   출력 수신 처리 + data-hold 감시              DCP / LLDP / SNMP
   next += period (절대 위상)
```

```c
/* RT 송신 스레드 뼈대 (C11 + POSIX) */
static void *rt_thread(void *arg)
{
    pn_dev_t *d = arg;
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    for (;;) {
        timespec_add_ns(&next, d->in_period_ns);   /* SCF*RR*31250 (Input CR) */
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL) == EINTR) {}
        if (!atomic_load(&d->ar_active)) continue;
        uint8_t frame[1518];
        size_t n = build_rtc1_frame(d, frame);     /* C_SDU + IOPS/IOCS + pad + APDU status */
        d->cycle_counter += d->scf * d->rr;        /* 31.25µs 단위 [사양 확인 필요] */
        send(d->fd_eth, frame, n, 0);
        check_output_data_hold(d);                 /* 출력 감시도 같은 박자로 */
    }
    return NULL;
}
```

- 이미지 공유는 짧은 뮤텍스(이 저장소 `io_lock`, [pn_stack.c:273-305](../../stacks/profinet/src/pn_stack.c))나 더블 버퍼로.
- 늦었을 때는 이 저장소처럼 **재동기, 몰아보내기 금지**([pn_rt.c:140-147](../../stacks/profinet/src/pn_rt.c)).
- 수신은 `recvmmsg`/`PACKET_RX_RING`(mmap) 으로 시스템 콜 수를 줄일 수 있다.

### 10.5 A-core Linux 에서의 타이밍 한계

| 조건 | 기대 가능한 지터 | 비고 |
|------|------------------|------|
| 일반 커널, 부하 적음 | 수십 µs ~ 수백 µs, 드물게 ms | 이 저장소 8ms 에이징 최대 편차 0.1ms ([CLAUDE.md](../../CLAUDE.md)) |
| PREEMPT_RT + SCHED_FIFO + CPU 격리 | 수 µs ~ 수십 µs | `isolcpus`, IRQ 친화도, `mlockall` |
| IRT 요구 | < 1 µs | 소프트웨어로 불가 — ASIC 필요 (1.6) |

권장: 1ms 이하 update time 은 PREEMPT_RT 없이 약속하지 말고, GSDML `MinDeviceInterval` 과 지원 SCF/RR 을
**실측 가능한 범위로** 적어라. 1ms × WDF 3 = 3ms 는 일반 커널에서 가끔 넘는다.

### 10.6 짧은 C 예제 — 사양 형태의 Identify 응답 블록

```c
/* DCP 응답 블록 하나: opt, sub, len(=2+vlen), BlockInfo, value, [pad] */
static size_t dcp_res_block(uint8_t *out, uint8_t opt, uint8_t sub,
                            uint16_t block_info, const void *v, uint16_t vlen)
{
    uint16_t len = (uint16_t)(2u + vlen);
    out[0] = opt; out[1] = sub;
    pn_wr_be16(out + 2, len);
    pn_wr_be16(out + 4, block_info);
    memcpy(out + 6, v, vlen);
    size_t n = 4u + len;
    if (len & 1u) out[n++] = 0;          /* 패딩: DCPDataLength 에는 포함 */
    return n;
}

/* 사용 예 */
n += dcp_res_block(b + n, 0x02, 0x02, 0x0000, name, name_len);          /* NameOfStation */
uint8_t role[2] = {0x01, 0x00};                                         /* IO-Device, reserved */
n += dcp_res_block(b + n, 0x02, 0x04, 0x0000, role, 2);
n += dcp_res_block(b + n, 0x01, 0x02, ip_set ? 0x0001 : 0x0000, ipb, 12);/* IP 상태 */
```

NDR 응답 헤더 (PNIOStatus 포함):

```c
static size_t ndr_res(uint8_t *out, const uint8_t status[4],
                      const uint8_t *blocks, uint32_t n, uint32_t args_max)
{
    memcpy(out, status, 4);            /* ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2 */
    pn_wr_le32(out + 4,  n);           /* ArgsLength   (drep=LE 가정) */
    pn_wr_le32(out + 8,  args_max);    /* MaximumCount = 요청의 ArgsMaximum [사양 확인 필요] */
    pn_wr_le32(out + 12, 0);           /* Offset */
    pn_wr_le32(out + 16, n);           /* ActualCount */
    memcpy(out + 20, blocks, n);
    return 20u + n;
}
```

---

## 11. 이 저장소의 구현 지도

### 11.1 파일/함수 ↔ 개념

| 개념 | 파일:줄 | 함수/심볼 |
|------|---------|-----------|
| 공개 API / 설정 구조체 | [pn_stack.h:24-88](../../stacks/profinet/include/pn_stack.h) | `pn_cfg_t`, `pn_stack_*` |
| 상수(FrameID, 옵션, 블록 타입, 인덱스) | [pn_types.h:7-89](../../stacks/profinet/include/pn_types.h) | `PN_*` |
| 내부 상태 / AR | [pn_internal.h:16-95](../../stacks/profinet/include/pn_internal.h) | `pn_ar_t`, `struct pn_stack` |
| 엔디안 / 상수시간 비교 | [pn_endian.h:7-64](../../stacks/profinet/include/pn_endian.h) | `pn_rd_be16` … `pn_ct_eq` |
| 생성·기본값·enforce | [pn_stack.c:13-86](../../stacks/profinet/src/pn_stack.c) | `pn_stack_create` |
| 시작 (소켓, 첫 LLDP) | [pn_stack.c:109-137](../../stacks/profinet/src/pn_stack.c) | `pn_stack_start` |
| 이더넷 디스패치 | [pn_stack.c:154-180](../../stacks/profinet/src/pn_stack.c) | `pn_stack_handle_eth` |
| 메인 루프 | [pn_stack.c:238-266](../../stacks/profinet/src/pn_stack.c) | `pn_stack_poll` |
| IO 이미지 접근 | [pn_stack.c:268-305](../../stacks/profinet/src/pn_stack.c) | `pn_stack_ar_up`, `pn_stack_read_output`, `pn_stack_read_input`, `pn_stack_write_input` |
| 테스트 훅 | [pn_stack.c:98-102, 182-236](../../stacks/profinet/src/pn_stack.c) | `pn_stack_set_eth_ops`, `pn_stack_handle_rpc`, `pn_stack_handle_snmp`, `pn_stack_take_rpc_tx` |
| raw 소켓 / UDP | [pn_eth.c:75-192](../../stacks/profinet/src/pn_eth.c) | `pn_eth_open`, `pn_eth_send`, `pn_eth_recv`, `pn_udp_open` |
| 이더넷 헤더 | [pn_eth.c:37-73](../../stacks/profinet/src/pn_eth.c) | `pn_eth_build`, `pn_eth_parse` |
| DCP 헤더 | [pn_dcp.c:65-86](../../stacks/profinet/src/pn_dcp.c) | `parse_hdr` |
| NameOfStation 규칙 | [pn_dcp.c:93-161](../../stacks/profinet/src/pn_dcp.c) | `pn_dcp_name_ok` |
| DCP Set 서명 검증 | [pn_dcp.c:164-249](../../stacks/profinet/src/pn_dcp.c) | `extract_hmac_and_body`, `pn_dcp_verify_set` |
| DCP Set 적용 | [pn_dcp.c:251-334](../../stacks/profinet/src/pn_dcp.c) | `apply_blocks`, `blocks_have`, `set_has_invalid_name` |
| Identify 필터 / 응답 블록 | [pn_dcp.c:336-409](../../stacks/profinet/src/pn_dcp.c) | `ident_filters_match`, `build_identify_blocks` |
| ResponseDelay | [pn_dcp.c:435-478](../../stacks/profinet/src/pn_dcp.c) | `ident_delay_ns`, `queue_or_send_ident`, `pn_dcp_poll` |
| DCP 진입점 | [pn_dcp.c:496-572](../../stacks/profinet/src/pn_dcp.c) | `pn_dcp_on_frame` |
| Hello | [pn_dcp.c:574-585](../../stacks/profinet/src/pn_dcp.c) | `pn_dcp_send_hello` |
| LLDP | [pn_lldp.c:7-63](../../stacks/profinet/src/pn_lldp.c) | `tlv`, `pn_lldp_send` |
| RPC 블록 워커 | [pn_rpc.c:29-52](../../stacks/profinet/src/pn_rpc.c) | `walk_blocks` |
| Read/Write/Control 요청 파싱 | [pn_rpc.c:104-172](../../stacks/profinet/src/pn_rpc.c) | `parse_read_req`, `parse_write_req`, `parse_ctrl_req`, `parse_uuid_any` |
| AR 소유권 | [pn_rpc.c:174-214](../../stacks/profinet/src/pn_rpc.c) | `ar_owner_ok`, `ar_same_controller`, `ar_touch_cmi`, `ar_uuid_ok` |
| Connect 파싱 | [pn_rpc.c:234-278](../../stacks/profinet/src/pn_rpc.c) | `parse_ar_iocr` |
| Connect 서명 | [pn_rpc.c:280-326](../../stacks/profinet/src/pn_rpc.c) | `verify_connect_sec` |
| Connect 응답 | [pn_rpc.c:328-382](../../stacks/profinet/src/pn_rpc.c) | `wr_block`, `build_connect_res_blocks` |
| RPC/NDR 래핑 | [pn_rpc.c:384-439](../../stacks/profinet/src/pn_rpc.c) | `wrap_rpc_resp`, `ndr_blocks`, `ndr_wrap`, `wrap_rpc_req` |
| ApplicationReady | [pn_rpc.c:441-457, 469-477](../../stacks/profinet/src/pn_rpc.c) | `queue_app_ready`, `flush_pending_rpc` |
| 에러 응답 | [pn_rpc.c:459-467](../../stacks/profinet/src/pn_rpc.c) | `reply_pnio_err` |
| CM 디스패치 | [pn_rpc.c:479-687](../../stacks/profinet/src/pn_rpc.c) | `pn_rpc_handle` |
| UDP 34964 루프 | [pn_rpc.c:689-713](../../stacks/profinet/src/pn_rpc.c) | `pn_rpc_poll` |
| 레코드 | [pn_record.c:12-164](../../stacks/profinet/src/pn_record.c) | `im_payload`, `pn_record_read`, `pn_record_write` |
| RT 수신 / 송신 | [pn_rt.c:69-148](../../stacks/profinet/src/pn_rt.c) | `pn_rt_on_frame`, `pn_rt_send_if_due` |
| 워치독 / abort | [pn_rt.c:8-67](../../stacks/profinet/src/pn_rt.c) | `pn_ar_abort`, `ar_controller_live`, `pn_ar_watchdog` |
| HMAC 검증 / 알람 더미 | [pn_sec.c:10-64](../../stacks/profinet/src/pn_sec.c) | `pn_sec_hmac`, `pn_sec_ok`, `pn_alarm_send_dummy` |
| SHA-256 / HMAC | [pn_crypto.c:28-167](../../stacks/profinet/src/pn_crypto.c) | `pn_sha256`, `pn_hmac_sha256` |
| SNMP | [pn_snmp.c:10-127](../../stacks/profinet/src/pn_snmp.c) | `pn_snmp_handle`, `pn_snmp_poll` |
| 어댑터 | [profinet_adapter.c:114-337](../../adapters/profinet/profinet_adapter.c) | `pn_init`, `pn_connect`, `pn_poll_cycle`, `pn_read_point`, `pn_write_point`, `pn_health`, `profinet_adapter_create` |
| 코어 등록 | [core/adapter_registry.c:30](../../core/adapter_registry.c) | `{"profinet", profinet_adapter_create}` |

### 11.2 어댑터와 코어

- 코어는 `protocol_adapter_t` 함수 포인터만 부른다 ([include/protocol_adapter.h:26-53](../../include/protocol_adapter.h)).
  `protocol_params`/`points` JSON 은 문자열 그대로 넘기고 해석하지 않는다([CLAUDE.md](../../CLAUDE.md) 코딩 컨벤션).
- `pn_init` 이 JSON 을 파싱해 `pn_cfg_t` 를 채운다. 기본값: `security_class=1`, `cycle_us=8000`, `input_len=32`,
  `output_len=8`, `iface="mock"` ([profinet_adapter.c:122-128](../../adapters/profinet/profinet_adapter.c)).
- `pn_connect` → `pn_stack_start`, `pn_poll_cycle` → `pn_stack_poll`, `pn_health` → `pn_stack_ar_up`.

config 키 (`protocol_params`) — [config/example.profinet.json](../../config/example.profinet.json):

| 키 | 타입 | → `pn_cfg_t` | 비고 |
|----|------|--------------|------|
| `iface` | string | `iface` | `"mock"` 이면 raw 소켓 없이 동작(테스트용). 실 NIC 는 `"eth0"` 등 |
| `device_name` | string | `station_name` | 초기 NameOfStation |
| `vendor_id` / `device_id` | number | 동일 | GSDML 과 일치해야 함 (예제 43981 = 0xABCD) |
| `ip` / `netmask` / `gateway` | "a.b.c.d" | 동일 | DCP 응답에 보고될 값. OS IP 는 따로 설정해야 함 |
| `security_class` | 0/1 | 동일 | 기본 1 |
| `enforce_security_class` | bool/number | 동일 | |
| `psk_hex` | 64 hex | `psk`, `psk_set` | class≥1 이면 필수 |
| `input_len` / `output_len` | number | 동일 | 최대 256 |
| `cycle_us` | number | 동일 | **RT 송신 주기**. 컨트롤러 update time 과 맞출 것 |

최상위 `cycle_ms`(예제 8)는 코어가 `poll_cycle` 을 부르는 주기다 ([core/config_loader.c:76-79](../../core/config_loader.c)).

### 11.3 points (slot/subslot/index) 가 IO 데이터에 연결되는 방법

```json
{ "name": "barcode_value", "access": "read",  "length": 32,
  "address": { "profinet": { "slot": 1, "subslot": 1, "index": 1, "byte_offset": 0,  "length": 32 } } },
{ "name": "temperature",   "access": "read",  "length": 4,
  "address": { "profinet": { "slot": 1, "subslot": 1, "index": 1, "byte_offset": 32, "length": 4 } } }
```

- `parse_points` 가 `slot/subslot/index/byte_offset` 을 읽지만 ([profinet_adapter.c:72-112](../../adapters/profinet/profinet_adapter.c))
  **실제로 쓰는 것은 `byte_offset` 과 최상위 `length`, `access` 뿐**이다. slot/subslot/index 는 저장만 하고 어디에도 쓰지
  않는다. 주소 객체 안의 `length` 도 읽지 않는다.
- `access: "read"` 포인트: `read_point` → **입력 이미지**에서 읽음 (앱이 올린 값 확인용).
  `access: "write"` 포인트: `read_point` → **출력 이미지**에서 읽음 (컨트롤러가 보낸 값) ([profinet_adapter.c:257-281](../../adapters/profinet/profinet_adapter.c)).
- `write_point` 는 access 와 무관하게 **입력 이미지**(Device→Controller)에 쓴다 ([profinet_adapter.c:283-297](../../adapters/profinet/profinet_adapter.c)).
  즉 "access" 는 컨트롤러 관점이다: read = 컨트롤러가 읽는 값(=디바이스 입력), write = 컨트롤러가 쓰는 값(=디바이스 출력).
- 예제 [config/example.profinet.json](../../config/example.profinet.json) 의 `trigger`(access write, offset 0, 1B)는 출력 이미지 0번
  바이트, `barcode_value`(read, offset 0, 32B)는 입력 이미지 0~31 — 두 포인트의 offset 이 같아도 서로 다른 이미지라 겹치지 않는다.
- `example.codesys.profinet.json` / `example.fake_sensor.profinet.json` 은 `input_len: 40` 에 `barcode_value`(0..31) +
  `temperature`(32..35, float) 를 둔다. GSDML 의 입력은 32B 이므로 **GSDML 도 40B 로 바꾸지 않으면** 컨트롤러와
  길이가 어긋난다 [주의].
- 다중 서브모듈을 제대로 지원하려면 (slot, subslot) → C_SDU 오프셋 매핑을 Connect 의 IOCR API 목록에서 만들어
  어댑터에 노출해야 한다. 이는 `protocol_adapter.h` 를 건드리지 않고 어댑터 내부에서 가능하다.

### 11.4 의도적 비범위 / 미구현 (코드 기준)

| 기능 | 상태 | 근거 |
|------|------|------|
| IRT / RT_CLASS_3 / PTCP / CC-C | **영구 비목표** | [pn_stack.h:15](../../stacks/profinet/include/pn_stack.h), [docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 4장 |
| RT_CLASS_UDP, 멀티캐스트 CR | 없음 | IOCRType 3/4 처리 없음 |
| MRP (미디어 이중화) | 없음 ("DUT not implemented") | [docs/ctt_pi_matrix.md](../ctt_pi_matrix.md) |
| Fast Start-Up | 없음 | 같은 문서 |
| 시스템 이중화(S2/R1), Shared Device, 다중 AR, Supervisor AR | 없음 | 단일 `pn_ar_t` |
| EPM, ReadImplicit(opnum 5), RPC 단편화 | 없음 | `pn_rpc_handle` 분기 |
| ExpectedSubmodule 비교 / ModuleDiffBlock | 없음 | 11.5 |
| 진단 레코드 / 진단 알람 / Alarm ACK | 없음 | 7.3, 5.f |
| 비휘발 저장 (이름, IP, I&M) | 없음 | 6.7 |
| OS IP 적용 (`apply_os_ip`) | 필드만 존재 | [pn_stack.h:44](../../stacks/profinet/include/pn_stack.h) |
| LLDP 수신 / SNMP MIB | 없음 / sysName 고정 응답 | 5.c, 7.1 |
| 포트 서브모듈(0x8001) 진단, PDev 레코드 | 없음 | — |
| PI 인증 | 아님 | [pn_stack.h:18](../../stacks/profinet/include/pn_stack.h) |

### 11.5 사양 ↔ 저장소 차이 총정리

모두 **기록**이다. 이 저장소 CTT/테스트는 스택과 같은 가정으로 짜여 있어 이 항목들을 잡지 못한다(12.8).
"영향" 열은 표준 컨트롤러(TIA Portal/S7, CODESYS 등)와 붙일 때 예상되는 결과다.

| # | 영역 | 사양(또는 일반 구현) | 이 저장소 | 근거 | 확인 방법 | 영향 |
|---|------|----------------------|-----------|------|-----------|------|
| D1 | DCP 응답 블록 | 값 앞 BlockInfo 2B | 없음 | [pn_dcp.c:55-63, 381-409](../../stacks/profinet/src/pn_dcp.c) | golden + scapy | **Identify/Get/Hello 해석 불가 → 장치 탐색 실패** |
| D2 | DeviceRole | IO-Device = `0x01` | `0x02`(IO-Controller), 필터도 `0x02` | [pn_dcp.c:370, 393](../../stacks/profinet/src/pn_dcp.c) | scapy 역할 표 | 역할 오표시 |
| D3 | Hello 목적지 | `01:0E:CF:00:00:01` | `…:00` | [pn_dcp.c:581](../../stacks/profinet/src/pn_dcp.c) | [사양 확인 필요] | FSU 없으면 영향 적음 |
| D4 | Set 응답 | 블록별 Response, 미지원은 BlockError | 대표 1개, 미적용 블록도 OK | [pn_dcp.c:541-563](../../stacks/profinet/src/pn_dcp.c) | 하네스 | 툴이 잘못된 성공을 봄 |
| D5 | Set 실패 | ServiceType 1 + BlockError | ServiceType 5 + BlockError 3 | [pn_dcp.c:480-494](../../stacks/profinet/src/pn_dcp.c) | 하네스 | 오류 원인 오해 |
| D6 | Get | 요청 항목만 | 전체 블록 | [pn_dcp.c:520-526](../../stacks/profinet/src/pn_dcp.c) | 하네스 | D1 과 겹쳐 해석 실패 |
| D7 | Set IP | OS 인터페이스 적용, 영구 저장 | 변수만 | [pn_dcp.c:277-284](../../stacks/profinet/src/pn_dcp.c) | 코드 | **컨트롤러가 준 IP 로 RPC 도달 불가** |
| D8 | LLDP | PNO OUI `00-0E-CF`, PortID `port-001`, 802.3 TLV | OUI `00-0C-CF`, PortID=MAC, 802.3 없음 | [pn_lldp.c:34-52](../../stacks/profinet/src/pn_lldp.c) | 하네스 | 토폴로지/이웃 기능 불가 |
| D9 | RPC drep/UUID | drep 존중, 인터페이스/객체 UUID 검사, EPM | LE 가정, 검사 없음, EPM 없음 | [pn_rpc.c:482-495](../../stacks/profinet/src/pn_rpc.c) | 코드 | EPM Lookup 을 Read 로 오인 |
| D10 | NDR 응답 | 첫 4B = PNIOStatus | ArgsLength 복사 | [pn_rpc.c:415-424](../../stacks/profinet/src/pn_rpc.c) | 하네스 + scapy (`status=72`) | **모든 RPC 응답이 오류로 보임** |
| D11 | ARBlockRes | ResponderUDPRTPort `0x8892` | `0x8894` | [pn_rpc.c:353](../../stacks/profinet/src/pn_rpc.c) | scapy 기본값 | [사양 확인 필요] |
| D12 | AlarmCRBlockRes | 본문 6B | 8B | [pn_rpc.c:368-374](../../stacks/profinet/src/pn_rpc.c) | scapy (`Raw 00 a0`) | 블록 길이 불일치 |
| D13 | ExpectedSubmodule | 비교 + ModuleDiffBlock | 무시 | [pn_rpc.c:234-278](../../stacks/profinet/src/pn_rpc.c) | 코드 | 구성 오류를 못 알림 |
| D14 | IODWriteReq | 헤더 64B, 데이터는 헤더 뒤 | 본문+34 에서 읽음 | [pn_rpc.c:120-140](../../stacks/profinet/src/pn_rpc.c) | 하네스 (I&M1 이 0 으로) | **파라미터/I&M 쓰기 오염** |
| D15 | Write/Read 응답 | IODWrite/ReadResHeader | 4B 0 / raw 데이터 | [pn_rpc.c:648-680](../../stacks/profinet/src/pn_rpc.c) | 하네스 | 응답 해석 실패 |
| D16 | PrmEnd 응답 | `0x8110`, Done | `0x0111`, 명령 에코 | [pn_rpc.c:605-613](../../stacks/profinet/src/pn_rpc.c), [pn_types.h:57](../../stacks/profinet/include/pn_types.h) | scapy | **시동 중단** |
| D17 | ApplicationReady | rpc v4, Controller IF UUID, `0x0112`, 재시도 | v1, UUID 0, `0x0110`, 1회, 마지막 피어 포트 | [pn_rpc.c:426-477](../../stacks/profinet/src/pn_rpc.c) | 하네스 | **데이터 교환 단계 진입 불가** |
| D18 | Release | `0x0114` → `0x8114` | `0x0114` 미인식, 무응답 | [pn_rpc.c:157-172, 553-580](../../stacks/profinet/src/pn_rpc.c) | 하네스 (`rc=-1 ar=1`) | 정상 해제 실패, 타임아웃 의존 |
| D19 | CMI 타임아웃 | ActivityTimeoutFactor×100ms | 2 s 고정 | [pn_internal.h:48](../../stacks/profinet/include/pn_internal.h) | 코드 | 느린 시동 시 AR 소실 |
| D20 | RT 송신 주기 | Input CR SCF×RR | `cfg.cycle_us` | [pn_rt.c:99-102](../../stacks/profinet/src/pn_rt.c) | 코드 | 설정 불일치 시 컨트롤러 워치독 |
| D21 | C_SDU | 오프셋대로, IOCS 포함, ≥40B 패딩 | data+IOPS, IOCS 없음, 패딩 없음 | [pn_rt.c:117-130](../../stacks/profinet/src/pn_rt.c) | 하네스 | 길이 불일치 프레임 폐기 가능 |
| D22 | DataStatus | `0x35` (Run 비트 0x10) | `0x25` (Run 없음=Stop) | [pn_types.h:76-78](../../stacks/profinet/include/pn_types.h) | scapy | 입력이 Stop 상태로 해석 |
| D23 | CycleCounter | SCF×RR 씩 증가 [사양 확인 필요] | +1 | [pn_rt.c:126](../../stacks/profinet/src/pn_rt.c) | 코드 | 일부 컨트롤러 경고 가능 |
| D24 | VLAN 태그 송신 | IOCRTagHeader 반영(PCP 6) | 태그 없음 | [pn_eth.c:37-49](../../stacks/profinet/src/pn_eth.c) | 하네스 | 혼잡 시 우선순위 없음 |
| D25 | 출력 소비 | IOPS/DataStatus 해석, DHT 후 대체값 | 무조건 복사, abort 시 이미지 유지 | [pn_rt.c:69-91, 8-20](../../stacks/profinet/src/pn_rt.c) | 코드 | **안전 상태 전환 없음** |
| D26 | Alarm | RTA 상태기계, 올바른 블록, ACK | 더미 바이트 | [pn_sec.c:30-64](../../stacks/profinet/src/pn_sec.c) | scapy | 알람 해석 불가 |
| D27 | Abort 통지 | ERR-RTA-PDU [사양 확인 필요] | 없음 | [pn_rt.c:8-20](../../stacks/profinet/src/pn_rt.c) | 코드 | 컨트롤러는 자체 타임아웃으로만 앎 |
| D28 | SNMP | 요청 파싱, request-id 에코, MIB | 고정 응답, request-id=1 | [pn_snmp.c:53-106](../../stacks/profinet/src/pn_snmp.c) | 하네스 | 매니저가 응답 폐기 |
| D29 | I&M0 OrderID | 공백 패딩 문자열 | 마지막 바이트 NUL | [pn_record.c:38](../../stacks/profinet/src/pn_record.c) | 하네스 | 표시 문제 |
| D30 | 에러 응답 | `DB 81 xx yy` 등 | `81 00 00 00` 을 데이터로 / 무응답 | [pn_rpc.c:459-467](../../stacks/profinet/src/pn_rpc.c) | 하네스 | 원인 진단 불가 |
| D31 | GSDML | 인터페이스/포트 서브모듈, UseableModules, 타이밍, 인증 정보 | 최소 형태, MinDeviceInterval 1ms | [gsdml:30-74](../../stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml) | [사양 확인 필요] | import/구성 실패 가능 |

요약: 이 스택은 **자체 CTT 기준으로 일관되게 동작하는 "형태가 비슷한" 구현**이고, 표준 컨트롤러와의 상호운용은
D1·D10·D14·D16·D17 만으로도 성립하기 어렵다고 판단된다(실기 미확인). 수정 우선순위를 매긴다면 D1 → D10 → D16/D17
→ D14/D15 → D18 → D22/D21 → D7 순이 탐색·연결·데이터 교환 순서와 맞다.

---

## 12. 테스트와 디버깅

### 12.1 빌드와 실행

```bash
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON -DENABLE_PN_TESTS=ON
cmake --build build -j4
ctest --test-dir build --output-on-failure -LE soak_ci -R "pn|profinet"
```

`ENABLE_PN_TESTS` 는 기본 ON, `BUILD_PN_LAB_TOOLS`(dcp_probe, pn_device_run)도 기본 ON
([CMakeLists.txt:31, 38](../../CMakeLists.txt)). 이 문서 작성 시 위 명령으로 **34개 테스트 전부 통과**(부록 E).

### 12.2 단위 테스트

| 파일 | 내용 |
|------|------|
| [tests/test_pn_crypto.c](../../tests/test_pn_crypto.c) | HMAC-SHA256 RFC 4231 case 1 |
| [tests/test_pn_dcp.c](../../tests/test_pn_dcp.c) | 이름 규칙(`test_name_ok`), Identify 필터·지연(`test_ident_filter_and_delay`), Set 이름·enforce(`test_set_name_and_enforce`) |
| [tests/test_pn_rpc.c](../../tests/test_pn_rpc.c) | 짧은 Write 블록, AR 소유권, NDR 거대 길이, AR 타임아웃/교체, 거부 시 AR 보존, data-hold 계산, AR 블록 MAC 경계, IOCR 시계 없을 때 회수, 자기 송신 무시 |

### 12.3 CTT 시나리오

도구 하나(`tools/ctt`) + YAML(`tests/scenarios/profinet/*.yaml`). 플러그인은 [tools/ctt/proto/profinet/pn_plugin.c](../../tools/ctt/proto/profinet/pn_plugin.c)
(2456줄)로, 컨트롤러 역할의 요청을 만들고 DUT(이 스택)의 응답을 검사한다. 카탈로그와 ID 체계(`PN-B-<AREA>-NNN`)는
[docs/ctt_pn_bundle.md](../ctt_pn_bundle.md), 카테고리 매핑은 [docs/ctt_pi_matrix.md](../ctt_pi_matrix.md).

| 영역 | 시나리오 |
|------|----------|
| DCP | `dcp_identify_name_of_station`, `dcp_get`, `dcp_hello`, `dcp_signal`, `dcp_set_ip`, `dcp_set_sec_class1`, `dcp_set_name_boundary`, `dcp_malformed` |
| CM | `rpc_connect_sec1_integrity`, `rpc_release`, `rpc_ar_lifetime`, `rpc_ar_lifetime_cm`, `rpc_ar_replace`, `rpc_write_prmend_appready`, `rpc_cm_without_ar` |
| NEG/SEC | `rpc_connect_without_integrity`, `rpc_connect_bad_hmac`, `rpc_malformed`, `io_without_ar`, `record_unknown_index` |
| 주기 | `rtc1_io_cycle_smoke`, `rtc1_cyclic_metrics`(48사이클 late/missed/jitter), `rtc1_cycle_payload`, `rtc1_cycle_4ms`, `soak_short`, `soak_ci`(30s, 라벨 soak_ci), `nightly/soak_nightly`(1h, 수동) |
| 기타 | `alarm_tx`, `alarm_low`, `record_read_im0`, `record_read_im1_4`, `lldp`, `snmp_get_sysname` |

```bash
./build/ctt --scenario tests/scenarios/profinet/rtc1_cyclic_metrics.yaml --report /tmp/pn.json   # ctt-report/v1
./build/ctt --transport=af_packet --iface=ctt-ctl --dut-iface=ctt-dut \
            --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml             # veth 랩
tests/run_ctt_lab.sh                                                                          # 랩 일괄 (CAP_NET_ADMIN/RAW)
```

랩 프로파일은 [docs/ctt_lab.md](../ctt_lab.md) 참고. 권한이 없으면 SKIP(exit 0), `CTT_LAB_REQUIRE=1` 이면 실패.

### 12.4 Golden

[tests/golden/profinet/](../../tests/golden/profinet/README.md) 의 pcap 7개(DCP Identify/Get/Hello/Signal/Set, Set-IP 후 Hello,
Alarm Low)는 mock 에서 캡처한 **이 스택의 출력**이다. 회귀(바뀌지 않았나) 검사용이지 **사양 정답지가 아니다** —
D1(BlockInfo 없음)이 golden 에 그대로 박혀 있다. 재생성: `tests/regen_ctt_goldens.sh`.

### 12.5 퍼징

```bash
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DBUILD_DAEMON=OFF -DBUILD_CTT=OFF -DBUILD_FUZZERS=ON \
      -DENABLE_PN_TESTS=OFF -DENABLE_EIP_TESTS=OFF -DENABLE_MB_TESTS=OFF -DENABLE_SLMP_TESTS=OFF
cmake --build build-fuzz --target fuzz_pn_eth fuzz_pn_rpc
python3 tests/fuzz/gen_corpus.py
./build-fuzz/fuzz_pn_rpc -max_total_time=60 -dict=tests/fuzz/dict/pn_rpc.dict tests/fuzz/corpus/pn_rpc
```

([.github/workflows/ci.yml](../../.github/workflows/ci.yml) 의 fuzz 잡과 동일.) 두 하네스는 첫 바이트로 모드를 골라
**살아 있는 AR 상태**에서 Write/PrmEnd/Release/RT/Sec1 경로까지 들어가도록 설계됐다
([tests/fuzz/fuzz_pn_rpc.c:1-17](../../tests/fuzz/fuzz_pn_rpc.c), [tests/fuzz/fuzz_pn_eth.c:1-13](../../tests/fuzz/fuzz_pn_eth.c)).
1시간 캠페인 결과: [docs/reports/fuzz_longrun_20260929.md](../reports/fuzz_longrun_20260929.md). 퍼저는 메모리 안전성을
보장할 뿐 **사양 적합성은 보지 않는다**.

### 12.6 Wireshark

| 목적 | 디스플레이 필터 |
|------|-----------------|
| PROFINET 전부 | `eth.type == 0x8892` 또는 `pn_rt \|\| pn_dcp \|\| pn_io` |
| DCP | `pn_dcp` |
| 특정 트랜잭션 | `pn_dcp.xid == 0x1234` [필드명은 버전별 확인] |
| RT 주기 | `pn_rt` , `pn_rt.frame_id == 0x8001` |
| CM RPC | `pn_io` 또는 `dcerpc && udp.port == 34964` |
| LLDP | `lldp` |
| SNMP | `snmp` |

팁:
- 이 저장소 DCP 응답을 Wireshark 로 보면 D1 때문에 블록 해석 경고가 나는 것이 **정상(예상된 차이)** 이다.
- RT 분석: Statistics → Conversations 로 주기 확인, `frame.time_delta_displayed` 열로 지터 확인.
- CTT 는 `--capture <dir|file.pcap>` 로 mock 트래픽도 pcap 으로 떨군다([docs/ctt_lab.md](../ctt_lab.md)).

### 12.7 CODESYS / TIA Portal 로 상호운용 확인

절차 개요 ([docs/ctt_lab.md](../ctt_lab.md) "CODESYS", [tests/codesys_manual_lab.sh](../../tests/codesys_manual_lab.sh)):

1. Linux: `./build/pn_device_run <iface>` (unsigned 랩 Device, 약 5초 동작 — 250회×20ms, [tests/pn_device_run.c:35-38](../../tests/pn_device_run.c))
   또는 데몬 + `config/example.codesys.profinet.json`(iface 를 실제 NIC 로, `security_class: 0`).
2. NIC 를 컨트롤러 네트워크에 연결, OS 에 IP 수동 설정(D7).
3. GSDML import → 장치 배치 → NameOfStation `sensor-line1`, RT, 8ms. **IRT 프로젝트 금지.**
4. 스캔(Identify) → 이름 지정(Set) → 다운로드 → Connect → 데이터 교환 관찰.

**예상**: 11.5 의 D1 로 인해 스캔 단계부터 장치 정보가 깨질 가능성이 높다. 이 문서 작성 중 실 컨트롤러로 확인하지는
않았다(부록 E). 실기 결과는 저장소 문서에 따로 남기는 것이 좋다.

### 12.8 왜 CI 가 green 인데 사양과 다른가

CTT·단위 테스트·퍼저가 **스택과 같은 저장소의 같은 가정**으로 요청을 만든다: 같은 `ndr_wrap`(PNIOStatus 없음), `rpc_vers=1`,
Connect 에 ARBlockReq 만, Write 데이터를 헤더 본문 안에, Release 를 `0x0101` 블록으로, AppReady 를 `0x0110` 으로 기대
([pn_plugin.c:814-865, 1297-1316, 1414-1452, 1533-1569](../../tools/ctt/proto/profinet/pn_plugin.c)). 자기 자신과의 대화는 항상 통한다.
**외부 기준**(Wireshark 해석, scapy/p-net 같은 독립 구현, 실 PLC, PI ART 테스터)으로 교차 검증하는 테스트를 추가해야 이
종류의 오류가 드러난다. 이 문서의 부록 E 가 그 방법(scapy 역파싱)의 예다.

### 12.9 권한

| 필요 | 이유 | 부여 |
|------|------|------|
| `CAP_NET_RAW` | AF_PACKET | `setcap cap_net_raw+ep <bin>` |
| `CAP_NET_BIND_SERVICE` | UDP 161 | `setcap cap_net_bind_service+ep <bin>` |
| `CAP_NET_ADMIN` | veth 생성(랩 스크립트) | sudo |

mock (`iface: "mock"`)은 아무 권한도 필요 없다 — raw 소켓·UDP 를 전혀 열지 않는다 ([pn_stack.c:109-127](../../stacks/profinet/src/pn_stack.c)).

---

## 13. 흔한 함정과 보안 고려사항

### 13.1 구현 함정

1. **엔디안 혼용**: NDR 은 LE(drep), 블록은 BE. UUID 는 반반. 한 번 틀리면 모든 게 "거의 맞게" 보인다.
2. **요청/응답 비대칭**: DCP BlockQualifier↔BlockInfo, NDR ArgsMaximum↔PNIOStatus. 이 저장소가 둘 다 놓쳤다(D1, D10).
3. **ApplicationReady 방향**: 디바이스가 클라이언트다. 서버 소켓만 있는 구조로는 응답 확인·재시도가 어렵다.
4. **IODWriteReqHeader 의 24바이트 RWPadding**: 데이터는 64바이트 헤더 **뒤**에 온다(D14).
5. **Data hold 와 송신 주기 혼동**: 송신은 Input CR, 감시는 Output CR. 한쪽 파라미터로 둘 다 계산하지 말 것.
6. **이 저장소 전용**: `cycle_us` ↔ 컨트롤러 update time ↔ GSDML `MinDeviceInterval` 셋을 맞춰라(D20, D31).
7. **이 저장소 전용**: `cycle_ms`(poll) > `cycle_us` 이면 RT 주기가 poll 에 끌려간다(6.3).
8. **최소 프레임 길이**: veth 는 패딩하지 않는다. 컨트롤러는 C_SDU 가 DataLength 와 다르면 버릴 수 있다(D21).
9. **IP 는 DCP 로 받아도 OS 에 적용해야** RPC 가 들어온다(D7).
10. **DataStatus 비트**: Run 은 `0x10`, `0x20` 은 "문제 없음"(D22).
11. **안전 상태**: AR 이 끊겼을 때 앱이 쓰는 출력값을 안전값으로 바꾸는 책임을 누가 지는지 명확히(D25). 이 저장소에서는
    앱이 `pn_stack_ar_up()`/`health()` 를 보고 직접 처리해야 한다.
12. **이름 정규화**: 대문자는 거부해야 한다(툴이 소문자로 바꿔 보내지만 보장 없음).
13. **AR 교체 판단**: "같은 컨트롤러" 판단을 IP 만으로 하면 NAT/다중 NIC 에서 틀린다. 이 저장소는 IP 또는
    CMInitiatorObjectUUID 를 쓴다([pn_rpc.c:187-198](../../stacks/profinet/src/pn_rpc.c)).
14. **자기 송신을 생존 증거로 쓰지 말 것**: 이 저장소도 과거에 그랬다가 고쳤다(`test_cmi_ignores_own_tx`,
    [pn_rt.c:22-26](../../stacks/profinet/src/pn_rt.c)).

### 13.2 보안 고려사항

- PROFINET RT/DCP 는 **인증이 없는 L2 프로토콜**이다. 같은 방송 도메인의 누구든 Identify/Set/RT 위조가 가능하다.
  방어의 기본은 **망 분리**(셀 보호, IEC 62443 zone/conduit), 관리형 스위치의 포트 보안, DCP 쓰기 보호(PI Class 1)다.
- 이 저장소 HMAC 프로파일은 DCP Set 과 Connect 만 보호하고 재전송 방어가 없다(8.3). "보안 기능"이 아니라
  "랩용 무결성 실험"으로 다뤄라.
- PSK 를 config 파일 평문으로 두지 말고(예제의 `1111…` 금지), 장치별 키와 교체 절차를 설계하라.
- 파서는 원격 입력을 받는다. 이 저장소처럼 **libFuzzer + ASan/UBSan** 을 CI 에 두는 것이 최소선이다(12.5).
- SNMP `public` 응답은 정보 노출이다. CC-B 요구와 보안 요구(쓰기 비활성, community 변경 가능)를 같이 만족시켜야 한다.
- 제품 출시 시 CRA(EU Cyber Resilience Act) 등 규제는 **제품 프로세스**다 ([pn_stack.h:18-19](../../stacks/profinet/include/pn_stack.h)).

---

## 14. 인증/적합성

- **PI 인증(Certification)**: 장치 제조사는 PI 회원으로 가입(VendorID 발급)하고, PI 공인 시험소(PITL)에서 **PI 테스트
  번들**(ART Tester 등 자동 시험 도구 포함)로 적합성 시험을 통과해야 PROFINET 인증서를 받는다. GSDML 도 검사 대상이다
  [사양 확인 필요: 현행 절차/도구 이름].
- **이 저장소 CTT green ≠ 인증.** 저장소 문서가 반복해서 명시한다: "내부 bundle-grade 게이트 ≠ PI 인증", "공식 PI Test
  Bundle 실행·DoC 는 멤버십+공인 랩 제품 프로세스", "CTT green 을 PI 인증서 대신 제출하지 말 것"
  ([docs/ctt_pn_bundle.md:7-10](../ctt_pn_bundle.md), [docs/ctt_pi_matrix.md](../ctt_pi_matrix.md) "이 표가 말해 주지 않는 것").
- 내부 TC ID 는 공식 번들 TC 번호를 복제하지 않는다 ([docs/ctt_pn_bundle.md](../ctt_pn_bundle.md) 1-2장).
- 11.5 의 차이를 고치기 전에는 공식 시험의 초반(DCP) 단계부터 실패할 것으로 예상된다.
- VendorID `0xABCD` 는 자리표시자다. 제품에는 PI 가 발급한 ID 가 필요하다.

---

## 15. 참고 사양 문헌

(이 저장소에는 원문이 없다. 제목·판은 [사양 확인 필요] — 구매/회원 자료실에서 최신판 확인.)

| 문헌 | 내용 |
|------|------|
| IEC 61158-5-10 | Fieldbus — Application layer **service** definition, Type 10 (PROFINET IO) |
| IEC 61158-6-10 | Fieldbus — Application layer **protocol** specification, Type 10 — 프레임·블록·상태기계의 정본 |
| IEC 61784-2 | 실시간 이더넷 통신 프로파일 (CPF 3 = PROFIBUS/PROFINET), Conformance Class 정의 |
| IEC 61784-3-3 | PROFIsafe (기능 안전) — 이 저장소 범위 밖 |
| PI: PROFINET Specification (Application Layer services/protocol, V2.x) | IEC 문서와 동일 계열의 PI 판 |
| PI: GSDML Specification for PROFINET (V2.35 등) + GSDML Checker | GSDML 스키마와 규칙 |
| PI: PROFINET Conformance Classes / Application Classes 가이드라인 | CC-A/B/C/D 요구 |
| PI: PROFINET Security (Security Class 1/2/3) 관련 사양·가이드라인 | 8장 |
| PI: Identification & Maintenance (I&M) Functions 가이드라인 | 7.2 |
| PI: Diagnosis for PROFINET 가이드라인 | 7.3 |
| PI: PROFINET Installation / Commissioning 가이드라인 | 망 구성 |
| IEEE 802.1Q | VLAN 태그, 우선순위 |
| IEEE 802.1AB | LLDP |
| IEEE 802.3 | 이더넷 |
| The Open Group, DCE 1.1: Remote Procedure Call (C706) | CL RPC 헤더, NDR, EPM |
| RFC 1157 / RFC 1213 | SNMPv1 / MIB-II |
| RFC 2104 / FIPS 180-4 / RFC 4231 | HMAC / SHA-256 / 테스트 벡터 |
| 공개 참고 구현 (사양 대체 아님) | Wireshark `packet-pn-*.c`/`packet-dcerpc-pn-io.c`, scapy `contrib/pnio*.py`, rt-labs p-net |

---

## 부록 A. 구현 체크리스트

**L2 / DCP**
- [ ] AF_PACKET 송수신, VLAN 태그 수신 처리, 60B 패딩
- [ ] Identify: All/Name/DeviceID/Type/Role/Alias 필터, ResponseDelay, **BlockInfo 포함** 응답, 유니캐스트 응답
- [ ] DeviceRole=`0x01`
- [ ] Set: Name/IP/Signal/ResetToFactory, BlockQualifier 에 따른 영구 저장, 블록별 Response, BlockError
- [ ] Set IP → OS 적용 (+ 주소 충돌 검사 [사양 확인 필요])
- [ ] Get: 요청 항목만
- [ ] NameOfStation 규칙
- [ ] (FSU 시) Hello → `01:0E:CF:00:00:01`

**LLDP / SNMP**
- [ ] LLDP: Chassis=Name, Port=`port-001`, TTL 20/5s, 802.3 TLV, PNO TLV(`00-0E-CF`), Mgmt Addr
- [ ] LLDP 수신·이웃 테이블
- [ ] SNMPv1: request-id 에코, Get/GetNext, MIB-II system/interfaces, LLDP-MIB

**RPC / CM**
- [ ] CL 헤더(v4), drep, 인터페이스/객체 UUID 검사, 중복 요청 재응답, 단편화(필요 시)
- [ ] EPM Lookup
- [ ] NDR 요청/응답(PNIOStatus)
- [ ] Connect: AR/IOCR/AlarmCR/ExpectedSubmodule 검증, 응답 블록, ModuleDiffBlock, 오류 `DB 81 xx yy`
- [ ] Write/Read: 64B 헤더, 응답 헤더, 오류 `DF/DE 80 xx yy`, ReadImplicit
- [ ] PrmEnd → `0x8110` Done
- [ ] AppReady: `0x0112` via Controller 인터페이스, 재시도, `0x8112` 확인
- [ ] Release `0x0114` → `0x8114`
- [ ] CMI 타임아웃 = Factor×100ms

**RT**
- [ ] Input CR 주기(SCF×RR)로 송신, C_SDU 오프셋, IOPS/IOCS, ≥40B, CycleCounter, DataStatus `0x35`, VLAN PCP
- [ ] Output CR 소비: FrameID/길이/IOPS/DataStatus 검사, DHT 감시, 대체값, abort 통지

**Alarm / 진단 / I&M**
- [ ] RTA DATA/ACK/NACK/ERR, 시퀀스, 재전송, AlarmNotification, AlarmAck
- [ ] 진단 모델(ChannelDiagnosis), 진단 레코드
- [ ] I&M0-4 BlockHeader, 비휘발, I&M0FilterData

**제품**
- [ ] GSDML 1:1 일치, GSDML Checker
- [ ] 퍼징, 부하 시험, 장시간 에이징
- [ ] PI 가입, VendorID, 인증 시험

## 부록 B. hex 예제 모음

| 예제 | 위치 | 검증 |
|------|------|------|
| Identify-All 요청 / 이름 필터 요청 | 5.b.3 | 하네스 |
| Identify 응답 (이 저장소) | 5.b.4 | golden, 하네스 |
| Identify 응답 (사양 형태) | 5.b.4 | scapy 역파싱 |
| Set Name / Set IP + Hello / Signal / Get | 5.b.6–5.b.7 | 하네스 |
| Set 실패 응답 | 5.b.8 | 하네스 |
| LLDPDU | 5.c | 하네스 |
| Connect 요청 362B | 5.d.4 | 하네스 + scapy |
| Connect 응답 172B (이 저장소) | 5.d.5 | 하네스 + scapy |
| Write 요청 (사양 형태) / Write 응답 (사양 형태) | 5.d.6 | 하네스 / scapy 생성 |
| Read I&M0 응답 (이 저장소) / I&M0 레코드 (사양 형태) | 5.d.7 | 하네스 / scapy 생성 |
| PrmEnd 요청·응답 / Control 응답 (사양 형태) | 5.d.8 | 하네스 + scapy |
| ApplicationReady (이 저장소) / IOXControlReq (사양 형태) | 5.d.8 | 하네스 / scapy 생성 |
| RT 입력 (이 저장소) / RT 출력 (사양 형태) | 5.e.4 | 하네스 + scapy |
| Alarm (이 저장소) / Alarm (사양 형태) | 5.f | golden, 하네스 / scapy 생성 |
| SNMP GetResponse | 7.1 | 하네스 |
| 서명 DCP Set / 서명 Connect | 8.2 | 하네스 |
| Connect 에러 응답 | 9.4 | 하네스 |

사양 형태의 Control 응답 전체 RPC PDU (scapy 생성, 132B) — 5.d.8 표와 함께 보면 NDR·블록 배치를 한눈에 볼 수 있다:

```
 0000  04 02 00 00 10 00 00 00 00 00 a0 de 97 6c d1 11
 0010  82 71 00 01 00 01 ab cd 01 00 a0 de 97 6c d1 11
 0020  82 71 00 a0 24 42 df 7d 00 00 00 00 00 00 00 00
 0030  00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00
 0040  00 00 00 00 04 00 ff ff ff ff 34 00 00 00 00 00
 0050  00 00 00 00 20 00 00 00 20 00 00 00 00 00 00 00     PNIOStatus=0 | ArgsLength 32 | MaxCount 32 | Offset 0
 0060  20 00 00 00 81 10 00 1c 01 00 00 00 a0 a1 a2 a3     ActualCount 32 | IODControlRes 0x8110
 0070  a4 a5 a6 a7 a8 a9 aa ab ac ad ae af 00 01 00 00
 0080  00 08 00 00                                          ControlCommand = Done
```

## 부록 C. 블록 타입 표

[검증: scapy `pnio_rpc.py` 블록 타입 표 발췌 — 원문 대조는 사양 확인 필요]

| 타입 | 이름 | 방향/용도 | 이 저장소 |
|------|------|-----------|-----------|
| `0x0001` / `0x0002` | AlarmNotification High / Low | Alarm | 흉내 |
| `0x0008` / `0x8008` | IODWriteReqHeader / ResHeader | Write | 요청만(비표준 해석) |
| `0x0009` / `0x8009` | IODReadReqHeader / ResHeader | Read | 요청만 |
| `0x0010` | DiagnosisData | 진단 레코드 | 없음 |
| `0x0012` / `0x0013` | Expected/RealIdentificationData | 레코드 | 없음 |
| `0x0018` | ARData | 레코드 | 없음 |
| `0x0020`–`0x0024` | I&M0–I&M4 | 레코드 데이터 | 쓰기 시 헤더 제거만 |
| `0x0030`–`0x0032` | I&M0FilterData (Submodule/Module/Device) | 레코드 | 없음 |
| `0x0101` / `0x8101` | ARBlockReq / Res | Connect | 파싱 / 생성(D11) |
| `0x0102` / `0x8102` | IOCRBlockReq / Res | Connect | 파싱 / 생성 |
| `0x0103` / `0x8103` | AlarmCRBlockReq / Res | Connect | 무시 / 생성(D12) |
| `0x0104` | ExpectedSubmoduleBlockReq | Connect | 무시(D13) |
| `0x8104` | ModuleDiffBlock | Connect 응답 [사양 확인 필요] | 없음 |
| `0x0105` | PrmServerBlockReq | Connect | 없음 |
| `0x0106` | MCRBlockReq | Connect | 없음 |
| `0x0107` | ARRPCBlockReq | Connect | 없음 |
| `0x0108` | ARVendorBlockReq | Connect | 없음 |
| `0x0109` / `0x010A` / `0x010B` | IRInfoBlock / SRInfoBlock / ARFSUBlock | Connect | 없음 |
| `0x0110` / `0x8110` | IODControlReq/Res (Connect, PrmEnd) | Control | 요청 파싱 / 응답은 `0x0111`(D16) |
| `0x0111` / `0x8111` | IODControlReq/Res (Plug) | Control | `PN_BLOCK_CONTROL_RES` 로 오용 |
| `0x0112` / `0x8112` | IOXControlReq/Res (Connect, AppReady) | Device→Controller | 없음(D17) |
| `0x0113` / `0x8113` | IOXControlReq/Res (Plug) | | 없음 |
| `0x0114` / `0x8114` | ReleaseBlockReq / Res | Release | 없음(D18) |
| `0x0116` / `0x0117` | IOXBlockReq Companion / RT_CLASS_3 | | 없음 |
| `0x0118` / `0x8118` | PrmBegin Req / Res | | 없음 |
| `0x0200`–`0x02xx` | PDev(포트/인터페이스/MRP/동기) 데이터 | 레코드 | 없음 |
| `0x0400` | MultipleBlockHeader | | 없음 |
| `0x0600`/`0x0601` | FSHello / FSParameter | FSU | 없음 |
| `0x8001` / `0x8002` | AlarmAck High / Low | Alarm | 없음 |
| `0x0E01` | **(이 저장소 전용)** Security Class 1 integrity | Connect | 필수(class≥1) |

## 부록 D. PNIO 에러 코드 표

[사양 확인 필요 — 아래는 공개 구현(Wireshark 등)에서 널리 쓰이는 값을 정리한 것. 구현 전 IEC 61158-6-10 표로 대조]

**ErrorCode**

| 값 | 의미 |
|----|------|
| `0x00` | OK |
| `0x81` | PNIO (일반) |
| `0xCF` | RTA error |
| `0xDA` | AlarmAck |
| `0xDB` | IODConnectRes |
| `0xDC` | IODReleaseRes |
| `0xDD` | IODControlRes / IOXControlRes |
| `0xDE` | IODReadRes |
| `0xDF` | IODWriteRes |

**ErrorDecode**: `0x80` PNIORW, `0x81` PNIO, `0x82` Manufacturer specific.

**ErrorCode1 — PNIORW (`0x80`) 일 때** (상위 니블 = 클래스)

| 값 | 의미 | 값 | 의미 |
|----|------|----|------|
| `0xA0` | application: read error | `0xB0` | access: invalid index |
| `0xA1` | application: write error | `0xB1` | access: write length error |
| `0xA2` | application: module failure | `0xB2` | access: invalid slot/subslot |
| `0xA7` | application: busy | `0xB3` | access: type conflict |
| `0xA8` | application: version conflict | `0xB4` | access: invalid area/API |
| `0xA9` | application: feature not supported | `0xB5` | access: state conflict |
| `0xC0` | resource: read constrain conflict | `0xB6` | access: access denied |
| `0xC1` | resource: write constrain conflict | `0xB7` | access: invalid range |
| `0xC2` | resource: busy | `0xB8` | access: invalid parameter |
| `0xC3` | resource: unavailable | `0xB9` | access: invalid type |

**ErrorCode1 — PNIO (`0x81`) 일 때** (ErrorCode2 = 문제 필드 번호 또는 사유)

| 값 | 대상 |
|----|------|
| `0x01` | Connect: 잘못된 ARBlockReq |
| `0x02` | Connect: 잘못된 IOCRBlockReq |
| `0x03` | Connect: 잘못된 ExpectedSubmoduleBlockReq |
| `0x04` | Connect: 잘못된 AlarmCRBlockReq |
| `0x05` | Connect: 잘못된 PrmServerBlockReq |
| `0x06` | Connect: 잘못된 MCRBlockReq |
| `0x07` | Connect: 잘못된 ARRPCBlockReq |
| `0x08` | Read/Write Record 파라미터 오류 |
| `0x14` | IODControlReq (PrmEnd) 오류 |
| `0x16` | IOXControlReq (AppReady) 오류 |
| `0x18` | ReleaseBlock 오류 |
| `0x3C` | AlarmAck 오류 |
| `0x3D` / `0x3E` | CMDEV / CMCTL 상태기계 |
| `0x40` | **CMRPC** — ErrorCode2: `0x00` ArgsLength invalid, `0x01` unknown blocks, `0x02` IOCR missing, `0x03` wrong AlarmCRBlock count, `0x04` out of AR resources, `0x05` AR UUID unknown, `0x06` state conflict … |
| `0x41`–`0x4E` | ALPMI/ALPMR/LMPM/MAC/RPC/APMR/APMS/CPM/PPM/DCPUCS/DCPUCR/DCPMCS/DCPMCR/FSPM 계층 |
| `0xFD` | RTA_ERR_CLS_PROTOCOL (RTA ERR 의 사유) |

## 부록 E. 이 문서의 검증 기록

| 항목 | 방법 | 결과 |
|------|------|------|
| 빌드/테스트 | `cmake -DBUILD_DAEMON=OFF -DBUILD_CTT=ON -DENABLE_PN_TESTS=ON` (별도 빌드 디렉토리), `ctest -R "pn\|profinet" -LE soak_ci` | 34/34 통과 |
| golden 바이트 | `tests/golden/profinet/*.pcap` 7개를 hex 덤프 | 5.b.4, 5.b.6, 5.f 에 사용 |
| 스택 입출력 | 스크래치 C 하네스: `pn_eth_ops_t` 로 송신 프레임 캡처, `pn_stack_handle_eth` / `pn_rpc_handle` / `pn_stack_handle_snmp` 에 이 문서의 요청 바이트 주입 | "[검증: 하네스]" 표시 예제 전부. 주요 관측: 사양형 Connect 수락(`in=8001 out=8002 scf=32 rr=32 dh=3`), 사양형 Write 가 I&M1 을 0 으로 덮음, `0x0114` Release 거부(`rc=-1 ar=1`), RT DataStatus `0x25`, 서명 Set 수락·변조 거부 |
| 독립 교차 확인 | scapy 2.7.0 `contrib/pnio.py`·`pnio_dcp.py`·`pnio_rpc.py` 로 (a) 이 문서의 Connect 요청 역파싱 — 모든 필드 의도대로, (b) 이 저장소 응답 역파싱 — `status=72`, `CMResponderUDPRTPort=34964`, AlarmCRBlockRes 여분 `00 a0`, PrmEnd 응답이 `IODBlockReq_plug` 로 해석, Identify 응답의 이름이 `nsor-line1` 로 깨짐, RT DataStatus 에 `run` 없음, (c) 사양형 Identify.res(손 작성)·Control/Write/Read 응답·I&M0·Alarm 생성 | 5장 "[검증: scapy]" 표시 전부 |
| 코드 대조 | 이 문서의 모든 `경로:줄` 인용은 작성 시점 소스에서 확인 | — |
| 실 컨트롤러 | **하지 않음** (TIA/CODESYS/실 PLC 없음) | 11.5 "영향" 열은 추정 |
| IEC 원문 | **대조하지 않음** (저장소에 없음) | [사양 확인 필요] 표시 |

scapy 는 커뮤니티 구현으로 **사양 원문이 아니다.** 다만 이 저장소와 독립적으로 작성됐다는 점에서 "자기 자신과만 대화하는"
테스트의 맹점(12.8)을 드러내는 데는 충분하다. 반대로 scapy 의 DCP 빌더는 일부 블록 생성이 동작하지 않아(필드 길이 정의 문제)
사양형 Identify.res 는 손으로 만들고 scapy 로 **파싱만** 했다.
