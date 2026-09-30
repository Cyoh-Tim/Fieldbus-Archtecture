# EtherNet/IP (CIP over Ethernet) 완전 입문 + 이 저장소 스택 해설

> 대상 독자: 산업용 통신·PLC·필드버스를 **처음** 접하는, 일반적인 프로그래밍만 아는 사람.
> 목표: 이 문서를 끝까지 읽으면 (1) EtherNet/IP Adapter 스택을 **바닥부터 직접 구현**할 수 있고,
> (2) 이 저장소의 `stacks/ethernetip/` 스택을 **읽고 유지보수**할 수 있다.
>
> 공통 기초(요청-응답 vs 주기 교환, TCP/UDP, 바이트 순서, 저장소 구조)는
> [`README.md`](README.md) 에 있다. 이 문서는 그 위에서 EtherNet/IP 만 깊게 판다.
>
> 이 문서는 학습·구현 자료다. ODVA 공식 사양서(The CIP Networks Library)를 대체하지 않는다.
> 저장소 CTT 통과는 **ODVA 인증이 아니다** (13장).

---

## 목차

- [0. 이 문서 읽는 법 + 최소 선행 지식](#0-이-문서-읽는-법--최소-선행-지식)
- [1. 왜 이 프로토콜이 존재하나](#1-왜-이-프로토콜이-존재하나)
- [2. 용어 사전](#2-용어-사전)
- [3. 전체 그림 — 계층과 시퀀스](#3-전체-그림--계층과-시퀀스)
- [4. 데이터/객체 모델](#4-데이터객체-모델)
- [5. 프레임 포맷 (바이트 단위)](#5-프레임-포맷-바이트-단위)
- [6. 동작과 상태](#6-동작과-상태)
- [7. CIP Security — 사양과 이 저장소 구현](#7-cip-security--사양과-이-저장소-구현)
- [8. 에러 처리, 타이밍, 제한값](#8-에러-처리-타이밍-제한값)
- [9. 직접 구현하기 — 단계별 로드맵](#9-직접-구현하기--단계별-로드맵)
- [10. 이 저장소의 구현 지도](#10-이-저장소의-구현-지도)
- [11. 테스트와 디버깅](#11-테스트와-디버깅)
- [12. 흔한 함정과 보안 고려사항](#12-흔한-함정과-보안-고려사항)
- [13. 인증/적합성](#13-인증적합성)
- [14. 참고 사양 문헌](#14-참고-사양-문헌)
- [부록 A. 구현 체크리스트](#부록-a-구현-체크리스트)
- [부록 B. Hex 예제 모음 (검증됨)](#부록-b-hex-예제-모음-검증됨)
- [부록 C. 상태 코드 표](#부록-c-상태-코드-표)
- [부록 D. 사양 ↔ 저장소 불일치 목록](#부록-d-사양--저장소-불일치-목록)

---

## 0. 이 문서 읽는 법 + 최소 선행 지식

### 0.1 표기 규칙

| 표기 | 의미 |
|---|---|
| **[사양]** | ODVA CIP/EtherNet/IP 사양이 정한 내용 (필자 지식 + 저장소 코드 교차 확인) |
| **[저장소]** | 이 저장소 코드가 실제로 하는 일. 항상 `경로:줄` 로 근거를 단다 |
| **⚠ 불일치** | 사양과 저장소 구현이 다른 곳. 수정 제안이 아니라 **기록** 이다 (부록 D 에 모음) |
| **(사양서 확인 필요)** | 필자가 100% 확신하지 못하는 세부. 구현 전에 공식 사양서로 확인할 것 |
| `0x1234` | 16진수 값 |
| `34 12` | 선(wire) 위의 바이트 나열 (왼쪽이 먼저 전송) |
| `stacks/ethernetip/src/eip_cm.c:127` | 저장소 루트 기준 파일:줄 |

링크는 이 문서 위치(`docs/protocols/`) 기준 상대 경로다. 저장소 루트는 `../../` 이다.

### 0.2 이 문서의 hex 예제는 어떻게 검증했나

5장·부록 B 의 **[저장소] 응답 hex 는 전부 실제 스택에 요청 바이트를 넣어 얻은 출력**이다.

- 빌드: `cmake -S . -B <scratch>/build-eip -DBUILD_DAEMON=OFF -DBUILD_CTT=ON` → `libeip_stack.a`
- 저장소 밖(scratchpad)에 작은 C 하네스를 두고, `mock=1` 스택을 만든 뒤
  `eip_stack_handle_encap()` / `eip_stack_handle_io()` 에 hex 를 넣고 응답을 덤프했다.
- 재현성을 위해 하네스는 생성 직후 `s->session_secret = 0x0A0B0C0C` 로 고정했다.
  그래서 첫 세션 핸들이 `1 ^ 0x0A0B0C0C = 0x0A0B0C0D` (와이어 `0D 0C 0B 0A`) 가 된다.
  실제 운용에서는 부팅마다 `getrandom()` 값이라 핸들이 매번 다르다
  (`stacks/ethernetip/src/eip_stack.c:149-156`).
- 스택 설정: vendor `0xABCD`, device type `0x0C`, product code 1, rev 1.0,
  serial `0x12345678`, 이름 `FieldbusSensor`, input asm 150(4바이트),
  output asm 101(2바이트), config asm 100.
- 같은 빌드에서 `ctest -L ethernetip` 19/19, `test_eip_stack`, `test_eip_crypto` 통과 확인.

사양상 "정석" 형태이지만 저장소가 받아들이지 않는 프레임(예: 32비트 Run/Idle 헤더가 붙은
O→T I/O)은 실행 검증이 불가능하므로 **사양 지식으로 작성**했고 그렇게 표시했다.

### 0.3 TCP 와 UDP — 이 프로토콜은 둘 다 쓴다

| 포트 | 전송 | 용도 | 비유 |
|---|---|---|---|
| **44818** (0xAF12) | TCP | explicit(명시적) 메시징: 설정 읽기/쓰기, 연결 수립(Forward Open) | 전화 통화 — 연결을 맺고 묻고 답함 |
| **44818** | UDP | ListIdentity 브로드캐스트(장치 찾기) 등 | 확성기 — "여기 EtherNet/IP 장치 있나요?" |
| **2222** (0x08AE) | UDP | Class 1 implicit(암시적) I/O: 주기 데이터 | 컨베이어 벨트 — 요청 없이 매 주기 상자가 흘러옴 |
| **2221** (0x08AD) | TCP(TLS) / UDP(DTLS) | CIP Security 보안 포트 | 금고가 달린 전화 |

- TCP 는 "바이트의 강물"이다. 메시지 경계가 없으므로 **Encapsulation 헤더의 Length** 로 한 메시지를 잘라낸다.
- UDP 는 "봉투"다. 한 번 보낸 것은 통째로 도착하거나 사라진다. 주기 I/O 는 늦은 옛 데이터보다
  새 데이터가 중요하므로 재전송 없는 UDP 가 맞다.

[저장소] 상수: `EIP_TCP_PORT_DEFAULT 44818`, `EIP_UDP_IO_PORT_DEFAULT 2222`,
`EIP_SECURE_PORT_DEFAULT 2221` (`stacks/ethernetip/include/eip_types.h:13-15`).
⚠ 불일치: 저장소 Adapter 는 **UDP 44818 소켓을 열지 않는다** (`bind_udp()` 는 `udp_io_port` 만 바인드,
`stacks/ethernetip/src/eip_stack.c:193-215`). 그래서 UDP 브로드캐스트 ListIdentity 로는 발견되지 않는다.

### 0.4 리틀 엔디안(little-endian)

EtherNet/IP/CIP 의 모든 정수는 **작은 자리 바이트가 먼저** 온다.

```
값 0x1234 (UINT, 16비트)      → 와이어: 34 12
값 8000 = 0x00001F40 (UDINT)  → 와이어: 40 1F 00 00
값 0x20000001 (연결 ID)        → 와이어: 01 00 00 20
```

예외: CPF 의 **Sockaddr Info** 아이템과 ListIdentity 응답의 소켓 주소 필드는 BSD `sockaddr_in` 을
그대로 옮긴 것이라 **빅 엔디안(네트워크 바이트 순서)** 이다 [사양]. 이 한 군데가 초보자 버그 1순위다.

[저장소] 읽기/쓰기 헬퍼: `eip_rd_le16/eip_rd_le32/eip_wr_le16/eip_wr_le32`
(`stacks/ethernetip/include/eip_endian.h`). 구조체를 `memcpy` 로 통째로 캐스팅하지 않고
**필드마다 헬퍼로 읽는 것**이 정석이다 (정렬·패딩·엔디안 문제를 한 번에 피한다).

### 0.5 16진수·비트 번호

- 한 바이트 = 0x00~0xFF. "워드(word)" 는 CIP 에서 **16비트 = 2바이트** 다. 경로 길이(path size)가
  "워드 수" 로 표기되므로 바이트 수 = 워드 수 × 2.
- 비트 번호는 LSB 가 bit 0. `0x4804` 의 bit 14 가 1 이라는 것은 `0x4804 & (1<<14) != 0` 이다.

### 0.6 객체지향 모델 — 최소 개념

CIP 는 장치를 **객체(object)들의 모음** 으로 본다. 프로그래머 비유:

| CIP | C/객체지향 비유 | 예 |
|---|---|---|
| Class (클래스) | 구조체 타입 / 클래스 정의 | Identity 클래스 = 0x01 |
| Instance (인스턴스) | 그 타입의 변수 하나 / 객체 | Identity 인스턴스 1 (장치 자기 자신) |
| Attribute (속성) | 구조체 필드 | Identity 인스턴스 1 의 속성 1 = Vendor ID |
| Service (서비스) | 메서드 호출 | Get_Attribute_Single(0x0E) = "필드 하나 읽기" |
| Path (경로, EPATH) | `obj->field` 로 가는 주소 | `20 01 24 01 30 01` = Class 1 / Instance 1 / Attribute 1 |

즉 "Identity 객체 1번의 Vendor ID 를 읽어라" 는 `service=0x0E, path=Class 0x01/Instance 1/Attribute 1` 인
요청 하나다. 이 규칙은 모든 객체에 똑같이 적용된다 — 이것이 CIP 의 핵심 아름다움이다.

인스턴스 **0** 은 특별하다: "클래스 자체" 를 뜻한다. 클래스 속성(Revision, Max Instance 등)을 읽을 때 쓴다 [사양].

---

## 1. 왜 이 프로토콜이 존재하나

### 1.1 Rockwell / Allen-Bradley 세계

미국 공장 자동화 시장의 큰 축은 **Rockwell Automation** (브랜드 Allen-Bradley) 이다.
Rockwell 계열 PLC(ControlLogix, CompactLogix)와 주변 장비는 원래 다음 필드버스들을 썼다.

| 네트워크 | 등장 | 물리층 | 특징 |
|---|---|---|---|
| **DeviceNet** | 1994 | CAN 버스 | 센서/액추에이터 같은 작은 장비용, 전원 겸용 케이블 |
| **ControlNet** | 1997 | 동축 케이블, 토큰 방식 | 결정적(스케줄된) 제어 데이터 |
| **EtherNet/IP** | 2000~2001 | 표준 이더넷 + TCP/UDP/IP | 사무실 이더넷 장비를 공장에 그대로 |
| CompoNet | 2000년대 | 전용 | 비트 단위 초소형 장비 |

세 네트워크는 물리층은 완전히 다르지만 **위쪽 언어는 같다**. 그 공통 언어가 **CIP (Common Industrial Protocol)** 다.

> 이름 함정: EtherNet/IP 의 "IP" 는 Internet Protocol 이 아니라 **Industrial Protocol** 이다.
> "Ether**N**et" 의 대문자 N 도 공식 표기다.

### 1.2 ODVA 와 CIP

- **ODVA** (원래 Open DeviceNet Vendors Association) 가 CIP 와 그 네트워크 적응(adaptation)들을 관리한다.
- 사양서는 "The CIP Networks Library" 로 묶여 있고, **Volume 1 = CIP 공통**, **Volume 2 = EtherNet/IP 적응**,
  **Volume 3 = DeviceNet**, **Volume 8 = CIP Security** 등으로 나뉜다 (14장).
- 장치 제조사는 ODVA 회원이 되어 **Vendor ID** 를 받고, 적합성 시험(Conformance Test)을 통과해야
  공식 EtherNet/IP 장치라고 말할 수 있다 (13장).

```
                ┌──────────────────────────────────────────────┐
  응용/객체 층   │  CIP  (객체 모델 + 서비스 + 연결 관리)          │  ← Volume 1
                ├───────────────┬──────────────┬───────────────┤
  네트워크 적응  │ EtherNet/IP   │ DeviceNet    │ ControlNet    │  ← Volume 2 / 3 / 4
                │ (TCP/UDP/IP)  │ (CAN)        │ (CTDMA)       │
                ├───────────────┼──────────────┼───────────────┤
  물리/링크      │ Ethernet      │ CAN          │ 동축          │
                └───────────────┴──────────────┴───────────────┘
```

이 구조 덕분에 PLC 는 **라우팅** 을 할 수 있다: EtherNet/IP 로 들어온 요청을 백플레인을 거쳐
DeviceNet 장치까지 보내는 것이 "경로(path)" 에 포트 번호를 적는 것만으로 된다 (5.4.4 Port segment).

### 1.3 누가 누구와 말하나 — Scanner/Originator vs Adapter/Target

| 이름 | 다른 이름 | 역할 | 보통 누구 |
|---|---|---|---|
| **Originator** | Scanner, Client | 연결을 **먼저 여는 쪽**. Forward Open 을 보낸다 | PLC |
| **Target** | Adapter, Server | 연결 요청을 **받는 쪽** | 센서, I/O 모듈, 인버터 |

- Scanner = "I/O 를 스캔하는 PLC" 라는 뜻의 Rockwell 용어. Adapter = "필드 장비를 네트워크에 적응시키는 장치".
- 한 장치가 둘 다 될 수 있다. [저장소] 기본은 **Adapter** (`EIP_ROLE_ADAPTER`), 옵션으로 제한된
  **Originator** (explicit Get/Set 만) (`stacks/ethernetip/include/eip_types.h:129-132`).

### 1.4 Producer/Consumer 모델 — 왜 "요청" 없이 데이터가 오나

Modbus 처럼 "줘 → 여기" 를 반복하면 PLC 가 장비 수만큼 요청을 보내야 한다. CIP 는 대신
**연결(connection)** 을 한 번 맺고, 그 뒤로는 양쪽이 **정해진 주기(RPI)** 마다 데이터를
"생산(produce)" 하고 상대는 "소비(consume)" 한다. 데이터에는 "누구에게" 가 아니라
**연결 ID** 만 붙는다. 그래서 한 센서의 입력을 여러 PLC 가 **멀티캐스트** 로 동시에 받을 수도 있다.

```
 PLC(Originator)                                   센서(Target)
   │  ── TCP: Forward Open ("8ms 마다 교환하자") ──▶  │
   │  ◀── TCP: 성공 + 연결 ID ──────────────────────  │
   │                                                  │
   │  ══ UDP: O→T 출력 데이터 (8ms 마다) ══════════▶  │   ← PLC 가 생산, 센서가 소비
   │  ◀═ UDP: T→O 입력 데이터 (8ms 마다) ══════════   │   ← 센서가 생산, PLC 가 소비
   │         (요청/응답 없이 양방향으로 계속)          │
```

---

## 2. 용어 사전

| 용어 | 풀이 | 이 문서/저장소 위치 |
|---|---|---|
| **CIP** | Common Industrial Protocol. 객체 모델 + 서비스 + 연결 관리를 정한 공통 상위층 | 4장 |
| **EtherNet/IP** | CIP 를 TCP/UDP/IP 위에 올리는 방법(적응층). Encapsulation + CPF | 5장 |
| **ODVA** | CIP 사양 관리 단체 | 1.2 |
| **Object / Class / Instance / Attribute** | 객체 타입 / 그 개체 / 필드 | 0.6, 4장 |
| **Service** | 객체에 대한 연산 코드(1바이트). 응답은 `service OR 0x80` | 4.2 |
| **EPATH** | CIP 경로 인코딩. 세그먼트(segment)의 나열 | 5.4 |
| **Segment** | EPATH 의 한 조각. 첫 바이트 상위 3비트가 종류 (logical/port/symbolic/data) | 5.4 |
| **Padded EPATH** | 16비트 이상 값 앞에 패딩 바이트를 넣어 워드 정렬한 EPATH. EtherNet/IP 는 padded 를 씀 | 5.4.2 |
| **Assembly** | 여러 속성을 **바이트 배열 하나로 묶은** 객체(0x04). I/O 데이터의 실체 | 4.5 |
| **Connection Point** | 연결 경로에서 "이 Assembly 인스턴스로 생산/소비한다" 를 나타내는 번호(세그먼트 0x2C) | 5.6.6 |
| **Connection Manager (CM)** | 연결을 열고 닫는 객체(0x06) | 4.6 |
| **Forward Open (FO)** | 연결 개설 서비스 0x54. 최대 511바이트 연결 | 5.6 |
| **Large Forward Open** | 0x5B. 연결 크기 필드가 32비트 (최대 65535바이트) | 5.6.8 |
| **Forward Close (FC)** | 연결 해제 서비스 0x4E | 5.7 |
| **Originator / Target** | 연결을 여는 쪽 / 받는 쪽 | 1.3 |
| **Scanner / Adapter** | Rockwell 식 Originator / Target | 1.3 |
| **O→T / T→O** | Originator→Target 방향(PLC 출력) / Target→Originator 방향(센서 입력) | 3장 |
| **RPI** | Requested Packet Interval. Originator 가 **요청한** 주기(µs) | 6.5 |
| **API** | Actual Packet Interval. Target 이 **실제로 약속한** 주기(µs). FO 응답에 담김 | 5.6.7 |
| **Connection ID** | UDP I/O 패킷에 붙는 32비트 연결 식별자. 방향마다 하나 | 5.6.3 |
| **Connection triad** | (Connection Serial Number, Originator Vendor ID, Originator Serial Number). 연결의 "주민번호" | 6.7 |
| **Connection Timeout Multiplier** | 워치독 배수. 0..7 → ×4, ×8 … ×512 | 6.4 |
| **Sequence count** | CIP 16비트 순번 (Connected Data 앞 2바이트) | 5.8 |
| **Encapsulation sequence number** | Sequenced Address 아이템 안의 32비트 순번 (UDP 순서 판별) | 5.8 |
| **Run/Idle header** | O→T 데이터 앞 32비트. bit0=1 이면 Run(출력 적용), 0 이면 Idle | 5.8, 6.8 |
| **Real-time format** | I/O 데이터 앞에 무엇이 붙나: modeless / zero-length / heartbeat / 32-bit header | 5.8 |
| **Transport class** | 0: 순번 없는 I/O, 1: 순번 있는 I/O(대부분의 I/O), 2: 응답 포함, 3: 연결형 explicit | 5.6.5 |
| **Class 0 / 1 / 3** | 위 transport class 를 쓰는 연결 | 6장 |
| **Explicit messaging** | 요청-응답형 메시지 (TCP). "속성 읽어 줘" | 3장 |
| **Implicit messaging** | 연결형 주기 I/O (UDP). 데이터의 의미가 연결에 "암시" 되어 있어서 이렇게 부름 | 3장 |
| **UCMM** | Unconnected Message Manager. 연결 없이 보내는 explicit 요청 (SendRRData) | 5.2.7 |
| **Unconnected Send (0x52)** | CM 서비스. 다른 포트/장치로 **라우팅** 할 요청을 감싸는 봉투 | 5.9.1 |
| **SendRRData / SendUnitData** | Encapsulation 명령. UCMM 용 / 연결형(Class 3) 용 | 5.2 |
| **Session handle** | RegisterSession 이 발급하는 32비트 번호. 이후 모든 TCP 요청 헤더에 넣는다 | 6.1 |
| **Sender context** | 요청 헤더의 8바이트. Target 은 그대로 되돌려 준다 (요청-응답 짝 맞추기) | 5.1 |
| **CPF** | Common Packet Format. Encapsulation 데이터 안의 "아이템 목록" 포맷 | 5.3 |
| **EDS** | Electronic Data Sheet. 장치 능력을 적은 INI 형식 파일. 스캐너 툴이 읽는다 | 10.6 |
| **Identity object (0x01)** | 벤더/제품/시리얼/상태. 모든 CIP 장치 필수 | 4.3 |
| **TCP/IP Interface object (0xF5)** | IP 설정/상태 | 4.7 |
| **Ethernet Link object (0xF6)** | 링크 속도, MAC 등 | 4.8 |
| **Message Router (0x02)** | 들어온 요청을 경로에 따라 객체로 보내는 교환원 | 4.4 |
| **QoS object (0x48)** | DSCP/802.1Q 우선순위 값 | 4.9 |
| **Exclusive Owner / Input Only / Listen Only** | 연결 종류: 출력 소유 / 입력만 / 남의 멀티캐스트 입력 엿듣기 | 6.6 |
| **Electronic key** | 연결 경로의 "이 장치가 맞나?" 검사 세그먼트(0x34): vendor/type/product/rev | 5.6.6 |
| **ACD** | Address Conflict Detection (IPv4 주소 충돌 감지, RFC 5227 기반) | 4.7 |
| **LLDP** | 이웃 장비 알림 L2 프로토콜 (IEEE 802.1AB). ODVA 최근 CT 가 요구 | 4.11 |
| **DLR** | Device Level Ring. 링 토폴로지 이중화 (이 저장소 범위 밖) | 10.8 |
| **CIP Sync** | IEEE 1588 PTP 기반 시간 동기 (범위 밖) | 10.8 |
| **CIP Security** | TLS/DTLS 기반 보안 확장 (Volume 8) | 7장 |
| **General status / Extended status** | CIP 응답 1바이트 결과 코드 / 추가 16비트 코드 | 부록 C |
| **CT / DoC** | ODVA Conformance Test / Declaration of Conformity | 13장 |
| **CTT** | 이 저장소의 내부 회귀 하네스 (Controller Test Tool). 인증 아님 | 11장 |

---

## 3. 전체 그림 — 계층과 시퀀스

### 3.1 계층: 편지 봉투 비유

EtherNet/IP 메시지는 **봉투 안의 봉투 안의 편지** 다.

```
TCP 44818 스트림
└─ Encapsulation 헤더 (24바이트)       "누구에게, 어느 세션, 몇 바이트"    ← 우편 봉투
   └─ 명령별 데이터 (SendRRData 이면: interface handle 4 + timeout 2)
      └─ CPF (Common Packet Format)     "아이템 개수 + [타입,길이,데이터]..." ← 서류철 칸막이
         ├─ Address 아이템 (Null 0x0000)                                  ← 받는 칸: "연결 없음"
         └─ Data 아이템 (Unconnected Data 0x00B2)
            └─ CIP 메시지 (Message Router Request)                        ← 편지 본문
               service(1) | path size(1) | path(EPATH) | data
               → Message Router 가 path 를 보고 객체로 배달
                  → Identity / Assembly / Connection Manager / ...
```

UDP 2222 의 Class 1 I/O 는 Encapsulation 헤더 **없이** 바로 CPF 로 시작한다:

```
UDP 2222 데이터그램
└─ CPF
   ├─ Sequenced Address 아이템 (0x8002): 연결 ID + 32비트 순번
   └─ Connected Data 아이템 (0x00B1): 16비트 CIP 순번 + [Run/Idle 32비트] + I/O 데이터
```

### 3.2 두 개의 통로

| | Explicit (명시적) | Implicit (암시적) |
|---|---|---|
| 전송 | TCP 44818 | UDP 2222 |
| 모양 | 요청 → 응답 | 연결 후 양방향 주기 생산/소비 |
| 봉투 | Encapsulation + CPF + CIP 요청 | CPF(Sequenced Addr + Connected Data) |
| 데이터 의미 | 메시지 안에 경로·서비스가 **명시** | 연결 ID 가 곧 의미 (어떤 Assembly 인지 **암시**) |
| 용도 | 설정, 진단, 연결 수립/해제 | 매 주기 센서값·출력 명령 |
| 연결 없이 | UCMM (SendRRData) | 불가 — 반드시 Forward Open 먼저 |
| 연결 있음 | Class 3 (SendUnitData) | Class 0/1 |

### 3.3 전체 시퀀스 — 장치 발견부터 I/O, 해제까지

```
 Scanner(PLC, Originator)                                  Adapter(센서, Target)
   │                                                            │
   │ ① UDP 브로드캐스트 44818: ListIdentity (0x0063)             │
   │───────────────────────────────────────────────────────────▶│  [저장소: UDP 44818 없음 → TCP 로만 응답]
   │◀─────────── ListIdentity 응답: vendor/product/serial/name ──│  build_list_identity()
   │                                                            │
   │ ② TCP connect 44818                                        │
   │───────────────────────────────────────────────────────────▶│  accept_clients()
   │ ③ RegisterSession (0x0065), session=0                      │
   │───────────────────────────────────────────────────────────▶│  session_alloc()
   │◀────────────────────── 응답: session handle = H ────────────│
   │                                                            │
   │ ④ SendRRData(H) { Get_Attribute_Single Identity/1/1 }       │  (선택: 장치 확인)
   │───────────────────────────────────────────────────────────▶│  handle_sendrr() → eip_cip_route_auth()
   │◀──────────────────────────── 응답: Vendor ID ───────────────│
   │                                                            │
   │ ⑤ SendRRData(H) { Forward_Open: RPI, 크기, 경로 100/101/150 }│
   │───────────────────────────────────────────────────────────▶│  eip_cm_forward_open()
   │◀────────────── 응답: O→T ID, T→O ID, API ──────────────────│  연결 슬롯 할당, 워치독 장전
   │                                                            │
   │ ⑥ UDP 2222: O→T { ConnID(O→T), seq, 출력 데이터 }  매 RPI    │
   │═══════════════════════════════════════════════════════════▶│  eip_io_handle_udp() → output 이미지
   │◀══════════ UDP 2222: T→O { ConnID(T→O), seq, 입력 데이터 } ═│  eip_io_produce() 매 RPI
   │        ... (반복. O→T 가 RPI×배수 동안 없으면 Target 이 연결 폐기) │  eip_io_watchdog()
   │                                                            │
   │ ⑦ SendRRData(H) { Forward_Close: triad }                    │
   │───────────────────────────────────────────────────────────▶│  eip_cm_forward_close()
   │◀──────────────────────────── 응답: 성공 ────────────────────│
   │ ⑧ UnRegisterSession (0x0066), TCP close                    │
   │───────────────────────────────────────────────────────────▶│  session_drop() / tcp_client_drop()
```

**중요한 관찰 두 가지**

1. Forward Open 은 **TCP 로** 가지만 그 결과로 생긴 I/O 는 **UDP 로** 흐른다. TCP 세션이 끊겨도
   Class 1 연결은 워치독이 만료될 때까지 살아 있을 수 있다 [사양: Class 0/1 연결은 encapsulation
   세션 종료에 묶이지 않는다 — (사양서 확인 필요)]. [저장소] 도 TCP 종료 시 세션만 지우고 Class 1 슬롯은
   건드리지 않는다 (`tcp_client_drop()`, `stacks/ethernetip/src/eip_stack.c:469-484`).
2. ⚠ 불일치: [저장소] Target 은 **첫 O→T 패킷을 받아야** T→O 생산을 시작한다.
   `eip_io_produce()` 가 `peer_udp_port == 0` 인 연결을 건너뛰기 때문이다
   (`stacks/ethernetip/src/eip_io.c:111`). 사양상 Target 은 연결 수립 직후부터 T→O 를 생산하며,
   목적지는 Originator IP 의 UDP 2222(또는 FO 요청의 Sockaddr Info T→O 가 지정한 주소)다.
   저장소는 대신 **O→T 패킷의 출발지 IP:포트** 로 보낸다 (`eip_io.c:57-58`).

---

## 4. 데이터/객체 모델

### 4.1 CIP 기본 데이터 타입

모든 값은 리틀 엔디안. 속성 표의 "타입" 열은 이 이름을 쓴다 [사양].

| 타입 | 크기 | 설명 | 예 (값 → 와이어) |
|---|---|---|---|
| BOOL | 1바이트 | 0/1 (저장 단위는 바이트) | 1 → `01` |
| SINT / USINT | 1 | 부호 있음/없음 8비트 | 200 → `C8` |
| INT / UINT | 2 | 16비트 | 0xABCD → `CD AB` |
| DINT / UDINT | 4 | 32비트 | 8000 → `40 1F 00 00` |
| LINT / ULINT | 8 | 64비트 | |
| REAL / LREAL | 4 / 8 | IEEE 754 | 1.0f → `00 00 80 3F` |
| BYTE / WORD / DWORD | 1/2/4 | 비트 문자열 (숫자 의미 없음) | |
| SHORT_STRING | 1+n | 길이 1바이트 + ASCII n바이트 | "AB" → `02 41 42` |
| STRING | 2+n | 길이 UINT + 문자 (홀수면 패딩 관례 있음, 사양서 확인 필요) | |
| EPATH | 가변 | 경로 (5.4) | |

### 4.2 공통 서비스 코드

서비스 코드는 1바이트, bit 7 은 "응답" 표시다 (응답 코드 = 요청 코드 | 0x80) [사양].

| 코드 | 이름 | 의미 | [저장소] |
|---|---|---|---|
| 0x01 | Get_Attributes_All | 인스턴스(또는 클래스)의 정해진 속성 전부를 한 번에 | Identity 만 (`eip_cip.c:287-297`) |
| 0x02 | Set_Attributes_All | 전부 쓰기 | 없음 |
| 0x03 | Get_Attribute_List | 지정 속성 목록 읽기 | 없음 |
| 0x04 | Set_Attribute_List | | 없음 |
| 0x05 | Reset | 장치/객체 리셋 | Identity (`eip_cip.c:298-308`) |
| 0x06 | Start / 0x07 Stop | | 없음 |
| 0x08 | Create / 0x09 Delete | 인스턴스 생성/삭제 | 없음 |
| 0x0A | Multiple_Service_Packet | 여러 요청을 한 메시지에 | 없음 (fuzz 주석: `tests/fuzz/fuzz_eip_encap.c:13-15`) |
| 0x0D | Apply_Attributes | | 없음 |
| 0x0E | **Get_Attribute_Single** | 속성 하나 읽기 | 대부분 객체 |
| 0x10 | **Set_Attribute_Single** | 속성 하나 쓰기 | Identity attr 17, Assembly attr 3, QoS, LLDP |
| 0x11 | Find_Next_Object_Instance | | 없음 |
| 0x4E | **Forward_Close** (CM 전용) | 연결 해제 | `eip_cm.c:284` |
| 0x52 | **Unconnected_Send** (CM 전용) | 라우팅 봉투 | 정의만, 처리 없음 → 0x08 (검증됨) |
| 0x54 | **Forward_Open** (CM 전용) | 연결 개설 | `eip_cm.c:127` |
| 0x5B | **Large_Forward_Open** (CM 전용) | 큰 연결 개설 | `eip_cm.c:127` (`large=1`) |
| 0x4C / 0x4D | Read Tag / Write Tag | **Rockwell Logix 전용**(벤더 서비스, 0x4B~0x63 범위는 객체별 의미) | 없음 (10.7 참고) |

0x32~0x4A 는 공통 예약, 0x4B~0x63 은 **객체별(object-specific)** 서비스다. 그래서 0x54 는
Connection Manager 에서만 "Forward Open" 이고 다른 객체에서는 다른 의미다 (사양서 확인 필요: 정확한 범위 경계).

[저장소] 서비스 상수: `stacks/ethernetip/include/eip_types.h:67-75`.

### 4.3 Identity 객체 (Class 0x01)

"이 장치는 누구인가" 를 담는 객체. 모든 CIP 장치 **필수**. 인스턴스 1 = 장치 자신.

| Attr | 이름 | 타입 | [사양] 의미 | [저장소] 반환값 (`eip_cip.c:39-141`) |
|---|---|---|---|---|
| 1 | Vendor ID | UINT | ODVA 가 할당한 제조사 번호 | `cfg.vendor_id` (기본 0xABCD) |
| 2 | Device Type | UINT | 장치 프로파일 (0x0C = Communications Adapter, 0x2B = Generic Device(keyable) 등) | `cfg.device_type` (기본 0x0C) |
| 3 | Product Code | UINT | 제조사가 정하는 제품 번호 | `cfg.product_code` |
| 4 | Revision | STRUCT{USINT major, USINT minor} | 펌웨어 리비전 | `major_rev, minor_rev` |
| 5 | Status | WORD | 비트필드 (아래 표) | 0x0004 (Class1 있음) / 0x0000, ACD 충돌 시 \|0x0100 |
| 6 | Serial Number | UDINT | 제조사 내 고유 | `cfg.serial_number` |
| 7 | Product Name | SHORT_STRING (≤32자) | 제품명 | `cfg.product_name` (32자 절단) |
| 8 | State | USINT | 장치 상태 (아래 표) | 3(Operational), ACD 충돌 시 2 |
| 9 | Configuration Consistency Value | UINT | 설정이 바뀌면 바뀌는 값 | `config_consistency` (Reset 마다 +1) |
| 10 | Heartbeat Interval | USINT | 초 단위 | 항상 0 |
| 17 | (저장소: Protection Mode) | (저장소: UDINT) | ⚠ 아래 참고 | `cfg.protection_mode` |

Identity **Status (attr 5) 비트** [사양]:

| 비트 | 이름 | 의미 |
|---|---|---|
| 0 | Owned | 이 장치에 소유(owner) 연결이 하나 이상 있다 |
| 1 | (예약) | |
| 2 | Configured | 공장 출하 설정에서 바뀐 설정이 있다 |
| 3 | (예약) | |
| 4–7 | Extended Device Status | 0=자가진단 중/알수없음, 2=faulted I/O 연결 있음, 3=I/O 연결 없음, 5=주요 fault, 6=Run 모드 I/O 연결 있음, 7=모든 I/O 연결 Idle (사양서 확인 필요: 전체 값 표) |
| 8 | Minor Recoverable Fault | |
| 9 | Minor Unrecoverable Fault | |
| 10 | Major Recoverable Fault | |
| 11 | Major Unrecoverable Fault | |
| 12–15 | Extended Device Status 2 | (사양서 확인 필요) |

⚠ 불일치: [저장소] 는 Class 1 연결이 있으면 `0x0004` (bit 2 = **Configured**) 를 세운다
(`stacks/ethernetip/src/eip_cip.c:78`). 사양상 "연결로 소유됨" 은 bit 0 (Owned, `0x0001`) 이고,
Run 모드 I/O 연결은 Extended Device Status = 6 (`0x0060`) 로 표시하는 것이 관례다. 검증 출력:
Forward Open 뒤 attr 5 = `04 00`.

Identity **State (attr 8) 값** [사양]:

| 값 | 의미 |
|---|---|
| 0 | Nonexistent |
| 1 | Device Self Testing |
| 2 | Standby |
| 3 | Operational |
| 4 | Major Recoverable Fault |
| 5 | Major Unrecoverable Fault |
| 6–254 | 예약 |
| 255 | Default (Get_Attributes_All 에서 "지원 안 함" 표시용) |

⚠ 불일치: [저장소] 는 ACD 충돌 시 state = 2 로 두고 주석에 "Minor Recoverable Fault" 라고 적었다
(`eip_cip.c:110-111`, `eip_stack.c:647`). 사양 표에서 2 는 **Standby** 다. "Minor Recoverable Fault" 는
State 값이 아니라 **Status 비트 8** 이며, 저장소는 Status 쪽에도 `0x0100` 을 올바르게 세운다 (`eip_cip.c:79-81`).
ODVA 의 ACD 관련 CT 가이던스가 정확히 무엇을 요구하는지는 사양서 확인 필요.

⚠ 불일치(사양서 확인 필요): 공개 자료상 Identity 의 **Protection Mode 는 attr 19 (WORD)** 로 알려져 있고,
attr 17 은 Geographic_Location (STRINGI) 이다. [저장소] 는 attr 17 을 UDINT Protection Mode 로 쓴다
(`eip_cip.c:131-137`, `eip_cip.c:309-318`). 제품화 전 Volume 1 Identity 절로 확인할 것.

**Identity Get_Attributes_All (0x01)** — [저장소] 는 attr 1~10 을 순서대로 붙이고 마지막에 attr 17 을
붙인다 (`eip_cip.c:143-170`). 사양상 GAA 가 어떤 속성을 어떤 순서로 돌려주는지는 객체 정의에 정해져
있다. 많은 구현(예: OpENer)은 attr 1~7 만 돌려준다 (사양서 확인 필요). 검증된 응답은 5.5.2.

**Identity Reset (0x05)** — [사양] 요청 데이터로 Reset 타입(0 = 전원 재투입 흉내, 1 = 공장 초기화 후 재시작,
2 = 통신 파라미터 제외 초기화)을 받을 수 있고, **응답을 먼저 보낸 뒤** 리셋한다.
[저장소] 는 타입을 읽지 않고, 입출력 이미지를 0 으로 지우고, 모든 Class 1 슬롯을 비우고,
Configuration Consistency Value 를 1 올린 뒤 성공 응답을 준다 (`eip_cip.c:298-308`). 프로세스는 재시작하지 않는다.

### 4.4 Message Router (Class 0x02)

들어온 CIP 요청의 경로를 보고 대상 객체로 배달하는 "교환원". [사양] 인스턴스 attr 1 은
**Object_List** = `UINT 개수 + UINT[개수] 클래스 코드 목록` 이다. attr 2 = 지원 최대 연결 수.

[저장소] Message Router 역할은 함수 `eip_cip_route_auth()` → `handle_object()` 의 **if 사슬** 이 한다
(`eip_cip.c:620-662`, `eip_cip.c:241-618`). 객체로서의 Class 0x02 는 attr 1 에 **개수 8 만** (목록 없이) 돌려준다
(`eip_cip.c:321-331`). ⚠ 불일치: 목록이 없고, 실제 구현 클래스 수(10개 이상)와도 다르다.

### 4.5 Assembly (Class 0x04) — I/O 데이터의 실체

Assembly 는 "여러 데이터를 바이트 배열 하나로 묶은 것" 이다. 센서 입장에서 가장 중요한 객체다.

```
 Assembly 150 (Input, T→O, 센서가 생산)          Assembly 101 (Output, O→T, PLC 가 생산)
 ┌────────────────────────────────────┐          ┌──────────────┐
 │ byte 0..31  바코드 문자열            │          │ byte 0 트리거 │
 │ byte 32..33 상태 워드               │          │ ...          │
 │ ...                                 │          └──────────────┘
 └────────────────────────────────────┘
          ▲ config points 가 오프셋으로 매핑 (10.4)
```

| Attr | 이름 | 타입 | [사양] | [저장소] (`eip_cip.c:172-205`) |
|---|---|---|---|---|
| 1 | Number of Members | UINT | 멤버 수 | 없음 |
| 2 | Member List | 배열 | 멤버 경로 | 없음 |
| 3 | **Data** | ARRAY of BYTE | 데이터 전체 | Get/Set 지원 |
| 4 | Size | UINT | 데이터 바이트 수 | Get 지원 |

**인스턴스 번호 관례** [사양, 대략]: 1~99(0x01~0x63) 는 ODVA 장치 프로파일용, **100~199(0x64~0xC7) 는
벤더 전용**, 그 위 범위도 벤더/예약 구분이 있다 (사양서 확인 필요: 정확한 경계). Rockwell 식 관례로
Config=100, Output=101~, Input=150 같은 번호를 많이 쓴다.
[저장소] 기본값: config 100, output 101, input 150 (`eip_types.h:125-127`), config 로 변경 가능.

[저장소] 는 인스턴스를 **정확히 3개** 만 만든다: config(`cfg.config_size`, 기본 1바이트), output, input
(`eip_assembly_init()`, `stacks/ethernetip/src/eip_path_asm.c:208-233`). 최대 64 인스턴스·2048바이트 상한 상수가 있으나
(`eip_types.h:23-24`) 추가 인스턴스를 만드는 경로는 없다.

⚠ 주의: [저장소] 는 **Input(T→O) Assembly 에 대한 explicit Set 도 허용** 해서 센서 입력 이미지를 원격에서 덮어쓸 수
있다 (검증: `10 03 20 04 24 96 30 03 01 02 03 04` → `90 00 00 00`, 이후 Get 이 `01 02 03 04`).
또 길이가 모자라면 앞부분만, 넘치면 잘라서 쓴다 (`eip_assembly_write()`, `eip_path_asm.c:271-283`).
[사양] 은 크기 불일치에 0x13(Not enough data)/0x15(Too much data) 를 주고, 소유 연결이 있는 Assembly 에
Set 을 거부(0x10 Device state conflict 등)하는 것이 일반적이다 (사양서 확인 필요).

### 4.6 Connection Manager (Class 0x06)

연결의 개설·해제를 담당. 인스턴스 1 에 서비스를 보낸다 (`20 06 24 01`).

| 서비스 | 코드 | [저장소] |
|---|---|---|
| Forward_Close | 0x4E | 지원 (`eip_cm.c:284-328`) |
| Unconnected_Send | 0x52 | 미지원 → 0x08 |
| Forward_Open | 0x54 | 지원 (`eip_cm.c:127-282`) |
| Get_Connection_Data | 0x56 | 미지원 |
| Search_Connection_Data | 0x57 | 미지원 |
| Get_Connection_Owner | 0x5A | 미지원 |
| Large_Forward_Open | 0x5B | 지원 (같은 함수, `large=1`) |

CM 인스턴스 속성(연결 통계 카운터 등)은 [저장소] 에 없다. CM 은 `handle_object()` 의 맨 앞에서
인스턴스 1 일 때만 처리된다 (`eip_cip.c:251-266`).

### 4.7 TCP/IP Interface (Class 0xF5)

| Attr | 이름 | 타입 | [사양] | [저장소] (`eip_cip.c:375-414`) |
|---|---|---|---|---|
| 1 | Status | DWORD | bit0-3 인터페이스 설정 상태(1 = BOOTP/DHCP/비휘발 설정 유효), bit4 Mcast pending, bit5 설정 pending, **bit6 AcdStatus**, bit7 AcdFault | 0x00000001, ACD 충돌 시 \|0x40 |
| 2 | Configuration Capability | DWORD | bit0 BOOTP, bit1 DNS, bit2 DHCP, bit3 DHCP-DNS update, bit4 Settable, bit5 HW configurable, bit6 변경시 리셋 필요, **bit7 ACD capable** | 0x10 \| (acd_enable ? 0x04 : 0) |
| 3 | Configuration Control | DWORD | bit0-3: 0=정적, 1=BOOTP, 2=DHCP | 0 |
| 4 | Physical Link Object | STRUCT{UINT path size, Padded EPATH} | Ethernet Link 객체 경로 (보통 `20 F6 24 01`) | path size 0 만 (2바이트) |
| 5 | Interface Configuration | STRUCT{IP, mask, gateway, DNS1, DNS2, domain STRING} | IP 설정 | 없음 |
| 6 | Host Name | STRING | | 없음 |
| 8 | TTL Value | USINT | 멀티캐스트 TTL | 없음 |
| 9 | Mcast Config | STRUCT | 멀티캐스트 주소 할당 | 없음 |
| 10 | Select ACD | BOOL | ACD 사용 여부 | ⚠ 저장소는 "ACD Status" UDINT (충돌 1/0) |
| 11 | Last Conflict Detected | STRUCT{USINT activity, MAC[6], ARP PDU[28]} | 마지막 충돌 정보 | ⚠ 저장소는 "ACD Activity" UDINT 카운터 |
| 12 | EtherNet/IP Quick Connect | BOOL | | 없음 |
| 13 | Encapsulation Inactivity Timeout | UINT (초) | 기본 120. 유휴 TCP 세션을 닫는 시간 | 없음 (대신 `idle_timeout_ms`, 6.1) |

⚠ 불일치(사양서 확인 필요): attr 2 에서 저장소는 `acd_enable` 을 bit 2(**DHCP client**)로 표시한다
(`eip_cip.c:388`, 검증: `14 00 00 00`). 필자가 아는 사양 배치로는 ACD capable 은 bit 7(`0x80`)이다.
attr 10/11 의 의미와 타입도 사양과 다르다 (위 표). attr 4 는 경로가 비어 있다.

### 4.8 Ethernet Link (Class 0xF6)

| Attr | 이름 | 타입 | [저장소] (`eip_cip.c:416-436`) |
|---|---|---|---|
| 1 | Interface Speed | UDINT (Mbps) | 항상 100 |
| 2 | Interface Flags | DWORD: bit0 link up, bit1 full duplex, bit2-4 협상 상태, bit5 수동설정시 리셋필요, bit6 HW fault | 항상 0x0F (link up, full duplex, 협상 상태 3 = 속도·듀플렉스 협상 성공) |
| 3 | Physical Address | USINT[6] | ⚠ 항상 `02 02 02 02 02 02` (실제 MAC 아님) |
| 4~10 | Counters, Control, Type, State, Admin, Label | | 없음 |

실제 NIC 를 읽지 않는 **고정값 스텁** 이다. 제품화 시 실제 링크 상태·MAC 을 넣어야 한다.

### 4.9 QoS (Class 0x48)

EtherNet/IP 패킷 IP 헤더의 **DSCP** (우선순위) 값을 정하는 객체.

| Attr | [사양] 이름 | [사양] 기본 DSCP | [저장소] attr 번호 (`eip_cip.c:439-498`) |
|---|---|---|---|
| 1 | 802.1Q Tag Enable | 0 | ⚠ 저장소: DSCP Urgent |
| 2 | DSCP PTP Event | 59 | ⚠ 저장소: DSCP Scheduled |
| 3 | DSCP PTP General | 47 | ⚠ 저장소: DSCP High |
| 4 | DSCP Urgent | 55 (0x37) | ⚠ 저장소: DSCP Low |
| 5 | DSCP Scheduled | 47 (0x2F) | ⚠ 저장소: DSCP Explicit |
| 6 | DSCP High | 43 (0x2B) | 없음 |
| 7 | DSCP Low | 31 (0x1F) | 없음 |
| 8 | DSCP Explicit | 27 (0x1B) | 없음 |

기본 **값** 은 [저장소] 도 사양과 같다 (`eip_types.h:106-110`). ⚠ 불일치(사양서 확인 필요): 필자가 아는
사양의 속성 **번호** 는 1 = 802.1Q Tag Enable, 2~3 = PTP, 4~8 = Urgent/Scheduled/High/Low/Explicit 인데,
저장소는 1~5 를 Urgent~Explicit 로 쓴다. 또 저장소는 값을 저장만 하고 **소켓에 `IP_TOS` 를 설정하지 않는다**
(`grep IP_TOS` 결과 없음). 즉 실제 패킷 DSCP 는 OS 기본값(0)이다.

### 4.10 Port (0xF4), EtherNet/IP Security (0x5E)

- **Port (0xF4)** [사양] 인스턴스 attr: 1 Port Type (UINT, TCP/IP = 4 — 사양서 확인 필요), 2 Port Number,
  3 Link Object, 4 Port Name, 7 Node Address. [저장소] attr 1 = 0, attr 2 = 1 만 (`eip_cip.c:501-516`).
- **EtherNet/IP Security (0x5E)** 는 CIP Security(Volume 8) 가 정의한 클래스 코드다. [저장소] 는 이 클래스 코드에
  **저장소 고유 의미** 의 속성을 얹었다: attr 1 = `security_class`, attr 2 = 능력 비트(bit0 integrity, bit1 TLS),
  attr 3 = 보안 TCP 포트 (`eip_cip.c:519-546`). 사양의 0x5E 속성(State, Capability Flags, Available/Allowed
  Cipher Suites, PSK, Active Certificate 등 — 사양서 확인 필요)과 **호환되지 않는다**. 7장 참고.

### 4.11 LLDP Management (0x109) / LLDP Data Table (0x10A)

ODVA 는 최근 CT 에서 LLDP 송신과 LLDP Management 객체를 요구한다 (저장소 문서 기준 — 사양서 확인 필요).
클래스 코드가 0xFF 를 넘으므로 경로에 **16비트 클래스 세그먼트** `21 00 09 01` 가 필요하다 (5.4.2).

| Attr | [저장소] 의미 (`eip_cip.c:549-608`) | Set |
|---|---|---|
| 1 | LLDP Enable (bit0 = 전역 enable) | 가능. 끄면 TX 캐시 삭제 |
| 2 | msgTxInterval (초) | 가능 (최소 1) |
| 3 | msgTxHold | 가능 |
| 4 | (Data Store — 미구현, TX-only) | |
| 5 | Last Change (sysUpTime 초) | |

0x10A (Data Table) 은 항상 0x05 (경로 목적지 없음) (`eip_cip.c:611-614`). LLDP 프레임은 `eip_lldp_build()` 가
만들지만(`stacks/ethernetip/src/eip_lldp.c:32-73`) **실제 NIC 로 송신하지 않는다** — "hot path 에서 AF_PACKET 회피"
주석대로 메모리에만 둔다 (`eip_lldp.c:96-100`). Chassis ID MAC 도 고정 `02:00:00:00:00:01` 이다.

### 4.12 객체가 요청을 받는 방법 — [저장소] 라우팅 순서

`handle_object()` 의 판정 순서 (`eip_cip.c:241-618`):

```
0. gate_set_reset(): 서비스가 Set_Attribute_Single(0x10) 또는 Reset(0x05) 이면
     - 소유 세션 없음            → 0x0F Privilege violation
     - security_class≥1 인데 인증 안 됨 → 0x0F
     - protection_mode != 0      → 0x0F
1. Class 0x06 & inst 1   → FO / Large FO / FC, 그 외 0x08
2. Class 0x01 & inst 1   → Get single / GAA / Reset / Set attr17
3. Class 0x02 & inst 1 & Get single
4. Class 0x04 (인스턴스 무관) → Get/Set  (없는 인스턴스는 0x05)
5. Class 0xF5, 0xF6, 0x48, 0xF4, 0x5E, 0x109 (inst 1)
6. Class 0x10A → 0x05
7. 그 외 전부 → 0x05 Path destination unknown
```

⚠ 불일치: "알려진 객체에 지원 안 하는 서비스" (예: Identity attr 1 에 Set) 가 1~5 어디에도 걸리지 않으면
7번으로 떨어져 **0x05** 가 된다 (검증: `10 03 20 01 24 01 30 01 34 12` → `90 00 05 00`). 사양상 이런 경우는
0x08(Service not supported) 또는 0x0E(Attribute not settable) 가 맞다. 또 클래스 레벨 요청(instance 0)은
어떤 객체도 처리하지 않는다.

### 4.13 General Status 코드 (요약)

전체 표는 부록 C. 자주 보는 것만:

| 코드 | 이름 | 언제 |
|---|---|---|
| 0x00 | Success | |
| 0x01 | Connection failure | CM 에러. **반드시 extended status** 가 따라옴 |
| 0x02 | Resource unavailable | 슬롯/메모리 부족 |
| 0x04 | Path segment error | 경로 해석 불가 |
| 0x05 | Path destination unknown | 없는 클래스/인스턴스 |
| 0x08 | Service not supported | |
| 0x0E | Attribute not settable | |
| 0x0F | Privilege violation | 권한 없음 |
| 0x13 / 0x15 | Not enough data / Too much data | 요청 데이터 길이 틀림 |
| 0x14 | Attribute not supported | 없는 속성 |
| 0x20 | Invalid parameter | |

---

## 5. 프레임 포맷 (바이트 단위)

### 5.1 Encapsulation 헤더 (24바이트)

TCP 44818 위의 모든 메시지(그리고 UDP 44818 의 ListIdentity 등)는 이 헤더로 시작한다 [사양, Vol 2].

| 오프셋 | 크기 | 필드 | 타입 | 설명 |
|---|---|---|---|---|
| 0 | 2 | Command | UINT | 명령 코드 (5.2) |
| 2 | 2 | Length | UINT | **헤더 뒤** 데이터 길이(바이트). 헤더 24바이트는 포함 안 함 |
| 4 | 4 | Session Handle | UDINT | RegisterSession 이 준 핸들. 세션 불필요 명령은 0 |
| 8 | 4 | Status | UDINT | 요청은 0. 응답에 결과 코드 |
| 12 | 8 | Sender Context | 8바이트 | 요청자가 임의로 넣고, 응답에 **그대로 복사** 됨 |
| 20 | 4 | Options | UDINT | 0 이어야 함 (0 아니면 수신측은 버림 — 사양서 확인 필요) |
| 24 | Length | Command specific data | | 명령별 |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   (바이트 오프셋 기준 그림)
┌───────────────┬───────────────┬───────────────────────────────┐
│ Command (LE)  │ Length (LE)   │ Session Handle (LE, 4)        │ 0..7
├───────────────┴───────────────┼───────────────────────────────┤
│ Status (LE, 4)                │ Sender Context (8) ...        │ 8..15
├───────────────────────────────┼───────────────────────────────┤
│ ... Sender Context            │ Options (LE, 4)               │ 16..23
└───────────────────────────────┴───────────────────────────────┘
```

**Encapsulation Status 코드** [사양]:

| 값 | 의미 | [저장소] 사용 |
|---|---|---|
| 0x0000 | Success | 사용 |
| 0x0001 | Invalid or unsupported command | 사용 (모르는 명령, 세션 할당 실패, CPF 파싱 실패) |
| 0x0002 | Insufficient memory | 없음 |
| 0x0003 | Incorrectly formed data | 없음 |
| 0x0064 | Invalid session handle | 사용 (SendRRData 세션 불일치) |
| 0x0065 | Invalid length | 정의만 (`eip_types.h:55`) — 실제로는 응답 없이 드롭 |
| 0x0069 | Unsupported encapsulation protocol revision | 없음 |

[저장소] 헤더 작성: `encap_hdr()` (`stacks/ethernetip/src/eip_encap.c:8-21`) — Sender Context 는 복사,
Options 는 0. 헤더 파싱: `eip_encap_process()` (`eip_encap.c:288-316`). **Length 가 실제 받은 바이트보다 크면
응답 없이 `-EINVAL`** (fail closed, `eip_encap.c:307-311`, 검증: 헤더만 보내고 Length=0x18 → rc=-22, 응답 0바이트).
TCP 경로에서는 스트림 버퍼가 Length 만큼 찰 때까지 기다리므로 이 경로는 테스트 주입에서만 탄다 (6.2).

### 5.2 Encapsulation 명령

| 코드 | 명령 | 전송 | 세션 필요 | [저장소] |
|---|---|---|---|---|
| 0x0000 | NOP | TCP | 아니오 | ⚠ 응답을 보냄 (사양: **응답 없음**) |
| 0x0004 | ListServices | TCP/UDP | 아니오 | 지원 |
| 0x0063 | ListIdentity | TCP/UDP | 아니오 | TCP 만 (UDP 44818 소켓 없음) |
| 0x0064 | ListInterfaces | TCP/UDP | 아니오 | ⚠ 미구현 → status 0x0001 |
| 0x0065 | RegisterSession | TCP | (발급) | 지원 |
| 0x0066 | UnRegisterSession | TCP | 예 | ⚠ 응답을 보냄 (사양: 응답 없이 TCP 종료) |
| 0x006F | SendRRData | TCP | 예 | 지원 (UCMM) |
| 0x0070 | SendUnitData | TCP | 예 | ⚠ 미구현 → status 0x0001 (Class 3 불가) |
| 0x0072 | IndicateStatus | | | 없음 |
| 0x0073 | Cancel | | | 없음 |

명령 상수: `eip_types.h:42-49`. 디스패치: `switch (cmd)` (`eip_encap.c:318-388`).

#### 5.2.1 NOP (0x0000)

[사양] TCP 연결 유지(keep-alive) 용. 데이터는 임의(무시), **응답하지 않는다**.
[저장소] 헤더를 그대로 되돌려 보낸다 (`eip_encap.c:319-322`). 검증: 24바이트 0 요청 → 24바이트 0 응답.
대부분의 Originator 는 이 응답을 무시하므로 실해는 적지만, 스트림 상에 예상 못 한 메시지가 끼는 셈이다.

#### 5.2.2 ListServices (0x0004)

"어떤 통신 서비스를 지원하나" 를 묻는다. 응답 CPF 아이템 타입 0x0100 (Communications) [사양]:

| 필드 | 크기 | 값 |
|---|---|---|
| Item count | 2 | 1 |
| Type ID | 2 | 0x0100 |
| Length | 2 | 20 |
| Protocol version | 2 | 1 |
| Capability flags | 2 | bit 5 = CIP over TCP 지원, bit 8 = Class 0/1 UDP 지원 |
| Name of service | 16 | "Communications" + NUL 패딩 |

**검증된 [저장소] 응답** (`eip_encap.c:362-372`):

```
요청:  04 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00
응답:  04 00 1A 00                         Command=0x0004, Length=26
       00 00 00 00  00 00 00 00            Session=0, Status=0
       00 00 00 00 00 00 00 00  00 00 00 00 Context, Options
       01 00                               Item count = 1
       00 01                               Type ID = 0x0100 (Communications)
       14 00                               Length = 20
       01 00                               Version = 1
       20 01                               Flags = 0x0120 (bit5 TCP + bit8 UDP class0/1)
       43 6F 6D 6D 75 6E 69 63 61 74 69 6F 6E 73 00 00   "Communications\0\0"
```

#### 5.2.3 ListIdentity (0x0063)

장치 발견용. 스캐너 툴(예: RSLinx 류)은 **UDP 브로드캐스트 255.255.255.255:44818** 로 보내고 응답을 모은다.
응답 CPF 아이템 타입 0x000C [사양]:

| 필드 | 크기 | 타입 | 설명 |
|---|---|---|---|
| Item count | 2 | UINT | 1 |
| Type ID | 2 | UINT | 0x000C |
| Length | 2 | UINT | 이하 바이트 수 |
| Encapsulation Protocol Version | 2 | UINT | 1 |
| **Socket Address** | 16 | **빅 엔디안** | sin_family(INT)=2, sin_port(UINT)=44818, sin_addr(UDINT)=장치 IP, sin_zero[8]=0 |
| Vendor ID | 2 | UINT | Identity attr 1 |
| Device Type | 2 | UINT | attr 2 |
| Product Code | 2 | UINT | attr 3 |
| Revision | 2 | USINT×2 | attr 4 |
| Status | 2 | WORD | attr 5 |
| Serial Number | 4 | UDINT | attr 6 |
| Product Name | 1+n | SHORT_STRING | attr 7 |
| State | 1 | USINT | attr 8 |

(사양서 확인 필요: 최근 판에서는 요청 Sender Context 앞 2바이트를 "Max Response Delay(ms)" 로 해석해,
Target 이 0~그 값 사이 무작위로 늦게 응답하도록 한다 — 브로드캐스트 응답 폭주 방지.)

**검증된 [저장소] 응답** (`build_list_identity()`, `eip_encap.c:23-67`):

```
요청:  63 00 00 00  00 00 00 00  00 00 00 00  01 02 03 04 05 06 07 08  00 00 00 00
                                              └ Sender Context ┘
응답:  63 00 36 00                  Command=0x0063, Length=54
       00 00 00 00  00 00 00 00     Session=0, Status=0
       01 02 03 04 05 06 07 08      Sender Context (그대로 복사)
       00 00 00 00                  Options
       01 00                        Item count = 1
       0C 00                        Type ID = 0x000C
       30 00                        Length = 48
       01 00                        Encap protocol version = 1
       00 00 00 00 00 00 00 00      Socket Address 16바이트 ← ⚠ 저장소는 전부 0
       00 00 00 00 00 00 00 00
       CD AB                        Vendor ID = 0xABCD
       0C 00                        Device Type = 0x0C
       01 00                        Product Code = 1
       01 00                        Revision 1.0
       00 00                        Status = 0x0000 (⚠ 항상 0, attr 5 와 무관)
       78 56 34 12                  Serial = 0x12345678
       0E 46 69 65 6C 64 62 75 73 53 65 6E 73 6F 72   Name: len 14 "FieldbusSensor"
       FF                           State = 0xFF (⚠ 항상 0xFF, attr 8 과 무관)
```

사양대로라면 IP 192.168.0.10 장치의 Socket Address 는 `00 02 AF 12 C0 A8 00 0A 00 00 00 00 00 00 00 00`
(family 2, port 0xAF12=44818, IP C0.A8.00.0A — 모두 빅 엔디안) 이다.
⚠ 불일치: 저장소는 소켓 주소를 0 으로(`eip_encap.c:40-42` 주석 "zeros ok for unit tests"), Status 를 0 으로,
State 를 0xFF 로 고정한다.

#### 5.2.4 ListInterfaces (0x0064)

[사양] 비-CIP 인터페이스 목록. 대부분 장치는 **아이템 0개** (`00 00`) 로 응답하면 된다.
⚠ [저장소] 미구현 — 응답 status 0x0001 (검증: `64 00 00 00 ... 01 00 00 00 ...`). 저장소 문서도 "DUT not implemented"
로 명시한다 (`docs/ctt_eip_bundle.md` 4장).

#### 5.2.5 RegisterSession (0x0065)

TCP 연결 후 **가장 먼저** 해야 하는 일. 요청 데이터 4바이트:

| 필드 | 크기 | 값 |
|---|---|---|
| Protocol version | 2 | 1 |
| Options flags | 2 | 0 |

응답은 같은 4바이트를 돌려주고, **헤더의 Session Handle** 에 새 핸들을 넣는다.

```
요청:  65 00 04 00  00 00 00 00  00 00 00 00  00×8  00 00 00 00   01 00 00 00
응답:  65 00 04 00  0D 0C 0B 0A  00 00 00 00  00×8  00 00 00 00   01 00 00 00
                    └ Session Handle = 0x0A0B0C0D (하네스 고정값, 실운용은 랜덤)
```

[사양] 버전이 1 이 아니면 status 0x0069 로 거절하고, 이미 세션을 가진 TCP 연결의 재등록도 거절한다(사양서 확인 필요:
정확한 status). [저장소] (`eip_encap.c:324-340`, `session_alloc()` `eip_encap.c:120-140`):

- 버전/옵션을 **검사하지 않고 그대로 에코** 한다. ⚠ 검증: 같은 연결에서 버전 2 로 다시 보내도 성공, 핸들 동일, 본문 `02 00 00 00` 에코.
- 같은 TCP 연결(owner)이 이미 세션을 가졌으면 **같은 핸들** 을 준다.
- 핸들 = `next_session++ XOR session_secret` (`session_new_handle()`, `eip_encap.c:105-118`). 추측하기 어렵게 만든 것이다.
- 세션 수 상한 64 (`EIP_CLASS3_SESSIONS_MAX`, `eip_types.h:26`). 넘으면 status 0x0001.

#### 5.2.6 UnRegisterSession (0x0066)

[사양] 세션 종료. 수신측은 **응답하지 않고** TCP 를 닫는다.
[저장소] 소유권이 맞으면 세션을 지우고 **빈 성공 응답** 을 보낸다. 소유권이 틀리면 status 0x0064 응답
(`eip_encap.c:342-352`). TCP 는 닫지 않는다 (Originator 가 닫거나 유휴 타임아웃).

#### 5.2.7 SendRRData (0x006F) — UCMM 요청/응답

"연결 없이 CIP 요청 하나 보내고 응답 받기". 데이터 구조:

| 필드 | 크기 | 설명 |
|---|---|---|
| Interface Handle | 4 | CIP 는 0 |
| Timeout | 2 | 초 단위 타임아웃. (사양서 확인 필요: CIP 에서는 0 을 권장/무시) |
| CPF | 가변 | 보통 2 아이템: Null Address(0x0000, 길이 0) + Unconnected Data(0x00B2, CIP 요청) |

[저장소] `handle_sendrr()` (`eip_encap.c:168-286`):

1. 본문 6바이트 미만 → 실패.
2. **세션 핸들이 이 TCP 연결 소유가 아니면** status 0x0064 (`eip_encap.c:177-182`). 검증: 핸들 0xDEADBEEF → `64 00 00 00`.
3. CPF 아이템을 순회하며 0x00B2(CIP) 와 0x00C1(저장소 무결성 MAC, 7장)을 찾는다. 길이 초과면 실패 (`eip_encap.c:193-211`).
4. 보안 검사 `eip_sec_check_ucmm()` 실패 → CIP 0x0F 응답 (MAC 없이).
5. `eip_cip_route_auth()` 로 라우팅, 응답을 Null + Unconnected Data (+ 필요시 MAC) 아이템으로 감싼다.

Interface Handle·Timeout·Address 아이템 타입은 검사하지 않는다.

#### 5.2.8 SendUnitData (0x0070) — Class 3 연결형 explicit

[사양] Forward Open(transport class 3) 으로 연 연결 위에서 explicit 메시지를 주고받는다.
CPF = Connected Address(0x00A1, 4바이트 연결 ID) + Connected Data(0x00B1, 2바이트 CIP 순번 + CIP 요청).
**응답이 없는 명령** 이다 — Target 은 역방향 연결 ID 로 별도의 SendUnitData 를 보낸다. 형식은 5.9.2.
⚠ [저장소] 미구현 (status 0x0001). 그런데 Forward Open 은 transport class 를 검사하지 않아 Class 3 FO 도
"성공" 하고 Class 1 슬롯을 하나 차지한다 (검증: transport 0xA3 FO → 성공). 6.3 참고.

### 5.3 Common Packet Format (CPF)

Encapsulation 데이터(그리고 UDP I/O 전체)는 CPF 로 되어 있다:

```
┌────────────┬───────────────────────────┬───────────────────────────┬──
│ Item count │ Item 1                    │ Item 2                    │ ...
│ UINT       │ Type ID(2) Length(2) Data │ Type ID(2) Length(2) Data │
└────────────┴───────────────────────────┴───────────────────────────┴──
```

| Type ID | 이름 | 길이 | 내용 | 용도 |
|---|---|---|---|---|
| 0x0000 | Null Address | 0 | 없음 | UCMM (SendRRData) |
| 0x000C | ListIdentity response | 가변 | 5.2.3 | |
| 0x00A1 | Connected Address | 4 | 연결 ID (UDINT) | SendUnitData |
| 0x00B1 | Connected Data | 가변 | 16비트 CIP 순번 + 데이터 | SendUnitData, UDP I/O |
| 0x00B2 | Unconnected Data | 가변 | CIP 요청/응답 | SendRRData |
| 0x0100 | ListServices response | 가변 | 5.2.2 | |
| 0x8000 | Sockaddr Info O→T | 16 | sockaddr_in (**빅 엔디안**) | FO 요청/응답 |
| 0x8001 | Sockaddr Info T→O | 16 | sockaddr_in (**빅 엔디안**) | FO 요청/응답 |
| 0x8002 | Sequenced Address | 8 | 연결 ID (UDINT) + encap 순번 (UDINT) | UDP I/O |
| 0x00C1 | (**저장소 전용** 무결성 MAC) | 32 | HMAC-SHA256 | 7장 — ODVA 할당 아님 |

[저장소] 상수: `eip_types.h:58-64`, `stacks/ethernetip/include/eip_sec.h:21`.
**Sockaddr Info 아이템(0x8000/0x8001)은 저장소가 생성도 해석도 하지 않는다** (`grep 0x8000` 결과는 상수 정의뿐).

**Sockaddr Info 의 의미** [사양, 요약 — 사양서 확인 필요]:
- FO **요청** 에 T→O(0x8001)를 넣으면: "T→O 데이터를 이 IP/포트로 보내 달라" (point-to-point 수신 포트 지정 등).
- FO **응답** 에 O→T(0x8000)가 있으면: "O→T 는 이 주소/포트로 보내라". T→O(0x8001)가 있으면: T→O 멀티캐스트 주소.
- 없으면 기본: UDP 2222, T→O point-to-point 는 Originator IP.

### 5.4 CIP 메시지와 EPATH

#### 5.4.1 요청/응답 포맷 [사양]

```
요청 (Message Router Request)
┌─────────┬────────────────────┬────────────────────────┬─────────────┐
│ Service │ Request Path Size  │ Request Path (EPATH)   │ Request Data│
│ USINT   │ USINT (워드 수)     │ Path Size × 2 바이트    │ 가변         │
└─────────┴────────────────────┴────────────────────────┴─────────────┘

응답 (Message Router Response)
┌──────────────┬──────────┬────────────────┬───────────────────┬────────────────────┬─────────────┐
│ Reply Service│ Reserved │ General Status │ Additional Status │ Additional Status  │ Response    │
│ USINT        │ USINT=0  │ USINT          │ Size USINT (워드)  │ UINT × Size        │ Data        │
│ (= svc|0x80) │          │                │                   │                    │             │
└──────────────┴──────────┴────────────────┴───────────────────┴────────────────────┴─────────────┘
```

[저장소] 요청 파싱 `eip_cip_route_auth()` (`eip_cip.c:620-662`): `path_words*2` 가 길이를 넘으면 0x04.
응답 작성 `cip_ok_header()` / `cip_error()` (`eip_cip.c:10-37`).
⚠ 주의: `cip_error()` 의 `ext` 인자는 `uint8_t` 라 16비트 extended status 를 담을 수 없다 — 현재 호출부는
모두 0 을 넘기므로 실해는 없다. CM 은 별도 `cm_err()` (16비트) 를 쓴다 (`eip_cm.c:8-20`).

#### 5.4.2 EPATH 세그먼트 인코딩

EPATH 는 세그먼트의 나열이다. 각 세그먼트의 **첫 바이트** 가 종류와 형식을 말한다 [사양].

```
 세그먼트 첫 바이트
  7   6   5   4   3   2   1   0
┌───────────┬───────────────────┐
│ Seg Type  │  Seg Format       │
└───────────┴───────────────────┘
 Seg Type: 000 Port, 001 Logical, 010 Network, 011 Symbolic, 100 Data, 101/110 Data type, 111 예약
```

**Logical segment (001)** 의 형식 비트:

```
  7   6   5   4   3   2   1   0
┌───────────┬───────────┬───────┐
│ 0   0   1 │ Logical   │ Format│
│           │ Type      │       │
└───────────┴───────────┴───────┘
 Logical Type: 000 Class ID, 001 Instance ID, 010 Member ID, 011 Connection Point,
               100 Attribute ID, 101 Special(Electronic Key), 110 Service ID, 111 예약
 Format:       00 = 8비트, 01 = 16비트, 10 = 32비트, 11 = 예약
```

그래서 자주 보는 첫 바이트:

| 첫 바이트 | 의미 | 뒤따르는 바이트 (padded EPATH) | 예 |
|---|---|---|---|
| 0x20 | Class ID 8비트 | 1 | `20 01` = Class 1 |
| 0x21 | Class ID 16비트 | 패드 1 + UINT 2 | `21 00 09 01` = Class 0x0109 |
| 0x24 | Instance ID 8비트 | 1 | `24 01` = Instance 1 |
| 0x25 | Instance ID 16비트 | 패드 1 + UINT 2 | `25 00 2C 01` = Instance 300 |
| 0x28 / 0x29 | Member ID 8/16 | 1 / 패드+2 | |
| 0x2C | Connection Point 8비트 | 1 | `2C 96` = CP 150 |
| 0x2D | Connection Point 16비트 | 패드 1 + UINT 2 | |
| 0x30 | Attribute ID 8비트 | 1 | `30 03` = Attribute 3 |
| 0x31 | Attribute ID 16비트 | 패드 1 + UINT 2 | |
| 0x34 | Electronic Key | key format 1 + 8바이트 | 5.6.6 |
| 0x91 | ANSI Extended Symbolic | 길이 1 + 문자 + (홀수면 패드 1) | `91 07 "Sensor1" 00` |
| 0x80 | Simple Data segment | 길이(워드) 1 + 데이터 | FO 경로의 config 데이터 |
| 0x01~0x0E | Port segment (확장 링크주소 아님) | 링크 주소 1 | `01 00` = 포트 1, 주소 0 |

"Padded" 규칙: EtherNet/IP 는 **padded EPATH** 를 쓴다. 16비트 값 앞에 0x00 패드를 넣어 값이 짝수 오프셋에
오게 한다. 그래서 16비트 세그먼트는 4바이트(= 2워드)가 되고, 경로 전체 길이가 항상 워드 단위가 된다.

[저장소] 인코더: `eip_path_append_class/instance/attribute/ansi_tag()` (`stacks/ethernetip/src/eip_path_asm.c:21-103`) —
0xFF 이하면 8비트, 아니면 16비트 형식. 디코더 `eip_path_parse()` (`eip_path_asm.c:105-181`) 는
0x20/0x21/0x24/0x25/0x30/0x31/0x91 만 이해하고 **그 외 세그먼트(포트, 멤버, 32비트 등)가 있으면 경로 전체를 거부**
(0x04) 한다. 같은 종류가 여러 번 나오면 **마지막 값** 이 이긴다.

#### 5.4.3 경로 예

```
Identity 인스턴스 1 속성 1:          20 01 24 01 30 01            (3워드 → Path Size = 03)
Assembly 인스턴스 150 속성 3:        20 04 24 96 30 03            (3워드)
Connection Manager 인스턴스 1:       20 06 24 01                  (2워드)
LLDP Management(0x109) 인스턴스 1 속성 1:
                                     21 00 09 01 24 01 30 01      (4워드)
심볼 태그 "Sensor1":                 91 07 53 65 6E 73 6F 72 31 00 (5워드; 7글자라 패드 1)
```

#### 5.4.4 Port segment — 라우팅

```
  7   6   5   4   3   2   1   0
┌───────────┬───┬───────────────┐
│ 0   0   0 │ E │ Port Identifier│   E=1 이면 링크 주소가 여러 바이트(길이 바이트가 따라옴)
└───────────┴───┴───────────────┘   Port Id 15(0xF)면 16비트 확장 포트 번호가 따라옴
```

예: `01 00` = "포트 1(ControlLogix 백플레인)의 링크 주소 0(슬롯 0)". ControlLogix CPU 에 Unconnected Send 로
보낼 때의 route path 가 대표적이다. [저장소] Adapter 는 FO 연결 경로에서 `0x01` 다음 1바이트만 건너뛴다
(`eip_cm.c:90-92`). 그 외 포트 형식은 거부한다.

### 5.5 Explicit 메시지 예 (검증됨)

모든 예는 세션 `0x0A0B0C0D` 로 등록된 상태에서 보낸 SendRRData 다. 공통 앞부분(40바이트):

```
6F 00 LL LL                      Command=SendRRData, Length
0D 0C 0B 0A                      Session Handle
00 00 00 00                      Status
00 00 00 00 00 00 00 00          Sender Context
00 00 00 00                      Options
00 00 00 00                      Interface Handle = 0
00 00                            Timeout = 0
02 00                            Item count = 2
00 00 00 00                      Item 1: Null Address, 길이 0
B2 00 NN NN                      Item 2: Unconnected Data, 길이 NN
...CIP (NN 바이트)...
```

#### 5.5.1 Get_Attribute_Single — Identity Vendor ID

```
요청 (48바이트):
6F 00 18 00  0D 0C 0B 0A  00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00
00 00 00 00  00 00  02 00  00 00 00 00  B2 00 08 00
0E                Service = Get_Attribute_Single
03                Path Size = 3 워드
20 01             Class 0x01 (Identity)
24 01             Instance 1
30 01             Attribute 1 (Vendor ID)

응답 (46바이트):
6F 00 16 00  0D 0C 0B 0A  00 00 00 00  00×8  00 00 00 00
00 00 00 00  00 00  02 00  00 00 00 00  B2 00 06 00
8E                Reply service = 0x0E | 0x80
00                Reserved
00                General status = Success
00                Additional status size = 0
CD AB             Vendor ID = 0xABCD
```

Length 계산 연습: 요청 본문 = 4(iface) + 2(timeout) + 2(count) + 4(null item) + 4(data item hdr) + 8(CIP) = **24 = 0x18**.

#### 5.5.2 Get_Attributes_All — Identity

```
CIP 요청:  01 02 20 01 24 01
CIP 응답 (41바이트, Unconnected Data 길이 0x29):
81 00 00 00       Reply 0x81, Success
CD AB             attr1 Vendor
0C 00             attr2 Device Type
01 00             attr3 Product Code
01 00             attr4 Revision 1.0
00 00             attr5 Status
78 56 34 12       attr6 Serial
0E 46 69 65 6C 64 62 75 73 53 65 6E 73 6F 72    attr7 Name "FieldbusSensor"
03                attr8 State = Operational
01 00             attr9 Config Consistency = 1
00                attr10 Heartbeat = 0
00 00 00 00       attr17 Protection Mode (저장소)
```

#### 5.5.3 Assembly 데이터 읽기

```
CIP 요청:  0E 03 20 04 24 96 30 03          Get Assembly 150 attr 3
CIP 응답:  8E 00 00 00 00 00 00 00          Success + 입력 이미지 4바이트
```

#### 5.5.4 에러 응답들 (검증됨)

| 상황 | CIP 요청 | [저장소] 응답 | 사양상 기대 |
|---|---|---|---|
| 없는 클래스 0x99 | `0E 03 20 99 24 01 30 01` | `8E 00 05 00` (Path dest unknown) | 동일 |
| Identity 없는 속성 99 | `0E 03 20 01 24 01 30 63` | `8E 00 14 00` (Attribute not supported) | 동일 |
| Identity attr 1 쓰기 | `10 03 20 01 24 01 30 01 34 12` | `90 00 05 00` | ⚠ 0x0E (Attribute not settable) |
| CM 에 Unconnected Send | `52 02 20 06 24 01` | `D2 00 08 00` (Service not supported) | (라우팅 미지원이면) 동일 |
| 잘못된 세션 | (SendRRData, 세션 DEADBEEF) | Encap status `64 00 00 00`, 데이터 없음 | 동일 |
| 모르는 Encap 명령 0x00FF | | Encap status `01 00 00 00` | 동일 |
| Sec Class 1 에서 MAC 없는 Set | `10 03 20 04 24 65 30 03 AA 55` | `90 00 0F 00` (Privilege violation) | 저장소 고유 정책 (7장) |

### 5.6 Forward Open (0x54) — 연결 개설의 모든 필드

#### 5.6.1 요청 필드 [사양]

CIP 요청: `54 02 20 06 24 01` (Service 0x54, 경로 CM/1) 뒤에 아래 데이터.

| # | 오프셋 | 크기 | 필드 | 설명 |
|---|---|---|---|---|
| 1 | 0 | 1 | Priority/Time_tick | bit 4 = priority(보통 0), bit 0-3 = tick. **1 tick = 2^tick ms** |
| 2 | 1 | 1 | Time-out_ticks | 이 **요청 자체** 의 타임아웃 = tick × ticks (라우팅 중 대기용) |
| 3 | 2 | 4 | O→T Network Connection ID | Target 이 정함 (요청값은 의미 없음 — 6.3) |
| 4 | 6 | 4 | T→O Network Connection ID | point-to-point 면 Originator 가 정함 |
| 5 | 10 | 2 | Connection Serial Number | Originator 가 정한 연결 일련번호 |
| 6 | 12 | 2 | Originator Vendor ID | Originator 장치의 벤더 |
| 7 | 14 | 4 | Originator Serial Number | Originator 장치의 시리얼 |
| 8 | 18 | 1 | Connection Timeout Multiplier | 0..7 → ×4 … ×512 (6.4) |
| 9 | 19 | 3 | Reserved | 0 |
| 10 | 22 | 4 | O→T RPI | µs |
| 11 | 26 | 2 (Large: 4) | O→T Network Connection Parameters | 5.6.4 |
| 12 | 28 (L:30) | 4 | T→O RPI | µs |
| 13 | 32 (L:34) | 2 (Large: 4) | T→O Network Connection Parameters | |
| 14 | 34 (L:38) | 1 | Transport Type/Trigger | 5.6.5 |
| 15 | 35 (L:39) | 1 | Connection Path Size | 워드 수 |
| 16 | 36 (L:40) | 가변 | Connection Path | 5.6.6 |

필드 5·6·7 의 묶음을 **connection triad** 라 부르며, 연결을 식별하는 키다 (Forward Close 도 이것으로 찾는다).

[저장소] 파싱: `eip_cm_forward_open()` (`eip_cm.c:127-186`). 최소 길이 36(Large 40)바이트 미만이면
0x20. Priority/tick·timeout ticks·reserved·**transport 바이트는 읽고 버린다** (`eip_cm.c:141-142`, `176`).

#### 5.6.2 Priority/Time_tick 계산

`0A 05` 이면 tick = 2^10 = 1024 ms, ticks = 5 → 이 요청의 타임아웃 약 5.12초.
이 값은 **연결의 워치독과 무관** 하다 (워치독은 RPI × multiplier).

#### 5.6.3 Connection ID 누가 정하나 [사양]

규칙: **데이터를 받는 쪽이 point-to-point 연결 ID 를 정하고, 멀티캐스트는 생산자가 정한다.**

| 방향 | point-to-point | multicast |
|---|---|---|
| O→T (Target 이 소비) | Target 이 정함 | (O→T 멀티캐스트는 드묾) Originator |
| T→O (Originator 가 소비) | **Originator** 가 정함 (요청값 사용) | **Target** 이 정함 |

FO 응답에 최종 ID 가 담기므로 Originator 는 **응답의 ID 를 써야** 한다.
[저장소] 는 요청의 O→T/T→O ID 가 0 이 아니면 **그대로 에코** 하고, 0 이면 `next_conn_id++` (0x20000001부터) 를 준다
(`eip_cm.c:228-233`, `eip_stack.c:157`). ⚠ 불일치: O→T ID 는 Target 이 정해야 한다. 요청에 0 이 아닌 O→T ID 를
보내는 Originator 가 있으면 저장소는 그것을 쓰는데, 두 Originator 가 같은 값을 보내면 O→T 수신에서 첫 연결만 매칭된다
(`eip_io.c:47-52`). 또 순차 ID 는 추측이 쉽다 (12장).

#### 5.6.4 Network Connection Parameters (NCP) 비트

**16비트 (Forward Open)** [사양]:

```
 15   14 13   12   11 10    9    8 ........................ 0
┌────┬───────┬────┬───────┬─────┬─────────────────────────────┐
│Red │ Type  │rsv │Priority│F/V │ Connection Size (bytes, 9비트) │
│Own │       │    │        │     │  최대 511                     │
└────┴───────┴────┴───────┴─────┴─────────────────────────────┘
 Type:     00 Null, 01 Multicast, 10 Point-to-point, 11 예약
 Priority: 00 Low, 01 High, 10 Scheduled, 11 Urgent
 F/V:      0 Fixed size, 1 Variable size
```

**32비트 (Large Forward Open)**: bit 31 Redundant Owner, bit 30-29 Type, bit 28 예약, bit 27-26 Priority,
bit 25 Fixed/Variable, bit 24-16 예약, **bit 15-0 Connection Size** (최대 65535).

예:

| NCP | 해석 |
|---|---|
| `0x4804` | Point-to-point, Scheduled, Fixed, 4바이트 |
| `0x4806` | Point-to-point, Scheduled, Fixed, 6바이트 |
| `0x2806` | **Multicast**, Scheduled, Fixed, 6바이트 (T→O 에 흔함) |
| `0x48000006` (Large) | Point-to-point, Scheduled, Fixed, 6바이트 |

**Connection Size 에 무엇이 포함되나** [사양 — 매우 중요]:
Class 1 연결의 크기는 **I/O 데이터 + 16비트 시퀀스 카운트(2) + (있다면) 32비트 Run/Idle 헤더(4)** 다.
관례적인 Class 1 에서 O→T 는 Run/Idle 헤더가 있고 T→O 는 없다(modeless). 그래서 출력 2바이트·입력 4바이트
장치라면 표준 스캐너는 **O→T = 2+2+4 = 8, T→O = 4+2 = 6** 을 요청한다. (Class 0 은 시퀀스 카운트가 없다.)

[저장소] `conn_size_from_net()` 은 16비트면 `& 0x1FF`, 32비트면 `& 0xFFFF` 로 크기만 꺼내고 Type/Priority/F-V 는
**무시** 한다 (`eip_cm.c:34-40`). `conn_size_matches()` 는 **크기 == Assembly 크기 또는 Assembly 크기 + 2** 만
허용한다 (`eip_cm.c:42-45`). 즉 저장소는 "시퀀스 카운트 있음, Run/Idle 헤더 없음" 형식만 받는다.

⚠ **불일치 (상호운용 최대 위험)**: 표준 O→T 크기(데이터+6)를 보내면 거절된다. 검증:

```
O→T NCP = 0x4808 (2바이트 출력 + seq 2 + Run/Idle 4 = 8)
응답 CIP: D4 00 20 01 09 01
          │  │  │  │  └──┴─ Extended status 0x0109 (Invalid connection size)
          │  │  │  └─ Additional status size = 1 워드
          │  │  └─ General status 0x20 (⚠ 사양은 0x01 Connection failure)
          │  └─ Reserved
          └─ Reply 0x54|0x80
```

Rockwell Generic Ethernet Module, CODESYS 스캐너 같은 상용 Originator 는 기본적으로 O→T 에 32비트 헤더를 쓰므로
이 저장소 Adapter 와 **그대로는 연결되지 않을 가능성이 높다** (11.6, 부록 D). 이 저장소 자체 EDS 도
O→T 헤더를 "32-bit run/idle" 로 선언한다 (10.6).

#### 5.6.5 Transport Type/Trigger 바이트 [사양]

```
  7     6   5   4    3   2   1   0
┌─────┬───────────┬───────────────┐
│ Dir │ Trigger   │ Transport     │
│     │           │ Class         │
└─────┴───────────┴───────────────┘
 Dir:      0 = Client, 1 = Server   (이 연결에서 Target 의 역할)
 Trigger:  000 Cyclic, 001 Change of State, 010 Application Object
 Class:    0, 1, 2, 3
```

| 값 | 의미 | 쓰임 |
|---|---|---|
| `0x01` | Client, Cyclic, Class 1 | 일반적인 주기 I/O |
| `0x11` | Client, COS, Class 1 | 변화 시 전송(+ 하트비트 RPI) |
| `0xA3` | Server, Application, Class 3 | 연결형 explicit 메시징 |

[저장소] 이 바이트를 **읽지 않는다** (`eip_cm.c:176` `off += 1`). ⚠ Class 3·COS·Class 0 요청도 Class 1 cyclic 처럼
받아들인다 (검증: 0xA3 → 성공, 슬롯 점유).

#### 5.6.6 Connection Path

I/O 연결의 경로는 "어느 Assembly 를 config / 소비(O→T) / 생산(T→O) 에 쓸 것인가" 를 말한다. 전형적 Exclusive Owner:

```
[34 04 CD AB 0C 00 01 00 01 00]   (선택) Electronic Key: format 4, vendor, type, product, major, minor
[01 00]                            (선택, 라우팅 시) Port segment
20 04                              Class 0x04 (Assembly)
24 64                              Instance 100 → Configuration Assembly
[80 nn <config data>]              (선택) Simple Data segment: 연결 시 보낼 config 데이터
2C 65                              Connection Point 101 → O→T (Target 이 소비)
2C 96                              Connection Point 150 → T→O (Target 이 생산)
```

사양상 첫 인스턴스(0x24)는 config, 그 다음 connection point 두 개는 **소비(O→T) → 생산(T→O)** 순서다
(사양서 확인 필요: 한쪽만 있는 경우의 해석 규칙).

**Electronic Key 세그먼트 (0x34)** [사양]:

| 바이트 | 필드 |
|---|---|
| 0 | `0x34` |
| 1 | Key Format = 4 |
| 2-3 | Vendor ID (0 = 검사 안 함) |
| 4-5 | Device Type (0 = 검사 안 함) |
| 6-7 | Product Code (0 = 검사 안 함) |
| 8 | Major Revision (bit 7 = Compatibility 비트, bit 0-6 = 리비전) |
| 9 | Minor Revision |

키가 맞지 않으면 CM 에러 0x01 + 0x0114(vendor/product 불일치), 0x0115(device type), 0x0116(revision) [사양].

[저장소] `parse_fo_path()` (`eip_cm.c:61-104`):
- 0x20/0x21 클래스는 **건너뜀** (값 무시), 0x24/0x25/0x2C/0x2D 값은 모두 "인스턴스 목록" 에 넣음 (순서·역할 구분 없음),
  0x34 는 1+8 바이트 건너뜀(**검사 안 함**, 검증: 키 포함 FO 성공), 0x01 은 1바이트 건너뜀, **그 외(0x80 데이터 세그먼트 포함)는 거부**.
- `fo_path_matches_asm()` (`eip_cm.c:106-125`): 목록에 설정된 output 인스턴스 **와** input 인스턴스가 **둘 다** 있어야 통과.
  config 인스턴스는 검사하지 않는다.
- 실패 시 `D4 00 05 01 00 00` (general 0x05, ext 0x0000). 검증: O→T 자리에 198(0xC6) 을 넣은 input-only 형태 경로 → 이 응답.
  ⚠ 사양상 경로 문제는 0x01 + 0x0315(Invalid segment in path) / 0x0117(Invalid produced/consumed application path) 등.

#### 5.6.7 성공 응답 필드 [사양]

| 오프셋 | 크기 | 필드 |
|---|---|---|
| 0 | 4 | O→T Network Connection ID (최종) |
| 4 | 4 | T→O Network Connection ID (최종) |
| 8 | 2 | Connection Serial Number (에코) |
| 10 | 2 | Originator Vendor ID (에코) |
| 12 | 4 | Originator Serial Number (에코) |
| 16 | 4 | O→T API (µs) — Target 이 실제로 쓸 주기 |
| 20 | 4 | T→O API (µs) |
| 24 | 1 | Application Reply Size (워드) |
| 25 | 1 | Reserved |
| 26 | 2×n | Application Reply |

**실패 응답** [사양]: General status 0x01 + extended status, 그리고 데이터로 Connection Serial(2), Originator Vendor(2),
Originator Serial(4), **Remaining Path Size(1)**, Reserved(1). ⚠ [저장소] 실패 응답은 status 부분(6바이트)만 보내고
이 10바이트를 붙이지 않는다 (`cm_err()`, `eip_cm.c:8-20`).

#### 5.6.8 전체 Forward Open 예 (검증됨)

설정: output 2바이트(asm 101), input 4바이트(asm 150), config asm 100.
**저장소가 받는 형식** (O→T = 2+2 = 4, T→O = 4+2 = 6):

```
Encapsulation + CPF (40바이트):
6F 00 42 00  0D 0C 0B 0A  00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00
00 00 00 00  00 00  02 00  00 00 00 00  B2 00 32 00      ← Unconnected Data 50바이트

CIP (50바이트):
54                 Service = Forward_Open
02 20 06 24 01     Path: 2워드, Class 0x06 / Instance 1
0A                 Priority/Time_tick: tick=10 → 1024 ms
05                 Time-out_ticks = 5 → 약 5.1 s
00 00 00 00        O→T Connection ID = 0 (Target 이 정하도록)
11 22 33 44        T→O Connection ID = 0x44332211 (Originator 제안)
34 12              Connection Serial = 0x1234
01 00              Originator Vendor = 0x0001
99 00 00 00        Originator Serial = 0x00000099
01                 Timeout Multiplier = 1 → ×8
00 00 00           Reserved
40 1F 00 00        O→T RPI = 8000 µs
04 48              O→T NCP = 0x4804 (P2P, Scheduled, Fixed, 4바이트)
40 1F 00 00        T→O RPI = 8000 µs
06 48              T→O NCP = 0x4806 (P2P, Scheduled, Fixed, 6바이트)
01                 Transport = Client, Cyclic, Class 1
04                 Connection Path Size = 4워드
20 04 24 64 2C 65 2C 96    Assembly / Config 100 / O→T 101 / T→O 150

응답 CIP (30바이트, Unconnected Data 길이 0x1E):
D4 00 00 00        Reply 0xD4, Success
01 00 00 20        O→T Connection ID = 0x20000001 (Target 할당)
11 22 33 44        T→O Connection ID = 0x44332211 (요청값 에코)
34 12 01 00        Serial 0x1234, Vendor 0x0001
99 00 00 00        Originator Serial
40 1F 00 00        O→T API = 8000 µs (⚠ 저장소는 RPI 를 그대로 에코)
40 1F 00 00        T→O API = 8000 µs
00 00              Application Reply Size 0, Reserved
```

같은 triad 로 한 번 더 보내면: `D4 00 01 01 00 01` (0x01 + ext 0x0100 "Connection in use or duplicate FO") — 사양과 일치.
이 때 저장소 워치독 = 8000 × 4 × 2^1 = **64000 µs** (검증: `watchdog_us=64000`).

**Large Forward Open (0x5B)** 은 NCP 두 칸만 4바이트로 바뀐다. 검증 예 (serial 0x1235):

```
5B 02 20 06 24 01  0A 05  00 00 00 00  11 22 33 44  35 12 01 00 99 00 00 00  01 00 00 00
40 1F 00 00  04 00 00 48  40 1F 00 00  06 00 00 48  01 04 20 04 24 64 2C 65 2C 96
응답: DB 00 00 00  01 00 00 20  11 22 33 44  35 12 01 00 99 00 00 00  40 1F 00 00  40 1F 00 00  00 00
```

16비트 NCP 의 크기 필드는 9비트(최대 511)이므로, 저장소 예제 설정처럼 input 512바이트를 쓰면 T→O 크기가 514 라
**Large Forward Open 이 필수** 다 (`config/example.ethernetip.json` 의 `input_size: 512`). Originator/EDS 가 Large FO 를
지원해야 한다.

### 5.7 Forward Close (0x4E)

요청 [사양]:

| 필드 | 크기 |
|---|---|
| Priority/Time_tick | 1 |
| Time-out_ticks | 1 |
| Connection Serial Number | 2 |
| Originator Vendor ID | 2 |
| Originator Serial Number | 4 |
| Connection Path Size | 1 (워드) |
| Reserved | 1 |
| Connection Path | 가변 (FO 와 같은 경로) |

응답: Serial(2), Vendor(2), Originator Serial(4), Application Reply Size(1), Reserved(1), [Application Reply].
실패: 0x01 + **0x0107 (Target connection not found)** 등.

검증된 예:

```
CIP 요청 (26바이트):
4E 02 20 06 24 01     Forward_Close → CM/1
0A 05                 tick, ticks
34 12 01 00           Serial 0x1234, Vendor 0x0001
99 00 00 00           Originator Serial
04 00                 Path size 4워드, Reserved
20 04 24 64 2C 65 2C 96

CIP 응답 (14바이트):
CE 00 00 00  34 12 01 00  99 00 00 00  00 00
```

[저장소] `eip_cm_forward_close()` (`eip_cm.c:284-328`) 는 triad 만 보고 슬롯을 비운다. 경로는 무시.
⚠ 불일치: triad 가 없어도 **성공** 을 돌려준다 (검증: 같은 FC 두 번째도 `CE 00 00 00 ...`). 사양은 0x01/0x0107.

### 5.8 Class 1 UDP I/O 패킷

#### 5.8.1 사양 형식

```
UDP 2222 데이터그램
┌────────────┬──────────────────────────────────────┬────────────────────────────────────────────────┐
│ Item count │ Sequenced Address Item               │ Connected Data Item                             │
│ 02 00      │ 02 80 | 08 00 | ConnID(4) | EncSeq(4) │ B1 00 | Len(2) | CIP Seq(2) | [Run/Idle(4)] | Data │
└────────────┴──────────────────────────────────────┴────────────────────────────────────────────────┘
```

| 필드 | 크기 | 설명 |
|---|---|---|
| Item count | 2 | 2 |
| Seq Addr Type/Len | 2+2 | `0x8002`, 8 |
| Connection ID | 4 | 이 **방향** 의 연결 ID (O→T 패킷엔 O→T ID) |
| Encapsulation Sequence Number | 4 | 패킷마다 +1. UDP 재정렬/중복 판별 |
| Conn Data Type/Len | 2+2 | `0x00B1`, 이하 길이 |
| CIP Sequence Count | 2 | Class 1 의 16비트 순번 (Class 0 에는 없음) |
| Run/Idle Header | 4 | **32-bit header format 인 경우만** (관례상 O→T). bit 0 = 1 Run / 0 Idle |
| Data | n | Assembly 데이터 |

**수신측 규칙** [사양, 요약 — 세부는 사양서 확인 필요]:
- Encapsulation 순번이 직전보다 "과거" 면(모듈러 비교) 버린다.
- CIP 순번이 직전과 **같으면** 새 데이터가 아니다 → 애플리케이션에 넘기지 않는다(워치독은 갱신).
- Idle 이면 데이터를 출력에 적용하지 않고 "Idle 상태 출력" 으로 둔다.

#### 5.8.2 [저장소] O→T 형식 (검증됨)

저장소는 Run/Idle 헤더 **없는** 형식을 기대한다:

```
02 00                  Item count 2
02 80 08 00            Sequenced Address, len 8
01 00 00 20            O→T Connection ID = 0x20000001
01 00 00 00            Encapsulation seq = 1
B1 00 04 00            Connected Data, len 4
01 00                  CIP Sequence Count = 1
AA 55                  출력 데이터 2바이트 → output 이미지 = AA 55
```

`eip_io_handle_udp()` (`stacks/ethernetip/src/eip_io.c:9-76`):

- 아이템을 순회해 0x8002(ID+순번)와 0x00B1(payload) 를 찾는다. 아이템 길이가 넘치면 드롭.
- O→T ID 로 슬롯을 찾는다. 없으면 `-ENOENT` (조용히 드롭).
- **출발지 IP/포트를 매 패킷마다 연결의 T→O 목적지로 덮어쓴다** (`eip_io.c:57-58`).
- payload 앞 2바이트(CIP 순번)를 **값 확인 없이** 건너뛰고, 나머지를 output 이미지 **앞에서부터** 복사 (`eip_io.c:62-74`).
- 순번 비교(중복/역순 폐기) 없음, Run/Idle 해석 없음.

같은 데이터를 사양 형식(Run/Idle 포함)으로 보내면 어떻게 되나? (정적 분석) — `B1 00 08 00 01 00 01 00 00 00 AA 55` 이면
seq 2바이트를 건너뛴 뒤 `01 00 00 00 AA 55` 6바이트 중 output_size(2) 만큼 `01 00` 을 복사한다. 즉 **Run/Idle 헤더가
출력 데이터로 들어간다.** (그 전에 FO 단계에서 크기 검사로 거절되므로 실제로 이 상황까진 오지 않는다.)

#### 5.8.3 [저장소] T→O 형식 (검증됨)

`eip_io_produce()` (`eip_io.c:106-181`) 가 만든 실제 프레임 (입력 이미지 = DE AD BE EF):

```
첫 생산:
02 00  02 80 08 00  11 22 33 44  01 00 00 00  B1 00 06 00  01 00  DE AD BE EF
       Seq Addr     T→O ConnID   EncSeq=1     Conn Data    CIPseq=1  입력 4바이트
두 번째 생산:
02 00  02 80 08 00  11 22 33 44  02 00 00 00  B1 00 06 00  02 00  DE AD BE EF
```

- Encapsulation 순번은 32비트 `++t2o_seq`, CIP 순번은 그 하위 16비트 — **데이터가 바뀌지 않아도 매번 증가** 한다.
- 헤더 없음(modeless) — 사양 관례상 T→O 와 일치.
- 목적지: 마지막 O→T 의 출발지 (`peer_ip:peer_udp_port`). 하네스 출력 `udp_send to 127.0.0.1:2222` 은 테스트 주입 함수가
  출발지를 127.0.0.1:2222 로 고정하기 때문이다 (`eip_stack.c:842`).

### 5.9 참고: 저장소가 구현하지 않은 두 가지 포맷

직접 구현하거나 Originator 를 만들 때 필요하다.

#### 5.9.1 Unconnected Send (0x52) [사양]

"이 요청을 저 포트 너머 장치에 전달해 줘" 라는 봉투. CM(`20 06 24 01`) 에 보낸다.

| 필드 | 크기 |
|---|---|
| Priority/Time_tick | 1 |
| Time-out_ticks | 1 |
| Message Request Size | 2 (바이트) |
| Message Request | 가변 (안쪽 CIP 요청 전체) |
| Pad | 0 또는 1 (요청 크기가 홀수면) |
| Route Path Size | 1 (워드) |
| Reserved | 1 |
| Route Path | 포트 세그먼트들 (예: `01 00` = 백플레인 슬롯 0) |

예: ControlLogix 슬롯 0 CPU 의 Identity 를 읽기 — 바깥 `52 02 20 06 24 01 | 0A 05 | 06 00 | 0E 02 20 01 24 01 | 01 00 01 00`
(안쪽 요청 `0E 02 20 01 24 01` 6바이트, route path 1워드 `01 00`) — 필드 구성은 사양 지식 기반, 실행 검증 안 함.

#### 5.9.2 SendUnitData (Class 3) [사양]

```
Encap: 70 00 LL LL | Session | 00000000 | Context | 00000000
       00 00 00 00                 Interface handle
       00 00                       Timeout (0)
       02 00                       Item count
       A1 00 04 00  <O→T ConnID>   Connected Address
       B1 00 NN NN  <seq16> <CIP 요청>   Connected Data (앞 2바이트 = Class 3 순번)
```

Target 응답은 T→O Connection ID 와 **같은 순번** 을 담은 SendUnitData 다. 같은 순번이 다시 오면 재전송이므로
처리하지 말고 이전 응답을 재전송한다 (사양서 확인 필요: 세부 규칙).

---

## 6. 동작과 상태

### 6.1 세션 관리

```
TCP accept ──▶ [세션 없음] ──RegisterSession──▶ [세션 H 등록] ──UnRegisterSession / TCP 종료 / 유휴──▶ [폐기]
                  │                                  │
                  └─ SendRRData 등 → status 0x64     └─ SendRRData(H) 허용 (H 가 이 TCP 연결 소유일 때만)
```

[사양] 세션 핸들은 **TCP 연결 하나에 하나** 다. 다른 TCP 연결에서 같은 핸들을 쓰면 안 된다.
TCP/IP 객체 attr 13 (Encapsulation Inactivity Timeout, 기본 120초) 동안 아무것도 안 오면 Target 이 TCP 를 닫는다.

[저장소]:

| 항목 | 동작 | 근거 |
|---|---|---|
| 핸들 소유권 | 세션 슬롯에 `owner_id` (TCP 슬롯 번호 기반) 저장, 요청마다 대조 | `eip_encap.c:82-90`, `eip_internal.h:65-68`, `143-155` |
| 핸들 값 | `seq XOR 부팅별 난수` | `eip_encap.c:105-118`, `eip_stack.c:149-156` |
| 세션 상한 | 64 | `eip_types.h:26` |
| TCP 연결 상한 | 32, **IP 당 4** (`max_conn_per_ip`) | `eip_types.h:27`, `eip_stack.c:433-439` |
| 유휴 종료 | `idle_timeout_ms` 기본 **60초** (사양 attr 13 기본 120초와 다름, attr 13 으로 노출되지도 않음) | `eip_types.h:118`, `eip_stack.c:603-612` |
| TCP 종료 시 | 그 연결 소유 세션 전부 삭제 | `tcp_client_drop()` `eip_stack.c:469-484` |
| TLS 연결 | 별도 owner 네임스페이스 (`EIP_ENCAP_OWNER_TLS`) | `eip_internal.h:144-155` |

### 6.2 TCP 스트림에서 메시지 자르기

```c
/* stacks/ethernetip/src/eip_stack.c:506-536 요지 */
while (rx_len >= 24) {
    need = 24 + le16(rx + 2);          /* Length 필드 */
    if (rx_len < need) break;          /* 아직 덜 옴 → 다음 recv 까지 대기 */
    eip_encap_process(rx, need, ...);  /* 한 메시지 처리 */
    memmove(rx, rx + need, rx_len - need);
    rx_len -= need;
}
```

수신 버퍼는 연결당 8192바이트 (`EIP_TCP_BUF_MAX`, `eip_types.h:20`). 버퍼를 넘치면 **연결을 끊는다**
(`eip_stack.c:498-501`). 사양상 Encapsulation Length 최대는 65511 이지만, 이 저장소는 사실상 ~8KB 메시지까지만 받는다.
처리 결과가 `rc != 0` (길이 불일치 등) 이면 응답 없이 그 메시지를 버리고 다음으로 간다.

### 6.3 연결 상태 기계와 Forward Open 검증 절차

[사양] 연결 객체 상태 (단순화):

```
            Forward Open 수락
 Non-existent ─────────────────▶ Established ──── 워치독 만료 ────▶ Timed Out ──▶ (삭제)
      ▲                              │  │
      │                              │  └── Forward Close ──────────────────────▶ (삭제)
      └──────────────────────────────┘
      (Configuring / Waiting-for-connection-ID 같은 중간 상태도 사양에 있다 — 사양서 확인 필요)
```

**사양상 Target 이 Forward Open 에서 하는 검사(권장 순서, 요약)**:

1. 요청 길이/형식 (→ 0x01 + 0x0205 등, 사양서 확인 필요)
2. 중복 triad? → 0x01/0x0100. 단, 크기 0 "null FO" 는 재설정 의미 (사양서 확인 필요)
3. Transport class/trigger 지원? → 0x01/0x0103
4. Electronic key → 0x01/0x0114·0x0115·0x0116
5. 경로의 Assembly/connection point 유효? → 0x01/0x0315, 0x0117
6. RPI 범위 → 0x01/0x0111 (+ 허용 범위 반환)
7. NCP(Type/Priority/Fixed) 지원? → 0x01/0x0108
8. 크기 → 0x01/0x0109 (또는 0x0127/0x0128 — 사양서 확인 필요)
9. 소유권: 이미 Exclusive Owner 가 있으면 → 0x01/0x0106
10. 자원 → 0x01/0x0113 (Out of connections)
11. 연결 ID 할당, 워치독 장전, 응답

[저장소] `eip_cm_forward_open()` 실제 순서 (`eip_cm.c:127-282`):

```
1. len < 36(40)                   → 0x20 (ext 0)
2. path size 넘침                  → 0x04
3. 경로에 output 과 input 인스턴스가 모두 있나 → 아니면 0x05 (ext 0)
4. o2t/t2o 크기 == asm 또는 asm+2 → 아니면 0x20 + ext 0x0109
5. triad 중복                      → 0x01 + ext 0x0100
6. 빈 슬롯 (최대 32)               → 없으면 0x02 (ext 0)
7. 연결 ID: 요청값≠0 이면 에코, 0 이면 0x2000000n
8. watchdog_us = eip_class1_watchdog_us(O→T RPI 또는 cfg.rpi_us, multiplier)
9. last_rx_ns = now  (워치독 즉시 장전)
10. 성공 응답 (API = RPI 에코)
```

검사하지 않는 것: transport class/trigger, electronic key, RPI 범위, NCP type/priority/fixed-variable, 소유권(Exclusive
Owner 중복 — 다른 triad 면 같은 Assembly 로 연결이 여러 개 생긴다; `class1_lifetime_dual.yaml` 이 이 동작을 고정),
config 데이터.

### 6.4 연결 타임아웃 계산

[사양] Timeout Multiplier 필드 값 N(0..7) 은 배수 4 × 2^N 를 뜻한다.

| N | 배수 | RPI 8 ms 일 때 타임아웃 |
|---|---|---|
| 0 | ×4 | 32 ms |
| 1 | ×8 | 64 ms |
| 2 | ×16 | 128 ms |
| 3 | ×32 | 256 ms |
| 4 | ×64 | 512 ms |
| 5 | ×128 | 1.024 s |
| 6 | ×256 | 2.048 s |
| 7 | ×512 | 4.096 s |

Target 의 O→T 소비 워치독 = **O→T RPI × 배수**, Originator 의 T→O 워치독 = **T→O RPI × 배수**.

[저장소] `eip_class1_watchdog_us()` (`stacks/ethernetip/include/eip_internal.h:199-212`) 가 정확히
`rpi_us × 4 × 2^min(N,7)` 을 계산한다 (RPI 0 이면 8000 으로 대체). 검증: (8000,0)=32000, (8000,1)=64000,
(8000,4)=512000, (10000,7)=5120000 µs.

**초기 워치독** — (사양서 확인 필요) 여러 구현(OpENer 등)은 연결 직후 첫 패킷이 오기 전에는 최소 **10초** 의 넉넉한
초기 타임아웃을 둔다. [저장소] 는 FO 순간부터 RPI×배수 로 바로 장전한다 (`eip_cm.c:248-249`). 그래서 RPI 8 ms, N=0 이면
FO 응답 후 32 ms 안에 첫 O→T 가 와야 한다. 상용 스캐너는 보통 곧바로 보내지만, 느린 Originator 에서는 연결 직후
끊기는 원인이 될 수 있다. 이 조기 장전은 "I/O 없이 FO 만 반복해 슬롯을 고갈시키는" 공격을 막으려고 넣은 것이다
(`docs/reports/security_fixes_20260928.md` G2).

`eip_io_watchdog()` (`eip_io.c:78-104`) 는 매 poll 마다 `now - last_rx_ns > watchdog` 인 슬롯을 비우고
`class1_timeouts` 를 올린다. 연결이 끊겨도 **output 이미지는 마지막 값 그대로** 남는다 (6.7).

### 6.5 I/O 송신 스케줄링 — RPI, API, COS

- **Cyclic**: RPI 마다 생산. 가장 흔함.
- **Change of State (COS)**: 데이터가 바뀔 때 생산 + RPI 마다 하트비트. Production Inhibit Time(최소 간격)을 둔다 (사양서 확인 필요: 세그먼트/파라미터 위치).
- **Application triggered**: 애플리케이션이 생산 시점을 결정.

[저장소] 는 cyclic 만 한다. `eip_io_produce()` (`eip_io.c:106-181`):

```c
if (last_tx_ns != 0 && now < last_tx_ns) continue;   /* 아직 차례 아님 */
... 프레임 작성 ...
if (last_tx_ns == 0) last_tx_ns = now + period;       /* 첫 송신 */
else {
    last_tx_ns += period;                              /* 위상 유지: 절대시각 누적 */
    if (last_tx_ns <= now) last_tx_ns = now + period;  /* 밀렸으면 재정렬(버스트 방지) */
}
```

**중요한 한계**: 이 함수는 **데몬 사이클(`cycle_ms`, 기본 8 ms)마다 한 번** 불린다 (`eip_stack_poll()` →
`eip_stack.c:614-619`, 호출자는 `core/fb_api.c:739` `run_cycle_loop()`). 따라서:

- 실효 최소 주기 = `cycle_ms`. RPI 가 사이클보다 짧으면(예: RPI 2 ms, cycle 8 ms) 8 ms 마다 1개만 나간다.
- RPI 가 사이클의 배수가 아니면 송신 간격이 사이클 단위로 **양자화** 되어 흔들린다 (예: RPI 10 ms, cycle 8 ms → 8/16 ms 간격 혼재).
- 저장소 에이징 결과(8 ms 사이클 편차 0.1 ms, `CLAUDE.md`) 는 **RPI = cycle 배수** 일 때의 이야기다.
- FO 응답의 API 는 RPI 를 그대로 돌려준다 — 실제로 지킬 수 없는 RPI 도 "수락" 한다. 사양은 지원 못 하는 RPI 에 0x0111 을
  주거나 API 로 실제 값을 알려 주게 되어 있다.

같은 poll 안에서 순서는 `accept → TCP → UDP 수신 → 워치독 → 생산 → 송신(flush) → LLDP → TLS` 다 (`eip_stack.c:594-620`).

### 6.6 연결 종류: Exclusive Owner / Input Only / Listen Only

| 종류 | O→T | T→O | 소유 | 조건 |
|---|---|---|---|---|
| **Exclusive Owner** | 출력 데이터(보통 Run/Idle 포함) | 입력 데이터 | 출력의 **유일한** 주인 | 같은 출력 Assembly 에 EO 는 하나만 (0x0106) |
| **Input Only** | 하트비트(데이터 0바이트, 별도 "heartbeat" connection point) | 입력 데이터 (멀티캐스트 가능) | 없음 | 여러 개 가능 |
| **Listen Only** | 하트비트 | **이미 있는** 멀티캐스트 T→O 를 공유 | 없음 | 다른 비-listen-only 연결이 있어야 함 (없으면 0x0119) |
| Redundant Owner | | | 여러 PLC 가 공동 소유 | NCP bit 15 |

Input Only/Listen Only 의 O→T 경로에는 입력 Assembly 대신 **벤더가 정한 heartbeat connection point 번호** 가 들어간다
(예: OpENer 샘플은 이를 위한 별도 인스턴스를 둔다; 번호 관례는 벤더마다 다름). EDS 의 Connection 항목에 선언한다.

[저장소] 는 경로에 output **과** input 인스턴스가 **둘 다** 있어야 통과하므로 Input Only / Listen Only 를 **지원하지 않는다**
(검증: O→T 자리에 198 → `D4 00 05 01 00 00`). 멀티캐스트 T→O 도 없다 (NCP type 무시, 목적지는 항상 유니캐스트).

### 6.7 중복 Forward Open, Forward Close, 해제 시 동작

- **중복 FO** (같은 triad): [사양·저장소 모두] 0x01/0x0100. 단 사양에는 "같은 triad 로 크기 0 을 보내 연결 파라미터를
  재설정" 하는 null/matching FO 개념도 있다 (사양서 확인 필요). 저장소는 없음.
- **Forward Close**: triad 로 찾아 해제. [저장소] 는 없어도 성공 (5.7).
- **연결이 사라질 때 출력은?** [사양/관례] 장치는 "연결 끊김 시 출력 동작"(0으로, 마지막 값 유지, fault 값 등)을
  제품 사양으로 정한다. [저장소] 는 출력 이미지를 **건드리지 않는다** (watchdog·FC 모두 `in_use = 0` 만,
  `eip_io.c:100`, `eip_cm.c:304`). 애플리케이션은 `health()` 의 `connected` 로 끊김을 알아야 한다
  (`adapters/ethernetip/ethernetip_adapter.c:490-498` — 단 TCP 세션만 있어도 connected=1 이라 I/O 끊김과 구분되지 않는다).
- **Identity Reset**: 모든 Class 1 슬롯을 즉시 비움. Originator 에게는 FC 가 아니라 **워치독 타임아웃** 으로 보인다.

### 6.8 Run/Idle 의미

O→T 32비트 헤더의 bit 0 이 1 이면 Run — PLC 가 RUN 모드라 출력이 유효. 0 이면 Idle — PLC 가 PROGRAM 모드 등이라
장치는 출력을 "Idle 상태 값" 으로 둬야 한다 [사양]. 헤더가 없는 연결(modeless)은 데이터가 오면 곧 Run 으로 간주
(사양서 확인 필요). **[저장소] 는 Run/Idle 개념이 없다** — 받은 데이터를 무조건 출력 이미지에 쓴다.
센서처럼 출력이 "트리거" 정도인 장치에서도, PLC 가 PROGRAM 모드로 가면 Idle 로 알려 주는 정보를 잃는 셈이다.

### 6.9 [저장소] 스레드와 락

- 스택은 **자체 스레드가 없다.** 모든 작업은 `eip_stack_poll()` 한 번 안에서 일어나고, 이 함수는 데몬의 단일 사이클
  루프가 부른다.
- `pthread_mutex_t lock` (`eip_internal.h:134`) 은 프로토콜 처리(encap, UDP, produce)와 애플리케이션 API
  (`eip_stack_read_input/write_input/...`, `eip_stack.c:718-794`) 사이의 **I/O 이미지 보호** 용이다.
  `fb_start()` 로 별도 스레드에서 사이클을 돌리는 경우를 대비한 것.
- poll 안의 작업량에는 **예산** 이 있다: TCP accept 8, TCP 클라이언트 8, UDP 64, TLS 4 (`eip_types.h:113-115`).
  poll 이 7 ms 를 넘으면 경고 로그 (`eip_stack.c:627-631`).

---

## 7. CIP Security — 사양과 이 저장소 구현

### 7.1 먼저 결론

| | ODVA CIP Security (Volume 8) | 이 저장소 "Security Class" |
|---|---|---|
| 정체 | TLS(TCP)/DTLS(UDP) 기반 표준 보안 | **저장소 자체 프로파일** (HMAC CPF 아이템 + TLS-PSK 리스너) |
| 이름 | "Profiles" (Confidentiality, Integrity(사양서 확인 필요), Authorization, User Authentication, Resource-Constrained …) | Class 0 / 1 / 2 (PROFINET 의 Security Class 명명을 빌린 내부 용어) |
| 상호운용 | 표준 준수 스캐너/툴과 동작 | **이 저장소 CTT/자체 Originator 외에는 동작하지 않음** |
| 인증 | ODVA CIP Security CT | 해당 없음 |

저장소 문서도 이 점을 명시한다: "ODVA CIP Security 할당 item 코드를 사칭하지 않는다" (`docs/ctt_odva_matrix.md`),
`0x00C1` 은 "vendor-profile integrity item" (`stacks/ethernetip/include/eip_sec.h:21`).

### 7.2 실제 ODVA CIP Security 개요 [사양 — 세부는 사양서 확인 필요]

- 문서: The CIP Networks Library **Volume 8: CIP Security**.
- 기본 아이디어: explicit 메시지는 **TLS** (TCP 2221), I/O 는 **DTLS** (UDP 2221) 로 감싼다. CIP 메시지 포맷 자체는 바꾸지 않는다.
- 자격 증명: X.509 인증서(장치 인증서, CA) 또는 **PSK**(사전 공유 키).
- 무결성만/기밀성까지: 암호화 없는(NULL) cipher suite 로 무결성만, AES 계열로 기밀성까지.
- 객체:
  - **CIP Security Object (0x5D)** — 장치 전체 보안 상태/설정
  - **EtherNet/IP Security Object (0x5E)** — TLS/DTLS 설정, 허용 cipher suite, PSK, 인증서 참조, "보안 연결만 허용" 등
  - **Certificate Management Object (0x5F)** — 인증서/CSR 관리
- 설정 도구(예: Rockwell FactoryTalk Policy Manager 류)가 "pull/push" 로 장치에 정책·인증서를 내려준다.
- I/O 연결: Originator 가 TLS 세션 위에서 Forward Open 을 보내고, 합의된 DTLS 세션으로 Class 1 패킷을 보호한다.
- 이후 판에서 사용자 인증(User Authentication), 권한(Authorization), 자원 제약 장치용 프로파일이 추가되었다.

### 7.3 [저장소] Security Class 0/1/2 — 코드 기준 정확한 동작

설정: `protocol_params.security_class` (0/1/2), `psk_hex` (64 hex = 32바이트), `secure_tcp_port` (기본 2221).
Class ≥1 인데 PSK 가 없으면 어댑터 init 실패 (`adapters/ethernetip/ethernetip_adapter.c:327-332`)와 스택 생성 실패
(`stacks/ethernetip/src/eip_stack.c:89-92`) 두 겹으로 막는다.

**Class 0 (open)**: 보안 없음. 단 Set/Reset 은 여전히 "등록된 세션" 과 `protection_mode == 0` 을 요구 (`gate_set_reset()`).

**Class 1 (integrity)** — `eip_sec.c`:

1. **어떤 요청에 MAC 이 필요한가** — `eip_sec_service_needs_mac()` (`eip_sec.c:29-41`):
   Set_Attribute_Single(0x10), Reset(0x05), Forward_Open(0x54), Large_Forward_Open(0x5B), Forward_Close(0x4E).
   **Get 류는 MAC 없이 허용**.
2. **MAC 위치** — SendRRData CPF 에 세 번째 아이템 `Type 0x00C1, Length 32, HMAC 32바이트` 를 붙인다.
3. **MAC 계산** — `HMAC-SHA256(key = PSK 32바이트, msg = SessionHandle(LE 4바이트) ‖ CIP 요청 전체)`
   (`mac_input()` `eip_sec.c:43-59`, OpenSSL `HMAC()` `eip_crypto.c:7-12`).
4. **검증** — 상수 시간 비교 (`eip_hmac_verify()`, `eip_crypto.c:14-24`). 실패/부재 → CIP 응답 `svc|0x80, 00, 0F, 00`
   (Privilege violation), MAC 없이 (`eip_encap.c:216-242`).
5. **응답 MAC** — 요청 서비스가 MAC 필요 대상이면, 응답에도 `0x00C1` 아이템을 붙인다:
   `HMAC(PSK, SessionHandle ‖ CIP 응답)` (`eip_encap.c:251-257`, `eip_sec.c:95-112`).

**검증된 예** (PSK = `11`×32, 세션 0x0A0B0C0D, Assembly 101 에 `AA 55` 쓰기):

```
MAC 입력 (14바이트):  0D 0C 0B 0A | 10 03 20 04 24 65 30 03 AA 55
                      └session LE┘ └──────── CIP 요청 ────────┘
HMAC-SHA256 =
  C3 83 52 6A 82 21 9D 33 09 A5 FE C2 67 D5 AF C7
  BD 8F 09 5C D8 53 CF BA F2 70 DC 77 4B F9 17 3E

요청 (86바이트):
6F 00 3E 00  0D 0C 0B 0A  00×4  00×8  00×4
00 00 00 00  00 00  03 00                      Item count = 3
00 00 00 00                                    Null Address
B2 00 0A 00  10 03 20 04 24 65 30 03 AA 55     Unconnected Data (CIP)
C1 00 20 00  C3 83 52 6A ... 4B F9 17 3E       저장소 무결성 아이템 (32바이트 MAC)

응답 (80바이트):
6F 00 38 00  0D 0C 0B 0A  00×4  00×8  00×4
00 00 00 00  00 00  03 00
00 00 00 00
B2 00 04 00  90 00 00 00                       Set 성공
C1 00 20 00  03 5B B8 1E A4 4C 25 CA FB F0 7B BD F7 A1 92 B6
             A3 97 0D 86 C0 1F A6 2F 73 7B 83 5C 55 B9 DB D1
             = HMAC(PSK, 0D 0C 0B 0A ‖ 90 00 00 00)  (하네스로 재계산해 일치 확인)
```

같은 요청을 MAC 없이 보내면 `B2 00 04 00 90 00 0F 00` (Privilege violation).

**Class 2 (TLS)** — `eip_sec_tls_start()` / `eip_sec_tls_poll()` (`eip_sec.c:128-184`, `392-415`):

- OpenSSL `TLS_server_method`, 최소 TLS 1.2, cipher `PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA` (`eip_sec.c:146-151`).
- PSK 콜백은 **identity 를 무시** 하고 항상 같은 PSK 를 준다 (`psk_server_cb()`, `eip_sec.c:116-126`).
- TCP `secure_tcp_port`(2221) 에서 비차단 accept/handshake, 이후 **평문 44818 과 똑같은 `eip_encap_process()`** 를 태운다.
- **Class 1 의 HMAC 규칙이 TLS 위에서도 그대로 적용** 된다 (TLS 여부를 구분하는 코드가 없다). 즉 Class 2 에서도 mutating
  요청엔 0x00C1 MAC 이 필요하다.
- **평문 44818 리스너도 계속 열려 있다** — Class 2 는 "TLS 를 추가로 제공" 할 뿐 강제하지 않는다.
- UDP I/O 에는 DTLS 가 없다.

### 7.4 사양 대비 차이 요약

| 항목 | ODVA CIP Security | [저장소] |
|---|---|---|
| explicit 보호 | TLS 세션 전체 | Class 1: 선택된 서비스만 HMAC, Get 은 평문·무인증 |
| I/O 보호 | DTLS | **없음** (UDP 평문, 무인증) |
| 메시지 포맷 변경 | 없음 (전송층에서 보호) | CPF 에 비표준 아이템 0x00C1 추가 |
| 키 | 인증서 또는 PSK, 객체로 관리 | config 파일의 PSK 하나 (`psk_hex`) |
| 재전송(replay) 방지 | TLS/DTLS 레코드 순번 | **없음** — 같은 세션 안에서 같은 요청+MAC 재전송 가능 |
| 보안 객체 | 0x5D/0x5E/0x5F 표준 속성 | 0x5E 에 저장소 고유 속성 3개 |
| 평문 포트 | 정책으로 차단 가능 | 항상 열림 |
| 식별 | 인증서 주체 / PSK identity | identity 무시 |

### 7.5 이 설계의 위협 분석 (구현자가 알아야 할 것)

1. **Replay**: MAC 입력에 순번/난수가 없다. 다른 TCP 연결에서 재전송하면 새 세션 핸들이 발급되고 MAC 입력에 핸들이
   들어가므로 실패한다(세션 결속). 그러나 **같은 TCP 연결 안** 에서는 같은 요청+MAC 이 몇 번이고 유효하다. 평문 44818 위의
   TCP 스트림에 끼어들 수 있는 위치(MITM)라면 캡처한 Set/Forward Open 을 재전송할 수 있다.
2. **UDP I/O 스푸핑**: O→T 연결 ID 는 0x20000001 부터 순차이고, 출발지 IP 검사도 없다. 연결 ID 를 맞힌 아무 호스트가
   출력 이미지를 덮어쓰고, **T→O 목적지를 자기 주소로 바꿀 수 있다** (`eip_io.c:57-58`). 저장소 Security Class 는 이것을 막지 않는다.
3. **Get 은 무인증**: 입력 Assembly(센서값)·Identity 는 누구나 읽는다. Class 2 여도 평문 포트로 읽힌다.
4. **Cipher**: PSK CBC 계열(비 PFS). PSK 가 유출되면 과거 TLS 트래픽도 복호화 가능.
5. **PSK 관리**: config JSON 평문. 예제 PSK(`11…11`)를 제품에 두지 말 것 (`docs/ethernetip_stack.md`).

---

## 8. 에러 처리, 타이밍, 제한값

### 8.1 세 층의 에러

| 층 | 어디에 | 예 |
|---|---|---|
| Encapsulation | 헤더 Status 필드 | 0x0064 잘못된 세션 |
| CIP General/Extended | CIP 응답 byte 2, 추가 상태 | 0x05, 0x01/0x0109 |
| 무응답 | 아무것도 안 보냄 | UDP I/O 오류, 길이 불일치 |

원칙 [사양]: Encapsulation 이 성공(0)이면 CIP 에러는 **CIP 응답 안에** 담는다. 즉 "없는 클래스" 는 Encap status 0 +
CIP status 0x05 다 (검증 5.5.4).

### 8.2 [저장소] 에러 처리 매트릭스 (검증 기반)

| 입력 | 결과 |
|---|---|
| Encap Length > 실제 바이트 | 응답 없음 (`-EINVAL`) |
| 모르는 Encap 명령 / ListInterfaces / SendUnitData | Encap status 0x0001 |
| 세션 없이/남의 세션으로 SendRRData | Encap status 0x0064 |
| CPF 아이템 길이 넘침, CIP 없음 | Encap status 0x0001 (데이터 없음) |
| CIP path size 넘침 / 모르는 세그먼트 | CIP 0x04 |
| 없는 클래스·인스턴스 / 지원 안 하는 서비스 조합 | CIP 0x05 |
| 지원 객체의 모르는 서비스 (CM) | CIP 0x08 |
| 없는 속성 | CIP 0x14 |
| 응답 버퍼 부족 | CIP 0x02 |
| Set/Reset 권한 | CIP 0x0F |
| UDP I/O: 모르는 연결 ID / 형식 오류 | 조용히 드롭 |
| TCP 수신 버퍼 8KB 초과 | TCP 연결 종료 |

로그는 `LOG_WARN("ethernetip", ...)` / `LOG_ERROR` (`core/logger.h`) 로 남긴다 — 저장소 규칙상 `printf` 금지 (`CLAUDE.md`).

### 8.3 제한값

| 상수 | 값 | 의미 | 위치 |
|---|---|---|---|
| `EIP_ENCAP_HDR_SIZE` | 24 | | `eip_types.h:17` |
| `EIP_TCP_BUF_MAX` | 8192 | TCP 수신 버퍼/응답 버퍼 | `eip_types.h:20` |
| `EIP_ASSEMBLY_INSTANCES_MAX` | 64 | (실사용 3) | `eip_types.h:23` |
| `EIP_ASSEMBLY_SIZE_MAX` | 2048 | Assembly 최대 바이트 | `eip_types.h:24` |
| `EIP_CLASS1_CONN_MAX` | 32 | 동시 I/O 연결 | `eip_types.h:25` |
| `EIP_CLASS3_SESSIONS_MAX` | 64 | 세션 | `eip_types.h:26` |
| `EIP_TCP_CLIENTS_MAX` | 32 | TCP 연결 | `eip_types.h:27` |
| `EIP_TLS_CLIENTS_MAX` | 16 | TLS 연결 | `eip_types.h:28` |
| `EIP_PRODUCT_NAME_MAX` | 32 | 제품명 | `eip_types.h:30` |
| `EIP_EXPLICIT_DATA_MAX` | 504 | UCMM CIP 데이터 (사양의 전통적 504바이트 한계와 같음) | `eip_types.h:32` |
| `EIP_PSK_LEN` / `EIP_HMAC_LEN` | 32 / 32 | | `eip_types.h:33-34` |
| `EIP_IDLE_TIMEOUT_MS_DEFAULT` | 60000 | TCP 유휴 종료 | `eip_types.h:118` |
| `EIP_MAX_CONN_PER_IP_DEFAULT` | 4 | IP 당 TCP 연결 | `eip_types.h:119` |
| poll 예산 | TCP 8 / UDP 64 / TLS 4 | 한 poll 에서 처리량 | `eip_types.h:113-115` |
| 16비트 NCP 크기 | 511 | 사양 (Large FO 로 65535) | `eip_cm.c:39` |

### 8.4 타이밍 요약

| 무엇 | 값 |
|---|---|
| 데몬 사이클 | `cycle_ms` (예제 8 ms) |
| Class 1 최소 실효 주기 | `cycle_ms` |
| 워치독 | O→T RPI × 4 × 2^N, FO 순간부터 |
| 기본 RPI (FO 에 0 이 왔을 때) | `rpi_us` (기본 8000) |
| TCP 유휴 | 60 s |
| LLDP TX 주기 | 30 s (메모리에만 생성) |

---

## 9. 직접 구현하기 — 단계별 로드맵

이 장은 "빈 폴더에서 Adapter 를 만든다" 는 가정으로 쓴다. 각 마일스톤은 **이전 것 위에** 쌓이며, 끝날 때마다
검증 방법이 있다. 저장소 코드는 참고 구현으로 병기한다(불일치는 피해서 구현할 것).

### 9.1 모듈 분해

```
┌──────────────────────────────────────────────────────────────┐
│ app API: write_input(off,buf) / read_output(off,buf) / health │  ← 저장소: eip_stack.h
├──────────────────────────────────────────────────────────────┤
│ io.c        Class 1 소비/생산, 워치독, 스케줄러               │  ← eip_io.c
│ cm.c        Forward Open/Close, 연결 테이블                   │  ← eip_cm.c
│ objects/*.c Identity, Assembly, TCP/IP, Ethernet Link, QoS … │  ← eip_cip.c (if 사슬)
│ router.c    EPATH 파싱 → (class,instance,attr) → 객체 테이블  │  ← eip_cip_route_auth, eip_path_asm.c
│ encap.c     24B 헤더, 세션, CPF, 명령 디스패치                │  ← eip_encap.c
│ net.c       TCP listen/accept/스트림 조립, UDP 44818/2222    │  ← eip_stack.c
│ bytes.h     LE 읽기/쓰기, 경계 검사 커서                      │  ← eip_endian.h
└──────────────────────────────────────────────────────────────┘
```

권장: 객체를 **테이블 구동**(class code → 핸들러 구조체) 으로 만든다. 저장소처럼 거대한 if 사슬은 서비스·에러 코드를
객체마다 일관되게 맞추기 어렵다(4.12 의 0x05 낙하 문제가 그 예).

```c
typedef struct {
    uint16_t class_id;
    int (*get_single)(uint16_t inst, uint16_t attr, buf_t *out);   /* 0x14 / 0x05 반환 */
    int (*set_single)(uint16_t inst, uint16_t attr, cur_t *in);    /* 0x0E / 0x13 / 0x15 */
    int (*get_all)(uint16_t inst, buf_t *out);
    int (*custom)(uint8_t svc, uint16_t inst, cur_t *in, buf_t *out); /* CM: 0x54 등 */
} cip_class_t;
```

### 9.2 파서 요령 — 경계 검사 커서

패킷 파서 버그의 거의 전부는 "길이 필드를 믿고 버퍼 밖을 읽는 것" 이다. 모든 읽기를 커서 하나로 강제하라.

```c
typedef struct { const uint8_t *p; size_t n, off; int err; } cur_t;

static uint8_t  rd8 (cur_t *c) { if (c->off + 1 > c->n) { c->err = 1; return 0; }
                                 return c->p[c->off++]; }
static uint16_t rd16(cur_t *c) { if (c->off + 2 > c->n) { c->err = 1; return 0; }
                                 uint16_t v = c->p[c->off] | (c->p[c->off+1] << 8);
                                 c->off += 2; return v; }
static uint32_t rd32(cur_t *c) { uint32_t lo = rd16(c); return lo | ((uint32_t)rd16(c) << 16); }
static cur_t    sub (cur_t *c, size_t len) {          /* 길이만큼 하위 커서 */
    cur_t s = { c->p + c->off, len, 0, 0 };
    if (c->off + len > c->n) { c->err = 1; s.n = 0; } else c->off += len;
    return s;
}
/* 사용: 여러 필드를 다 읽고 마지막에 한 번만 if (c.err) → 에러 응답 */
```

저장소도 같은 원칙(길이 먼저 검사)을 손으로 지킨다: `eip_encap.c:193-201`, `eip_io.c:22-31`. 퍼저가 이 경로를 지킨다 (11.4).

### 9.3 마일스톤

#### M0. 뼈대: TCP 44818 accept + 스트림 조립

- 할 일: 비차단 listen/accept, 연결별 수신 버퍼, "24바이트 헤더 + Length" 단위로 자르기 (6.2).
- 검증: `nc` 로 24바이트 아무거나 보내 보고 연결이 유지되는지, 반쪽만 보내고 나머지를 나중에 보내도 한 메시지로 처리되는지.

#### M1. ListIdentity 응답

- 할 일: 5.2.3 표대로 CPF 아이템 0x000C. **Socket Address 는 빅 엔디안.** UDP 44818 소켓도 열어 브로드캐스트 요청에 응답.
- 검증: Wireshark 필터 `enip.command == 0x0063` 에서 "Identity" 트리가 제대로 펼쳐지는지. Python 한 줄 발견 스크립트:

```python
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.settimeout(1.0)
s.sendto(struct.pack("<HHII8sI", 0x63, 0, 0, 0, b"\0"*8, 0), ("255.255.255.255", 44818))
print(s.recvfrom(1024)[0].hex(" "))
```

#### M2. RegisterSession / UnRegisterSession / NOP

- 할 일: 버전 1 확인(아니면 0x0069), TCP 연결당 세션 1개, 추측 어려운 핸들, NOP 무응답, UnRegister 시 TCP 종료.
- 검증: 세션 없이 SendRRData → 0x0064. 다른 TCP 연결에서 남의 핸들 → 0x0064 (저장소 `test_g5_session_owner_and_close`).

#### M3. SendRRData + Message Router + Identity Get_Attribute_Single

- 할 일: CPF 파싱(Null + 0x00B2), CIP 요청 파싱, EPATH(0x20/0x21/0x24/0x25/0x30/0x31), Identity attr 1~7, 응답 포장.
- 검증: 5.5.1 의 hex 를 그대로 보내 같은 응답이 나오는지. `pycomm3` 의 generic message 기능이나 Wireshark 의 CIP 디섹터로 확인.

```
/* 의사코드: CIP 라우터 */
route(req):
    svc = rd8; words = rd8; path = sub(words*2)
    (cls, inst, attr) = parse_epath(path)       실패 → [svc|0x80, 0, 0x04, 0]
    obj = find_class(cls)                       없음 → 0x05
    switch svc:
      0x0E: if !obj.get_single → 0x08;  return obj.get_single(inst, attr)
      0x10: 권한/보안 검사 → 0x0F;       return obj.set_single(inst, attr, data)
      0x01: return obj.get_all(inst)
      default: obj.custom ? obj.custom(...) : 0x08
```

#### M4. Assembly 객체

- 할 일: 입력/출력/config 인스턴스, attr 3(Data), attr 4(Size). Set 은 정확한 길이만(0x13/0x15), 소유 연결이 있으면 거부.
- 검증: Get 150/3 → 입력 이미지, Set 101/3 → 출력 이미지 변화.

#### M5. Forward Open (Class 1, Exclusive Owner)

핵심. 6.3 의 검사 순서를 **사양 에러 코드로** 구현한다.

```
/* 의사코드: Forward Open */
fo(req, large):
    parse 5.6.1 필드 (large 면 NCP 32비트)          부족 → 0x01/0x0205(?) 또는 0x13
    if find_triad(serial, vendor, oser) → 0x01/0x0100
    tt = transport byte; if (tt & 0x0F) != 1 or trigger != cyclic → 0x01/0x0103
    path: [ekey] 20 04 24 cfg [80 data] 2C cons 2C prod
          ekey 불일치 → 0x0114/0x0115/0x0116
          cons/prod 가 내 Assembly 아님 → 0x0315 / 0x0117
    if RPI 범위 밖 → 0x01/0x0111
    size_ot = NCP.size;  expect_ot = out_size + 2 + (O→T 헤더 ? 4 : 0)
    size_to = NCP.size;  expect_to = in_size + 2
    불일치 → 0x01/0x0109 (또는 0x0127/0x0128)
    if 출력 Assembly 에 이미 EO → 0x01/0x0106
    slot = alloc                                  없음 → 0x01/0x0113
    slot.ot_id = random_unique()                  ← Target 이 정함
    slot.to_id = NCP_to.type==multicast ? random_unique() : req.to_id
    slot.timeout = ot_rpi * (4 << mult)
    slot.first_deadline = now + max(timeout, 10s)  ← 초기 워치독 여유 (사양서 확인)
    slot.dst = originator_ip:2222 (Sockaddr 0x8001 있으면 그 값)
    응답 5.6.7 (API = 실제 지킬 수 있는 주기), 필요시 Sockaddr 아이템
```

- 검증: 5.6.8 hex. 실패 경로마다 CIP 응답에 **triad + remaining path size** 가 붙는지 Wireshark 로 확인.

#### M6. Class 1 I/O

```
/* 의사코드: UDP 2222 수신 */
on_udp(buf, src):
    cpf 파싱 → 0x8002(conn_id, enc_seq), 0x00B1(payload)
    c = find_by_ot_id(conn_id);  없음 → drop
    if src.ip != c.originator_ip → drop          ← 스푸핑 1차 방어
    if !seq_newer(enc_seq, c.last_enc_seq) → drop  (32비트 모듈러 비교)
    cip_seq = le16(payload); p = payload + 2
    if c.ot_has_run_idle: run = le32(p) & 1; p += 4
    c.deadline = now + c.timeout                  ← 워치독 갱신은 중복이어도
    if cip_seq == c.last_cip_seq → return         ← 새 데이터 아님
    if run: memcpy(output_image, p, out_size)  else: apply_idle_outputs()

/* 생산: 전용 타이머나 사이클 루프에서 */
for each c: if now >= c.next_tx:
    frame = [02 00][02 80 08 00][to_id][++enc_seq][B1 00 len][cip_seq][input_image]
    sendto(c.dst); c.next_tx += c.to_api   (밀리면 now+api 로 재정렬)
```

```c
/* 32비트 순번 비교 (랩어라운드 안전) */
static int seq_newer(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
```

- 검증: Wireshark `udp.port == 2222` 에서 "CIP I/O" 로 디코드되는지(FO 를 함께 캡처해야 연결 ID 를 안다),
  패킷 간격 그래프(Statistics → I/O Graph)가 RPI 에 붙는지, O→T 를 끊으면 timeout 후 T→O 가 멈추는지.

#### M7. Forward Close + 연결 정리

- 할 일: triad 로 찾기, 없으면 0x01/0x0107, 경로 일치 확인(사양서 확인 필요), 출력 안전값 적용.
- 검증: FC 후 T→O 중단, 같은 triad 로 FO 재개 가능 (저장소 `class1_lifetime.yaml` 과 같은 흐름).

#### M8. TCP/IP·Ethernet Link·QoS 객체, 실제 값

- 할 일: 실제 IP/마스크/MAC/링크 상태, attr 13 유휴 타임아웃, DSCP 를 소켓에 적용(`setsockopt(IP_TOS, dscp << 2)`).
- 검증: 스캐너 툴의 장치 속성 화면, Wireshark 에서 IP DSCP 필드.

#### M9. EDS 작성과 상용 스캐너 연동

- 할 일: 10.6 의 EDS 구조로 파일 작성, ODVA 의 EDS 검사 도구(EZ-EDS 등, 회원용 — 사양서 확인 필요)로 문법 검사.
- 검증: Studio 5000 / CODESYS 에 EDS 등록 → 연결 성공 → I/O 값 확인 (11.6).

#### M10 (선택). Class 3, Unconnected Send 라우팅, CIP Security(TLS/DTLS)

### 9.4 타이머/스레드 설계

| 방식 | 장점 | 단점 | 이 저장소 |
|---|---|---|---|
| 단일 루프 + 주기 poll | 락 적음, 단순 | 생산 주기가 루프 주기에 양자화 | **이 방식** (`cycle_ms`) |
| 단일 루프 + `epoll` + `timerfd` (가장 가까운 deadline 까지 대기) | RPI 정확, CPU 효율 | 구현 조금 복잡 | |
| I/O 전용 RT 스레드 (SCHED_FIFO) + explicit 스레드 | 지터 최소 | 이미지 공유에 락/더블버퍼 필요 | |

I/O 이미지는 **더블 버퍼(또는 seqlock)** 로 두면 생산 스레드가 애플리케이션 쓰기 도중의 "반쯤 쓴" 값을 보내지 않는다.
저장소는 mutex 로 memcpy 구간을 보호한다 (`eip_stack.c:737-755`).

### 9.5 Originator(클라이언트) 측 구현

Originator 는 Adapter 의 거울이다.

1. TCP 연결 → RegisterSession → 핸들 보관.
2. UCMM Get/Set: SendRRData(Null + 0x00B2). 응답의 **General status 와 Additional status size** 를 확인하고, 데이터는
   `4 + 2*addl_size` 바이트 뒤부터다. (저장소 `originator_sendrr()` 가 이렇게 한다, `stacks/ethernetip/src/eip_client.c:120-139`.)
3. 백플레인 너머(ControlLogix 슬롯 N CPU)면 Unconnected Send(0x52) + route path `01 N` 로 감싼다 (5.9.1).
4. I/O 가 필요하면 Forward Open 을 **보내는 쪽** 이 된다: triad 생성(연결마다 serial 증가), T→O ID 를 정하고, O→T 에
   Run/Idle 헤더를 붙여 RPI 마다 생산, T→O 워치독.
5. 끝낼 때 Forward Close → UnRegisterSession → TCP close.

**Logix 태그 읽기는 Get_Attribute_Single 이 아니다.** Rockwell Logix 컨트롤러는 심볼 경로(`91 len name`)에
**Read Tag(0x4C)** 서비스와 요소 개수(UINT)를 보내고, 응답은 데이터 타입(UINT, 예: DINT=0x00C4) + 데이터다. Write Tag(0x4D)는
타입 + 개수 + 데이터 (Rockwell 문서 "Logix5000 Data Access" 기반, 벤더 전용 — 사양서 확인 필요).

[저장소] Originator 의 현재 한계 (`eip_client.c`, `eip_stack.c:246-305`):

| 항목 | 저장소 |
|---|---|
| RegisterSession | 2초 blocking 대기, 응답 status 확인 안 함 |
| explicit Get/Set | UCMM 직접 전송(라우팅 없음) — 대상이 직접 Message Router 를 가진 장치여야 함 |
| 태그 R/W | ⚠ Get/Set_Attribute_Single + 심볼 경로 (Logix 는 0x4C/0x4D 를 기대 → 실 PLC 에서 동작 안 할 가능성 높음) |
| 응답 수신 | `recv` 1회 — TCP 조각 난 응답 재조립 없음 |
| Security Class 1 대상 | MAC 아이템을 붙이지 않음 → 보안 Target 에 Set 불가 |
| Class 1 Originator | 없음 (헤더 주석의 "optional Class1" 은 미구현) |
| mock/adapter 모드 태그 R/W | 자기 자신의 입력 Assembly 로 루프백 (`eip_client.c:246-262`) |

실사용 Originator 참고 구현(오픈소스): **EIPScanner**(C++), **pycomm3**(Python, Logix 중심), **cpppo**(Python),
**libplctag**(C). Adapter 참고 구현: **OpENer**(C, ODVA 회원사들이 유지). 라이선스·정확성은 각 프로젝트에서 확인할 것.

---

## 10. 이 저장소의 구현 지도

### 10.1 파일 지도

| 파일 | 줄 수 | 역할 |
|---|---|---|
| [`stacks/ethernetip/include/eip_types.h`](../../stacks/ethernetip/include/eip_types.h) | 134 | 포트·명령·아이템·서비스·클래스·상태 상수, 용량 한도 |
| [`stacks/ethernetip/include/eip_endian.h`](../../stacks/ethernetip/include/eip_endian.h) | 33 | LE 헬퍼 |
| [`stacks/ethernetip/include/eip_stack.h`](../../stacks/ethernetip/include/eip_stack.h) | 135 | 공개 API, `eip_cfg_t` |
| [`stacks/ethernetip/include/eip_internal.h`](../../stacks/ethernetip/include/eip_internal.h) | 221 | 내부 구조체(`struct eip_stack`, 연결/세션), 워치독 공식 |
| [`stacks/ethernetip/include/eip_sec.h`](../../stacks/ethernetip/include/eip_sec.h) | 43 | 보안 API, `0x00C1` |
| [`stacks/ethernetip/include/eip_crypto.h`](../../stacks/ethernetip/include/eip_crypto.h) | 16 | HMAC API |
| [`stacks/ethernetip/src/eip_encap.c`](../../stacks/ethernetip/src/eip_encap.c) | 399 | Encapsulation, 세션, SendRRData |
| [`stacks/ethernetip/src/eip_cip.c`](../../stacks/ethernetip/src/eip_cip.c) | 668 | Message Router + 모든 객체 |
| [`stacks/ethernetip/src/eip_cm.c`](../../stacks/ethernetip/src/eip_cm.c) | 328 | Forward Open/Close |
| [`stacks/ethernetip/src/eip_io.c`](../../stacks/ethernetip/src/eip_io.c) | 181 | Class 1 소비·생산·워치독 |
| [`stacks/ethernetip/src/eip_path_asm.c`](../../stacks/ethernetip/src/eip_path_asm.c) | 283 | EPATH 인코드/디코드, Assembly 저장소, 시계 |
| [`stacks/ethernetip/src/eip_client.c`](../../stacks/ethernetip/src/eip_client.c) | 301 | Originator explicit |
| [`stacks/ethernetip/src/eip_sec.c`](../../stacks/ethernetip/src/eip_sec.c) | 415 | HMAC 무결성, TLS-PSK 리스너 |
| [`stacks/ethernetip/src/eip_crypto.c`](../../stacks/ethernetip/src/eip_crypto.c) | 24 | OpenSSL HMAC-SHA256 래퍼 |
| [`stacks/ethernetip/src/eip_lldp.c`](../../stacks/ethernetip/src/eip_lldp.c) | 101 | LLDP 프레임 생성(송신 안 함) |
| [`stacks/ethernetip/src/eip_stack.c`](../../stacks/ethernetip/src/eip_stack.c) | 845 | 생성/소켓/poll 루프/앱 API/테스트 주입 |
| [`stacks/ethernetip/eds/FieldbusSensor.eds`](../../stacks/ethernetip/eds/FieldbusSensor.eds) | 91 | EDS |
| [`adapters/ethernetip/ethernetip_adapter.c`](../../adapters/ethernetip/ethernetip_adapter.c) | 530 | config 파싱, 포인트 ↔ 이미지 매핑 |

### 10.2 개념 ↔ 함수 매핑

| 개념 | 함수 | 위치 |
|---|---|---|
| 스택 생성·기본값·보안 설정 검사 | `eip_stack_create()` | `stacks/ethernetip/src/eip_stack.c:40` |
| 소켓 열기 (TCP 44818, UDP 2222, TLS 2221) | `eip_stack_start()`, `bind_tcp_listen()`, `bind_udp()`, `eip_sec_tls_start()` | `eip_stack.c:307`, `:217`, `:193`, `eip_sec.c:128` |
| 한 사이클 처리 | `eip_stack_poll()` | `eip_stack.c:582` |
| TCP accept + IP 당 제한 | `accept_clients()` | `eip_stack.c:420` |
| TCP 스트림 → Encap 메시지 | `service_tcp_client()` | `eip_stack.c:486` |
| Encapsulation 디스패치 | `eip_encap_process()` | `stacks/ethernetip/src/eip_encap.c:288` |
| 헤더 작성 | `encap_hdr()` | `eip_encap.c:8` |
| ListIdentity | `build_list_identity()` | `eip_encap.c:23` |
| 세션 발급/소유/삭제 | `session_alloc()`, `session_owned()`, `session_drop()`, `eip_encap_drop_owner()` | `eip_encap.c:120`, `:82`, `:142`, `:152` |
| SendRRData (UCMM) | `handle_sendrr()` | `eip_encap.c:168` |
| Message Router | `eip_cip_route_auth()` → `handle_object()` | `stacks/ethernetip/src/eip_cip.c:620`, `:241` |
| Set/Reset 권한 게이트 | `gate_set_reset()` | `eip_cip.c:213` |
| Identity 속성 | `identity_get_attr()`, `identity_get_attr_all()` | `eip_cip.c:39`, `:143` |
| Assembly 속성 | `assembly_get_attr()`, `assembly_set_attr()` | `eip_cip.c:172`, `:198` |
| CIP 응답 헤더 | `cip_ok_header()`, `cip_error()` | `eip_cip.c:27`, `:10` |
| EPATH 인코딩 | `eip_path_append_class/instance/attribute/ansi_tag()` | `stacks/ethernetip/src/eip_path_asm.c:21/42/63/84` |
| EPATH 디코딩 | `eip_path_parse()` | `eip_path_asm.c:105` |
| Assembly 저장소 | `eip_assembly_init/find/read/write()` | `eip_path_asm.c:208/245/255/271` |
| Forward Open | `eip_cm_forward_open()` | `stacks/ethernetip/src/eip_cm.c:127` |
| FO 경로 해석 | `parse_fo_path()`, `fo_path_matches_asm()` | `eip_cm.c:61`, `:106` |
| 연결 크기 검사 | `conn_size_from_net()`, `conn_size_matches()` | `eip_cm.c:34`, `:42` |
| 중복 triad | `find_dup_triad()` | `eip_cm.c:47` |
| Forward Close | `eip_cm_forward_close()` | `eip_cm.c:284` |
| 워치독 공식 | `eip_class1_watchdog_us()` | `stacks/ethernetip/include/eip_internal.h:200` |
| O→T 소비 | `eip_io_handle_udp()` | `stacks/ethernetip/src/eip_io.c:9` |
| 워치독 만료 | `eip_io_watchdog()` | `eip_io.c:78` |
| T→O 생산 | `eip_io_produce()` → `flush_produces()` | `eip_io.c:106`, `eip_stack.c:562` |
| HMAC 필요 서비스 | `eip_sec_service_needs_mac()` | `stacks/ethernetip/src/eip_sec.c:29` |
| HMAC 검증/부착 | `eip_sec_check_ucmm()`, `eip_sec_append_mac_item()` | `eip_sec.c:61`, `:95` |
| TLS 서비스 | `tls_accept()`, `tls_service()`, `eip_sec_tls_poll()` | `eip_sec.c:266`, `:337`, `:392` |
| Originator 연결 | `connect_originator()` | `eip_stack.c:246` |
| Originator UCMM | `originator_sendrr()`, `eip_stack_explicit_get/set()`, `eip_stack_tag_read/write()` | `stacks/ethernetip/src/eip_client.c:48/142/191/229/266` |
| ACD 주입 | `eip_stack_acd_conflict()` | `eip_stack.c:634` |
| LLDP | `eip_lldp_build()`, `eip_lldp_poll()` | `stacks/ethernetip/src/eip_lldp.c:32`, `:75` |
| 앱 I/O 이미지 API | `eip_stack_read_input/write_input/read_output/write_output()` | `eip_stack.c:718/737/757/776` |
| 테스트 주입 | `eip_stack_handle_encap()`, `eip_stack_handle_encap_owned()`, `eip_stack_handle_io()` | `eip_stack.c:814`, `:796`, `:836` |
| RT 통계 | `eip_stack_rt_stats()` | `eip_stack.c:656` |

### 10.3 핵심 자료구조

- `eip_cfg_t` (`stacks/ethernetip/include/eip_stack.h:25-67`) — 역할, 포트, Identity 값, Assembly 번호/크기, RPI, mock,
  보안, DoS 한도, LLDP/ACD 옵션.
- `struct eip_stack` (`eip_internal.h:70-136`) — 소켓들, 세션 배열, TCP/TLS 클라이언트 배열, **Class 1 연결 배열 32개**,
  Assembly 배열, I/O 이미지 포인터, QoS/ACD/LLDP 상태, RT 통계, mutex.
- `eip_class1_conn_t` (`eip_internal.h:19-42`) — 연결 ID 두 개, 크기, RPI 두 개, peer IP/포트(첫 O→T 에서 학습),
  순번, 마지막 수신 시각, 다음 송신 시각, triad, 배수, 워치독, 마지막 생산 프레임 버퍼.

### 10.4 코어 → 어댑터 → 스택: 어떻게 구동되나

```
core/main.c:41  fb_run()
  └ core/fb_api.c:739  run_cycle_loop()   매 cycle_ms (기본 8ms) 절대시각 sleep
      └ adapter->poll_cycle()             = eip_poll_cycle()     adapters/ethernetip/ethernetip_adapter.c:400
          └ eip_stack_poll()                                      stacks/ethernetip/src/eip_stack.c:582
응용(센서 앱)
  └ fb_write_point("barcode_value", ...)  core/fb_api.c
      └ adapter->write_point()            = eip_write_point()    ethernetip_adapter.c:463
          └ eip_stack_write_input(off, ...)  (T→O 이미지)
```

어댑터 등록은 `core/adapter_registry.c:29` 한 줄뿐이다 — 코어는 EtherNet/IP 를 전혀 모른다 (`CLAUDE.md` 규칙).
(`core/scheduler.c:28` `scheduler_run()` 도 같은 모양의 루프를 가진다.)

### 10.5 config: protocol_params 와 points

**protocol_params** — 어댑터가 cJSON 으로 직접 읽는다 (`eip_init()`, `ethernetip_adapter.c:137-377`):

| 키 | 기본 (어댑터) | 의미 |
|---|---|---|
| `role` | `"server"` | `"client"` 면 Originator |
| `bind_ip` / `ip` | "" (0.0.0.0) | Adapter: 바인드 주소 / Originator: `ip` 가 원격 |
| `remote_ip` | | Originator 원격 |
| `port` | 44818 | TCP (Originator 원격 포트 겸용) |
| `udp_io_port` | 2222 | Class 1 UDP |
| `vendor_id`, `device_type`, `product_code`, `serial_number`, `product_name` | 0xABCD, 0x0C, 1, (스택 기본 0x12345678), "FieldbusSensor" | Identity |
| `input_assembly` / `output_assembly` / `config_assembly` | 150 / 101 / 100 | Assembly 번호 |
| `assembly_instance` | | 옛 키 → input_assembly |
| `input_size` / `output_size` | 256 / 256 | 이미지 바이트 (points 가 더 필요하면 자동 확장) |
| `rpi_us` | 8000 | FO 에 RPI 0 일 때 기본 |
| `security_class` | 0 | 0/1/2 (7장) |
| `psk_hex` | | 64 hex. Class≥1 필수 |
| `secure_tcp_port` | 2221 | TLS |
| `protection_mode` | 0 | 비0 이면 Set/Reset 전부 0x0F |
| `idle_timeout_ms` / `max_conn_per_ip` | 60000 / 4 | TCP DoS 한도 |
| `iface`, `lldp_enable`, `lldp_tx_interval_sec`, `acd_enable` | "", true, 30, true | LLDP/ACD |
| `mock` | false | true 면 소켓 없음 (테스트) |

`major_rev`/`minor_rev` 는 config 키가 없다 (어댑터가 1/0 고정, `ethernetip_adapter.c:161-162`). `config_size` 도 키가 없다(1바이트).

**points** — `address.ethernetip` 의 세 가지 형태 (`parse_points()`, `ethernetip_adapter.c:71-135`):

| 형태 | 예 | Adapter 역할에서 | Originator 역할에서 |
|---|---|---|---|
| assembly + offset | `{ "assembly": 150, "byte_offset": 0, "length": 32 }` | 이미지 오프셋 | (이미지 오프셋) |
| tag | `{ "tag": "Sensor1.Barcode" }` | 이미지 오프셋 (tag 무시) | `eip_stack_tag_read/write()` |
| CIP path | `{ "class_id": 4, "instance": 150, "attribute": 3 }` | 이미지 오프셋 0 (path 무시) | `eip_stack_explicit_get/set()` |

Adapter 역할의 핵심 규칙 (`eip_read_point()` `:418-461`, `eip_write_point()` `:463-488`):

- `access: "read"` 포인트 → **입력(T→O) 이미지**, `byte_offset` 위치. 앱은 `write_point` 로 여기에 센서값을 **쓴다**.
- `access: "write"` 포인트 → **출력(O→T) 이미지**. 앱은 `read_point` 로 PLC 가 보낸 값을 **읽는다**.
- ⚠ `assembly` 숫자는 **기본값 채우기에만** 쓰이고 실제 읽기/쓰기는 항상 설정된 input/output 이미지로 간다. `assembly: 100`
  (config) 같은 값을 적어도 config Assembly 로 가지 않는다.
- ⚠ `write_point` 는 access 와 무관하게 **항상 입력 이미지** 에 쓴다 (`:484-487`). "write" 포인트에 앱이 쓰면 같은 오프셋의
  입력 이미지가 바뀐다 — 설계 의도(센서는 입력만 생산)지만 이름이 헷갈리기 쉽다.
- 포인트의 `offset + length` 가 이미지보다 크면 이미지를 자동 확장 (최대 2048) (`:342-362`).

**예제 해설** — [`config/example.ethernetip.json`](../../config/example.ethernetip.json):

```
input_assembly 150 / input_size 512   → T→O 514바이트(seq 포함) → Large Forward Open 필요 (5.6.8)
output_assembly 101 / output_size 128 → O→T 130 허용 (Run/Idle 포함 134 는 거절 ⚠)
security_class 1 + psk_hex 11…11      → FO/Set/Close 에 0x00C1 MAC 필요 → 상용 스캐너 불가
mock: true                            → 소켓을 열지 않음! 데몬으로 돌려도 네트워크에 안 보임
points:
  barcode_value  read  offset 0  len 32  → 입력 이미지 0..31
  status_word    read  offset 32 len 2   → 입력 이미지 32..33
  trigger        write offset 0  len 1   → 출력 이미지 0 (PLC 가 씀)
```

실제 스캐너와 붙이려면 [`config/example.codesys.ethernetip.json`](../../config/example.codesys.ethernetip.json)
(`mock: false`, `security_class: 0`, input 64 / output 16) 이나
[`config/example.sw_master.ethernetip.json`](../../config/example.sw_master.ethernetip.json) (루프백 15562/15563) 를 본다.

### 10.6 EDS 파일 해설

EDS(Electronic Data Sheet)는 INI 비슷한 텍스트 파일로, 스캐너 설정 툴이 "이 장치는 어떤 Assembly 를 몇 바이트로, 어떤
RPI 범위로 연결할 수 있다" 를 알게 해 준다. [`stacks/ethernetip/eds/FieldbusSensor.eds`](../../stacks/ethernetip/eds/FieldbusSensor.eds):

| 섹션 | 내용 | 코멘트 |
|---|---|---|
| `[File]` | 설명, 날짜, Revision 1.1 | |
| `[Device]` | VendCode 43981(0xABCD), ProdType 12, ProdCode 1, MajRev 1, **MinRev 1**, ProdName | ⚠ 스택 Identity minor rev 는 0 (어댑터 고정) → 전자키 minor 검사 시 불일치 |
| `[Device Classification]` | `Class1 = EtherNet/IP` | |
| `[Params]` | Param1 "Input Size" | 링크 경로가 placeholder |
| `[Assembly]` | Assem100 Config(1), Assem101 Output(128), Assem150 Input(512) | |
| `[Connection Manager]` | Connection1 Exclusive Owner | 아래 참고 |
| `[Port]` | TCP 포트 | 표준 형식과 다름(사양서 확인 필요) |
| `[Capacity]` | MaxIOConnections 32 등, `TSpec1 = TCP, 44818` | ⚠ TSpec 은 보통 `TxRx, 연결크기, 초당패킷` 형식 (사양서 확인 필요) |
| `[LLDP Management]` | 클래스 0x109 | |

**Connection1 해석** [사양의 EDS Connection 항목 필드 순서 — 사양서 확인 필요]:
`trigger&transport(DWORD), connection params(DWORD), O→T RPI, O→T size, O→T format, T→O RPI, T→O size, T→O format,
config1 size, config1 format, config2 size, config2 format, name, help, path`.

- 첫 DWORD `0x04010002`: bit 1 = Class 1, bit 16 = Cyclic, bit 24-27 의 값 4 = Exclusive Owner (OpENer 샘플 EDS 와 같은 값).
  EDS 주석은 "Exclusive Owner" 라고만 적었다.
- 둘째 DWORD `0x44640405`: bit 0 O→T fixed, bit 2 T→O fixed, **bit 8-10 = 4 → O→T 헤더 = 32비트 Run/Idle**, bit 12-14 = 0 →
  T→O pure data, bit 16-19 = 4 → O→T P2P, bit 20-23 = 6 → T→O multicast/P2P, bit 24-31 = scheduled 우선순위.
  EDS 주석은 이것을 "trigger & transport" 라고 잘못 부른다.
- ⚠ **EDS 는 O→T 32비트 Run/Idle 헤더를 선언하지만 스택은 그 형식을 거절한다** (5.6.4). 이 EDS 로 설정한 스캐너는
  O→T 크기 = 128+6 = 134 를 보내고 0x0109 로 실패할 것으로 예상된다(정적 분석; 실기 미검증).
- 이후 필드 `1000000,8000, 128, 1000000,8000, 512, ,, ,Assem100,,Assem101,Assem150,,` 는 위 필드 순서와 칸 수가 맞지 않는다
  (RPI 자리에 두 값, format 자리에 크기 등). EZ-EDS 류 검사기로 검증이 필요하다. 표준에 가까운 모양 예:

```
Connection1 =
    0x04010002,                 $ trigger & transport: Class1, cyclic, exclusive owner
    0x44640405,                 $ conn params: O→T 32bit run/idle, T→O pure data, ...
    ,,Assem101,                 $ O→T RPI(기본), size(비움 = Assembly 크기), format(Assembly 참조)
    ,,Assem150,                 $ T→O RPI, size, format
    ,,                          $ config part 1
    ,,                          $ config part 2
    "Exclusive Owner",          $ name
    "",                         $ help
    "20 04 24 64 2C 65 2C 96";  $ path: config 100, O→T 101, T→O 150
```

(스택이 Run/Idle 을 지원하지 않는 동안에는 둘째 DWORD 의 O→T 헤더 비트를 "pure data" 로 바꾸는 것이 EDS-스택 일관성에 맞다.)

### 10.7 이 저장소에만 있는 동작 (알아 둘 것)

| 동작 | 위치 |
|---|---|
| 심볼 태그 경로(클래스 없이 0x91)는 **입력 Assembly attr 3** 으로 매핑 | `eip_cip.c:648-658` |
| Set/Reset 은 세션 소유 + (Class≥1 이면 인증) + protection_mode 0 필요 | `eip_cip.c:213-239` |
| protection_mode ≠ 0 이면 protection_mode 자신도 Set 불가 (원격 해제 불가) | 같은 게이트 |
| mock 모드: 소켓 없이 poll 이 워치독/생산/LLDP 만 수행 | `eip_stack.c:588-593` |
| ACD 는 실제 ARP 감시 없이 `eip_stack_acd_conflict()` 주입으로만 | `eip_stack.c:634-654` |

### 10.8 의도적 비범위

| 항목 | 상태 |
|---|---|
| Class 3 연결형 explicit (SendUnitData) | 없음 |
| Unconnected Send 라우팅 / Multiple Service Packet | 없음 |
| Input Only / Listen Only / 멀티캐스트 T→O / COS | 없음 |
| Run/Idle 헤더 | 없음 (⚠ 상호운용 영향 큼) |
| ListInterfaces, UDP 44818 ListIdentity | 없음 |
| CIP Security (ODVA 표준 TLS/DTLS, 인증서, 0x5D/0x5F) | 없음 (저장소 프로파일만) |
| DLR (링), CIP Sync (PTP), CIP Motion, CIP Safety | 없음 |
| LLDP 실제 송신/수신, 실제 ACD(ARP) | 없음 |
| 공식 ODVA CT / DoC | 제품 프로세스 (13장) |

---

## 11. 테스트와 디버깅

### 11.1 빌드와 한 번에 돌리기

```bash
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON      # libssl-dev 필요 (OpenSSL HMAC/TLS)
cmake --build build -j
ctest --test-dir build --output-on-failure -L ethernetip    # CTT EIP 시나리오 19개
./build/test_eip_stack                                      # C 단위 테스트
./build/test_eip_crypto                                     # HMAC-SHA256 RFC 4231 case 1
```

이 문서 작성 시 위 명령으로 19/19 통과, `test_eip_stack` "eip stack tests OK", `test_eip_crypto` OK 를 확인했다.

### 11.2 C 단위 테스트 — [`tests/test_eip_stack.c`](../../tests/test_eip_stack.c)

| 함수 | 줄 | 무엇을 지키나 |
|---|---|---|
| `test_identity_get` | 59 | Identity 속성 |
| `test_assembly_rw_and_forward_open` | 140 | Assembly Get/Set, FO, Class 1 I/O |
| `test_register_session` | 283 | 세션 발급 |
| `test_security_integrity` | 307 | Class 1 HMAC 거부/수락, 응답 MAC |
| `test_qos_dscp_ct_defaults` | 590 | DSCP 기본값 |
| `test_acd_identity_state` | 609 | ACD → Identity/TCPIP 상태 |
| `test_lldp_mgmt_and_frame` | 634 | 0x109, LLDP 프레임 |
| `test_class1_watchdog_and_rt_stats` | 674 | 워치독, RT 통계 |
| `test_list_identity_and_protection` | 799 | ListIdentity, protection_mode |
| `test_g2_watchdog_dup_path_size` | 947 | FO 슬롯 회수, 중복 triad, 경로/크기 거절 (보안 수정 G2) |
| `test_g5_encap_session_and_cip_len` | 1070 | Encap 길이 fail-closed, 세션 |
| `test_g5_session_owner_and_close` | 1177 | 세션 소유권, 연결 종료 시 정리 |
| `test_g6_cip_set_reset_gates` | 1320 | Set/Reset 권한 게이트 |
| `test_g7_eip_tcp_idle_and_per_ip` | 1483 | 실제 소켓: 유휴 종료, IP 당 제한 |

### 11.3 CTT 시나리오 — [`tests/scenarios/ethernetip/`](../../tests/scenarios/ethernetip/)

CTT(Controller Test Tool)는 PLC(Originator) 역할의 스텁이 **스택을 in-process 로** (`eip_stack_handle_encap()`,
`eip_stack_handle_io()`) 두드리는 내부 회귀 하네스다. DUT 는 `stacks/ethernetip/` 이며 데몬 어댑터가 아니다
([`tools/ctt/proto/ethernetip/README.md`](../../tools/ctt/proto/ethernetip/README.md)).

```bash
./build/ctt --scenario tests/scenarios/ethernetip/assembly_fo_io.yaml
./build/ctt --scenario tests/scenarios/ethernetip/class1_cyclic_metrics.yaml --report /tmp/eip.json
tests/run_mock_soak.sh --protocol ethernetip --seconds 30
```

YAML 스텝 action (플러그인 `eip_step()`, `tools/ctt/proto/ethernetip/eip_plugin.c:1324-`):
`register_session, list_identity, list_services, get_attr, write_input, read_input, read_output, forward_open,
forward_close, encap_inject, class1_io, io_cycle, soak, watchdog, acd_conflict, lldp, poll`.
`forward_open` 은 `integrity: true` 면 0x00C1 MAC 을 붙이고 `large: true` 면 0x5B 를 쓴다.
플러그인의 FO 는 NCP 에 **크기만** (플래그 비트 0) 넣고, O→T 크기 기본값 = output_size (seq 미포함) 다
(`build_forward_open_body()`, `eip_plugin.c:631-685`) — 즉 CTT 자체가 저장소 형식에 맞춰져 있어 5.6.4 의 상호운용 문제를
잡지 못한다.

예 — [`assembly_fo_io.yaml`](../../tests/scenarios/ethernetip/assembly_fo_io.yaml) (EIP-A-CM-001):

```yaml
steps:
  - action: write_input          # 앱이 입력 이미지에 씀
    data: "BARCODE-1234567890"
  - action: forward_open         # FO: RPI 8ms, o2t 8, t2o 32
    serial: 0x1234
    rpi_us: 8000
    o2t_size: 8
    t2o_size: 32
    expect: { cip_status: 0, class1: up }
  - action: class1_io            # O→T 8바이트 0x5A
    fill: 0x5A
    length: 8
    expect: { u8: 0x5A, class1: up }
```

시나리오 카탈로그(`EIP-A-*`)와 커버리지 갭은 [`docs/ctt_eip_bundle.md`](../ctt_eip_bundle.md),
[`docs/ctt_odva_matrix.md`](../ctt_odva_matrix.md) 가 정본이다. 갭으로 명시된 것: ListInterfaces, Originator 태그 R/W,
TLS Class 2, Ethernet Link/Port 시나리오.

### 11.4 퍼징

| 하네스 | 대상 | 요지 |
|---|---|---|
| [`tests/fuzz/fuzz_eip_encap.c`](../../tests/fuzz/fuzz_eip_encap.c) | Encap + UCMM + CM | 첫 바이트로 모드 선택. open / protection_mode=1 / security_class=1 세 스택에 세션을 유지하고 GetAttr·Set·FO/FC·List*·HMAC 경로를 두드림 |
| [`tests/fuzz/fuzz_eip_io.c`](../../tests/fuzz/fuzz_eip_io.c) | Class 1 I/O | 세션+FO 를 살려 둔 채 살아 있는 O→T ID 를 끼운 CPF, 정상 I/O, raw 프레임, FO/FC 재개, poll |

```bash
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DBUILD_DAEMON=OFF -DBUILD_CTT=OFF -DBUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_eip_encap fuzz_eip_io
python3 tests/fuzz/gen_corpus.py
./build-fuzz/fuzz_eip_io -max_total_time=60 -dict=tests/fuzz/dict/eip_io.dict tests/fuzz/corpus/eip_io
```

PR CI 는 타깃당 60초(`.github/workflows/ci.yml`), 주간 1시간 캠페인(`.github/workflows/fuzz-weekly.yml`).
하네스 설계 배경: [`docs/reports/fuzz_harness_audit_20260929.md`](../reports/fuzz_harness_audit_20260929.md).

### 11.5 Wireshark

| 필터 | 보는 것 |
|---|---|
| `enip` | 모든 Encapsulation (TCP/UDP 44818) |
| `cip` | CIP 메시지 |
| `cipcm` | Connection Manager (FO/FC) |
| `enip.command == 0x006f` | SendRRData 만 |
| `cip.genstat != 0` | 에러 응답만 (필드명은 Wireshark 버전에 따라 확인) |
| `udp.port == 2222` | Class 1 I/O |
| `tcp.port == 44818 && tcp.len > 0` | explicit 트래픽 |

요령:
- **Class 1 I/O 는 FO 를 같이 캡처해야** "CIP I/O" 로 해석된다 (연결 ID ↔ 경로 매핑을 FO 에서 배움).
- 비표준 포트(저장소 sw_master 예제 15562/15563)는 *Decode As…* 로 ENIP/CIP I/O 를 지정.
- FO 응답의 Extended status 는 트리의 "Additional Status" 에 나온다. 5.6.4 의 `0x0109` 를 여기서 바로 볼 수 있다.
- Statistics → I/O Graph 로 T→O 간격을 그리면 6.5 의 사이클 양자화가 보인다.

### 11.6 상용 스캐너로 상호운용 확인

**Rockwell Studio 5000 (Logix)** — "Generic Ethernet Module" 로 추가 (사양/제품 문서 기준, 실기 미검증):

| 항목 | 값 |
|---|---|
| Comm Format | Data - SINT (바이트 단위) |
| Input Assembly Instance / Size | 150 / input_size |
| Output Assembly Instance / Size | 101 / output_size |
| Configuration Instance / Size | 100 / 0 |
| RPI | cycle_ms 의 배수 (예: 8 ms) |

예상 결과: Generic Module 은 O→T 에 Run/Idle 헤더를 붙이므로 FO 가 `0x0109`(연결 크기) 로 거절될 가능성이 높다 (5.6.4).
입력이 511바이트를 넘으면 Large FO 가 필요하다. Security Class ≥1 이면 MAC 이 없어 `0x0F`.

**CODESYS EtherNet/IP Scanner** — EDS 를 디바이스 저장소에 설치하고 스캐너 아래에 추가. 저장소 절차:
[`docs/codesys_master_io.md`](../codesys_master_io.md) 4장, 설정 [`config/example.codesys.ethernetip.json`](../../config/example.codesys.ethernetip.json).
같은 Run/Idle·EDS 문제(10.6)를 먼저 해결해야 할 것으로 보인다. 저장소 문서상 현재 CODESYS 경로는 RegisterSession 프로브
("stand-in") 수준이다 ([`docs/sw_master_io.md`](../sw_master_io.md)).

**저장소 자체 소프트웨어 마스터** — [`examples/sw_master.py`](../../examples/sw_master.py) `--protocol ethernetip`:
RegisterSession → FO → Class 1 루프(저장소 형식). 라이브 소켓으로 도는 유일한 실제 네트워크 경로다.

### 11.7 문서의 hex 를 직접 재현하는 하네스 골격

```c
/* 저장소 밖에서: gcc -I stacks/ethernetip/include -I include -I core h.c build/libeip_stack.a -lssl -lcrypto -lpthread */
#include "eip_internal.h"   /* session_secret 고정용 (재현성) */
#include "eip_stack.h"
eip_cfg_t c = {0};
c.mock = 1; c.input_size = 4; c.output_size = 2;           /* 나머지는 스택 기본값 */
eip_stack_t *s = eip_stack_create(&c);
s->session_secret = 0x0A0B0C0C;                             /* 첫 핸들 = 0x0A0B0C0D */
eip_stack_start(s);
uint8_t req[] = { /* 5장 hex */ }, resp[1024]; size_t n;
eip_stack_handle_encap(s, req, sizeof req, resp, sizeof resp, &n);   /* TCP 메시지 */
eip_stack_handle_io(s, io, io_len);                                    /* UDP O→T */
eip_transport_ops_t ops = { .udp_send = my_capture };                  /* T→O 캡처 */
eip_stack_set_transport_ops(s, ops); eip_stack_poll(s);
```

---

## 12. 흔한 함정과 보안 고려사항

### 12.1 구현 함정

| # | 함정 | 증상 | 대책 |
|---|---|---|---|
| 1 | 헤더 Length 에 24바이트를 포함 | 모든 응답이 잘림/붙음 | Length = 헤더 **뒤** 바이트 수 |
| 2 | Sockaddr 를 LE 로 | 스캐너가 이상한 IP/포트 표시 | 이 필드만 빅 엔디안 |
| 3 | Path Size 를 바이트로 | 0x04 경로 에러 | **워드 수** |
| 4 | 16비트 세그먼트에 패드 누락 | 경로 해석 어긋남 | `21 00 LL HH` |
| 5 | Class 1 크기에서 seq(2)/Run-Idle(4) 누락 | 0x0109 | 5.6.4 공식 |
| 6 | O→T ID 를 Originator 값으로 | 여러 스캐너 충돌 | Target 이 고유 ID 선택 |
| 7 | T→O 를 첫 O→T 까지 보류 | 스캐너 T→O 워치독 만료 | 연결 직후 생산 시작 |
| 8 | 워치독을 FO 즉시 짧게 | 연결 직후 끊김 | 초기 여유(사양서 확인) |
| 9 | 생산 주기를 루프 주기로 양자화 | 지터, API 위반 | timerfd/deadline 기반 |
| 10 | CIP 순번 중복 체크 없음 | 같은 데이터 재적용 | 5.8.1 규칙 |
| 11 | 출발지 IP 미검사 | 스푸핑/목적지 탈취 | 연결의 Originator IP 고정 |
| 12 | FO 실패 응답에 triad/remaining path 누락 | 스캐너가 에러 해석 실패 | 5.6.7 |
| 13 | `NOP`/`UnRegisterSession` 에 응답 | 드물게 Originator 파서 혼란 | 무응답 |
| 14 | TCP 한 번 recv = 한 메시지 가정 | 조각난 메시지에서 오동작 | 스트림 조립 (저장소 Adapter 는 OK, Originator 는 ⚠) |
| 15 | GAA 에 비표준 속성 포함 | 툴이 Identity 를 잘못 표시 | 객체 정의대로 |
| 16 | EDS 와 스택 불일치 | 설정 툴에서는 OK, 연결 시 실패 | EDS 를 스택 사실에 맞춤 (10.6) |
| 17 | 511바이트 초과를 일반 FO 로 | 크기 필드 9비트 넘침 | Large FO |
| 18 | Vendor ID 임의 값 | 인증 불가, 실제 벤더와 충돌 | ODVA 할당 ID |

### 12.2 보안 고려사항

EtherNet/IP 기본 프로토콜(CIP Security 없이)은 **인증·암호화가 없다**. 네트워크에 닿는 누구나:

- ListIdentity 로 장치를 찾고, Identity/Assembly 를 읽고,
- RegisterSession 후 Set/Reset/Forward Open 을 보낼 수 있고 (저장소는 Class 0 에서 Set/Reset 에 "세션" 만 요구),
- UDP I/O 를 위조할 수 있다.

따라서 현장 방어는 **네트워크 분리(셀/존, IEC 62443 zones & conduits), 방화벽에서 44818/2222 제한** 이 기본이고,
장치 측으로는 CIP Security 가 정석이다. 이 저장소가 제공하는 방어와 한계:

| 방어 | 저장소 | 한계 |
|---|---|---|
| 세션 핸들 추측 방지 | XOR 난수 핸들 + TCP 결속 | |
| DoS: 연결 수/유휴 | IP 당 4, 유휴 60 s, poll 예산 | UDP 플러딩 방어 없음 |
| FO 슬롯 고갈 | 즉시 워치독, 경로/크기/중복 검사 | 다른 triad 로 32개 채우기는 가능 (RPI×배수 동안) |
| 쓰기 보호 | `protection_mode`, 세션 요구, Class≥1 HMAC | Get 은 무보호 |
| I/O | 없음 | 연결 ID 순차 + 출발지 무검사 → 출력 위조·T→O 탈취 (7.5) |
| 기밀성 | Class 2 TLS-PSK (옵션) | 평문 포트 병존, UDP 평문 |

저장소 보안 수정 이력과 62443 매핑: [`docs/reports/security_fixes_20260928.md`](../reports/security_fixes_20260928.md).

---

## 13. 인증/적합성

- **ODVA Conformance Test (CT)**: ODVA 가 제공하는 시험 소프트웨어/절차로 장치를 시험한다. 공식 **Declaration of Conformity
  (DoC)** 는 ODVA 회원 가입(Vendor ID 할당) + 공인 테스트 서비스(ODVA 시험소 등)에서 CT 통과 후 발급된다.
  제품 공개 전 EDS 검사, 상호운용 테스트(plugfest)도 과정에 포함된다 (사양서/ODVA 안내 확인 필요: 현행 CT 버전·절차).
- CIP Security 를 주장하려면 별도의 CIP Security CT 가 있다.
- **이 저장소의 CTT green 은 인증이 아니다.** 저장소 문서가 반복해 못 박는다: "CTT green 을 ODVA 인증서 대신 제출하지 말 것"
  ([`docs/ctt_odva_matrix.md`](../ctt_odva_matrix.md)), "내부 bundle-grade 게이트 ≠ ODVA 인증"
  ([`docs/ctt_eip_bundle.md`](../ctt_eip_bundle.md)).
- SOC(Statement of Compliance) 초안: [`docs/ethernetip_soc.md`](../ethernetip_soc.md). 이 초안의 객체 표는 **저장소 구현 설명** 이며,
  4장·부록 D 의 불일치(QoS 속성 번호, TCP/IP attr 10/11, Identity attr 17 등)가 CT 에서 지적될 수 있는 항목이다.
- 인증을 목표로 한다면 최소한 부록 D 의 "상호운용" 항목(Run/Idle, UDP ListIdentity, T→O 즉시 생산, FO 에러 형식, Forward Close
  not found, NOP/Unregister 무응답, ListInterfaces)을 먼저 정리해야 한다.

---

## 14. 참고 사양 문헌

| 문헌 | 내용 | 비고 |
|---|---|---|
| ODVA, *The CIP Networks Library, Volume 1: Common Industrial Protocol (CIP)* | 객체 모델, 데이터 타입, EPATH, 서비스, 연결(Connection Manager/Connection 객체), 상태 코드, EDS | 이 문서 4·5.4·5.6·6장의 근거 |
| ODVA, *Volume 2: EtherNet/IP Adaptation of CIP* | Encapsulation, CPF, TCP/UDP 사용, TCP/IP·Ethernet Link·QoS 객체, ACD, Class 0/1 UDP 포맷 | 5.1~5.3, 5.8 |
| ODVA, *Volume 8: CIP Security* | TLS/DTLS, 보안 객체 0x5D/0x5E/0x5F, 프로파일 | 7장 |
| ODVA, *Volume 5: CIP Safety* / *Volume 7: CIP Motion* 등 | 범위 밖 | |
| ODVA 기술 문서/가이드 (EtherNet/IP 개요, "Recommended Functionality for EtherNet/IP Devices", QoS/DLR/LLDP 관련 문서) | 권장 구현 사항 | 명칭·판은 ODVA 사이트 확인 |
| Rockwell Automation, *Logix5000 Controllers Data Access* (Programming Manual) | Read/Write Tag(0x4C/0x4D) 등 Logix 전용 서비스 | 9.5 |
| IETF RFC 5227 | IPv4 Address Conflict Detection | ACD |
| IEEE 802.1AB | LLDP | 4.11 |
| RFC 4279 / RFC 5487 | TLS-PSK cipher suites | 7.3 |
| RFC 2104 / RFC 4231 | HMAC / HMAC-SHA256 테스트 벡터 | `tests/test_eip_crypto.c` |
| OpENer (github.com/EIPStackGroup/OpENer) | 오픈소스 EtherNet/IP Adapter 스택 | 구현 비교용 (사양 아님) |

사양서는 ODVA 에서 구매/회원 제공된다. 판(edition)에 따라 속성·코드가 추가되므로 "사양서 확인 필요" 표시 항목은 반드시 현행
판으로 확인할 것.

---

## 부록 A. 구현 체크리스트

**Encapsulation**
- [ ] 24바이트 헤더, Length = 뒤 바이트 수, Sender Context 에코, Options ≠ 0 처리
- [ ] TCP 스트림 조립, 최대 길이 정책
- [ ] NOP 무응답
- [ ] ListIdentity (TCP + **UDP 44818 브로드캐스트**), Socket Address 빅 엔디안, Status/State 실제 값
- [ ] ListServices (0x0100, flags 0x0120)
- [ ] ListInterfaces (아이템 0개)
- [ ] RegisterSession 버전 검사(0x0069), TCP 당 1세션, 추측 불가 핸들
- [ ] UnRegisterSession 무응답 + TCP 종료
- [ ] SendRRData: 세션 검사(0x0064), CPF 경계 검사, Null + 0x00B2
- [ ] (선택) SendUnitData / Class 3
- [ ] 유휴 타임아웃 = TCP/IP attr 13

**CIP / 객체**
- [ ] EPATH: 8/16비트 logical, padded, port, symbolic, data 세그먼트 (모르면 0x04)
- [ ] 서비스 미지원 0x08, 속성 없음 0x14, 쓰기 불가 0x0E, 길이 0x13/0x15, 경로 없음 0x05
- [ ] 클래스 레벨(instance 0) 속성 (Revision 등)
- [ ] Identity 1~7(+8,9 권장), Status 비트 정확히(Owned=bit0), Reset 타입
- [ ] Message Router Object_List
- [ ] Assembly 3/4, Set 길이·소유 검사
- [ ] TCP/IP 1~6, 8~13 (특히 5 Interface Configuration, 13 타임아웃), ACD 속성 정확히
- [ ] Ethernet Link 실제 속도/플래그/MAC, 카운터
- [ ] QoS 1~8 번호대로, DSCP 를 소켓에 적용
- [ ] (신규 CT) LLDP Management + 실제 LLDP 송신

**연결**
- [ ] FO/Large FO 모든 필드 파싱, 실패 응답에 triad + remaining path size
- [ ] transport class/trigger 검사(0x0103), NCP type/priority/fixed 검사(0x0108)
- [ ] Electronic key 검사(0x0114~0x0116)
- [ ] 크기 = 데이터 + 2 + (Run/Idle 4) (0x0109)
- [ ] RPI 범위(0x0111), API 반환
- [ ] Exclusive Owner 중복(0x0106), Input Only / Listen Only / 멀티캐스트
- [ ] Target 이 O→T ID 선택(예측 어려운 값)
- [ ] 연결 직후 T→O 생산, 목적지 = Originator IP:2222 또는 Sockaddr
- [ ] 워치독 RPI×4×2^N (+초기 여유), 만료 시 출력 안전값
- [ ] O→T: 출발지 IP 확인, encap 순번/CIP 순번 규칙, Run/Idle
- [ ] Forward Close: 없으면 0x0107

**운영/품질**
- [ ] EDS 가 스택 동작과 일치, EDS 검사 도구 통과
- [ ] Wireshark 로 모든 메시지 디코드 정상
- [ ] 퍼저 (encap, CIP, FO, I/O)
- [ ] 상용 스캐너 2종 이상과 연결
- [ ] (보안) CIP Security 또는 네트워크 분리 가이드

---

## 부록 B. Hex 예제 모음 (검증됨)

전제: 0.2 의 하네스 설정 (세션 0x0A0B0C0D, vendor 0xABCD, serial 0x12345678, "FieldbusSensor", in 150/4B, out 101/2B, cfg 100).
"SRR(n, cip)" = 5.5 의 공통 40바이트 앞부분(Length = 16 + n, Unconnected Data 길이 n) + CIP n바이트.

| # | 요청 | [저장소] 응답 | 절 |
|---|---|---|---|
| B1 | `63 00 00 00` + 0×4 + 0×4 + ctx `01..08` + 0×4 | `63 00 36 00 … 01 00 0C 00 30 00 01 00 [0×16] CD AB 0C 00 01 00 01 00 00 00 78 56 34 12 0E "FieldbusSensor" FF` | 5.2.3 |
| B2 | `04 00 00 00` + 0×20 | `04 00 1A 00 … 01 00 00 01 14 00 01 00 20 01 "Communications" 00 00` | 5.2.2 |
| B3 | `64 00 00 00` + 0×20 | 헤더만, status `01 00 00 00` | 5.2.4 |
| B4 | `00 00 00 00` + 0×20 (NOP) | 같은 24바이트 에코 | 5.2.1 |
| B5 | `65 00 04 00` + 0×20 + `01 00 00 00` | `65 00 04 00 0D 0C 0B 0A 00…00 01 00 00 00` | 5.2.5 |
| B6 | SRR(8, `0E 03 20 01 24 01 30 01`) | CIP `8E 00 00 00 CD AB` | 5.5.1 |
| B7 | SRR(8, `0E 03 20 01 24 01 30 07`) | CIP `8E 00 00 00 0E 46 69 65 6C 64 62 75 73 53 65 6E 73 6F 72` | |
| B8 | SRR(6, `01 02 20 01 24 01`) | CIP `81 00 00 00 CD AB 0C 00 01 00 01 00 00 00 78 56 34 12 0E …72 03 01 00 00 00 00 00 00` | 5.5.2 |
| B9 | SRR(8, `0E 03 20 99 24 01 30 01`) | CIP `8E 00 05 00` | 5.5.4 |
| B10 | SRR(8, `0E 03 20 01 24 01 30 63`) | CIP `8E 00 14 00` | |
| B11 | SRR(10, `10 03 20 01 24 01 30 01 34 12`) | CIP `90 00 05 00` | |
| B12 | SRR(6, `52 02 20 06 24 01`) | CIP `D2 00 08 00` | |
| B13 | SRR with session `EF BE AD DE` | 헤더만, status `64 00 00 00` | |
| B14 | `FF 00 00 00 0D 0C 0B 0A` + 0×16 | 헤더만, status `01 00 00 00` | |
| B15 | `70 00 00 00 0D 0C 0B 0A` + 0×16 (SendUnitData) | 헤더만, status `01 00 00 00` | 5.2.8 |
| B16 | `6F 00 18 00 0D 0C 0B 0A` + 0×16 (본문 없음) | 응답 없음 (`-EINVAL`) | 5.1 |
| B17 | SRR(8, `0E 03 20 04 24 96 30 03`) | CIP `8E 00 00 00 00 00 00 00` | 5.5.3 |
| B18 | SRR(50, FO 5.6.8, O→T NCP `08 48`) | CIP `D4 00 20 01 09 01` | 5.6.4 |
| B19 | SRR(50, FO 5.6.8) | CIP `D4 00 00 00 01 00 00 20 11 22 33 44 34 12 01 00 99 00 00 00 40 1F 00 00 40 1F 00 00 00 00` | 5.6.8 |
| B20 | B19 재전송 | CIP `D4 00 01 01 00 01` | |
| B21 | SRR(8, `0E 03 20 01 24 01 30 05`) (FO 후) | CIP `8E 00 00 00 04 00` | 4.3 |
| B22 | UDP `02 00 02 80 08 00 01 00 00 20 01 00 00 00 B1 00 04 00 01 00 AA 55` | 출력 이미지 = `AA 55` | 5.8.2 |
| B23 | (poll, 입력 `DE AD BE EF`) | UDP `02 00 02 80 08 00 11 22 33 44 01 00 00 00 B1 00 06 00 01 00 DE AD BE EF` | 5.8.3 |
| B24 | SRR(26, FC 5.7) | CIP `CE 00 00 00 34 12 01 00 99 00 00 00 00 00` (두 번째도 동일) | 5.7 |
| B25 | `66 00 00 00 0D 0C 0B 0A` + 0×16 | 같은 헤더, status 0 (에코) | 5.2.6 |
| B26 | SRR(54, Large FO 5.6.8) | CIP `DB 00 00 00 01 00 00 20 …` | 5.6.8 |
| B27 | SRR(50, FO 경로 `20 04 24 64 2C C6 2C 96`) | CIP `D4 00 05 01 00 00` | 6.6 |
| B28 | SRR(50, FO transport `A3`) | 성공 (Class 1 슬롯 점유) | 5.6.5 |
| B29 | SRR(60, FO 경로 앞에 `34 04 CD AB 0C 00 01 00 01 00`) | 성공 (키 검사 안 함) | 5.6.6 |
| B30 | SRR(12, `10 03 20 04 24 96 30 03 01 02 03 04`) | CIP `90 00 00 00`, 입력 이미지 변경 | 4.5 |
| B31 | SRR(12, `0E 05 91 07 53 65 6E 73 6F 72 31 00`) | CIP `8E 00 00 00` + 입력 이미지 4바이트 | 10.7 |
| B32 | SRR(10, `0E 04 21 00 09 01 24 01 30 01`) (LLDP 0x109) | CIP `8E 00 00 00 00 00 00 00` (lldp_enable=0 설정) | 4.11 |
| B33 | Sec1: SRR(10, `10 03 20 04 24 65 30 03 AA 55`) MAC 없음 | CIP `90 00 0F 00` | 7.3 |
| B34 | Sec1: 같은 요청 + `C1 00 20 00 C3 83 52 6A … 17 3E` | CIP `90 00 00 00` + `C1 00 20 00 03 5B B8 1E … DB D1` | 7.3 |

---

## 부록 C. 상태 코드 표

### C.1 CIP General Status [사양]

| 코드 | 이름 |
|---|---|
| 0x00 | Success |
| 0x01 | Connection failure (extended status 필수) |
| 0x02 | Resource unavailable |
| 0x03 | Invalid parameter value |
| 0x04 | Path segment error |
| 0x05 | Path destination unknown |
| 0x06 | Partial transfer |
| 0x07 | Connection lost |
| 0x08 | Service not supported |
| 0x09 | Invalid attribute value |
| 0x0A | Attribute list error |
| 0x0B | Already in requested mode/state |
| 0x0C | Object state conflict |
| 0x0D | Object already exists |
| 0x0E | Attribute not settable |
| 0x0F | Privilege violation |
| 0x10 | Device state conflict |
| 0x11 | Reply data too large |
| 0x12 | Fragmentation of a primitive value |
| 0x13 | Not enough data |
| 0x14 | Attribute not supported |
| 0x15 | Too much data |
| 0x16 | Object does not exist |
| 0x17 | Service fragmentation sequence not in progress |
| 0x18 | No stored attribute data |
| 0x19 | Store operation failure |
| 0x1A | Routing failure, request packet too large |
| 0x1B | Routing failure, response packet too large |
| 0x1C | Missing attribute list entry data |
| 0x1D | Invalid attribute value list |
| 0x1E | Embedded service error |
| 0x1F | Vendor specific error |
| 0x20 | Invalid parameter |
| 0x21 | Write-once value or medium already written |
| 0x22 | Invalid reply received |
| 0x25 | Key failure in path |
| 0x26 | Path size invalid |
| 0x27 | Unexpected attribute in list |
| 0x28 | Invalid Member ID |
| 0x29 | Member not settable |

(0x23~0x24, 0x2A 이후는 판에 따라 추가 — 사양서 확인 필요.)

### C.2 Connection Manager Extended Status (General 0x01 과 함께) [사양 — 드문 코드는 사양서 확인 필요]

| 코드 | 의미 |
|---|---|
| 0x0100 | Connection in use or duplicate Forward Open |
| 0x0103 | Transport class and trigger combination not supported |
| 0x0106 | Ownership conflict |
| 0x0107 | Target connection not found |
| 0x0108 | Invalid network connection parameter |
| 0x0109 | Invalid connection size |
| 0x0110 | Target for connection not configured |
| 0x0111 | RPI not supported |
| 0x0113 | Out of connections |
| 0x0114 | Vendor ID or product code mismatch |
| 0x0115 | Device type mismatch |
| 0x0116 | Revision mismatch |
| 0x0117 | Invalid produced or consumed application path |
| 0x0118 | Invalid or inconsistent configuration application path |
| 0x0119 | Non-listen only connection not opened |
| 0x011A | Target object out of connections |
| 0x011B | RPI is smaller than the production inhibit time |
| 0x0127 | Invalid O→T network connection size (사양서 확인 필요) |
| 0x0128 | Invalid T→O network connection size (사양서 확인 필요) |
| 0x0203 | Connection timed out |
| 0x0204 | Unconnected request timed out |
| 0x0205 | Parameter error in unconnected request |
| 0x0301 | No buffer memory available |
| 0x0311 | Invalid port |
| 0x0312 | Invalid link address |
| 0x0315 | Invalid segment in connection path |

[저장소] 가 실제로 쓰는 조합: `0x01/0x0100` (중복), `0x20/0x0109` (크기, ⚠ general 이 0x01 이 아님), `0x05/0x0000` (경로),
`0x20/0x0000` (짧은 요청), `0x04/0x0000` (path size), `0x02/0x0000` (슬롯 없음) — `eip_cm.c` 전체, 상수 `eip_types.h:78-88`.

### C.3 Encapsulation Status

5.1 표 참고.

---

## 부록 D. 사양 ↔ 저장소 불일치 목록

모두 **기록** 이며 이 문서는 코드를 수정하지 않는다. "영향" 은 상용 장비와의 상호운용(I), 적합성 시험(C), 보안(S) 관점.

| # | 항목 | 사양 | 저장소 | 근거 | 영향 |
|---|---|---|---|---|---|
| D1 | O→T Run/Idle 32비트 헤더 | Class 1 O→T 관례 형식, 크기에 +4 | 미지원: 크기 asm 또는 asm+2 만 허용, payload 에서 헤더 미제거 | `eip_cm.c:42-45`, `eip_io.c:62-74` | **I 높음** |
| D2 | EDS vs 스택 | EDS 가 장치 동작과 일치해야 | EDS 는 O→T 32bit header 선언, Connection 필드 정렬 이상, MinRev 1 vs Identity 0 | `FieldbusSensor.eds` | I, C |
| D3 | T→O 생산 시작/목적지 | 연결 직후, Originator IP:2222/Sockaddr/멀티캐스트 | 첫 O→T 수신 후, 마지막 O→T 출발지로 | `eip_io.c:57-58,111` | I, S |
| D4 | O→T 연결 ID 선택 | Target 선택 | 요청값 ≠0 이면 에코, 아니면 순차 | `eip_cm.c:228-233` | I, S |
| D5 | FO 실패 응답 형식 | general 0x01 + ext, 데이터에 triad + remaining path size | general 0x20/0x05/0x02 사용, 데이터 없음 | `eip_cm.c:8-20,136,194,207` | I, C |
| D6 | FO 검사 항목 | transport/trigger, NCP, e-key, RPI, 소유권 | 미검사 | `eip_cm.c:127-250` | C |
| D7 | Input Only / Listen Only / 멀티캐스트 | 지원 권장 | 미지원 | `eip_cm.c:106-125` | I |
| D8 | Forward Close not found | 0x01/0x0107 | 성공 | `eip_cm.c:297-327` | C |
| D9 | 초기 워치독 | 첫 패킷 전 여유(구현 관례, 사양서 확인) | FO 즉시 RPI×배수 | `eip_cm.c:248-249` | I |
| D10 | Class 1 순번 규칙 | encap 순번/CIP 순번으로 중복·역순 폐기 | 미검사 | `eip_io.c:59-67` | C |
| D11 | UDP I/O 출발지 | Originator IP 와 일치 확인 (권장) | 미검사, 매 패킷 목적지 갱신 | `eip_io.c:57-58` | S |
| D12 | UDP 44818 ListIdentity | 필수(발견) | 소켓 없음 | `eip_stack.c:193-215` | I, C |
| D13 | ListIdentity 필드 | Socket Address, Status, State 실제 값 | 0 / 0 / 0xFF 고정 | `eip_encap.c:40-62` | C |
| D14 | NOP | 응답 없음 | 응답 | `eip_encap.c:319-322` | C |
| D15 | UnRegisterSession | 응답 없이 TCP 종료 | 응답, TCP 유지 | `eip_encap.c:342-352` | C |
| D16 | RegisterSession 버전 | 1 아니면 0x0069 | 검사 없이 에코 | `eip_encap.c:331-339` | C |
| D17 | ListInterfaces | 아이템 0 응답 | 0x0001 | `eip_encap.c:384-387` | C |
| D18 | SendUnitData / Class 3 | 지원(대부분 장치) | 미지원, 그런데 Class 3 FO 는 수락 | `eip_encap.c`, `eip_cm.c:176` | I, C |
| D19 | Identity Status | Owned=bit0, Ext. device status | 연결 시 0x0004(Configured) | `eip_cip.c:78` | C |
| D20 | Identity State (ACD) | 2 = Standby | ACD 시 2 를 "Minor Recoverable Fault" 로 사용 | `eip_cip.c:110-111` | C |
| D21 | Identity Protection Mode 속성 번호 | attr 19 WORD (사양서 확인 필요) | attr 17 UDINT | `eip_cip.c:131-137` | C |
| D22 | Identity GAA 구성 | 객체 정의대로 (1~7 흔함, 사양서 확인) | 1~10 + 17 | `eip_cip.c:143-170` | C |
| D23 | 지원 객체의 미지원 서비스/쓰기 불가 속성 | 0x08 / 0x0E | 0x05 | `eip_cip.c:616` | C |
| D24 | Message Router attr 1 | 개수 + 클래스 목록 | 개수 8 만 | `eip_cip.c:324-327` | C |
| D25 | TCP/IP attr 2 ACD capable | bit 7 (사양서 확인) | bit 2 (DHCP) 사용 | `eip_cip.c:388` | C |
| D26 | TCP/IP attr 10/11 | Select ACD(BOOL) / Last Conflict(STRUCT) | ACD Status / Activity (UDINT) | `eip_cip.c:402-411` | C |
| D27 | TCP/IP attr 5/6/13 등 | 필수/권장 | 없음 | `eip_cip.c:375-414` | C |
| D28 | Ethernet Link 값 | 실제 링크/MAC | 100 Mbps / 0x0F / 02:02:… 고정 | `eip_cip.c:416-436` | C |
| D29 | QoS 속성 번호 | 1 Tag enable, 2-3 PTP, 4-8 DSCP (사양서 확인) | 1~5 = Urgent~Explicit | `eip_cip.c:448-468` | C |
| D30 | QoS 적용 | 소켓 DSCP 설정 | 저장만 | (IP_TOS 없음) | I |
| D31 | Port attr 1 | Port Type (TCP/IP = 4, 사양서 확인) | 0 | `eip_cip.c:504-507` | C |
| D32 | 0x5E 보안 객체 | Vol 8 속성 | 저장소 고유 속성 | `eip_cip.c:519-546` | I, C |
| D33 | CIP Security | TLS/DTLS 전체 세션 | HMAC CPF 0x00C1 + TLS-PSK(평문 병존), I/O 무보호, replay 방지 없음 | `eip_sec.c` | S, I |
| D34 | Assembly Set | 길이 정확히, 소유 연결 시 거부 | 절단/부분 쓰기, 입력 Assembly 도 허용 | `eip_path_asm.c:271-283` | C, S |
| D35 | FO 응답 API | 실제 지킬 주기 | RPI 에코 (사이클 양자화 무시) | `eip_cm.c:274-277`, 6.5 | I |
| D36 | Encapsulation 최대 길이 | 65511 | 8192 초과 시 연결 끊음 | `eip_stack.c:498-501` | C |
| D37 | Originator 태그 R/W | Logix 는 0x4C/0x4D | Get/Set_Attribute_Single + 심볼 경로 | `eip_client.c:229-301` | I |
| D38 | Originator 보안/수신 | — | MAC 미부착, 응답 1회 recv | `eip_client.c:48-140` | I |
| D39 | LLDP | 실제 송신 | 메모리에만 생성, 고정 MAC | `eip_lldp.c:40,96-100` | C |
| D40 | Identity Reset | 타입 파라미터, 응답 후 리셋 | 타입 무시, 이미지/연결만 초기화 | `eip_cip.c:298-308` | C |
| D41 | TCP 유휴 타임아웃 | TCP/IP attr 13 (기본 120 s) | 60 s, 객체로 노출 안 함 | `eip_types.h:118` | C |
