# Modbus TCP — 바닥부터 구현까지 심층 입문서

> 대상 독자: 산업용 프로토콜·PLC·필드버스를 한 번도 본 적 없고, 일반적인
> 프로그래밍 지식만 있는 사람 (네트워크는 조금 약해도 된다).
> 목표: 이 문서만 읽고 **Modbus TCP 서버/클라이언트를 처음부터 직접 구현**할 수
> 있고, 이 저장소의 `stacks/modbus/` · `adapters/modbus/` 를 이해·유지보수할 수 있게 한다.
>
> 문서 위치가 `docs/protocols/` 이므로 저장소 루트는 `../../` 이다.
> 저장소 코드 인용은 `경로:줄번호` 형식이며, 2026-09-30 시점 코드 기준이다.
> 이 문서의 **모든 hex 예제는 실제 스택(`mb_stack_handle_adu`)에 넣어 응답을 확인했다**
> (검증 방법은 [부록 C](#부록-c-이-문서의-검증-방법)).

---

## 목차

- [0. 이 문서 읽는 법 + 선행 지식](#0-이-문서-읽는-법--선행-지식)
- [1. 왜 이 프로토콜이 존재하나](#1-왜-이-프로토콜이-존재하나)
- [2. 용어 사전](#2-용어-사전)
- [3. 전체 그림](#3-전체-그림)
- [4. 데이터 모델 — 네 개의 테이블](#4-데이터-모델--네-개의-테이블)
- [5. 프레임 포맷](#5-프레임-포맷)
- [6. 동작과 상태](#6-동작과-상태)
- [7. 에러 처리, 타이밍, 제한값](#7-에러-처리-타이밍-제한값)
- [8. 직접 구현하기](#8-직접-구현하기)
- [9. 이 저장소의 구현 지도](#9-이-저장소의-구현-지도)
- [10. 테스트와 디버깅](#10-테스트와-디버깅)
- [11. 흔한 함정과 보안 고려사항](#11-흔한-함정과-보안-고려사항)
- [12. 인증/적합성](#12-인증적합성)
- [13. 참고 사양 문헌](#13-참고-사양-문헌)
- [부록 A. 구현 체크리스트](#부록-a-구현-체크리스트)
- [부록 B. hex 예제 모음](#부록-b-hex-예제-모음)
- [부록 C. 이 문서의 검증 방법](#부록-c-이-문서의-검증-방법)
- [부록 D. 사양 vs 저장소 차이 요약](#부록-d-사양-vs-저장소-차이-요약)

---

## 0. 이 문서 읽는 법 + 선행 지식

### 0.1 읽는 순서

| 목적 | 읽을 절 |
|---|---|
| "Modbus 가 뭔지"만 알고 싶다 | 1, 2, 3, 4.1 |
| PLC 담당자와 주소/데이터형 얘기를 해야 한다 | 4 전체, 11.1 |
| 패킷을 캡처해서 읽어야 한다 | 5, 부록 B, 10.4 |
| 스택을 직접 구현한다 | 0~8 전부, 부록 A |
| 이 저장소 코드를 고친다 | 5, 6, 9, 10, 부록 D |

공통 기초(산업 통신 일반, 계층, 인증 생태계)는 [`README.md`](README.md) 에 있다.
이 문서는 그것을 몰라도 읽히도록 Modbus 에 필요한 만큼은 다시 설명한다.

### 0.2 비트, 바이트, 워드

- **비트(bit)**: 0 또는 1. 스위치 하나의 켜짐/꺼짐.
- **바이트(byte)**: 비트 8개. 0~255. 네트워크로 오가는 최소 단위.
- **워드(word)**: 이 문서에서는 **16비트 = 2바이트**. 0~65535 (부호 있으면 -32768~32767).
  Modbus 의 "레지스터(register)" 한 칸이 정확히 1워드다.

비트 번호는 오른쪽(가장 작은 자리)부터 0 이다. `0x0008` 은 이진수
`0000 0000 0000 1000` 이므로 **bit 3** 이 켜져 있다.

### 0.3 16진수(hex)

바이트 하나를 16진 두 자리로 쓴다: `0x00`~`0xFF`. 패킷은 `00 01 00 00 00 06 01 03 …`
처럼 바이트를 공백으로 나열해 표기한다. 16비트 값은 두 바이트: `0x006B` = 107.

| 10진 | 16진 | 비고 |
|---|---|---|
| 1 | 0x0001 | |
| 107 | 0x006B | FC03 예제의 시작 주소 |
| 125 | 0x007D | FC03 최대 레지스터 수 |
| 2000 | 0x07D0 | FC01 최대 비트 수 |
| 65280 | 0xFF00 | 코일 ON 값 |

### 0.4 엔디안 — Modbus 는 빅 엔디안

16비트 값 `0x1234` 를 바이트로 보낼 때:

- **빅 엔디안(big-endian)**: `12 34` (큰 자리 먼저). **Modbus 의 모든 16비트 필드는 빅 엔디안**이다.
- **리틀 엔디안(little-endian)**: `34 12`. x86/대부분의 ARM CPU 메모리가 이렇다.

그래서 C 로 구현할 때 `uint16_t` 를 `memcpy` 로 버퍼에 복사하면 x86 에서 **틀린 바이트
순서**가 나간다. 반드시 `(p[0] << 8) | p[1]` 같은 헬퍼로 읽고 쓴다 (8.3 절).

> 주의: Modbus 사양이 정하는 것은 **16비트 한 칸 안의** 순서뿐이다. 32비트 float 을
> 레지스터 **두 칸**에 나눠 담을 때 어느 칸이 먼저인지(워드 순서)는 사양에 없다.
> 이것이 현장에서 가장 흔한 버그다 (4.5 절).

### 0.5 TCP 는 "메시지"가 아니라 "바이트의 강물"

TCP 소켓은 보낸 바이트를 **순서대로, 빠짐없이** 전달하지만, **경계는 보존하지 않는다.**

```
보낸 쪽:  send(12바이트 요청 A)  send(12바이트 요청 B)
받는 쪽:  recv → 5바이트        (A 의 앞부분)
          recv → 19바이트       (A 의 나머지 7 + B 전체 12)
```

그래서 Modbus TCP 는 모든 메시지 앞에 **길이 필드가 들어 있는 7바이트 헤더(MBAP)** 를
붙인다. 받는 쪽은 "헤더 7바이트를 모은다 → 길이를 읽는다 → 그만큼 더 모은다" 를
반복해 메시지를 잘라낸다. 이 **재조립(reassembly)** 을 빼먹는 것이 초보 구현의
1순위 버그다 (6.4 절).

### 0.6 소켓 최소 지식

| 호출 | 서버에서 | 클라이언트에서 |
|---|---|---|
| `socket()` | 소켓 생성 | 소켓 생성 |
| `bind()` + `listen()` | 포트 502 에서 대기 시작 | — |
| `accept()` | 새 접속마다 **새 fd** 를 돌려줌 | — |
| `connect()` | — | 서버 IP:502 로 접속 |
| `recv()` / `send()` | 바이트 읽기/쓰기 | 동일 |
| `close()` | 연결 종료 (상대는 `recv()==0` 으로 알게 됨) | 동일 |

**non-blocking** 소켓은 읽을 게 없으면 기다리지 않고 `EAGAIN` 을 돌려준다. 이 저장소
서버는 모든 소켓을 non-blocking 으로 두고 주기적으로 훑는다 (`set_nonblock`,
[`stacks/modbus/src/mb_stack.c:69`](../../stacks/modbus/src/mb_stack.c)).

---

## 1. 왜 이 프로토콜이 존재하나

### 1.1 공장 이야기

물탱크가 하나 있다. 탱크에는 **수위 센서**, **온도 센서**, 물을 채우는 **펌프**, 넘칠 때
울리는 **경보등**이 달려 있다. 이 장비들을 제어하는 두뇌가 **PLC(Programmable Logic
Controller)** 다. PLC 는 수 ms 마다 "센서 값 읽기 → 프로그램 실행(수위가 낮으면 펌프 ON)
→ 출력 쓰기" 를 끝없이 반복한다. 벽에는 운전원이 보는 터치스크린 **HMI(Human-Machine
Interface)** 가 있고, 사무실에는 공장 전체를 기록·감시하는 **SCADA** 서버가 있다.

```
      [SCADA 서버] ─────┐        "탱크 1 온도 기록해야지"
                        │
      [HMI 터치패널] ───┤        "수위 몇 %야? 펌프 수동 ON!"
                        │  Ethernet (Modbus TCP, 포트 502)
      [PLC] ────────────┤
        │               │
   (배선 또는 버스)      └── [인버터(펌프 모터 속도)]  [전력량계]  [온도 조절기]
        │
   [수위 센서] [펌프 릴레이] [경보등]
```

이 장비들은 제조사가 다 다르다. 그런데 서로 숫자를 주고받아야 한다. "온도 조절기의
현재 온도를 읽어라", "인버터 주파수를 45.0Hz 로 써라" — 이런 요청을 **제조사와 무관하게**
주고받는 가장 오래되고 가장 단순한 공용어가 **Modbus** 다.

비유하면 Modbus 장치는 **번호가 붙은 사물함들이 있는 벽**이다. 상대는 "사물함 107번부터
3칸 내용 보여 줘", "사물함 2번에 3을 넣어 줘" 라고만 말할 수 있다. 사물함에 무엇이
들어 있는지(온도인지 속도인지)는 **장치 매뉴얼(통신 가이드)** 에만 적혀 있고, 프로토콜은
전혀 모른다. 이 단순함이 Modbus 가 40년 넘게 살아남은 이유이자 모든 혼란의 원인이다.

### 1.2 누가 누구와 대화하나

Modbus 는 **순수한 요청-응답(request/response)** 프로토콜이다. 한쪽만 말을 걸 수 있다.

| 역할 | 현재 이름 | 옛 이름 | 하는 일 | 대표 장비 |
|---|---|---|---|---|
| 묻는 쪽 | **Client** | Master | 요청을 보냄. 응답을 기다림 | PLC, HMI, SCADA, 게이트웨이 |
| 답하는 쪽 | **Server** | Slave | 요청을 받아 처리하고 응답 | 센서, 인버터, 전력량계, 원격 I/O, **이 저장소 데몬(기본)** |

- 서버는 **절대 먼저 말하지 않는다.** 값이 바뀌어도 알릴 방법이 없다. 클라이언트가
  주기적으로 물어봐야(폴링, polling) 한다.
- 한 서버에 여러 클라이언트가 동시에 붙을 수 있다 (PLC 와 HMI 가 같은 인버터를 읽는 식).
- Modbus Organization 은 2020년 전후로 master/slave 대신 client/server 용어를 쓰도록
  권고했다. 현장 매뉴얼에는 여전히 master/slave 가 흔하다.

### 1.3 역사와 위치

| 시기 | 사건 |
|---|---|
| 1979 | Modicon 사(현 Schneider Electric 계열)가 자사 PLC 용으로 **시리얼 Modbus** 발표. RS-232/RS-485 케이블, **RTU**(바이너리) 와 **ASCII**(문자) 두 인코딩 |
| 1990년대 말 | Ethernet 위의 **Modbus TCP**(당시 "Modbus/TCP") 발표. 시리얼 프레임의 주소·CRC 를 버리고 7바이트 MBAP 헤더를 붙임 |
| 2000년대 초 | 사양 관리가 비영리 단체 **Modbus-IDA → Modbus Organization** 으로 이관. 사양서 무료 공개 |
| 2006 | *Modbus Application Protocol Specification V1.1b* 계열, *Messaging on TCP/IP Implementation Guide V1.0b* 공개 |
| 2012 | Application Protocol V1.1b3 (현재 널리 인용되는 판) |
| 2018 | *Modbus/TCP Security* (TLS, 포트 802) 사양 공개 |

(연도는 공개 자료 기준의 대략치다. 정확한 판 번호·날짜는 13장의 사양서 표지를 확인할 것.)

**위치**: Modbus 는 PROFINET·EtherNet/IP 처럼 "실시간 주기 교환"이나 "장치 자동 탐색"
기능이 없다. 대신 **구현이 너무 쉬워서** 거의 모든 산업 장비가 "기본 탑재 공용어"로
지원한다. 그래서 이 저장소도 네 프로토콜 중 Modbus 를 우선순위 2번(코어 다음)으로
둔다 ([`../../CLAUDE.md`](../../CLAUDE.md) "우선순위").

| 장점 | 한계 |
|---|---|
| 사양이 짧고 무료 | 보안 없음(인증·암호화 없음) |
| 요청-응답뿐이라 디버깅 쉬움 | 데이터형이 16비트 칸뿐 (float 순서 혼란) |
| TCP 만 있으면 어디서나 동작 | 장치 탐색·자기 기술(self-description) 없음 |
| 방화벽/라우팅 친화적 (TCP 502) | 서버 → 클라이언트 이벤트 알림 불가 |

### 1.4 시리얼 Modbus 와의 관계 (배경 지식)

이 저장소는 **TCP 만** 다룬다 ([`../ctt_mb_bundle.md`](../ctt_mb_bundle.md) "RTU / serial / UDP 는
영구 비목표"). 그래도 매뉴얼에 RTU 얘기가 섞여 나오므로 차이만 알아 둔다.

```
시리얼 RTU ADU :  [주소 1B] [ PDU (FC + 데이터) ] [CRC 2B]      (프레임 경계 = 3.5문자 무음 시간)
Modbus TCP ADU :  [MBAP 7B: TID, Proto, Len, Unit] [ PDU ]      (프레임 경계 = Len 필드, CRC 없음 — TCP 가 보장)
```

**PDU(가운데 부분)는 완전히 같다.** 그래서 "RTU ↔ TCP 게이트웨이"는 앞뒤 포장만 바꿔
끼운다. 시리얼의 1바이트 "슬레이브 주소"는 TCP 에서 MBAP 의 **Unit Identifier** 로
옮겨졌다 (6.5 절).

---

## 2. 용어 사전

| 용어 | 원어 | 뜻 |
|---|---|---|
| 클라이언트 / 마스터 | Client / Master | 요청을 보내는 쪽 (PLC, HMI) |
| 서버 / 슬레이브 | Server / Slave | 요청에 응답하는 쪽 (센서, 이 데몬) |
| PDU | Protocol Data Unit | **기능 코드 + 데이터**. 전송 매체와 무관한 Modbus 의 알맹이. 최대 253바이트 |
| ADU | Application Data Unit | PDU 에 전송용 포장을 붙인 것. TCP 에서는 MBAP + PDU, 최대 260바이트 |
| MBAP 헤더 | Modbus Application Protocol header | TCP ADU 앞 7바이트: TID(2) + Protocol ID(2) + Length(2) + Unit ID(1) |
| TID | Transaction Identifier | 요청-응답 짝을 맞추는 번호. 서버는 그대로 복사해 돌려줌 |
| Protocol ID | Protocol Identifier | 항상 `0x0000` (= Modbus) |
| Length | Length | MBAP 의 Length 필드 **뒤에 오는** 바이트 수 (= Unit ID 1 + PDU 길이) |
| Unit ID | Unit Identifier | 게이트웨이 뒤 시리얼 장치 번호. 직접 연결 장치에선 사실상 의미 없음 |
| FC | Function Code | PDU 첫 바이트. "무엇을 하라" (01=코일 읽기, 03=레지스터 읽기 …) |
| 예외 응답 | Exception Response | 실패 응답. FC 에 `0x80` 을 더하고 예외 코드 1바이트를 붙임 |
| 예외 코드 | Exception Code | 01 잘못된 FC, 02 잘못된 주소, 03 잘못된 값, 04 장치 고장 … |
| 코일 | Coil | 1비트, 읽기/쓰기. 원래 뜻은 릴레이 코일(출력) |
| 이산 입력 | Discrete Input | 1비트, 읽기 전용. 스위치/센서 접점 |
| 입력 레지스터 | Input Register | 16비트, 읽기 전용. 측정값 |
| 홀딩 레지스터 | Holding Register | 16비트, 읽기/쓰기. 설정값·명령·범용 |
| PDU 주소 | PDU address / offset | 프레임 안에 실제로 들어가는 0부터 시작하는 번호 (0~65535) |
| 참조 번호 | Reference / Modicon notation | 매뉴얼 표기 "40001", "30001" 등. 1부터 시작 + 테이블 접두사 |
| 워드 순서 | Word order | 32비트 이상 값을 여러 레지스터에 나눌 때 어느 워드가 먼저인가 (ABCD/CDAB…) |
| 폴링 | Polling | 클라이언트가 주기적으로 같은 요청을 반복하는 것 |
| 파이프라이닝 | Pipelining | 응답을 기다리지 않고 요청 여러 개를 연달아 보내는 것 |
| 게이트웨이 | Gateway | TCP ↔ 시리얼 변환기. Unit ID 로 뒤쪽 장치를 고름 |
| 포인트 | Point | 이 저장소 config 의 "이름 붙은 값" (예: `temperature`). 어댑터가 레지스터로 번역 |
| CTT | Controller Test Tool | 이 저장소 내부 회귀 시험 도구 (`tools/ctt/`). 인증 아님 |

---

## 3. 전체 그림

### 3.1 계층

```
 ┌───────────────────────────────────────────────────────────┐
 │  응용: "온도 = 레지스터 16 × 0.1"   ← 장치 매뉴얼이 정함     │  (이 저장소: adapters/modbus)
 ├───────────────────────────────────────────────────────────┤
 │  Modbus PDU: [FC 1B][데이터 0~252B]                         │  (stacks/modbus handle_pdu)
 ├───────────────────────────────────────────────────────────┤
 │  MBAP: [TID 2B][Proto 2B][Len 2B][Unit 1B]                  │  (stacks/modbus handle_adu, serve_client)
 ├───────────────────────────────────────────────────────────┤
 │  TCP (포트 502) — 신뢰성·순서 보장, 경계 없음                 │  (OS)
 ├───────────────────────────────────────────────────────────┤
 │  IP / Ethernet                                             │  (OS)
 └───────────────────────────────────────────────────────────┘
```

한 개의 요청 ADU 를 뜯어 보면 이렇다 (FC03, 레지스터 107부터 3개 읽기):

```
 00 01 | 00 00 | 00 06 | 01 | 03 | 00 6B | 00 03
 ─────   ─────   ─────   ──   ──   ─────   ─────
  TID    Proto    Len   Unit  FC   시작주소  수량
 └──────────── MBAP 7바이트 ──────┘└──── PDU 5바이트 ───┘
                        Len = 0x0006 = Unit(1) + PDU(5)
```

### 3.2 정상 시퀀스

```
 Client (PLC)                                       Server (센서/데몬)
     │                                                   │  listen(:502)
     │──── TCP SYN ─────────────────────────────────────▶│
     │◀─── SYN/ACK ──────────────────────────────────────│  accept()
     │──── ACK ─────────────────────────────────────────▶│
     │                                                   │
     │── [TID=1] FC03 addr=0x006B qty=3 ────────────────▶│  주소·수량 검사 → 맵에서 읽기
     │◀─ [TID=1] FC03 bc=6 022B 0000 0064 ───────────────│
     │                                                   │
     │── [TID=2] FC06 addr=0x0001 val=0x0003 ───────────▶│  holding[1] = 3
     │◀─ [TID=2] FC06 addr=0x0001 val=0x0003 (에코) ─────│
     │                                                   │
     │   … 매 주기(예: 10~100ms) 반복. 연결은 계속 열어 둔다 …   │
     │                                                   │
     │──── FIN ─────────────────────────────────────────▶│  recv()==0 → close
```

### 3.3 이상 시퀀스

```
 (a) 예외: 없는 주소
     │── [TID=3] FC03 addr=0x00C7 qty=2 ───────────────▶│  199+2 > 맵 크기 200
     │◀─ [TID=3] 0x83 0x02 (ILLEGAL DATA ADDRESS) ──────│

 (b) 응답 없음: Unit ID 불일치 (이 저장소 서버의 동작)
     │── [TID=4] Unit=9 FC03 … ────────────────────────▶│  unit_id=1 이 아님 → 무시
     │        … 클라이언트 타임아웃 …                       │

 (c) 파이프라이닝: 응답을 기다리지 않고 연달아
     │── [TID=10] FC03 … ──▶│
     │── [TID=11] FC03 … ──▶│
     │◀─ [TID=10] 응답 ──────│
     │◀─ [TID=11] 응답 ──────│   ← TID 로 짝을 맞춘다

 (d) 프레임 손상: MBAP Length 가 254 초과 (이 저장소 서버)
     │── [len=0x0100] … ───▶│  재동기 불가능 → TCP 연결 끊음
     │◀──── FIN ────────────│
```

### 3.4 이 저장소 안에서의 위치

```
  PLC / HMI (Modbus TCP Client)
        │  TCP :502 (예제는 :1502)
        ▼
 ┌──────────────── multiproto_daemon ─────────────────────────────────────┐
 │ core/fb_api.c  run_cycle_loop: cycle_ms(기본 8ms)마다 mutex 잡고         │
 │                adapter->poll_cycle()                                    │
 │      │                                                                  │
 │      ▼                                                                  │
 │ adapters/modbus/modbus_adapter.c   mb_poll_cycle → mb_stack_poll        │
 │   · config points ↔ (테이블, 주소, 데이터형, 엔디안, scale) 번역         │
 │   · read_point/write_point: 앱 ↔ 로컬 레지스터 맵                        │
 │      │                                                                  │
 │      ▼                                                                  │
 │ stacks/modbus/src/mb_stack.c                                            │
 │   · accept / recv / 재조립 / handle_adu / handle_pdu / send             │
 │   · 로컬 맵: holding[] input[] coils[] discrete[]                       │
 └─────────────────────────────────────────────────────────────────────────┘
        ▲
        │ fb_write_f32(rt, "temperature", 25.5f)   (앱)
```

핵심: **서버 역할에서 PLC 의 요청은 스택이 로컬 맵만 보고 즉시 답한다.** 앱은 맵에
값을 "게시(write_point)"해 두고, PLC 가 쓴 값을 "조회(read_point)"한다. 스택은 "온도"라는
개념을 모르고, 어댑터는 소켓을 모른다.

---

## 4. 데이터 모델 — 네 개의 테이블

### 4.1 네 테이블

Modbus 서버는 개념적으로 **네 개의 배열**을 가진다.

| 테이블 | 원소 크기 | 클라이언트 접근 | 원래 의도 | 읽기 FC | 쓰기 FC | 관행 표기 |
|---|---|---|---|---|---|---|
| **Coils** | 1비트 | 읽기/쓰기 | 디지털 출력(릴레이) | 01 | 05, 15 | 0xxxx (00001~) |
| **Discrete Inputs** | 1비트 | 읽기 전용 | 디지털 입력(스위치) | 02 | — | 1xxxx (10001~) |
| **Input Registers** | 16비트 | 읽기 전용 | 아날로그 입력(측정값) | 04 | — | 3xxxx (30001~) |
| **Holding Registers** | 16비트 | 읽기/쓰기 | 설정값·출력·범용 | 03 | 06, 16, 22, 23 | 4xxxx (40001~) |

- 각 테이블은 PDU 주소 **0~65535** (16비트) 범위를 가진다. 장치는 보통 그중 일부만 구현하고,
  구현 안 된 주소를 읽으면 예외 02 를 돌려준다.
- 사양은 네 테이블이 **물리적으로 분리돼도, 같은 메모리를 겹쳐 봐도** 된다고 허용한다.
  (예: 어떤 장치는 input register 5 와 holding register 5 가 같은 값이다.) 그래서
  "테이블이 다르면 값도 다르다"고 가정하면 안 되고, 매뉴얼을 봐야 한다.
- "읽기 전용"은 **프로토콜 수준**의 이야기다. 서버 내부의 앱(펌웨어)은 input register 를
  자유롭게 갱신한다. 이 저장소에서 앱이 `write_point` 로 input register 를 채우는 것이
  바로 그것이다.

**이 저장소**: 네 테이블을 각각 별도 배열로 둔다 — `uint16_t *holding, *input`,
`uint8_t *coils, *discrete`(비트 packed) ([`mb_stack.c:37-40`](../../stacks/modbus/src/mb_stack.c)).
크기는 `n_holding` 등 config 로 정하고, 생략 시 각 10000 (`MB_MAP_REGS_MAX`,
[`mb_types.h:10-11`](../../stacks/modbus/include/mb_types.h); 적용은 `mb_stack_create`,
[`mb_stack.c:404-419`](../../stacks/modbus/src/mb_stack.c)).

### 4.2 주소 — 프레임 속 0-based vs 매뉴얼의 "40001"

가장 많은 사람이 가장 오래 헤매는 부분이다. 세 가지 표기가 섞여 쓰인다.

| 표기 | 예 (홀딩 레지스터 첫 칸) | 어디서 쓰나 |
|---|---|---|
| **PDU 주소** (0-based offset) | `0` | **프레임에 실제로 들어가는 값.** 프로그래머, Wireshark |
| **레지스터 번호** (1-based) | `1` ("holding register 1") | 사양의 데이터 모델 설명, 일부 매뉴얼 |
| **Modicon 참조 번호** (5자리) | `40001` | 대부분의 장치 매뉴얼, HMI 설정 |
| **확장 참조 번호** (6자리) | `400001` | 10000칸 넘게 쓰는 장치 매뉴얼 |

사양 자체가 "데이터 모델에서 1~n 으로 번호 붙인 원소는 PDU 에서 0~n-1 로 주소 지정된다"
고 말한다. 즉 **"레지스터 1" = PDU 주소 0** 이다. 여기에 Modicon 관행이 테이블 번호를
맨 앞 자리에 붙여 **"40001" = 홀딩 레지스터 1 = PDU 주소 0** 이 된다.

```
 매뉴얼 "40108"
    │└┬─┘
    │ └── 108 번째 레지스터 (1-based)
    └──── 4 = Holding Register 테이블
            ▼
 PDU 주소 = 108 - 1 = 107 = 0x006B     → 프레임: 03 00 6B …
```

변환 공식:

| 매뉴얼 표기 | 테이블 | PDU 주소 |
|---|---|---|
| 0xxxx (00001~09999) | Coil | xxxx − 1 |
| 1xxxx (10001~19999) | Discrete Input | xxxx − 10001 |
| 3xxxx (30001~39999) | Input Register | xxxx − 30001 |
| 4xxxx (40001~49999) | Holding Register | xxxx − 40001 |
| 4xxxxx (400001~465536) | Holding Register | xxxxxx − 400001 |

**혼란 사례**:

| 매뉴얼 문구 | 실제 의미일 가능성 | 확인 방법 |
|---|---|---|
| "Register 40001 = 온도" | PDU 0 | 가장 흔함 |
| "Address 40001" 인데 표 옆에 "(offset 0)" | PDU 0 | 표기 확인 |
| "Holding register 100" | PDU 99 **또는** PDU 100 | 제조사마다 다름. 둘 다 읽어 보고 값이 말이 되는 쪽 |
| "Modbus address 0x0064" (16진) | 대개 PDU 100 그대로 | 16진 표기는 보통 PDU 주소 |
| "4x0100" | 제조사 도구 방언 | 매뉴얼/도구 문서 |

현장 요령: **값을 아는 레지스터(모델 번호, 펌웨어 버전 등) 하나를 골라 N 과 N−1 을 둘 다
읽어 본다.** 한 칸 밀림(off-by-one)은 거의 항상 이 차이다.

이 저장소 어댑터의 정규화 규칙은 9.4 절에 실측 표가 있다.

### 4.3 비트 테이블의 포장 (packing)

코일/이산 입력을 여러 개 읽으면 응답은 **바이트 하나에 8개씩**, **첫 비트가 첫 바이트의
최하위 비트(LSB)** 에 들어간다. 8의 배수가 아니면 마지막 바이트의 남는 상위 비트는 0.

```
코일 20~38 (19개, PDU 주소 0x13부터) 상태가 아래와 같다면:
  코일:   27 26 25 24 23 22 21 20 | 35 34 33 32 31 30 29 28 | - - - - - 38 37 36
  값  :    1  1  0  0  1  1  0  1 |  0  1  1  0  1  0  1  1 | 0 0 0 0 0  1  0  1
  바이트:           0xCD          |          0x6B          |        0x05
```

(사양서 FC01 예제와 같은 값이며, 이 저장소 스택으로 재현했다 — 5.4 절.)

### 4.4 16비트 한 칸에 담기는 것

| 원래 값 | 레지스터 값 | 설명 |
|---|---|---|
| uint16 1234 | `0x04D2` | 그대로 |
| int16 −1 | `0xFFFF` | 2의 보수 |
| int16 −100 | `0xFF9C` | 2의 보수 |
| 25.5 ℃ (0.1 단위) | `0x00FF` (=255) | **스케일링**: 정수로 보내고 매뉴얼이 "×0.1" 이라고 알려 줌 |
| BCD 1234 | `0x1234` | 16진 자리마다 10진 숫자 하나 (오래된 장치) |
| 비트 묶음 | `0x0008` | bit 3 = 경보. "상태 워드" |
| 문자 "AB" | `0x4142` | 'A'(0x41)가 상위 바이트 |

### 4.5 32/64비트 값 — 워드 순서 지옥

float32 `1.5` 는 IEEE-754 로 `0x3FC00000` 이다. 바이트로 `3F C0 00 00`, 이것을 앞에서부터
**A B C D** 라고 부르자. 레지스터 두 칸에 넣는 방법이 장치마다 네 가지다.

| 이름 | 레지스터 N | 레지스터 N+1 | 누가 쓰나 (경향) |
|---|---|---|---|
| **ABCD** (big-endian, "high word first") | `3FC0` | `0000` | 사양 정신에 가장 가까움. 많은 장치 기본 |
| **CDAB** (word swap, "low word first") | `0000` | `3FC0` | Modicon/Schneider 계열, 많은 PLC |
| **BADC** (byte swap) | `C03F` | `0000` | 드묾 |
| **DCBA** (little-endian) | `0000` | `C03F` | 드묾 (리틀엔디안 CPU 메모리를 그대로 덤프) |

좀 더 구별하기 쉬운 값으로 (이 저장소 코덱 `mb_canonical_to_wire` 로 실측):

| 값 | ABCD | BADC | CDAB | DCBA |
|---|---|---|---|---|
| int32 `0x12345678` | `1234 5678` | `3412 7856` | `5678 1234` | `7856 3412` |
| float32 `123.456f` = `0x42F6E979` | `42F6 E979` | `F642 79E9` | `E979 42F6` | `79E9 F642` |
| uint64 `0x1122334455667788` | `1122 3344 5566 7788` | `2211 4433 6655 8877` | `7788 5566 3344 1122` | `8877 6655 4433 2211` |

64비트 CDAB 는 "4개 워드 전체를 역순"으로 구현돼 있다 ([`modbus_codec.c:208-218`](../../adapters/modbus/modbus_codec.c)).
64비트에서 CDAB 의 의미는 장치마다 해석이 갈리므로(워드 전체 역순 vs 32비트 반쪽만
교환) 반드시 알려진 값으로 확인할 것.

**모르는 장치의 워드 순서 알아내는 법**: 값을 아는 float(예: 설정값 1.0 = `0x3F800000`)을
읽어 두 레지스터를 본다. `3F80 0000` 이면 ABCD, `0000 3F80` 이면 CDAB.

### 4.6 문자열

레지스터 한 칸에 문자 **2개**(상위 바이트가 먼저) 넣는 것이 일반적이다. `"ABC123"` →
`4142 4331 3233`. 일부 장치는 칸당 1문자(하위 바이트만), 일부는 바이트 순서를 뒤집는다
(`"BA"` = `0x4241`). 끝은 `0x00` 으로 채운다.

```
PLC 가 FC03 addr 0 qty 4 로 바코드를 읽으면 (이 저장소 example.modbus.json 실측):
  응답 PDU: 03 08 41 42 43 31 32 33 00 00      → "ABC123\0\0"
```

---

## 5. 프레임 포맷

### 5.1 MBAP 헤더 (7바이트)

| 오프셋 | 크기 | 필드 | 요청에서 | 응답에서 | 이 저장소 |
|---|---|---|---|---|---|
| 0 | 2 | Transaction Identifier | 클라이언트가 정함 (보통 매 요청 +1) | **요청 값 그대로 복사** | 복사 ([`mb_stack.c:340`](../../stacks/modbus/src/mb_stack.c)) |
| 2 | 2 | Protocol Identifier | `0x0000` | `0x0000` | ≠0 이면 거부 ([`mb_stack.c:357`](../../stacks/modbus/src/mb_stack.c)) |
| 4 | 2 | Length | 뒤따르는 바이트 수 = 1 + PDU 길이 | 서버가 다시 계산 | `1 + out_len` ([`mb_stack.c:342`](../../stacks/modbus/src/mb_stack.c)) |
| 6 | 1 | Unit Identifier | 게이트웨이 뒤 장치 번호 (직접 연결 시 관례상 0xFF/1/0) | **요청 값 그대로** | 에코 ([`mb_stack.c:343`](../../stacks/modbus/src/mb_stack.c)) |

- 모든 2바이트 필드는 빅 엔디안.
- Length 의 최솟값은 2 (Unit 1 + FC 1), 최댓값은 254 (Unit 1 + PDU 253).
- 전체 ADU 길이 = `6 + Length` (TID·Proto·Length 6바이트 + Length 가 센 바이트). 최대 260.

### 5.2 PDU 일반형과 기능 코드 공간

```
요청 PDU  : [FC 1B][요청 데이터]
정상 응답 : [FC 1B][응답 데이터]          (FC 는 요청과 같음)
예외 응답 : [FC | 0x80][예외 코드 1B]     (정확히 2바이트)
```

| FC 범위 | 용도 (사양) |
|---|---|
| 1~64, 73~99, 111~127 | 공용(public) 기능 코드 — 사양이 정의하거나 예약 |
| 65~72, 100~110 | 사용자 정의(user-defined) — 제조사 전용 |
| 128~255 | 예외 응답 표시용 (FC + 0x80) — 요청에 쓰면 안 됨 |

### 5.3 기능 코드 목록

| FC | 16진 | 이름 | 테이블 | 이 저장소 |
|---|---|---|---|---|
| 1 | 0x01 | Read Coils | Coil | ✅ |
| 2 | 0x02 | Read Discrete Inputs | DI | ✅ |
| 3 | 0x03 | Read Holding Registers | HR | ✅ |
| 4 | 0x04 | Read Input Registers | IR | ✅ |
| 5 | 0x05 | Write Single Coil | Coil | ✅ |
| 6 | 0x06 | Write Single Register | HR | ✅ |
| 7 | 0x07 | Read Exception Status | — | ❌ (시리얼 전용) |
| 8 | 0x08 | Diagnostics | — | ❌ → 예외 01 (시리얼 전용) |
| 11 | 0x0B | Get Comm Event Counter | — | ❌ (시리얼 전용) |
| 12 | 0x0C | Get Comm Event Log | — | ❌ (시리얼 전용) |
| 15 | 0x0F | Write Multiple Coils | Coil | ✅ |
| 16 | 0x10 | Write Multiple Registers | HR | ✅ |
| 17 | 0x11 | Report Server ID | — | ❌ (시리얼 전용) |
| 20 | 0x14 | Read File Record | 파일 | ❌ |
| 21 | 0x15 | Write File Record | 파일 | ❌ |
| 22 | 0x16 | Mask Write Register | HR | ✅ |
| 23 | 0x17 | Read/Write Multiple Registers | HR | ✅ |
| 24 | 0x18 | Read FIFO Queue | HR | ❌ |
| 43/14 | 0x2B/0x0E | Read Device Identification (MEI) | — | ❌ → 예외 01 |

"시리얼 전용" 표시는 사양서가 해당 FC 를 "Serial Line only" 로 분류한 것들이다.
구현된 FC 목록은 `mb_types.h:22-31`, 분기는 `handle_pdu` 의 `switch`
([`mb_stack.c:158-334`](../../stacks/modbus/src/mb_stack.c)).

이하 각 FC 의 요청/응답 표와 **실측 hex**. 모든 예제는 unit_id=1 서버에 넣은 결과다.
값은 가능한 한 **사양서 본문 예제와 같은 값**으로 맞췄으므로 사양서와 대조해 읽을 수 있다.

### 5.4 FC 01 Read Coils / FC 02 Read Discrete Inputs

**요청 PDU** (5바이트)

| 오프셋 | 크기 | 필드 | 범위 |
|---|---|---|---|
| 0 | 1 | FC | 0x01 / 0x02 |
| 1 | 2 | Starting Address | 0x0000~0xFFFF |
| 3 | 2 | Quantity of bits | 1~2000 (0x0001~0x07D0) |

**응답 PDU**

| 오프셋 | 크기 | 필드 | 설명 |
|---|---|---|---|
| 0 | 1 | FC | 0x01 / 0x02 |
| 1 | 1 | Byte Count | N = ceil(수량 / 8) |
| 2 | N | 상태 비트 | 4.3 절 포장 규칙. 남는 상위 비트 0 |

**예제: 코일 20~38 읽기** (PDU 주소 0x0013 = 19, 수량 0x0013 = 19)

```
REQ : 00 01 00 00 00 06 01 01 00 13 00 13
RESP: 00 01 00 00 00 06 01 01 03 CD 6B 05
```

| 바이트 | 필드 | 의미 |
|---|---|---|
| `00 01` | TID | 1 |
| `00 00` | Proto | Modbus |
| `00 06` | Length | 뒤에 6바이트 (Unit + PDU 5) |
| `01` | Unit | 1 |
| `01` | FC | Read Coils |
| `00 13` | 시작 주소 | 19 = "코일 20" |
| `00 13` | 수량 | 19개 |
| 응답 `00 06` | Length | Unit 1 + FC 1 + BC 1 + 데이터 3 |
| 응답 `03` | Byte Count | ceil(19/8)=3 |
| `CD 6B 05` | 상태 | 코일 20~27=0xCD, 28~35=0x6B, 36~38=0x05(상위 5비트 0) |

**예제: 이산 입력 197~218 읽기** (PDU 0x00C4 = 196, 수량 22)

```
REQ : 00 02 00 00 00 06 01 02 00 C4 00 16
RESP: 00 02 00 00 00 06 01 02 03 AC DB 35
```

**이 저장소**: [`mb_stack.c:159-184`](../../stacks/modbus/src/mb_stack.c). 수량 검사
`qty < 1 || qty > 2000` 과 범위 검사 `map_ok_bits` 를 한 조건으로 묶어 **둘 다 예외 02** 를
낸다 (사양은 수량 위반에 예외 03 — 부록 D #1).

### 5.5 FC 03 Read Holding Registers / FC 04 Read Input Registers

**요청 PDU**: FC(1) + Starting Address(2) + Quantity(2), 수량 1~125 (0x0001~0x007D).

**응답 PDU**: FC(1) + Byte Count(1, = 2×수량) + 레지스터 값(2×수량, 각 빅 엔디안).

**예제: 홀딩 레지스터 108~110 읽기** (PDU 0x006B, 수량 3)

```
REQ : 00 03 00 00 00 06 01 03 00 6B 00 03
RESP: 00 03 00 00 00 09 01 03 06 02 2B 00 00 00 64
```

| 바이트 | 필드 | 의미 |
|---|---|---|
| `03` | FC | Read Holding Registers |
| `00 6B` | 시작 주소 | 107 ("40108") |
| `00 03` | 수량 | 3 |
| 응답 `00 09` | Length | 1 + 1 + 1 + 6 = 9 |
| `06` | Byte Count | 3 × 2 |
| `02 2B` | reg 107 | 555 |
| `00 00` | reg 108 | 0 |
| `00 64` | reg 109 | 100 |

**예제: 입력 레지스터 9 읽기** (PDU 0x0008, 수량 1)

```
REQ : 00 04 00 00 00 06 01 04 00 08 00 01
RESP: 00 04 00 00 00 05 01 04 02 00 0A
```

**최대 크기**: 125개 읽기 응답은 ADU 259바이트 (Length `0x00FD`=253, Byte Count 250) — 실측.

**이 저장소**: [`mb_stack.c:185-206`](../../stacks/modbus/src/mb_stack.c). 역시 수량 위반이
예외 02.

### 5.6 FC 05 Write Single Coil

**요청 PDU**: FC(1) + Output Address(2) + Output Value(2). 값은 **`0xFF00`(ON) 또는
`0x0000`(OFF) 만** 합법. 그 외 값은 예외 03.

**응답 PDU**: 요청과 **완전히 같다** (에코).

**예제: 코일 173 ON** (PDU 0x00AC = 172)

```
REQ : 00 05 00 00 00 06 01 05 00 AC FF 00
RESP: 00 05 00 00 00 06 01 05 00 AC FF 00
```

OFF 는 값만 `00 00`. 흔한 실수: ON 을 `00 01` 로 보냄 → `85 03` (5.13 절).

**이 저장소**: [`mb_stack.c:207-223`](../../stacks/modbus/src/mb_stack.c). 값 검사를 주소
검사보다 먼저 한다 (사양 처리 순서와 일치). 그래서 값도 틀리고 주소도 범위 밖이면 03 이
나온다 (실측).

### 5.7 FC 06 Write Single Register

**요청 PDU**: FC(1) + Register Address(2) + Register Value(2). **응답**: 에코.

**예제: 레지스터 2 에 3 쓰기** (PDU 0x0001)

```
REQ : 00 07 00 00 00 06 01 06 00 01 00 03
RESP: 00 07 00 00 00 06 01 06 00 01 00 03
```

**이 저장소**: [`mb_stack.c:224-237`](../../stacks/modbus/src/mb_stack.c).

### 5.8 FC 15 (0x0F) Write Multiple Coils

**요청 PDU**

| 오프셋 | 크기 | 필드 | 범위 |
|---|---|---|---|
| 0 | 1 | FC | 0x0F |
| 1 | 2 | Starting Address | |
| 3 | 2 | Quantity of Outputs | 1~1968 (0x07B0) |
| 5 | 1 | Byte Count | N = ceil(수량/8) — **정확히 일치해야** 함 |
| 6 | N | 출력 값 | FC01 과 같은 LSB-first 포장 |

**응답 PDU**: FC(1) + Starting Address(2) + Quantity(2). 데이터는 돌려주지 않는다.

**예제: 코일 20 부터 10개 쓰기** (PDU 0x0013, 수량 10, 데이터 `CD 01`)

```
REQ : 00 08 00 00 00 09 01 0F 00 13 00 0A 02 CD 01
RESP: 00 08 00 00 00 06 01 0F 00 13 00 0A
```

`CD` = 코일 20~27 = 1,0,1,1,0,0,1,1 (LSB 부터), `01` = 코일 28 = 1, 코일 29 = 0.
되읽기(FC01 addr 0x13 qty 10) → `01 02 CD 01` (실측).

**이 저장소**: [`mb_stack.c:238-261`](../../stacks/modbus/src/mb_stack.c). 수량·바이트수·실제
PDU 길이를 먼저 확인(예외 03) 한 뒤 범위(예외 02). 사양 순서와 일치.

### 5.9 FC 16 (0x10) Write Multiple Registers

**요청 PDU**: FC(1) + Starting Address(2) + Quantity(2, 1~123 = 0x007B) + Byte Count(1, = 2×수량)
+ 값(2×수량).
**응답 PDU**: FC(1) + Starting Address(2) + Quantity(2).

**예제: 레지스터 2 부터 2개에 `000A`, `0102` 쓰기** (PDU 0x0001)

```
REQ : 00 0A 00 00 00 0B 01 10 00 01 00 02 04 00 0A 01 02
RESP: 00 0A 00 00 00 06 01 10 00 01 00 02
```

| 바이트 | 필드 |
|---|---|
| `00 0B` | Length = 1 + (1+2+2+1+4) = 11 |
| `10` | FC 16 |
| `00 01` / `00 02` | 시작 주소 1, 수량 2 |
| `04` | Byte Count |
| `00 0A 01 02` | 값 두 개 |

**이 저장소**: [`mb_stack.c:262-284`](../../stacks/modbus/src/mb_stack.c).

### 5.10 FC 22 (0x16) Mask Write Register

한 레지스터의 **일부 비트만** 바꾼다 (읽고-고치고-쓰기를 서버 안에서 원자적으로).

```
결과 = (현재값 AND And_Mask) OR (Or_Mask AND (NOT And_Mask))
```

- And_Mask 의 1 비트 = "현재 값 유지", 0 비트 = "Or_Mask 값으로 교체".
- 요청 PDU: FC(1) + Reference Address(2) + And_Mask(2) + Or_Mask(2). **응답**: 에코.

**예제** (현재값 `0x0012`, And `0x00F2`, Or `0x0025` → 결과 `0x0017`)

```
REQ : 00 0C 00 00 00 08 01 16 00 04 00 F2 00 25
RESP: 00 0C 00 00 00 08 01 16 00 04 00 F2 00 25
되읽기 FC03 addr 4 → 03 02 00 17
```

계산: `0x12 & 0xF2 = 0x12`, `0x25 & ~0xF2 = 0x25 & 0x0D = 0x05`, `0x12 | 0x05 = 0x17`.

**이 저장소**: [`mb_stack.c:285-302`](../../stacks/modbus/src/mb_stack.c).

### 5.11 FC 23 (0x17) Read/Write Multiple Registers

한 트랜잭션으로 **쓰기 먼저, 그다음 읽기**. (사양: 쓰기가 읽기보다 먼저 수행된다.)

**요청 PDU**

| 오프셋 | 크기 | 필드 | 범위 |
|---|---|---|---|
| 0 | 1 | FC | 0x17 |
| 1 | 2 | Read Starting Address | |
| 3 | 2 | Quantity to Read | 1~125 (0x007D) |
| 5 | 2 | Write Starting Address | |
| 7 | 2 | Quantity to Write | 1~121 (0x0079) |
| 9 | 1 | Write Byte Count | 2 × Quantity to Write |
| 10 | 2×W | 쓸 값 | |

**응답 PDU**: FC(1) + Byte Count(1, = 2×Quantity to Read) + 읽은 값.

**예제: 레지스터 4~9 읽고 15~17 에 `00FF` ×3 쓰기** (read addr 3 qty 6, write addr 14 qty 3)

```
REQ : 00 0E 00 00 00 11 01 17 00 03 00 06 00 0E 00 03 06 00 FF 00 FF 00 FF
RESP: 00 0E 00 00 00 0F 01 17 0C 00 FE 0A CD 00 01 00 03 00 0D 00 FF
```

**이 저장소**: [`mb_stack.c:303-331`](../../stacks/modbus/src/mb_stack.c). 쓰기 루프(321행)
후 읽기 루프(326행) — 사양 순서와 일치.

### 5.12 FC 43 / MEI 14 (0x2B/0x0E) Read Device Identification

장치의 제조사명·제품 코드·버전 문자열을 읽는 기능. **이 저장소는 구현하지 않는다**
([`../ctt_mb_bundle.md`](../ctt_mb_bundle.md) §3.2 "Slave ID / MEI (FC43) — DUT not implemented").
그래서 실제 응답은 예외 01 이다 (실측):

```
REQ : 00 11 00 00 00 05 01 2B 0E 01 00
RESP: 00 11 00 00 00 03 01 AB 01          ← 0x2B|0x80 = 0xAB, ILLEGAL FUNCTION
```

직접 구현한다면 형식은 다음과 같다 (**사양 기반 설명, 이 저장소로 검증 불가** — 필드
세부 값은 사양서 확인 필요):

| 요청 필드 | 크기 | 값 |
|---|---|---|
| FC | 1 | 0x2B |
| MEI Type | 1 | 0x0E |
| Read Device ID code | 1 | 01 기본 / 02 일반 / 03 확장 (스트림) / 04 개별 객체 |
| Object Id | 1 | 시작 객체 (기본 00) |

| 응답 필드 | 크기 | 설명 |
|---|---|---|
| FC, MEI Type, Read Device ID code | 3 | 요청 에코 |
| Conformity Level | 1 | 장치가 지원하는 수준 (예: 0x01 / 0x81 …) |
| More Follows | 1 | 0x00 끝, 0xFF 이어짐 |
| Next Object Id | 1 | More Follows=0xFF 일 때 다음 요청의 Object Id |
| Number of Objects | 1 | 이 응답의 객체 수 |
| (Object Id, Length, Value) × n | | 00 VendorName, 01 ProductCode, 02 MajorMinorRevision 은 기본(basic) 필수 |

예시(설명용, 값은 임의): `2B 0E 01 01 00 00 03 00 04 "ACME" 01 03 "X10" 02 04 "V1.0"`.

### 5.13 예외 응답

**형식**: `[FC | 0x80][예외 코드]` — PDU 정확히 2바이트, MBAP Length = 3, ADU 9바이트.

| 코드 | 이름 | 의미 | 이 저장소가 내는가 |
|---|---|---|---|
| 0x01 | ILLEGAL FUNCTION | 지원 안 하는 FC | ✅ 미구현 FC 전부 ([`mb_stack.c:332-333`](../../stacks/modbus/src/mb_stack.c)) |
| 0x02 | ILLEGAL DATA ADDRESS | 주소(또는 주소+수량)가 범위 밖 | ✅ (+ FC01~04 수량 위반에도 — 부록 D #1) |
| 0x03 | ILLEGAL DATA VALUE | 값/수량/바이트수/PDU 길이가 규칙 위반 | ✅ |
| 0x04 | SERVER DEVICE FAILURE | 처리 중 복구 불가 오류 | ❌ (`MB_EX_SLAVE_FAILURE` 정의만, 미사용 — [`mb_types.h:37`](../../stacks/modbus/include/mb_types.h)) |
| 0x05 | ACKNOWLEDGE | 오래 걸리는 명령 접수됨 (주로 프로그래밍 명령) | ❌ |
| 0x06 | SERVER DEVICE BUSY | 바쁘니 나중에 | ❌ |
| 0x08 | MEMORY PARITY ERROR | 파일 레코드 FC 관련 | ❌ |
| 0x0A | GATEWAY PATH UNAVAILABLE | 게이트웨이가 경로를 못 찾음 | ❌ (게이트웨이 아님) |
| 0x0B | GATEWAY TARGET DEVICE FAILED TO RESPOND | 게이트웨이 뒤 장치 무응답 | ❌ |

**실측 예외 모음**

| 상황 | 요청 | 응답 |
|---|---|---|
| FC08 (미구현) | `00 10 00 00 00 06 01 08 00 00 12 34` | `00 10 00 00 00 03 01 88 01` |
| 범위 밖 (맵 200칸, addr 199 qty 2) | `00 12 00 00 00 06 01 03 00 C7 00 02` | `00 12 00 00 00 03 01 83 02` |
| FC05 값 `0x0001` | `00 16 00 00 00 06 01 05 00 00 00 01` | `00 16 00 00 00 03 01 85 03` |
| FC16 바이트수 불일치 | `00 19 00 00 00 09 01 10 00 00 00 02 03 00 11 22` | `00 19 00 00 00 03 01 90 03` |
| PDU 가 FC 뿐 (Length=2) | `00 1A 00 00 00 02 01 03` | `00 1A 00 00 00 03 01 83 03` |
| FC03 수량 0 | `00 13 00 00 00 06 01 03 00 00 00 00` | `00 13 00 00 00 03 01 83 02` ← 사양은 03 |
| FC03 수량 126 | `00 14 00 00 00 06 01 03 00 00 00 7E` | `00 14 00 00 00 03 01 83 02` ← 사양은 03 |
| FC06 범위 밖 | `00 22 00 00 00 06 01 06 00 C8 00 01` | `00 22 00 00 00 03 01 86 02` |

예외 응답 생성: `build_exception` ([`mb_stack.c:130-140`](../../stacks/modbus/src/mb_stack.c)).

---

## 6. 동작과 상태

### 6.1 서버의 요청 처리 흐름 (사양 상태도 요약)

사양서는 FC 마다 처리 순서를 상태도로 정해 둔다. 공통 골격은 다음과 같다.

```
 요청 PDU 수신
    │
    ├─ FC 를 지원하나? ───────────── 아니오 → 예외 01
    │
    ├─ 수량/값/바이트수가 규칙 안인가? ── 아니오 → 예외 03
    │     (FC03: 1 ≤ qty ≤ 0x7D, FC05: 값 ∈ {0x0000, 0xFF00}, FC16: bc == 2·qty …)
    │
    ├─ 주소 (및 주소+수량) 가 유효한가? ─ 아니오 → 예외 02
    │
    ├─ 실행 ─────────────────────── 실패 → 예외 04
    │
    └─ 정상 응답
```

**순서가 중요한 이유**: 적합성 시험기는 "수량도 틀리고 주소도 틀린" 요청을 보내고 03 이
오는지 본다. 이 저장소는 FC05/06/15/16/22/23 에서는 이 순서를 지키지만, FC01~04 에서는
수량과 주소를 한 조건으로 묶어 02 를 낸다 (부록 D #1).

### 6.2 TCP 연결 관리

**사양/구현 가이드의 요지** (Messaging on TCP/IP Implementation Guide):

- 서버는 TCP **502** 포트에서 대기한다 (IANA 등록 포트).
- 클라이언트는 연결을 **열어 둔 채 재사용**하는 것이 권장된다. 요청마다 connect/close 하면
  느리고 서버 자원을 낭비한다.
- 한 서버는 여러 클라이언트 연결을 동시에 받을 수 있어야 하며, 동시 연결 수 상한은 장치가
  정한다.
- 죽은 연결(케이블 뽑힘 등)을 감지하기 위해 keep-alive 또는 유휴 타임아웃을 쓴다.
  구현 가이드는 소켓 옵션(TCP_NODELAY, SO_KEEPALIVE 등)의 사용을 논한다 — 구체적 권고
  문구·값은 사양서 확인 필요.

**이 저장소 서버의 연결 정책** (실측 + 코드):

| 항목 | 값/동작 | 코드 |
|---|---|---|
| 포트 | `port` (기본 502, 예제 1502) | `mb_stack_create`, [`mb_stack.c:382-384`](../../stacks/modbus/src/mb_stack.c) |
| bind 주소 | `bind_ip` / `ip` (기본 0.0.0.0) | `server_listen`, [`mb_stack.c:472-478`](../../stacks/modbus/src/mb_stack.c) |
| listen backlog | 4 | [`mb_stack.c:486`](../../stacks/modbus/src/mb_stack.c) |
| 동시 클라이언트 | `max_clients` 기본 4, 최대 8 (`MB_CLIENTS_MAX`) | [`mb_stack.c:391-397`](../../stacks/modbus/src/mb_stack.c) |
| 초과 접속 | `accept` 후 **즉시 close** (클라이언트는 곧바로 FIN 을 받음 — 실측) | `accept_clients`, [`mb_stack.c:616-619`](../../stacks/modbus/src/mb_stack.c) |
| 소스 IP 당 상한 | `max_conn_per_ip` 기본 4, 초과 시 close + `LOG_WARN` | [`mb_stack.c:602-608`](../../stacks/modbus/src/mb_stack.c) |
| 유휴 타임아웃 | `idle_timeout_ms` 기본 60000. 마지막 수신 후 초과 시 close | `mb_stack_poll`, [`mb_stack.c:1030-1040`](../../stacks/modbus/src/mb_stack.c) |
| TCP keep-alive | 설정 안 함 (유휴 타임아웃으로 대체) | — |
| TCP_NODELAY | **설정 안 함** (`netinet/tcp.h` 를 include 하지만 미사용) — 6.3 절 | — |
| 송신 실패 | `send_all` 이 -1 → 연결 close. non-blocking 소켓이라 송신 버퍼가 차서 `EAGAIN` 이 나도 끊는다 (코드 읽기) | [`mb_stack.c:676-693`](../../stacks/modbus/src/mb_stack.c) |

유휴 타임아웃과 IP 당 상한은 `tests/test_mb_stack.c:232-287` (`test_g7_mb_idle_and_per_ip`)가
실제 소켓으로 검증한다.

### 6.3 Transaction ID 와 파이프라이닝

- 클라이언트는 요청마다 TID 를 정하고, 서버는 **그대로 복사**한다. 클라이언트는 응답의 TID 로
  "어느 요청의 응답인가"를 판단한다.
- TCP 는 순서를 보장하므로 한 연결 안에서 서버가 순서대로 답하면 TID 가 없어도 짝은 맞는다.
  TID 가 진짜로 필요해지는 때는 (1) 파이프라이닝, (2) 타임아웃 뒤 늦게 온 응답을 버릴 때다.
- 구현 가이드는 클라이언트가 응답을 기다리지 않고 여러 요청을 보내는 것(파이프라이닝)을
  허용한다. 서버가 동시에 처리할 수 있는 트랜잭션 수는 장치마다 다르다.

**이 저장소 서버**: 한 번의 `recv` 로 여러 ADU 가 들어오면 `while` 루프로 **전부 순서대로**
처리한다 ([`mb_stack.c:650-672`](../../stacks/modbus/src/mb_stack.c)). 수신 버퍼는
`MB_RX_CAP = 2 × 260 = 520` 바이트 ([`mb_stack.c:18`](../../stacks/modbus/src/mb_stack.c)).
응답도 요청 순서 그대로다.

**실측 — Nagle 효과**: 서버가 `TCP_NODELAY` 를 켜지 않으므로, 파이프라인된 두 번째 응답이
**Nagle 알고리즘 + 상대의 지연 ACK** 에 걸려 늦게 나갈 수 있다. 같은 C 하네스에서

| 서버 | 두 ADU 를 한 번에 보낸 뒤 20ms 안에 받은 응답 |
|---|---|
| 저장소 스택 그대로 | **1개** (두 번째는 다음 확인 때 도착) |
| 스크래치 복사본에 `setsockopt(TCP_NODELAY)` 한 줄 추가 | **2개** |

반면 새로 연 연결에서 Python 클라이언트로 4개를 파이프라인했을 때는 4개가 모두 ~1ms 안에
왔다 (리눅스 quick-ACK 구간). 즉 **조건부로 수십 ms 지연**이 생긴다. 한 번에 한 요청만
보내는 일반 PLC 폴링에는 영향이 거의 없지만, 파이프라이닝 클라이언트나 지연에 민감한
시험에는 영향이 있다. (저장소 수정은 이 문서 범위 밖 — 부록 D #7.)

### 6.4 부분 수신(TCP 조각) 처리 — 재조립

```
상태: buf[], len

on_readable():
    n = recv(fd, buf+len, cap-len)
    if n <= 0: 연결 종료
    len += n
    loop:
        if len < 7:                  break          # 헤더도 아직
        L = be16(buf[4..5])
        if L < 2 or L > 254:         연결 종료       # 경계를 잃었다 = 재동기 불가
        need = 6 + L
        if len < need:               break          # 본문이 아직
        handle(buf[0..need])                        # ADU 하나 처리
        memmove(buf, buf+need, len-need); len -= need
```

**이 저장소**: `serve_client` ([`mb_stack.c:628-674`](../../stacks/modbus/src/mb_stack.c))가
정확히 이 구조다. 실측:

| 입력 | 결과 |
|---|---|
| 12바이트 요청을 5 + 7 로 나눠 보냄 | 첫 5바이트 후 응답 없음, 나머지 7바이트 후 정상 응답 |
| 두 ADU 를 한 `send` 로 | 두 응답 모두 (TID 0x0A, 0x0B) |
| 잘못된 Unit ADU + 정상 ADU | 첫 번째 무시, 두 번째 응답 |
| Protocol ID ≠ 0 ADU + 정상 ADU | 첫 번째 버림(연결 유지), 두 번째 응답 |
| MBAP Length = 0x0100 (>254) | 연결 끊음 (FIN) |

주의할 점: MBAP Length 가 **실제 PDU 보다 짧게** 적힌 요청(예: FC03 인데 Length=3)은
서버가 "짧은 PDU → 예외 03" 으로 답한 뒤 남은 바이트를 **다음 ADU 의 시작으로 오인**한다.
이것은 Modbus TCP 의 구조적 한계로, 어떤 구현이든 Length 를 믿을 수밖에 없다.

### 6.5 Unit Identifier

- **시리얼 시절**: 한 RS-485 선에 장치 최대 247대, 각자 주소 1~247. 주소 0 은 브로드캐스트
  (모두 실행, 아무도 응답 안 함).
- **TCP**: 장치는 IP 주소로 구별되므로 Unit ID 는 원래 **게이트웨이 뒤 시리얼 장치를 고르는
  용도**다. 구현 가이드는 TCP 에 직접 붙은 장치를 부를 때 Unit ID 로 `0xFF` 를 쓰라고 권하고
  (사양서 문구 확인 권장), 서버는 받은 값을 응답에 그대로 돌려준다.
- **현장 현실**: 많은 클라이언트가 1 을 보내고, 많은 장치가 "아무 값이나 받거나", "자기 번호만
  받거나", "0/0xFF 도 받는" 식으로 제각각이다. TCP 에서 Unit ID 0 의 의미(브로드캐스트인가
  아닌가)도 구현마다 다르다 — 사양서 확인 필요.

**이 저장소 서버의 규칙** ([`mb_stack.c:149-152`](../../stacks/modbus/src/mb_stack.c)):

```c
if (!s->cfg.unit_id_any && unit != (uint8_t)s->cfg.unit_id && unit != 0) {
    return 0;   /* 응답 없이 무시 */
}
```

| 요청 Unit | `unit_id_any=false`, `unit_id=1` | `unit_id_any=true` |
|---|---|---|
| 1 | 응답 (Unit 1 에코) | 응답 |
| 0 | **응답** (Unit 0 에코) — 브로드캐스트로 취급하지 않음 | 응답 |
| 0xFF | **무시 (무응답)** | 응답 (Unit 0xFF 에코) |
| 9 | 무시 | 응답 |

실측값이다. 결론: **클라이언트가 0xFF 를 보내는 환경이면 `unit_id_any: true`** 를 켜거나
`unit_id: 255` 로 설정해야 한다. 무시된 요청은 예외도 안 오므로 클라이언트는 타임아웃만 본다
(디버깅 시 1순위 확인 항목).

### 6.6 손상된 MBAP 처리

| 조건 | `mb_stack_handle_adu` (단일 ADU) | `serve_client` (TCP 스트림) |
|---|---|---|
| 입력 < 8바이트 | `-EINVAL` | (7바이트 모일 때까지 대기) |
| Protocol ID ≠ 0 | `-EINVAL`, 응답 없음 | 해당 ADU 버리고 **연결 유지** |
| Length < 2 | `-EINVAL` | **연결 끊음** |
| Length > 254 (ADU > 260) | `6+len > req_len` 이면 `-EINVAL` | **연결 끊음** |
| Length 가 실제보다 큼 | `-EINVAL` | 나머지가 올 때까지 대기 |
| Length 가 실제보다 작음 | 짧은 PDU 로 처리 (대개 예외 03) | 위와 같음 + 남은 바이트가 다음 ADU 로 오인됨 |

코드: [`mb_stack.c:351-359`](../../stacks/modbus/src/mb_stack.c), [`mb_stack.c:650-656`](../../stacks/modbus/src/mb_stack.c).
CTT `MB-T-NEG-002` (`adu_malformed.yaml`)가 이 표의 앞쪽 다섯 경우를 고정한다.

### 6.7 클라이언트 측 동작

사양이 클라이언트에 요구하는 것은 적다: TID 로 응답을 짝짓고, 타임아웃을 두고, 예외를
처리하라. 좋은 클라이언트의 실무 규칙:

1. 연결은 한 번 열고 재사용한다.
2. **요청마다 타임아웃**을 둔다 (LAN 이면 보통 수백 ms ~ 1s).
3. 타임아웃이 나면 **늦게 도착할 응답을 반드시 처리**해야 한다: (a) TID 가 다르면 버리고
   계속 읽거나, (b) 가장 안전하게 **연결을 끊고 다시 연다**.
4. 여러 포인트를 읽을 때는 **인접 레지스터를 하나의 FC03 으로 묶는다**(최대 125).
5. 재시도 횟수·재연결 백오프를 둔다.

**이 저장소 클라이언트** (`role: "client"`):

| 항목 | 동작 | 코드 |
|---|---|---|
| 연결 | **블로킹 `connect()`** (타임아웃 없음 — 도달 불가 IP 면 커널 재시도 동안 멈춤) | `client_connect`, [`mb_stack.c:500-531`](../../stacks/modbus/src/mb_stack.c) |
| 재연결 | `poll` 때 `client_fd<0 \|\| !connected` 이면 재시도 | [`mb_stack.c:1044-1051`](../../stacks/modbus/src/mb_stack.c) |
| 응답 대기 | `select` 로 `client_timeout_ms`(기본 200) 대기 | `client_recv_adu`, [`mb_stack.c:695-750`](../../stacks/modbus/src/mb_stack.c) |
| TID | 함수별 `static uint16_t tid_seq` **세 개** (`client_txn`/`write_regs`/`write_bits`, [`mb_stack.c:767,879,949`](../../stacks/modbus/src/mb_stack.c)) — 각각 1부터 시작하고 모든 스택 인스턴스가 공유 | 실측: 읽기·레지스터 쓰기·코일 쓰기 첫 요청이 모두 TID `0x0001` |
| 폴링 | `mb_poll_cycle` 이 포인트마다 **하나씩** FC01~04 요청 (묶지 않음) | [`modbus_adapter.c:549-569`](../../adapters/modbus/modbus_adapter.c) |
| 쓰기 | 1개면 FC06/FC05, 여러 개면 FC16/FC15 | [`mb_stack.c:886-912`](../../stacks/modbus/src/mb_stack.c), [`mb_stack.c:956-986`](../../stacks/modbus/src/mb_stack.c) |

실측 클라이언트 요청 바이트 (가짜 서버로 캡처):

```
mb_stack_client_read(HOLDING, addr=10, qty=2)     → 00 01 00 00 00 06 01 03 00 0A 00 02
mb_stack_client_write_regs(addr=20, {0102,0304})  → 00 01 00 00 00 0B 01 10 00 14 00 02 04 01 02 03 04
mb_stack_client_write_bits(addr=5, {1,0,1})       → 00 01 00 00 00 08 01 0F 00 05 00 03 01 05
```

**실측 — 타임아웃 후 영구 비동기화(desync)**: 서버가 첫 응답만 300ms 늦게(>200ms) 보내고
이후는 즉시 답하게 한 시험에서, 첫 트랜잭션은 `-ETIMEDOUT`, **이후 모든 트랜잭션이
`-EIO`("tid mismatch")** 였고 `connected` 는 계속 1 이라 재연결도 일어나지 않았다.
원인: 타임아웃 뒤 늦게 온 응답이 다음 트랜잭션의 첫 `recv` 에 읽혀 TID 불일치로 실패하고,
그 트랜잭션의 진짜 응답은 또 다음 트랜잭션에 읽히는 식으로 한 칸씩 밀린다
([`mb_stack.c:744-747`](../../stacks/modbus/src/mb_stack.c) 에서 불일치 시 연결을 정리하지 않음).
직접 구현할 때는 규칙 3 을 지킬 것 (부록 D #10).

### 6.8 이 저장소의 타이밍 모델 — "주기적 폴링 서버"

이 저장소 서버는 이벤트 구동이 아니다. **데몬의 사이클 스레드가 `cycle_ms`(기본 8ms)마다
`poll_cycle` → `mb_stack_poll` 을 부를 때만** accept/recv/응답이 일어난다
([`core/fb_api.c:739`](../../core/fb_api.c) `run_cycle_loop` → [`modbus_adapter.c:549`](../../adapters/modbus/modbus_adapter.c)
→ [`mb_stack.c:1015`](../../stacks/modbus/src/mb_stack.c)).

- 따라서 요청 → 응답 지연은 **최대 약 1 사이클(8ms) + 처리 시간**이다.
- 한 poll 안에서는 도착해 있는 요청을 **모두** 처리하므로, 사이클 사이에 쌓인 파이프라인
  요청도 한 번에 답한다.
- PLC 폴링 주기를 `cycle_ms` 보다 짧게 잡아도 응답은 사이클 단위로 묶여 나간다.
- 스택 자체는 스레드를 만들지 않으며, 사이클 루프는 `poll_cycle` 전체를 런타임 mutex 안에서
  실행한다 (앱의 `fb_read_*/fb_write_*` 와 직렬화, [`core/fb_api.c:750-755`](../../core/fb_api.c)).

---

## 7. 에러 처리, 타이밍, 제한값

### 7.1 크기 제한 — 모두 "PDU ≤ 253바이트"에서 나온다

시리얼 RS-485 ADU 최대 256바이트 − 주소 1 − CRC 2 = **PDU 253바이트**. TCP 는 이 PDU 를
그대로 물려받아 **ADU = 7 + 253 = 260바이트**.

| FC | 제한 | 유도 | 사양 값 | 이 저장소 |
|---|---|---|---|---|
| 03/04 읽기 | 레지스터 수 | 응답 1+1+2N ≤ 253 → N ≤ 125 | 1~125 (0x7D) | `qty > 125` ([`mb_stack.c:194`](../../stacks/modbus/src/mb_stack.c)) |
| 01/02 읽기 | 비트 수 | 응답 1+1+⌈N/8⌉ ≤ 253 → N ≤ 2008, 사양은 2000 으로 정함 | 1~2000 (0x7D0) | `qty > 2000` ([`mb_stack.c:168`](../../stacks/modbus/src/mb_stack.c)) |
| 16 쓰기 | 레지스터 수 | 요청 1+2+2+1+2N ≤ 253 → N ≤ 123 | 1~123 (0x7B) | `qty > 123` ([`mb_stack.c:269`](../../stacks/modbus/src/mb_stack.c)) |
| 15 쓰기 | 비트 수 | 요청 1+2+2+1+⌈N/8⌉ ≤ 253 → N ≤ 1976, 사양은 1968 | 1~1968 (0x7B0) | `qty > 1968` ([`mb_stack.c:245`](../../stacks/modbus/src/mb_stack.c)) |
| 23 읽기/쓰기 | 읽기 R, 쓰기 W | 응답 R ≤ 125; 요청 1+2+2+2+2+1+2W ≤ 253 → W ≤ 121 | R 1~125, W 1~121 (0x79) | [`mb_stack.c:313`](../../stacks/modbus/src/mb_stack.c) |
| MBAP Length | | 1 + 253 | 2~254 | [`mb_stack.c:653`](../../stacks/modbus/src/mb_stack.c) |
| ADU | | 7 + 253 | ≤ 260 | `MB_ADU_MAX 260` ([`mb_types.h:13`](../../stacks/modbus/include/mb_types.h)) |

주소 + 수량이 65536 을 넘는 경우(예: addr 0xFFFF qty 2)는 범위 위반(예외 02)이다.
이 저장소는 `uint32_t end = addr + qty` 로 오버플로 없이 검사한다 ([`mb_stack.c:104`](../../stacks/modbus/src/mb_stack.c)).

### 7.2 이 저장소의 기타 제한

| 항목 | 값 | 위치 |
|---|---|---|
| 테이블 크기 | 각 최대 10000 (생략 시 10000) | [`mb_types.h:10-11`](../../stacks/modbus/include/mb_types.h), [`mb_stack.c:404-419`](../../stacks/modbus/src/mb_stack.c) |
| 동시 클라이언트 | 1~8 (기본 4) | [`mb_types.h:17`](../../stacks/modbus/include/mb_types.h) |
| 포인트 수 | 256 | `MAX_POINTS`, [`modbus_adapter.c:17`](../../adapters/modbus/modbus_adapter.c) |
| 포인트 이름 | 63자 | `MAX_NAME` |
| 포인트 값 버퍼 | 512바이트 | `WIRE_CAP` |
| bit_count | 1~32 (넘으면 32 로 clamp) | [`modbus_adapter.c:387-396`](../../adapters/modbus/modbus_adapter.c) |
| 클라이언트 쓰기 수량 | ≤123 | [`modbus_adapter.c:886-890`](../../adapters/modbus/modbus_adapter.c) |

### 7.3 타이밍

Modbus TCP 사양은 **주기나 응답 시간 상한을 정하지 않는다.** 시리얼의 "3.5문자 무음" 같은
타이밍 규칙도 TCP 에는 없다. 모든 타이밍은 클라이언트 설정이다.

| 항목 | 흔한 값 | 이 저장소 |
|---|---|---|
| 폴링 주기 | 10ms~1s | 서버는 `cycle_ms`(기본 8ms)마다 처리 |
| 응답 타임아웃 | 200ms~3s | 클라이언트 `client_timeout_ms` 기본 200 |
| 유휴 연결 정리 | 장치마다 (수십 초~분) | 서버 `idle_timeout_ms` 기본 60000 |
| 재연결 | 백오프 수백 ms~수 s | 클라이언트는 다음 poll 에 즉시 재시도 (백오프 없음) |

CTT 의 주기 시험(`MB-T-CYC-*`)은 **mock 주입 경로**에서 FC03 을 8ms/4ms 간격으로 반복해
late/missed/jitter 를 재는 **내부 지표**이며, Modbus.org 타이밍 주장이 아니다
([`../ctt_mb_bundle.md`](../ctt_mb_bundle.md) §5).

### 7.4 에러 처리 전략 (구현자용)

| 계층 | 에러 | 올바른 대응 |
|---|---|---|
| TCP | 연결 끊김, `recv==0` | 상태 정리, 클라이언트면 재연결 |
| MBAP | Proto ≠ 0 | 그 ADU 버림 (응답 안 함) |
| MBAP | Length 불가능 값 | 스트림 경계를 잃었으므로 **연결 끊기** |
| PDU | 지원 안 하는 FC | 예외 01 |
| PDU | 값·수량·길이 위반 | 예외 03 |
| PDU | 주소 범위 | 예외 02 |
| 응용 | 내부 실패 (하드웨어 등) | 예외 04 |
| 클라이언트 | 타임아웃 | 연결 재수립 또는 TID 불일치 응답 버리기 |
| 클라이언트 | 예외 응답 | 코드별 로그, 02/03 은 설정 오류(재시도 무의미), 06 은 재시도 |

---

## 8. 직접 구현하기

### 8.1 모듈 분해

```
 ┌──────────────┐   ┌──────────────┐   ┌───────────────┐   ┌─────────────┐
 │ net (소켓)    │──▶│ framer        │──▶│ pdu_dispatch  │──▶│ data_model  │
 │ accept/recv  │   │ MBAP 재조립     │   │ FC별 파서/검증  │   │ 4개 테이블   │
 │ send/close   │◀──│ 응답 MBAP 작성  │◀──│ 응답/예외 작성  │◀──│ 콜백/락      │
 └──────────────┘   └──────────────┘   └───────────────┘   └─────────────┘
        ▲                                                          ▲
        │                         ┌────────────────┐               │
        └──── client (선택) ──────│ txn: TID/타임아웃 │               └── 앱
                                  └────────────────┘
```

이 저장소의 대응: net+framer = `server_listen`/`accept_clients`/`serve_client`/`send_all`;
framer 의 단일 ADU 부분 = `mb_stack_handle_adu`; pdu_dispatch = `handle_pdu`; data_model =
`mb_stack_{read,write}_{regs,bits,bytes}`; client = `client_txn`/`client_recv_adu`.
**`handle_adu` 를 소켓과 분리해 둔 것이 좋은 설계**다 — CTT·fuzz·단위 테스트가 소켓 없이
바이트만 넣어 시험할 수 있다.

### 8.2 단계별 로드맵

| 단계 | 만들 것 | 검증 방법 |
|---|---|---|
| M0 | `be16`/`put16` 헬퍼, 4개 테이블 배열 | 단위 테스트: `be16({0x12,0x34})==0x1234` |
| M1 | `handle_pdu`: FC03 만. 예외 01/02/03 | 5.5 절 hex 를 넣어 응답 바이트 비교 |
| M2 | `handle_adu`: MBAP 파싱/검증/응답 MBAP | Proto≠0, Length<2, 짧은 입력 → 거부. 부록 B 전부 |
| M3 | TCP 서버 1 클라이언트, **재조립 루프** | 요청을 1바이트씩 쪼개 보내도 응답 1개. 두 요청을 한 번에 → 응답 2개 |
| M4 | FC01/02/04/05/06 | 사양 예제(부록 B). FC05 값 0x0001 → `85 03` |
| M5 | FC15/16/22/23 | 바이트수 불일치 → 03. FC23 은 쓰기 후 읽기 순서 |
| M6 | 다중 클라이언트(`poll`/`select`/`epoll`), 연결 상한, 유휴 타임아웃, TCP_NODELAY | 클라이언트 N+1 개 접속 → 마지막은 거절. 파이프라인 4개가 1ms 내 |
| M7 | 앱 연동: 스레드 안전한 테이블 접근 | 앱 스레드가 쓰는 동안 FC03 반복 → 찢어진 값(torn read) 없음 |
| M8 | 클라이언트: TID, 타임아웃, 재연결, 묶음 읽기 | 서버 응답 지연 주입 → 타임아웃 후 **정상 복귀** (6.7 desync 재현 금지) |
| M9 | 견고성: fuzz, 상호운용 | libFuzzer + ASan, modpoll/mbpoll/pymodbus 로 교차 확인 |

### 8.3 엔디안 헬퍼

```c
static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* 32비트 값을 두 레지스터로 — 워드 순서는 매개변수로 */
static void u32_to_regs(uint32_t v, uint16_t r[2], int word_swap /* 0=ABCD, 1=CDAB */)
{
    uint16_t hi = (uint16_t)(v >> 16), lo = (uint16_t)v;
    r[0] = word_swap ? lo : hi;
    r[1] = word_swap ? hi : lo;
}
static float regs_to_f32(const uint16_t r[2], int word_swap)
{
    uint32_t u = word_swap ? ((uint32_t)r[1] << 16 | r[0]) : ((uint32_t)r[0] << 16 | r[1]);
    float f; memcpy(&f, &u, sizeof f);   /* 포인터 캐스팅 대신 memcpy (strict aliasing) */
    return f;
}
```

이 저장소의 대응: `rd_be16`/`wr_be16` ([`mb_stack.c:47-56`](../../stacks/modbus/src/mb_stack.c)),
엔디안 변환 `mb_wire_to_canonical` ([`modbus_codec.c:193-224`](../../adapters/modbus/modbus_codec.c)).

### 8.4 파서 작성 요령 — 검증 순서

한 FC 의 파서는 **이 순서**를 지킨다. 순서를 바꾸면 경계 밖 읽기 버그나 틀린 예외 코드가 난다.

1. **PDU 길이 먼저**: 필드를 읽기 전에 `pdu_len` 이 고정부 길이 이상인지 (FC03 = 5, FC16 ≥ 6,
   FC23 ≥ 10). 모자라면 예외 03.
2. **수량 범위** (1~125 등) → 예외 03.
3. **Byte Count 일관성**: `bc == 2*qty` (FC16) / `bc == ceil(qty/8)` (FC15), 그리고
   `pdu_len >= 고정부 + bc` → 예외 03.
4. **주소 범위**: `(uint32_t)addr + qty <= table_size` — 반드시 32비트로 더한다 → 예외 02.
5. **실행** 후 응답 작성. 응답 버퍼 용량 확인.

```c
/* FC16 파서 — 이 저장소 handle_pdu 262~284행과 같은 구조 */
case 0x10: {
    if (pdu_len < 6) return ex(fc, 0x03);                       /* 1 */
    uint16_t addr = be16(pdu + 1), qty = be16(pdu + 3);
    uint8_t  bc   = pdu[5];
    if (qty < 1 || qty > 123) return ex(fc, 0x03);              /* 2 */
    if (bc != qty * 2 || pdu_len < 6u + bc) return ex(fc, 0x03);/* 3 */
    if ((uint32_t)addr + qty > N_HOLDING) return ex(fc, 0x02);  /* 4 */
    for (unsigned i = 0; i < qty; i++)                          /* 5 */
        holding[addr + i] = be16(pdu + 6 + 2 * i);
    out[0] = 0x10; put16(out + 1, addr); put16(out + 3, qty);
    return 5;
}
```

**흔한 파서 버그**

| 버그 | 결과 | 예방 |
|---|---|---|
| `addr + qty` 를 16비트로 계산 | 0xFFFF+2 = 1 로 wrap → 범위 검사 통과 → 버퍼 오버런 | 32비트로 더하기 |
| `bc` 를 믿고 `pdu_len` 확인 안 함 | 선언보다 짧은 패킷에서 경계 밖 읽기 | 3단계 |
| 응답 버퍼 크기 가정 | FC03 qty 125 → 259바이트 | 260 바이트 버퍼 |
| `uint16_t` 를 `memcpy` 로 직렬화 | x86 에서 바이트 뒤집힘 | 헬퍼만 사용 |
| 수량 0 허용 | Byte Count 0 응답 (사양 위반) | `qty >= 1` |

### 8.5 최소 서버 — 완전한 예제 (약 100줄)

아래는 **FC03/FC06 만** 지원하는 교육용 서버다. 재조립·파이프라이닝·다중 클라이언트·
TCP_NODELAY 를 모두 갖췄다. 이 문서 작성 때 이 코드 블록을 그대로 추출해 컴파일(`gcc -std=c11 -Wall -Wextra`, 경고 0)하고,
조각난 요청·파이프라인 4개·예외를 넣어 동작을 확인했다 (파이프라인 4개 응답 0.1ms).

```c
/* mini_server.c — 교육용 최소 Modbus TCP 서버 (FC03/FC06, 단일 스레드, poll 기반) */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NREG 100
#define MAXC 4
static uint16_t holding[NREG];

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }

/* PDU 하나 처리 → 응답 PDU 길이 반환 (out 에 기록) */
static size_t handle_pdu(const uint8_t *pdu, size_t n, uint8_t *out)
{
    uint8_t fc = pdu[0];
    if (fc == 0x03) {
        if (n != 5) goto bad_value;                 /* 길이부터 */
        uint16_t addr = be16(pdu + 1), qty = be16(pdu + 3);
        if (qty < 1 || qty > 125) goto bad_value;   /* 수량 → 예외 03 */
        if ((uint32_t)addr + qty > NREG) goto bad_addr; /* 범위 → 예외 02 */
        out[0] = 0x03;
        out[1] = (uint8_t)(qty * 2);
        for (int i = 0; i < qty; i++) put16(out + 2 + 2 * i, holding[addr + i]);
        return 2 + 2u * qty;
    }
    if (fc == 0x06) {
        if (n != 5) goto bad_value;
        uint16_t addr = be16(pdu + 1);
        if (addr >= NREG) goto bad_addr;
        holding[addr] = be16(pdu + 3);
        memcpy(out, pdu, 5);                        /* 요청 에코 */
        return 5;
    }
    out[0] = fc | 0x80; out[1] = 0x01; return 2;    /* ILLEGAL FUNCTION */
bad_value: out[0] = fc | 0x80; out[1] = 0x03; return 2;
bad_addr:  out[0] = fc | 0x80; out[1] = 0x02; return 2;
}

struct conn { int fd; uint8_t buf[520]; size_t len; };

/* 받은 바이트 뒤에 붙이고, 완성된 ADU 를 전부 처리. 실패 시 -1 → 연결 종료 */
static int on_readable(struct conn *c)
{
    ssize_t r = recv(c->fd, c->buf + c->len, sizeof(c->buf) - c->len, 0);
    if (r <= 0) return -1;
    c->len += (size_t)r;
    while (c->len >= 7) {                           /* MBAP 가 다 왔나 */
        uint16_t len = be16(c->buf + 4);
        if (be16(c->buf + 2) != 0 || len < 2 || len > 254) return -1;
        size_t need = 6u + len;                     /* 전체 ADU 크기 */
        if (c->len < need) break;                   /* 조각: 더 기다림 */
        uint8_t resp[260];
        size_t pl = handle_pdu(c->buf + 7, len - 1u, resp + 7);
        memcpy(resp, c->buf, 4);                    /* TID, Protocol ID 복사 */
        put16(resp + 4, (uint16_t)(pl + 1));
        resp[6] = c->buf[6];                        /* Unit ID 에코 */
        if (send(c->fd, resp, 7 + pl, MSG_NOSIGNAL) != (ssize_t)(7 + pl)) return -1;
        memmove(c->buf, c->buf + need, c->len - need);
        c->len -= need;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 1502;
    for (int i = 0; i < NREG; i++) holding[i] = (uint16_t)(0x1000 + i);
    int ls = socket(AF_INET, SOCK_STREAM, 0), on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 8)) { perror("bind"); return 1; }
    struct conn cs[MAXC];
    for (int i = 0; i < MAXC; i++) cs[i].fd = -1;
    for (;;) {
        struct pollfd p[MAXC + 1];
        p[0] = (struct pollfd){.fd = ls, .events = POLLIN};
        for (int i = 0; i < MAXC; i++) p[i + 1] = (struct pollfd){.fd = cs[i].fd, .events = POLLIN};
        if (poll(p, MAXC + 1, 1000) < 0) break;
        if (p[0].revents & POLLIN) {
            int fd = accept(ls, NULL, NULL), slot = -1;
            for (int i = 0; i < MAXC; i++) if (cs[i].fd < 0) { slot = i; break; }
            if (slot < 0) close(fd);
            else {
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
                cs[slot].fd = fd; cs[slot].len = 0;
            }
        }
        for (int i = 0; i < MAXC; i++)
            if (cs[i].fd >= 0 && (p[i + 1].revents & (POLLIN | POLLHUP | POLLERR)))
                if (on_readable(&cs[i]) < 0) { close(cs[i].fd); cs[i].fd = -1; }
    }
    return 0;
}
```

(`poll` 에 fd `-1` 을 넣으면 그 항목은 무시된다 — POSIX 규칙이라 빈 슬롯을 그대로 넘겨도 된다.)
이 예제는 교육용이다: 블로킹 `send` 가 느린 클라이언트에 막힐 수 있고, 유휴 타임아웃·IP 당
상한·Unit ID 필터가 없다. 제품이라면 이 저장소 `serve_client`/`accept_clients` 의 정책을
참고해 채운다.

### 8.6 버퍼와 동시성

- **연결마다 수신 버퍼 하나** (≥ 260, 파이프라이닝을 받으려면 2×260 이상). 전역 버퍼를 공유하면
  두 클라이언트의 조각이 섞인다.
- **이벤트 루프 선택**: 연결 몇 개면 `poll`/`select`, 수백 개면 `epoll`. 이 저장소는 외부
  사이클이 non-blocking `recv` 를 훑는 방식(최대 8연결이라 충분).
- **데이터 테이블 락**: 네트워크 스레드와 앱 스레드가 다르면 테이블 접근을 락으로 감싼다.
  특히 **32비트 값(레지스터 2칸)은 두 칸을 한 락 안에서** 써야 한다. 그렇지 않으면 PLC 가
  "새 상위 워드 + 옛 하위 워드" 를 읽는 **찢어진 읽기(torn read)** 가 생긴다.
  이 저장소는 사이클 스레드와 앱 호출을 `fb_api` 의 mutex 하나로 직렬화하므로 한
  `write_point` 안의 여러 레지스터는 원자적으로 보인다 ([`core/fb_api.c:1059`](../../core/fb_api.c) 근처 `fb_write_point` 의 lock).
- **쓰기 콜백**: 제품 스택은 "PLC 가 레지스터 X 를 썼다" 이벤트를 앱에 알려 주는 콜백을 두는
  경우가 많다. 이 저장소는 콜백 없이 앱이 `read_point` 로 폴링한다 (9.7 절).

### 8.7 클라이언트 구현

```
client_txn(fc, pdu):
    if not connected: connect_with_timeout() or fail
    tid = next_tid()                        # 연결 단위 카운터 하나, 0 건너뛰기는 선택
    send_all(MBAP(tid, 0, 1+len(pdu), unit) + pdu)
    deadline = now + timeout
    loop:
        hdr = recv_exact(7, deadline)       # 타임아웃이면 → close(); return TIMEOUT
        if proto != 0 or L < 2 or L > 254:  close(); return PROTO_ERR
        body = recv_exact(L-1, deadline)
        if rtid != tid:  continue           # 늦게 온 옛 응답 → 버리고 계속 읽기
        break
    if body[0] == fc|0x80: return EXCEPTION(body[1])
    if body[0] != fc: close(); return PROTO_ERR
    validate body length per FC (예: FC03 → body[1] == 2*qty, len == 2+body[1])
    return OK(body)
```

핵심 차이점 (이 저장소 `client_recv_adu` 대비):

1. **타임아웃 시 연결을 닫는다** (또는 TID 불일치 응답을 버리고 계속 읽는다). 이 저장소는 둘 다
   하지 않아 6.7 절의 영구 desync 가 생긴다.
2. `recv_exact` 는 **정확히 필요한 바이트만** 읽는다. 이 저장소는 첫 `recv` 에서 버퍼 용량만큼
   읽어 다음 응답의 앞부분을 삼킬 수 있다 ([`mb_stack.c:710`](../../stacks/modbus/src/mb_stack.c)).
3. **비블로킹 connect + 타임아웃** (또는 `SO_SNDTIMEO`).
4. **묶음 읽기**: 포인트들을 테이블·주소로 정렬해 125칸 이내 연속 구간끼리 FC03 한 번으로.

Python 으로 된 의존성 없는 최소 클라이언트 (이 저장소 `mb_seeded_server` 에 대고 실행해
`FC03: 03 06 a0 00 a0 01 a0 02`, float `1.5`, `FC01: 01 01 aa`, OOB `83 02` 를 확인):

```python
import socket, struct

def txn(sock, tid, unit, pdu):
    adu = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu
    sock.sendall(adu)
    hdr = b""
    while len(hdr) < 7:                      # MBAP 7바이트를 먼저 모은다
        chunk = sock.recv(7 - len(hdr))
        if not chunk:
            raise ConnectionError("closed")
        hdr += chunk
    rtid, proto, length, runit = struct.unpack(">HHHB", hdr)
    body = b""
    while len(body) < length - 1:            # Length-1 = PDU 길이
        chunk = sock.recv(length - 1 - len(body))
        if not chunk:
            raise ConnectionError("closed")
        body += chunk
    assert rtid == tid and proto == 0, (rtid, proto)
    return body

s = socket.create_connection(("127.0.0.1", 1602), timeout=2)
pdu = txn(s, 1, 1, struct.pack(">BHH", 0x03, 0, 3))          # FC03 addr 0 qty 3
print("FC03:", pdu.hex(" "))
pdu = txn(s, 2, 1, struct.pack(">BHH", 0x03, 300, 2))        # float 1.5 ABCD
print("float:", struct.unpack(">f", pdu[2:6])[0])
```

(`./build/mb_seeded_server --port 1602` 를 먼저 띄운다. 이 서버는 holding i = `0xA000+i`,
holding 300/301 = float 1.5 ABCD 로 시드돼 있다 — [`../../tests/mb_seeded_server.c`](../../tests/mb_seeded_server.c).)

### 8.8 설계 선택지 요약

| 선택 | 옵션 | 이 저장소 |
|---|---|---|
| 데이터 저장 | 테이블 배열 / 콜백으로 앱에 위임 | 배열 (로컬 맵) |
| 테이블 겹침 | 분리 / 같은 메모리 공유 | 분리 |
| 미구현 주소 | 예외 02 / 0 반환 | 예외 02 (맵 크기로 결정) |
| 잘못된 Unit | 무시 / 예외 / 모두 수락 | 무시 (`unit_id_any` 로 모두 수락) |
| 스레딩 | 전용 스레드 / 외부 폴링 | 외부 폴링 (`mb_stack_poll`) |
| 동시 처리 | 연결별 순차 | 순차 |

---

## 9. 이 저장소의 구현 지도

### 9.1 파일

| 파일 | 줄 수 | 역할 |
|---|---|---|
| [`stacks/modbus/include/mb_types.h`](../../stacks/modbus/include/mb_types.h) | 51 | 상수(포트, 크기, FC, 예외), 역할/테이블 enum |
| [`stacks/modbus/include/mb_stack.h`](../../stacks/modbus/include/mb_stack.h) | 67 | 공개 API, `mb_cfg_t` |
| [`stacks/modbus/src/mb_stack.c`](../../stacks/modbus/src/mb_stack.c) | 1178 | 소켓, 재조립, PDU 처리, 로컬 맵, 클라이언트 |
| [`adapters/modbus/modbus_adapter.c`](../../adapters/modbus/modbus_adapter.c) | 950 | config 파싱, 주소 정규화, read/write_point |
| [`adapters/modbus/modbus_codec.c`](../../adapters/modbus/modbus_codec.c) | 508 | 엔디안, 숫자 인코딩, BCD, 문자열, 비트필드 |
| [`adapters/modbus/modbus_adapter.h`](../../adapters/modbus/modbus_adapter.h) | 28 | 유일한 공개 함수 `modbus_adapter_create()` |
| [`tools/ctt/proto/modbus/mb_plugin.c`](../../tools/ctt/proto/modbus/mb_plugin.c) | 760 | CTT 플러그인 (클라이언트 흉내 + 주입) |
| [`tests/test_mb_stack.c`](../../tests/test_mb_stack.c) | 303 | 스택 단위 테스트 |
| [`tests/test_mb_adapter.c`](../../tests/test_mb_adapter.c) | 123 | 어댑터 단위 테스트 |
| [`tests/fuzz/fuzz_mb_adu.c`](../../tests/fuzz/fuzz_mb_adu.c) | 383 | libFuzzer 하네스 |
| [`tests/mb_seeded_server.c`](../../tests/mb_seeded_server.c) | 90 | 시드된 시험용 서버 |
| [`tests/mb_reliability_harness.py`](../../tests/mb_reliability_harness.py) | 453 | 장시간 신뢰성 하네스 |

스택은 cJSON 도 어댑터도 모른다 — `BUILD_DAEMON=OFF` 로 스택 + CTT 만 빌드된다
([`../../CMakeLists.txt`](../../CMakeLists.txt) 64~67행 `mb_stack` 라이브러리).

### 9.2 개념 ↔ 함수 표

| 개념 (절) | 함수 | 위치 |
|---|---|---|
| 빅 엔디안 헬퍼 (0.4) | `rd_be16`, `wr_be16` | `mb_stack.c:47`, `:52` |
| 네 테이블 (4.1) | `struct mb_stack` 의 `holding/input/coils/discrete` | `mb_stack.c:28-45` |
| 비트 포장 (4.3) | `get_bit`, `set_bit`, `bit_bytes` | `mb_stack.c:78-96` |
| 주소 범위 검사 (6.1) | `map_ok_regs`, `map_ok_bits` | `mb_stack.c:98`, `:114` |
| 예외 응답 (5.13) | `build_exception` | `mb_stack.c:130` |
| Unit 필터 (6.5) | `handle_pdu` 앞부분 | `mb_stack.c:149-152` |
| FC 분기 (5.4~5.11) | `handle_pdu` | `mb_stack.c:142-346` |
| MBAP 검증 (5.1, 6.6) | `mb_stack_handle_adu` | `mb_stack.c:348-370` |
| 생성·기본값 | `mb_stack_create` | `mb_stack.c:372-438` |
| listen (6.2) | `server_listen` | `mb_stack.c:453` |
| accept·상한 (6.2) | `accept_clients`, `mb_count_ip` | `mb_stack.c:580`, `:591` |
| 재조립·파이프라이닝 (6.3, 6.4) | `serve_client` | `mb_stack.c:628-674` |
| 송신 | `send_all` | `mb_stack.c:676` |
| 주기 진입점·유휴 타임아웃 (6.8) | `mb_stack_poll` | `mb_stack.c:1015-1052` |
| 클라이언트 연결 (6.7) | `client_connect` | `mb_stack.c:500` |
| 클라이언트 수신·TID (6.7) | `client_recv_adu` | `mb_stack.c:695-750` |
| 클라이언트 읽기 | `client_txn`, `mb_stack_client_read` | `mb_stack.c:753`, `:841` |
| 클라이언트 쓰기 | `mb_stack_client_write_regs`, `_write_bits` | `mb_stack.c:869`, `:939` |
| 앱 ↔ 맵 | `mb_stack_{read,write}_{regs,bits}` | `mb_stack.c:1064-1127` |
| 문자열 바이트 ↔ 레지스터 | `mb_stack_{read,write}_bytes` (상위 바이트 먼저) | `mb_stack.c:1129`, `:1154` |
| 테이블 이름 별칭 | `parse_reg_type` | `modbus_adapter.c:64` |
| 40001 정규화 (4.2) | `normalize_start`, `address_mode_zero` | `modbus_adapter.c:160`, `:203` |
| 수량 추론 | `infer_quantity` | `modbus_adapter.c:219` |
| 포인트 파싱 | `parse_points` | `modbus_adapter.c:273-430` |
| protocol_params 파싱 | `mb_init` | `modbus_adapter.c:432-526` |
| 워드 순서 (4.5) | `mb_parse_endian`, `mb_wire_to_canonical` | `modbus_codec.c:22`, `:193` |
| 숫자/BCD | `mb_decode_number`, `mb_encode_number` | `modbus_codec.c:289`, `:337` |
| 문자열 (4.6) | `mb_pack_string`, `mb_unpack_string` | `modbus_codec.c:417`, `:442` |
| 비트필드 | `mb_extract_bits`, `mb_insert_bits` | `modbus_codec.c:478`, `:493` |
| 어댑터 vtable | `modbus_adapter_create` | `modbus_adapter.c:934-950` |
| 코어 등록 | `{"modbus_tcp", modbus_adapter_create}` | [`core/adapter_registry.c:26`](../../core/adapter_registry.c) |

### 9.3 `mb_cfg_t` — 스택 설정

[`mb_stack.h:16-31`](../../stacks/modbus/include/mb_stack.h)

| 필드 | 의미 | 기본 (0/빈 값일 때) |
|---|---|---|
| `role` | `MB_ROLE_SERVER` / `MB_ROLE_CLIENT` | server |
| `bind_ip` | 서버 listen 주소 | 0.0.0.0 |
| `remote_ip` | 클라이언트 접속 대상 | (필수) |
| `port` | TCP 포트 | 502 |
| `unit_id` | 내 Unit ID / 클라이언트가 보낼 Unit ID | 1 |
| `unit_id_any` | 1 이면 모든 Unit 수락 | 0 |
| `client_timeout_ms` | 클라이언트 응답 대기 | 200 |
| `max_clients` | 서버 동시 연결 (1..8) | 4 |
| `idle_timeout_ms` | 유휴 연결 정리 | 60000 |
| `max_conn_per_ip` | IP 당 연결 | 4 |
| `n_holding` … `n_discrete` | 테이블 크기 (≤10000) | 10000 |

### 9.4 어댑터가 config points 를 스택에 연결하는 방법

**흐름**

```
config.json
  protocol_params ─▶ mb_init ─▶ mb_cfg_t ─▶ mb_stack_create
  points[] ───────▶ parse_points ─▶ modbus_point_t[]
                       (reg_type, start, quantity, data_type, endian,
                        bit, bit_count, byte_offset, scale, eng_offset …)

앱 fb_write_f32("temperature", 25.5)
  └▶ core: encode_numeric → 4바이트 BE float
     └▶ mb_write_point
          ├ apply_scale: raw = (25.5 - offset) / 0.1 = 255
          ├ mb_encode_number(UINT16) → 00 FF
          ├ wire_from_app: 엔디안 적용
          └ write_map_window → mb_stack_write_bytes(HOLDING, 16, …) → holding[16]=0x00FF

PLC FC03 addr 16 → handle_pdu 가 holding[16] 을 그대로 응답
```

**access 의미** — PLC 관점 ([`../modbus_stack.md`](../modbus_stack.md) §4):

| `access` | PLC 가 | 앱이 |
|---|---|---|
| `read` | 읽는다 | `write_point` 로 맵에 게시 |
| `write` | 쓴다 | `read_point` 로 맵에서 조회 |
| `readwrite` | 둘 다 | 둘 다 |

주의: `access` 는 **앱 API 쪽 권한**(코어 `app_may_write`)일 뿐, 스택은 모른다. PLC 는
`access: "read"` 포인트의 레지스터에도 FC06/16 으로 **쓸 수 있다** (실측: FC06 addr 16 =
0x1234 → 앱이 읽은 temperature = 466). 다음 `write_point` 가 덮어쓸 때까지 그 값이 남는다.

**주소 정규화 실측표** (`normalize_start`, [`modbus_adapter.c:160-201`](../../adapters/modbus/modbus_adapter.c)):

| 테이블 | config `start` | 해석된 값 | PDU 주소 | 비고 |
|---|---|---|---|---|
| holding | `40001` | 40001 | 0 | 5자리 Modicon |
| holding | `40017` | 40017 | 16 | |
| holding | `"40001"` (문자열) | 40001 | 0 | 문자열도 허용 |
| holding | `100` | 100 | **100** | 4000 미만은 0-based 로 간주 |
| holding | `4001` | 4001 | **1** | 4000~4999 는 `-4000` (부록 D #13) |
| holding | `"0x10"` | 16 | 16 | 16진 문자열 |
| input | `30001` | 30001 | 0 | |
| input | `3001` | 3001 | 1 | 3000~3999 는 `-3000` |
| discrete | `10001` | 10001 | 0 | |
| coil | `1` | 1 | **0** | 코일만 1..9999 를 1-based 로 간주 |
| coil | `5` | 5 | 4 | |
| coil | `"00010"` | **8** | **7** | `strtol(…, 0)` 이 앞의 0 을 **8진수**로 해석 (부록 D #12) |
| coil | `"00009"` | **0** | 0 | 8진수에 9 가 없어 "0" 까지만 파싱 |
| holding | `"040001"` | **16385** | 16385 | 8진수 |

`zero_based: true` 또는 `address_base: "zero"|"pdu"|"0"` 이면 정규화 없이 그대로 PDU 주소로
쓴다 ([`modbus_adapter.c:203-217`](../../adapters/modbus/modbus_adapter.c)). 최종 주소 =
정규화 값 + `address.modbus.offset` (65535 초과 시 포인트 건너뜀,
[`modbus_adapter.c:364-379`](../../adapters/modbus/modbus_adapter.c)).

**수량 추론** (`infer_quantity`, [`modbus_adapter.c:219-263`](../../adapters/modbus/modbus_adapter.c)):
`quantity` 가 없으면 데이터형으로 — uint16/int16/bool/bcd16 = 1, 32비트형 = 2, 64비트형 = 4,
문자열 = ⌈length / chars_per_register⌉, 비트필드 = ⌈(bit + bit_count)/16⌉.

**이름 충돌 주의**: 포인트 최상위 `offset` 은 **엔지니어링 오프셋**(`eng = raw*scale + offset`,
[`modbus_adapter.c:316`](../../adapters/modbus/modbus_adapter.c)), `address.modbus.offset` 은
**레지스터 오프셋**([`modbus_adapter.c:369-370`](../../adapters/modbus/modbus_adapter.c))이다.
같은 이름이 두 층에서 다른 뜻이다.

### 9.5 config 예시 해설 — `config/example.modbus.json`

[`../../config/example.modbus.json`](../../config/example.modbus.json)

```json
"protocol_params": { "role": "server", "ip": "0.0.0.0", "port": 1502,
                     "unit_id": 1, "unit_id_any": false, "max_clients": 4,
                     "client_timeout_ms": 200 }
```

→ 0.0.0.0:1502 에서 대기하는 서버, Unit 1 만 응답, 최대 4 클라이언트. 테이블 크기는 생략했으므로
각 10000.

어댑터가 해석한 포인트 (실측, `parse_points` 결과):

| 포인트 | 테이블 | PDU 시작 | 수량 | 데이터형/엔디안 | PLC 가 보는 모습 |
|---|---|---|---|---|---|
| `barcode_value` | holding | 0 | 16 | string 32, 2문자/칸 | FC03 0~15 → ASCII |
| `temperature` | holding | 16 | 1 | uint16 ×0.1 | FC03 16 → 25.5℃ 면 `00 FF` |
| `pressure` | input | 0 | 2 | float CDAB | FC04 0~1 → 1.5 면 `0000 3FC0` |
| `trigger` | coil | 0 | 1 | bool | PLC 가 FC05 0 으로 켬 |
| `alarm_bit` | holding | 99 | 1 | bool, bit 3 | 워드 99 의 bit 3 (`0x0008`) |
| `status_nibble` | holding | 100 | 1 | uint16, bit 0~3 | 워드 100 의 하위 니블 — **부록 D #14 버그 영향** |

실측 트랜잭션 (앱이 temperature=25.5, pressure=1.5, barcode="ABC123" 게시 후):

```
PLC 가 온도 읽기   REQ : 00 01 00 00 00 06 01 03 00 10 00 01
                  RESP: 00 01 00 00 00 05 01 03 02 00 FF              → 255 × 0.1 = 25.5
PLC 가 압력 읽기   REQ : 00 02 00 00 00 06 01 04 00 00 00 02
                  RESP: 00 02 00 00 00 07 01 04 04 00 00 3F C0        → CDAB: 3FC0 0000 = 1.5
PLC 가 바코드 읽기 REQ : 00 03 00 00 00 06 01 03 00 00 00 04
                  RESP: 00 03 00 00 00 0B 01 03 08 41 42 43 31 32 33 00 00  → "ABC123"
PLC 가 트리거 ON   REQ : 00 04 00 00 00 06 01 05 00 00 FF 00
                  RESP: 00 04 00 00 00 06 01 05 00 00 FF 00        → 앱 read_point(trigger)=1
PLC 가 경보 워드   REQ : 00 05 00 00 00 06 01 06 00 63 00 08
                  RESP: 00 05 00 00 00 06 01 06 00 63 00 08        → 앱 read_point(alarm_bit)=1
```

PLC 쪽 설정으로 옮기면: "Holding 40017 (UINT, ×0.1)", "Input 30001 (REAL, word swap)",
"Coil 00001", "Holding 40100.3". 이 저장소 가이드는 [`../modbus_stack.md`](../modbus_stack.md) §8~9.

### 9.6 코어가 어댑터를 구동하는 방법

1. `multiproto_daemon config.json` → `fb_open` → `config_load` 가 `protocol`, `cycle_ms` 만 해석하고
   `protocol_params`/`points` 는 문자열로 보관.
2. `adapter_registry_lookup("modbus_tcp")` → `modbus_adapter_create` ([`core/adapter_registry.c:26`](../../core/adapter_registry.c)).
3. `init(params_json, points_json)` ([`core/fb_api.c:412`](../../core/fb_api.c)) → `mb_init` →
   `parse_points` + `mb_stack_create`.
4. `connect()` ([`core/fb_api.c:433`](../../core/fb_api.c)) → `mb_connect` → `mb_stack_start` → listen.
5. `fb_run` → `run_cycle_loop` ([`core/fb_api.c:739`](../../core/fb_api.c)): 절대시간
   `clock_nanosleep` 으로 `cycle_ms` 마다 mutex 안에서 `poll_cycle`.
6. 앱의 `fb_read_*/fb_write_*` 는 같은 mutex 아래에서 `read_point/write_point`.

코어에는 `if (protocol == modbus)` 같은 분기가 없다 — [`../../CLAUDE.md`](../../CLAUDE.md) 의
"core 는 프로토콜을 몰라야 한다" 원칙. (`core/scheduler.c` 의 `scheduler_run` 은 같은 모양의
루프지만 데몬 경로에서는 `fb_api.c` 의 루프가 쓰인다 — [`README.md`](README.md) §4.6.)

### 9.7 이 저장소가 의도적으로 하지 않는 것 / 단순화한 것

| 항목 | 상태 | 근거 |
|---|---|---|
| Modbus RTU/ASCII (시리얼), UDP | 영구 비목표 | [`../ctt_mb_bundle.md`](../ctt_mb_bundle.md) §4 |
| FC07/08/11/12/17 (시리얼 진단), FC20/21/24, FC43 | 미구현 → 예외 01 | `handle_pdu` default |
| Modbus/TCP Security (TLS, 802) | 없음 | [`../modbus_stack.md`](../modbus_stack.md) §3 |
| 게이트웨이 기능 (Unit → 시리얼 라우팅) | 없음. Unit 은 필터로만 | `mb_stack.c:149` |
| 예외 04/05/06 | 내지 않음 | — |
| 쓰기 이벤트 콜백 | 없음. 앱이 폴링 | `mb_stack.h` API |
| 서버 이벤트 구동 | 없음. `cycle_ms` 폴링 | 6.8 절 |
| 클라이언트 묶음 읽기 | 없음. 포인트당 1 요청 | `mb_poll_cycle` |
| 포인트별 쓰기 보호 | 없음. 맵 크기 안이면 PLC 가 다 쓸 수 있음 | 9.4 절 |
| 공식 인증 | 아님 | 12장 |

### 9.8 관찰된 사양 불일치·결함

[부록 D](#부록-d-사양-vs-저장소-차이-요약)에 모아 두었다. 이 문서는 **기록만** 하고 코드는
고치지 않았다 (어댑터/스택 수정은 [`../../CLAUDE.md`](../../CLAUDE.md) 작업 경계에 따라 별도 작업).

---

## 10. 테스트와 디버깅

### 10.1 빌드와 단위 테스트

```bash
# 스택 + CTT 만 (cJSON 불필요)
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON
cmake --build build -j
ctest --test-dir build -L modbus --output-on-failure -LE soak_ci   # CTT Modbus 14개
ctest --test-dir build -R test_mb_stack --output-on-failure          # 스택 단위 테스트

# 어댑터 테스트·데몬·시드 서버까지 (cJSON 은 pkg-config 또는 FetchContent)
cmake -S . -B build -DBUILD_DAEMON=ON
cmake --build build -j
./build/test_mb_adapter
./build/mb_seeded_server --port 1602 --seconds 60
```

`test_mb_stack` ([`../../tests/test_mb_stack.c`](../../tests/test_mb_stack.c)) 이 보는 것: FC03 응답
길이·값, FC05, 문자열 바이트 포장, 예외 02, FC22 마스크 결과, 실제 소켓으로 유휴 타임아웃과
IP 당 상한. `test_mb_adapter` 는 40001+offset, scale, CDAB float, 1문자/칸 문자열, 비트필드 bool.

### 10.2 CTT 시나리오

CTT 는 **클라이언트 흉내 플러그인**이 MBAP+PDU 를 조립해 `mb_stack_handle_adu` 에 직접
주입한다 (소켓·NIC 없음, [`../../tools/ctt/proto/modbus/README.md`](../../tools/ctt/proto/modbus/README.md)).

| TC ID | YAML (`tests/scenarios/modbus/`) | 무엇을 보나 |
|---|---|---|
| MB-T-FC-001 | `fc03_read_holding.yaml` | FC03 길이 13, bc 4, 값 |
| MB-T-FC-002 | `fc05_write_single_coil.yaml` | FC05 → 맵 비트 |
| MB-T-FC-003 | `fc22_mask_write.yaml` | `0xFFFF` & F0F0 \| 000F → `0xF0FF` |
| MB-T-FC-004 | `fc_server_matrix.yaml` | FC01~06, 0F, 10, 16, 17, 125개, FC08→01, Unit 9 무응답 |
| MB-T-FC-005 | `string_bytes.yaml` | "ABC123" ↔ `4142 4331 3233` |
| MB-T-CM-001/002 | `holding_lifetime.yaml`, `coil_lifetime.yaml` | 쓰기→읽기→잘못된 Unit→덮어쓰기 |
| MB-T-CYC-001/002/003 | `soak_short`, `fc03_cyclic_metrics`, `fc03_cycle_4ms` | 8ms/4ms 주기 late/missed/jitter |
| MB-T-NEG-001 | `exception_illegal_address.yaml` | OOB, qty=0(→02), FC 0x2B→01 |
| MB-T-NEG-002 | `adu_malformed.yaml` | 짧은/잘못된 MBAP → `handle_ok: false` |
| MB-T-NEG-003 | `exception_illegal_value.yaml` | FC05 값 0x0001, PDU FC 뿐 → 03 |

YAML 해부 (`fc03_read_holding.yaml`):

```yaml
device: { role: server, unit_id: 1, n_holding: 64, … , iface: mock }   # mb_setup 이 스택 생성
steps:
  - action: seed        # 맵에 직접 값 넣기 (mb_stack_write_regs)
    type: holding
    address: 0
    values: [0x1234, 0xABCD]
  - action: request     # 플러그인이 ADU 조립 → handle_adu → 응답 검사
    fc: 0x03
    tid: 0x0001
    address: 0
    quantity: 2
    expect: { fc: 0x03, length: 13, byte_count: 4, values: [0x1234, 0xABCD] }
  - action: map_check   # 맵 직접 확인
    type: holding
    address: 0
    values: [0x1234, 0xABCD]
```

액션은 `seed`, `request`, `map_check`, `adu_inject`(원시 hex), `soak` 다섯 개
([`mb_plugin.c`](../../tools/ctt/proto/modbus/mb_plugin.c) `mb_step`). 새 시나리오는 이 디렉터리에
YAML 을 추가하면 CMake GLOB 가 `ctt_mb_<이름>` 테스트로 등록한다
([`../../CMakeLists.txt`](../../CMakeLists.txt) 427~434행). 리포트는
`./build/ctt --scenario … --report out.json` (`ctt-report/v1`).

`MB-T-NEG-001` 이 "qty=0 → 예외 02" 를 기대값으로 **고정**하고 있다는 점에 주의. 부록 D #1 을
사양에 맞게 고치면 이 YAML 도 같이 바꿔야 한다.

### 10.3 Fuzz

[`../../tests/fuzz/fuzz_mb_adu.c`](../../tests/fuzz/fuzz_mb_adu.c) 는 첫 바이트로 8가지 모드를
고른다: 원시 스트림, 구현 FC 로 감싼 PDU, FC22/23 집중, 불법 FC(0x08/0x2B …), 예외 유발(qty 0,
2001, OOB, 코일 값, 바이트수 불일치), Unit/Proto 변형, 쓰기-읽기 쌍, 여러 ADU 묶음.

```bash
CC=clang cmake -S . -B build-fuzz -DBUILD_FUZZERS=ON -DBUILD_DAEMON=OFF -DBUILD_CTT=OFF
cmake --build build-fuzz --target fuzz_mb_adu
cp -r tests/fuzz/corpus/mb_adu /tmp/mb_corpus          # libFuzzer 는 코퍼스 디렉터리에 새 파일을 쓴다
./build-fuzz/fuzz_mb_adu -dict=tests/fuzz/dict/mb_adu.dict -max_total_time=600 /tmp/mb_corpus
```

코퍼스 384개, 사전은 [`../../tests/fuzz/dict/mb_adu.dict`](../../tests/fuzz/dict/mb_adu.dict).
(이 문서 작성 환경에는 clang 의 libFuzzer 런타임이 없어 위 빌드가 링크 단계에서 실패했다.
대신 같은 하네스를 gcc `-fsanitize=address,undefined` 로 빌드해 코퍼스 384개 + 무작위 입력
200,000개를 재생했고 새니타이저 보고는 없었다 — 부록 C.)

### 10.4 Wireshark 로 보기

- Wireshark 는 TCP 502 를 자동으로 **Modbus/TCP**(`mbtcp`) + **Modbus**(`modbus`) 로 해석한다.
- 예제처럼 **1502** 를 쓰면: 패킷 우클릭 → *Decode As…* → TCP port 1502 → *Modbus/TCP*.
  (버전에 따라 Protocol Preferences 의 Modbus/TCP 포트 설정으로도 가능.)
- 유용한 표시 필터 (필드 이름은 Wireshark 버전에 따라 조금 다를 수 있다):

| 목적 | 필터 |
|---|---|
| Modbus 만 | `mbtcp` 또는 `modbus` |
| 특정 FC | `modbus.func_code == 3` |
| 예외 응답만 | `modbus.func_code >= 128` 또는 `modbus.exception_code` |
| 특정 트랜잭션 | `mbtcp.trans_id == 5` |
| 특정 Unit | `mbtcp.unit_id == 255` |
| 재전송/지연 확인 | `tcp.analysis.flags`, `tcp.time_delta > 0.05` |

- 루프백 캡처: `sudo tcpdump -i lo -w mb.pcap port 1502` 후 Wireshark 로 열기.
  빠르게 hex 만 보려면 `sudo tcpdump -i lo -X port 1502`.
- 읽는 요령: 요청/응답 짝을 `mbtcp.trans_id` 로 맞추고, 응답이 없는 요청이 있으면 6.5 절(Unit
  ID) → 6.6 절(MBAP) 순서로 의심한다. 파이프라인 응답이 수십 ms 늦으면 6.3 절(Nagle).

### 10.5 상용/오픈 도구로 상호운용 확인

| 도구 | 종류 | 예 (옵션은 도구 버전의 `--help` 로 확인) |
|---|---|---|
| **modpoll** | CLI 클라이언트 (proconX) | `modpoll -m tcp -p 1502 -a 1 -r 1 -c 2 -t 4 -1 127.0.0.1` |
| **mbpoll** | CLI 클라이언트 (오픈소스) | `mbpoll -m tcp -p 1502 -a 1 -r 1 -c 2 -t 4 -1 127.0.0.1` |
| **diagslave** | CLI 서버 (proconX) | 클라이언트 역할 시험용 상대 |
| **pymodbus** | Python 라이브러리 | 스크립트 클라이언트/서버 |
| **Modbus Poll / Modbus Slave** | Windows GUI (상용) | 현장 엔지니어 표준 도구 |
| **QModMaster** | GUI (오픈소스) | |

주의: modpoll/mbpoll 의 `-r` 은 기본 **1-based 참조 번호**다 (`-r 1` → PDU 주소 0). `-t 4` =
holding, `-t 3` = input, `-t 0` = coil, `-t 1` = discrete, `-t 4:float` 등으로 형식을 지정한다
(정확한 옵션 표기는 도구 문서 확인). 상호운용 점검 순서:

1. `./build/mb_seeded_server --port 1602` 또는 데몬 + example config 기동.
2. 도구로 holding 0~2 읽기 → 시드 값(`A000 A001 A002`) 확인 → **주소 기준(0/1-based) 확정**.
3. float 읽기(holding 300, ABCD 1.5) → **워드 순서 확정**.
4. Unit ID 를 0xFF/0/2 로 바꿔 보며 응답 여부 확인 (6.5 절 표와 일치해야 함).
5. 도구의 쓰기 기능 → 앱 `read_point` 로 반영 확인.

이 저장소에는 CODESYS 모양의 마스터 흉내와 소프트웨어 마스터도 있다 (SoftPLC·인증 아님):
[`../../examples/codesys_shaped_modbus_master.py`](../../examples/codesys_shaped_modbus_master.py),
[`../../examples/sw_master.py`](../../examples/sw_master.py), [`../ctt_lab.md`](../ctt_lab.md) §실행 표.

### 10.6 증상별 점검표

| 증상 | 1순위 의심 | 확인 |
|---|---|---|
| 연결은 되는데 응답이 전혀 없음 | Unit ID 불일치 (0xFF 등) | 6.5 표, `unit_id_any` |
| 연결 직후 끊김 | `max_clients`/`max_conn_per_ip` 초과 | 데몬 로그 `per-IP limit` |
| 한참 뒤 끊김 | `idle_timeout_ms` (60s) | 폴링 주기 < 60s 인지 |
| 예외 02 | 주소 off-by-one, 맵 크기(`n_holding`) | 4.2, 9.4 표 |
| 예외 03 | FC05 값, 수량 한도, 바이트수 | 5.13 표 |
| 값이 이상하게 큼/작음 | 워드 순서, scale | 4.5 |
| 문자열 글자 순서 뒤집힘 | `string_swap`, `chars_per_register` | 4.6 |
| 값이 0 으로만 읽힘 | 앱이 `write_point` 안 함 / 다른 테이블 읽음 | `access`, 테이블 |
| 클라이언트 모드가 계속 실패 | 6.7 desync (한 번 타임아웃 후 `-EIO` 반복) | 로그 `poll … failed (-5)` → 데몬 재시작 |

---

## 11. 흔한 함정과 보안 고려사항

### 11.1 함정

1. **off-by-one 주소** — "40001" 은 PDU 0. 매뉴얼마다 다르다 (4.2).
2. **워드 순서** — float/int32 는 ABCD/CDAB 중 무엇인지 반드시 확인 (4.5).
3. **TCP 경계** — `recv` 한 번 = 메시지 하나라고 가정하지 말 것 (0.5, 6.4).
4. **Unit ID** — 0xFF/0/1 수락 정책 불일치로 "응답 없음" (6.5).
5. **FC05 값** — ON 은 `FF 00` 이지 `00 01` 이 아니다.
6. **수량 한도** — 125/2000/123/1968/121 을 넘기면 예외. 클라이언트가 나눠 읽어야 한다.
7. **32비트 값의 원자성** — 두 레지스터를 다른 시점에 갱신하면 찢어진 값 (8.6).
8. **테이블 겹침 가정** — 어떤 장치는 input/holding 이 같은 메모리 (4.1).
9. **느린 폴링과 유휴 타임아웃** — 폴링 간격이 서버 유휴 타임아웃보다 길면 매번 재연결.
10. **Nagle** — 서버/클라이언트 모두 TCP_NODELAY 를 켜는 것이 안전 (6.3).
11. **타임아웃 후 늦은 응답** — 버리거나 연결을 다시 열 것 (6.7).
12. **이 저장소 config 특유**:
    - 문자열 주소에 앞자리 0 을 붙이면 8진수 (`"00010"` → 7). 숫자로 쓰거나 0 을 빼라.
    - holding 의 작은 숫자(`100`)는 0-based, coil 의 작은 숫자(`5`)는 1-based. 헷갈리면
      `zero_based: true` 로 통일.
    - 4자리 `4001` 은 PDU 1 이 된다 (전통 4자리 표기에서는 PDU 0).
    - 포인트 최상위 `offset`(엔지니어링)과 `address.modbus.offset`(레지스터)은 다르다.
    - 비트필드 포인트의 `data_type` 은 `uint8`/`bool` 로 둘 것 (부록 D #14).

### 11.2 보안

Modbus TCP 에는 **인증도, 암호화도, 권한 개념도 없다.** 502 포트에 TCP 로 닿을 수 있는
누구나 모든 코일을 켜고 모든 레지스터를 쓸 수 있다. 이것은 사양의 설계이며 버그가 아니다.

| 위협 | 설명 | 대책 |
|---|---|---|
| 무단 쓰기 | 아무나 FC05/06/16 으로 설비 조작 | 네트워크 분리(OT 망), 방화벽에서 502 를 PLC IP 만 허용 |
| 도청 | 평문이라 값·명령 노출 | VPN/분리망, 또는 Modbus/TCP Security |
| 스캔/정찰 | 주소 전 범위 FC03 으로 맵 파악 | 맵 크기를 필요한 만큼만 (`n_holding` 등) |
| DoS | 연결 폭주, 느린 송신 | 연결 상한, IP 당 상한, 유휴 타임아웃 |
| 재전송/위조 | TID 는 보안 기능 아님 | TLS |

**Modbus/TCP Security** (Modbus Organization, 2018 전후): 같은 PDU 를 **TLS** 로 감싸고
(포트 **802**), X.509 인증서로 상호 인증하며, 인증서에 담긴 역할(role)로 FC/주소 권한을
나누는 사양이다. 세부(필수 TLS 버전·암호군, 역할 확장 OID)는 사양서 확인 필요.
이 저장소는 구현하지 않는다.

**이 저장소가 주는 것 / 주지 않는 것**:

| 있음 | 없음 |
|---|---|
| `bind_ip` 로 특정 NIC 에만 listen | 클라이언트 IP 허용 목록(allowlist) |
| `max_clients` (≤8), `max_conn_per_ip`, `idle_timeout_ms` | 포인트/주소별 쓰기 보호 (`access: read` 여도 PLC 가 쓸 수 있음) |
| `n_holding` 등 맵 크기 제한 (미사용 주소 → 예외 02) | 속도 제한(rate limit), 감사 로그 |
| 파서 fuzz 하네스 | TLS |

운영 권고: 기본 맵 크기(각 10000)는 필요 이상이다. `n_holding` 등을 포인트가 쓰는 최대
주소 + 1 로 줄이면 PLC 가 엉뚱한 주소를 쓰는 사고와 정찰 표면이 줄어든다.

---

## 12. 인증/적합성

- **Modbus Organization** 은 적합성 시험(conformance testing) 프로그램을 운영하며, 공인 시험소에서
  시험을 통과한 제품이 적합 제품으로 인정받는 구조다. 현행 절차·비용·시험소 목록은 modbus.org
  에서 확인할 것 (사양서 확인 필요 항목).
- Modbus 는 무료 공개 사양이라 **인증 없이도 구현·판매가 가능**하며, 실제로 대부분의 장치는
  인증 없이 "Modbus 지원"을 표기한다. 고객(특히 대형 SI·전력 분야)이 인증을 요구하는 경우가 있다.
- **이 저장소의 CTT green 은 인증이 아니다.** [`../ctt_mb_bundle.md`](../ctt_mb_bundle.md)와
  [`../ctt_modbus_matrix.md`](../ctt_modbus_matrix.md) 는 반복해서 이를 명시한다:
  - `MB-T-*` ID 는 내부 라벨이며 Modbus.org 시험 번호를 재구성하지 않는다.
  - 기본 CI 는 `handle_adu` 주입(mock)이며 실제 `:502` 소켓 시험은 기본 ctest 에 없다.
  - 부록 D #1 처럼 **사양과 다른 예외 코드를 기대값으로 고정한 시나리오**도 있다. 즉 CTT
    green 이 사양 적합을 뜻하지도 않는다.
- 인증을 준비한다면 최소한: 부록 D 의 #1~#5 정리, 예외 처리 순서 전수 점검, 실소켓 경로
  시험, FC43/14(Device Identification) 구현 여부 결정(인증 프로파일에 따라 요구될 수 있음 —
  사양서/시험 요구사항 확인 필요).

---

## 13. 참고 사양 문헌

모두 modbus.org 에서 무료로 받을 수 있다 (판 번호는 받을 때 표지 확인).

| 문서 | 이 문서에서 쓰인 곳 |
|---|---|
| **MODBUS Application Protocol Specification V1.1b3** | PDU, FC 정의·예제, 예외 코드, 상태도, 데이터 모델 (4, 5, 6.1, 7.1) |
| **MODBUS Messaging on TCP/IP Implementation Guide V1.0b** | MBAP, 포트 502, 연결 관리, Unit ID 권고, 파이프라이닝 (5.1, 6.2~6.5) |
| MODBUS over Serial Line Specification and Implementation Guide V1.02 | RTU/ASCII, 시리얼 주소·브로드캐스트 배경 (1.4, 6.5) |
| MODBUS/TCP Security Protocol Specification | TLS, 포트 802, 역할 기반 권한 (11.2) |
| IANA Service Name and Transport Protocol Port Number Registry | 502 (mbap), 802 (mbap-s) |

저장소 내부 문서:

- [`../modbus_stack.md`](../modbus_stack.md) — 이 저장소 Modbus 프로파일·config 작성 가이드
- [`../ctt_mb_bundle.md`](../ctt_mb_bundle.md), [`../ctt_modbus_matrix.md`](../ctt_modbus_matrix.md) — CTT 카탈로그
- [`../design.md`](../design.md) — 전체 설계
- [`README.md`](README.md) — 네 프로토콜 공통 기초와 저장소 구조

---

## 부록 A. 구현 체크리스트

**MBAP / 프레이밍**
- [ ] 모든 16비트 필드를 빅 엔디안 헬퍼로 읽고 쓴다
- [ ] Protocol ID ≠ 0 → 버림
- [ ] Length < 2 또는 > 254 → 연결 종료
- [ ] 연결별 수신 버퍼 + 재조립 루프 (조각·여러 ADU)
- [ ] 응답 TID·Proto·Unit 을 요청에서 복사, Length 재계산
- [ ] 응답 버퍼 ≥ 260

**PDU**
- [ ] 길이 → 수량 → 바이트수 → 주소 순 검증, 예외 03/03/03/02
- [ ] `addr + qty` 를 32비트로
- [ ] FC01/02: 1~2000, LSB-first 포장, 남는 비트 0
- [ ] FC03/04: 1~125
- [ ] FC05: `0x0000`/`0xFF00` 만, 응답 에코
- [ ] FC06: 응답 에코
- [ ] FC15: 1~1968, bc == ⌈N/8⌉
- [ ] FC16: 1~123, bc == 2N
- [ ] FC22: `(cur & and) | (or & ~and)`, 응답 에코
- [ ] FC23: R 1~125, W 1~121, **쓰기 후 읽기**
- [ ] 미지원 FC → 예외 01 (FC ≥ 0x80 요청 처리 방침 결정)
- [ ] (선택) FC43/14 Device Identification

**연결**
- [ ] 다중 클라이언트, 상한 초과 처리
- [ ] 유휴 타임아웃 또는 keep-alive
- [ ] TCP_NODELAY
- [ ] 송신 부분 쓰기/EAGAIN 처리 (끊지 말고 버퍼링하거나 블로킹 전송 한도)
- [ ] Unit ID 정책 문서화 (0xFF, 0 수락 여부)

**클라이언트**
- [ ] 연결 타임아웃
- [ ] 요청별 응답 타임아웃
- [ ] 타임아웃 후 연결 재수립 또는 TID 불일치 응답 폐기
- [ ] 연결 단위 TID 카운터
- [ ] 응답 FC·길이 검증, 예외 코드 보고
- [ ] 인접 포인트 묶음 읽기

**응용**
- [ ] 워드 순서·스케일·문자열 규칙을 설정 가능하게
- [ ] 32비트 값 원자적 갱신 (락)
- [ ] 맵 크기를 실제 사용 범위로

**검증**
- [ ] 부록 B 전 예제 바이트 일치
- [ ] fuzz (ASan/UBSan)
- [ ] modpoll/mbpoll/pymodbus 교차 확인
- [ ] Wireshark 캡처에서 해석 오류 없음

---

## 부록 B. hex 예제 모음

모두 이 저장소 스택(unit_id=1)에 넣어 얻은 실제 응답이다. 시드: coil 19~37 = CD 6B 05 패턴,
discrete 196~217 = AC DB 35 패턴, holding 107~109 = 022B 0000 0064, input 8 = 000A,
holding 4 = 0012, holding 3~8 = 00FE 0ACD 0001 0003 000D 00FF. 맵 크기: holding 200, input 50,
coil 256, discrete 256.

**정상**

| # | 설명 | 요청 | 응답 |
|---|---|---|---|
| B1 | FC01 코일 20~38 | `00 01 00 00 00 06 01 01 00 13 00 13` | `00 01 00 00 00 06 01 01 03 CD 6B 05` |
| B2 | FC02 입력 197~218 | `00 02 00 00 00 06 01 02 00 C4 00 16` | `00 02 00 00 00 06 01 02 03 AC DB 35` |
| B3 | FC03 레지스터 108~110 | `00 03 00 00 00 06 01 03 00 6B 00 03` | `00 03 00 00 00 09 01 03 06 02 2B 00 00 00 64` |
| B4 | FC04 입력 레지스터 9 | `00 04 00 00 00 06 01 04 00 08 00 01` | `00 04 00 00 00 05 01 04 02 00 0A` |
| B5 | FC05 코일 173 ON | `00 05 00 00 00 06 01 05 00 AC FF 00` | `00 05 00 00 00 06 01 05 00 AC FF 00` |
| B6 | FC05 코일 173 OFF | `00 06 00 00 00 06 01 05 00 AC 00 00` | `00 06 00 00 00 06 01 05 00 AC 00 00` |
| B7 | FC06 레지스터 2 ← 3 | `00 07 00 00 00 06 01 06 00 01 00 03` | `00 07 00 00 00 06 01 06 00 01 00 03` |
| B8 | FC15 코일 20~29 | `00 08 00 00 00 09 01 0F 00 13 00 0A 02 CD 01` | `00 08 00 00 00 06 01 0F 00 13 00 0A` |
| B9 | FC01 되읽기 | `00 09 00 00 00 06 01 01 00 13 00 0A` | `00 09 00 00 00 05 01 01 02 CD 01` |
| B10 | FC16 레지스터 2~3 | `00 0A 00 00 00 0B 01 10 00 01 00 02 04 00 0A 01 02` | `00 0A 00 00 00 06 01 10 00 01 00 02` |
| B11 | FC03 되읽기 | `00 0B 00 00 00 06 01 03 00 01 00 02` | `00 0B 00 00 00 07 01 03 04 00 0A 01 02` |
| B12 | FC22 마스크 | `00 0C 00 00 00 08 01 16 00 04 00 F2 00 25` | `00 0C 00 00 00 08 01 16 00 04 00 F2 00 25` |
| B13 | FC03 마스크 결과 | `00 0D 00 00 00 06 01 03 00 04 00 01` | `00 0D 00 00 00 05 01 03 02 00 17` |
| B14 | FC23 읽기 6/쓰기 3 | `00 0E 00 00 00 11 01 17 00 03 00 06 00 0E 00 03 06 00 FF 00 FF 00 FF` | `00 0E 00 00 00 0F 01 17 0C 00 FE 0A CD 00 01 00 03 00 0D 00 FF` |
| B15 | FC03 FC23 쓰기 확인 | `00 0F 00 00 00 06 01 03 00 0E 00 03` | `00 0F 00 00 00 09 01 03 06 00 FF 00 FF 00 FF` |
| B16 | Unit 0 | `00 1B 00 00 00 06 00 03 00 6B 00 01` | `00 1B 00 00 00 05 00 03 02 02 2B` |
| B17 | Unit 0xFF + `unit_id_any` | `00 40 00 00 00 06 FF 03 00 00 00 01` | `00 40 00 00 00 05 FF 03 02 00 00` |

**예외**

| # | 설명 | 요청 | 응답 |
|---|---|---|---|
| E1 | FC08 미구현 | `00 10 00 00 00 06 01 08 00 00 12 34` | `00 10 00 00 00 03 01 88 01` |
| E2 | FC43/14 미구현 | `00 11 00 00 00 05 01 2B 0E 01 00` | `00 11 00 00 00 03 01 AB 01` |
| E3 | FC03 범위 밖 | `00 12 00 00 00 06 01 03 00 C7 00 02` | `00 12 00 00 00 03 01 83 02` |
| E4 | FC03 수량 0 | `00 13 00 00 00 06 01 03 00 00 00 00` | `00 13 00 00 00 03 01 83 02` (사양: 03) |
| E5 | FC03 수량 126 | `00 14 00 00 00 06 01 03 00 00 00 7E` | `00 14 00 00 00 03 01 83 02` (사양: 03) |
| E6 | FC01 수량 2001 | `00 15 00 00 00 06 01 01 00 00 07 D1` | `00 15 00 00 00 03 01 81 02` (사양: 03) |
| E7 | FC05 값 0x0001 | `00 16 00 00 00 06 01 05 00 00 00 01` | `00 16 00 00 00 03 01 85 03` |
| E8 | FC05 값·주소 모두 불량 | `00 17 00 00 00 06 01 05 0F FF 12 34` | `00 17 00 00 00 03 01 85 03` |
| E9 | FC16 PDU 짧음 | `00 18 00 00 00 06 01 10 00 00 00 7C` | `00 18 00 00 00 03 01 90 03` |
| E10 | FC16 바이트수 불일치 | `00 19 00 00 00 09 01 10 00 00 00 02 03 00 11 22` | `00 19 00 00 00 03 01 90 03` |
| E11 | PDU 가 FC 뿐 | `00 1A 00 00 00 02 01 03` | `00 1A 00 00 00 03 01 83 03` |
| E12 | Length(3) < 실제 | `00 20 00 00 00 03 01 03 00 6B 00 01` | `00 20 00 00 00 03 01 83 03` |
| E13 | FC06 범위 밖 | `00 22 00 00 00 06 01 06 00 C8 00 01` | `00 22 00 00 00 03 01 86 02` |
| E14 | FC 0x81 (상위 비트 설정) | `00 21 00 00 00 02 01 81` | `00 21 00 00 00 03 01 81 01` |

**응답 없음**

| # | 설명 | 요청 | 결과 |
|---|---|---|---|
| N1 | Unit 0xFF (기본 설정) | `00 1C 00 00 00 06 FF 03 00 6B 00 01` | `rc=0`, 응답 길이 0 (무시) |
| N2 | Unit 9 | `00 1D 00 00 00 06 09 03 00 6B 00 01` | 무시 |
| N3 | Protocol ID 1 | `00 1E 00 01 00 06 01 03 00 6B 00 01` | `-EINVAL` |
| N4 | Length 16 > 실제 | `00 1F 00 00 00 10 01 03 00 6B 00 01` | `-EINVAL` (스트림에서는 나머지 대기) |

**크기 경계**: FC03 qty 125 → ADU 259바이트, Length `00 FD`, Byte Count 250. 응답 버퍼가
100바이트면 `rc=0`, 응답 길이 0 (조용히 버림, [`mb_stack.c:336-339`](../../stacks/modbus/src/mb_stack.c)).

---

## 부록 C. 이 문서의 검증 방법

작업 디렉터리는 스크래치 공간이며 저장소 파일은 이 문서 외에 수정하지 않았다.

| 검증 | 방법 | 결과 |
|---|---|---|
| 빌드 | `cmake -DBUILD_DAEMON=OFF -DBUILD_CTT=ON` (별도 build 디렉터리) | 성공 |
| CTT | `ctest -L modbus -LE soak_ci` | 14/14 통과 |
| 스택 단위 | `test_mb_stack` | OK |
| 부록 B 전체 | 작은 C 하네스가 hex 를 `mb_stack_handle_adu` 에 넣고 응답 출력 | 표의 값 그대로 |
| 재조립·파이프라이닝·상한·Length 초과 | 실제 소켓으로 `mb_stack_poll` 구동 | 6.4 표 |
| Nagle 영향 | 같은 하네스를 원본 / `TCP_NODELAY` 추가 복사본(스크래치)으로 비교 | 6.3 표 |
| 클라이언트 요청 바이트 | fork 한 가짜 서버가 수신 바이트 출력 | 6.7 |
| 클라이언트 desync | 첫 응답만 300ms 지연하는 가짜 서버 | 6.7 |
| 어댑터 정규화·예제 config·엔디안 | 어댑터 소스를 include 한 하네스 (cJSON 은 데몬 빌드의 FetchContent) | 9.4, 9.5, 4.5 |
| 비트필드 결함 | 같은 하네스로 uint16 bit_count 4 포인트 읽기/쓰기 | 부록 D #14 |
| Python 클라이언트 | `mb_seeded_server` 에 대고 실행 | 8.7 |
| 최소 서버(8.5) | `gcc -Wall -Wextra` 경고 0, 조각/파이프라인/예외 시험 | 통과 |
| fuzz | clang libFuzzer 런타임 부재로 링크 실패 → gcc ASan/UBSan 로 코퍼스 384 + 무작위 20만 입력 재생 | 새니타이저 보고 없음 |
| 사양 사실 | 사양서 원문 대조가 아닌 지식 기반. 불확실한 곳은 본문에 "사양서 확인 필요" 표기 | — |

---

## 부록 D. 사양 vs 저장소 차이 요약

기록만 한다. 수정은 별도 작업 (스택/어댑터 경계는 [`../../CLAUDE.md`](../../CLAUDE.md) 참고).
"실측"은 부록 C 방법으로 재현한 것, "코드"는 읽기로 확인한 것.

| # | 구분 | 내용 | 근거 |
|---|---|---|---|
| 1 | 사양 불일치 | FC01~04 의 **수량 위반(0, 초과)에 예외 02** 를 낸다. 사양 상태도는 수량 위반 → 03, 주소 위반 → 02. CTT `MB-T-NEG-001` 이 qty=0 → 02 를 기대값으로 고정 | 실측 E4~E6, `mb_stack.c:168,194`, `exception_illegal_address.yaml` |
| 2 | 사양 권고와 다름 | 기본 설정에서 **Unit 0xFF 요청을 무시**. 구현 가이드는 직접 연결 장치에 0xFF 사용을 권고 → 0xFF 를 보내는 클라이언트와 "무응답" 문제 | 실측 N1, `mb_stack.c:149` |
| 3 | 해석 차이 | Unit 0 을 일반 요청처럼 응답 (시리얼에서는 브로드캐스트 = 무응답). TCP 에서의 의미는 사양서 확인 필요 | 실측 B16 |
| 4 | 선택 사항 | 잘못된 Unit 은 무응답. 게이트웨이라면 0x0A/0x0B 예외가 맞지만 종단 장치의 무시는 흔한 선택 | 실측 N2 |
| 5 | 미사용 | 예외 04 를 절대 내지 않음 (`MB_EX_SLAVE_FAILURE` 미사용) | 코드 `mb_types.h:37` |
| 6 | 경계 | FC ≥ 0x80 요청에 `fc|0x80` = 같은 값으로 예외 응답 (`81 01`) — 예외 응답 표시 공간과 겹침 | 실측 E14 |
| 7 | 성능 | 서버 소켓에 **TCP_NODELAY 미설정** → 파이프라인 응답이 Nagle/지연 ACK 로 늦어질 수 있음. 한 줄 추가로 해소됨을 스크래치 복사본으로 확인 | 실측 6.3 |
| 8 | 견고성 | non-blocking 소켓의 `send` 가 `EAGAIN` 이어도 연결을 끊음 (느린 클라이언트 + 큰 파이프라인에서) | 코드 `mb_stack.c:676-693`, `:665-668` |
| 9 | 클라이언트 | 블로킹 `connect()` (타임아웃 없음) → 사이클 스레드 정지 가능 | 코드 `mb_stack.c:519` |
| 10 | 클라이언트 결함 | **한 번 타임아웃 후 영구 TID 불일치(-EIO)**, `connected` 유지로 재연결도 안 함. 첫 `recv` 가 필요 이상 읽음 | 실측 6.7, `mb_stack.c:710,744-747` |
| 11 | 클라이언트 | TID 카운터가 함수별 `static` 3개 (모두 1부터, 인스턴스 간 공유) | 실측, `mb_stack.c:767,879,949` |
| 12 | 어댑터 결함 | 주소 문자열을 `strtol(…, 0)` 로 파싱 → 앞자리 0 이면 **8진수** (`"00010"`→PDU 7, `"00009"`→0, `"040001"`→16385) | 실측, `modbus_adapter.c:113` |
| 13 | 어댑터 일관성 | 작은 숫자 해석이 테이블마다 다름 (coil 1-based, 나머지 0-based). 4자리 `4001`→PDU 1 (전통 4자리 표기는 PDU 0), holding `4500` 을 PDU 4500 으로 의도해도 500 이 됨 | 실측, `modbus_adapter.c:160-201` |
| 14 | 어댑터 결함 | **bit_count ≤ 8 비트필드 + 2바이트 데이터형(uint16 등)**: 쓰기는 값의 **상위 바이트**만 사용 (0x000A → 0 기록), 읽기는 두 번째 바이트가 **초기화 안 된 스택 메모리** (실측 `0A 5F`, `0A A9`). 예제 config 의 `status_nibble` 이 해당. 앱의 `fb_write_u16` 도 2바이트 BE 를 넘기므로 같은 문제로 추정 (`core/fb_api.c:631-635`) | 실측, `modbus_adapter.c:601-602,634-635,673-676` |
| 15 | 문서/스키마 | 스키마의 `chars_per_word` 를 어댑터가 읽지 않음 (`chars_per_register`/`chars_per_reg`/`char_per_register` 만) | 코드 `config.schema.json:58`, `modbus_adapter.c:335-340` |
| 16 | 보안/설계 | `access: "read"` 포인트도 PLC 가 쓸 수 있음 (스택은 access 를 모름) | 실측 9.4 |
| 17 | 설계 | 서버 응답 지연 ≤ 1 `cycle_ms` (폴링 구동) | 코드 6.8 |
