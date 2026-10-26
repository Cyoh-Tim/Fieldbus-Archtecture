# 감사 2026-10-25 — EtherNet/IP 어댑터·Originator: SIGPIPE, 늦은 응답, 재연결, 포인트 기본 크기, connect 타임아웃

- 영역: EtherNet/IP 어댑터·Originator (`adapters/ethernetip/` 포인트 매핑·변환·`protocol_params`, 태그·CIP 경로 서비스, 연결 수명주기,
  `stacks/ethernetip/` 의 Originator 경로 `eip_client.c`·`connect_originator`) — 12단계 일요일 감사 (영역 순환: EIP 스택 → **EIP 어댑터·Originator**)
- 출처: 12단계 감사 라운드. 코드 대조 + 오라클 DUT `eip_oracle_fbapi`(fb_api + 어댑터, 실제 루프백 소켓)·`eip_oracle_adapter` 를
  사양 기반 가짜 대상(`FakeLogix` 파생)·pycomm3 스캐너로 두드림. 실제 데몬 `multiproto_daemon` 으로 1건 교차 확인
- 기준 커밋: `4d03ff7` (main, #150 T12-9 병합 직후)
- 판단: opus 하위 에이전트 (코드 대조 + 오라클 재현 + OpENer `d8820ef`·EIPScanner·pycomm3 소스 대조). 루틴이 8개 재현을 직접 다시 돌리고 OpENer·EIPScanner 근거를 확인함
- 큐 추가: 5개 (A20261025-1 ~ A20261025-5 → 큐 94~98)

이미 알려진 것은 다시 올리지 않았다: T1·T2 (바이트 순서·scale — 명시한 `length`·`data_type` 경로는 통과), T11-2 (`minor_rev`),
T11-12 (Logix 0x4C/0x4D, TCP 재조립, 보안 MAC), T3·T9-5 (Modbus/SLMP 의 같은 종류 — EIP 는 없음), A20261012-2, A20261013-1, A20261015-1,
A20261017-1/-2, A20261018-1~6. 입문서 9.5 표의 "Class 1 Originator 없음" 은 제품 범위(CLAUDE.md "Originator explicit") 밖이라 결함으로 세지 않았다.

## A20261025-1. TCP 응답 send 에 MSG_NOSIGNAL 이 없어, 피어가 닫으면 SIGPIPE 로 데몬(또는 앱)이 죽는다

**문제:** EIP 스택의 TCP 송신이 모두 `send(fd, …, 0)` 이고, 데몬·`fb_api` 어디에도 `SIGPIPE` 무시가 없다. 피어가 닫은 소켓에 두 번째 이후
`send` 를 하면 커널이 `EPIPE` 와 함께 SIGPIPE 를 보내고, 기본 동작으로 프로세스 전체가 끝난다. 어댑터 역할에서는 인증 없이 아무 호스트나
요청 여러 개를 한 번에 보내고 곧바로 닫기만 하면 센서 데몬이 죽는다 (원격 DoS). 스캐너가 응답을 기다리지 않고 끊는 정상적인 상황(타임아웃 후
재접속, 앱 강제 종료)에서도 일어난다. Originator 역할에서는 대상이 연결을 닫은 뒤 세 번째 요청에서 앱이 죽는다 (A20261025-3 재현에 나옴).

**근거 (파일:줄, 기준 커밋 `4d03ff7`):**
- `stacks/ethernetip/src/eip_stack.c:596` — 어댑터 응답 `(void)send(c->fd, resp, resp_len, 0);` (`:569-601` 한 번 받은 버퍼의 요청을 연달아 처리)
- `stacks/ethernetip/src/eip_client.c:82` — Originator 요청 `send(s->originator_fd, req, off, 0)`; `eip_stack.c:323` RegisterSession 도 같음
- `stacks/ethernetip/src/eip_sec.c:378` — TLS 경로 `SSL_write` (OpenSSL 도 내부에서 플래그 없는 write 를 쓴다)
- `core/main.c:37-38` — `SIGINT`/`SIGTERM` 만 등록. 같은 저장소의 `stacks/modbus/src/mb_stack.c:799`, `stacks/slmp/src/slmp_stack.c:664`,
  `:1329` 는 `MSG_NOSIGNAL` 을 쓴다

**재현 (오라클, DUT `eip_oracle_adapter`):** TCP 접속 → ListIdentity(세션 불필요) 8개를 한 번에 보내고 응답을 읽지 않고 `close()`.

```
test_peer_close_does_not_kill_adapter (--runxfail)
E       AssertionError: 어댑터 DUT 가 시그널 SIGPIPE 로 종료
E       assert -13 is None
```

실제 데몬도 같다: `config/example.ethernetip.json` 을 루프백·`security_class 0`·`mock false` 로 바꿔 `multiproto_daemon` 을 띄우고
같은 요청을 보내면 첫 시도에 `exit -13` (SIGPIPE).

**기대값과 출처:**
- 독립 구현 OpENer (`d8820ef`) `source/src/ports/generic_networkhandler.c:889-892` — TCP 응답을 `send(…, MSG_NOSIGNAL)` 로 보내고,
  `:51-58` 은 `MSG_NOSIGNAL` 이 없는 플랫폼에서 "Check if your system stops on SIGPIPE, as this can happen with the send() function" 경고를 낸다.
- 독립 구현 EIPScanner `src/sockets/TCPSocket.cpp:39-43` — 소켓에 `SO_NOSIGPIPE` (Linux 가 아닌 플랫폼용; 같은 목적).
- POSIX `send(2)`: 연결이 끊긴 스트림 소켓에 쓰면 `EPIPE`, 그리고 `MSG_NOSIGNAL` 이 없으면 SIGPIPE.

**수정 범위:** `stacks/ethernetip/` (+ `tests/`).
- `eip_stack.c:323`, `:596`, `eip_client.c:82` 의 `send` 에 `MSG_NOSIGNAL`. 실패(`EPIPE`/`ECONNRESET`)면 그 클라이언트를 `tcp_client_drop`.
- TLS 경로(`eip_sec.c`)는 `SSL_write` 가 SIGPIPE 를 낼 수 있으므로 소켓 BIO 대신 `MSG_NOSIGNAL` 쓰는 BIO 를 쓰거나, 스택 시작 시
  `SIGPIPE` 를 무시하는 쪽 중 하나 (코어에 넣는다면 프로토콜 무관 변경이라 CLAUDE.md 경계 안 — 다만 별도 PR).

**완료 조건:** `test_peer_close_does_not_kill_adapter` 통과 (`A20261025-1` 표시 삭제). 단위 테스트로 Originator 쪽(대상이 닫은 뒤 요청 3회 →
프로세스 생존, 음수 errno)도 보인다.

## A20261025-2. Originator 가 2 s 타임아웃 뒤 늦게 온 이전 응답을 다음 요청의 응답으로 받는다

**문제:** `originator_sendrr()` 는 요청의 Sender Context 를 0 으로 두고, 응답의 Command·Session·Status·Sender Context·CIP 응답 서비스 코드를
요청과 대조하지 않는다. 대기는 `select` 2 s 이고, 시간이 지나면 `-ETIMEDOUT` 만 돌려줄 뿐 연결을 닫거나 늦은 응답을 버리지 않는다. 그래서 대상이
한 번 2 s 를 넘겨 답하면, 이후 모든 요청이 **한 칸 앞 요청의 응답** 을 rc 0 으로 받는다. 다른 포인트의 값이 앱에 들어가고(데이터 무결성),
쓰기(Set)도 앞선 Get 의 성공 응답을 받아 실패를 성공으로 보고할 수 있다. Modbus T9-1·SLMP T10-2 (병합됨) 와 같은 종류다.

**근거 (파일:줄, 기준 커밋 `4d03ff7`):**
- `stacks/ethernetip/src/eip_client.c:77-80` — 헤더를 0 으로 채움 (Sender Context = 0, 요청마다 같음)
- `:86-89` — `wait_recv(…, 2000)` 실패 시 그대로 반환. 소켓에 늦은 응답이 남는다
- `:91-139` — 응답의 Command(`resp+0`), Session(`resp+4`), Status(`resp+8`), Sender Context(`resp+12`), 응답 서비스(`payload[0]` = 요청 서비스|0x80)
  를 보지 않고 첫 `0x00B2` 항목의 데이터를 돌려준다

**재현 (오라클, DUT `eip_oracle_fbapi` Originator 설정):** 가짜 대상 `IdentityTarget` 은 Identity attr 1 = 0x1111, attr 2 = 0x2222 를 돌려주되
첫 응답만 2.6 s 늦게 보낸다. 앱이 `vendor`(attr 1) 를 읽고(타임아웃) 이어서 `device_type`(attr 2) 을 읽는다.

```
test_originator_late_reply_not_taken_for_next_request (--runxfail)
E       AssertionError: 첫 읽기 'VAL -3 0', 둘째 읽기 'VAL 0 4369'
```

`device_type` 읽기가 vendor 값 4369(0x1111)를 rc 0 으로 돌려준다.

**기대값과 출처:**
- `docs/protocols/ethernetip.md` 5.1 [사양, Vol 2]: Sender Context 는 "요청자가 임의로 넣고, 응답에 그대로 복사" (`:665`), 용어표 `:243`
  "Target 은 그대로 되돌려 준다 (요청-응답 짝 맞추기)". 대조할 값을 넣지도 보지도 않는다.
- 독립 구현 EIPScanner `src/SessionInfo.cpp:58-65` — 모든 응답의 encapsulation Status 와 Session Handle 을 검사하고 다르면 예외.
  pycomm3 `packets/base.py:76-83` `ResponsePacket.is_valid` 도 encapsulation status 를 본다. 저장소 Originator 는 둘 다 안 본다.
- 저장소 선례: T9-1 (Modbus TID 불일치)·T10-2 (SLMP 타임아웃 뒤 stale 응답) 를 결함으로 고쳤다.

**수정 범위:** `stacks/ethernetip/` (+ `tests/`).
- 요청마다 다른 Sender Context 를 넣고, 응답의 Command·Session·Status·Context·응답 서비스 코드가 다르면 버리고 계속 기다린다
  (남은 시간 안에서). 또는 타임아웃이면 연결을 닫고 다음 요청에서 다시 연결한다 (Modbus T9-1 방식). 둘 다면 더 좋다.
- A20261025-3 과 같은 함수를 고친다. 한 PR 에서 함께 고쳐 두 표시를 같이 지워도 된다 (허용). T11-12 (TCP 재조립) 와도 같은 수신 경로다.

**완료 조건:** `test_originator_late_reply_not_taken_for_next_request` 통과 (`A20261025-2` 표시 삭제), 기존 Originator 오라클 그대로 통과.
단위 테스트로 Context·서비스 불일치 응답을 버리는 것을 보인다.

## A20261025-3. Originator 가 대상의 연결 종료를 감지·재연결하지 않고 health 는 connected 로 남는다

**문제:** Originator 는 `eip_stack_start()` 에서 한 번 연결하고, 그 뒤 연결이 끊겨도(대상 재시작, 대상의 encapsulation 유휴 타임아웃 —
이 저장소 어댑터는 60 s, 사양 기본 120 s) 아무것도 하지 않는다. `eip_stack_poll()` 은 Originator 역할에서 아무 일도 하지 않고, 요청이 실패해도
소켓·세션을 정리하지 않는다. 그래서 (1) 대상이 돌아와도 읽기·쓰기가 영영 실패하고, (2) `fb_health().connected` 가 계속 1 이며,
(3) 죽은 소켓에 세 번째 `send` 를 하는 순간 SIGPIPE 로 앱이 죽는다 (A20261025-1). 폴링 간격이 대상 유휴 타임아웃보다 긴 앱은 정상 운전 중에도
이 상태가 된다.

**근거 (파일:줄, 기준 커밋 `4d03ff7`):**
- `stacks/ethernetip/src/eip_stack.c:731-771` — `eip_stack_poll` 은 `mock` 과 `EIP_ROLE_ADAPTER` 만 처리 (Originator 분기 없음)
- `:855-866` — `eip_stack_session_up` 은 `clients[0].active && session != 0` 만 본다. 끊겨도 지우는 곳이 없다
- `stacks/ethernetip/src/eip_client.c:82-93` — `send`/`recv` 실패(`recv` 0 = EOF 포함)를 `-EIO` 로 돌려줄 뿐 `originator_fd` 를 닫지 않음
- `adapters/ethernetip/ethernetip_adapter.c:779-790` (connect 1회), `:1007-1015` (`health` = `class1_up || session_up`)
- 코어는 다시 연결하지 않는다: `core/fb_api.c:433` (connect 는 open 때 1회)

**재현 (오라클, DUT `eip_oracle_fbapi` Originator 설정):** 가짜 대상이 첫 연결에서 첫 응답 뒤 연결을 닫고, 이후 연결은 정상 처리한다.

```
test_originator_reconnects_after_target_closes (--runxfail)
E       AssertionError: 재연결 후 읽기 성공 없음: ['VAL 0 4369', 'VAL -3 0', None] (DUT 시그널 SIGPIPE 로 종료, 대상 연결 수 1)
```

health 는 단위 하네스(`eip_oracle_fbapi` + `H` 명령, 감사 스크래치 `health_harness.c`)로 확인:

```
H      -> HEALTH 0 connected=1
R      -> VAL 0 4369
R      -> VAL -3 0 (대상이 닫은 뒤)
H      -> HEALTH 0 connected=1 (3.5 s 뒤)
대상 연결 수 1
```

**기대값과 출처:**
- `docs/design.md:144` — "연결 끊김/재연결: 어댑터별 `health()` 상태를 코어가 주기적으로 확인, **재연결 로직은 어댑터 내부 책임**."
- 저장소 관례: Modbus 클라이언트는 오류 뒤 소켓을 닫고 백오프 후 재연결한다 (`stacks/modbus/src/mb_stack.c:814-853`, T3).
- 사양: TCP/IP Interface attr 13 Encapsulation Inactivity Timeout 기본 120 s (`docs/protocols/ethernetip.md` 부록 D41, T11-10 오라클) —
  대상이 유휴 연결을 닫는 것은 정상 동작이다.

**수정 범위:** `stacks/ethernetip/` (+ `tests/`). (어댑터 `health` 는 스택의 `session_up` 을 그대로 쓰므로 스택만 고치면 된다.)
- `send`/`recv` 실패·EOF 에서 `originator_fd`·`clients[0]` 를 정리 (`session_up` → 0).
- 다음 요청(또는 `eip_stack_poll` 의 Originator 분기)에서 백오프를 두고 다시 연결 + RegisterSession. 이벤트 구동(큐 74) 이전이라도
  "요청 시 재연결" 이면 사이클 로직을 늘리지 않는다.

**완료 조건:** `test_originator_reconnects_after_target_closes` 통과 (`A20261025-3` 표시 삭제). 단위 테스트로 끊긴 뒤 `session_up == 0`,
대상 복귀 후 읽기 성공을 보인다.

## A20261025-4. `length` 를 생략한 숫자 포인트를 1바이트로, `data_type` 을 생략한 포인트를 무변환으로 다룬다

**문제:** 어댑터는 포인트 `length` 가 없으면 1 로 둔다 (`data_type` 크기를 쓰지 않는다). 코어는 숫자 포인트 크기를 `data_type` 으로만 정하고
(`length` 는 문자열·바이트만) BE 2/4바이트를 넘기므로, 어댑터는 그중 **앞 1바이트(BE 상위 바이트)** 만 Assembly 에 쓰고 읽을 때도 1바이트만
읽는다. 또 `data_type` 이 없으면 코어는 `uint16` 으로 보고 BE 를 넘기는데 어댑터는 "변환 없음" 으로 두어 T1 의 바이트 뒤집힘이 그대로 남는다.
스키마는 `length`·`data_type` 을 필수로 두지 않는다 (`config/config.schema.json:28`).

**근거 (파일:줄, 기준 커밋 `4d03ff7`):**
- `adapters/ethernetip/ethernetip_adapter.c:468` — `pt->length = cJSON_IsNumber(length) ? length->valueint : 1;` (`:506-509` 주소 쪽 `length` 도 같음)
- `:469-483` — `data_type` 이 없으면 `EIP_DT_NONE` → `endian_width 0` (변환 없음)
- `:906-909`, `:982-985` — 읽기·쓰기 길이를 `pt->length` 로 자름 → `:268` `n < width` 면 swap 도 안 함
- 코어 `core/fb_api.c:331-333` (`data_type` 기본 `"uint16"`), `:192-211` (숫자 크기 = 타입 크기), `:627-638` (`encode_numeric` 이 그 크기로 BE)
- Modbus 어댑터는 같은 경우를 `data_type` 크기로 처리: `adapters/modbus/modbus_codec.c:55-56` (기본 `MB_DT_UINT16`),
  `adapters/modbus/modbus_adapter.c:411-415` (`byte_len = mb_type_native_size(data_type, length, …)`)

**재현 (오라클, DUT `eip_oracle_fbapi`, 스캐너 = pycomm3 Get_Attribute_Single attr 3 / 사양 기반 Class 1):**

```
test_numeric_point_defaults_on_wire[uint16_no_length]  (fb_write_u32 300) → 01 00   (기대 2C 01, 스캐너 UINT = 1)
test_numeric_point_defaults_on_wire[int32_no_length]   (fb_write_i32 -2)  → ff 00 00 00 (기대 fe ff ff ff)
test_numeric_point_defaults_on_wire[no_data_type]      (length 2, 300)    → 01 2c   (기대 2C 01, 스캐너 UINT = 11265)
test_numeric_point_without_length_read_from_scanner    스캐너 O→T UINT 300 → 앱 (0, 44)  (기대 (0, 300))
```

**기대값과 출처:**
- CIP 기본 타입 크기 (CIP Vol 1 Appendix C; 오라클의 `CIP_TYPE_SIZE`·pycomm3 `UINT`/`DINT`): UINT 2 B, DINT 4 B, LE. pycomm3 가 읽은 값이 1 / 11265 다.
- 인수인계 T0 A안 (`structure_handoff_20260930.md:66-96`): wire 바이트 순서는 어댑터 책임이고 앱↔어댑터 경계는 canonical BE. T1 완료 조건
  "`2C 01 -> CIP UINT 300`" 은 `length` 를 쓴 설정에서만 지켜진다.
- 저장소 관례: 코어와 Modbus 어댑터 모두 `data_type` 기본 uint16, 숫자 크기 = 타입 크기.

**수정 범위:** `adapters/ethernetip/` (+ `tests/`).
- 숫자 `data_type` 이면 `length` 가 없을 때 `eip_type_wire_len()` 을 쓴다 (`length` 가 타입 크기의 배수면 배열로 유지).
- `data_type` 이 없으면 코어와 같이 `uint16` 으로 본다 (또는 init 에서 경고 + 거부 — 어느 쪽이든 코어와 같은 해석).
- 같은 패턴이 `adapters/profinet/profinet_adapter.c:382` 에 있다 (이 라운드 범위 밖, PN 어댑터 라운드에서 확인).

**완료 조건:** `test_numeric_point_defaults_on_wire[*]` 3개와 `test_numeric_point_without_length_read_from_scanner` 통과
(`A20261025-4` 표시 삭제), 기존 T1·T2 오라클 그대로 통과.

## A20261025-5. Originator TCP connect 에 타임아웃이 없어 응답 없는 대상이면 `fb_open` 이 ~2 분 막힌다

**문제:** `connect_originator()` 는 블로킹 `connect()` 를 타임아웃 없이 부른다. 대상이 꺼져 있거나 방화벽이 SYN 을 버리면 커널 SYN 재시도
(`tcp_syn_retries` 6 → 약 127 s) 가 끝날 때까지 `fb_open`(데몬 기동, `fb_reload`) 이 반환하지 않는다. 그 사이 앱은 에러도 받지 못한다.
(RegisterSession·요청은 2 s 로 끊는데 connect 만 무제한이다.)

**근거 (파일:줄, 기준 커밋 `4d03ff7`):**
- `stacks/ethernetip/src/eip_stack.c:296-313` — `socket()` → 블로킹 `connect()` → 성공 뒤에야 `set_nonblock`
- `:329-338` — RegisterSession 응답은 2 s `select` 로 제한 (connect 와 대비)

**재현 (오라클, DUT `eip_oracle_fbapi` Originator 설정):** accept 하지 않는 `listen(0)` 소켓에 연결 하나를 채워 다음 SYN 이 버려지게 한다
(응답 없는 대상).

```
test_originator_connect_has_timeout (--runxfail)
E       AssertionError: fb_open 이 12.0 s 동안 반환하지 않음 (출력 None)
```

끝까지 기다리면: `fb_open 반환까지 134.4 s, 출력 'OPEN -3'` (로그 `originator connect failed (-110)`).

**기대값과 출처:**
- 독립 구현 EIPScanner `src/sockets/TCPSocket.cpp:46-90` — non-blocking `connect` + `select(connTimeout)`, 넘으면 `ETIMEDOUT`
  (`SessionInfo` 기본 1000 ms, `SessionInfo.cpp:37-39`).
- pycomm3 `socket_.py:36-45` — `settimeout(5.0)` 뒤 `connect` (5 s 에 실패).
- 저장소 선례: T9-5 (Modbus 클라이언트 non-blocking connect) 를 결함으로 큐에 넣었다.

**수정 범위:** `stacks/ethernetip/` (+ `tests/`). non-blocking connect + `poll`/`select` 타임아웃 (RegisterSession 과 같은 2 s 또는 설정값),
`SO_ERROR` 확인. A20261025-3 의 재연결도 같은 함수를 쓰므로 재연결 시 사이클을 막지 않게 된다.

**완료 조건:** `test_originator_connect_has_timeout` 통과 (`A20261025-5` 표시 삭제: 10 s 안에 `OPEN <음수>`).

## 확인 필요 (큐에 넣지 않음)

1. **Originator RegisterSession 응답을 검사하지 않는다** (`eip_stack.c:339-348`: Command·Status 무시, 받은 바이트 수 24 이상이면 핸들 저장).
   대상이 `0x0069` 로 거절해도 `eip_stack_start` 는 0 을 돌려주고 "originator connected" 로그를 남긴다 (이후 요청은 세션 0 이라 `-ENOTCONN`).
   EIPScanner `SessionInfo.cpp:28-31`·pycomm3 는 거절로 본다. 다만 입문서 9.5 표에 "응답 status 확인 안 함" 으로 이미 적혀 있고 실해(health 는 0)가
   작아 이번 5개에서 뺐다. A20261025-2/-3 PR 에서 같이 고치기 좋다.
2. **Originator 역할에서 Assembly 주소 포인트가 조용히 성공한다.** Class 1 Originator 가 없어(입문서 9.5) 그 포인트의 쓰기는 로컬 이미지에만
   들어가고 읽기는 0 을 rc 0 으로 돌려준다. 거부(init 경고·`-ENOTSUP`)가 맞아 보이지만 독립 근거가 없다.
3. **연결이 끊긴 뒤 출력 이미지가 마지막 Run 값으로 남는다** (지난 라운드 확인 필요 2 의 어댑터 쪽). `eip_read_point` (`ethernetip_adapter.c:931-933`)
   는 연결 상태와 무관하게 출력 Assembly 를 읽고, 앱이 끊김을 구분할 방법은 `fb_health` 뿐이다. OpENer 는 앱 콜백에 맡겨 근거가 되지 못한다.
4. **scale 쓰기 값이 타입 범위를 넘으면 감싸서 보낸다** (`eip_encode_number` `:391-419`: uint16 scale 0.1 에 공학값 7000 → 원시 70000 → 4464,
   음수 → 65526, NaN 은 정의되지 않은 변환). Modbus 어댑터(`llround`)도 같아 관례로 판정할 수 없다. 포화/거부 중 무엇이 맞는지 담당자 결정 필요.
5. **`access` 문자열 해석이 코어와 다르다.** 코어는 대소문자 무시 + `w` 별칭(`core/fb_api.c:258-270`), 어댑터는 `strcmp(…, "write")`
   (`:747`, `:839`). `"Write"`/`"w"` 포인트는 코어에선 PLC 쓰기(앱 쓰기 금지)인데 어댑터는 입력 이미지에서 읽어 스캐너 출력을 앱이 못 본다.
   스키마 설명은 소문자 `read|write|readwrite` 뿐이라 결함 근거가 약하다.
6. **`major_rev` 를 설정할 수 없다** (`ethernetip_adapter.c:557` 고정 1, `minor_rev` 만 파싱). 문서화된 키가 아니고 EDS `MajRev = 1` 과 맞아 실해 없음.
7. **Originator explicit Get 이 포인트 `length` 보다 긴 속성 값을 조용히 자른다** (`eip_client.c:133-136`). DINT 속성을 uint16 포인트로 잡으면
   하위 2바이트를 rc 0 으로 준다. 설정 오류를 알릴지(경고) 판단 필요.

## 재현 명령

```
cmake -S . -B build -DBUILD_DAEMON=ON -DBUILD_API=ON -DBUILD_CTT=ON -DENABLE_EIP_TESTS=ON -DBUILD_ORACLE_DUTS=ON
cmake --build build -j8
# oracle_additions.py 를 tests/oracle/test_eip_oracle.py 끝에 붙인 뒤
ORACLE_BUILD_DIR=build python -m pytest tests/oracle/test_eip_oracle.py -q
    → 34 passed, 49 xfailed (새 8개 포함, XPASS·FAIL 없음)
ORACLE_BUILD_DIR=build python -m pytest tests/oracle/test_eip_oracle.py --runxfail -q \
    -k "peer_close or late_reply or reconnects_after or defaults_on_wire or without_length_read or connect_has_timeout"
    → 8 failed (A20261025-1 ×1, -2 ×1, -3 ×1, -4 ×4, -5 ×1)
```

교차 XPASS 주의: A20261025-3 테스트는 지금 SIGPIPE(-1)와 재연결 없음(-3) 두 이유로 실패한다. -1 만 고치면 계속 실패(재연결 없음)하고,
-3 을 고치면(끊김 감지 후 재연결) 죽은 소켓에 다시 쓰지 않으므로 -1 의 어댑터 쪽 테스트에는 영향이 없다. -2 를 "타임아웃이면 연결을 닫고
재연결" 로 고치면 -3 의 재연결 코드가 생길 수 있다 — 그러면 같은 PR 에서 -3 표시도 지운다 (허용).
