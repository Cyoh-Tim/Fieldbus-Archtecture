# 감사 2026-10-12 — 보류했던 "확인 필요" 두 건 (SLMP 감시 타이머 대기, EIP Forward Close 출발지)

- 영역: SLMP 클라이언트 (20261011-slmp.md "확인 필요" 1) · EtherNet/IP CM (PR #118 선별 코멘트의 "확인 필요")
- 출처: 저장소 담당자 요청 (2026-10-12, "좀 더 알아보자")
- 기준 커밋: `e2e6682` (main)
- 판단: opus 하위 에이전트 2개 (참조 구현·사양 발췌 조사 + 스크래치 재현) → 검증 담당이 재현을 직접 다시 돌려 확인
- 큐 추가: 2개 (A20261012-1 → 큐 77, A20261012-2 → 큐 78)

## A20261012-1. SLMP 클라이언트 응답 대기가 감시 타이머와 같아 모듈의 만료 이상 응답을 받지 못한다

**문제:** `slmp_stack_create` 는 `timeout_ms` 가 감시 타이머보다 **짧을 때만** 감시 타이머 값으로 올린다. 그래서 응답 대기가
감시 타이머와 같아진다 (기본 0x0010 = 4 s). 감시 타이머는 요청을 받은 모듈이 접근 대상에 처리를 넘기면서 시작하므로,
모듈이 만료 시 보내는 이상 응답은 클라이언트 송신 뒤 항상 "타이머 + 왕복" 이후에 온다. 클라이언트는 그 직전에
`-ETIMEDOUT` 으로 포기하고, T10-2 규칙대로 소켓을 닫고 백오프한다. 그 결과
- PLC 의 엔드 코드(원인)를 잃고 "타임아웃" 으로만 보인다.
- 연결 폐기·백오프·재접속이 불필요하게 일어난다 (다음 요청은 `-EAGAIN`).
- 같은 이유로 `connect()` 대기도 감시 타이머 값(4 s)으로 부풀려져 있다 (같은 `cfg.timeout_ms` 를 쓴다).

데이터 손상은 없다 (T10-2 가 타임아웃 시 소켓을 닫아 늦은 응답 오인을 막는다). 자국 CPU 직결에서는 드물고,
타국 경유(`network_no`/`pc_no` 지정)나 PLC 고부하에서 생긴다.

**근거 (파일:줄, 기준 커밋 `e2e6682`):**
- `stacks/slmp/src/slmp_stack.c:284-294` — 주석은 "the client gives up before the PLC's own timeout reply" 를 막으려 하지만
  비교가 `timeout_ms < monitor_ms` 라 같은 값을 허용하고, 올릴 때도 `timeout_ms = monitor_ms` (여유 없음).
- 같은 파일의 응답·connect 대기가 모두 이 `cfg.timeout_ms` 를 쓴다 (`wait_fd`/`recv_exact`, connect 경로).
- 저장소 문서는 "길게" 를 요구한다: 인수인계 T10-2 수정 방향 "소켓 타임아웃은 감시 타이머보다 길게 잡는다"
  (`docs/reports/structure_handoff_20260930.md:389`), `docs/protocols/slmp.md` 6.4 "소켓 타임아웃 > 감시 타이머", 6.5 "0.5~1 초 길게".
- 단위 테스트 `tests/test_slmp_stack.c` 는 반대로 "같은 값이면 그대로" 를 기대한다 (함께 고칠 대상).

**재현 (수정 전, `slmp_oracle_client` + 사양 기반 가짜 모듈):** 가짜 모듈이 요청의 타이머 필드(오프셋 9-10)를 읽고 첫 요청에만
`타이머 × 250 ms + late` 뒤 엔드 코드 `C0B5` + 에러 정보 9 B 로 답한다.

```
main       timer=0x0010 late +0.05s: read1 rc -110, read2 rc -11 (backoff), accepts 1 -> FAIL
main       timer=0x0010 late +0.15s: read1 rc -110, read2 rc -11, accepts 1          -> FAIL
main       timer=0x0010 late +0.5s : read1 rc -110, read2 rc -11, accepts 1          -> FAIL
+1 s 패치  (같은 세 경우)            : read1 rc -5 (엔드 코드), read2 rc 0, accepts 1   -> PASS
```

오라클 `test_slmp_oracle.py::test_client_waits_past_monitoring_timer_for_abnormal_response` 를 `--runxfail` 로 돌린 결과:

```
AssertionError: ([(1, -110, 0), (2, -11, 0)], 1, [16])
```

대조군 `test_client_receives_abnormal_response_before_monitoring_timer` (타이머 0.3 s 전에 이상 응답) 는 지금도 통과한다 (`-5`, `0`, 연결 1개).

**기대값과 출처:**
- 클라이언트 대기 > 감시 타이머. 유한 타이머와 유한 대기를 함께 쓰는 공개 클라이언트 5개가 모두 그렇다:
  pymcprotocol 0.3.0 (`type3e.py:80-82` "socket timeout is always set timer+1sec. To recieve Timeout answer", +1 s),
  gomcprotocol (+1 s), node mcprotocol (`globalTimeout` 4500 ms vs 타이머 4 s, +0.5 s), HslCommunication Python (+7.5 s),
  pymelsec (+1 s, pymcprotocol 파생). 같게 두는 구현은 없었다. (PLC4X 는 타이머 0 = 무한으로 두고 자체 타임아웃만 쓴다.)
- Mitsubishi 매뉴얼 발췌 (FX5 SLMP JY997D56001, RJ71C24 MC SH-080008): 감시 타이머는 요청을 받은 장치가 접근 대상에 처리를
  요청한 뒤 응답까지 기다리는 시간이고 250 ms 단위, `0000H` 는 무한 대기. "응답이 오지 않으면 감시 타이머 경과 후 재송신" —
  즉 사양은 무응답 가능성도 전제한다. 만료 시 엔드 코드 값은 확인하지 못했다 (오라클은 특정 값에 의존하지 않는다).
  매뉴얼 원문 PDF 는 이 환경에서 열지 못했고 검색 발췌만 봤다.

**수정 범위:** `stacks/slmp/`, `tests/`, `docs/slmp_stack.md`.
- 응답 대기 = `max(timeout_ms, monitor_ms + 1000)`. connect 대기는 사용자 `timeout_ms` 그대로 (`cfg.timeout_ms` 를 덮어쓰지 말고
  내부 값으로 따로 둔다).
- 감시 타이머 0 → 0x0010 치환은 유지. 엔드 코드 ≠ 0 → `-EIO`·연결 유지·`LOG_WARN` 은 지금처럼. 여유 안에 응답이 없으면
  지금처럼 `-ETIMEDOUT`·연결 폐기·백오프.
- `tests/test_slmp_stack.c` 의 "같으면 그대로" 기대와 `docs/slmp_stack.md` 의 대기 설명을 고친다.

**완료 조건:** `test_client_waits_past_monitoring_timer_for_abnormal_response` 통과 (`A20261012-1` 표시 삭제), 대조군 그대로.
연결 불가 상대의 connect 대기가 사용자 `timeout_ms` 로 돌아온 것을 단위 테스트로 보인다.

**T3·구동 모델과의 관계:** 여유 +1 s 는 응답 없는 PLC 에서 한 번의 블로킹을 4 s → 5 s 로 늘린다. 반대로 connect 대기를 사용자
`timeout_ms` 로 되돌리면 도달 불가 PLC 에서는 4 s → 1 s 로 준다. 블로킹 자체(코어 잠금을 잡은 채 동기 트랜잭션)는 큐 25 (T3)·
74~76 (구동 모델) 의 몫이고 이 항목과 독립이다. 감시 타이머 기본값을 낮출지는 그때 함께 정한다 (CTT 가 0x0010 을 고정하고 있음).

## A20261012-2. EIP Forward Close 가 다른 IP 에서 와도 triad 만 맞으면 남의 Class 1 연결을 닫는다

**문제:** `eip_cm_forward_close` 는 triad(Connection Serial, Originator Vendor, Originator Serial)로만 연결을 찾고 닫는다.
Forward Open 을 보낸 originator 의 IP 를 기록하지 않아서, 44818/TCP 에 닿는 다른 호스트가 triad 를 맞춰 Forward Close 를
보내면 스캐너의 Class 1 연결이 끊긴다 (출력 정지·안전 상태 전환, 반복하면 DoS). triad 는 추측이 쉽다: Vendor ID 는 공개 값,
Originator Serial 은 ListIdentity 로 읽히고, Connection Serial 은 16비트이며 응답이 `0x0107`(없음)과 성공으로 갈려 맞았는지
알려 준다. 실제 스캐너 연동 설정은 `security_class 0` 이라 HMAC 보호도 없다 (`config/example.codesys.ethernetip.json`).

**근거 (파일:줄, 기준 커밋 `e2e6682`):**
- `stacks/ethernetip/src/eip_cm.c:352` `eip_cm_forward_close` — peer 정보를 받지 않고 triad 비교만 한다.
- `stacks/ethernetip/src/eip_io.c:57` — 연결의 `peer_ip` 는 Forward Open 때가 아니라 첫 O→T UDP 패킷에서 채워진다.

**재현 (수정 전, `eip_oracle_adapter`, raw CIP):** 127.0.0.1 세션이 Forward Open (mult 7, 워치독 약 10 s) → 127.0.0.2 에서
연 세션이 같은 triad 로 Forward Close → 원 세션이 같은 triad 로 Forward Open 을 다시 보내 중복(`0x0100`)인지 본다.

```
다른 IP FC 응답 ce00000001013713bebafeca0000   (성공, 연결 닫힘)
중복 FO 응답   d4000000…                        (0x0100 이 아니라 새 연결로 성공)
```

오라클 `test_eip_oracle.py::test_forward_close_from_other_ip_rejected` 를 `--runxfail` 로 돌린 결과:
`AssertionError: 연결이 닫힘 (다른 IP FC 응답 ce000000…, 중복 FO 응답 d4000000…)`.
대조군 `test_forward_close_same_ip_new_session_allowed` (같은 IP 의 새 TCP 세션) 는 지금도 통과한다.

**기대값과 출처:**
- 독립 Target 구현 두 곳이 같은 검사를 한다: OpENer `source/src/cip/cipconnectionmanager.c` ForwardClose — Forward Open 때 기록한
  originator IP 와 TCP peer IP 가 다르면 연결을 닫지 않고 General **0x0F** (`WrongCloser`), 추가 상태 없음, triad 꼬리는 붙임.
  CIPster `cipconnectionmanager.cc` — 주석 "Vol2 3-3.10 Forward_Close" 와 함께 `kCipErrorPrivilegeViolation` (0x0F).
- CIP Vol 2 §3-3.10 원문은 이 환경에서 열지 못했다 (CIPster 주석의 인용만). 신뢰도 중간 — 담당자가 원문을 보면 높음으로 올릴 수 있다.
- 세션(TCP 연결) 일치는 요구하지 않는다: 스캐너가 TCP 를 다시 맺어 Forward Close 를 보내는 것은 정상이고, 이 스택도 TCP 가
  끊겨도 Class 1 을 유지한다. 그래서 검사는 IP 단위다 (OpENer 와 같음).

**수정 범위:** `stacks/ethernetip/`, `tests/`. **큐 22 (T11-6, #114) 이후** — T11-6 도 Forward Open 시점의 originator IP 기록이
필요하므로 그 필드를 그대로 쓴다.
- Forward Open 성공 시 TCP/TLS peer IP 를 연결에 저장 (`eip_encap_process` → `eip_cip_route_auth` → `eip_cm_*` 로 전달).
- Forward Close 에서 triad 는 맞고 IP 가 다르면 연결을 두고 `CE 00 0F 00` + triad + `00 00`, `LOG_WARN`.
- peer IP 를 모르는 경로(mock)는 검사를 건너뛴다. triad 가 없으면 지금처럼 `0x01/0x0107`.

**완료 조건:** `test_forward_close_from_other_ip_rejected` 통과 (`A20261012-2` 표시 삭제), 대조군과 `0x0107` 경로 그대로.

## 확인 필요 (큐에 넣지 않음)

1. **SLMP 만료 엔드 코드 값과 응답 보장 여부.** 사양 발췌는 무응답도 전제한다. 실 PLC 캡처(타국 경유 또는 타이머 1 + 부하) 한 번이면 확정된다.
2. **EIP 중복 Forward Open 검사 순서.** 지금은 경로 → 크기 → 중복 순이라 크기가 틀린 중복 FO 가 `0x0100` 대신 `0x0109` 를 받는다.
   OpENer·CIPster 는 중복을 먼저 본다. 어느 오류가 이기는지 정한 사양 문구는 찾지 못했고, 정상 재전송은 어느 순서든 `0x0100` 이다.
   결함 아님 — T11-5/T11-7 을 고칠 때 검사 순서를 함께 정리하면 된다.
3. **Forward Close 경로 불일치(`0x0316`).** 선택 사항 (CIPster 도 "spec says this is optional" 로 꺼 둠).

## 문서

- `docs/protocols/ethernetip.md:1351-1352` 가 아직 "triad 가 없어도 **성공**" 이라고 쓴다 (#118 이후 `0x01/0x0107`). 큐 70 (문서) 비고에 추가.
