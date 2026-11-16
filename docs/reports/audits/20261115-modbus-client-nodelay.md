# 2026-11-15 — Modbus 클라이언트 소켓의 TCP_NODELAY (#211 선별)

- 영역: Modbus 스택 (11단계 제안 선별)
- 출처: #211 (T9-7) "발견한 다른 문제" 1
- 기준 커밋: `00a7a53` (main, #211 병합 직후)
- 판단: 검증 담당 (루틴 직접, 코드 확인)
- 큐 추가: 1개 (A20261115-6 → 큐 132)

## A20261115-6. Modbus 클라이언트 연결 소켓에 `TCP_NODELAY` 가 없다 (낮음)

**문제:** #211 은 서버가 accept 한 소켓에만 `TCP_NODELAY` 를 켰다. 클라이언트 역할의 연결 소켓은 그대로라, 클라이언트가 작은 요청을 연달아
보내면 (쓰기 직후 읽기 등) 두 번째 요청이 서버의 지연 ACK 까지 Nagle 에 묶일 수 있다.
**근거:** `stacks/modbus/src/mb_stack.c:591` `client_connect` — `socket()` 뒤 `TCP_NODELAY` 설정 없음 (`00a7a53`).
`docs/protocols/modbus.md` 6.3 과 체크리스트 10 이 서버·클라이언트 모두 켜라고 한다.
**기대값과 출처:** 서버 쪽과 같은 근거 (T9-7, 오라클 `test_pipelined_responses_not_delayed_by_nagle`). 클라이언트 쪽 오라클은 pymodbus 서버를 상대로
파이프라인 요청 지연을 재는 형태가 되는데, 클라이언트 스택은 요청을 하나씩 기다려 보내므로(파이프라인 없음) 지연이 드러나는 경로가 좁다 — 그래서 낮음.
**수정 범위:** `stacks/modbus/`, `tests/`. **완료 조건:** 연결 직후 소켓에 `TCP_NODELAY` 가 켜졌는지 `getsockopt` 로 보는 단위 테스트.
