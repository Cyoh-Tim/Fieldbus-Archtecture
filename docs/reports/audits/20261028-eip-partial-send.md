# 감사 2026-10-28 — EIP TCP·TLS 응답의 짧은 send / EAGAIN 을 성공으로 본다

- 영역: EtherNet/IP 스택 (11단계 제안 선별)
- 출처: PR #164 (A20261025-1) "발견한 다른 문제"
- 기준 커밋: `e194134` (main, #164 병합 직후)
- 판단: 검증 담당 (루틴 직접, 오라클 재현 + OpENer 소스 대조)
- 큐 추가: 1개 (A20261028-1 → 큐 99)

## A20261028-1. 송신 버퍼가 차면 응답이 빠지고 잘린 프레임이 스트림에 들어간다

**문제:** 어댑터는 accept 한 TCP 소켓과 TLS 소켓을 nonblocking 으로 두고, 응답을 `send`/`SSL_write` 한 번으로 보낸다.
반환값이 응답 길이보다 짧거나 `EAGAIN`/`SSL_ERROR_WANT_WRITE` 이면 남은 바이트를 버리고 다음 요청으로 넘어간다.
스캐너가 잠시 읽지 않아(부하, GC, 디버거 정지, 느린 링크) 커널 송신 버퍼가 차면

- 응답 일부가 통째로 빠진다 (요청-응답 짝이 어긋나 스캐너는 시간 초과 뒤 재시도),
- 한 응답의 앞부분만 나가고 다음 응답이 바로 붙는다. encapsulation 헤더의 길이와 실제 바이트가 달라
  스캐너는 프레임 경계를 잃고, 그 TCP 세션의 이후 응답을 모두 잘못 해석한다.

연결은 끊지 않으므로 스캐너는 깨진 스트림 위에서 계속 기다린다.

**근거 (파일:줄, 기준 커밋 `e194134`):**
- `stacks/ethernetip/src/eip_stack.c:514` — accept 한 클라이언트를 `set_nonblock`.
- 같은 파일 `:599-603` `service_tcp_client` — `w = send(…, MSG_NOSIGNAL)`. `EPIPE`/`ECONNRESET` 만 처리하고, `0 <= w < resp_len`
  과 `EAGAIN` 은 그대로 다음 요청으로 간다.
- `stacks/ethernetip/src/eip_sec.c:520-521` — `SSL_MODE_ENABLE_PARTIAL_WRITE`. `:589-597` 은 `w < resp_len` 이나
  `SSL_ERROR_WANT_WRITE` 에서 나머지를 다시 쓰지 않는다 (TLS 레코드가 잘리지는 않지만 응답 바이트가 빠진다).
- `stacks/ethernetip/src/eip_client.c:82` `originator_sendrr` — 요청 `send` 의 반환값이 0 이상이면 길이를 보지 않는다
  (`originator_fd` 도 nonblocking, `eip_stack.c:313`). 요청이 작아 재현은 못 했고 코드로만 확인했다.

**재현 (오라클, DUT `eip_oracle_adapter`):** `tests/oracle/test_eip_oracle.py::test_slow_reader_gets_every_reply_intact`
를 `--runxfail` 로 돌린다. ListIdentity 200000개를 파이프라인하고 (클라이언트 `SO_RCVBUF` 4096) 2 s 뒤에 읽는다.

```
AssertionError: 응답 36025 개 뒤 잘린 프레임: 6c6530300000000001000c00300001000002dcd17f0000010000000000000000
```

`…6c6530 30` 은 ListIdentity 응답 product name 의 뒷부분이다 — 앞 응답의 꼬리만 나간 자리에 다음 프레임이 붙었다.
스크래치 하네스로 같은 흐름을 읽기만 계속하면 요청 200000개에 온전한 응답 50055개, 그 뒤 잘린 프레임, 연결은 유지, DUT 는 살아 있다.

**기대값과 출처:**
- 독립 구현 OpENer (`d8820ef`) `source/src/ports/generic_networkhandler.c` — listener 만 `SetSocketToNonBlocking` (`:166`) 하고
  `accept` 한 소켓(`:419`)은 그대로 blocking 이다 (Linux 의 `accept` 는 `O_NONBLOCK` 을 물려주지 않는다). 그래서 `:889-892` 의
  `send(…, MSG_NOSIGNAL)` 은 응답을 다 쓰거나 실패한다. 잘린 프레임이 스트림에 들어갈 경로가 없다.
- encapsulation 은 TCP 스트림 위의 길이 접두 프레임이라, 잘린 프레임 하나로 그 세션의 이후 프레임을 모두 잘못 읽는다
  (사양 원문 직접 인용 못 함 — OpENer 동작과 프레임 형식을 판정 근거로 쓴다).
- 같은 저장소 Modbus 스택의 같은 종류 항목 T9-8 (큐 52): "송신 버퍼에 남겨 두고 다음 poll 에서 재시도". 오라클
  `test_slow_reader_keeps_connection` 과 같은 기준을 쓴다.

**수정 범위:** `stacks/ethernetip/`, `tests/`.
- 클라이언트별 송신 대기 버퍼를 둔다. 짧은 `send`·`EAGAIN` 이면 남은 바이트를 넣고, 다음 poll 에서 소켓이 쓰기 가능할 때 먼저 비운다.
- 대기 바이트가 있는 동안에는 그 클라이언트의 다음 요청을 처리하지 않는다 (수신 버퍼에 둔다 — 순서 유지, 메모리 상한).
  대기 버퍼가 넘칠 상황이면 연결을 끊는다 (잘린 프레임을 보내는 것보다 낫다).
- TLS 경로도 같다: `SSL_write` 의 나머지와 `WANT_WRITE` 를 대기 버퍼로 (OpenSSL 재시도 규칙: 같은 데이터로 다시 호출).
- `originator_sendrr`: 요청을 다 보낼 때까지 쓰기 가능 대기(타임아웃 안)로 반복하거나, 짧으면 `-EIO`.
- 이벤트 구동(`wait_fds`, 큐 74)을 쓰게 되면 대기 바이트가 있는 fd 는 `POLLOUT` 도 기다린다. 지금은 poll 주기 재시도로 충분하다.

**완료 조건:** `test_slow_reader_gets_every_reply_intact` 통과 (`A20261028-1` 표시 삭제), `test_peer_close_does_not_kill_adapter`
등 기존 EIP 오라클 그대로. 단위 테스트로 TLS 경로의 부분 쓰기(작은 `SO_SNDBUF`)도 보인다.

## 선별 결과 (큐에 넣지 않음)

- #164 의 BIO 메서드 참조 수(`g_nosig_users`) 잠금 없음: 프로세스당 스택 하나라 지금은 결함 아님. 이 보고서에만 남긴다.
