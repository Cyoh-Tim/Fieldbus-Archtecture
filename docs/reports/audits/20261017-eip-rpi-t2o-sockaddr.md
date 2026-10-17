# 감사 2026-10-17 — EIP 어댑터 최소 RPI 와 cycle_ms, P2P T→O Sockaddr 의 주소

- 영역: EtherNet/IP 어댑터 · 스택 (11단계 제안 선별)
- 출처: PR #131 (T5 EIP) "발견한 다른 문제" 1, PR #126 (T11-6) 검증 중 OpENer 대조
- 기준 커밋: `9a2abc2` (main, #126·#131 병합 직후)
- 판단: 검증 담당 (루틴 직접, 오라클 재현 + OpENer 소스 대조)
- 큐 추가: 2개 (A20261017-1 → 큐 82, A20261017-2 → 큐 83)

## A20261017-1. 어댑터의 장치 최소 RPI 가 `cycle_ms` 를 따르지 않는다

**문제:** T5 (EIP, #131) 로 스택은 `eip_cfg_t.rpi_us` 보다 짧은 RPI 를 `0x01/0x0112` 로 거절하고, 수락한 RPI 는 그 배수로 올려
API 에 넣는다. 그런데 어댑터는 `rpi_us` 를 `protocol_params.rpi_us` (없으면 8000) 에서만 정하고 `cycle_ms` 는 보지 않는다.
`cycle_ms` 16 에 `rpi_us` 를 생략하면 8000 µs Forward Open 을 수락하고 API 8000 을 돌려주지만, 데몬은 16 ms 마다
`poll_cycle` 을 돌리므로 실제 생산 간격은 16 ms 다. 스캐너는 실제보다 두 배 빠른 주기를 믿는다.

**근거 (파일:줄, 기준 커밋 `9a2abc2`):**
- `adapters/ethernetip/ethernetip_adapter.c:553` — `cfg.rpi_us = 8000;`
- 같은 파일 `:652-654` — `protocol_params.rpi_us` 만 읽는다. `cycle_ms` 를 쓰는 곳이 없다.
- 인수인계 T5 (`docs/reports/structure_handoff_20260930.md:225-259`) — "최소 RPI(= `cycle_ms`)", 거절 시 "`cycle_ms×1000`",
  EDS RPI Param min = `cycle_ms×1000`. 오라클 `test_eds_rpi_param_minimum_matches_cycle` 도 같은 기준.

**재현:** `tests/oracle/test_eip_oracle.py::test_adapter_min_rpi_follows_cycle_ms` 를 `--runxfail` 로 돌린다.

```
AssertionError: 수락 또는 다른 응답: d4000000010000200101007e01013713bebafeca401f0000401f00000000
(성공 응답 0xD4/0x00, O→T·T→O API 0x00001F40 = 8000 µs)
```

대조군 `test_adapter_min_rpi_from_rpi_us_param` (`rpi_us` 16000 명시) 은 통과한다 — 어댑터→스택 경로 자체는 맞다.

**기대값과 출처:** 장치 최소 RPI = `cycle_ms×1000` (`rpi_us` 를 더 크게 주면 그 값). 인수인계 T5 와 EDS 기준.

**수정 범위:** `adapters/ethernetip/`, `tests/`. 스키마·예제 config 에 `rpi_us` 설명이 있으면 같이.
- `cfg.rpi_us = max(cycle_ms×1000, protocol_params.rpi_us)`. `rpi_us` 가 `cycle_ms×1000` 보다 작으면 `LOG_WARN` 후 올린다.
- 코어는 바꾸지 않는다 (`cycle_ms` 는 어댑터가 config 에서 직접 읽는다).

**완료 조건:** `test_adapter_min_rpi_follows_cycle_ms` 통과 (`A20261017-1` 표시 삭제), 대조군 그대로.

## A20261017-2. P2P T→O Sockaddr Info 의 sin_addr 을 생산 목적지로 쓴다

**문제:** T11-6 (#126) 은 Forward Open 의 `0x8001` Sockaddr Info (T→O) 로 생산 목적지를 정한다. 그 항목의 **주소와 포트 둘 다** 쓴다.
- sin_addr 이 `0.0.0.0` 이면 항목 전체를 버리고 Originator:2222 로 보낸다 — 요청한 포트를 무시한다.
- sin_addr 이 Originator 가 아닌 다른 호스트면 그쪽으로 생산한다. TCP 세션을 연 쪽이 제3의 호스트로 주기 트래픽을 보내게 할 수 있다.

point-to-point T→O 에서 목적지 주소는 Forward Open 을 보낸 Originator 이고, Sockaddr 은 포트만 준다.

**근거 (파일:줄, 기준 커밋 `9a2abc2`):**
- `stacks/ethernetip/src/eip_encap.c:40-49` `rd_sockaddr_to` — `*port == 0 || *ip_host == 0` 이면 -1 (항목 무시).
- `stacks/ethernetip/src/eip_cm.c:543` `eip_cm_forward_open` — `c->peer_ip = s->rr_t2o_ip;` (Sockaddr 주소를 그대로 목적지로).

**재현:** `tests/oracle/test_eip_oracle.py` 의 두 테스트를 `--runxfail` 로 돌린다.

```
test_t2o_sockaddr_zero_addr_uses_port   AssertionError: sin_addr 0 + 포트로 T→O 가 오지 않음
test_t2o_sockaddr_other_addr_ignored    AssertionError: Originator(127.0.0.1) 의 그 포트로 T→O 가 오지 않음
```

대조군 `test_t2o_produced_to_sockaddr_without_o2t` (sin_addr = Originator 주소) 는 통과한다.
같은 포트를 `127.0.0.2` 에도 열어 두면 T→O 는 그쪽(sin_addr 의 호스트)으로 온다 (스크래치 확인).

**기대값과 출처:**
- 독립 구현 OpENer (`d8820ef`) `source/src/cip/cipioconnection.c` `OpenProducingPointToPointConnection` (`:443-462`):
  포트는 `0x8001` 항목의 `sin_port` (없으면 2222), 주소는 항상 `GetPeerAddress()` (Forward Open 을 보낸 TCP 피어).
- 사양 원문(CIP Vol 2 2-6.3.3 의 P2P 에서 sin_addr 처리)은 직접 인용하지 못했다 — OpENer 를 판정 근거로 쓴다.

**수정 범위:** `stacks/ethernetip/`, `tests/`.
- P2P T→O: 목적지 주소 = Originator (`rr_originator_ip`), 포트 = `0x8001` 의 `sin_port` (0 이면 2222). sin_addr 은 보지 않는다.
- Originator 주소를 모르는 경우(mock)는 지금처럼 첫 O→T 에서 배운다.

**완료 조건:** 두 테스트 통과 (`A20261017-2` 표시 삭제), 대조군과 T11-6 테스트 그대로.

## 선별 결과 (큐에 넣지 않음)

- #131 제안 2 (`eip_cm.c` 성공 응답 길이 `need` 26/30): 이미 A20261015-1 (큐 81).
- #131 제안 3·4 (입문서의 "RPI 에코·범위 안 봄" 서술 `docs/protocols/ethernetip.md:1298`, `:1544`, `:1605`, `:2554`,
  `docs/ctt_eip_bundle.md` 의 `EIP-A-CM-005` 행 없음): 문서 — 큐 70 비고에 추가.
- #131 제안 5 (`tests/fuzz/fuzz_eip_io.c:419` 의 1 µs RPI 연결이 이제 거절돼 워치독 경로를 못 탐): 퍼저 커버리지 문제,
  결함 아님. 큐 70 비고가 아니라 이 보고서에만 남긴다. 다음에 fuzz 하네스를 고치는 항목이 생기면 함께 (RPI 를 8000 이상으로).
- #126 제안 (`poll_cycle` 느린 경고 로그): VM 타이밍. 항목 없음.
