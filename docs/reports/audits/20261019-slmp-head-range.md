# 감사 2026-10-19 — SLMP 선두 디바이스 번호 3바이트 범위, `device_code` + 같은 접두사 `start`

- 영역: SLMP 스택·어댑터 (11단계 제안 선별, #138 검증)
- 출처: PR #138 (T10-3) "발견한 다른 문제" 1, #138 검증 중 회귀 확인
- 기준 커밋: `a80892f` (main, #137 병합 직후)
- 판단: 검증 담당 (루틴 직접, pymcprotocol·오라클 하네스 재현)
- 큐 추가: 1개 (A20261019-1 → 큐 90). 회귀 방지 오라클 1개 (표시 없음)

## A20261019-1. 클라이언트가 0xFFFFFF 를 넘는 선두 디바이스 번호를 24비트로 잘라 보낸다

**문제:** Binary 3E 의 선두 디바이스 번호는 3바이트다. 스택 클라이언트 인코더는 `uint32_t head` 를 범위 검사 없이 `wr_le24` 로 쓰므로,
`0x1000005` 를 요청하면 PLC 는 선두 번호 `5` 를 받는다. 응답은 정상이라 앱은 D16777221 을 읽었다고 믿지만 실제로는 D5 값이다
(쓰기면 다른 디바이스를 덮어쓴다). 어댑터의 JSON 숫자 `start` 경로도 상한을 보지 않고 `(uint32_t)` 로 넘긴다 (문자열 경로는 #138 이후
`0xFFFFFF` 초과를 거절).

**근거 (파일:줄, 기준 커밋 `a80892f`):**
- `stacks/slmp/src/slmp_stack.c:113` `wr_le24`, `:509` (batch read), `:575` (batch write) — `range->addr.head` 를 그대로 3바이트로 기록.
- `adapters/slmp/slmp_adapter.c:183-184` — `else if (have_num) { head = (uint32_t)start_num; }` (상한 없음).

**재현:** `tests/oracle/test_slmp_oracle.py::test_client_head_above_24bit_rejected` 를 `--runxfail` 로 돌린다
(DUT `slmp_oracle_client --start 16777221`, PLC 역할 `SpecPlc` 는 워드 n 을 `0x1000 + n` 으로 답한다).

```
AssertionError: 3바이트 범위 밖 선두 번호를 잘라 보냄: ['READ', '16777221', '0', '1005']
(값 0x1005 = 0x1000 + 5 → PLC 가 받은 선두 번호는 5)
```

**기대값과 출처:**
- 독립 구현 pymcprotocol `Type3E._make_devicedata` — 3E 선두 번호를 `to_bytes(3, "little")` 로 쓰며 `D16777221` 은
  `OverflowError: int too big to convert` (인코딩 거부). `D16777215` 는 `ffffffa8`.
- Mitsubishi SLMP Reference Manual (Binary 3E, 서브커맨드 0000/0001): 선두 디바이스 번호 3바이트 — 오라클 주석 `test_client_stack_reads_high_device_numbers` 와 같은 기준.

**수정 범위:** `stacks/slmp/`, `adapters/slmp/`, `tests/`.
- 스택 클라이언트 인코더(읽기·쓰기)는 `head > 0xFFFFFF` (또는 `head + 점수 - 1 > 0xFFFFFF`) 면 보내지 않고 `-ERANGE`.
- 어댑터 숫자 `start` 도 문자열 경로와 같이 `0xFFFFFF` 초과·음수면 `LOG_ERROR` 후 init 실패.
- T10-3 (#138, 큐 27) 이 같은 함수(`parse_device_head`)를 고치므로 그 PR 병합 뒤에 한다.

**완료 조건:** `test_client_head_above_24bit_rejected` 통과 (`A20261019-1` 표시 삭제). 단위 테스트로 숫자 `start` 16777216 의 init 실패를 보인다.

## 회귀 방지 테스트 (큐 항목 아님)

`test_adapter_device_code_with_same_prefix_start` — `{"device_code": "B", "start": "B1"}` 은 B 1번이어야 한다 (MELSEC 표기 `B1`,
pymcprotocol `headdevice="B1"` = B 0x1). main 은 통과한다. #138 (`58736b7`) 은 `device_code` 가 있으면 `start` 전체를 그 디바이스의
번호로 먼저 읽어서, 이름이 16진 숫자인 `B` 에서 `"B1"` 이 `0xB1` 이 된다:

```
main  a80892f : B0 워드 = 0x0002 (B 1번)
#138  58736b7 : B0B0 워드 = 0x0002 (B 0xB1번)  → AssertionError
```

#138 검증 코멘트에서 FAIL 사유로 알렸다. 표시 없는 테스트라 #138 이 이 동작을 고치지 않으면 그 PR 의 oracle job 이 실패한다.
