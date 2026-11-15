# 2026-11-14 — SLMP 워드 맵 범위 검사의 32비트 덧셈 넘침 (#208 선별), 큐 71 비고

- 영역: SLMP 스택 (11단계 제안 선별)
- 출처: #208 (T10-6) "발견한 다른 문제", #208 `[Claude 확인 요청]` 답
- 기준 커밋: `7c05f46` (main, #208 병합 직후)
- 판단: 검증 담당 (루틴 직접, ASan 하네스 재현)
- 큐 추가: 1개 (A20261114-1 → 큐 126). 큐 71 비고 보강

## A20261114-1. `slmp_stack_read_words`/`write_words` 의 워드 슬롯 범위 검사가 `uint32_t` 덧셈 넘침으로 뚫린다

**문제:** 워드 디바이스(및 클라이언트 역할의 비트 디바이스 워드 슬롯) 경로가 `head + quantity > slot->capacity` 로 범위를 본다.
`head` 가 `uint32_t` 라 `0xFFFFFFFF + 1` 이 0 이 되어 검사를 통과하고, `memcpy(slot->words + head, …)` 가 맵 밖을 읽거나 쓴다.
**근거:** `stacks/slmp/src/slmp_stack.c:403-406` (read), `:434-437` (write) (`7c05f46`).
**재현 (스크래치 하네스, ASan, 서버 역할, `slmp_stack_read_words(s, SLMP_DEV_D, 0xFFFFFFFF, &w, 1)`):**

```
ERROR: AddressSanitizer: SEGV on unknown address 0x5252000000fe
    #0 __memmove_avx512_unaligned_erms
    #1 slmp_stack_read_words stacks/slmp/src/slmp_stack.c:406
```

**닿는 경로:** 와이어 요청의 선두 번호는 3바이트 (최대 0xFFFFFF) 라 원격 요청으로는 닿지 않는다. 공개 API (`slmp_stack.h`) 와 어댑터가
config 의 주소를 넘기는 경로로 닿는다 — 큐 90 (A20261019-1, 0xFFFFFF 를 넘는 선두 번호) 이 어댑터 쪽 입력을 막기 전까지는 config 값으로도
닿을 수 있다. 그래서 v0.2.0 게이트(원격·비인증 기준) 에는 넣지 않고 일반 행으로 둔다.
**기대값:** 범위 밖이면 `-ERANGE`. `head > capacity || quantity > capacity - head` 처럼 넘치지 않는 비교.
**수정 범위:** `stacks/slmp/`, `tests/`. **완료 조건:** 단위 테스트: `head = 0xFFFFFFFF`·`0xFFFFFFF0` 등에서 read/write 가 `-ERANGE`, ASan 깨끗.

## 큐 71 비고 (A20261011-3)

#208 확인 요청 답 (https://github.com/Cyoh-Tim/Fieldbus-Archtecture/pull/208#issuecomment-6871291528): T10-6 은 서버 역할만 비트 디바이스
워드 접근의 선두를 비트 번호로 바꿨다. 클라이언트 캐시는 아직 워드 인덱스 해석이다. 큐 71 PR 에서 클라이언트 캐시도 같은 비트 번호
해석으로 맞추면 `test_client_stack_writes_high_device_numbers[M512-word]` 와 `test_adapter_client_reads_high_device_numbers[M512-word]`
(큐 72) 가 통과할 수 있다.
