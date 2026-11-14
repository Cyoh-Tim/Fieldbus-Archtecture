# 2026-11-13 — EIP 단위 테스트 포트 예약 경합, SLMP 문서 T10-5 반영 (#204 검증·선별)

- 영역: 테스트 기반 (EIP 단위 테스트), SLMP 문서
- 출처: #204 (T10-5) 검증 중 로컬 CI sanitizers job 실패, #204 "발견한 다른 문제"
- 기준 커밋: `639c541` (main, #204 병합 직후)
- 판단: 검증 담당 (루틴 직접)
- 큐 추가: 2개 (A20261113-1, -2 → 큐 124, 125)

## A20261113-1. EIP 단위 테스트의 `reserve_port` 가 같은 포트를 다시 내줄 수 있다 (가끔 실패)

**문제:** `reserve_port()` 는 TCP 소켓을 포트 0 에 bind 해 받은 번호를 읽고 **바로 닫는다**. 그래서 연달아 부른 두 번째·세 번째 호출이
같은 번호를 받을 수 있고, 그 사이 다른 프로세스(병렬 ctest, 다른 job)가 그 포트를 잡을 수도 있다. UDP 포트도 TCP 소켓으로 고른다.
**재현 (로컬 CI, main `3ce04cb` + #204, sanitizers job):**

```
24/94 Test  #24: test_eip_t11_11 ..........................***Failed    0.03 sec
FAIL: distinct ports
```

같은 job 을 부하 없이 단독으로 다시 돌리면 PASS. #204 (SLMP) 와 무관하다.
**근거:** `tests/test_eip_t11_11.c:119-137` `reserve_port` (`close(fd)` 뒤 번호 반환), `:304-318` 세 번 호출 뒤 `distinct ports` 검사.
같은 helper 가 `tests/test_eip_sigpipe.c`, `test_eip_t11_4.c`, `test_eip_t11_6.c`, `test_eip_t11_9.c`, `test_eip_t11_10.c` 에 복사돼 있다
(`test_eip_t11_4.c:414`·`:497`, `test_eip_t11_9.c:395` 도 같은 번호 검사로 실패할 수 있고, 검사가 없는 곳은 겹치면 bind 실패로 다른 메시지를 낸다).
**수정 범위:** `tests/` 만. 예: 필요한 포트를 모두 bind 한 채로 번호를 모은 뒤 한꺼번에 닫는다 (같은 번호가 나올 수 없음), UDP 용은
`SOCK_DGRAM` 으로 고른다, 또는 스택이 포트 0 bind 를 받아 실제 포트를 알려 주는 API 가 있으면 그것을 쓴다. 공용 helper 를
`tests/` 헤더 하나로 모아도 된다.
**완료 조건:** 위 6개 테스트가 같은 방식으로 포트를 고른다. `ctest -R test_eip -j8 --repeat until-fail:20` 이 통과한다.

## A20261113-2. SLMP 문서·CTT 매트릭스가 T10-5 이전 동작을 적고 있다

#204 "발견한 다른 문제" 그대로 (위치 확인함).
- `docs/protocols/slmp.md` `:545`, `:564`, `:725`, `:748`, `:1600`, `:1646`, `:1647`, `:2001`, `:2003`, `:2010`, `:2068`, `:2074` 근처 —
  미지원 커맨드 `C050h`, 이상 응답 길이 2, 짧은 쓰기 무응답, `frame_malformed`·B-15 의 무응답 폐기.
- `docs/ctt_slmp_matrix.md:45`, `docs/ctt_slmp_bundle.md:96`, `:105` — Random R/W `end 0xC050`. `docs/ctt_board_data.json` 은 매트릭스에서
  `tools/ctt/gen_board_data.py` 로 다시 만든다.
**지금 동작 (#204 뒤):** 미지원 커맨드 `C059h`, 이상 응답에 9바이트 에러 정보 (요청 경로 + 커맨드·서브커맨드 에코, 길이 필드 11),
쓰기 데이터 길이 불일치 `C061h` (맵 불변).
**수정 범위:** `docs/` 만 (보드는 생성기로). **완료 조건:** 위 위치가 지금 동작과 같고 `ctt_board_data_fresh` 테스트 통과.
과거 기록 (`docs/reports/structure_handoff_20260930.md`, `CHANGELOG.md`, `docs/reports/security_fixes_20260928.md`) 은 고치지 않는다.
