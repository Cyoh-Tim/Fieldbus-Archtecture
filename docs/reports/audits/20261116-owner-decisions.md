# 2026-11-16 — 담당자 결정: T6 병합 범위, 자동 등록 테스트 라벨

- 출처: 2026-11-15·16 실행 요약의 "정해 주셔야 할 것" 2건
- 판단: 검증 담당 추천 → **담당자 결정 (2026-11-16): "둘 다 추천대로 진행해"**

## 결정 1. T6 (큐 56, #212) 은 이슈 범위 안이면 검증 담당이 병합한다

T6 은 `CLAUDE.md` 의 스케줄러 위치 문구와 `CMakeLists.txt` 의 `core/scheduler.c` 소스 목록을 바꾼다. 병합 정책(9단계)은 CMake 를
"테스트 타깃 추가만" 허용하므로, 이 항목에 한해 담당자가 범위를 승인했다: `core/`, `CLAUDE.md` 의 스케줄러 위치 문구,
`CMakeLists.txt` 의 `core/scheduler.c` 소스 목록, `tests/`. 그 밖의 `CMakeLists.txt`·`CLAUDE.md` 변경은 여전히 사람 몫이다.
#212 에 같은 내용을 알렸다.

## 결정 2. 자동 등록 단위 테스트에 프로토콜 라벨과 `timing` 라벨을 붙인다

- `fb_add_item_tests` (#200) 가 등록하는 `tests/test_<proto>_t*.c` 에 프로토콜 라벨 (`profinet`, `ethernetip`, `modbus`, `slmp` — CTT 시나리오와
  같은 이름) 을 붙인다. `ctest -L modbus` 가 Modbus 단위 테스트도 잡는다.
- 파일 이름이 `_timing.c` 로 끝나면 `timing` 라벨도 붙인다. CI 는 `timing` 을 일반 job 에서 빼고 부하 없이 따로
  (`-L timing --repeat until-pass:3`) 돌린다 (`.github/workflows/ci.yml`).
- 지금 시간을 재는 항목 테스트는 `test_mb_t9_7` (#211, 파이프라인 응답 지연 중앙값 < 20 ms) 하나라 `tests/test_mb_t9_7_timing.c` 로 이름을 바꿨다.
- 이슈 템플릿 1항에 이름 규칙을 더했다.
