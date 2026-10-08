# 감사 2026-10-03 — 코어 scale 포인트 32비트 읽기

- 영역: 코어 (11단계 제안 선별)
- 출처: PR #80 (T2 EIP) 본문 "발견한 다른 문제" — 구현 에이전트 제안
  (`decode_numeric` 이 scale 이 있는 uint32/int32 의 float32 페이로드를 정수로 읽는다)
- 기준 커밋: `a15b3e9` (main, PR #81 병합 직후)
- 큐 추가: 1개 (A20261003-1 → 큐 63)

## A20261003-1. scale 이 있는 uint32/int32 포인트를 읽으면 float32 비트가 정수로 나온다

**문제:** scale/offset 이 있는 숫자 포인트는 앱 경계에서 공학값 float32 다 (`fb_point_info_t.flags =
FB_POINT_F_SCALED`, `wire_size = 4`, `native_type = FB_TYPE_F32`). Modbus 어댑터도 읽을 때
`raw × scale + offset` 을 BE float32 4바이트로 돌려준다. 그런데 코어의 읽기 변환이 "native 크기가 4가
아닐 때만" float32 로 해석해서, native 크기가 4인 uint32/int32 는 float32 비트를 그대로 정수로 읽는다.
쓰기(`encode_numeric`)는 scale 포인트를 항상 float32 로 보내므로 쓰기·읽기가 비대칭이다.
uint16/int16 등 다른 크기와 float32 포인트는 영향이 없다. 결함이 코어에 있으므로 Modbus·SLMP·EIP·PN
어댑터 모두 같은 경로를 탄다.

**근거 (파일:줄, 기준 커밋 `a15b3e9`):**
- `core/fb_api.c:558-562` `decode_numeric` — `if (m->scaled && n == 4 && m->native_size != 4)` 일 때만
  `be_load_f32`. uint32/int32 는 `native_size == 4` 라서 이 분기를 지나 `:585-597` 의 정수 변환으로 간다.
- `core/fb_api.c:233-235` `native_type_of` — `m->scaled` 이면 `FB_TYPE_F32`.
- `core/fb_api.c:292-296` `fill_point_info` — scale 포인트의 `wire_size` 는 4.
- `core/fb_api.c:607-611` `encode_numeric` — scale 포인트는 크기와 무관하게 `be_store_f32`.
- `adapters/modbus/modbus_adapter.c:826-836` — 읽기에서 `eng = raw * scale + offset` 을 float32 로 만든다.
- 계약: `include/fb_api.h:52-56` ("engineering float32 when the adapter applied scale/offset").

**재현 (수정 전, `mb_slmp_oracle_app` + pymodbus 3.15.0):** holding 40–41 에 uint32 포인트
(`scale` 0.1, `byte_order` big, `word_order` abcd). pymodbus 로 `[0x0001, 0x0000]` (raw 65536) 를 쓰고
앱이 `fb_read_f32` 로 읽는다.

```
RF32 s32 → R 0 1.17105e+09     (기대 6553.6)
```

`1171050701 = 0x45CCCCCD` 는 float32 `6553.6` 의 비트다. int32 도 같다.
같은 설정의 uint16 (raw 1234 → 123.4) 과 uint32/int32 쓰기 (6553.6 → 레지스터 `0001 0000`) 는 맞다.

오라클 `tests/oracle/test_modbus_oracle.py::test_adapter_scaled_32bit_read[uint32-regs0]`,
`[int32-regs1]` 을 `--runxfail --tb=line` 으로 돌린 결과:

```
test_modbus_oracle.py:652: AssertionError: ['R', '0', '1.17105e+09']
```

**기대값과 출처:** 공학값 = raw × scale + offset = 65536 × 0.1 = 6553.6. raw 는 독립 구현체 pymodbus 가
쓴 정수이고, 32비트 레지스터 쌍의 워드 순서는 설정에서 명시(ABCD). 기대값은 저장소 계약
`include/fb_api.h` 와 같은 설정의 16비트 포인트 동작(같은 테스트 파일 `test_adapter_scaled_uint16_read`)에서
나온다. 크기에 따라 공학값 규칙이 달라질 근거는 없다.

**수정 범위:** `core/`, `tests/`.
- `decode_numeric` 이 scale 포인트의 4바이트 페이로드를 native 크기와 무관하게 BE float32 로 읽는다
  (`encode_numeric` 과 대칭). 코어에 프로토콜 분기를 넣지 않는다.
- 단위 테스트 `tests/test_fb_api.c` 에 scale 이 있는 uint32/int32 읽기 경우를 추가한다.

**완료 조건:**
- 오라클 `test_adapter_scaled_32bit_read` (uint32·int32) 가 통과하고 `@known_defect("A20261003-1", …)` 표시를 지운다.
- 같은 파일의 `test_adapter_scaled_uint16_read`, `test_adapter_scaled_32bit_write` 와 다른 오라클 결과
  (passed·xfailed 수)가 그대로다.
- 스크래치 검증: 조건에서 `&& m->native_size != 4` 만 지운 최소 패치에서 이 두 테스트만 XPASS(strict)가 되고
  나머지 scale 테스트 3개는 통과였다.
