# 감사 2026-10-20 — SLMP 예제 config: 바코드 문자열이 온도 레지스터와 겹침

- 영역: SLMP 예제·랩 하네스 (11단계 제안 선별)
- 출처: `[Grok 제안]` #140 (T10-4 #141 작업 중 sw-master-soak 간헐 실패)
- 기준 커밋: `ff26db0` (main, #139 병합 직후)
- 판단: 검증 담당 (루틴 직접, config 정적 검사 + 하네스 코드 대조)
- 큐 추가: 1개 (A20261020-1 → 큐 91)

## A20261020-1. 예제 SLMP config 의 `barcode_value` 가 `temperature` (D110) 를 덮는다

**문제:** 두 SLMP 예제 config 에서 `barcode_value` 는 `D100` 부터 문자열 32자(= 16워드, D100~D115) 이고 `temperature` 는 `D110` 이다.
바코드를 쓰면(널 패딩 포함) D110 이 문자열 일부로 덮인다. `examples/fake_sensor_app.c` 는 바코드 → 온도 순으로 쓰고,
`examples/sw_master.py` 는 바코드 16워드와 D110 을 따로 읽으므로, 두 쓰기 사이에 온도를 읽으면 0.0 °C 가 나온다
(sw-master-soak job 간헐 실패). 제품 예제(`example.slmp.json`)를 복사한 사용자도 같은 겹침을 갖는다.
다른 프로토콜 예제는 온도가 문자열 바로 뒤에 있어 겹치지 않는다 (Modbus `offset 16`, EIP/PN `byte_offset 32`).

**근거 (파일:줄, 기준 커밋 `ff26db0`):**
- `config/example.slmp.json`, `config/example.fake_sensor.slmp.json` — `barcode_value` `{"device_code": "D", "start": 100}`, `"length": 32`;
  `temperature` `{"device": "D", "address": "110", "quantity": 1}`.
- `examples/sw_master.py:426-441` — 주석이 겹침을 적어 두고 D110 을 따로 읽는다.
- `examples/fake_sensor_app.c:90-99` — `fb_write_string(barcode_value)` 다음 `fb_write_f32(temperature)`.

**재현:** `tests/oracle/test_slmp_oracle.py::test_example_slmp_config_points_do_not_overlap` 를 `--runxfail` 로 돌린다
(config JSON 만 읽는다. 문자열 워드 수는 MELSEC 관례 워드당 2문자).

```
AssertionError: example.fake_sensor.slmp.json: 겹치는 포인트 [('barcode_value', 'temperature')] — 범위 [('barcode_value', 'D', 100, 115), ('temperature', 'D', 110, 110)]
AssertionError: example.slmp.json: 겹치는 포인트 [('barcode_value', 'temperature')] — …
```

#140 의 실측: `examples/run_sw_master_soak.sh slmp --seconds 3 --period-ms 50` 에서 `FAIL cycle=32: temperature out of fake-sensor range: 0.0` (한 번).

**기대값과 출처:** 한 디바이스의 두 포인트 워드 범위는 겹치지 않는다. MELSEC 문자열은 워드당 2문자 (`$MOV`, pymcprotocol 문자열 워드 변환과 같음) 이므로
32자는 16워드다. 다른 프로토콜 예제의 배치(온도 = 문자열 바로 뒤)와도 맞춘다.

**수정 범위:** `config/`, `examples/` (`sw_master.py`, 필요하면 `fake_sensor_app.c` 주석), `docs/` 의 D110 서술.
- `temperature` 를 문자열 뒤(예: `D116`)로 옮기고, `sw_master.py` 의 D110 읽기·주석을 같은 주소로 바꾼다.
- `docs/slmp_stack.md:229`, `docs/protocols/slmp.md:1106`, `:1502-1507`, `:1539` 의 D110 을 함께 고친다.
- T10-4 (#141, 큐 28) 가 같은 config 를 바꾸므로 그 PR 병합 뒤에 한다.

**완료 조건:** `test_example_slmp_config_points_do_not_overlap` 2개 통과 (`A20261020-1` 표시 삭제), sw-master-soak (slmp) 통과.
