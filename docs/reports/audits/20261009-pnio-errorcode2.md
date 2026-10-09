# 감사 2026-10-09 — PROFINET 거부 PNIOStatus ErrorCode2 정정 (오라클·인수인계)

- 영역: PROFINET RPC·레코드 (PR #106 질문 답변 중 발견, 오라클 기대값 반론)
- 출처: PR #106 (T5 PN) 의 ReductionRatio 상한 질문을 p-net 원문으로 확인하다가, 오라클의 기대 코드가 틀린 것을 찾음
- 판단: 루틴이 원문으로 발견 → fable 독립 2차 의견 동의 (주장 4개 모두)
- 기준 커밋: `5ebec2a` (main)
- 큐 추가: 없음 (오라클 정정, 큐 16·66 비고)

## 무엇이 틀렸나

PNIOStatus 의 ErrorCode2 는 ErrorCode1 이 가리키는 블록의 **필드 서수(10진)** 다. 두 군데가 틀렸다.

| 테스트 (`tests/oracle/test_pn_oracle.py`) | 전 기대값 | 정답 | 의미 |
|---|---|---|---|
| `test_connect_rejects_cycle_below_device_minimum` (T5 PN) | `DB 81 02 0E` | **`DB 81 02 0B`** | ErrorCode2 11 = ReductionRatio. 14(0x0E) 는 FrameSendOffset |
| `test_connect_rejects_nonstandard_tag_header[alarm-low-prio6]` (A20261007-1) | `DB 81 04 12` | **`DB 81 04 0C`** | ErrorCode2 12 = AlarmCRTagHeaderLow (10진 12 를 16진으로 옮긴 오류) |
| 같은 테스트 `[alarm-high-prio5]` (추가) | — | **`DB 81 04 0B`** | ErrorCode2 11 = AlarmCRTagHeaderHigh |
| 같은 테스트 `[iocr-prio5]` | `DB 81 02 11` | 그대로 | ErrorCode2 17 = IOCRTagHeader = 0x11 |
| `test_connect_second_controller_out_of_ar_resources` | `DB 81 40 04` | 그대로 | CMRPC / Out of AR Resources |

## 근거

- Wireshark `plugins/epan/profinet/packet-pn.c`
  - `pn_io_error_code2_pnio_2` (IOCRBlockReq): `{ 10, "GatingCycle" }`, `{ 11, "ReductionRatio" }`, `{ 12, "Phase" }`,
    `{ 14, "FrameSendOffset" }`, `{ 17, "IOCRTagHeader" }`. 10 의 "GatingCycle" 은 SendClockFactor 자리의 초기 명칭이다.
  - `pn_io_error_code2_pnio_4` (AlarmCRBlockReq): `{ 11, "AlarmCRTagHeaderHigh" }`, `{ 12, "AlarmCRTagHeaderLow" }`.
  - `pn_io_error_code2_pnio_64` (CMRPC): `{ 4, "Out of AR Resources" }`.
- p-net `src/device/pf_cmdev.c`
  - SendClockFactor 가 1/2/4/…/128 이 아니면 `FAULTY_IOCR_BLOCK_REQ, 10`.
  - RT_CLASS_1 의 ReductionRatio 가 1..512 밖이면 (RR ≥ 256 이면 SCF ≤ 64, RR = 512 면 SCF ≤ 32 조건 포함) `…, 11`.
  - `pf_fspm_get_min_device_interval(net) > send_clock_factor * reduction_ratio` 이면 `…, 11` — **주기 미달은 11**.
  - IOCR 태그 VID ≠ 0 또는 우선순위 ≠ 6 → 17, 알람 High/Low 태그 → `FAULTY_ALARM_BLOCK_REQ, 11` / `12`.
  - 상수 `include/pnet_api.h`: `PNET_ERROR_CODE_CONNECT 0xDB`, `PNET_ERROR_DECODE_PNIO 0x81`,
    `…_FAULTY_IOCR_BLOCK_REQ 0x02`, `…_FAULTY_ALARM_BLOCK_REQ 0x04`, `PNET_ERROR_CODE_1_CMRPC 0x40`,
    `PNET_ERROR_CODE_2_CMRPC_NO_AR_RESOURCES 0x04`.

## 인수인계 문서의 오류

`docs/reports/structure_handoff_20260930.md` T5 절은 "ErrorCode2 `0x0D`(SendClockFactor) 또는 `0x0E`(ReductionRatio)" 와
예 `DB 81 02 0E` 를 적고, 근거로 p-net 상수 `PNET_ERROR_CODE_2_IOCR_SEND_CLOCK_FACTOR/REDUCTION_RATIO` 를 든다. 그런 상수는
`pnet_api.h`·`pf_cmdev.c` 어디에도 없다 (fable 확인). 13/14 는 SCF/RR(10/11) 에서 정확히 3 칸 밀린 필드(Sequence /
FrameSendOffset)라 필드 서수를 잘못 센 것으로 보인다. 오라클은 이 문서를 그대로 옮겨 틀렸다.

- 정답: SendClockFactor 오류 `DB 81 02 0A`, ReductionRatio·주기 미달 `DB 81 02 0B`.
- 인수인계 문서 자체는 검증 담당 자체 PR 범위 밖이라 고치지 않고, 큐 16 비고와 이 보고서에 정정을 남긴다.
  큐 16 (#93) 과 그 구현 PR #106 에 알렸다.

## 정정 영향

- main 빌드에서 두 테스트는 그대로 xfail 이다 (스택이 아직 이 거부를 하지 않는다 — 지금은 각각 PNIOStatus `00000000`
  또는 `81 00 00 00` 계열). 고친 뒤에도 표시는 그대로 두고 기대값만 바뀐다.
- PR #106 은 주기 미달에 `DB 81 02 0B` 를 써야 하고, 이 정정이 main 에 들어간 뒤 main 을 병합해 T5 (PN) 표시를 지운다.
