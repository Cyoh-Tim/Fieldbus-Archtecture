# 감사 2026-10-07 — PROFINET Connect 태그 헤더 검증

- 영역: PROFINET RPC·레코드 (PR #96 검증 중 발견, 11단계 제안 선별)
- 출처: PR #96 (T12-8) `[Claude 확인 요청]` 답을 위한 사양 판단 — opus 하위 에이전트, 근거 대조·재현: 루틴
- 기준 커밋: `811b1dd` (main, PR #90 병합 직후)
- 큐 추가: 1개 (A20261007-1 → 큐 66)

## A20261007-1. Connect 의 IOCRTagHeader·AlarmCRTagHeader 값을 검사하지 않는다

**문제:** IOCRBlockReq 의 IOCRTagHeader 와 AlarmCRBlockReq 의 AlarmCRTagHeaderHigh/Low 는 사양 고정값(IOCR `0xC000` =
우선순위 6·VID 0, 알람 High `0xC000`, 알람 Low `0xA000` = 우선순위 5·VID 0)인데, 장치가 다른 값의 Connect 도 받아들인다.
독립 구현(장치·컨트롤러 모두)은 이런 Connect 를 거부한다. T12-8 (PR #96) 은 송신 프레임의 태그를 다루고, 이 항목은 수신한
Connect 의 검증이다.

**근거 (파일:줄, 기준 커밋 `811b1dd`):**
- `stacks/profinet/src/pn_rpc.c` Connect 처리 — IOCRBlockReq·AlarmCRBlockReq 의 태그 헤더 필드를 검사하는 분기가 없다
  (`grep -n TagHeader` 로 검사 코드 없음 확인).

**재현 (수정 전, `pn_oracle_pipe` + scapy 2.7.0):** 표준 Connect(`connect_pdu()`)에서 IOCRTagHeader 우선순위만 5로,
또는 AlarmCRTagHeaderLow 만 `0xC000` 으로 바꿔 보낸다. 오라클을 `--runxfail --tb=line` 으로 돌린 결과:

```
test_pn_oracle.py:379: AssertionError: PNIOStatus 00000000 (기대 db810211)
test_pn_oracle.py:379: AssertionError: PNIOStatus 00000000 (기대 db810412)
```

**기대값과 출처:**

| 입력 | PNIOStatus | 출처 |
|---|---|---|
| IOCRTagHeader VID ≠ 0 또는 우선순위 ≠ 6 | `DB 81 02 11` (CONNECT, PNIO, FaultyIOCRBlockReq, 17) | p-net `src/device/pf_cmdev.c` IOCR 검사 (`iocr_tag_header.vlan_id != 0` / `iocr_user_priority != 6` → 17), Siemens CM `cm_argr.c` (`!= 0xC000` → 17) |
| AlarmCRTagHeaderHigh VID ≠ 0 또는 우선순위 ≠ 6 | `DB 81 04 11` (FaultyAlarmCRBlockReq, 11) | p-net `pf_cmdev.c` 알람 CR 검사, Siemens CM `cm_argr.c` (`!= 0xC000` → 11) |
| AlarmCRTagHeaderLow VID ≠ 0 또는 우선순위 ≠ 5 | `DB 81 04 12` (FaultyAlarmCRBlockReq, 12) | p-net `pf_cmdev.c`, Siemens CM `cm_argr.c` (`!= 0xA000` → 12) |

- 상수: p-net `include/pnet_api.h` `PNET_ERROR_CODE_CONNECT 0xDB`, `PNET_ERROR_DECODE_PNIO 0x81`,
  `PNET_ERROR_CODE_1_CONN_FAULTY_IOCR_BLOCK_REQ 0x02`, `PNET_ERROR_CODE_1_CONN_FAULTY_ALARM_BLOCK_REQ 0x04`.
- PNIOStatus 는 drep 순서 정수 (A20261002-1 과 같은 규칙). 오라클 판정 헬퍼 `ndr_response` 가 scapy 로 만든 LE drep 거부
  응답(`0xDB810211`, `0xDB810412`)을 그대로 읽는 것을 자체 시험으로 확인했다.
- Siemens 컨트롤러는 항상 `0xC000`/`0xC000`/`0xA000` 을 보낸다 (`cm_cl30.c`). 표준 컨트롤러와의 상호운용에는 영향이 없고,
  잘못된 Connect 를 받아들여 엉뚱한 우선순위로 보내는 것을 막는 검증이다.

출처 URL:
- p-net: https://github.com/rtlabs-com/p-net/blob/master/src/device/pf_cmdev.c, https://github.com/rtlabs-com/p-net/blob/master/include/pnet_api.h
- Siemens PROFINET 스택 미러: https://github.com/mohammadfatemieh/ASV (`modules/messages/PLC/SIEMENS/Profinet/src/source/cm/src/src/cm_argr.c`)

**수정 범위:** `stacks/profinet/`, `tests/`.
- Connect 블록 검증에 위 세 검사를 넣고, 원인별 PNIOStatus 로 거부한다. 거부 응답은 큐 59(A20261002-1)·큐 16(T5 PN)과 같은
  `reply_pnio_err` 를 쓰므로, 원인 코드를 인자로 받는 형태가 먼저(또는 같이) 있어야 한다.

**완료 조건:**
- 오라클 `test_connect_rejects_nonstandard_tag_header` (iocr-prio5, alarm-low-prio6) 가 통과하고 `@known_defect("A20261007-1", …)` 를 지운다.
- 표준 Connect 를 쓰는 다른 PN 오라클 결과(passed·xfailed 수)가 그대로다.

## 확인 필요 (큐에 넣지 않음)

- **송신 프레임 태그**: RTC1·알람은 Connect 값과 무관하게 항상 802.1Q 태그(`0xC000`/`0xA000`)로 보낸다 (p-net `pf_ppm.c`
  `pf_ppm_init_buf`, `pf_alarm.c`; Siemens EDDS·ACP). PR #96 (T12-8) 에 그렇게 답했고 그 PR 에서 처리한다.
- **CTT 플러그인의 VLAN 미인식** (`tools/ctt/proto/profinet/pn_plugin.c` EtherType/FrameID 오프셋 12/14 고정): PR #96 에서
  CTT 원칙(결함 PR 에서 함께 고침)으로 처리한다.
- **AlarmCRTagHeaderHigh 오라클**: 이번 테스트는 IOCR 과 알람 Low 만 넣었다 (High 는 같은 코드 경로).
