# 감사 2026-10-29 — PN DCP Set 의 AR 중 규칙·ResetToFactory 오라클 정정, EPM 응답 오라클 강화

- 영역: PROFINET DCP·CL-RPC (0-1단계 질문 답, #161·#167 검증 중 오라클 재검토)
- 출처: #167 (T12-16) `[Claude 확인 요청]`, #161 (T12-14) 검증
- 기준 커밋: `0f6bcff` (main)
- 판단: 검증 담당 (루틴 직접, p-net·Wireshark·scapy 대조) + opus 하위 에이전트 독립 2차 의견 (같은 결론, 인용은 루틴이 다시 확인)
- 큐 추가: 없음 (큐 35·36 의 기존 T 항목 기준을 바꾼다)

## 1. 오라클 정정 — AR 중 NameOfStation Set 은 기본적으로 거부가 아니다

**이전 기대값 (틀림):** `test_dcp_set_name_rejected_during_ar` — AR 이 있으면 NameOfStation Set 을 BlockError 0x06 으로 거부.
오라클의 Connect 는 ARProperties bit 27 (RejectDCPsetRequests) 을 0 (Accepted) 으로 보낸다.

**근거:**
- p-net (`rtlabs-com/p-net` master) `src/device/pf_cmina.c` `pf_cmina_dcp_set_ind` W_CONNECT 분기 —
  "Case 27, 28 in Profinet 2.4 Table 1096 CMINA state table — Change name or reset IP — Abort active ARs".
  이름은 바꾸고 AR 은 `PNET_ERROR_CODE_2_ABORT_DCP_STATION_NAME_CHANGED` (0x1F, `pnet_api.h`) 로 끊는다.
  같은 이름이면 "Case 24 — No change of name or IP. All OK".
- 같은 함수 "Case 26 — Change IP, active connection" → 오류 (IP 는 AR 중 바꾸지 않는다).
- Wireshark `packet-dcerpc-pn-io-all.c` ARProperties bit 27 `RejectDCPsetRequests` (0 Accepted / 1 Rejected),
  CIM 블록 `DCPSetControl.SetNameOfStation` "Enable/Disable NameOfStation setting while an AR is active".
  거부는 AR 이 그렇게 요청했을 때의 동작이다.
- BlockError 값: Wireshark `packet-pn-dcp.c` 0x06 "In operation, SET not possible" 이 의미상 맞지만 1차 출처(IEC 61158-6-10 표)는
  직접 확인하지 못했다. p-net 은 AR 중 IP 거부에 초기값 0x02 를 남긴다 (의도한 값이 아님). 오라클은 0 이 아닌 것만 본다.

**새 기대값 (오라클 테스트, `@known_defect("T12-16")`):**
- `test_dcp_set_name_during_ar_accepted_and_aborts_ar` — RejectDCPsetRequests=0: BlockError 0, 이름 적용, RTC1 멈춤 (AR abort).
- `test_dcp_set_name_rejected_when_ar_rejects_dcp_set` — bit 27 = 1: BlockError ≠ 0, 이름·RTC1 유지.
- `test_dcp_set_ip_rejected_during_ar` — AR 중 다른 IP: BlockError ≠ 0, IP·RTC1 유지.

## 2. 오라클 추가 — ResetToFactory (Control 5/6)

- 모드 = BlockQualifier bit 1..15 (Wireshark `pn_dcp_BlockQualifier`: 1 application data, 2 communication parameter,
  3 engineering, 4 all except security, 8 all to factory, 9 reset and restore; 0·5–7 reserved). p-net `reset_mode = block_qualifier >> 1`.
- 공장값은 **빈 NameOfStation·IP 0.0.0.0** 이다 (기동 config 값이 아님): p-net `pf_cmina_set_default_cfg` 모드 2 이상 —
  ip_addr/mask/gateway = 0, station_name memset 0. config 값은 power-on (모드 0) 에서 저장값이 없을 때만 쓴다.
  모드 1 이상은 I&M (p-net `pf_fspm_clear_im_data`). Reset Factory Settings (5/5) 는 p-net `reset_mode = 99` (전부).
- AR 중: p-net "Case 27, 30 — reset to factory — Abort active ARs" (`PNET_ERROR_CODE_2_ABORT_DCP_RESET_TO_FACTORY` 0x20). 수락하고 AR 을 끊는다.
- 예약 모드: 1차 출처 없음. p-net 은 검사하지 않는다. 검증 담당 결정: 값을 바꾸지 않고 BlockError ≠ 0 (구현은 0x03). 오라클은 보지 않는다.

**새 오라클 테스트:** `test_dcp_reset_to_factory_communication_parameters` (모드 2 → 빈 이름·0.0.0.0),
`test_dcp_reset_to_factory_during_ar_aborts_ar` (AR 중 BlockError 0, RTC1 멈춤).

## 3. 오라클 강화 — EPM ept_lookup 응답을 디코드한다

**이전 검사 (약함):** `test_rpc_epm_lookup_lists_pnio_interface` 는 응답 스텁에 PNIO Device 인터페이스 UUID 바이트가 있는지와
마지막 4바이트가 0 인지만 봤다. #161 의 응답은 이 검사를 통과하지만 scapy 로 디코드하면 깨져 있다.

```
ept_entry_t: annotation offset=131076 (0x00020004) actual_count=75, tower tower_length=1
status = 1
tower floor: 00 05 00 13 0d … (floor 개수·lhs 길이를 big-endian 으로 씀)
```

**기준:**
- scapy `scapy.layers.msrpce.raw.ept.ept_lookup_Response` (NDR) 와 `scapy.layers.msrpce.ept.protocol_tower_t`
  (floor 개수·lhs/rhs 길이·버전 `LEShortField`, 포트·IP big-endian).
- Wireshark `packet-dcerpc-epm.c` `epm_dissect_tower_data` — floor 개수와 lhs/rhs 길이 `tvb_get_letohs`.
- p-net `src/device/pf_block_writer.c` `pf_put_tower_entry` — referent, annotation offset·length·64바이트, tower 길이 ×2, floor.
- 검사기 확인: p-net 배치로 손으로 만든 정상 응답 (LE floor) 은 새 검사를 통과한다 (스크래치).

**새 검사:** status 0, num_ents ≥ 1, tower 디코드, PNIO Device tower 의 floor = UUID(PNIO Device, v1)·UUID(NDR, v2)·ncadg(0x0A)·UDP 34964·IP.
`@known_defect("T12-14")` 는 그대로 (main 은 EPM 미구현).

## 선별 결과

- #167 "발견한 다른 문제" (CTT 하네스 `tools/ctt/proto/profinet/pn_plugin.c` `dcp_status_from_str` 가 `result: reject` 를
  ServiceType 5 로만 판정): 확인. T12-16 이후 거부는 ServiceType 1 + BlockError ≠ 0 이다. 별도 항목 대신 큐 36 범위에
  `tools/ctt/proto/profinet/` (이 판정만) 을 더했다 — 같은 범위의 PN 항목이 `pn_plugin.c` 를 고쳐 병합된 선례 (#86, #89, #94, #96).
  시나리오의 `result: reject` 는 지우지 않고 하네스를 고친다.
