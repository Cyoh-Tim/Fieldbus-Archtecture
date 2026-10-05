# 감사 2026-10-05 — PROFINET 오라클 Connect 요청 정정과 T12-4·T12-5 검증 중 발견

- 영역: PROFINET RPC·레코드 (PR 검증 중 오라클 반론, 11단계 제안 선별)
- 출처: PR #90 (T12-4) 검증 — opus 사양 판단, fable 2차 의견 (두 모델 동의). PR #89 (T12-5) 질문 답. PR #91 (T12-6) 질문.
- 기준 커밋: `2931f7f` (main, PR #91 병합 직후)
- 큐 추가: 없음 (오라클 정정 + 비고 갱신)

## 1. 오라클 정정 — ExpectedSubmoduleBlockReq 의 NO_IO DataDescription

**문제 (오라클 쪽):** `tests/oracle/test_pn_oracle.py` `connect_pdu()` 가 SubmoduleProperties_Type=0 (NO_IO) 서브모듈 3개
(slot 0 subslot 1, 0x8000, 0x8001)에 DataDescription 을 넣지 않았다. scapy 는 `PacketListField.count_from` 을 디섹트에만
쓰고 빌드는 준 리스트(`[]`)를 그대로 직렬화하므로, 블록이 76바이트로 나갔고 scapy 자신도 되읽지 못했다
(`ExpectedSubmoduleBlockReq(raw(blk))` 가 두 번째 서브모듈부터 어긋나고 끝에 10바이트 Raw 가 남는다).
PR #90 의 스택 파서와 단위 테스트가 같은 잘못된 형태에 맞춰져 오라클을 통과했다.

**근거:**
- Wireshark `plugins/epan/profinet/packet-dcerpc-pn-io.c` `dissect_ExpectedSubmoduleBlockReq`:
  `case(0x00): /* no input and no output data (one Input DataDescription Block follows) */`.
- p-net `src/device/pf_block_reader.c` `pf_get_exp_submodule`: "At least one submodule data descriptor" — 1개는 무조건,
  Type==IO 일 때만 2개. 검증 `pf_cmdev.c`: NO_IO 는 descriptor 1개·방향 INPUT·길이 0·IOCS 1·IOPS 1 이 아니면 Connect 거부.
- scapy `scapy/contrib/pnio_rpc.py` `ExpectedSubmodule.DataDescription` `count_from=lambda p: 2 if p.SubmoduleProperties_Type == 3 else 1`.

**수정:** NO_IO 서브모듈마다 `ExpectedSubmoduleDataDescription(DataDescription=1, SubmoduleDataLength=0, LengthIOCS=1, LengthIOPS=1)`.
블록 길이 `0x5e`, scapy 왕복 디섹트가 4개 서브모듈을 그대로 복원한다 (Raw 없음).

## 2. 오라클 정정 — ARServerBlock 은 Advanced startup 에서만

**문제 (오라클 쪽):** `test_connect_response_has_ar_server_block` 이 Legacy(ARProperties.StartupMode=0) Connect 의 응답에
ARServerBlock(0x8106)을 요구했다.

**근거:**
- p-net `src/device/pf_cmrpc.c` Connect 응답 작성: `if (startup_mode) { /* Additional blocks in advanced start mode:
  {ARServerBlockRes, [ARVendorBlockRes*]} */ … }` — Legacy 에서는 넣지 않는다.
- Siemens CM 컨트롤러 스택 `cm_cl30.c` `cm_cl_parse_connect_response()`: `CM_BLOCK_TYPE_ARSERVERBLOCK` 을 받았는데
  `ar_properties & CM_AR_PROP_STARTUP_MODE_ADVANCED` 가 0 이면 "only valid with … ADVANCED" 로 `CM_AR_REASON_PROT` (AR 중단).
  Advanced 인데 ARServerBlock 이 없어도 "AdvancedStartup: not all block_type seen, arserver" 로 중단.
- Wireshark 는 조건 없이 디섹트만 한다 (출현 조건 근거 아님).

**수정:** `connect_pdu(startup_mode=)` 인자(ARProperties bit 30). `test_connect_response_has_ar_server_block` 은
`startup_mode=1` 로 확인 (T12-4 표시 유지). `test_connect_legacy_response_has_no_ar_server_block` 추가 — Legacy 응답에
0x8106 이 없어야 한다 (main 은 블록을 보내지 않으므로 지금 통과, PR #90 head 는 실패).

**정정 영향 (스크래치 실행):**
- main `2931f7f` 빌드: 수정 전·후 오라클의 테스트별 결과가 같고, 새 Legacy 테스트만 PASSED 로 추가 (`10 passed, 36 xfailed`, 3회 동일).
- PR #90 head `bc5b113` 빌드, `--runxfail`: 수정 전 오라클은 `frame_offsets`·`ar_server_block`·`module_diff`·`minimum_frame`
  4 passed. 수정 후에는
  ```
  test_pn_oracle.py:286: AssertionError: assert b'\x80\x00\x0...0\x00\x00\x00' == b'\x10\x11\x1...$%&\'()*+,-./'
  test_pn_oracle.py:342: AssertionError: 블록 타입 ['0x8101', '0x8102', '0x8102', '0x8103', '0x8104', '0x8106']
  ```

## 3. 인수인계 T12-5 문구 정정 — ApplicationReady 목적지

인수인계 문서 T12-5 행의 "ApplicationReady 를 `CMInitiatorUDPRTPort` 로 전송" 은 틀렸다. ApplicationReady(CControl 요청)는
**Connect 송신자 IP 의 UDP 34964 (0x8894) 고정**이다. `CMInitiatorUDPRTPort` 는 RT 프레임용 값(일반적으로 0x8892)이다.
- 근거: p-net `src/device/pf_cmrpc.c` CControl 세션 `p_sess->ip_addr = p_ar->p_sess->ip_addr; p_sess->port = PF_RPC_SERVER_PORT;
  /* Destination port on IO-controller */`, `pf_types.h` `#define PF_RPC_SERVER_PORT 0x8894`.
- PR #89 에 답함. 인수인계 문서 자체는 검증 담당 자체 PR 범위 밖이라 여기와 큐 10 비고에 정정을 남긴다.

## 확인 필요 (큐에 넣지 않음)

- **CTT `step_rt_output` O→T DataStatus** (`tools/ctt/proto/profinet/pn_plugin.c`): T12-6 이후 `0x15` (StationProblemIndicator
  없음). 스택은 수신 DataStatus 를 보지 않아(D25) 영향 없음. `tools/ctt/` 가 범위인 다음 PN PR 에서 `0x35` 로 맞춘다 (PR #91 답).
- **첫 O→T 프레임 전 data-hold 워치독** (`stacks/profinet/src/pn_rt.c`): PrmEnd 뒤 O→T 프레임이 없으면 DHT 가 지나 AR 을 끊는다.
  p-net 은 첫 프레임 전(W_START/FRUN)에는 DHT 를 세지 않는다 (`pf_cpm_driver_sw.c`). T4/T12-15 (큐 15) 와 함께 확인한다.
- **ApplicationReady 확인 응답 처리** (PR #89): 0x8112 블록 타입만 본다. p-net 은 PNIOStatus·ControlCommand Done 까지 확인하고,
  2초 간격 3회 재전송 뒤 AR 을 중단한다. T12-5 완료 조건 밖이라 PR 에 선택 사항으로 남겼다.
- **CTT `build_connect_pdu`** 가 ARBlockReq 를 26바이트로 잘라 보내고 IOCR·ExpectedSubmodule 이 없다 — T12-0 잔여 (PR #89·#90 제보).
