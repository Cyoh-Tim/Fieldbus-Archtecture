# 2026-11-25 — PN DCP Get 후속 (#238 제안 선별, #226 확인 요청 답)

- 영역: PROFINET DCP (11단계 제안 선별)
- 출처: PR #238 (A20261003-2) "발견한 다른 문제" 1~3, 이슈 #226 `[Claude 확인 요청]` (All selector) 과 검증 담당 답
- 기준 커밋: `211a600` (main, #238 병합 직후)
- 판단: 검증 담당 (기본 모델). 근거는 p-net `src/common/pf_dcp.c` (검증 담당 스크래치 사본) 과 저장소 코드.
- 큐 추가: 1개 (A20261125-1 → 큐 142). 문서 제안은 큐 68 비고.

## A20261125-1. CTT `dcp_get` 이 Identify 형식 요청 `FF FF 00 00` 을 Get 에 보내고, 스택이 Get 의 All selector 를 Identify 블록으로 펼친다

**문제:** CTT 플러그인 `step_dcp_get` 는 Get.req 본문을 Identify 의 All 블록처럼 Option `0xFF`·Suboption `0xFF`·DCPBlockLength `0000`
(4바이트, DCPDataLength 4) 으로 보낸다. Get.req 블록은 길이 필드 없는 (Option, Suboption) 쌍의 목록이라, 이 요청은
`(0xFF,0xFF)` 와 `(0x00,0x00)` 두 선택자로 읽힌다. #238 은 CTT 를 깨지 않기 위해 Get 의 `(0xFF,0xFF)` 를 Identify 블록 7개로 펼치고,
`(0x00,0x00)` 에는 NegRes `05 04 0003 00 00 01` 을 붙였다 (golden `tests/golden/profinet/dcp_get_res.pcap` 도 그렇게 바뀜).
CTT 와 스택이 같은 비표준 형식을 정답으로 공유하는 상태다 (인수인계 T12-0 과 같은 종류).

**근거 (파일:줄, 기준 커밋 `211a600`):**
- `tools/ctt/proto/profinet/pn_plugin.c:637-646` `step_dcp_get` — `pn_wr_be16(pay + 10, 4)` (DCPDataLength 4), `pay[12] = PN_DCP_OPT_ALL; pay[13] = 0xFF; pn_wr_be16(pay + 14, 0)`.
- `stacks/profinet/src/pn_dcp.c` `append_get_selector` — `opt == PN_DCP_OPT_ALL && sub == 0xFF` 이면 `append_all_readable_blocks`.
- 시나리오 `tests/scenarios/profinet/dcp_get.yaml`, `dcp_malformed.yaml`, `dcp_set_name_boundary.yaml` 이 `dcp_get` 응답에서 스테이션 이름을 본다.

**기대값과 출처:**
- p-net `src/common/pf_dcp.c` Get 루프: 요청을 2바이트 쌍으로 읽어 쌍마다 `pf_dcp_get_req` 를 부르고, 그 안의 `switch (opt)` 에서
  `case PF_DCP_OPT_ALL: skip = true;` — 블록도 NegRes 도 넣지 않는다 ("Do not insert block in response").
- Wireshark `packet-pn-dcp.c` `dissect_PNDCP_PDU`: Get+Request 는 "Selectors" 로 `dissect_PNDCP_Option` (2바이트) 만 읽는다 (A20261003-2 보고서 근거와 같음).
- 따라서 표준 Get 은 특정 (Option, Suboption) 쌍을 보내고, All selector 는 Get 에서 응답을 만들지 않는다.

**수정 범위:** `tools/ctt/`, `stacks/profinet/`, `tests/` (CTT 와 스택을 한 PR 에서 함께 — 따로 하면 한쪽이 깨진다).
- `step_dcp_get` 가 진짜 Get.req 를 보낸다. 기본은 NameOfStation `02 02` (DCPDataLength 2). 시나리오에서 선택자를 고를 수 있게 하면 좋다 (예: `selectors: ["02 02", "01 02"]`).
- 스택 `append_get_selector` 의 `(0xFF,0xFF)` 분기를 p-net 처럼 아무것도 넣지 않게 바꾼다.
- golden `tests/golden/profinet/dcp_get_res.pcap` 을 새 요청의 응답(이름 블록 하나)으로 다시 만든다. 바꾼 기대값을 PR 설명에 적는다.
- `tests/test_pn_dcp.c` 의 "Get All selector plus option 0" 기대값 (블록 8개) 을 바꾼다.

**완료 조건:**
- `dcp_get`·`dcp_malformed`·`dcp_set_name_boundary` 시나리오와 golden 검사 통과.
- `test_pn_dcp` 에서 Get `FF FF` 는 블록 0개 (DCPDataLength 0, ServiceType Success), Get `02 02` 는 이름 블록 하나.
- PN 오라클 결과 (passed·xfailed 수) 그대로.

## 문서 제안 (큐 68 비고로)

- `docs/protocols/profinet.md:932-933` (5.b.7) — "무엇을 요청하든 Identify 블록 전체를 돌려준다 [차이]" 는 #238 이후 틀림 (요청 쌍마다 블록 하나, 미지원은 NegRes).

## 확인 필요 (큐에 넣지 않음)

- **옵션별 Suboption `0xFF`** (예: Get `02 FF` = Device 의 모든 서브옵션?): #238 은 BlockError `0x02` 로 답한다. p-net 은 `pf_cmina_dcp_get_req`
  에서 개별 서브옵션만 처리하는 것으로 보이나, 사양 원문(IEC 61158-6-10)에서 옵션별 `0xFF` 의 뜻을 확인하지 못했다. 근거가 생기면 큐에 넣는다.
