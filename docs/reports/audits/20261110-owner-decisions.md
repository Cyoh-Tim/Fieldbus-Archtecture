# 2026-11-10 — 담당자 결정: v0.2.0 릴리스 게이트, AR 없는 Read, 무응답 대신 에러 응답

- 영역: 릴리스 기준 (전체), PROFINET CL-RPC 거부 동작
- 출처: 2026-11-08 감사 "확인 필요" 1·4 (`20261108-pn-rpc-records.md`), 2026-11-03 이후 릴리스 시기 질문
- 기준 커밋: `5af1ded` (main)
- 판단: 검증 담당 추천 → **담당자 결정 (2026-11-10): "추천대로 가자"**
- 큐 추가: 2개 (A20261110-2 → 큐 119, A20261110-3 → 큐 120). `work_queue.md` 에 "v0.2.0 릴리스 게이트" 절

## 결정 1. v0.2.0 은 게이트 행이 모두 끝나면 태그한다

큐는 하루에 약 1.5행 늘고 약 1행 닫힌다. "큐를 비운다" 를 기준으로 하면 릴리스가 오지 않는다.
**게이트 = 남은 큐 행 가운데 (a) 인수인계 우선순위 치명·높음, (b) 보안·가용성 (원격 비인증 DoS, 메모리 안전, 남의 연결 조작),
(c) 값이 조용히 틀리는 데이터 무결성 결함, (d) 인증·표준 지원을 와이어나 문서로 잘못 주장하는 것.** 그 밖의 행 (중간·낮음 T 항목,
상호운용 편차, 문서, 이벤트 구동 등 설계 개선) 은 v0.3 이후로 넘긴다. 릴리스 노트에는 "자체 스택, 인증 아님" 을 적는다.

게이트 행 목록과 분류는 `docs/reports/work_queue.md` "v0.2.0 릴리스 게이트" 절에 둔다 (2026-11-10 기준 16행, 검증 담당 분류).
새 감사·선별 행이 위 (a)–(d) 에 들면 검증 담당이 그 절에 더하고 보고서에 이유를 적는다. 게이트에서 빼는 것은 담당자가 정한다.

## 결정 2. AR 없는 opnum 2 Read 는 Read Implicit 뒤 거부한다 (A20261110-2 → 큐 119)

**지금:** AR 이 없어도 Read (opnum 2) 를 받아 레코드를 돌려준다. ARUUID 가 NIL 이어도 같다.
보안 결정 G4 (`docs/reports/security_fixes_20260928.md` "Read without an AR remains allowed (device records)") 의 관용이다.
**결정:** 표준 툴은 AR 없는 읽기를 Read Implicit (opnum 5, 큐 110 A20261108-1) 로 보낸다. 그것이 들어오면 opnum 2 의 관용은
상호운용 이득 없이 노출면만 남긴다. 큐 110 이후 opnum 2 + AR 없음은 거부한다. 이 결정이 G4 의 그 문장을 대신한다.
**기대값과 출처:** p-net master `src/device/pf_cmrpc.c` `pf_cmrpc_rm_read_ind` — NIL ARUUID + opnum ≠ 5 →
`PNET_ERROR_CODE_1_CONN_FAULTY_FAULTY_RECORD` (0x08) / `PNET_ERROR_CODE_2_CMRPC_AR_UUID_UNKNOWN` (0x05) = `DE 81 08 05`.
AR 없음 + opnum ≠ 5 → `PNET_ERROR_CODE_1_CMRPC` (0x40) / `PNET_ERROR_CODE_2_CMRPC_IOCR_MISSING` (0x02) = `DE 81 40 02`
(`include/pnet_api.h:181`, `:202`, `:241`, `:244`).
**재현 (오라클, DUT `pn_oracle_pipe`, Connect 없음):** `test_record_read_opnum2_without_ar_rejected` (`--runxfail`) →
`NIL ARUUID: PNIOStatus 00000000, 블록 8009003c01000001`, `unknown ARUUID: PNIOStatus 00000000, …`.
**수정 범위:** `stacks/profinet/`, `tests/`, `tools/ctt/proto/profinet/` (`record_read` 동작이 AR 없으면 opnum 5 를 쓰도록 — 이 판정만),
`tests/scenarios/profinet/` (`record_read_im0.yaml`, `record_read_im1_4.yaml`, `record_unknown_index.yaml`, `rpc_cm_without_ar.yaml` 의
`record_read` 는 AR 없이 읽는다). 큐 110 이후.
**완료 조건:** 오라클 2개 통과 (`A20261110-2` 표시 삭제). 큐 110 의 `test_record_read_implicit_im0_without_ar` 계속 통과. CTT 계속 PASS.

## 결정 3. 거부는 무응답이 아니라 에러 응답으로 알린다 (A20261110-3 → 큐 120)

**지금:** AR 없는 Control·Write, AR 중 다른 ARUUID 의 Read, 송신 IP 가 AR 소유자와 다른 Release·Control·Write·Read 를 응답 없이 버린다.
보안 결정 G4 와 CTT PN-B-NEG-008 (`tests/scenarios/profinet/rpc_cm_without_ar.yaml` `rpc_response: false`) 이 무응답을 고정한다.
**결정:** fail-closed 는 "실행하지 않는다" 이지 "답하지 않는다" 가 아니다. 에러 응답도 실행하지 않는다.
응답은 요청보다 크지 않아 증폭에 쓸 수 없고, 장치 존재는 DCP 로 이미 드러난다. 무응답은 컨트롤러가 "장치 없음" 과 "거부" 를
구분하지 못하게 할 뿐이다. 독립 구현 p-net 은 에러 PNIOStatus 로 답한다.
**기대값과 출처:** p-net `pf_cmrpc.c` — AR 을 못 찾은 DControl → `DD 81 40 05`, Write (`pf_cmrpc_perform_one_write`) → `DF 81 40 05`,
opnum 2 Read → `DE 81 40 02` (결정 2 와 같은 경로). Release 는 큐 113 (A20261108-4) 이 `DC 81 40 05` 로 다룬다.
송신 IP 불일치는 p-net 에 없는 저장소 검사 (G4) 라 독립 기준이 없다 — 코드는 구현 PR 에서 `[Claude 확인 요청]` 으로 정한다
(검증 담당 제안: 모르는 AR 과 같은 코드). 거부해도 기존 AR 은 그대로다.
**재현 (오라클):** `test_rpc_without_ar_error_response[Control|Write]` → `AR 없는 요청에 응답 없음`,
`test_read_other_ar_uuid_during_ar_error_response` → `다른 ARUUID 의 Read 에 응답 없음`. 송신 IP 경로는 pipe DUT 가 송신 IP 를 넣지
못해 단위 테스트로 본다.
**수정 범위:** `stacks/profinet/`, `tests/`, `tests/scenarios/profinet/rpc_cm_without_ar.yaml` (`rpc_response: true` + 에러 PNIOStatus 기대).
큐 113 과 같은 함수라 113 이후. 113 PR 에서 이 테스트가 통과하면 `A20261110-3` 표시도 그 PR 에서 지워도 된다.
**완료 조건:** 오라클 3개 통과 (`A20261110-3` 표시 삭제). 단위 테스트: 송신 IP 불일치 Release·Control·Write·Read 에 에러 PNIOStatus,
AR·RTC1 유지. CTT PN-B-NEG-008 의 바뀐 기대값을 PR 설명에.
