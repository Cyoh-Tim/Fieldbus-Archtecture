# 2026-11-10 — EIP 자체 보안 프로파일이 표준 클래스 0x5E 로 응답한다 (#186 답, #195 선별)

- 영역: EtherNet/IP 스택 (0-1단계 질문 답 + 11단계 제안 선별)
- 출처: #186 `[Claude 확인 요청]` (식별자 `CIP_CLASS_EIP_SECURITY` 유지 여부), #195 (T11-11) "발견한 다른 문제"
- 기준 커밋: `5af1ded` (main, #192 병합 직후)
- 판단: 검증 담당 (루틴 직접, 원시 CIP 재현 + Wireshark 대조)
- 큐 추가: 1개 (A20261110-1 → 큐 118). 큐 117 비고 보강

## A20261110-1. 표준 클래스 0x5E (EtherNet/IP Security Object) 를 비표준 의미로 노출한다

**문제:** 저장소 보안은 자체 프로파일 (HMAC 무결성 / TLS-PSK, ODVA CIP Security 아님, 인증 주장 아님 — `CLAUDE.md` 4항) 이다.
그런데 스택은 CIP Volume 8 의 EtherNet/IP Security Object 클래스 번호 0x5E 로 Get_Attribute_Single 에 답한다.
- attr 1 = `security_class` (UINT 2바이트). 표준 attr 1 은 State (USINT).
- attr 2 = 능력 비트 (UDINT, bit 0 HMAC, bit 1 TLS). 표준 attr 2 Capability Flags 의 비트 의미와 다르다.
- attr 3 = TLS 포트 (UINT). 표준 attr 3 은 Available Cipher Suites.
표준 툴(Wireshark, 엔지니어링 툴의 CIP Security 설정 화면)은 장치에 CIP Security 객체가 있다고 보고 값을 잘못 읽는다.
이름을 아무리 고쳐도 와이어에서는 CIP Security 를 주장하는 셈이다.

**근거:** `stacks/ethernetip/src/eip_cip.c:534-560` (`5af1ded`) — `class_id == CIP_CLASS_EIP_SECURITY (0x5E) && instance == 1`
Get_Attribute_Single attr 1·2·3. `stacks/ethernetip/include/eip_types.h:114`.
**재현 (오라클, DUT `eip_oracle_adapter`, security_class 0):** `test_eip_security_object_not_misrepresented` (`--runxfail`) →
`AssertionError: class 0x5E attr 1 8e0000000000` (status 0, 데이터 `0000` 2바이트).
**기대값과 출처:** Wireshark `epan/dissectors/packet-enip.c` (master) 클래스 0x5E 속성 표 — 1 State (`cip_usint`), 2 Capability Flags,
3 Available Cipher Suites, 4 Allowed Cipher Suites, 5 Pre-Shared Keys, … 서비스 0x4B Begin_Config, 0x4C Kick_Timer, 0x4D Apply_Config.
`packet-cip.c` 클래스 이름 표 `0x5D "CIP Security"`, `0x5E "EtherNet/IP Security"`.
**수정 범위:** `stacks/ethernetip/`, `tests/` (+ `tests/scenarios/ethernetip/sec_integrity_fo.yaml` 의 `class_id: 0x5E` 단계).
- 자체 프로파일 상태를 CIP 로 보여야 하면 벤더 고유 클래스 범위 (0x64–0xC7) 의 번호로 옮긴다. 필요 없으면 0x5E 응답을 지운다
  (없는 객체 → general status 0x05). 어느 쪽인지는 구현 PR 에서 `[Claude 확인 요청]` 으로 정한다.
- 식별자 `CIP_CLASS_EIP_SECURITY` 는 표준 번호 이름이라 남겨도 되지만, 이 클래스로 응답하지 않는다.
- 문서 (`docs/ethernetip_stack.md`, `docs/protocols/ethernetip.md`, `docs/ctt_odva_matrix.md`) 의 0x5E 설명을 같은 PR 에서 맞춘다.
**완료 조건:** `test_eip_security_object_not_misrepresented` 통과 (`A20261110-1` 표시 삭제). CTT `sec_integrity_fo` 계속 PASS
(바뀐 기대값은 PR 설명에).

## 선별 결과 (#195 "발견한 다른 문제")

| 후보 | 판정 | 이유 |
|---|---|---|
| `config/example.codesys.ethernetip.json:9` `_comment` "no CIP Security HMAC" | 큐 117 에 붙임 | 문서성 문구. 같은 표현 정리 |
| `README.md:69-71` EIP 범위에 보안 프로파일 문장 없음 | 큐 117 에 붙임 | PN 줄과 맞춘다. 잘못된 주장은 아님 |
| `docs/soak_report_20260909.md`, `docs/reports/security_fixes_20260928.md` 의 옛 표현 | 제외 | 과거 기록은 고치지 않는다 |
| `docs/reports/structure_handoff_20260930.md:423` "저장소 무결성 프로파일(비표준)" | 제외 | 작업 지시 원문. #186 댓글이 우선 |
