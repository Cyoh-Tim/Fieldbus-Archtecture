# 감사 2026-10-11 — EIP EDS Param 링크 경로, 병합 뒤 문서 지연

- 영역: EtherNet/IP 어댑터 (EDS) · 문서 (11단계 제안 선별)
- 출처: PR #111 (T11-2) "발견한 다른 문제" 2건, PR #106 (T5 PN) "발견한 다른 문제" 3번,
  같은 날 SLMP 감사([20261011-slmp.md](20261011-slmp.md))의 문서 항목
- 기준 커밋: `8dd315b` (main, #94·#106·#111 병합 직후)
- 판단: 검증 담당 (루틴 직접). EDS 형식은 OpENer 샘플 EDS 로 교차 확인
- 큐 추가: 2개 (A20261011-1, A20261011-2)

## A20261011-1. EDS Param1 의 링크 경로 크기·경로가 맞지 않는다

**문제:** `[Params] Param1` 의 둘째·셋째 필드(링크 경로 크기, 링크 경로)가 `6,0` 이다. 크기는 6바이트라고
선언하면서 경로는 EPATH 문자열이 아닌 숫자 `0` 이다. EDS 검사기나 엔지니어링 도구가 Param1 을 읽을 때
링크 경로를 해석하지 못하거나, 6바이트 경로를 기대하다 항목 전체를 버릴 수 있다. T11-2 (#111) 는 Param1 의
타입·크기와 Connection1·Port1 을 고쳤지만 이 두 필드는 주석 그대로 "placeholder" 로 남았다.

**근거 (파일:줄, 기준 커밋 `8dd315b`):**
- `stacks/ethernetip/eds/FieldbusSensor.eds:26` — `6,0,                $ assembly link path size/path (placeholder)`.
- 같은 파일 `:40` 의 `Param2` 는 `0,,` (크기 0, 경로 없음) 로 올바른 형태다.

**재현:** `tests/oracle/test_eip_oracle.py::test_eds_param_link_path_consistent` 를 `--runxfail` 로 돌린다.

```
AssertionError: 따옴표 문자열 아님: '0'
```

(Param1 의 크기 6 → 경로를 따옴표 hex 문자열로 읽으려다 `0` 에서 실패)

**기대값과 출처:** 링크가 없으면 크기·경로 둘 다 비운다 (`,,`), 링크가 있으면 크기 = 경로 바이트 수이고 경로는
`"20 04 24 64 30 03"` 같은 따옴표 hex EPATH 문자열이다.
- OpENer 샘플 EDS (`data/opener_sample_app.eds`, EIPStackGroup/OpENer master): `Param1 = 0, ,,  $ Link Path Size, Link Path`.
- CIP Vol. 1 7장 EDS `[Params]` 항목 정의: Link Path Size (USINT) 와 Link Path (Packed EPATH). 원문은 직접 인용하지 못했다
  — OpENer 샘플과 이 저장소의 `Param2` 를 판정 근거로 쓴다.

**수정 범위:** `stacks/ethernetip/eds/` 만. Param1 을 어떤 객체에도 링크하지 않으면 `,,` 로, Assembly 크기 속성에
링크하려면 그 EPATH 와 정확한 크기로.

**완료 조건:** `test_eds_param_link_path_consistent` 통과 (`A20261011-1` 표시 삭제). 다른 EDS 오라클 테스트는 그대로 통과.

## A20261011-2. 병합된 수정을 따라가지 못한 문서 (EIP EDS·minor_rev, CTT rpc_connect, SLMP 비트 형식)

**문제:** 세 수정이 병합됐는데 문서가 이전 동작을 설명한다. 코드 변경은 없다.

**근거 (파일:줄, 기준 커밋 `8dd315b`):**
1. EIP (T11-2, #111 이후):
   - `docs/protocols/ethernetip.md:2174` — "`major_rev`/`minor_rev` 는 config 키가 없다 (어댑터가 1/0 고정)". 지금은 `protocol_params.minor_rev` 를 읽는다 (기본 0).
   - `:2219` — EDS `[Device]` 를 "MinRev 1 … 전자키 minor 검사 시 불일치" 로 설명. 지금은 `MinRev = 0` 으로 예제 Identity 1.0 과 같다.
   - `:2228-2250` — Connection1 해석과 "RPI 자리에 두 값" 경고, `[사양서 확인 필요]` 표시. 지금은 15필드, RPI 는 `Param2` (UDINT, µs, 최소 8000), 경로 `20 04 24 64 2C 65 2C 96`.
   - 위험 표 D2 (`:2717`) — "Connection 필드 정렬 이상, MinRev 1 vs Identity 0". O→T 32비트 헤더 거절은 T11-1 (#109) 로, 나머지는 T11-2 로 해소됐다.
2. CTT (T5 PN, #106 이후): `docs/ctt.md:217` 의 `rpc_connect` 행이 선택 필드 `send_clock_factor` / `reduction_ratio`
   (둘 중 하나라도 있으면 입력 IOCR 추가, 빠진 쪽 기본 SCF 32 / RR 8)와 `expect.pniostatus` 를 적지 않는다.
3. SLMP (T10-1, #59 이후, 비트 단위 니블 형식):
   - `docs/slmp_stack.md:93` — "bit 일괄: 포인트당 1바이트 (`0x00` / `0x01`)".
   - `docs/protocols/slmp.md:662-680` ("이 저장소와의 차이 (중요, 부록 D-1)" 블록과 그 바이트열), `:1003`, `:1042`
     ("1바이트/비트 방식이라 비트 읽기는 사실상 1920 점"), `:1439`, `:1628`, `:1642`, 부록 D-1 행.
     세부는 [20261011-slmp.md](20261011-slmp.md) 의 문서 절.

**기대값과 출처:** 각 수정 PR 의 코드와 테스트 — `stacks/ethernetip/eds/FieldbusSensor.eds`, `adapters/ethernetip/ethernetip_adapter.c`
(`minor_rev`), `tools/ctt/proto/profinet/pn_plugin.c` (`step_rpc_connect`), `stacks/slmp/src/slmp_stack.c` (니블 포장),
pymcprotocol `batchread_bitunits`/`batchwrite_bitunits` (짝수 인덱스 = 상위 니블).

**수정 범위:** `docs/` 만 (`docs/protocols/ethernetip.md`, `docs/ctt.md`, `docs/slmp_stack.md`, `docs/protocols/slmp.md`).
PROFINET 입문서의 `MinDeviceInterval` 서술은 큐 68 (A20261008-4) 에 묶었다.

**완료 조건:** 위 줄들이 현재 동작을 설명한다. `[사양서 확인 필요]` 표시는 오라클·참조 구현으로 확인된 것만 지운다.
오라클 표시 없음 (문서만).

## 확인 필요

- 없음.
