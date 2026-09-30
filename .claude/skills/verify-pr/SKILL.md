---
name: verify-pr
description: 코딩 에이전트(Grok 등)가 올린 PR 을 구현자와 독립적으로 검증한다. 인수인계 문서(docs/reports/structure_handoff_*.md)의 완료 조건, 수정 전 실패/수정 후 통과 재현, 독립 구현체(오라클) 교차 확인, CLAUDE.md 경계를 확인하고 PR 에 결과 코멘트 1개를 남긴다. 주간 검증 루틴이나 "PR 검증해" 요청 때 사용.
---

# PR 독립 검증 절차

이 저장소는 **Grok 이 구현하고 Claude 가 검증**한다. 검증자는 구현자의 테스트를 믿지 않는다.
배경: 2026-09-30 분석에서 EtherNet/IP·PROFINET 스택이 자체 테스트를 모두 통과했지만, CTT·golden·단위
테스트가 스택과 같은 잘못된 가정을 공유하고 있었다 ([`docs/reports/structure_handoff_20260930.md`](../../../docs/reports/structure_handoff_20260930.md) T11-0, T12-0).
사양서 원문이 없으므로, **실제 장비와 상호운용이 검증된 오픈소스 구현체를 오라클로 쓴다.**

## 절대 하지 않는 것

- PR 브랜치에 푸시하지 않는다. 병합·승인(approve)하지 않는다. 브랜치를 삭제하지 않는다.
- 검증용 하네스·스크립트를 저장소에 커밋하지 않는다 (스크래치 디렉토리에만 둔다).
- PR 의 테스트가 통과했다는 사실만으로 PASS 를 주지 않는다.
- 추측으로 FAIL 을 주지 않는다. 재현하지 못한 의심은 "확인 필요" 로 적는다.

## 0. 대상 PR 고르기

1. `main` 을 향한 **열린 PR** 을 모두 나열한다.
2. 다음은 건너뛴다.
   - draft PR
   - Claude 세션이 연 PR (브랜치가 `claude/` 로 시작)
   - 현재 head SHA 에 대한 검증 코멘트가 이미 있는 PR. 마커 `<!-- claude-verify: <head_sha> -->` 로 판별한다.
     head 가 바뀌었으면 다시 검증한다.
3. 대상이 없으면 "검증할 PR 없음" 으로 끝낸다 (코멘트 없음).

## 1. PR 이 무엇을 하는지 파악

- 제목·본문에서 인수인계 T 항목(예: `T11-1`, `T9-3`)을 찾는다. 인수인계 문서에서 그 항목의
  **문제 / 근거 / 수정 범위 / 완료 조건** 을 읽는다.
- T 항목이 없는 PR 은 본문의 주장과 diff 를 기준으로 검증하고, 결과에 "T 항목 없음" 이라고 적는다.
- `git diff --stat origin/main...<head>` 로 바뀐 경로를 확인한다.

## 2. 경계 검사 (CLAUDE.md)

`CLAUDE.md` 를 읽고 확인한다.
- 어댑터 작업이 다른 `adapters/<name>/` 를 건드렸는가
- `core/*.c` 에 프로토콜 이름 분기(`if (protocol == …)`, `strcmp(…, "modbus_tcp")` 등)가 추가됐는가
- `include/protocol_adapter.h` 가 사전 논의 없이 바뀌었는가
- `printf` 직접 호출이 추가됐는가 (`LOG_*` 대신)
- PROFINET IRT / CC-C 를 켰는가
- T 항목의 "수정 범위" 밖 파일이 바뀌었는가 (테스트·문서 추가는 허용)

위반은 FAIL 사유다. 단, T 항목이 그 범위를 명시적으로 허용했으면 예외.

## 3. 전체 회귀 — 기존 CI 결과를 먼저 읽는다

전체 회귀(빌드, ctest, golden, sanitizers, fuzz 60s, mock-flow, sw-master-soak, codesys-dut)는
**기존 GitHub Actions CI(`.github/workflows/ci.yml`)가 PR 마다 이미 돌린다.** 같은 것을 다시 돌리지 않는다.

1. PR head SHA 의 check run 을 읽는다.
   - 진행 중이면 이번 실행에서는 "CI 진행 중 — 다음 주기에 재검증" 으로 적고 코멘트를 달지 않는다.
   - 실패가 있으면 그 job 로그를 읽고, base(`main`)에서도 실패하는지 확인한다. PR 이 만든 실패면
     그것만으로 **FAIL** 이다 (4·5단계는 생략 가능, 코멘트에 실패 job 과 원인 요약).
   - Cursor Bugbot 처럼 사용량 한도로 실행되지 못한 봇 체크(neutral)는 판정에 넣지 않는다.
2. CI 가 green 이면, 4·5단계를 위해 PR head 를 별도 worktree(스크래치 디렉토리)에 체크아웃해서
   로컬로 빌드한다. CI 에 없는 `-Werror` 를 추가해 경고 회귀도 본다.

```bash
cmake -S <wt> -B <wt>/build -DBUILD_DAEMON=ON -DBUILD_CTT=ON -DBUILD_API=ON \
      -DENABLE_PN_TESTS=ON -DENABLE_EIP_TESTS=ON -DENABLE_MB_TESTS=ON -DENABLE_SLMP_TESTS=ON \
      -DCMAKE_C_FLAGS="-Wall -Wextra -Werror"
cmake --build <wt>/build -j
```

CI 가 하지 못하는 것만 로컬에서 한다: **base 에서 실패/head 에서 통과 비교(4단계)** 와 **독립 오라클(5단계)**.
T11-0·T12-0 으로 오라클 테스트가 저장소 CI 에 들어오면, 5단계는 그 CI job 결과 확인 + 오라클 테스트
자체가 스택과 가정을 공유하지 않는지 검토하는 것으로 줄인다.

## 4. 재현 테스트: 수정 전 실패, 수정 후 통과

인수인계 문서는 항목마다 재현 테스트를 요구한다.
1. PR 이 추가·수정한 테스트 파일을 찾는다.
2. **base 코드 + PR 의 테스트** 조합을 만든다 (base worktree 에 테스트 파일만 복사). 빌드해서 돌린다.
   → **실패해야 한다.** 통과하면 그 테스트는 결함을 잡지 못하는 것이다 (FAIL 사유).
3. PR head 에서 같은 테스트가 **통과해야 한다.**
4. 인수인계 문서에 재현 하네스나 명령이 적혀 있으면(예: T1 의 `fb_write_u32(300)` → `2C 01`) 그것도
   직접 돌려서 기대값을 확인한다.

## 5. 독립 오라클 교차 확인 (핵심)

PR 이 바꾼 프로토콜에 대해, **저장소 코드를 공유하지 않는** 구현체로 스택의 실제 바이트를 확인한다.
스택은 DUT(시험 대상)로만 돌리고, 판정은 오라클이 한다. 하네스는 스크래치에 둔다.

| 프로토콜 | 오라클 (pip) | 방법 |
|---|---|---|
| Modbus TCP | `pymodbus` | 스택 서버(`mb_seeded_server` 또는 데몬)에 pymodbus 클라이언트로 FC01–06/15/16/23 요청, 값과 예외 코드 확인. 클라이언트 모드는 pymodbus 서버를 상대로 |
| SLMP | `pymcprotocol` | 스택 서버 시뮬레이터에 pymcprotocol 로 워드/비트 batch read·write. 클라이언트 모드는 pymcprotocol 인코딩 바이트와 스택 인코딩 바이트 비교 (비트 단위는 니블 형식) |
| EtherNet/IP | `pycomm3`, `scapy` (`scapy.contrib.enipTCP`), 가능하면 tshark | ListIdentity·RegisterSession·Get_Attribute, Forward Open(O→T 32-bit Run/Idle 헤더 포함, Logix 기본 형식) 요청과 응답 파싱. 응답을 오라클 파서로 해석했을 때 필드가 기대값과 맞는지 |
| PROFINET | `scapy` (`scapy.contrib.pnio`, `pnio_dcp`, `pnio_rpc`), 가능하면 tshark | mock Ethernet 으로 DCP Identify/Set, RPC Connect/Write/Read/Control, RTC1 프레임을 받아 scapy 로 디섹트. BlockInfo, PNIOStatus, DataStatus, 블록 타입이 사양 형태로 읽히는지 |

- 오라클이 해당 기능을 지원하지 않으면 그렇게 적고, 대신 Wireshark 디섹터 소스의 필드 정의나 인수인계
  문서의 기대값을 근거로 쓴다. 근거가 없으면 "오라클 없음 — 확인 필요".
- 참고용 하네스 패턴: `docs/protocols/<proto>.md` 의 "테스트와 디버깅" 절과 부록의 hex 예제.
- `pip install` 은 가능하다 (pypi 는 프록시 예외). tshark 는 없을 수 있다.

## 6. 판정

| 판정 | 조건 |
|---|---|
| **PASS** | 경계 위반 없음, 전체 회귀 통과, 재현 테스트가 base 에서 실패·head 에서 통과, 오라클 확인 통과, T 항목 완료 조건 모두 충족 |
| **FAIL** | 위 중 하나라도 실제로 재현된 실패가 있음 |
| **확인 필요** | 실패는 재현되지 않았지만 오라클이 없거나 실장비 확인이 필요한 항목이 남음 |

PASS 여도 **병합은 사람이 결정**한다. 코멘트에 "병합 여부는 저장소 담당자가 결정" 을 적는다.

## 7. PR 에 코멘트 1개

PR 대화 탭에 일반 코멘트 하나를 남긴다 (review approve/request-changes 아님). 형식:

```markdown
<!-- claude-verify: <head_sha> -->
## Claude 독립 검증 — <PASS | FAIL | 확인 필요>

대상: <T 항목> · head `<sha 7자리>` · 검증 시각 <UTC>

| 확인 | 결과 | 근거 |
|---|---|---|
| 경계 (CLAUDE.md) | ✅/❌ | … |
| 전체 회귀 (ctest, sanitizer) | ✅/❌ | 통과 수 / 실패 테스트 |
| 재현: base 에서 실패 | ✅/❌ | 테스트 이름, 실패 메시지 |
| 재현: head 에서 통과 | ✅/❌ | … |
| 오라클 (<이름>) | ✅/❌/— | 핵심 바이트 또는 필드 |
| 완료 조건 | ✅/❌ | 조건별 한 줄 |

### 실패·확인 필요 상세
(재현 명령과 실제 출력. 없으면 생략)

병합 여부는 저장소 담당자가 결정한다.

---
_Generated by [Claude Code](https://claude.ai/code)_
```

- 오라클 하네스 코드가 짧으면(50줄 이하) `<details>` 로 코멘트에 붙인다. 재현 가능성이 중요하다.
- 같은 PR 에 코멘트를 여러 개 달지 않는다. head 가 바뀌어 재검증할 때만 새 코멘트를 단다.

## 8. 실행 요약

모든 PR 을 처리한 뒤, 세션 최종 메시지로 요약한다: PR 번호, T 항목, 판정, 한 줄 사유.
인수인계 문서에서 아직 PR 이 없는 치명·높음 항목이 있으면 그 목록도 붙인다 (진행 상황 파악용).
