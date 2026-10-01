# 작업 큐 — 구현 에이전트용 이슈 순서

인수인계 문서([`structure_handoff_20260930.md`](structure_handoff_20260930.md))의 T 항목을 **처리 순서대로** 나열한다.
검증 담당(Claude)의 일일 루틴이 이 표를 보고 GitHub 이슈를 만든다. 구현 에이전트(Grok)는 이슈를 번호 순서대로 하나씩 처리한다.

## 운영 규칙

- **열린 큐 이슈는 최대 6개**다. 이슈 제목은 `[큐 NN] T.. — 요약`, 라벨은 `grok-queue`.
- 일일 루틴(매일 12:52 KST)이 하는 일:
  1. 열린 PR 을 검증하고, 병합 정책(`.claude/skills/verify-pr/SKILL.md` 9단계)에 맞으면 병합한다. PR 본문의 `Closes #N` 으로 이슈가 닫힌다.
  2. 열린 큐 이슈가 6개보다 적으면, 아래 표에서 **아직 이슈가 없는 다음 순번**부터 채운다 (이슈 본문은 맨 아래 템플릿).
  3. 이 표의 "상태" 칸은 고치지 않는다. 진행 상황은 이슈·PR 로 본다.
- 순서를 바꾸거나 항목을 빼려면 이 파일을 고친다 (저장소 담당자 또는 검증 담당).
- "결정 필요"·"사양 확인 필요" 항목(T9-11, T10-7)은 큐에 넣지 않는다. 사람이 정한 뒤 추가한다.
- 인수인계 항목이 끝나면 검증 담당의 감사 라운드(`.claude/skills/verify-pr/SKILL.md` 12단계)가 새 항목(`A<YYYYMMDD>-<n>`)을
  표 끝에 추가한다. 근거는 `docs/reports/audits/` 의 보고서다. 구현 에이전트의 제안(`[Grok 제안]`)도 검증 담당이 재현한 뒤 같은 방식으로 들어온다.
- T11-0·T12-0 의 남은 CTT 수정은 따로 이슈를 만들지 않는다. 각 결함 PR 에서 CTT·golden 이 잘못된 동작을 고정하고 있으면 함께 고친다.

## 순서

| 큐 | T 항목 | 요약 | 작업 범위 | 오라클 표시 (`tests/oracle`) | 비고 |
|---|---|---|---|---|---|
| — | T10-2 | SLMP 타임아웃 후 stale 응답 | — | — | 완료 (#49) |
| — | T10-1 | SLMP 비트 단위 니블 형식 | — | T10-1 ×2 | 이슈 없이 진행 중 (2026-09-30) |
| 01 | T9-1 | Modbus 클라이언트 타임아웃 후 영구 TID 불일치 | `stacks/modbus/`, `tests/` | T9-1 | |
| 02 | T9-3 | Modbus 주소 문자열 앞자리 0 이 8진수로 파싱됨 | `adapters/modbus/`, `tests/` | T9-3 (테스트 2개) | |
| 03 | T9-2 | Modbus 비트필드 + 2바이트 타입 쓰기·읽기 깨짐 | `adapters/modbus/`, `tests/` | T9-2 ×2 | |
| 04 | T1 | EtherNet/IP 숫자 포인트 바이트 순서 (BE→LE) | `adapters/ethernetip/`, `tests/` | T1 ×2 (테스트 4개) | T0 A안 |
| 05 | T2 (EIP) | EtherNet/IP 포인트 scale/offset | `adapters/ethernetip/`, `tests/` | T2 (EIP) ×2 | T1 이후, T0 A안 |
| 06 | T2 (PN) | PROFINET 포인트 scale/offset | `adapters/profinet/`, `tests/` | T2 (PN) ×2 | T0 A안 |
| 07 | T12-1 | PN RPC 응답 NDR 첫 워드 = PNIOStatus | `stacks/profinet/`, `tests/`, `tools/ctt/`, `tests/golden/` | T12-1 | |
| 08 | T12-2 | PN DCP 응답 블록 BlockInfo | `stacks/profinet/`, `tests/`, `tools/ctt/`, `tests/golden/` | T12-2 | T12-22 테스트는 이 수정 뒤에야 블록 해석 가능 |
| 09 | T12-3 | PN Read/Write 응답 헤더 블록, I&M BlockHeader, Write 데이터 위치 | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-3 ×2 | T12-1 이후 (응답 NDR 해석이 전제) |
| 10 | T12-5 | PN PrmEnd 응답 0x8110/Done, ApplicationReady 형식 | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-5 ×2 | T12-1 이후 |
| 11 | T12-4 | PN IOCR 프레임 오프셋·ExpectedSubmodule·ModuleDiff/ARServer 블록 | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-4 ×3 | 큰 작업. T12-1 이후. IOCR `DataLength` 를 따르면 C_SDU 가 40바이트가 되어 T12-7 테스트도 통과할 수 있다. 그러면 T12-7 표시도 이 PR 에서 지운다 (허용) |
| 12 | T12-6 | PN DataStatus 0x35 | `stacks/profinet/`, `tests/`, `tests/golden/` | T12-6 | |
| 13 | T12-7 | PN RTC1 최소 길이 패딩 | `stacks/profinet/`, `tests/` | T12-7 | |
| 14 | T12-8 | PN RTC1·알람 VLAN 태그 | `stacks/profinet/`, `tests/` | T12-8 | 오라클은 RTC1 만 본다 (알람은 PR 테스트로) |
| 15 | T4 + T12-15 | PN RT 송신 주기 = 협상값, CycleCounter 증가량 | `stacks/profinet/`, `tests/` | T4, T12-15 | |
| 16 | T5 (PN) + T12-13 | PN 최소 주기 거부(`DB 81 02 0E`)와 GSDML 정리 | `stacks/profinet/`, `stacks/profinet/gsdml/`, `tests/` | T5 (PN) ×2, T12-13 | T12-1 이후 |
| 17 | T11-1 | EIP O→T 32-bit Run/Idle 헤더 | `stacks/ethernetip/`, `tests/`, `tools/ctt/` | T11-1 | |
| 18 | T11-2 | EIP EDS 재작성, minor_rev | `stacks/ethernetip/eds/`, `adapters/ethernetip/` | T11-2 ×5 | 어댑터 부분은 별도 PR 가능 |
| 19 | T11-3 | EIP Forward Open/Close 실패 응답 형식 | `stacks/ethernetip/`, `tests/`, `tools/ctt/` | T11-3 | |
| 20 | T11-4 | EIP UDP 44818 ListIdentity 등 | `stacks/ethernetip/`, `tests/` | T11-4 ×4 | ListInterfaces 는 T11-9 에도 있다. T11-9 PR 이 구현하면 `test_list_interfaces_supported` 의 T11-4 표시도 그 PR 에서 지운다 (허용) |
| 21 | T11-5 | EIP Exclusive Owner 소유권, Input Only, 멀티캐스트 | `stacks/ethernetip/`, `tests/` | T11-5 | |
| 22 | T11-6 | EIP Connection ID 선택·생산 목적지·출발지 검증 | `stacks/ethernetip/`, `tests/` | T11-6 ×4 | 보안 |
| 23 | T11-7 | EIP transport class/trigger 검사 | `stacks/ethernetip/`, `tests/` | T11-7 | |
| 24 | T5 (EIP) | EIP 최소 RPI 거부(`0x01/0x0112` + 허용 RPI)와 EDS RPI 범위 | `stacks/ethernetip/`, `tests/` | T5 (EIP) ×3 | T11-2 이후. 거부 응답 꼬리는 T11-3 형식에 의존 (T11-3 이후). T11-2 PR 이 EDS RPI Param 까지 넣으면 `test_eds_rpi_param_minimum_matches_cycle` 의 T5 (EIP) 표시도 그 PR 에서 지운다 (허용) |
| 25 | T3 | Modbus/SLMP 클라이언트 모드 fail-fast·백오프 (1단계) | `adapters/modbus/`, `adapters/slmp/` (PR 2개) | T3 (Modbus 만) | #49 검증 코멘트의 connect 타임아웃 메모 참고. #49 검증 코멘트의 connect 타임아웃 메모 참고. SLMP 는 이미 백오프가 있어 오라클 없음 (완료 조건의 timeout 해석은 사람 결정). T9-1 수정에 백오프까지 넣으면 T3 표시도 그 PR 에서 지운다 (허용) |
| 26 | T9-5 | Modbus 클라이언트 non-blocking connect | `stacks/modbus/`, `tests/` | T9-5 | |
| 27 | T10-3 | SLMP A~F 로 시작하는 16진 번호 파싱 | `adapters/slmp/`, `tests/` | T10-3 (테스트 3개) | |
| 28 | T10-4 | SLMP 문자열·32비트 기본 배치를 MELSEC 관례로 | `adapters/slmp/`, `config/`, `tests/` | T10-4 ×2 (테스트 3개) | 기존 설정 호환성 주의 |
| 29 | T9-4 | Modbus 수량 위반 예외 03 | `stacks/modbus/`, `tests/`, `tests/scenarios/modbus/` | T9-4 ×2 | |
| 30 | T9-6 | Modbus Unit ID 0xFF 수락 | `stacks/modbus/`, `tests/` | T9-6 | |
| 31 | T12-9 | PN 자체 HMAC 보안 기본값 끄기·명칭 정리 | `adapters/profinet/`, `stacks/profinet/`, `docs/` | T12-9 | |
| 32 | T12-10 | PN 알람 RTA-PDU 형식·AlarmCRBlockReq 파싱 | `stacks/profinet/`, `tests/` | T12-10 ×2 | |
| 33 | T12-11 | PN LLDP OUI·PortID·필수 TLV | `stacks/profinet/`, `tests/` | T12-11 | |
| 34 | T12-12 | PN AlarmCRBlockRes 길이, ARBlockRes 포트 | `stacks/profinet/`, `tests/` | T12-12 ×2 | |
| 35 | T12-14 | PN DCE/RPC 헤더 처리 (drep, UUID, 단편화, EPM) | `stacks/profinet/`, `tests/` | T12-14 ×4 | |
| 36 | T12-16 | PN DCP Set 처리 규칙 | `stacks/profinet/`, `tests/` | T12-16 ×3 | |
| 37 | T12-17 | PN 표준 Release(0x0114) | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-17 | |
| 38 | T12-18 | PN 미지원 레코드 index 에러 | `stacks/profinet/`, `tests/` | T12-18 ×2 | T12-1 이후 |
| 39 | T12-19 | PN SNMP 요청 파싱 | `stacks/profinet/`, `tests/` | T12-19 ×2 | |
| 40 | T12-20 | PN DCP IP 적용·이름/I&M 저장 | `stacks/profinet/`, `tests/` | 없음 | 오라클 없음: OS IP 적용은 실제 NIC·root 필요, 비휘발 저장은 설정 인터페이스 미정 |
| 41 | T12-21 | PN 어댑터 slot/subslot/index, 예제 입력 길이 | `adapters/profinet/`, `config/` | T12-21 | |
| 42 | T12-22 | PN IOCRReference, DCP 지연 슬롯, DeviceRole 0x01 | `stacks/profinet/`, `tests/` | T12-22 | T12-2 이후 |
| 43 | T11-8 | EIP Class 1 소비 규칙·FO 파라미터 검증 | `stacks/ethernetip/`, `tests/` | T11-8 ×4 (테스트 6개) | |
| 44 | T11-9 | EIP Encapsulation 편차 | `stacks/ethernetip/`, `tests/` | T11-9 | |
| 45 | T11-10 | EIP 표준 객체 속성 | `stacks/ethernetip/`, `tests/` | T11-10 ×10 | |
| 46 | T11-11 | EIP 자체 보안 프로파일 명칭 정리 | `stacks/ethernetip/`, `docs/` | 없음 | |
| 47 | T11-12 | EIP Originator Logix 태그 서비스 | `stacks/ethernetip/`, `tests/` | T11-12 ×3 | |
| 48 | T11-13 | EIP 기타 (워치독 여유, Reset, 버퍼, LLDP 송신) | `stacks/ethernetip/`, `tests/` | T11-13 ×4 | |
| 49 | T10-5 | SLMP 서버 시뮬 엔드 코드·에러 정보 | `stacks/slmp/`, `tests/`, `tests/scenarios/slmp/` | T10-5 | |
| 50 | T10-6 | SLMP 서버 시뮬 비트 디바이스 워드 접근 선두 번호 | `stacks/slmp/`, `tests/` | T10-6 | |
| 51 | T9-7 | Modbus TCP_NODELAY | `stacks/modbus/` | T9-7 | |
| 52 | T9-8 | Modbus send EAGAIN 처리 | `stacks/modbus/`, `tests/` | T9-8 | T9-8 을 응답 모아 보내기로 구현하면 T9-7 도 통과할 수 있다. 그러면 T9-7 표시도 그 PR 에서 지운다 (허용) |
| 53 | T9-9 | Modbus TID 카운터 인스턴스 필드로 | `stacks/modbus/` | T9-9 | |
| 54 | T9-10 | Modbus 스키마 `chars_per_word` 통일 | `adapters/modbus/` 또는 `config/` | T9-10 | |
| 55 | T8 | `config_loader.c` 를 `LOG_*` 로 | `core/config_loader.c` | 없음 | 패치가 인수인계 문서에 있음 |
| 56 | T6 | `core/scheduler.c` 중복 정리 | `core/`, `CLAUDE.md`, `CMakeLists.txt` | 없음 | |
| 57 | T7 | 사이클 지연 µs 측정 | `core/`, `include/fb_api.h` | 없음 | T6 이후 |
| 58 | T0 | 스케일·바이트 순서 규칙 문구 통일 (A안) | `CLAUDE.md`, `docs/`, `include/fb_api.h` 주석 | 없음 | T1·T2 이후 |

## 이슈 본문 템플릿

일일 루틴이 큐 이슈를 만들 때 이 템플릿을 채운다. `<…>` 는 위 표와 인수인계 문서에서 가져온다.
인수인계 문서의 해당 항목(표 행 또는 절)을 **요약하지 말고 그대로** "항목 내용" 에 붙인다.

````markdown
<!-- work-queue: <큐 번호> <T 항목> -->
## 작업: 인수인계 <T 항목> — <요약>

main 최신 기준으로 새 브랜치를 만들어 작업한다. 이 이슈 하나당 PR 하나.

1. `CLAUDE.md` 를 먼저 읽고 규칙을 지킨다. 작업 범위: <작업 범위>. 그 밖의 디렉토리는 건드리지 않는다.
   새 테스트 실행 파일이 필요하면 `CMakeLists.txt` 에 테스트 타깃(`add_executable`/`add_test`)을 추가하는 것만 허용한다.
2. `docs/reports/structure_handoff_20260930.md` 의 "공통 규칙" 과 "<T 항목>" 만 읽고 그 작업만 한다.
   (감사 발견 항목 `A<ID>` 는 인수인계 문서 대신 비고에 링크된 `docs/reports/audits/…` 보고서의 해당 절을 읽는다.)
   관련 설명이 `docs/protocols/<프로토콜>.md` 에 있으면 함께 읽는다.
3. 코드를 고치기 전에 결함을 재현하는 테스트를 먼저 추가하고, 그 테스트가 실패하는 것을 확인한다.
   PR 설명에 수정 전 실패 출력을 붙인다.
4. 오라클 표시: <`tests/oracle/` 의 `@known_defect("<T 항목>", …)` 줄을 지운다 | 이 항목은 오라클 표시가 없다>.
   큐 표 "비고" 에 이 PR 에서 함께 지워도 된다고 적힌 다른 표시가 있으면, 그 테스트가 실제로 통과할 때만 같이 지운다.
   `tests/oracle/` 의 다른 내용(기대값, 요청 인코더, requirements)은 바꾸지 않는다.
5. 기존 CTT 시나리오·golden 이 잘못된 동작을 정답으로 고정하고 있으면 같은 PR 에서 고치고, 바꾼 기대값을 PR 설명에 모두 적는다.
6. 줄번호가 문서와 다르면 함수 이름으로 찾는다.
   모호한 부분(사양 해석, 오라클 기대값에 대한 반론, 범위 밖 변경이 필요해 보이는 것)은 추측으로 구현하지 말고,
   이 이슈(PR 을 열었으면 PR)에 `[Claude 확인 요청]` 으로 시작하는 코멘트를 남긴다. 검증 담당이 일일 루틴에서 답한다.
   답을 기다리는 동안 나머지 부분은 진행한다.
   `[담당자 결정]` 머리말은 저장소 담당자만 쓴다. 구현 에이전트는 쓰지 않는다.
7. 검증 (GitHub Actions 는 꺼져 있다): `python3 tools/ci/local_ci.py --install-deps` 가 전부 PASS 여야 한다.
   `summary.md` 표를 PR 설명에 붙인다.
8. PR 제목은 `fix(<프로토콜>): <T 항목> <요약>`, 본문 첫 줄은 `Closes #<이 이슈 번호>`.
   설명에 인수인계 문서의 "완료 조건" 을 하나씩 어떻게 만족했는지 적는다.
   작업 중 이 항목 밖의 문제를 봤으면 고치지 말고 PR 설명의 "발견한 다른 문제" 절에 파일:줄·재현·근거를 적는다
   (PR 과 무관하면 제목이 `[Grok 제안]` 인 이슈로). 검증 담당이 재현해서 큐에 넣는다.
9. PR 은 열기만 하고 병합하지 않는다. 검증 담당(Claude)이 일일 루틴(매일 12:52 KST)에서 검증하고, 병합 정책에 맞으면 병합한다.

### 항목 내용 (인수인계 문서에서 그대로)

<인수인계 문서의 해당 행 또는 절>
````
