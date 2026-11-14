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
| 10 | T12-5 | PN PrmEnd 응답 0x8110/Done, ApplicationReady 형식 | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-5 ×2 | T12-1 이후. ApplicationReady 목적지는 컨트롤러 IP 의 UDP 34964 고정 (인수인계의 "`CMInitiatorUDPRTPort` 로 전송" 은 틀림 — [audits/20261005-pn-oracle-connect.md](audits/20261005-pn-oracle-connect.md) 3절) |
| 11 | T12-4 | PN IOCR 프레임 오프셋·ExpectedSubmodule·ModuleDiff/ARServer 블록 | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-4 ×3 | 큰 작업. T12-1 이후. IOCR `DataLength` 를 따르면 C_SDU 가 40바이트가 되어 T12-7 테스트도 통과할 수 있다. 그러면 T12-7 표시도 이 PR 에서 지운다 (허용). 2026-10-05 오라클 정정: Connect 의 NO_IO 서브모듈에 DataDescription 1개, ARServerBlock 은 Advanced startup 에서만 (`test_connect_legacy_response_has_no_ar_server_block` 추가 — 이 표시 없이 통과해야 함) |
| 12 | T12-6 | PN DataStatus 0x35 | `stacks/profinet/`, `tests/`, `tests/golden/` | T12-6 | |
| 13 | T12-7 | PN RTC1 최소 길이 패딩 | `stacks/profinet/`, `tests/` | T12-7 | |
| 14 | T12-8 | PN RTC1·알람 VLAN 태그 | `stacks/profinet/`, `tests/` | T12-8 | 오라클은 RTC1 만 본다 (알람은 PR 테스트로) |
| 15 | T4 + T12-15 | PN RT 송신 주기 = 협상값, CycleCounter 증가량 | `stacks/profinet/`, `tests/` | T4, T12-15 | |
| 16 | T5 (PN) + T12-13 | PN 최소 주기 거부(`DB 81 02 0E`)와 GSDML 정리 | `stacks/profinet/`, `stacks/profinet/gsdml/`, `tests/` | T5 (PN) ×2, T12-13 | T12-1 이후. **거부 코드 정정 (2026-10-09): 주기 미달은 `DB 81 02 0B` (ErrorCode2 11 ReductionRatio). 제목·인수인계의 `0E`(14 = FrameSendOffset) 는 오류** — [audits/20261009-pnio-errorcode2.md](audits/20261009-pnio-errorcode2.md) |
| 17 | T11-1 | EIP O→T 32-bit Run/Idle 헤더 | `stacks/ethernetip/`, `tests/`, `tools/ctt/` | T11-1 | |
| 18 | T11-2 | EIP EDS 재작성, minor_rev | `stacks/ethernetip/eds/`, `adapters/ethernetip/` | T11-2 ×5 | 어댑터 부분은 별도 PR 가능 |
| 19 | T11-3 | EIP Forward Open/Close 실패 응답 형식 | `stacks/ethernetip/`, `tests/`, `tools/ctt/` | T11-3 | |
| 20 | T11-4 | EIP UDP 44818 ListIdentity 등 | `stacks/ethernetip/`, `tests/` | T11-4 ×4 | ListInterfaces 는 T11-9 에도 있다. T11-9 PR 이 구현하면 `test_list_interfaces_supported` 의 T11-4 표시도 그 PR 에서 지운다 (허용) |
| 21 | T11-5 | EIP Exclusive Owner 소유권, Input Only, 멀티캐스트 | `stacks/ethernetip/`, `tests/` | T11-5 | |
| 22 | T11-6 | EIP Connection ID 선택·생산 목적지·출발지 검증 | `stacks/ethernetip/`, `tests/` | T11-6 ×4 | 보안 |
| 23 | T11-7 | EIP transport class/trigger 검사 | `stacks/ethernetip/`, `tests/` | T11-7 | |
| 24 | T5 (EIP) | EIP 최소 RPI 거부(`0x01/0x0112` + 허용 RPI)와 EDS RPI 범위 | `stacks/ethernetip/`, `tests/` | T5 (EIP) ×3 | T11-2 이후. 거부 응답 꼬리는 T11-3 형식에 의존 (T11-3 이후). T11-2 PR 이 EDS RPI Param 까지 넣으면 `test_eds_rpi_param_minimum_matches_cycle` 의 T5 (EIP) 표시도 그 PR 에서 지운다 (허용) |
| 25 | T3 | Modbus/SLMP 클라이언트 모드 fail-fast·백오프 (1단계) | `adapters/modbus/`, `adapters/slmp/` (PR 2개) | T3 (Modbus 만) | #49 검증 코멘트의 connect 타임아웃 메모 참고. #49 검증 코멘트의 connect 타임아웃 메모 참고. SLMP 는 이미 백오프가 있어 오라클 없음 (완료 조건의 timeout 해석은 사람 결정). T9-1 수정에 백오프까지 넣으면 T3 표시도 그 PR 에서 지운다 (허용). **구동 모델 항목(큐 74~76) 이후에 진행 (2026-10-12): 그 뒤 이벤트 구동 클라이언트 기준으로 완료 조건을 다시 본다** |
| 26 | T9-5 | Modbus 클라이언트 non-blocking connect | `stacks/modbus/`, `tests/` | T9-5 | |
| 27 | T10-3 | SLMP A~F 로 시작하는 16진 번호 파싱 | `adapters/slmp/`, `tests/` | T10-3 (테스트 3개) | |
| 28 | T10-4 | SLMP 문자열·32비트 기본 배치를 MELSEC 관례로 | `adapters/slmp/`, `config/`, `tests/` | T10-4 ×2 (테스트 3개) | 기존 설정 호환성 주의 |
| 29 | T9-4 | Modbus 수량 위반 예외 03 | `stacks/modbus/`, `tests/`, `tests/scenarios/modbus/` | T9-4 ×2 | |
| 30 | T9-6 | Modbus Unit ID 0xFF 수락 | `stacks/modbus/`, `tests/` | T9-6 | |
| 31 | T12-9 | PN 자체 HMAC 보안 기본값 끄기·명칭 정리 | `adapters/profinet/`, `stacks/profinet/`, `docs/` | T12-9 | |
| 32 | T12-10 | PN 알람 RTA-PDU 형식·AlarmCRBlockReq 파싱 | `stacks/profinet/`, `tests/` | T12-10 ×2 | |
| 33 | T12-11 | PN LLDP OUI·PortID·필수 TLV | `stacks/profinet/`, `tests/` | T12-11 |. 2026-10-25 #155 검증: scapy LLDP 확인을 오라클로 옮김 — `test_lldp_port_id_is_port_name`, `test_lldp_profinet_required_tlvs` 의 T12-11 표시도 이 항목 PR 에서 함께 지운다 (통과할 때만) |
| 34 | T12-12 | PN AlarmCRBlockRes 길이, ARBlockRes 포트 | `stacks/profinet/`, `tests/` | T12-12 ×2 | |
| 35 | T12-14 | PN DCE/RPC 헤더 처리 (drep, UUID, 단편화, EPM) | `stacks/profinet/`, `tests/` | T12-14 ×4 |. 2026-10-27 (#151 반론): 오라클 `pnio_request` 의 장치 object UUID 를 Instance+DeviceID+VendorID (`…-00010001abcd`) 로 정정. object UUID 검사는 이 순서만 받는다. EPM 은 UDP 34964 에서만 (UDP 135 안 엶). 2026-10-29: EPM 오라클을 scapy `ept_lookup_Response`·`protocol_tower_t` 디코드로 강화 (ept_entry_t 배치, tower floor 개수·길이 LE) — 보고서 [audits/20261029-pn-dcp-ar-epm.md](audits/20261029-pn-dcp-ar-epm.md) |
| 36 | T12-16 | PN DCP Set 처리 규칙 | `stacks/profinet/`, `tests/`, `tools/ctt/proto/profinet/` (DCP Set `result: reject` 판정만) | T12-16 ×7 | 2026-10-29 오라클 정정 (#167 답): AR 중 이름 Set 은 기본 수락 + AR abort, ARProperties bit 27 RejectDCPsetRequests=1 일 때만 거부. AR 중 IP Set 거부. ResetToFactory 는 BlockQualifier 모드별, 공장값 = 빈 이름·0.0.0.0, AR 중 수락 + abort. 근거 p-net CMINA 상태표 구현·Wireshark — 보고서 [audits/20261029-pn-dcp-ar-epm.md](audits/20261029-pn-dcp-ar-epm.md). CTT 하네스 `reject` = ServiceType 1 + BlockError ≠ 0 |
| 37 | T12-17 | PN 표준 Release(0x0114) | `stacks/profinet/`, `tests/`, `tools/ctt/` | T12-17 | |
| 38 | T12-18 | PN 미지원 레코드 index 에러 | `stacks/profinet/`, `tests/` | T12-18 ×2 | T12-1 이후. 2026-11-02 (#174 검증): 오라클 `test_record_read_unsupported_index_error` 에 IODReadResHeader padding 0 검사 추가 — PNIOStatus 는 NDR 에만 (Wireshark `dissect_IODReadResHeader_block`, p-net `pf_put_read_result`). #160 답: 진단(0x800A)·I&M0FilterData(0xF840) 레코드 바디는 이 항목 밖, 그 index 는 에러가 기대값 |
| 39 | T12-19 | PN SNMP 요청 파싱 | `stacks/profinet/`, `tests/` | T12-19 ×2 | 2026-11-01 감사 확인 필요 2 (같은 원인): community 불일치·SNMP 아닌 데이터는 무응답, 요청 version 에코, GetNext 는 다음 OID — 같은 PR 에서 함께 ([audits/20261101-pn-dcp-lldp-snmp.md](audits/20261101-pn-dcp-lldp-snmp.md)) |
| 40 | T12-20 | PN DCP IP 적용·이름/I&M 저장 | `stacks/profinet/`, `tests/` | 없음 | 오라클 없음: OS IP 적용은 실제 NIC·root 필요, 비휘발 저장은 설정 인터페이스 미정 |
| 41 | T12-21 | PN 어댑터 slot/subslot/index, 예제 입력 길이 | `adapters/profinet/`, `config/` | T12-21 | |
| 42 | T12-22 | PN IOCRReference, DCP 지연 슬롯, DeviceRole 0x01 | `stacks/profinet/`, `tests/` | T12-22 | T12-2 이후 |
| 43 | T11-8 | EIP Class 1 소비 규칙·FO 파라미터 검증 | `stacks/ethernetip/`, `tests/` | T11-8 ×4 (테스트 6개) | |
| 44 | T11-9 | EIP Encapsulation 편차 | `stacks/ethernetip/`, `tests/` | T11-9 | #179 답 (OpENer 기준): RegisterSession 의 프로토콜 버전·options 오류는 인수인계의 0x0003 대신 **0x0069** (OpENer `encap.c`), 그 밖의 명령에서 options ≠ 0 은 버림. UnRegisterSession 은 응답 없이 세션 닫기 |
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
| 59 | A20261002-1 | PN 다른 컨트롤러 Connect 거부 PNIOStatus `DB 81 40 04` (현재 `81 00 00 00` = ErrorCode 0) | `stacks/profinet/`, `tests/` | A20261002-1 | 출처 #74 제안, 보고서 [audits/20261002-pn-rpc-reject.md](audits/20261002-pn-rpc-reject.md). T12-1 이후 |
| 60 | A20261003-1 | scale 이 있는 uint32/int32 읽기가 float32 공학값 비트를 정수로 해석 (6553.6 → 1171050701) | `core/`, `tests/` | A20261003-1 ×2 | 출처 #80 제안, 보고서 [audits/20261003-core-scaled-decode.md](audits/20261003-core-scaled-decode.md) |
| 61 | A20261003-2 | PN DCP Get 이 요청한 블록 대신 Identify 블록 7개 전체를 Success 로 돌려준다 (지원하지 않는 옵션도 NegRes `05 04` 없음) | `stacks/profinet/`, `tests/` | A20261003-2 ×2 | 출처 #81 제안, 보고서 [audits/20261003-pn-dcp-get.md](audits/20261003-pn-dcp-get.md) |
| 62 | A20261004-1 | PN I&M0 OrderID 20번째 바이트가 NUL (19자 리터럴, VisibleString 공백 패딩 아님) | `stacks/profinet/`, `tests/` | A20261004-1 | 출처 #86 제안, 보고서 [audits/20261004-pn-im0.md](audits/20261004-pn-im0.md) |
| 63 | A20261004-2 | Modbus 클라이언트가 요청 수량과 Byte Count 가 다른 FC01~04 응답을 rc 0 으로 받음 (없는 값은 이전 미러·초기화 안 된 스택 메모리) | `stacks/modbus/`, `tests/` | A20261004-2 ×3 | 출처 12단계 감사, 보고서 [audits/20261004-modbus.md](audits/20261004-modbus.md) |
| 64 | A20261004-3 | Modbus 클라이언트가 요청과 Unit ID 가 다른 응답을 받음 (pymodbus 는 버림) | `stacks/modbus/`, `tests/` | A20261004-3 | 출처 12단계 감사, 보고서 [audits/20261004-modbus.md](audits/20261004-modbus.md). 읽기·쓰기 세 응답 경로 모두 |
| 65 | A20261004-4 | Modbus 클라이언트 모드에서 실패한 쓰기(PLC 예외, input 거부)의 값이 로컬 미러에 남아 fb_read 가 PLC 가 받지 않은 값을 돌려줌 | `adapters/modbus/`, `tests/` | A20261004-4 ×2 | 출처 12단계 감사, 보고서 [audits/20261004-modbus.md](audits/20261004-modbus.md) |
| 66 | A20261007-1 | PN Connect 의 IOCRTagHeader·AlarmCRTagHeader 값을 검사하지 않음 (사양: `DB 81 02 11`, `DB 81 04 0B/0C` (2026-10-09 정정, 처음 `11/12`) 로 거부) | `stacks/profinet/`, `tests/` | A20261007-1 ×3 | 출처 #96 검증, 보고서 [audits/20261007-pn-tag-header.md](audits/20261007-pn-tag-header.md). 큐 59 또는 16 (`reply_pnio_err` 원인 코드) 이후 |
| 67 | A20261007-2 | PN 장치가 실제 인터페이스에서도 인터페이스 MAC 대신 고정 `02:FB:00:00:00:01` 을 쓴다 (실 NIC 에서 O→T 유실 → AR 끊김, 장치 간 MAC 충돌) | `stacks/profinet/`, `tests/` | A20261007-2 (랩) | 출처 랩 감사, 보고서 [audits/20261007-lab.md](audits/20261007-lab.md). 랩 테스트는 CI 에서 건너뛰므로 검증 담당이 랩으로 확인한다 |
| 68 | A20261008-4 | PN 입문서(`docs/protocols/profinet.md`)를 T12-4~T12-8 이후 동작으로 갱신: RTC1·알람 항상 802.1Q 태그(0.6절 "태그 없이" 서술·[사양 확인 필요] 정리), 태그 시 최소 C_SDU 36, 예제 프레임 길이, DataStatus `0x35` (`:331`, `:1396`) | `docs/protocols/` | 없음 | 출처 #96 "발견한 다른 문제", #101. 문서만. 근거는 [audits/20261007-pn-tag-header.md](audits/20261007-pn-tag-header.md), PR #91·#96 검증 코멘트. **추가 (2026-10-11, #106 제안 2):** T5 (PN) 이후 GSDML `MinDeviceInterval=256`(8 ms), `SendClock 32`·RR `8…512`, Interface/Port 서브모듈 서술 (`:606`, `:626`, D31 `:2233`), 주기 미달 거부 `DB 81 02 0B`. 추가 (2026-10-24, #143 답): 5.f 알람 RTA 예시 — 첫 DATA 의 SendSeqNum/AckSeqNum 은 `FFFF`/`FFFE` (p-net `pf_alarm.c:1012-1017`, `:1518-1519`; 예시의 `00 00`/`ff ff` 는 틀림), VarPartLen `00 00` 도 틀림 (BlockHeader 포함 블록 길이), AddFlags 는 WindowSize 하위 니블·TACK bit 4 (Wireshark), `[사양 확인 필요]` 정리. T12-10 (#153) 병합 뒤 ACK-RTA·ERR-RTA·재전송 서술도 같이. 추가 (2026-10-25, #155 제안 1): T12-11 이후 LLDPDU — `:967-997` 5.c 와 차이 표, D8 `:2213`, `:2449` 체크리스트 (PNO OUI `00-0E-CF`, Port ID `port-001`, Port Status·Chassis MAC·MAC/PHY·Management Address). 추가 (2026-10-26, #158 제안): T12-12 이후 Connect.res — `:1192`, `:1200`, `:1202` 덤프와 D11·D12 (`:2216-2217`): CMResponderUDPRTPort `0x8892` (RT_CLASS_1), AlarmCRBlockRes 본문 6바이트. 2026-11-06: 9.5 제한값 표 "지연 Identify 대기열" 을 T12-22 답(#184: 슬롯 4, 가득 차면 새 요청 무시, 키 = 요청자 MAC+Xid)으로, T12-20 비휘발 저장(`nvm_dir`, `pn-ip.bin`/`pn-im.bin`) 설명 추가 |
| 69 | A20261011-1 | EIP EDS Param1 링크 경로 크기 6 + 경로 `0` (EPATH 아님). 링크가 없으면 `,,` | `stacks/ethernetip/eds/` | A20261011-1 | 출처 #111 제안 1, 보고서 [audits/20261011-eip-eds-docs.md](audits/20261011-eip-eds-docs.md) |
| 70 | A20261011-2 | 문서를 병합된 수정에 맞춘다: EIP 입문서 EDS·`minor_rev` (T11-2), `docs/ctt.md` `rpc_connect` 선택 SCF/RR·`pniostatus` (T5 PN), SLMP 비트 단위 니블 형식 (T10-1) | `docs/` | 없음 | 출처 #111 제안 2, #106 제안 3, SLMP 감사. 문서만. 보고서 [audits/20261011-eip-eds-docs.md](audits/20261011-eip-eds-docs.md). 추가 (2026-10-12): `docs/protocols/ethernetip.md:1351-1352` "triad 가 없어도 성공" 서술 (#118 이후 `0x01/0x0107`). 추가 (2026-10-13, #121 제안 1·2): T11-4 이후 UDP 44818·sockaddr·State·ListInterfaces 서술 (`docs/protocols/ethernetip.md`, `tools/ctt/proto/ethernetip/README.md:23`, `docs/ctt_eip_bundle.md`, `docs/ctt_odva_matrix.md` — 목록은 [audits/20261013-eip-udp-broadcast.md](audits/20261013-eip-udp-broadcast.md)). 추가 (2026-10-14): `docs/protocols/ethernetip.md:2232` "첫 DWORD `0x04010002` … OpENer 샘플 EDS 와 같은 값" 은 틀림 (OpENer EO 는 `0x84010002`, bit31 차이), `:2235` T→O "multicast/P2P" 서술은 T11-5 이후 P2P 전용. 추가 (2026-10-15, #124 제안 2·4): `class1_lifetime_dual.yaml` 을 "두 Class 1 연결, A 닫은 뒤 B 유지" 로 적는 곳 (`docs/protocols/ethernetip.md` 6.3 근처, `docs/ctt_eip_bundle.md` EIP-A-CM-003, `docs/ctt_odva_matrix.md`), NCP Type 무시 서술 (`ethernetip.md:1162`, `:1624`), O→T Run/Idle 거절 서술 (`:1163`, `:2237`). 추가 (2026-10-17, #131 제안 3·4): T5 (EIP) 이후 RPI 를 에코하고 범위를 안 본다는 서술 (`docs/protocols/ethernetip.md:1298`, `:1544`, `:1605`, `:2554` — 지금은 최소 미만 `0x01/0x0112` + 허용 RPI, 수락 시 최소의 배수로 올린 API), `docs/ctt_eip_bundle.md` 카탈로그에 `EIP-A-CM-005` (`rpi_below_minimum.yaml`) 행 없음. 추가 (2026-10-18, #135 제안 1~3): T9-5 이후 Modbus 클라이언트 connect 서술 (`docs/protocols/modbus.md:1004` 블로킹 `connect()`, 부록 D 9번 `:2033`), T9-1 이후 부록 D 10번 `:2034` (한 번 타임아웃 뒤 영구 TID 불일치 — 지금은 소켓을 닫고 재연결), `docs/modbus_stack.md:229` `client_timeout_ms` 는 응답 대기와 connect 대기 둘 다. 추가 (2026-10-21, #141 제안 1·2): T10-4 이후 SLMP 생략 기본 배치 서술 — `docs/protocols/slmp.md:1549` (`ABCD` 기본), `:1833-1840` (11.1 의 6·7, `string_swap: false` 기본), `:2006` B-11, `:2079-2080` D-13·D-14 는 지금 CDAB·`$MOV` 기본과 반대. `docs/slmp_stack.md:260-263` 에 생략 기본값과 `layout` (`melsec`\|`legacy`) 키가 없다. 추가 (2026-10-22, #144 제안): T9-4 이후 FC01–04 수량 위반은 예외 03 — `docs/protocols/modbus.md:588-590`, `:625-626`, `:801`, `:819-820`, `:848-850`, `:1672`, `:1703-1704`, `:1969-1971`, `:2025` (부록 D #1), `docs/ctt_mb_bundle.md:80`, `docs/ctt_modbus_matrix.md:35` 와 그 제목을 복사한 `docs/ctt_board_data.json:2188`. T9-6 (#147) 병합 뒤: 기본 Unit 0xFF 수락 — `docs/protocols/modbus.md:958`, `:967`, `:1985` (N1), `:2026` (부록 D #2) |
| 71 | A20261011-3 | SLMP 클라이언트 스택이 로컬 맵(워드 4096·비트 8192·비트 디바이스 워드 단위 512) 밖 주소의 쓰기를 PLC 로 보내지 않음 (`-ERANGE`), 읽기는 캐시 실패를 조용히 버림 | `stacks/slmp/`, `tests/` | A20261011-3 ×3 | 출처 12단계 감사, 보고서 [audits/20261011-slmp.md](audits/20261011-slmp.md). 큐 72 보다 먼저. #208 (T10-6) 은 서버 역할만 비트 번호 선두로 바꿨다 — 이 PR 에서 클라이언트 캐시도 같은 해석으로 맞춘다 ([audits/20261114-slmp-word-range-overflow.md](audits/20261114-slmp-word-range-overflow.md)) |
| 72 | A20261011-4 | SLMP 클라이언트 어댑터가 맵 밖 주소(D5000·W1000·M512 워드 등) 포인트를 읽지(FB_ERR_IO, poll 은 성공)·쓰지 못함 | `adapters/slmp/`, `tests/` | A20261011-4 ×4 | 같은 보고서. 큐 71 이후 (쓰기 테스트는 71 병합 뒤에만 통과) |
| 73 | A20261011-5 | SLMP 서버 시뮬이 비트 단위 읽기 3841~7168 점에 `C051`, 쓰기 4055~7168 점에 응답 없이 연결을 끊음 (사양 7168) | `stacks/slmp/`, `tests/` | A20261011-5 ×4 | 같은 보고서 |
| 74 | A20261008-1 | 코어 이벤트 구동 지원: 어댑터 선택 함수 `wait_fds` + `poll()` 대기, reload 시 대기 스레드 quiesce, `thread_stop` atomic | `include/protocol_adapter.h`, `core/`, `tests/` | 없음 | 출처 담당자 지시(2026-10-08), 설계 [design.md](../design.md) 1장 5항, 보고서 [audits/20261008-drive-model.md](audits/20261008-drive-model.md). 참고 diff 가 보고서에 있음. `include/protocol_adapter.h` 변경은 이 항목에서 허용. **우선 (담당자 결정 2026-10-12): 큐 이슈를 만들 때 다른 순번보다 먼저 만든다. 75·76 도 74 이슈가 닫히면 바로 다음에 만든다** |
| 75 | A20261008-2 | Modbus 서버 이벤트 구동 (cycle_ms=1000 에서 응답 최대 863ms), 클라이언트 `poll_interval_ms` | `stacks/modbus/`, `adapters/modbus/`, `tests/`, `docs/modbus_stack.md` | A20261008-2 | A20261008-1 이후. 보고서 [audits/20261008-drive-model.md](audits/20261008-drive-model.md) |
| 76 | A20261008-3 | SLMP 서버(시뮬) 이벤트 구동 (cycle_ms=1000 에서 응답 최대 863ms), 클라이언트 `poll_interval_ms` | `stacks/slmp/`, `adapters/slmp/`, `tests/`, `docs/slmp_stack.md` | A20261008-3 | A20261008-1 이후. 보고서 [audits/20261008-drive-model.md](audits/20261008-drive-model.md) |
| 77 | A20261012-1 | SLMP 클라이언트 응답 대기가 감시 타이머와 같아 모듈의 만료 이상 응답(엔드 코드)을 받지 못하고 연결을 버림. connect 대기도 감시 타이머 값으로 부풀려짐 | `stacks/slmp/`, `tests/`, `docs/slmp_stack.md` | A20261012-1 | 출처 담당자 요청(2026-10-12) 조사, 보고서 [audits/20261012-pending-items.md](audits/20261012-pending-items.md). `tests/test_slmp_stack.c` 의 "같으면 그대로" 기대도 함께 고친다 |
| 78 | A20261012-2 | EIP Forward Close 가 다른 IP 에서 와도 triad 만 맞으면 남의 Class 1 연결을 닫음 (OpENer·CIPster 는 General 0x0F) | `stacks/ethernetip/`, `tests/` | A20261012-2 | 같은 보고서. 큐 22 (T11-6) 이후 — Forward Open 시점 originator IP 기록을 공유 |
| 79 | A20261013-1 | EIP `bind_ip` 를 유니캐스트 주소로 주면 UDP encapsulation 소켓이 브로드캐스트 ListIdentity(RSLinx 브라우즈)를 받지 못함 | `stacks/ethernetip/`, `tests/` | A20261013-1 (랩) | 출처 #121 검증 랩, 보고서 [audits/20261013-eip-udp-broadcast.md](audits/20261013-eip-udp-broadcast.md). 랩 테스트는 CI 에서 건너뛰므로 검증 담당이 랩으로 확인한다 |
| 80 | T11-5 후속 | EIP 멀티캐스트 T→O 구현 (생산자 공유, RPI·우선순위 일치 검사, 그룹 주소·TTL), Listen Only (`0x0119`), Input Only (heartbeat connection point + EDS Connection 항목) | `stacks/ethernetip/`, `tests/` | 없음 (구현 PR 이 오라클 추가를 요청하면 검증 담당이 선행 추가) | 큐 21 (T11-5, #124) 이후. #113 답(2026-10-14)으로 T11-5 에서 뺀 부분. 그때까지는 멀티캐스트 `0x0124`/`0x0123` 거절, EDS T→O P2P 전용 (`0x44440405`). 근거: OpENer `appcontype.c`·`cipioconnection.c`, 샘플 EDS Connection2/3 |
| 81 | A20261015-1 | EIP 표준 Forward Open 성공 응답 30바이트를 `need = 26` 으로 검사해 `resp_cap` 26~29 에서 힙 오버플로 (내부 API, 지금 호출부는 도달 안 함) | `stacks/ethernetip/`, `tests/` | 없음 (sanitizers job 의 단위 테스트) | 출처 #124 제안 1, 보고서 [audits/20261015-eip-cm-respcap.md](audits/20261015-eip-cm-respcap.md) |
| 82 | A20261017-1 | EIP 어댑터의 장치 최소 RPI 가 `cycle_ms` 를 따르지 않음 (`protocol_params.rpi_us` 기본 8000 만 봄 — `cycle_ms` 16 에서 8000µs FO 수락, API 8000 인데 실제 생산 16 ms) | `adapters/ethernetip/`, `tests/` | A20261017-1 | 출처 #131 제안 1, 보고서 [audits/20261017-eip-rpi-t2o-sockaddr.md](audits/20261017-eip-rpi-t2o-sockaddr.md). 최소 RPI = max(`cycle_ms×1000`, `rpi_us`) |
| 83 | A20261017-2 | EIP P2P T→O `0x8001` Sockaddr 의 sin_addr 을 목적지로 씀 (sin_addr 0 이면 요청 포트 무시, 다른 호스트면 그쪽으로 생산). P2P 는 Originator 주소 + 항목 포트 | `stacks/ethernetip/`, `tests/` | A20261017-2 ×2 | 출처 #126 검증 (OpENer `OpenProducingPointToPointConnection` 대조), 같은 보고서. 보안 |
| 84 | A20261018-1 | EIP Class 1 O→T 데이터 길이가 연결 크기와 달라도 앞부분을 출력에 씀 (짧으면 앞 바이트만 — 다른 주기 값이 섞임, 길면 잘라서). 길이가 다르면 버린다 | `stacks/ethernetip/`, `tests/` | A20261018-1 ×2 | 출처 2026-10-18 일요일 감사 (opus), 보고서 [audits/20261018-eip-stack.md](audits/20261018-eip-stack.md). 근거 OpENer `NotifyAssemblyConnectedDataReceived`, EIPScanner `IOConnection.cpp`. T11-8 (큐 43) 과 같은 함수 |
| 85 | A20261018-2 | EIP Class 1 연결 크기에 16비트 순번이 빠진 값(= Assembly 크기)도 수락 — 그 연결의 T→O 는 협상보다 2바이트 크고 O→T 는 2바이트를 잃음. `0x01/0x0127`·`0x0128` (또는 `0x0109`) 로 거절 | `stacks/ethernetip/`, `tests/`, `tools/ctt/proto/ethernetip/`, `examples/sw_master.py` | A20261018-2 ×2 | 같은 보고서. CTT 기본 크기·시나리오·단위 테스트 FO 본문·sw_master 하네스가 이 형식을 고정하므로 같은 PR 에서 `+2` 로 맞춘다. 근거 OpENer `cipioconnection.c`, EIPScanner `ConnectionManager.cpp` |
| 86 | A20261018-3 | EIP Forward Open 연결 경로를 위치로 해석하지 않음 (소비·생산 뒤바뀜, 없는 config 인스턴스, Assembly 아닌 클래스도 Exclusive Owner 로 수락) | `stacks/ethernetip/`, `tests/` | A20261018-3 ×3 | 같은 보고서. 근거 OpENer `cipconnectionmanager.c`·`appcontype.c` `GetExclusiveOwnerConnection`. 큐 80 (Input Only/Listen Only) 의 바탕 |
| 87 | A20261018-4 | EIP Assembly attr 3 Set 이 길이가 틀려도 부분 쓰기·잘라 쓰기 후 성공. `0x13`/`0x15`, 데이터 불변 | `stacks/ethernetip/`, `tests/` | A20261018-4 ×2 | 같은 보고서. 근거 OpENer `DecodeCipAssemblyAttribute3` |
| 88 | A20261018-5 | EIP 존재하는 객체(Assembly·Identity)에 정의되지 않은 서비스를 `0x05` 로 답함. `0x08` Service not supported (없는 클래스·인스턴스만 `0x05`) | `stacks/ethernetip/`, `tests/` | A20261018-5 ×2 | 같은 보고서. 근거 OpENer `cipcommon.c` `NotifyClass`. T11-10 (큐 45) 과 같은 분기 — 그 PR 에서 함께 해도 된다 (표시 같이 삭제 허용) |
| 89 | A20261018-6 | EIP Null Forward Open(NCP 형식 둘 다 Null)을 실제 Exclusive Owner 연결로 수락해 정상 FO 를 `0x0106` 으로 막음. `0x01/0x0132`, FO 를 보내는 CTT·단위 테스트·하네스는 Point-to-point 형식으로 | `stacks/ethernetip/`, `tests/`, `tools/ctt/proto/ethernetip/`, `examples/sw_master.py` | A20261018-6 | 담당자 결정 (2026-10-19, CTT 같이 고침). 보고서 [audits/20261018-eip-stack.md](audits/20261018-eip-stack.md). 근거 OpENer `HandleNull*ForwardOpenRequest`. 큐 85 와 같은 CTT 인코더·하네스를 바꾼다 |
| 90 | A20261019-1 | SLMP 클라이언트가 0xFFFFFF 를 넘는 선두 디바이스 번호를 24비트로 잘라 보냄 (D0x1000005 요청이 D5 를 읽고 성공), 어댑터 숫자 `start` 상한 없음. `-ERANGE` / init 실패 | `stacks/slmp/`, `adapters/slmp/`, `tests/` | A20261019-1 | 출처 #138 제안 1, 보고서 [audits/20261019-slmp-head-range.md](audits/20261019-slmp-head-range.md). 근거 pymcprotocol `_make_devicedata` (3바이트, OverflowError). 큐 27 (T10-3) 이후 |
| 91 | A20261020-1 | SLMP 예제 config 의 `barcode_value` (D100~D115) 가 `temperature` (D110) 와 겹쳐 바코드 쓰기가 온도를 덮음 (sw-master-soak 간헐 0 °C). 온도를 문자열 뒤로 | `config/`, `examples/`, `docs/` | A20261020-1 ×2 | 출처 #140 [Grok 제안], 보고서 [audits/20261020-slmp-example-overlap.md](audits/20261020-slmp-example-overlap.md). 큐 28 (T10-4) 이후 |
| 92 | T9-6 후속 | Modbus `unit_id_reject_ff` (Unit 0xFF 특수 처리 끄기) 를 config 로 켤 수 없음: 어댑터 `protocol_params` 와 CTT device YAML 이 `unit_id`/`unit_id_any` 만 읽는다. 둘 다 `unit_id_reject_ff` 를 읽고 `docs/modbus_stack.md` 표(`:210`, `:225`)에 적는다 | `adapters/modbus/`, `tools/ctt/proto/modbus/`, `docs/modbus_stack.md`, `tests/` | 없음 (PR 단위 테스트: config 로 켜면 0xFF 무응답) | 출처 #147 제안 2·3. 인수인계 T9-6 수정 범위 "0xFF 는 항상 수락 (설정으로 끌 수 있게)" 의 설정 부분. 큐 30 (T9-6, #147) 이후. `adapters/modbus/modbus_adapter.c:508-513`, `tools/ctt/proto/modbus/mb_plugin.c:685-689` |
| 93 | A20261025-6 | PN AlarmCRBlockReq 의 RTATimeoutFactor (1..100)·RTARetries (3..15)·MaxAlarmDataLength (200..1432) 범위를 검사하지 않아 TF 0 (알람 ACK 타이머 꺼짐) 등도 Connect 수락. `DB 81 04 07`/`08`/`0A` 로 거부 | `stacks/profinet/`, `tests/` | A20261025-6 ×4 | 출처 #153 사양 검토, 보고서 [audits/20261025-pn-alarm-followups.md](audits/20261025-pn-alarm-followups.md). 근거 p-net `pf_cmdev.c` |
| 94 | A20261025-1 | EIP TCP 응답 `send` 에 `MSG_NOSIGNAL` 이 없고 SIGPIPE 무시도 없어, 요청을 몰아 보내고 닫은 피어 하나가 데몬을 죽인다 (인증 불필요) | `stacks/ethernetip/`, `tests/` | A20261025-1 | 2026-10-25 일요일 감사 (opus), 보고서 [audits/20261025-eip-adapter-originator.md](audits/20261025-eip-adapter-originator.md). 근거 OpENer `generic_networkhandler.c:889-892`, EIPScanner `SO_NOSIGPIPE`, 저장소 Modbus·SLMP 는 이미 `MSG_NOSIGNAL`. 보안. **우선 (담당자 결정 2026-10-26): 순번보다 먼저 발행 (#162)** |
| 95 | A20261025-2 | EIP Originator 가 2 s 타임아웃 뒤 늦게 온 이전 응답을 다음 요청의 응답으로 받음 (Sender Context·서비스 미대조) | `stacks/ethernetip/`, `tests/` | A20261025-2 | 같은 보고서. 큐 96 과 같은 함수 — 한 PR 에서 두 표시 함께 삭제 허용 |
| 96 | A20261025-3 | EIP Originator 가 대상의 TCP 종료를 감지·재연결하지 않고 health 는 connected 로 남음 | `stacks/ethernetip/`, `tests/` | A20261025-3 | 같은 보고서. 큐 95 와 같은 PR 허용, 큐 94 (SIGPIPE) 이후가 좋다 |
| 97 | A20261025-4 | EIP 어댑터가 `length` 생략 숫자 포인트를 1바이트로, `data_type` 생략 포인트를 무변환으로 다룸 (uint16 300 → `01 00`) | `adapters/ethernetip/`, `tests/` | A20261025-4 ×4 | 같은 보고서. 기본 = data_type 크기·LE (CIP UINT/DINT, T0 A안). PN 어댑터 같은 패턴은 범위 밖 |
| 98 | A20261025-5 | EIP Originator TCP connect 가 블로킹·타임아웃 없음 — 응답 없는 대상이면 `fb_open` 이 ~130 s 막힘 | `stacks/ethernetip/`, `tests/` | A20261025-5 | 같은 보고서. 근거 EIPScanner `TCPSocket.cpp` (non-blocking + 타임아웃), pycomm3 5 s. Modbus T9-5 와 같은 방식 |
| 99 | A20261028-1 | EIP TCP·TLS 응답의 짧은 `send`·`EAGAIN`·`SSL_ERROR_WANT_WRITE` 를 성공으로 보고 나머지를 버림 — 스캐너가 잠시 안 읽으면 응답이 빠지고 잘린 프레임으로 스트림 경계가 깨짐 (연결 유지) | `stacks/ethernetip/`, `tests/` | A20261028-1 | 출처 #164 "발견한 다른 문제", 보고서 [audits/20261028-eip-partial-send.md](audits/20261028-eip-partial-send.md). 근거 OpENer (accept 소켓 blocking). Modbus T9-8 (큐 52) 과 같은 기준 |
| 100 | A20261101-1 | PN DCP Set IPParameter 가 IP suite 유효성을 보지 않음 (비연속 넷마스크·멀티캐스트·루프백·브로드캐스트·다른 서브넷 게이트웨이도 BlockError 0 으로 적용). 길이도 정확히 12 만 | `stacks/profinet/`, `tests/` | A20261101-1 ×6 | 출처 12단계 일요일 감사 (opus), 보고서 [audits/20261101-pn-dcp-lldp-snmp.md](audits/20261101-pn-dcp-lldp-snmp.md). 근거 p-net `pf_cmina_is_ipsuite_valid` → 0x03. 0.0.0.0 (IP 지우기) 은 유효 |
| 101 | A20261101-2 | PN NameOfStation 이 비면 LLDP Chassis ID TLV 가 subtype 만 (길이 1) — Wireshark·scapy 가 LLDPDU 전체를 버림. 이름이 없으면 subtype 4 + MAC | `stacks/profinet/`, `tests/` | A20261101-2 | 같은 보고서. 근거 p-net `pf_lldp.c`, Wireshark `packet-lldp.c` |
| 102 | A20261101-3 | PN 빈 NameOfStation Set (이름 지우기) 을 0x03 으로 거부, AR 중 IP 0.0.0.0 (IP 지우기) 을 0x06 으로 거부. p-net: 빈 이름 유효, AR 중 IP 지우기는 수락 + AR abort | `stacks/profinet/`, `tests/` | A20261101-3 ×2 | 같은 보고서. 큐 100 과 같은 PR 이어도 된다 (그때 두 표시 모두 지움, 허용) |
| 103 | A20261101-4 | PN Identify/Get DeviceOptions 가 (1,2)·(2,2) 두 쌍만 나열 (MAC·Vendor·DeviceID·Role·DeviceOptions·Signal·ResetToFactory 빠짐) | `stacks/profinet/`, `tests/` (`tests/golden/profinet/` 갱신 포함) | A20261101-4 | 같은 보고서. 근거 p-net `pf_dcp.c` `device_options[]` |
| 104 | A20261101-5 | PN DCP Hello.req 목적지가 Identify 멀티캐스트 `01:0E:CF:00:00:00` — Hello 는 `…:00:01` | `stacks/profinet/`, `tests/` (`tests/golden/profinet/` 갱신 포함) | A20261101-5 | 같은 보고서. 근거 p-net `dcp_mc_addr_hello`. 입문서 D3 [사양 확인 필요] 정리는 큐 68 비고 |
| 105 | A20261103-1 | PN SNMPv2c GetBulkRequest(0xA5) 무응답 — v2c bulk walk 시간 초과 | `stacks/profinet/`, `tests/` | A20261103-1 | 담당자 결정 (2026-11-03) CC-B 범위. 보고서 [audits/20261103-pn-snmp-lldp-ccb.md](audits/20261103-pn-snmp-lldp-ccb.md). 근거 net-snmp `SNMP_MSG_GETBULK` |
| 106 | A20261103-2 | PN MIB-II system 그룹이 sysName.0 뿐 (sysDescr·sysObjectID·sysUpTime·sysContact·sysLocation·sysServices 없음, sysContact·sysLocation Set 불가) | `stacks/profinet/`, `tests/` | A20261103-2 ×2 | 같은 보고서. 근거 p-net `pf_snmp.h`, SNMPv2-MIB. sysObjectID 값·sysName 분리는 `[Claude 확인 요청]` 으로. 영구 저장은 T12-20 방식 |
| 107 | A20261103-3 | PN LLDP-MIB 로컬 데이터 없음 (lldpLocChassisId·Subtype, lldpLocPortTable) — 값은 송신 LLDPDU 와 같아야 함 | `stacks/profinet/`, `tests/` | A20261103-3 | 같은 보고서. 근거 p-net `pf_snmp.h`, LLDP-MIB |
| 108 | A20261103-4 | PN LLDP 수신 없음 → lldpRemTable 없음 (이웃 Chassis·Port, TTL 만료) | `stacks/profinet/`, `tests/` | A20261103-4 | 같은 보고서. 큐 107 이후. 근거 p-net `pf_lldp.c` 수신, LLDP-MIB. LLDP-EXT-PNO-MIB 는 후속 판단 |
| 109 | T12-20 후속 | PN 어댑터가 `protocol_params.nvm_dir`·`apply_os_ip` 를 읽어 `pn_cfg_t` 에 넣지 않아, 데몬은 DCP 로 받은 이름·IP·I&M 을 재시작 뒤 잃고 NIC 주소도 바꾸지 않음 (스택은 #180 으로 지원) | `adapters/profinet/`, `config/`, `tests/` | 없음 | 오라클 없음 (OS IP 는 root·실 NIC, 저장은 데몬 재시작). 단위 테스트: config 의 두 키가 `pn_cfg_t` 로 들어가는지, `nvm_dir` 이 없거나 쓸 수 없으면 `LOG_WARN` 후 RAM 만. 스키마·예제 config 에 키 설명. 근거 #171 답 |
| 110 | A20261108-1 | PN Read Implicit (opnum 5) 무응답 (-ENOSYS) — AR 없이 I&M0 를 읽는 엔지니어링 툴·컨트롤러 식별이 시간 초과 | `stacks/profinet/`, `tests/` | A20261108-1 | 2026-11-08 감사. 보고서 [audits/20261108-pn-rpc-records.md](audits/20261108-pn-rpc-records.md). 근거 p-net `pf_cmrpc.c` READ_IMPLICIT, Wireshark "Read Implicit". 입문서 `docs/protocols/profinet.md` ReadImplicit 행도 같이 고쳐도 됨 |
| 111 | A20261108-2 | PN I&M0 Write 를 성공으로 응답 (`DF 80 B6 00` 이어야), I&M1–4 Write 길이 미검사 (정확히 54/16/54/54 아니면 `DF 80 B1 00`) | `stacks/profinet/`, `tests/` | A20261108-2 ×2 | 같은 보고서. 근거 p-net `pf_fspm.c`, Wireshark. 같이 바뀌는 고정값: CTT `tests/scenarios/profinet/rpc_write_prmend_appready.yaml`, `rpc_ar_lifetime_cm.yaml` (I&M1 헤더 없는 6바이트 → 60바이트 블록), 단위 `tests/test_pn_t12_18.c:287-290`, `tests/test_pn_rpc.c:296-312` |
| 112 | A20261108-3 | PN IODControlReq(0x0110) ControlCommand 미검사 — PrmEnd 가 아니어도 Done (`DD 81 14 08` 이어야) | `stacks/profinet/`, `tests/` | A20261108-3 | 같은 보고서. 근거 p-net `pf_cmrpc_rm_dcontrol_interpret_req`, Wireshark ErrorCode1 0x14 / 0x08 |
| 113 | A20261108-4 | PN AR 없는 Release 를 성공(+블록 아닌 4바이트)으로, 다른 ARUUID 의 Release·Control·Write 를 무응답으로 처리 — "AR UUID unknown" `DC/DD/DF 81 40 05` 이어야 | `stacks/profinet/`, `tests/` | A20261108-4 ×2 | 같은 보고서. 근거 p-net `pf_cmrpc.c` CMRPC_AR_UUID_UNKNOWN, Wireshark. 송신 IP 불일치·AR 없는 Control/Write 무응답은 보안 결정 G4·CTT PN-B-NEG-008 그대로 (보고서 확인 필요 4). 단위 `tests/test_pn_rpc.c:272-281` 기대 변경. 이 PR 에서 `A20261110-3` (큐 120) 테스트도 통과하면 그 표시도 지워도 된다 (허용) |
| 114 | A20261109-1 | EIP TCP/IP·Ethernet Link·Port 의 읽기 전용 속성 Set 에 0x05 (Path destination unknown) — 있는 속성은 0x0E (Attribute not settable) | `stacks/ethernetip/`, `tests/` | A20261109-1 | 출처 #192 "발견한 다른 문제" 2. 보고서 [audits/20261109-eip-t11-9-10-followups.md](audits/20261109-eip-t11-9-10-followups.md). 근거 OpENer `cipcommon.c` `SetAttributeSingle`. settable 속성 Set 은 그대로. #192 (큐 45) 이후 |
| 115 | A20261109-2 | EIP 거부된 RegisterSession(핸들 0) 이 그 연결의 `c->session` 을 0 으로 덮어 어댑터 연결 상태가 내려감 (세션은 살아 있음) | `stacks/ethernetip/`, `tests/` | 없음 | 출처 #190 "발견한 다른 문제" 4. 같은 보고서. 근거 OpENer `encap.c`. 단위 테스트 (TCP·TLS) |
| 116 | A20261109-3 | EIP Identity Protection Mode attr 19 (WORD) 미노출, TCP/IP·Ethernet Link·QoS·Port 클래스 속성 (instance 0) 없음, TCP/IP attr 5 mask·gateway·DNS 가 호스트 값이 아님 (낮음) | `stacks/ethernetip/`, `tests/` | 없음 | #183 답 후속. 같은 보고서. 근거 Wireshark `packet-cip.c` (attr 19), OpENer class revision. `protection_mode` 비트 대응은 `[Claude 확인 요청]` 으로 |
| 117 | A20261109-4 | EIP 문서가 T11-8~T11-10 이전 동작을 적음 (`docs/protocols/ethernetip.md`, `docs/ethernetip_stack.md`, `tools/ctt/proto/ethernetip/README.md`) | `docs/`, `tools/ctt/proto/ethernetip/README.md`, `README.md`, `config/example.codesys.ethernetip.json` (`_comment` 만) | 없음 | 출처 #190·#192 "발견한 다른 문제". 같은 보고서에 위치 목록. 문서만. #192 이후. #195 추가분: `config/example.codesys.ethernetip.json:9` `_comment` 의 "CIP Security HMAC", `README.md` EIP 범위에 자체 보안 프로파일 문장 ([audits/20261110-eip-security-object-0x5e.md](audits/20261110-eip-security-object-0x5e.md)) |
| 118 | A20261110-1 | EIP 자체 보안 프로파일이 표준 클래스 0x5E (EtherNet/IP Security Object) 로 응답 — attr 1 security_class UINT·attr 3 TLS 포트로 CIP Security 객체가 있는 것처럼 보임 | `stacks/ethernetip/`, `tests/` | A20261110-1 | 출처 #186 답·#195. 보고서 [audits/20261110-eip-security-object-0x5e.md](audits/20261110-eip-security-object-0x5e.md). 근거 Wireshark `packet-enip.c` 0x5E 속성 표. 벤더 클래스로 옮길지 지울지는 `[Claude 확인 요청]` 으로. CTT `sec_integrity_fo.yaml` 0x5E 단계 함께. #195 (큐 46) 이후 |
| 119 | A20261110-2 | PN AR 없는 Read(opnum 2) 를 받아 레코드를 돌려줌 — Read Implicit 뒤 거부 (NIL ARUUID `DE 81 08 05`, AR 없음 `DE 81 40 02`) | `stacks/profinet/`, `tests/`, `tests/scenarios/profinet/`, `tools/ctt/proto/profinet/` (`record_read` 의 opnum 만) | A20261110-2 | 담당자 결정 (2026-11-10). 보고서 [audits/20261110-owner-decisions.md](audits/20261110-owner-decisions.md). 근거 p-net `pf_cmrpc_rm_read_ind`. 보안 결정 G4 의 "Read without an AR remains allowed" 를 대신한다. 큐 110 이후. CTT `record_read_*`·`record_unknown_index`·`rpc_cm_without_ar` 의 AR 없는 읽기를 opnum 5 로 |
| 120 | A20261110-3 | PN 거부를 무응답으로 처리 — AR 없는 Control·Write, AR 중 다른 ARUUID 의 Read, 송신 IP 불일치 요청에 에러 PNIOStatus 로 답해야 (AR 유지) | `stacks/profinet/`, `tests/`, `tests/scenarios/profinet/rpc_cm_without_ar.yaml` | A20261110-3 ×2 | 담당자 결정 (2026-11-10). 같은 보고서. 근거 p-net (`DD/DF 81 40 05`, Read `DE 81 40 02`). 송신 IP 불일치 코드는 `[Claude 확인 요청]` 으로 (단위 테스트). 큐 113 이후 |
| 121 | A20261112-1 | EIP HMAC 무결성 재료를 572 바이트에서 잘라 CIP 본문 568 바이트 뒤가 보호되지 않음 — 꼬리를 바꾼 Set 이 같은 MAC 으로 수락, 본문 전체 MAC 은 거부 | `stacks/ethernetip/`, `tests/` | 없음 | 출처 #201 "발견한 다른 문제" 3. 보고서 [audits/20261112-eip-t11-13-followups.md](audits/20261112-eip-t11-13-followups.md). v0.2.0 게이트 (b). 재료를 고정 버퍼 없이 HMAC 에 순서대로 넣는다 (검사·생성·originator). 단위 테스트 |
| 122 | A20261112-2 | EIP LLDP Chassis ID·Port ID TLV 에 subtype 옥텟 없음 (scapy 가 Chassis subtype 을 MAC 첫 바이트로 읽음) | `stacks/ethernetip/`, `tests/`, `tests/scenarios/ethernetip/lldp_mgmt.yaml` | 없음 | 출처 #201 "발견한 다른 문제" 1. 같은 보고서. 근거 IEEE 802.1AB, scapy·Wireshark LLDP. #201 (큐 48) 이후 |
| 123 | A20261112-3 | EIP TLS 세션의 encapsulation 수신 한도가 8192 (평문 TCP 는 #201 뒤 65511) — 큰 PDU 에서 TLS 연결을 끊음 (낮음) | `stacks/ethernetip/`, `tests/` | 없음 | 출처 #201 "발견한 다른 문제" 2. 같은 보고서. #201 이후 |
| 124 | A20261113-1 | EIP 단위 테스트 `reserve_port` 가 bind 뒤 바로 닫아 같은 포트를 다시 내줄 수 있음 — `test_eip_t11_11` `distinct ports` 가끔 실패 (6개 파일에 같은 helper) | `tests/` | 없음 | 출처 #204 검증 (sanitizers job 1회 실패, 단독 재실행 PASS). 보고서 [audits/20261113-eip-test-port-flake-slmp-docs.md](audits/20261113-eip-test-port-flake-slmp-docs.md). 완료: `ctest -R test_eip -j8 --repeat until-fail:20` |
| 125 | A20261113-2 | SLMP 문서·CTT 매트릭스가 T10-5 이전 동작 (`C050h`, 이상 응답 길이 2, 짧은 쓰기 무응답) 을 적음 | `docs/` | 없음 | 출처 #204 "발견한 다른 문제". 같은 보고서에 위치 목록. 보드 JSON 은 `tools/ctt/gen_board_data.py` 로 |
| 126 | A20261114-1 | SLMP `slmp_stack_read_words`/`write_words` 워드 슬롯 범위 검사 `head + quantity > capacity` 가 `uint32_t` 넘침으로 통과 → 맵 밖 memcpy (API·config 경로, ASan SEGV) | `stacks/slmp/`, `tests/` | 없음 | 출처 #208 "발견한 다른 문제". 보고서 [audits/20261114-slmp-word-range-overflow.md](audits/20261114-slmp-word-range-overflow.md). 와이어 선두 3바이트라 원격 요청으로는 닿지 않음. 단위 테스트 |

## v0.2.0 릴리스 게이트

담당자 결정 (2026-11-10, [audits/20261110-owner-decisions.md](audits/20261110-owner-decisions.md) 결정 1): 아래 행이 모두 끝나면 v0.2.0 을 태그한다.
나머지 행은 v0.3 이후. 분류는 검증 담당이 하고, 새 행이 기준에 들면 검증 담당이 더한다. 빼는 것은 담당자가 정한다.
기준: (a) 인수인계 치명·높음 (b) 보안·가용성 (c) 조용히 틀리는 데이터 (d) 인증·표준 지원의 잘못된 주장.

| 큐 | 항목 | 기준 | 한 줄 |
|---|---|---|---|
| 46 | T11-11 | d | EIP 보안 명칭 (PR #195 검증 PASS, 충돌 해소 대기) |
| 60 | A20261003-1 | c | scale 있는 uint32/int32 읽기가 float 비트를 정수로 |
| 63 | A20261004-2 | b, c | Modbus 클라이언트가 Byte Count 다른 응답 수락 (초기화 안 된 메모리 노출) |
| 64 | A20261004-3 | c | Modbus 클라이언트가 Unit ID 다른 응답 수락 |
| 65 | A20261004-4 | c | Modbus 클라이언트 실패한 쓰기 값이 미러에 남음 |
| 67 | A20261007-2 | a, b | PN 고정 MAC — 실 NIC 에서 AR 끊김 |
| 78 | A20261012-2 | b | EIP 다른 IP 의 Forward Close 가 남의 연결을 닫음 |
| 80 | T11-5 후속 | a | EIP 멀티캐스트 T→O·Listen Only·Input Only (인수인계 높음) |
| 81 | A20261015-1 | b | EIP Forward Open 응답 힙 오버플로 (내부 API) |
| 84 | A20261018-1 | c | EIP O→T 길이 불일치 데이터를 출력에 씀 |
| 90 | A20261019-1 | c | SLMP 클라이언트 선두 번호 24비트 절단 (다른 주소 읽기 성공) |
| 94 | A20261025-1 | b | EIP SIGPIPE 원격 비인증 DoS |
| 95 | A20261025-2 | c | EIP Originator 늦은 응답을 다음 요청 결과로 |
| 98 | A20261025-5 | b | EIP Originator connect 블로킹 (~130 s) |
| 99 | A20261028-1 | b, c | EIP 짧은 send 로 응답 유실·스트림 경계 깨짐 |
| 118 | A20261110-1 | d | EIP 자체 보안이 표준 클래스 0x5E 로 응답 |
| 121 | A20261112-1 | b | EIP HMAC 재료 절단 — 568 바이트 뒤 변조 수락 |

(2026-11-12 기준 17행 — 2026-11-12 큐 121 추가. 46 은 #195 로 끝남. 이슈 발행 순서는 운영 규칙대로 큐 번호순이다.)

## 이슈 본문 템플릿

일일 루틴이 큐 이슈를 만들 때 이 템플릿을 채운다. `<…>` 는 위 표와 인수인계 문서에서 가져온다.
인수인계 문서의 해당 항목(표 행 또는 절)을 **요약하지 말고 그대로** "항목 내용" 에 붙인다.

````markdown
<!-- work-queue: <큐 번호> <T 항목> -->
## 작업: 인수인계 <T 항목> — <요약>

main 최신 기준으로 새 브랜치를 만들어 작업한다. 이 이슈 하나당 PR 하나.

1. `CLAUDE.md` 를 먼저 읽고 규칙을 지킨다. 작업 범위: <작업 범위>. 그 밖의 디렉토리는 건드리지 않는다.
   새 단위 테스트는 `tests/test_<proto>_t<번호>.c` (예: `tests/test_eip_t11_13.c`, `tests/test_slmp_t10_5.c`) 파일로 둔다.
   스택 라이브러리만 링크하는 이 형태는 CMake 가 자동으로 빌드·등록한다 (`fb_add_item_tests`). **`CMakeLists.txt` 는 고치지 않는다**
   (PR 마다 같은 자리에 `add_test` 를 넣어 서로 충돌하던 것을 막는다). 어댑터 링크·compile definition 이 꼭 필요한 테스트만
   `CMakeLists.txt` 에 테스트 타깃(`add_executable`/`add_test`)을 직접 추가하고 PR 설명에 이유를 적는다.
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
