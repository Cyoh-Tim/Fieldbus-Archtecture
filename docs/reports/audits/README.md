# 감사 라운드 — 새 문제 찾기

인수인계 문서(`../structure_handoff_20260930.md`)의 항목이 줄어들면, 검증 담당(Claude)의 일일 루틴이 하루에 영역 하나씩
감사해서 새 결함을 찾는다. 절차는 [`.claude/skills/verify-pr/SKILL.md`](../../../.claude/skills/verify-pr/SKILL.md) 11~14단계.

- 발견 ID: `A<YYYYMMDD>-<n>`. 보고서: 이 폴더의 `<YYYYMMDD>-<영역>.md`.
- 재현과 독립 근거(오라클 라이브러리 또는 사양 문서)가 둘 다 있는 것만 큐(`../work_queue.md`)에 올린다.
- 오라클로 판정할 수 있으면 `tests/oracle/` 에 `@known_defect("A<ID>", …)` 를 먼저 넣는다.
- 한 라운드에 큐 항목 최대 5개. 발견이 없어도 기록한다.

## 영역 순환

위에서부터 차례로 돌고, 끝나면 처음으로 돌아간다. 다음 라운드는 아래 기록의 마지막 영역 다음이다.

| 순서 | 영역 | 주로 볼 것 |
|---|---|---|
| 1 | Modbus 스택·어댑터 | 예외 코드, 경계 수량, 클라이언트 재연결, 주소·타입 변환 (pymodbus) |
| 2 | SLMP | 3E 프레임, 디바이스 코드, 비트/워드 단위, 엔드 코드 (pymcprotocol) |
| 3 | EtherNet/IP 스택 | Encapsulation, CM Forward Open/Close, Class 1, 표준 객체 (pycomm3, scapy enipTCP) |
| 4 | EtherNet/IP 어댑터·Originator | 포인트 변환, 태그 서비스, 설정 파싱 |
| 5 | PROFINET DCP·LLDP·SNMP | 블록 형식, Set 규칙, TLV (scapy pnio_dcp, lldp, snmp) |
| 6 | PROFINET RPC·레코드 | NDR, Connect/Control/Read/Write, 에러 PNIOStatus (scapy pnio_rpc, dcerpc) |
| 7 | PROFINET RT·알람 | RTC1 프레임, 주기, DataStatus, RTA (scapy pnio) |
| 8 | 코어 | fb_api, config_loader, 사이클 루프, 스케일·바이트 순서 규칙 (CLAUDE.md 경계) |
| 9 | 보안 | EIP·PN 자체 보안 경로, 입력 검증, 자원 한도 |
| 10 | fuzz 장시간 | 각 하니스 10분 + sanitizer 재현 |

## 기록

| 날짜 | 영역 | 보고서 | 큐 추가 | 비고 |
|---|---|---|---|---|
| 2026-09-30 | (시작) | — | — | 인수인계 T 항목 58개가 큐에 있음. 감사는 큐 여유가 10개 미만이 되거나 일요일에 시작 |
| 2026-10-02 | PROFINET RPC·레코드 (11단계 제안 선별) | [20261002-pn-rpc-reject.md](20261002-pn-rpc-reject.md) | 59 (A20261002-1) | PR #74 제안. 다른 컨트롤러 Connect 거부 PNIOStatus. 보안 실패·블록 파싱 경로는 "확인 필요" |
| 2026-10-03 | 코어 (11단계 제안 선별) | [20261003-core-scaled-decode.md](20261003-core-scaled-decode.md) | 60 (A20261003-1) | PR #80 제안. scale 이 있는 uint32/int32 읽기가 float32 비트를 정수로 해석 |
| 2026-10-03 | PROFINET DCP·LLDP·SNMP (11단계 제안 선별) | [20261003-pn-dcp-get.md](20261003-pn-dcp-get.md) | 61 (A20261003-2) | PR #81 제안. DCP Get 이 요청과 무관하게 Identify 블록 전체를 돌려주고 NegRes 블록이 없음 |
| 2026-10-04 | PROFINET RPC·레코드 (11단계 제안 선별) | [20261004-pn-im0.md](20261004-pn-im0.md) | 62 (A20261004-1) | PR #86 제안. I&M0 OrderID 끝 NUL. Write 길이 초과·CTT fallback 은 "확인 필요" |
| 2026-10-04 | Modbus 스택·어댑터 (12단계 일요일 감사, opus) | [20261004-modbus.md](20261004-modbus.md) | 63–65 (A20261004-2, -3, -4) | 클라이언트 응답 검증(Byte Count·Unit)과 실패 쓰기 미러. 서버 경로는 결함 없음. 쓰기 에코·BCD·다중 coil 매핑은 "확인 필요" |
| 2026-10-05 | PROFINET RPC·레코드 (PR 검증 중 오라클 반론, opus + fable) | [20261005-pn-oracle-connect.md](20261005-pn-oracle-connect.md) | — (큐 10·11 비고) | 오라클 Connect ExpectedSubmodule NO_IO DataDescription·ARServerBlock 조건 정정, T12-5 ApplicationReady 목적지 정정 |
| 2026-10-07 | PROFINET RPC·레코드 (PR #96 검증 중, opus) | [20261007-pn-tag-header.md](20261007-pn-tag-header.md) | 66 (A20261007-1) | Connect 태그 헤더 미검증. 송신 태그·CTT VLAN 은 PR #96 에서 처리 |
| 2026-10-07 | 랩 상호운용 (veth, EIPScanner·scapy 컨트롤러) | [20261007-lab.md](20261007-lab.md) | 67 (A20261007-2) | PN 장치 MAC 고정값. T11-1·T11-6·T12-8·T4 의 랩 증거. ApplicationReady 34964 는 실제 경로에서도 맞음 |
| 2026-10-08 | PROFINET 문서 (11단계 제안 선별) | — | 68 (A20261008-4) | #96 "발견한 다른 문제"·#101: 입문서가 T12-4~T12-8 이후 동작(태그, C_SDU 36, DataStatus 0x35)과 어긋남. 문서만 |
| 2026-10-09 | PROFINET RPC (오라클 반론, 루틴 발견 + fable 동의) | [20261009-pnio-errorcode2.md](20261009-pnio-errorcode2.md) | — (큐 16·66 비고) | T5 주기 미달 `DB 81 02 0E`→`0B`, 알람 Low 태그 `04 12`→`04 0C` (10진 서수). 인수인계 T5 의 0x0D/0x0E 오류 |
| 2026-10-11 | EtherNet/IP 어댑터 (EDS) · 문서 (11단계 제안 선별) | [20261011-eip-eds-docs.md](20261011-eip-eds-docs.md) | 69–70 (A20261011-1, -2) | #111·#106 제안. EDS Param1 링크 경로 `6,0`. 병합 뒤 문서 지연(EIP EDS·minor_rev, CTT rpc_connect, SLMP 비트 형식). PN GSDML 서술은 큐 68 비고 |
| 2026-10-11 | SLMP 스택·어댑터 (12단계 일요일 감사, opus) | [20261011-slmp.md](20261011-slmp.md) | 71–73 (A20261011-3, -4, -5) | 클라이언트 로컬 맵 용량 밖 주소(스택 쓰기 미송신, 어댑터 FB_ERR_IO), 서버 비트 7168 점. 실패 쓰기 미러는 결함 없음. 감시 타이머 = 소켓 타임아웃, 길이 불일치 C061 등은 "확인 필요" |
