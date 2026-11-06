# 2026-11-03 — PROFINET SNMP·LLDP 의 CC-B 범위 (담당자 결정) · DCP BlockError 0x06 · SNMP 퍼저

- 영역: PROFINET SNMP·LLDP (기능 범위), DCP Set 거부 값 (결정 기록)
- 출처: 2026-11-01 감사 "확인 필요" 2·3 (`20261101-pn-dcp-lldp-snmp.md`), #177 (T12-19) 검증 중 GetBulk 미응답
- 기준 커밋: `c30eb6e` (main, #177 병합 직후)
- 판단: 검증 담당 (루틴 직접). 범위는 **담당자 결정 (2026-11-03)**: 추천대로 진행
- 큐 추가: 4개 (A20261103-1 ~ -4 → 큐 105–108). 결함 큐(T12 계열) 뒤 순서

## 담당자 결정 (2026-11-03)

1. **PROFINET 보안 문구**: "Security Class 1" 대신 "자체 보안 프로파일 (PI Security Class 1 일부 기능 포함, 인증 주장 아님)".
   `CLAUDE.md` 5항, `CMakeLists.txt` pn_stack 주석, `README.md` 프로토콜 범위를 같은 PR 에서 고친다.
2. **DCP Set 거부 BlockError**: AR 이 RejectDCPsetRequests 를 켰을 때와 AR 중 IP 변경 거부는 **0x06** (In operation, SET not possible) 을 쓴다.
   Wireshark `packet-pn-dcp.c` 의 값 정의가 근거이고, IEC 61158-6-10 원문 확인은 실 컨트롤러 랩 때로 미룬다.
   오라클은 지금처럼 0 이 아닌 값만 본다 (`20261029-pn-dcp-ar-epm.md` 1절).
3. **SNMP·LLDP 는 CC-B 범위에 넣는다**: 아래 큐 105–108. 결함 큐 뒤에 둔다.
4. **SNMP 파서 CI 퍼저**: `tests/fuzz/fuzz_pn_snmp.c` 를 CI fuzz job 에 더한다 (`.github/workflows/ci.yml`).

## 근거 (공통)

- p-net `src/common/pf_snmp.h` 머리말: PROFINET 장치의 SNMP 변수는 MIB-II (RFC 3418), LLDP-MIB (IEEE 802.1AB-2005),
  LLDP-EXT-DOT3-MIB, LLDP-EXT-PNO-MIB 에 있고, PI 가이드라인 PN-Topology 6.2 가 쓰임을 정한다. p-net 은 SNMP 에이전트를 외부
  소프트웨어(Linux 포트는 net-snmp)에 맡기고 getter 를 준다: sysName·sysContact·sysLocation·sysDescr, lldpLoc*·lldpRem* 등.
  setter: sysName·sysContact·sysLocation (영구 저장).
- OID: SNMPv2-MIB `system` 1~7 (sysContact·sysName·sysLocation 는 MAX-ACCESS read-write), LLDP-MIB `lldpMIB` =
  1.0.8802.1.1.2, `lldpLocalSystemData` = …1.3 (ChassisIdSubtype 1, ChassisId 2, SysName 3, LocPortTable 7 / Entry 1 / PortIdSubtype 2,
  PortId 3), `lldpRemTable` = …1.4.1 (Entry 1: TimeMark 1, LocalPortNum 2, Index 3, ChassisIdSubtype 4, ChassisId 5, PortIdSubtype 6,
  PortId 7, SysName 9; INDEX TimeMark·LocalPortNum·Index). 원문은 librenms 가 배포하는 MIB 파일로 확인했다.
- 지금 스택 (#177 뒤): SNMPv1/v2c Get·GetNext·Set 을 해석하고 객체는 sysName.0 하나다. LLDP 는 송신만 한다
  (`pn_stack.c` 가 0x88CC 수신 프레임을 버림).

## A20261103-1. SNMPv2c GetBulkRequest 에 응답하지 않는다

**문제:** v2c GetBulk (PDU 0xA5) 를 무응답으로 버린다. v2c 매니저의 bulk walk (`snmpbulkwalk`, 많은 NMS 의 v2c 기본) 는
시간 초과로 끝나고 토폴로지 도구가 장치를 읽지 못한다.

**근거:** `stacks/profinet/src/pn_snmp.c` (`c30eb6e`) — `parse_request` 가 Get·GetNext·Set 외 PDU 를 거부.
**재현:** `test_snmp_v2c_getbulk_answered --runxfail` → `GetBulk 응답 없음`.
**기대값과 출처:** net-snmp `agent/snmp_agent.c` 는 `SNMP_MSG_GETBULK` 를 처리한다 (non-repeaters / max-repetitions 만큼 GetNext 반복).
RFC 3416 원문은 이 실행에서 받지 못했다 (프록시 차단).
**수정 범위:** `stacks/profinet/`, `tests/`. **완료 조건:** 테스트 통과 (`A20261103-1` 표시 삭제).

## A20261103-2. MIB-II system 그룹이 sysName.0 뿐이다

**문제:** sysDescr·sysObjectID·sysUpTime·sysContact·sysLocation·sysServices 가 noSuchName. sysContact·sysLocation Set 불가.
**재현:** `test_snmp_mib2_system_group` → `error 2 index 1`, `test_snmp_mib2_syscontact_set` → `Set 응답 2`.
**기대값과 출처:** SNMPv2-MIB system 1~7, p-net `pf_snmp.h` getter/setter. sysDescr 은 제품 문자열 (I&M0 과 맞춘다),
sysObjectID 는 제품 OID (값은 구현 PR 에서 `[Claude 확인 요청]` 으로 정한다), sysUpTime 은 스택 기동 뒤 1/100 s.
Set 값의 영구 저장은 T12-20 (큐 40) 의 저장 방식을 따른다.
**확인 필요:** p-net 은 sysName 을 NameOfStation 과 따로 두는 쓰기 가능 변수로 다룬다 (PN-Topology Annex A: LLDP System Name 과 같음).
지금 스택은 sysName.0 = NameOfStation, 읽기 전용이다. 바꿀지는 이 항목에서 묻는다.
**수정 범위:** `stacks/profinet/`, `tests/`. **완료 조건:** 두 테스트 통과.

## A20261103-3. LLDP-MIB 로컬 데이터가 없다

**문제:** lldpLocChassisIdSubtype/ChassisId, lldpLocPortTable 이 없다. 토폴로지 도구가 SNMP 로 장치의 LLDP 정체를 읽지 못한다.
**재현:** `test_snmp_lldp_local_matches_lldpdu` → `lldpLocChassisId 응답 2`.
**기대값과 출처:** LLDP-MIB, p-net `pf_snmp.h` (lldpLocChassisId·Subtype, lldpLocPortId·Subtype·Desc, ManAddr). 값은 실제 송신
LLDPDU 와 같아야 한다 (오라클이 송신 프레임과 비교).
**수정 범위:** `stacks/profinet/`, `tests/`. **완료 조건:** 테스트 통과.

## A20261103-4. LLDP 를 수신하지 않아 lldpRemTable 이 없다

**문제:** 이웃의 LLDPDU 를 버린다. lldpRemTable, AliasName Identify 필터 (2/6), 이웃 기반 이름 지정이 모두 불가능하다.
**재현:** 이웃 LLDPDU (Chassis "neighbor-sw", Port "port-003", TTL 120) 주입 뒤 `GetNext lldpRemChassisId` →
`이웃 행 없음: OID 1.3.6.1.2.1.1.5.0`.
**기대값과 출처:** p-net `src/common/pf_lldp.c` 수신 처리 + `pf_snmp.h` lldpRem*, LLDP-MIB lldpRemTable. TTL 만료 시 행 삭제.
**수정 범위:** `stacks/profinet/`, `tests/`. 큐 107 (LLDP-MIB 로컬) 이후. **완료 조건:** 테스트 통과.
LLDP-EXT-PNO-MIB (PortNoS·LPD·Tx/Rx delay) 는 이 항목 뒤 후속으로 판단한다.
