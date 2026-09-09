# Changelog

이 프로젝트는 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) 형식을 따른다.
버전은 `VERSION` 과 CMake `project(... VERSION ...)` 의 **제품 스냅샷**이다.
앱 ABI (`FB_API_VERSION_*` in `include/fb_api.h`) 와는 별개다.

## [Unreleased]

내부 CTT. **인증이 아니다.**

### Added

- EtherNet/IP Encaps ListServices YAML (`EIP-A-ENC-003`) — DUT 핸들러 고정
- Large Forward Open YAML (`EIP-A-CM-004`, CIP `0x5B`) — 기존 DUT 경로 + Class1 IO

### Notes

- PROFINET Alarm Ack / Modbus FC08·MEI 는 DUT 미구현 → gap 유지
- 라이브 TCP `:502` / `:5000` 은 기본 CI 에 넣지 않음 (`docs/ctt_lab.md`)

## [0.1.0] — 2026-09-09

내부 스냅샷. 장비 없는 데모·내부 CTT mock 게이트까지 제품 경로가 닫힌다.
**인증 릴리스가 아니다.** 하드웨어 랩(PLC / 실 NIC / AF_PACKET)은 이후.

### 범위 / 인증이 아닌 것 (Not certification)

- CTT green · `docs/ctt_board.html` 통과 배지 ≠ PI / ODVA / Modbus.org / Mitsubishi 공인 랩 evidence
- 내부 bundle-grade 카탈로그 (`PN-B-*`, `EIP-A-*`, `MB-T-*`, `SLMP-3E-*`) ≠ 공식 인증
- PROFINET **CC-B + RT Class 1** only. **IRT / CC-C 는 목표 아님** (permanent non-goal)
- SLMP **Binary 3E** batch only. ASCII / 4E 는 enum 예약만
- 기본 CI 에 `CAP_NET_RAW` / sudo / 실 NIC 없음 (`iface: mock`, 루프백)
- EtherCAT / CC-Link / CODESYS 랩 데모는 main 밖 (PR #1 / #5 / #6 미머지)
- libmodbus 없음. EIP·PN 런타임은 자체 스택 (구매 스텁 아님)

### Added

- PROFINET IO Device 스택 (DCP / LLDP / RPC / RTC1 / SNMP / Sec Class 1)
- Modbus TCP 자체 스택·어댑터 (서버/슬레이브, #2 → #15)
- SLMP Binary 3E 자체 스택·어댑터 (#3 → #15)
- EtherNet/IP Adapter(+Originator) 자체 스택 (#4 → #15)
- CTT 공통 runner + PN/EIP/Modbus/SLMP 플러그인 (#14)
- 포인트 지향 앱 C API `fb_api` (#18)
- JSON → 런타임 애니메이션 `docs/json-config-flow.html` (#17)
- CTT 시나리오 현황 보드 (#19, lookup 수정 #20)
- 내부 bundle-grade v1: PN CC-B/RTC1 (#21), EIP Adapter Class 1 (#22), Modbus TCP + SLMP 3E (#23)
- 장비 없는 fake sensor → `fb_write_*` / `fb_read_*` → CTT mock (#24, 네 프로토콜 #25)
- PN CC-B lifetime / NEG / cyclic fill + 보드 갱신 (#26)
- 장비 없는 데모 패키지: `docs/demo.md` · `docs/index.html` (#27)
- 필드 의미/메모리 맵 시각화 `docs/config-viz.html` (PR #16 내용을 이 스냅샷에 편입; 데모 정본 HTML은 `json-config-flow.html`)

### Notes

- 8ms 사이클 에이징(PREEMPT_RT 없이 편차 ~0.1ms)은 코어 스케줄러 수치다. IRT 동기와 혼동하지 말 것.
- 랩 AF_PACKET 은 `docs/ctt_lab.md` / `tests/run_ctt_lab.sh` (기본 데모·CI 아님).
