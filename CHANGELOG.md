# Changelog

이 프로젝트는 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) 형식을 따른다.
버전은 `VERSION` 과 CMake `project(... VERSION ...)` 의 **제품 스냅샷**이다.
앱 ABI (`FB_API_VERSION_*` in `include/fb_api.h`) 와는 별개다.

## [Unreleased]

내부 CTT. **인증이 아니다.**

### Fixed

- SLMP Binary 3E: bound batch qty (word ≤960, bit ≤7168, qty≠0) with end
  `0xC051`; unknown subcommand `0xC050`; unknown device `0xC056` (no map alloc).
  Closes stack overflow when `qty≈1013` into a 960-word array (G1)
- EtherNet/IP: arm Class1 watchdog at Forward Open; reject duplicate
  connection triad; require exclusive-owner assembly path; match o2t/t2o
  sizes to configured assemblies (G2)
- PROFINET RPC: IODWriteReq body must be ≥34 bytes before reading record
  length (G3); reject Connect from another controller while AR is up;
  same sender IP / CMInitiatorObjectUUID may replace; abort AR on CMI
  activity timeout (2 s until O→T or PrmEnd; our RTC1 TX does not
  count) or RT data-hold after controller liveness. Data-hold uses the
  output IOCR period (`SendClockFactor × ReductionRatio × 31.25 µs`),
  not `cycle_us`. With no output-CR clock the 2 s CMI window stays
  armed. A rejected Connect (HMAC / ownership) does not clear
  the current AR (G4); NDR
  `argsLen==UINT32_MAX` no longer wraps `20+n` into an unbounded block
  walk (fuzz SEGV). ARBlockReq MAC is copied only when the body is at
  least 26 bytes (fuzz heap-buffer-overflow)
- EtherNet/IP Encaps: reject CIP item length <2; SendRRData /
  UnregisterSession require a session **owned by this TCP/TLS
  connection** (status `0x64`); drop session on disconnect; unguessable
  handles (G5). CTT/unit tests parse Forward Open replies after the
  Encaps header so a `0xD4` byte in the handle is not a false CIP match.

- Config JSON parse error: print `cJSON_GetErrorPtr()` before `free(raw)`
  (heap use-after-free on `fb_reload` of malformed JSON; ASan)
- CTT PROFINET `dcp_set_ip`: do not pass uninitialized `frames[0]`/`flens[0]`
  into `finish_eth_step` when no Set.Res was captured (C UB on the miss path)
- SLMP client batch read: skip `memcpy`/`wire_words_to_be` on empty OK payload
  (`data == NULL`, length 0) instead of C `memcpy(NULL, 0)` UB
- GCC `-Wsign-compare` in `slmp_encode_batch_read` and EIP originator SendRR
- CTT AF_PACKET: reject iface names longer than `IFNAMSIZ` instead of truncating
- `tools/ctt/gen_board_data.py`: drop unused table-header local (pyflakes)

### Changed

- CTT timed soak: `clock_nanosleep(TIMER_ABSTIME)` 절대시각 대기
  (`tools/ctt/cycle_clock.c`). 상대 `sleep_ms(cycle)` 드리프트 제거.
  PREEMPT_RT / isolcpus 없음. 소프트 예산: late@1.5×cycle = 0 (µs 인증 아님).
  5 min×4 비교: [`docs/soak_report_20260910_jitter.md`](docs/soak_report_20260910_jitter.md)
  (avg 8.000 ms·37500 사이클; `jitter_max` 는 공유 VM 스파이크가 지배)
- PN RTC1 / EIP Class1 produce 주기를 last=now 가 아니라 phase += period 로 유지
- Soak 핫패스: YAML/encode 재파싱·SLMP handle_request heap alloc 제거 (루프 안만)
- Default `CMAKE_BUILD_TYPE` RelWithDebInfo so `_FORTIFY_SOURCE=2` has `-O2`

### Added

- IEC 62443 coding-level 수정 리포트
  [`docs/reports/security_fixes_20260928.md`](docs/reports/security_fixes_20260928.md)
  (G1–G5 + G9 fuzz/hardening; G6/G7/G8 는 이 PR 범위 밖. **인증 아님**)
- libFuzzer 하네스 `tests/fuzz/` (`mb_adu`, `slmp_request`, `eip_encap`,
  `eip_io`, `pn_eth`, `pn_rpc`) + CI `fuzz` (~60s/target) +
  `-fstack-protector-strong` / `_FORTIFY_SOURCE=2` (opt)
- 풀테스트 리포트 [`docs/reports/full_test_20260910.md`](docs/reports/full_test_20260910.md)
  (`main` @ `e387a31`, daemon+API+CTT 92/92 포함 `soak_ci`, mock flow 4프로토콜,
  sw-master 30s, CODESYS stand-in, ASan+UBSan+LSan; **인증 아님**)
- 정적+동적 분석 리포트 [`docs/reports/analysis_20260910.md`](docs/reports/analysis_20260910.md)
  (ASan UAF / C UB 수정 포함, **인증 아님**)
- 소프트웨어 마스터 soak (CODESYS 없음): Modbus TCP · SLMP Binary 3E · EtherNet/IP
  Class 1(또는 explicit) 가 우리 DUT 스택에 **라이브 TCP(/UDP) 루프백** IO.
  [`docs/sw_master_io.md`](docs/sw_master_io.md), `examples/sw_master.py`,
  `examples/run_sw_master_soak.sh`, `config/example.sw_master.ethernetip.json`.
  PROFINET 은 라이브 마스터 없음 (mock 안내만). 인증/PREEMPT_RT/`CAP_NET_RAW` 아님
- CODESYS SoftPLC 를 마스터로 두는 DUT 경로: [`docs/codesys_master_io.md`](docs/codesys_master_io.md),
  `examples/run_codesys_dut.sh`, CODESYS 형태 Modbus 스탠드인
  (`examples/codesys_shaped_modbus_master.py`, **SoftPLC 아님**),
  `config/example.codesys.*.json`. IDE 부트 앱·인증 클레임 없음
- EtherNet/IP Encaps ListServices YAML (`EIP-A-ENC-003`) — DUT 핸들러 고정
- Large Forward Open YAML (`EIP-A-CM-004`, CIP `0x5B`) — 기존 DUT 경로 + Class1 IO
- Timed mock soak: MB/SLMP/EIP `duration_s` + EIP `soak` action, `--seconds` /
  `CTT_SOAK_DURATION_S`, `*/nightly/soak_nightly.yaml`, `tests/run_mock_soak.sh`
  (내부 게이트, 인증 아님)
- 장비 없는 soak 실행 기록 [`docs/soak_report_20260909.md`](docs/soak_report_20260909.md)
  (실제 duration = 5 min × 4 sequential; 2h×4 / 30min×4 는 이 세션에서 미완료)

### Notes

- PROFINET Alarm Ack / Modbus FC08·MEI 는 DUT 미구현 → gap 유지
- 라이브 TCP `:502` / `:5000` 은 기본 CI 에 넣지 않음 (`docs/ctt_lab.md`)
- 2h×4 연속 soak 는 클라우드 세션 한 번에 넣기 어려움. 리포트는 실제 duration 을 명시

## [0.1.0] — 2026-09-09

내부 스냅샷. 장비 없는 데모·내부 CTT mock 게이트까지 제품 경로가 닫힌다.
**인증 릴리스가 아니다.** 하드웨어 랩(PLC / 실 NIC / AF_PACKET)은 이후.

### 범위 / 인증이 아닌 것 (Not certification)

- CTT green · `docs/ctt_board.html` 통과 배지 ≠ PI / ODVA / Modbus.org / Mitsubishi 공인 랩 evidence
- 내부 bundle-grade 카탈로그 (`PN-B-*`, `EIP-A-*`, `MB-T-*`, `SLMP-3E-*`) ≠ 공식 인증
- PROFINET **CC-B + RT Class 1** only. **IRT / CC-C 는 목표 아님** (permanent non-goal)
- SLMP **Binary 3E** batch only. ASCII / 4E 는 enum 예약만
- 기본 CI 에 `CAP_NET_RAW` / sudo / 실 NIC 없음 (`iface: mock`, 루프백)
- EtherCAT / CC-Link 랩 데모는 main 밖 (PR #1 / #5 / #6 미머지).
  CODESYS 는 DUT 쪽 문서·스탠드인만 (SoftPLC 앱 다운로드는 IDE 필요)
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
