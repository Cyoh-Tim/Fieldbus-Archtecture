# 감사 2026-11-15 — PROFINET RT·알람: O→T 수신 검사, 컨트롤러 ERR-RTA, 중복 DATA-RTA, 알람 송신자 검사

- 영역: PROFINET RT·알람 (`stacks/profinet/src/pn_rt.c`, `pn_sec.c` 의 RTA 부분, `pn_stack.c` 의 수신 분기) — 12단계 감사
  (RTC1 Class 1 주기 데이터, CycleCounter, DataStatus, IOPS/IOCS, AlarmCR·RTA-PDU DATA/ACK/NACK/ERR, SequenceNumber,
  재전송·타임아웃, 워치독·DataHold). IRT·CC-C 는 영구 비목표라 보지 않았다.
- 출처: 12단계 감사 라운드. 오라클 DUT `pn_oracle_pipe`·`pn_oracle_app` (mock Ethernet) 를 scapy 2.7.0 (`contrib.pnio`, `contrib.pnio_rpc`) 으로 두드림
- 기준 커밋: `6fdd10f` (origin/main). `stacks/profinet/` 는 `00a7a53` (이 보고서를 올린 시점의 main) 까지 바뀌지 않았다.
  DUT 는 `cmake -DBUILD_DAEMON=ON` 빌드 (로컬 CI oracle job 과 같은 설정)
- 대조 소스 (2026-11-15 내려받음): p-net `master` `1c3b0b4` (2026-11-13; `src/common/pf_cpm.c`, `pf_cpm_driver_sw.c`, `pf_alarm.c`,
  `src/device/pf_cmsu.c`, `pf_cmdev.c`, `include/pnet_api.h`), Wireshark `master` `f07cf797` (`plugins/epan/profinet/packet-pn-rt.c`,
  `packet-dcerpc-pn-io.c`), scapy 2.7.0 (`contrib/pnio.py` `PNIORealTimeCyclicPDU.dataStatus`, `contrib/pnio_rpc.py` `PDU_TYPE_TYPE`)
- 판단: opus 하위 에이전트 (코드 대조 + 오라클 재현 + p-net·Wireshark·scapy 대조). 재현·인용은 루틴이 다시 확인했다 (새 오라클 11개
  strict xfail, `--runxfail` 11 failed, p-net `pf_cpm_driver_sw.c:337-349`·`pf_alarm.c:786-806`·`:1972-1979` 원문 대조). 하위 에이전트는
  최소 패치 DUT 에서 새 11개 통과·기존 PN 오라클 결과 그대로임도 확인했다
- 큐 추가: 5개 (A20261115-1 ~ -5 → 큐 127–131). -1·-2 는 v0.2.0 게이트 (기준 c·b). 오라클 하네스 정정 1개 (이 라운드에서 함께 고침 — 아래 "오라클 하네스")

이미 알려진 것은 다시 올리지 않았다: T12-6 (DataStatus 0x35), T12-7 (최소 길이 패딩), T12-8 (VLAN 태그), T4·T12-15 (송신 주기·CycleCounter 증가량),
A20261025-6 (AlarmCR 범위, 큐 93), A20261007-1 (태그 헤더, 큐 66), 큐 68 (입문서 RT·알람 서술 갱신).
기존 오라클이 다루는 동작(RTC1 DataStatus·길이·오프셋·VLAN·CycleCounter 증가량·송신 주기, 알람 RTA-PDU 형식·AlarmDstEndpoint)은 발견으로 세지 않았다.

요약: 장치의 **O→T 소비(CPM)** 에 수신 검사가 거의 없다. FrameID 와 목적지 MAC 만 맞으면 어떤 프레임이든 출력 이미지에 쓰고
data-hold 타이머를 되살린다 (A20261115-1, -2). **알람 수신(APMR)** 은 ACK·DATA 만 보고, 컨트롤러의 ERR-RTA·중복 DATA·송신자 확인이
없다 (-3, -4, -5). 송신 쪽(RTC1 형식, 알람 DATA 형식·재전송·ERR-RTA abort)은 p-net 과 같았다 (단, 오라클 DUT 에서는 재전송이 돌지 않는다 — 하네스 문제).

## A20261115-1. O→T 의 DataValid=0 프레임과 CycleCounter 가 늘지 않은 프레임을 받아 출력에 쓰고 AR 을 유지한다

**문제:** 컨트롤러 → 장치 RTC1 을 받을 때 APDUStatus 를 보지 않는다.
1. DataStatus.DataValid(bit 2)=0 인 프레임도 출력 이미지에 쓴다. 컨트롤러가 "이 데이터는 무효" 라고 표시한 값이 그대로 장치 출력이 된다.
2. CycleCounter 가 직전 프레임과 같거나 뒤로 간 프레임(중복·지연·재생 프레임)도 새 데이터로 쓴다.
3. 두 경우 모두 data-hold 타이머를 리로드한다. 컨트롤러가 무효 데이터만 보내거나 같은 프레임이 반복돼도 AR 이 끊기지 않고, 대체값(0)으로 가지 않는다.

**근거 (파일:줄, 기준 커밋 `6fdd10f`):**
- `stacks/profinet/src/pn_rt.c:232-269` `pn_rt_on_frame` — FrameID 만 비교(`:242`)하고 IODataObject 경로는 `:248` 길이만 본 뒤 `:251` `consume_output_csdu`,
  `:252-253` `saw_rt`·`last_rt_rx_ns` 갱신. IODataObject 없는 경로(`:258-268`)도 같다. CycleCounter·DataStatus·TransferStatus 를 읽는 코드가 없다.
- `pn_rt.c:105-108` data-hold 기준 시각이 `last_rt_rx_ns` 라서 위의 모든 프레임이 타이머를 되살린다.

**재현 (오라클, DUT `pn_oracle_app` 출력 포인트 `out0` = C_SDU[0:2], `pn_oracle_pipe`):** Connect(DataHoldFactor 10 → 160 ms) 뒤
정상 O→T (CycleCounter 0x0100, out0 0x1234) 하나, 이어서 아래 프레임 (out0 0x5678).

```
good cycle 0x0200 ds 0x35    out0 before=0x1234 after=0x5678   (대조: 정상 갱신)
stale cycle 0x0100           out0 before=0x1234 after=0x5678
DataValid=0 ds 0x31          out0 before=0x1234 after=0x5678
stale-cycle    6 frames ~300ms: ERR-RTA=[] RTC1 in last 60ms=4     (data-hold 160 ms 의 2배 가까이 나쁜 프레임만)
data-invalid   6 frames ~300ms: ERR-RTA=[] RTC1 in last 60ms=4
```

`--runxfail`: `test_oto_invalid_c_sdu_not_applied[stale-cycle|data-invalid]` → `AssertionError: …: 출력 이미지가 0x5678 로 바뀌었다 (0x1234 유지 기대)`,
`test_oto_invalid_c_sdu_does_not_hold_ar[stale-cycle|data-invalid]` → `AssertionError: …: 나쁜 O→T 만 받는데 data-hold 만료 abort (ERR-RTA) 가 없다`.

**기대값과 출처:**
- 독립 구현 p-net `src/common/pf_cpm_driver_sw.c:330` `data_valid = (data_status & 0x04) != 0`, `:342` `c_sdu_structure = (pf_cpm_check_cycle(p_cpm->cycle, cycle) == 0)`,
  `:344-349` `dht_reload = frame_structure && c_sdu_structure && (data_valid || backup)`,
  `update_data = frame_structure && c_sdu_structure && data_valid && (primary || backup)`, `:350-357` DataValid=0 은 무시, `:359-386` 리로드·갱신은 이 조건일 때만.
- p-net `src/common/pf_cpm.c:181-193` `pf_cpm_check_cycle` — `(uint16_t)(now - prev)` 가 1..61440 일 때만 새 프레임. `:249` 활성화 때 `cycle = -1` (첫 프레임은 받음).
- 만료 시 `pf_cpm_driver_sw.c:66-73` `ABORT_AR_CONSUMER_DHT_EXPIRED` (0x05) — 이 저장소의 data-hold abort 코드(`pn_rt.c:16-18`)와 같다.
- Wireshark `packet-pn-rt.c:188` DataValid = bit 2, `:222-229` "Valid"/"Invalid". scapy `contrib/pnio.py` `dataStatus` 플래그 `validData` (bit 2).

**수정 범위:** `stacks/profinet/` + `tests/` (+ `tools/ctt/proto/profinet/pn_plugin.c` 의 O→T 주입만).
- `pn_rt_on_frame` 두 경로 모두: APDUStatus(C_SDU 뒤 4바이트)를 읽어 CycleCounter 가 새 값(차이 1..61440, AR 시작 뒤 첫 프레임은 무조건)이 아니면 버린다.
  DataValid=0 이면 출력은 쓰지 않는다. data-hold 리로드는 p-net 처럼 `DataValid || Backup` 일 때만.
- 같이 바뀌는 고정값: `tests/test_pn_t12_4.c:377-391` 은 DataStatus 0x00 (memset) 프레임의 출력 반영을 기대한다 → `0x35`·CycleCounter 로 바꾼다
  (최소 패치에서 이 단위 테스트만 실패했다). CTT `pn_plugin.c:1344-1366` `inject_ot_rtc1` 은 CycleCounter 를 늘 1 로 보낸다 → 호출마다 늘린다
  (IODataObject 없는 경로까지 고치면 CTT io_cycle 뒤 data-hold 가 만료된다).

**완료 조건:** `test_oto_invalid_c_sdu_not_applied` 2개, `test_oto_invalid_c_sdu_does_not_hold_ar` 2개 통과 (`A20261115-1` 표시 삭제).
`test_rtc1_*`, `test_adapter_*` 계속 통과. 단위 테스트로 CycleCounter 0xFFFF→0x0000 넘김과 Backup(bit 0=0)+DataValid=0 (리로드만, 갱신 없음)을 보인다.

## A20261115-2. O→T 의 송신 MAC·TransferStatus·길이를 보지 않는다 — 다른 스테이션이 출력을 쓰고 AR 을 붙잡는다

**문제:** 목적지 MAC 이 장치이고 FrameID 가 출력 IOCR 과 같으면 송신자가 누구든 받는다. AR 의 컨트롤러(CMInitiatorMacAdd)가 아닌 스테이션이
장치 출력을 바꾸고 data-hold 를 리로드할 수 있다 (컨트롤러가 사라져도 AR 이 남는다). TransferStatus≠0 (사양상 무시할 프레임)과
C_SDU 가 IOCR DataLength 보다 짧은 프레임도 받는다. 짧은 프레임은 APDUStatus 4바이트까지 데이터로 복사한다.

**근거 (파일:줄, 기준 커밋 `6fdd10f`):**
- `stacks/profinet/src/pn_stack.c:173` `ours` (목적지 MAC) 만 보고 `:182-183` `pn_rt_on_frame`. 송신 MAC `src` 는 RT·알람 분기에 넘기지 않는다.
- `pn_rt.c:246-251` — `avail >= out_csdu_len + 4` 가 아니면 `avail = plen - 2` 그대로 `consume_output_csdu` (짧은 프레임도 받음, 꼬리 4바이트가 데이터가 됨).
  TransferStatus 를 읽지 않는다.

**재현 (오라클, DUT `pn_oracle_app`):** A20261115-1 과 같은 절차, 두 번째 프레임만 다르게.

```
other src MAC                out0 before=0x1234 after=0x5678   (송신 00:11:22:33:44:66, AR 컨트롤러는 …:55)
TransferStatus 0x01          out0 before=0x1234 after=0x5678
short C_SDU 20               out0 before=0x1234 after=0x5678   (IOCR DataLength 40)
```

`--runxfail`: `test_oto_bad_frame_structure_not_applied[other-src-mac|transfer-status|short-c-sdu]` → `AssertionError: …: 출력 이미지가 0x5678 로 바뀌었다 (0x1234 유지 기대)`.

**기대값과 출처:**
- p-net `src/common/pf_cpm_driver_sw.c:337-341` `frame_structure = (transfer_status == 0) && (pf_cpm_check_src_addr(p_cpm, p_buf) == 0) && (len == p_cpm->buffer_length)`.
  거짓이면 갱신도 리로드도 없다 (`:344-349`, `:401-407`).
- p-net `src/common/pf_cpm.c:195-210` `pf_cpm_check_src_addr` (송신 MAC == `p_cpm->sa`), `:252-256` `sa` = `ar_param.cm_initiator_mac_add`,
  `:262-268` `buffer_length` = 헤더 + `c_sdu_length` + 4.
- Wireshark `packet-pn-rt.c:1141-1146` TransferStatus≠0 → "(ignore this frame)".

**수정 범위:** `stacks/profinet/` + `tests/`.
- RT 수신은 송신 MAC 이 `ar.initiator_mac` 일 때만 (알람과 같이 — A20261115-5). TransferStatus≠0 은 버린다.
- C_SDU 가 IOCR DataLength 보다 짧으면 버린다. 더 긴 경우는 이더넷 최소 길이 패딩만 허용할지 구현 선택 (p-net 은 정확히 같아야 함. C_SDU 40 이상이면 패딩이 생기지 않는다).
- A20261115-1 과 같은 함수라 같은 PR 이어도 된다 (그때 두 표시 모두 지움, 허용).

**완료 조건:** `test_oto_bad_frame_structure_not_applied` 3개 통과 (`A20261115-2` 표시 삭제). CTT `ctt_pn_*` 계속 PASS (CTT 주입은 컨트롤러 MAC 을 쓴다 — 최소 패치에서 33/33 PASS).

## A20261115-3. 컨트롤러가 보낸 ERR-RTA-PDU 를 무시한다 — AR 이 남는다

**문제:** 컨트롤러는 AR 을 끊을 때 알람 CR 로 ERR-RTA-PDU 를 보낸다 (예: 파라미터 Write 실패, 컨트롤러 정지). 장치는 PDU Type 4 를 버리고
AR 을 유지한 채 RTC1 을 계속 보낸다. PrmEnd 전이면 CMI 타임아웃(CMInitiatorActivityTimeoutFactor × 100 ms, 오라클 Connect 는 60 s)까지
AR 이 남아 다른 컨트롤러의 Connect 를 거부하고, 같은 컨트롤러의 새 Connect 도 옛 AR 위에서 처리된다.

**근거 (파일:줄, 기준 커밋 `6fdd10f`):** `stacks/profinet/src/pn_sec.c:309-311` — `typ != RTA_TYPE_ACK && typ != RTA_TYPE_DATA` 이면 `return`.
ERR (4) 처리 코드가 없다. (2026-10-25 보고서 "확인 필요 2" 를 재현으로 확정.)

**재현 (오라클, DUT `pn_oracle_pipe`):** Connect(LocalAlarmReference 7) 뒤 ERR-RTA (Dst 1 = 장치 AlarmCRBlockRes, Src 7, PDUType 0x14, PNIOStatus `CF 81 FD 0D`).

```
inject ERR-RTA fe01000100071401fffffffe0004cf81fd0d: device RTA tx=[] RTC1 in next 60ms=4
```

`--runxfail`: `test_alarm_err_rta_from_controller_aborts_ar` → `AssertionError: ERR-RTA 를 받은 뒤에도 RTC1 이 나간다 (AR 유지)`.

**기대값과 출처:**
- p-net `src/common/pf_alarm.c:2235-2275` `PF_RTA_PDU_TYPE_ERR` (VarPartLen 4) → APMR OPEN 이면 `pf_alarm_error_ind(…, error_code_1, error_code_2)`,
  `:330-350` → `pf_cmsu_alarm_error_ind` (`src/device/pf_cmsu.c:309-318`) → `pf_cmdev_state_ind(net, p_ar, PNET_EVENT_ABORT)`.
- Wireshark `packet-dcerpc-pn-io.c:1795-1799` PDU Type 4 "ERR-RTA-PDU", `:19996-19998` ERR-RTA 본문 = PNIOStatus. scapy `pnio_rpc.py:1332-1337` `0x04: "RTA_TYPE_ERR"`.

**수정 범위:** `stacks/profinet/` + `tests/`. 송신자 검사(A20261115-5)를 통과한 ERR-RTA (VarPartLen 4) 를 받으면 AR abort (출력 대체값 0, 지금의 `pn_ar_abort` 경로).
장치가 같은 ERR-RTA 로 답할지는 구현 선택 (p-net 은 CMDEV abort 에서 APMX close 로 ERR 을 보낸다).

**완료 조건:** `test_alarm_err_rta_from_controller_aborts_ar` 통과 (`A20261115-3` 표시 삭제). `test_alarm_*` 계속 통과.
단위 테스트로 VarPartLen≠4 ERR-RTA 는 무시함을 보인다.

## A20261115-4. 같은 DATA-RTA 가 다시 오면 (장치 ACK 유실) ACK 를 다시 보내지 않는다

**문제:** 컨트롤러의 DATA-RTA (주로 AlarmAck) 에 장치가 보낸 ACK-RTA 가 유실되면, 컨트롤러는 같은 SendSeqNum 으로 DATA 를 재전송한다.
장치는 그 seq 를 이미 받았으므로 버리고 ACK 를 다시 보내지 않는다. 컨트롤러는 RTARetries 끝에 알람 채널 오류로 AR 을 끊는다.
프레임 하나가 유실되면 AR 이 끊긴다.

**근거 (파일:줄, 기준 커밋 `6fdd10f`):** `stacks/profinet/src/pn_sec.c:324-326` — `recv_seq != ch->exp_seq` 이면 `return`. 주석 `:318-323` 이
"p-net resends the ACK for exp_seq_count_o and NACKs the rest" 라고 적고도 구현하지 않았다. (2026-10-25 보고서 "확인 필요 1" 을 재현으로 확정.)

**재현 (오라클, DUT `pn_oracle_pipe`):** Connect → `ALARM fe01` → 컨트롤러 TACK → AlarmAck-Low DATA-RTA (SendSeq 0xFFFF) 두 번.

```
device DATA: ['000700011111fffffffe001a|00020016']
controller TACK -> device tx []
controller AlarmAck DATA seq ffff (1st) -> device tx ['000700011301fffeffff0000|']
controller AlarmAck DATA seq ffff (again) -> device tx []
```

`--runxfail`: `test_alarm_duplicate_data_rta_re_acked` → `AssertionError: 재전송된 DATA-RTA (SendSeqNum 0xFFFF) 에 ACK-RTA 를 다시 보내지 않는다`.

**기대값과 출처:**
- p-net `src/common/pf_alarm.c:1972-1979` — `send_seq_num == exp_seq_count_o` 이면 APMS 에 AckSeqNum 을 넘기고 `pf_alarm_apmr_send_ack` 로 ACK 재송신
  (`:1721-1740`, SendSeq = `send_seq_count_o`, AckSeq = `exp_seq_count_o` — 첫 ACK 와 같은 값).
- 같은 함수 `:1980-1997` 그 밖의 seq 는 NACK-RTA (`pf_alarm_apmr_send_nack`, `:1763-1790`) + 로그북 `ABORT_CODE_SEQ`.
- Wireshark `packet-dcerpc-pn-io.c:1795-1799` PDU Type 2 NACK·3 ACK.

**수정 범위:** `stacks/profinet/` + `tests/`. `pn_alarm_on_frame` 에서 TACK=1 이고 SendSeqNum 이 `ack_seq` (= exp_seq_count_o) 이면 `apms_on_tack` 후
`send_ack_rta` 로 같은 ACK 를 다시 보낸다. 상태(exp_seq)는 바꾸지 않는다. 기대 밖 seq 의 NACK-RTA 는 같은 PR 에서 해도 된다 (오라클은 재ACK 만 판정).

**완료 조건:** `test_alarm_duplicate_data_rta_re_acked` 통과 (`A20261115-4` 표시 삭제). `tests/test_pn_t12_10.c` 의 AlarmAck·piggyback 테스트 계속 통과.

## A20261115-5. 알람 프레임의 송신 MAC·AlarmSrcEndpoint 를 보지 않는다 — 다른 스테이션의 ACK 가 대기 중 알람을 지운다

**문제:** 알람 수신은 AlarmDstEndpoint(장치 참조)만 본다. AR 컨트롤러가 아닌 MAC, 또는 컨트롤러 LocalAlarmReference 가 아닌 AlarmSrcEndpoint 의
ACK-RTA 도 받아 대기 중인 알람을 확인 처리한다. 진짜 컨트롤러가 알람을 받지 못했는데 장치는 재전송을 멈추고 다음 seq 로 넘어간다
(알람 유실). 같은 경로로 DATA·(A20261115-3 이후) ERR 도 아무 스테이션에서나 받게 된다.

**근거 (파일:줄, 기준 커밋 `6fdd10f`):**
- `stacks/profinet/src/pn_sec.c:301-303` — `pn_rd_be16(rta) != alarm_src(&s->ar)` (Dst) 만 검사. Src endpoint(`rta + 2`) 는 읽지 않는다.
- `pn_stack.c:182-183` — 송신 MAC 을 넘기지 않는다 (A20261115-2 와 같은 자리). `pn_sec.c:245-259` `apms_on_tack` 은 seq 만 맞으면 대기 프레임을 지운다.

**재현 (오라클, 하네스 정정한 `pn_oracle_pipe` — 아래 "오라클 하네스"):** Connect(LocalAlarmReference 7) → `ALARM fe01` → ACK-RTA (AckSeq 0xFFFF) → 200 ms 동안 재전송 수.

```
controller MAC, src ep 7   retransmits in 200ms=0 next ALARM: DATA=['0007000111110000fffe001a|…']  (대조: 정상 ACK)
other MAC, src ep 7        retransmits in 200ms=0 next ALARM: DATA=['0007000111110000fffe001a|…']
controller MAC, src ep 5   retransmits in 200ms=0 next ALARM: DATA=['0007000111110000fffe001a|…']
(ACK 없음 대조: 250 ms 동안 DATA 3번, 그 뒤 ERR-RTA cf81fd08 abort)
```

`--runxfail`: `test_alarm_ack_from_wrong_source_ignored[other-src-mac|other-src-endpoint]` → `AssertionError: …: AR 컨트롤러가 아닌 ACK-RTA 로 대기 중 알람(SendSeq 0xffff)의 재전송이 멈췄다`.

**기대값과 출처:**
- p-net `src/common/pf_alarm.c:786-806` `pf_alarm_apmr_frame_handler` — "Only accept alarm frames from the alarm endpoint of the IO-controller of the AR":
  송신 MAC ≠ `apmx.da` 또는 `source_endpoint != apmx.dst_ref` 이면 버린다. `:1030-1036` `da` = CMInitiatorMacAdd, `dst_ref` = AlarmCRBlockReq LocalAlarmReference.
- Wireshark `packet-dcerpc-pn-io.c:19943-19946` RTA-PDU 첫 두 필드 AlarmDstEndpoint·AlarmSrcEndpoint.

**수정 범위:** `stacks/profinet/` + `tests/` (오라클 하네스 mock send 반환값은 이 라운드 PR 에서 이미 고쳤다 — 아래).
알람 프레임은 송신 MAC == `ar.initiator_mac` 이고 AlarmSrcEndpoint == `alarm_dst_ref` 일 때만 처리한다.

**완료 조건:** 하네스 정정 뒤 `test_alarm_ack_from_wrong_source_ignored` 2개 통과 (`A20261115-5` 표시 삭제). 정상 컨트롤러 ACK 는 그대로 재전송을 멈춘다
(`tests/test_pn_t12_10.c` `test_ack_advances_seq_and_stops_retry`).

## 오라클 하네스 — 오라클 DUT 에서는 알람 ACK 타이머·재전송이 돌지 않았다 (큐 항목 아님, 이 라운드에서 정정)

`tests/oracle/dut/pn_oracle_pipe.c:36-45`·`pn_oracle_app.c:40-49` 의 `mock_send` 는 보낸 바이트 수를 돌려준다. `pn_eth_send`(`pn_eth.c:155-159`)는 그 값을
그대로 넘기고, `pn_alarm_send_dummy`(`pn_sec.c:188-198`)는 `rc != 0` 을 실패로 보고 ACK 타이머를 켜지 않는다 (호출자에게 양수 반환 — pipe 는 `rc < 0` 만 ERR 로 찍는다).
그래서 오라클 DUT 에서는 ACK 를 기다리지 않고, 재전송·`alarm ACK timeout` abort 도 없고, 정상 ACK 를 받아도 seq 가 늘지 않는다
(재현: 같은 seq 0xFFFF 로 `ALARM` 두 번 성공, 하네스 정정 시 두 번째는 `ERR -16`). AF_PACKET 경로(`pn_eth.c:172`)·단위 테스트 mock·CTT mock
(`tools/ctt/mock_eth.c` `ctt_ring_push` → 0)은 성공 = 0 이라 제품·CTT 는 영향 없다.
- 정정 (이 라운드 PR): 두 mock 의 `return (int)len;` → `return 0;`. 정정해도 기존 `test_pn_oracle.py` 결과는 같다 (48 passed, 45 xfailed — 정정 전후 둘 다 확인).
- 스택 쪽 보강(선택): `pn_sec.c` 가 `rc < 0` 만 실패로 보거나 `pn_stack.h:95-99` `pn_eth_ops_t.send` 반환값 규칙을 적는다.
- A20261115-5 테스트는 이 정정이 있어야 결함만으로 판정된다 (정정 없이 스택만 고치면 2개가 계속 실패한다 — 확인함).

## 확인 필요 (큐에 넣지 않음)

1. **AlarmAck 전에 다음 알람을 보낸다, AlarmSpecifier SequenceNumber 가 늘 0.** 전송 ACK(TACK) 뒤 바로 다음 알람이 나간다. p-net 은 ALPMI 가 W_ACK 에서
   AlarmAck DATA 를 받아야 W_ALARM 으로 돌아가고 (`pf_alarm.c:514-536`, `:2353`, `:2381`, `:2783`), SequenceNumber 는 11비트로 늘린다 (`:2366-2369`,
   Wireshark `packet-dcerpc-pn-io.c:6640-6654` `& 0x07FF`). 이 저장소에서 알람은 CTT/오라클 도우미(`pn_stack_send_alarm_ex`)만 보내고 제품 경로가 없어 우선순위 낮음.
2. **기대 밖 SendSeqNum 의 DATA-RTA 에 NACK-RTA 없음** (`pn_sec.c:324-326`). p-net `pf_alarm.c:1980-1997` 은 NACK. A20261115-4 PR 에서 같이 해도 된다. 오라클 재현은 하지 않았다.
3. **컨트롤러 IOPS BAD·ProviderState Stop 을 애플리케이션이 알 수 없다.** 출력 서브모듈 IOPS 가 0x00 이어도 출력 이미지에 쓴다 (`pn_rt.c:203-229`). p-net 은 데이터와
   IOPS 를 함께 넘기고 (`pf_cpm.c:398` `pf_cpm_get_data_and_iops`), DataStatus 변화를 알린다 (`pf_cpm_driver_sw.c:385-395` `pf_fspm_data_status_changed`).
   대체값 정책은 어댑터 인터페이스 결정 (`pn_stack.h` 에 IOPS 조회가 없음).
4. **첫 O→T 전 data-hold.** PrmEnd 뒤 O→T 가 없으면 마지막 RPC 기준 DataHoldFactor × 주기 (기본 48 ms) 로 끊는다 (`pn_rt.c:105-108`). p-net CPM 은 FRUN 에서
   DHT 를 세지 않고 첫 유효 프레임 뒤 RUN 에서만 센다 (`pf_cpm_driver_sw.c:62-64`). 실제 컨트롤러는 Connect 직후 O→T 를 보내 영향은 작다. 사양 확인 필요.
5. **알 수 없는 블록 타입의 DATA-RTA 를 ACK 한다**, **VarPartLen≠0 ACK-RTA 를 받는다.** p-net 은 각각 AR abort `ABORT_AR_ALARM_IND_ERROR` (`pf_alarm.c:1952-1970`) 와 무시 (`:2169-2190`).

## 선별 결과

| 후보 | 판정 | 이유 |
|---|---|---|
| O→T DataValid=0·CycleCounter 정지 프레임 수용 | **A20261115-1** | 재현 + p-net·Wireshark·scapy. 무효 데이터가 출력으로, AR 이 안 끊김. 우선순위 가장 높음 |
| O→T 송신 MAC·TransferStatus·길이 미검사 | **A20261115-2** | 재현 + p-net·Wireshark. 아무 스테이션이 출력을 씀 |
| 컨트롤러 ERR-RTA 무시 | **A20261115-3** | 재현 + p-net·Wireshark·scapy (10-25 확인 필요 2) |
| 중복 DATA-RTA 재ACK 없음 | **A20261115-4** | 재현 + p-net (10-25 확인 필요 1). ACK 하나 유실로 AR 끊김 |
| 알람 송신 MAC·SrcEndpoint 미검사 | **A20261115-5** | 재현(하네스 정정) + p-net |
| 오라클 mock_send 반환값 → 알람 타이머 꺼짐 | 오라클 하네스 정정 | 제품·CTT 영향 없음. 검증 담당이 테스트와 함께 고침 |
| ALPMI AlarmAck 대기·SequenceNumber | 확인 필요 1 | 제품 알람 경로 없음 |
| IOPS/ProviderState 미전달 | 확인 필요 3 | 인터페이스 결정 |
| RTC1 송신 형식·주기·DataStatus·VLAN·패딩 | 결함 아님 / 기존 큐 | 기존 오라클 통과 또는 T12-6·7·8·T4·T12-15 |
| 장치 ERR-RTA (abort 통지) 형식·코드 | 결함 아님 | `CF 81 FD 05/06/08` — p-net `pf_alarm.c:1603-1626` 과 같음 |


## 재현 명령

```
# 기준 DUT: main, BUILD_DAEMON=ON (로컬 CI oracle job 과 같은 설정). 저장소 루트에서
K="oto_invalid or oto_bad_frame or err_rta_from_controller or duplicate_data_rta or ack_from_wrong_source"
ORACLE_BUILD_DIR=build python -m pytest -q tests/oracle/test_pn_oracle.py -k "$K"              # 11 xfailed
ORACLE_BUILD_DIR=build python -m pytest -q --runxfail tests/oracle/test_pn_oracle.py -k "$K"  # 11 failed (메시지는 위 각 절)
ORACLE_BUILD_DIR=build python -m pytest -q tests/oracle/test_pn_oracle.py                      # 48 passed, 56 xfailed, XPASS 없음
```

수정 범위 메모 (하위 에이전트 최소 패치 확인에서): A20261115-1 을 고치면 `tests/test_pn_t12_4.c` 의 DataStatus 0 O→T 프레임과 CTT
`tools/ctt/proto/profinet/pn_plugin.c` `inject_ot_rtc1` (CycleCounter 를 늘 1 로 보냄) 도 함께 바꿔야 한다.
