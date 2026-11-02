# 감사 2026-11-01 — PROFINET DCP·LLDP·SNMP: IP suite 유효성, 이름 없는 LLDP Chassis ID, 이름·IP 지우기, DeviceOptions, Hello 목적지

- 영역: PROFINET DCP·LLDP·SNMP (`stacks/profinet/src/pn_dcp.c`, `pn_lldp.c`, `pn_snmp.c`, `pn_stack.c` 의 프레임 분기) — 12단계 감사
  (영역 순환: EIP 어댑터·Originator → **PROFINET DCP·LLDP·SNMP**)
- 출처: 12단계 감사 라운드. 지난 라운드 뒤 병합된 T12-16 DCP Set 규칙(#167), T12-11 LLDP(#155) 사후 리뷰 + 오라클 DUT `pn_oracle_pipe`
  (mock Ethernet) 를 scapy 2.7.0 (`contrib.pnio_dcp`, `contrib.lldp`, `layers.snmp`) 로 두드림
- 기준 커밋: `d734cc4` (main, #167 T12-16 병합 직후). DUT 빌드는 로컬 CI `m167b` (`52cbdf9`, 트리가 `d734cc4` 와 같음 — `git diff --stat` 빈 출력)
- 대조 소스 (2026-11-01 내려받음): p-net `master` (`src/common/pf_dcp.c`, `src/common/pf_lldp.c`, `src/device/pf_cmina.c`,
  `src/common/pf_snmp.h`), Wireshark `a5739274c5` (`epan/dissectors/packet-lldp.c`, `plugins/epan/profinet/packet-pn-dcp.c`)
- 판단: opus 하위 에이전트 (코드 대조 + 오라클 재현 + p-net·Wireshark·scapy 대조). 재현 5건과 p-net 인용은 루틴이 다시 확인
- 큐 추가: 5개 (A20261101-1 ~ -5 → 큐 100–104)

이미 알려진 것은 다시 올리지 않았다: T12-19 (SNMP 요청 파싱·request-id·요청 OID, 큐 39), T12-20 (DCP IP OS 적용·저장, 큐 40),
A20261003-2 (DCP Get, 큐 61), T12-22 (DeviceRole 0x02·Identify 지연 슬롯 1개, 큐 42), T12-11 (LLDP OUI·PortID·필수 TLV, 큐 33 — 병합됨),
T12-16 (DCP Set 규칙, 큐 36 — 병합됨, 오라클 7개 통과). 기존 오라클(`test_pn_oracle.py` DCP·LLDP·SNMP 17개: 12 passed, 5 xfailed)이
다루는 동작은 발견으로 세지 않았다.

## A20261101-1. DCP Set IPParameter 가 IP suite 유효성을 보지 않는다 (넷마스크·멀티캐스트·루프백·브로드캐스트·게이트웨이)

**문제:** DCP Set IPParameter(1/2) 는 값이 12바이트 이상이면 무엇이든 BlockError 0 으로 적용한다. 비연속 넷마스크(255.0.255.0),
멀티캐스트(224.0.0.5)·루프백(127.0.0.1) IP, 서브넷 브로드캐스트·네트워크 주소(호스트부 전부 1 / 0), 다른 서브넷의 게이트웨이가 모두
"성공" 으로 들어가고 Get·Identify·Hello·LLDP Management Address 로 그대로 알려진다. 엔지니어링 툴의 오타 하나로 장치가 도달할 수 없는
주소를 갖게 되고, 컨트롤러는 Set.res 성공을 보고 그 주소로 Connect 를 시도한다. T12-20 (OS 적용) 이 들어오면 잘못된 값이 그대로 OS 인터페이스에
적용된다.

**근거 (파일:줄, 기준 커밋 `d734cc4`):**
- `stacks/profinet/src/pn_dcp.c:347-376` — `apply_set_block` IP 분기. 같은 값(`:356`)·AR 중(`:359`)·길이 12 미만(`:362`)만 보고
  `:365-371` 에서 `cfg.ip/netmask/gateway` 에 그대로 넣고 `PN_DCP_BLOCK_ERR_OK`
- 같은 함수에서 길이 12 초과(DCPBlockLength > 14)도 받아들인다 (`:362` 은 `< 12` 만 거부). p-net 은 정확히 12 (`pf_cmina.c:667-669`)

**재현 (오라클, DUT `pn_oracle_pipe`):** 장치 MAC 로 Set.req(IPParameter, BlockQualifier 1) 를 보내고 Get IPParameter 로 확인.

```
$ (스크래치 하네스) explore.py setip
valid              Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('192.168.0.60', '255.255.255.0', '192.168.0.1')
mask noncontig     Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('192.168.0.60', '255.0.255.0', '0.0.0.0')
ip multicast       Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('224.0.0.5', '255.255.255.0', '0.0.0.0')
ip loopback        Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('127.0.0.1', '255.0.0.0', '0.0.0.0')
ip subnet bcast    Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('192.168.0.255', '255.255.255.0', '0.0.0.0')
ip host0           Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('192.168.0.0', '255.255.255.0', '0.0.0.0')
gw other subnet    Set.res ServiceType=1 BlockError={(1, 2): 0} -> Get IP ('192.168.0.60', '255.255.255.0', '10.0.0.1')
```

`test_dcp_set_rejects_invalid_ip_suite[*]` (6개, `--runxfail`): `E AssertionError: 잘못된 IP suite 를 받아들임: 응답 블록 {(1, 2): 0}`.

**기대값과 출처:**
- 독립 구현 p-net `src/device/pf_cmina.c` `pf_cmina_dcp_set_ind`: `:666-671` IPParameter 는 길이 12 이고 `pf_cmina_is_ipsuite_valid` 를 통과할
  때만 적용, 아니면 `:720-726` "Case 10, 22 in Profinet 2.4 Table 1096 CMINA state table" → `PF_DCP_BLOCK_ERROR_SUBOPTION_NOT_SET` (0x03), IP 유지.
- 유효성 규칙 (p-net 주석이 "Profinet 2.4, section 4.3.1.4.21.2~5" 를 인용): `:1650-1671` suite = 넷마스크·IP·게이트웨이 모두 유효,
  `:1756-1766` 넷마스크는 연속 비트 (`!(mask & (~mask >> 1))`), `:1705-1745` IP 는 0.0.0.0/0 (IP 지우기) 외에는 호스트부 0·전부 1 금지,
  0.x / 127.x / 224~239.x / 240~255.x 금지, `:1780-1790` 게이트웨이는 0 이거나 IP 와 같은 서브넷.

**수정 범위:** `stacks/profinet/` (+ `tests/`).
- `apply_set_block` IP 분기에서 길이 정확히 12 와 suite 유효성 검사 → 실패 시 `PN_DCP_BLOCK_ERR_SUB_NOT_SET`, cfg 변경 없음, Hello 없음.
  0.0.0.0/0.0.0.0/0.0.0.0 (IP 지우기) 는 유효로 둔다 (A20261101-3 과 같은 규칙).
- 검사 순서: 같은 값 → 유효성 → AR 중 거부 (p-net 은 파싱 단계에서 유효성을 먼저 본다).

**완료 조건:** `test_dcp_set_rejects_invalid_ip_suite` 6개 통과 (`A20261101-1` 표시 삭제). 기존 `test_dcp_set_answers_every_block`,
`test_dcp_set_ip_rejected_during_ar` 계속 통과. 단위 테스트로 길이 13 이상 거부, 0.0.0.0 수락을 보인다.

## A20261101-2. NameOfStation 이 비면 LLDP Chassis ID 가 빈 문자열(TLV 길이 1)이라 LLDPDU 전체가 버려진다

**문제:** LLDP Chassis ID 는 항상 subtype 7 (locally assigned) + NameOfStation 이다. 이름이 비면(ResetToFactory·이름 지우기 뒤, 즉 공장 상태)
Chassis ID TLV 가 subtype 1바이트뿐인 길이 1 TLV 가 된다. IEEE 802.1AB 는 chassis ID 를 1~255 옥텟으로 정하므로 형식 오류이고,
Wireshark 는 "Invalid Chassis ID TLV" 로 그 LLDPDU 의 나머지(Port ID·TTL·PNO TLV)를 해석하지 않는다. 이름 없는 장치를 토폴로지로 찾아
이름을 주는 경우(이웃 기반 이름 지정)에 정확히 이 상태의 LLDP 가 필요하다. 이웃 스위치·컨트롤러가 이 LLDPDU 를 버리면 장치가
토폴로지에서 사라진다.

**근거 (파일:줄, 기준 커밋 `d734cc4`):**
- `stacks/profinet/src/pn_lldp.c:103-107` — `chassis[0] = 7; memcpy(chassis + 1, station_name, namelen); tlv(…, 1, chassis, 1 + namelen)`.
  이름 길이 0 을 따로 다루지 않는다
- 이름이 비는 경로: `pn_dcp.c:269-280` `clear_comm_factory` (ResetToFactory 모드 2/3/4/8/9, Reset Factory Settings).
  (`pn_stack_create` 는 config 의 빈 이름을 `pn-device` 로 채우므로 기동 직후에는 나타나지 않는다 — `pn_oracle_pipe ""` 로 확인)

**재현 (오라클, DUT `pn_oracle_pipe`):** DCP Set ResetToFactory(5/6, BlockQualifier 모드 2) → `POLL 5300` (LLDP 주기 5 s) → 다음 LLDPDU.

```
$ (스크래치 하네스) explore.py lldp_reset
Set.res (1, {(5, 6): 0})
...
scapy.contrib.lldp.LLDPInvalidFrameStructure: Invalid frame structure.
got: LLDPDUChassisID
expected: LLDPDUChassisID LLDPDUPortID LLDPDUTimeToLive <...>
```

`test_lldp_chassis_id_without_name_of_station` (`--runxfail`): `E AssertionError: Chassis ID TLV 길이 1 (subtype 뒤 ID 0 옥텟)`
(TLV 헤더 `0x0201`, 값 `07`).

**기대값과 출처:**
- Wireshark `epan/dissectors/packet-lldp.c` (`a5739274c5`) `dissect_lldp_chassis_id` `:1780-1786` — `dataLen < 2` 이면
  "Invalid Chassis ID Length (%u), expected > (2)" 후 `-1`, `:5051-5056` 이 그 경우 "Invalid Chassis ID TLV" 로 나머지 TLV 해석을 멈춘다.
- scapy 2.7.0 `contrib/lldp.py` `LLDPDUChassisID._check` — strict 모드(기본)에서 "id must be >= 1 characters long", 프레임 구조 검사 실패
  (위 재현 출력).
- 독립 구현 p-net `src/common/pf_lldp.c` `pf_lldp_get_chassis_id` `:584-628` — 이름 길이 0 이면 `:597-605` "Use the device MAC address":
  subtype 4 (`PF_LLDP_SUBTYPE_MAC`) + 장치 MAC 6바이트. Port ID 도 같은 규칙을 "Profinet 2.4 Protocol, table 335 LLDP substitutions:
  Use chassis MAC address if no NameOfStation is assigned" (`:670-672`) 로 인용한다.

**수정 범위:** `stacks/profinet/` (+ `tests/`).
- `pn_lldp_send`: 이름 길이 0 이면 Chassis ID = subtype 4 + `cfg.mac`. 이름이 있으면 지금처럼 subtype 7 + 이름 (T12-11 단위 테스트 유지).
- (선택) 이름이 바뀐 직후 LLDP 를 바로 한 번 보내기 — "확인 필요" 4 참고.

**완료 조건:** `test_lldp_chassis_id_without_name_of_station` 통과 (`A20261101-2` 표시 삭제). `test_lldp_*` 기존 3개 계속 통과.
단위 테스트로 빈 이름 → Chassis ID TLV 길이 7, subtype 4, MAC.

## A20261101-3. 이름 지우기(빈 NameOfStation Set)를 거부하고, AR 중 IP 지우기(0.0.0.0)를 "다른 IP 로 변경" 처럼 거부한다

**문제:** CMINA 는 "이름/IP 를 지우는" Set 을 별도 경우로 다룬다. 이 스택은 두 경우를 모두 거부한다.
1. Set NameOfStation 값 길이 0 (DCPBlockLength 2, BlockQualifier 만) → BlockError 0x03, 이름 유지. 엔지니어링 툴의 이름 지우기·초기화가 실패한다.
2. AR 중 Set IPParameter 0.0.0.0/0.0.0.0/0.0.0.0 → BlockError 0x06 (In operation), AR 유지. 사양 상태표는 이것을 "IP 지우기" 로 보고
   수락 + AR abort 한다. T12-16 이 맞게 고친 "AR 중 **다른 IP 로 변경** → 거부 (Case 26)" 와 다른 경우인데 같은 분기로 처리된다.

**근거 (파일:줄, 기준 커밋 `d734cc4`):**
- `stacks/profinet/src/pn_dcp.c:97-100` — `pn_dcp_name_ok` 이 `n == 0` 이면 0, `:379-382` — `vlen == 0 || !pn_dcp_name_ok(…)` → `SUB_NOT_SET`
- `pn_dcp.c:356-361` — 같은 suite 가 아니면 AR 중엔 무조건 `PN_DCP_BLOCK_ERR_IN_OPERATION`. 0.0.0.0 을 구분하지 않는다
- 단위 테스트 `tests/test_pn_dcp.c:261` 이 `pn_dcp_name_ok("", 0) == 0` 를 고정하고 있다 (Set 경로에서 길이 0 을 따로 받으면 이 함수는 그대로 둬도 된다)

**재현 (오라클, DUT `pn_oracle_pipe`):**

```
$ (스크래치 하네스) explore.py setip
empty name Set.res (1, {(2, 2): 3}) name now b'oracle-dut'
AR + IP reset 0.0.0.0 Set.res (1, {(1, 2): 6}) ip ('192.168.0.50', '255.255.255.0', '0.0.0.0')
RTC1 after: 4
```

`--runxfail`: `test_dcp_set_empty_name_of_station_accepted` → `E AssertionError: ServiceType 1, 응답 블록 {(2, 2): 3}`,
`test_dcp_set_ip_reset_during_ar_accepted_and_aborts_ar` → `E AssertionError: ServiceType 1, 응답 블록 {(1, 2): 6}`.

**기대값과 출처 (독립 구현 p-net `src/device/pf_cmina.c`):**
- `:1520-1521`, `:1538-1542` `pf_cmina_is_stationname_valid` — "Also empty station name is valid here (indicating that no station name has
  been set)", `len == 0` → true. `:814-829` Set NameOfStation 은 이 함수를 통과하면 이름을 복사 (빈 이름 = 이름 없음).
- `:922-927` Set 뒤 `have_name = strlen(name) > 0`, `have_ip = ip|mask|gw != 0`. `W_CONNECT` (AR 있음) 분기:
  `:1004-1025` `have_name == false` → "Case 27, 30 … Reset name or reset to factory — Abort active ARs" (0x1F),
  `:1030-1048` `have_ip == false` → "Case 27, 28 … Change name or reset IP — Abort active ARs", `ret = 0` (수락),
  `:1050-1070` 그 밖의 IP 변경만 AR 중 "Case 26 … Change IP, active connection" 거부.
- abort 코드: p-net `include/pnet_api.h:353` `PNET_ERROR_CODE_2_ABORT_DCP_STATION_NAME_CHANGED 0x1f` (스택의 `note_abort(…, 0x1F)` 와 같은 값).

**수정 범위:** `stacks/profinet/` (+ `tests/`).
- Set NameOfStation 길이 0 → 이름 비움, BlockError 0. AR 중이면 `reject_dcp_set` 이 아닐 때 수락 + abort 0x1F (이름 변경과 같은 규칙).
- Set IPParameter 0/0/0 → AR 중에도 수락, 적용 뒤 AR abort 0x1F. 다른 IP 로의 변경은 지금처럼 0x06 거부.

**완료 조건:** `test_dcp_set_empty_name_of_station_accepted`, `test_dcp_set_ip_reset_during_ar_accepted_and_aborts_ar` 통과
(`A20261101-3` 표시 삭제). 기존 T12-16 오라클 7개 계속 통과. 단위 테스트로 AR 중 빈 이름 Set → 수락 + abort,
`RejectDCPsetRequests=1` AR 에서는 거부.

## A20261101-4. Identify/Get 의 DeviceOptions 가 지원 옵션 7개 이상 중 2개만 나열한다

**문제:** DeviceOptions(2/5) 값은 장치가 지원하는 (Option, Suboption) 목록인데, 이 스택은 (1,2) IPParameter 와 (2,2) NameOfStation 만
고정으로 넣는다. 같은 Identify.res 에 실린 DeviceVendor(2/1)·DeviceID(2/3)·DeviceRole(2/4)·MAC(1/1)·DeviceOptions(2/5) 자신과,
Set 으로 실제로 받는 Control Signal(5/3)·ResetToFactory(5/6)·Reset Factory Settings(5/5)·Start/Stop(5/1, 5/2) 이 빠진다. 툴은 이 목록을 보고
지원 기능(점멸, 공장 초기화, 필터 가능한 항목)을 판단한다.

**근거 (파일:줄, 기준 커밋 `d734cc4`):**
- `stacks/profinet/src/pn_dcp.c:511-515` — `opts[] = {IP, IP_PARAM, DEV, DEV_NAME}` 고정
- 지원 근거(같은 파일): `:489-510` Identify 블록 7종, `:407-424` Control Start/Stop/Signal/Factory/Reset 처리
- `tests/test_pn_dcp.c:469` 단위 테스트와 `tests/golden/profinet/dcp_identify_res.pcap`·`dcp_get_res.pcap`·`dcp_hello*.pcap` 이 지금 값을 고정

**재현 (오라클):**

```
$ (스크래치 하네스) explore.py opts
DCPManufacturerSpecificBlock 2 1 ...
DCPNameOfStationBlock 2 2 ...
DCPDeviceIDBlock 2 3 ...
DCPDeviceRoleBlock 2 4 ...
DCPIPBlock 1 2 ...
DCPMACBlock 1 1 ...
DCPDeviceOptionsBlock 2 5 02050006000001020202
```

`test_dcp_identify_device_options_lists_supported_options` (`--runxfail`):
`E AssertionError: DeviceOptions 에 없는 (Option, Suboption): [(1, 1), (2, 1), (2, 3), (2, 4), (2, 5), (5, 3), (5, 6)] (목록 [(1, 2), (2, 2)])`.

**기대값과 출처:**
- 독립 구현 p-net `src/common/pf_dcp.c:133-160` `device_options[]` ("Device options to be included for example in DCP IDENTIFY responses") —
  IP 1/2·1/1, Device 2/1·2/2·2/3·2/4·2/5·2/6, Control 5/1·5/2·5/3·5/5·5/6, All FF/FF. `:455-459` DeviceOptions 값 = 이 배열 전체,
  `:1959-1971` Identify 응답 블록도 이 배열로 만든다 (나열한 것 = 응답에 싣는 것).
- scapy `contrib/pnio_dcp.py` `DCPDeviceOptionsBlock.device_options` (`DeviceOption(option, sub_option)` 목록), Wireshark
  `packet-pn-dcp.c` 도 같은 쌍 목록으로 해석한다 — 형식은 맞고 내용만 부족하다.

**수정 범위:** `stacks/profinet/` (+ `tests/`, `tests/golden/`).
- `build_identify_blocks` 의 DeviceOptions 를 실제 응답 블록 + 지원 Control 서브옵션으로. 표 하나로 두고 Identify·Get·Hello 가 같이 쓴다.
- golden pcap 4개와 `tests/test_pn_dcp.c:469` 를 새 값으로 (golden 갱신은 이 PR 에서 허용).

**완료 조건:** `test_dcp_identify_device_options_lists_supported_options` 통과 (`A20261101-4` 표시 삭제), 기존 DCP 오라클 통과.

## A20261101-5. DCP Hello.req 를 Hello 멀티캐스트가 아닌 Identify 멀티캐스트 01:0E:CF:00:00:00 으로 보낸다

**문제:** Hello.req (FrameID 0xFEFC) 목적지가 Identify 용 `01:0E:CF:00:00:00` 이다. Hello 를 듣는 쪽(FSU 컨트롤러)은
`01:0E:CF:00:00:01` 을 받고, 다른 목적지의 Hello 는 버린다. 입문서 11.5 표 D3 이 이 차이를 "[사양 확인 필요]" 로 남겨 둔 항목이다.

**근거 (파일:줄, 기준 커밋 `d734cc4`):**
- `stacks/profinet/src/pn_dcp.c:10` `k_dcp_mc = 01:0E:CF:00:00:00`, `:718` `send_dcp(s, k_dcp_mc, PN_FRAMEID_DCP_HELLO, …)`
- `docs/protocols/profinet.md:116`, `:913`, `:2208` (D3) — `01:0E:CF:00:00:01` 을 기대값으로 적고 [사양 확인 필요]

**재현 (오라클):** DCP Set IP 를 다른 값으로 → 스택이 Hello 를 보냄.

```
$ (스크래치 하네스) explore.py hello
Set.res (1, {(1, 2): 0})
Hello dst 01:0e:cf:00:00:00 src 02:fb:00:00:00:01
```

`test_dcp_hello_destination_is_hello_multicast` (`--runxfail`): `E AssertionError: Hello 목적지 ['01:0e:cf:00:00:00'] (01:0e:cf:00:00:01 기대)`.
(scapy `ProfinetIO.guess_payload_class` 는 0xFEFC 를 DCP 로 해석하지 않아 FrameID 와 Ethernet 목적지만 본다.)

**기대값과 출처:**
- 독립 구현 p-net `src/common/pf_dcp.c:108-112` "This is the standard DCP HELLO broadcast address (MAC)" `dcp_mc_addr_hello = 01:0e:cf:00:00:01`,
  `:1283-1287` `pf_dcp_hello_req` 가 이 주소로 보냄, `:1197-1205` `pf_dcp_hello_ind` 는 목적지가 이 주소가 아니면 "Wrong dest eth address - discard".

**수정 범위:** `stacks/profinet/` (+ `tests/`, `tests/golden/` 의 `dcp_hello*.pcap`). 입문서 D3 의 [사양 확인 필요] 정리는 큐 68 (문서) 비고로.

**완료 조건:** `test_dcp_hello_destination_is_hello_multicast` 통과 (`A20261101-5` 표시 삭제). CTT `dcp_set_ip` Hello 검사 계속 PASS.

## 확인 필요 (큐에 넣지 않음)

1. **Identify 복합 필터 (NameOfStation + MAC / IPParameter / DeviceOptions) 에 응답하지 않는다.** `pn_dcp.c:440-483` `ident_filters_match` 는
   Option 1 블록·DeviceOptions 블록을 만나면 `return 0`. 재현: `explore.py ident` → `name+ip -> 0`, `name+mac -> 0`, `name+opts -> 0`
   (`name+vendor`·`name+devid` 는 1). p-net `pf_dcp.c:1683-1720` (MAC·IPParameter), `:1808-1820` (DeviceOptions) 은 이름 필터 뒤의 이 블록들을 값 비교로 맞춘다.
   재현과 p-net 근거는 있으나, 실제 컨트롤러·툴이 이 조합을 보내는지 확인하지 못했고 이번 라운드 한도(5)를 넘어 보류. 다음 DCP 라운드 후보.
   같은 함수에서 IdentifyAll(FF/FF) 이 첫 블록이 아니어도 통과한다 (`all-not-first -> 1`; p-net `:1658-1682` 는 첫 블록일 때만, 아니면 무응답).
2. **SNMP: community·version·GetNext·비 SNMP 페이로드.** `explore.py snmp` — community `wrong` 요청에도 `public` 으로 응답, v2c(version 1)
   요청에 v1 으로 응답, GetNext(1.3.6.1.2.1.1) 에 sysName.0 그대로, `deadbeef` 4바이트에도 40여 바이트 GetResponse (반사 증폭). 모두
   `pn_snmp.c:187-240` 이 요청을 읽지 않는 같은 원인이라 T12-19 (큐 39) 로 묶이는 것이 맞다. T12-19 이슈 완료 조건에 "community 불일치·
   SNMP 아닌 데이터는 무응답, version 에코, GetNext" 를 넣자고 제안 (새 큐 항목 아님). MIB-II system/interfaces·LLDP-MIB 는 p-net
   `pf_snmp.h:38-98` 이 CC-B 장치가 내놓는 변수 목록을 정리해 두었으나, 제품 범위(CC-B 의 SNMP 요구) 결정이 먼저다.
3. **LLDP 수신이 없다** (`pn_stack.c:177-179` 이 0x88CC 를 버림). 그래서 AliasName Identify 필터(2/6, p-net `pf_dcp.c:1903-1925`
   `pf_lldp_is_alias_matching`)·LLDP-MIB 원격 테이블·이웃 기반 이름 지정이 불가능하다. 입문서 11.4 표에 "LLDP 수신 없음" 으로 이미 적힌 기능
   부재라 결함으로 세지 않았다. 제품 범위 결정 필요.
4. **이름·IP 변경 뒤 LLDP 를 바로 다시 보내지 않는다** (다음 5 s 주기까지 이전 Chassis ID·Management Address, TTL 20 s). p-net 이 변경 즉시
   송신하는지 소스에서 확인하지 못함.
5. **Hello 송신 시점과 내용.** 스택은 DCP Set 으로 IP 가 바뀔 때마다 Hello 를 보내고(`pn_dcp.c:701-704`), 내용은 Identify 블록 7개이며
   DeviceInitiative(6/1) 블록이 없다. p-net 은 기동 시 `send_hello`(DeviceInitiative=1) 설정일 때만 이름·IP 가 있으면 Hello 를 보내고
   (`pf_cmina.c:183`, `:470-555`), 내용은 NameOfStation·IPParameter·DeviceID·OEM ID·DeviceInitiative (`pf_dcp.c:1305-1420`).
   Wireshark `packet-pn-dcp.c:399-400` 의 DeviceInitiative 값 표도 "after power on" 이다. 사양 원문으로 Set 뒤 Hello 가 허용되는지 확인 필요.
   CTT `dcp_set_ip` 가 Set 뒤 Hello 를 기대하고 있다 (`tools/ctt/proto/profinet/pn_plugin.c:778-781`).
6. **ResponseDelayFactor > 6400.** p-net `pf_dcp.c:1450-1466` `pf_dcp_calculate_response_delay` 는 허용 범위 1~6400 밖이면 지연 0, 스택(`pn_dcp.c:546-555`)은 그대로 MAC % factor
   × 10 ms (최대 655 s). 오라클 DUT MAC 하위 16비트가 1 이라 차이가 10 ms 로만 보여 판정 가치가 낮다.

## 선별 결과

| ID | 요약 | 우선순위 근거 | 오라클 | 수정 범위 |
|---|---|---|---|---|
| A20261101-1 | DCP Set IP suite 유효성 없음 | 잘못된 주소가 성공으로 들어가 장치 도달 불가 (T12-20 이후 OS 에 적용) | ×6 | `stacks/profinet/`, `tests/` |
| A20261101-2 | 이름 없을 때 LLDP Chassis ID 빈 문자열 | 공장 상태 장치의 LLDPDU 를 Wireshark·scapy 가 버림 → 토폴로지에서 사라짐 | ×1 | `stacks/profinet/`, `tests/` |
| A20261101-3 | 이름 지우기·AR 중 IP 지우기 거부 | 툴의 이름/IP 초기화 실패, CMINA Case 27/28/30 불일치 (T12-16 옆) | ×2 | `stacks/profinet/`, `tests/` |
| A20261101-4 | DeviceOptions 2쌍만 | 툴의 기능 판단(Signal·초기화) 오류 | ×1 | `stacks/profinet/`, `tests/`, `tests/golden/` |
| A20261101-5 | Hello 목적지 MAC | 입문서 D3 [사양 확인 필요] 를 p-net 으로 확정. FSU 없으면 영향 작음 | ×1 | `stacks/profinet/`, `tests/`, `tests/golden/` |

오라클 실행 (`--runxfail` 없이): `11 xfailed`. `--runxfail`: `11 failed` — 각 실패 메시지가 위 결함과 일치.

## 재현 명령

오라클 DUT 를 빌드한 디렉토리를 `ORACLE_BUILD_DIR` 로 준다 (CI `oracle` job 과 같은 타깃).

```
ORACLE_BUILD_DIR=build python -m pytest -q --runxfail tests/oracle/test_pn_oracle.py   -k "invalid_ip_suite or chassis_id_without or empty_name_of or ip_reset_during or device_options_lists or hello_destination"
```

본문의 `explore.py` 출력은 감사 중 쓴 스크래치 하네스 (저장소에 넣지 않음) 의 것이다. 판정은 위 오라클 테스트가 한다.
