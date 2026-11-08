# 감사 2026-11-08 — PROFINET RPC·레코드: Read Implicit, I&M Write 규칙, ControlCommand, AR UUID unknown

- 영역: PROFINET RPC·레코드 (`stacks/profinet/src/pn_rpc.c`, `pn_record.c`, `pn_stack.c` 의 I&M 저장 부분) — 12단계 감사
  (영역 순환: PROFINET DCP·LLDP·SNMP → **PROFINET RPC·레코드**)
- 출처: 12단계 감사 라운드. 지난 RPC 감사 뒤 병합된 T12-14 DCE/RPC 헤더(#161), T12-17 표준 Release 0x0114(#170),
  T12-18 미지원 레코드 index(#174), T12-20 DCP IP 적용·이름/IP/I&M NVM(#180), T12-22 IOCRReference 에코(#184) 사후 리뷰 +
  오라클 DUT `pn_oracle_pipe` (mock Ethernet) 를 scapy 2.7.0 (`contrib.pnio_rpc`, `layers.dcerpc`, `layers.msrpce.raw.ept`) 로 두드림
- 기준 커밋: `24e6de9` (main). DUT 빌드는 로컬 CI `oracle` 잡 (`pn_rpc.c`·`pn_record.c`·`pn_stack.c`·`pn_dcp.c`·`pn_oracle_pipe.c` 가
  `24e6de9` 와 바이트 단위로 같음 — `git show 24e6de9:<f> | cmp`)
- 대조 소스 (2026-11-08 내려받음): p-net `master` `19782d5` (`src/device/pf_cmrpc.c`, `pf_cmrdr.c`, `pf_cmwrr.c`, `pf_fspm.c`,
  `pf_cmrpc_epm.c`, `pf_block_reader.c`, `include/pnet_api.h`, `src/pf_types.h`), Wireshark `master` (`30f6bc36` 무렵,
  `plugins/epan/profinet/packet-dcerpc-pn-io.c`, `plugins/epan/profinet/packet-pn.c`, `epan/dissectors/packet-dcerpc.c`)
- 판단: opus 하위 에이전트 (코드 대조 + 오라클 재현 + p-net·Wireshark·scapy 대조). 재현·인용은 루틴이 다시 확인했다 (새 오라클 13개 strict xfail,
  `--runxfail` 13 failed, p-net `pf_cmrpc.c:3753`·`:2550-2567`·`pf_fspm.c:908-920`, Wireshark `:20497`). 하위 에이전트는 최소 패치 DUT 에서
  13개 통과·기존 PN 오라클 결과 그대로임도 확인했다 (아래 "재현 명령")
- 큐 추가: 4개 (A20261108-1 ~ -4 → 큐 110–113)

이미 알려진 것은 다시 올리지 않았다: A20261002-1 (다른 컨트롤러 Connect 거부 `DB 81 40 04`, 큐 59), A20261004-1 (I&M0 OrderID NUL, 큐 62),
A20261007-1 (태그 헤더, 큐 66), A20261025-6 (AlarmCR 범위, 큐 93), T12-20 후속 (어댑터 `nvm_dir`, 큐 109).
기존 오라클(`test_pn_oracle.py`: 48 passed, 27 xfailed — 이 라운드 테스트 추가 전)이 다루는 동작(Read I&M0·I&M1 왕복, 미지원 index `DE/DF 80 B0 00`, PrmEnd Done,
표준 Release, BE drep, 단편화 Connect, EPM lookup 디코드)은 발견으로 세지 않았다.

사후 리뷰 결과 요약: #161 단편 재조립·drep·object UUID 는 p-net 과 같은 규칙(번호 순서 엄격, 틀리면 버림)이라 결함 없음.
#170 Release 0x8114 응답은 맞으나 **AR 이 없을 때의 Release 가 성공으로 응답** (A20261108-4). #174 는 미지원 index 만 고쳐서
**같은 함수의 I&M0 Write·I&M 길이 규칙이 남음** (A20261108-2, 코드 주석이 "outside T12-18" 로 미룸). #180 NVM 은 pipe DUT 에 저장소가
없어 오라클로 볼 수 없고, 코드 대조에서 결함을 찾지 못함. #184 IOCRReference 에코는 기존 오라클로 통과.

## A20261108-1. Read Implicit (opnum 5) 에 응답하지 않는다 — AR 없이 I&M0 를 읽을 수 없다

**문제:** PNIO Device 인터페이스의 opnum 5 (Read Implicit) 를 모르는 opnum 으로 보고 `-ENOSYS` 로 버린다. Read Implicit 는 AR 을 맺지 않고
레코드(대표적으로 I&M0)를 읽는 서비스로, 엔지니어링 툴의 장치 탐색·식별과 컨트롤러의 Connect 전 식별에 쓰인다. 요청자는 응답이 없어
DCE/RPC 재전송 끝에 시간 초과한다. (opnum 2 Read 는 AR 이 없어도 받아 주지만, 표준 클라이언트는 AR 없는 읽기를 opnum 5 로 보낸다.)

**근거 (파일:줄, 기준 커밋 `24e6de9`):**
- `stacks/profinet/src/pn_rpc.c:1721` — `else if (op == OP_READ)` 만 Read 로 처리. `:1821-1822` 그 밖의 opnum → `return -ENOSYS` (무응답)
- `pn_rpc.c:21` `#define OP_READ 2` 외에 opnum 5 정의 없음. 입문서 `docs/protocols/profinet.md:1865` 도 "알 수 없는 opnum (5 ReadImplicit 포함) 무응답",
  `:2190` 표가 "EPM, ReadImplicit(opnum 5), RPC 단편화 — 없음" (같은 행의 EPM·단편화는 T12-14 로 구현됨)

**재현 (오라클, DUT `pn_oracle_pipe`):** Connect 없이 NIL ARUUID 의 IODReadReq(slot 0, subslot 1, index 0xAFF0) 를 opnum 5 와 2 로 보냄.

```
no AR, opnum5 ReadImplicit I&M0 NIL ARUUID    응답 없음 ERR=['-38']
no AR, opnum2 Read I&M0 NIL ARUUID            ptype=2 PNIOStatus=00000000 blocks=8009003c0100... (len 124)
AR, opnum5 ReadImplicit I&M0                  응답 없음 ERR=['-38']
```

`test_record_read_implicit_im0_without_ar` (`--runxfail`): `E AssertionError: Read Implicit (opnum 5) 응답 없음`.

**기대값과 출처:**
- Wireshark `plugins/epan/profinet/packet-dcerpc-pn-io.c:20497` — PNIO 인터페이스 표 `{ 5, "Read Implicit", dissect_IPNIO_rqst, dissect_IPNIO_Read_resp }`
  (응답 형식은 opnum 2 Read 와 같음: NDR PNIOStatus + IODReadResHeader 0x8009 + 레코드).
- 독립 구현 p-net `src/device/pf_cmrpc.c:3753-3766` `case PF_RPC_DEV_OPNUM_READ_IMPLICIT` → `pf_cmrpc_rm_read_ind`.
  `:2947-2958` NIL ARUUID 는 opnum 5 에서만 허용 (opnum 2 면 `DE 81 08 05`), `:2998-3004` implicit AR 이면 TargetARUUID 로 AR 을 찾아 보고,
  `:3007-3018` AR 이 꼭 필요한 index 가 아니면 `pf_cmrdr_rm_read_ind` 로 I&M0 등을 읽는다.

**수정 범위:** `stacks/profinet/` (+ `tests/`).
- `pn_rpc_handle`: opnum 5 를 Read 경로로 보낸다. ARUUID 는 NIL 이어도 되고 AR 소유자·ARUUID 검사(`:1734-1744`)를 하지 않는다 (AR 이 있어도 implicit).
  응답은 opnum 2 와 같은 NDR·IODReadResHeader, RPC 헤더 opnum 5 에코.
- 미지원 index 는 지금처럼 `DE 80 B0 00`. AR 전용 index(p-net `pf_index_is_ar_specific`)는 이 저장소에 없으므로 따로 다룰 필요 없음.
- 입문서 `docs/protocols/profinet.md` 9.4·11.4 표의 ReadImplicit 행 갱신 (문서만, 같은 PR 에서 해도 됨).

**완료 조건:** `test_record_read_implicit_im0_without_ar` 통과 (`A20261108-1` 표시 삭제). 기존 Read 오라클(`test_record_read_im0`,
`test_record_read_unsupported_index_error`) 계속 통과. 단위 테스트로 AR 이 있을 때도 NIL ARUUID opnum 5 가 응답하고 AR 을 건드리지 않음을 보인다.

## A20261108-2. I&M Write 규칙: I&M0 Write 를 성공으로 받고, I&M1–4 Write 길이를 보지 않는다

**문제:**
1. I&M0 (index 0xAFF0) 는 읽기 전용인데 Write 를 PNIOStatus 0 으로 받는다 (저장하지 않으면서 성공을 알림). 엔지니어링 툴은 쓰기가 됐다고 본다.
2. I&M1–4 Write 는 길이가 무엇이든 성공이다. 짧으면 나머지를 공백(I&M4 는 0)으로 채우고, 길면 잘라서 저장한다. BlockHeader 뒤 payload 가
   I&M1 10바이트·59바이트, I&M2 15바이트 모두 `PNIOStatus 0`. 잘못 만든 레코드가 조용히 반쯤 적용되고, T12-20 이후로는 NVM 에도 그대로 남는다.

**근거 (파일:줄, 기준 커밋 `24e6de9`):**
- `stacks/profinet/src/pn_record.c:167-172` — "I&M0 is read-only: accept the write and do not store it. Access-denied DF 80 B6 00 is outside T12-18" → `return 0`
- `pn_record.c:17-28` `im_payload` — 헤더가 있으면 떼고 `*out_n = len < want ? len : want` (짧은 것도 긴 것도 통과),
  `:116-165` I&M1–4 분기가 길이 검사 없이 공백/0 채움 후 `pn_nvm_after_im` 과 `return 0`
- `pn_rpc.c:1795-1806` — `pn_record_write` 가 `-ENOENT` 일 때만 에러 PNIOStatus (`DF 80 B0 00`)

**재현 (오라클, DUT `pn_oracle_pipe`):** Connect 뒤 Write (slot 0, subslot 1).

```
write I&M0 (block, len 60)                    ptype=2 PNIOStatus=00000000 blocks=8008003c...aff00000003c... (len 64)
write I&M1 header+10 bytes                    ptype=2 PNIOStatus=00000000 blocks=8008003c...aff100000010... (len 64)
write I&M1 header+54+5 extra                  ptype=2 PNIOStatus=00000000 blocks=8008003c...aff100000041... (len 64)
write I&M2 15 bytes no header                 ptype=2 PNIOStatus=00000000 ...
write I&M1 short 'AB' no header               ptype=2 PNIOStatus=00000000  → read I&M1 = 0021 0038 0100 4142 2020…
```

`--runxfail`: `test_record_write_im0_access_denied` → `E AssertionError: PNIOStatus 00000000` (`assert 0 == 3749754368` = `0xDF80B600`),
`test_record_write_im_wrong_length_error[I&M1 payload 10|I&M1 payload 59|I&M2 payload 15]` → `PNIOStatus 00000000` (`0xDF80B100` 기대).

**기대값과 출처:**
- 독립 구현 p-net `src/device/pf_fspm.c:910-920` `case PF_IDX_SUB_IM_0: /* read-only */` → `PNET_ERROR_CODE_WRITE` / `PNIORW` / `ACC_ACCESS_DENIED` = `DF 80 B6 00`.
- p-net `pf_cmrpc.c:3320-3346` I&M 등 index > 0x7FFF 는 BlockHeader 를 떼고 `record_data_length - 6` 을 넘김. `pf_fspm.c:938-962` I&M1 은
  `pf_get_im_1` 이 32+22 바이트를 읽은 위치가 길이와 같아야 하고, `:983` I&M2 `== 16`, `:1032` I&M3 `== 54`, `:1080` I&M4 `== 54`. 아니면
  `ACC_WRITE_LENGTH_ERROR` = `DF 80 B1 00` (`:955-962`, `:1004-1011`, `:1053-1060`, `:1094-1101`).
- Wireshark `packet-dcerpc-pn-io.c:7487-7509` `dissect_IandM1_block` (IM_Tag_Function 32 + IM_Tag_Location 22), `:7514-7530` I&M2 IM_Date 16;
  `:19647-19651` Write 의 0xAFF1–0xAFF3 레코드는 `dissect_block` (BlockHeader 필수). `packet-pn.c:178` `0xb1 "access: write length error"`,
  `:183` `0xb6 "access: access denied"`. 입문서 `docs/protocols/profinet.md:1851-1852` 도 같은 값.

**수정 범위:** `stacks/profinet/` + `tests/` (+ `tests/scenarios/profinet/` CTT 시나리오 2개).
- `pn_record_write`: I&M0 → 접근 거부(새 반환값, 예: `-EACCES`) → `pn_rpc.c` 에서 `DF 80 B6 00`. I&M1–4 → BlockHeader(0x0021–0x0024) 뒤
  payload 가 정확히 54 / 16 / 54 / 54 가 아니면 길이 오류 → `DF 80 B1 00`, 저장·NVM 갱신 없음. 에러 시 IODWriteResHeader 의 PNIOStatus 도 같은 값
  (`DF 80 B0 00` 경로와 같은 방식).
- 헤더 없는 정확한 길이 payload 를 계속 받을지는 구현 선택 (내부 API 단위 테스트 `tests/test_pn_dcp.c:838-854` 등이 이 형식을 쓴다).
  오라클은 헤더가 있는 레코드만 판정한다.
- 같이 바뀌는 고정값: CTT `tests/scenarios/profinet/rpc_write_prmend_appready.yaml:18-31`, `rpc_ar_lifetime_cm.yaml:22-28` 이 I&M1 에
  헤더 없는 6바이트 `line-A` 를 쓰고 성공·되읽기를 기대한다 → 60바이트 I&M1 블록(`data_hex`)으로 바꾼다. `tests/test_pn_t12_18.c:287-290`
  (I&M1 8바이트 성공 기대), `tests/test_pn_rpc.c:296-312` (I&M1 6바이트 Write 성공 기대) 도 정확한 길이로 바꾼다.

**완료 조건:** `test_record_write_im0_access_denied`, `test_record_write_im_wrong_length_error` 3개 통과 (`A20261108-2` 표시 삭제).
기존 `test_record_write_im1_roundtrip` (헤더 + 54) 계속 통과. 단위 테스트로 I&M3·I&M4 의 53/55 바이트 거부, 거부 시 기존 값·NVM 유지.

## A20261108-3. IODControlReq 의 ControlCommand 를 보지 않고 무엇이든 Done 으로 응답한다

**문제:** Control(opnum 4)의 IODControlReq(0x0110) 에서 ControlCommand 가 PrmEnd(0x0001) 가 아니어도 `PNIOStatus 0` + IODControlRes Done 을
보낸다. PrmEnd|Done(0x0009)·ApplicationReady(0x0002)·Release(0x0004)·0x0000 모두 "완료" 로 응답하지만 PrmEnd 처리(ApplicationReady 큐잉)는
하지 않는다 (0x0002 는 오히려 `app_ready=1` 을 세운다). 컨트롤러는 PrmEnd 가 끝났다고 보고 오지 않을 ApplicationReady 를 기다린다.
PrmEnd 요청 블록에 PrmEnd 이외의 명령은 사양 위반이고, 표준 장치는 ControlCommand 오류로 거부한다.

**근거 (파일:줄, 기준 커밋 `24e6de9`):**
- `stacks/profinet/src/pn_rpc.c:206-219` `parse_ctrl_req` — 명령 값을 읽기만 함
- `pn_rpc.c:1702-1720` — ARUUID 만 보고 무조건 Done 블록(`:1706`)과 `ndr_res(…, NULL, …)` (PNIOStatus 0). `:1713-1719` PrmEnd·AppReady 만 상태를 바꾸고
  그 밖의 값은 아무것도 하지 않음. `:1689`·`:1695-1697` 블록이 없으면 PrmEnd 로 간주
- (인접) `:210` 0x0110 이 아닌 블록(PrmBegin 0x0118 등)은 ARUUID 를 못 읽어 `:1698-1700` `-EPERM` 무응답 — "확인 필요" 3

**재현 (오라클, DUT `pn_oracle_pipe`):** Connect 뒤 `IODControlReq(block_type=0x0110, ARUUID, SessionKey=1, ControlCommand=…)`.

```
Control 0x0110 cmd PrmEnd|Done 0x0009         ptype=2 PNIOStatus=00000000 blocks=8110001c0100…0001000000080000 (len 32)
    ApplicationReady queued: False
Control 0x0110 cmd AppReady 0x0002            ptype=2 PNIOStatus=00000000 blocks=8110001c0100…0001000000080000 (len 32)
Control 0x0110 cmd Release 0x0004             ptype=2 PNIOStatus=00000000 blocks=8110001c0100…0001000000080000 (len 32)
Control 0x0110 cmd 0x0000                     ptype=2 PNIOStatus=00000000 blocks=8110001c0100…0001000000080000 (len 32)
```

`test_control_rejects_wrong_control_command[PrmEnd+Done 0x0009|ApplicationReady 0x0002|Release 0x0004|none 0x0000]` (`--runxfail`):
`E AssertionError: …: PNIOStatus 00000000, 블록 ['0x8110']` (`0xDD811408` 기대).

**기대값과 출처:**
- 독립 구현 p-net `src/device/pf_cmrpc.c:2552-2567` `pf_cmrpc_rm_dcontrol_interpret_req` — `control_command != BIT(PRM_END)` 이면
  "DControl ControlCommand has wrong bit pattern" → `PNET_ERROR_CODE_CONTROL` / `PNIO` / `DCTRL_FAULTY_CONNECT` (0x14) /
  `DCTRL_FAULTY_CONNECT_CONTROLCOMMAND` (0x08) = `DD 81 14 08` (`include/pnet_api.h:188`, `:361`). `:2645-2657` 에러면 IODControlRes 를 싣지 않음.
- Wireshark `plugins/epan/profinet/packet-pn.c:316` ErrorCode1 0x14 "IODControl: Faulty ControlBlockConnect", `:764-775`
  `pn_io_error_code2_pnio_20` "CheckingRules for ControlBlockConnect" `{ 8, "Error in Parameter ControlCommand" }`.

**수정 범위:** `stacks/profinet/` (+ `tests/`).
- Control 0x0110 에서 ControlCommand 가 정확히 PrmEnd 가 아니면 `DD 81 14 08`, 블록 없음, AR 상태·ApplicationReady 변경 없음.
- 블록이 없을 때 PrmEnd 로 간주(`:1689`, `:1695-1697`)하지 않는다 (p-net 은 ArgsLength 불일치 `DD 81 40 00`). 정확한 코드는 "확인 필요" 3.

**완료 조건:** `test_control_rejects_wrong_control_command` 4개 통과 (`A20261108-3` 표시 삭제). `test_prm_end_response_done`,
`test_application_ready_request` 계속 통과. CTT `rpc_write_prmend_appready`·`rpc_ar_lifetime_cm` (parameter_end) 계속 PASS.

## A20261108-4. 모르는 AR 에 대한 Release·Control·Write 에 "AR UUID unknown" 대신 무응답 또는 성공으로 응답한다

**문제:**
1. AR 이 없을 때 Release(opnum 1) 를 `PNIOStatus 0` 성공으로 응답하고, 블록 자리에 블록이 아닌 4바이트 `00000000` (ArgsLength 4) 을 싣는다.
   컨트롤러는 없는 AR 이 해제됐다고 판단하고, 디코더는 길이 0 블록을 읽는다.
2. AR 이 있는 동안 다른 ARUUID 의 Release·Control·Write 는 같은 송신자(IP 검사 통과)여도 응답 없이 버린다 (`-EPERM`). 요청자는 DCE/RPC 재전송
   끝에 시간 초과하고, "장치 없음" 과 "AR 이 다름(예: 장치 재시작 뒤 옛 AR)" 을 구분하지 못한다. 거부 자체(AR 유지)는 맞고, 응답만 빠졌다.

**근거 (파일:줄, 기준 커밋 `24e6de9`):**
- `stacks/profinet/src/pn_rpc.c:1672-1676` — `had_ar == 0` 이면 `uint8_t z[4] = {0}; ndr_res(stub_out, NULL, z, 4, be)` (PNIOStatus 0)
- `pn_rpc.c:1651-1654` Release, `:1698-1701` Control, `:1787-1790` Write — ARUUID 불일치 시 `return -EPERM` (무응답)
- A20261002-1 (큐 59) 은 Connect 거부를 `DB 81 40 04` 로 고치는 항목이다. 이 발견은 그 옆의 같은 종류(CMRPC ErrorCode2 0x05)다.

**재현 (오라클, DUT `pn_oracle_pipe`):**

```
no AR, Release                                ptype=2 PNIOStatus=00000000 blocks=00000000 (len 4)
AR, Release wrong ARUUID                      응답 없음 ERR=['-1']
AR, Control wrong ARUUID                      응답 없음 ERR=['-1']
AR, Write wrong ARUUID                        응답 없음 ERR=['-1']
```

`--runxfail`: `test_release_without_ar_ar_uuid_unknown` → `E AssertionError: PNIOStatus 00000000, 블록 00000000` (`0xDC814005` 기대),
`test_rpc_unknown_ar_uuid_error_response[Release|Control|Write]` → `…: 모르는 ARUUID 에 응답 없음`.

**기대값과 출처:**
- 독립 구현 p-net `src/device/pf_cmrpc.c:2416-2448` `pf_cmrpc_rm_release_ind` — AR 을 못 찾으면 `PNET_ERROR_CODE_RELEASE` / `PNIO` / `CMRPC` /
  `CMRPC_AR_UUID_UNKNOWN` = `DC 81 40 05` 를 응답에 넣는다 (`:2451-2456`). `:2737-2760` DControl → `DD 81 40 05`. `:3270-3280`
  `pf_cmrpc_perform_one_write` → `DF 81 40 05`. 상수 `include/pnet_api.h:123-126`, `:202`, `:244`.
- Wireshark `plugins/epan/profinet/packet-pn.c:917-924` `pn_io_error_code2_pnio_64` (CMRPC) `{ 5, "AR UUID unknown" }`.

**수정 범위:** `stacks/profinet/` (+ `tests/`).
- Release: AR 이 없거나 ARUUID 가 다르면 `DC 81 40 05`, 블록 없음 (`reply_pnio_err` 와 같은 형식). Control → `DD 81 40 05`, Write → `DF 81 40 05`.
  거부 시 기존 AR 유지는 지금처럼.
- 송신 IP 불일치(`ar_owner_ok`) 경로의 무응답과 AR 이 없을 때 Control·Write 무응답은 그대로 둔다 — 보안 결정(`docs/reports/security_fixes_20260928.md`
  G4)과 CTT PN-B-NEG-008 (`tests/scenarios/profinet/rpc_cm_without_ar.yaml` `rpc_response: false`) 이 고정하고 있어 "확인 필요" 4 로 남긴다.
- 단위 테스트 `tests/test_pn_rpc.c:272-281` ("control wrong uuid" `-EPERM` 기대)을 에러 응답 기대로 바꾼다.

**완료 조건:** `test_release_without_ar_ar_uuid_unknown`, `test_rpc_unknown_ar_uuid_error_response` 3개 통과 (`A20261108-4` 표시 삭제).
`test_release_standard_block`, CTT `rpc_malformed` (AR 없는 Release `rpc_response: true`)·`rpc_cm_without_ar` 계속 PASS. 거부 뒤 RTC1 유지.

## 확인 필요 (큐에 넣지 않음)

1. **AR 없이 opnum 2 Read 를 받는다 (NIL ARUUID 포함).** p-net 은 NIL ARUUID + opnum 2 를 `DE 81 08 05`, AR 없는 opnum 2 를 `DE 81 40 02`
   로 거부한다 (`pf_cmrpc.c:2947-2995`). 그러나 저장소 보안 결정 G4 가 "Read without an AR remains allowed (device records)" 로 정했다.
   A20261108-1 (Read Implicit) 이 들어오면 opnum 2 의 관용을 거둘지 담당자 결정이 필요하다.
2. **없는 slot/subslot 의 I&M Read·Write 성공.** slot 99 / subslot 0x7777 의 I&M0 Read, slot 99 subslot 9 의 I&M1 Write 가 모두 PNIOStatus 0
   (`pn_record.c:51-52`, `:105-106` 이 slot/subslot 을 버림). 입문서 9.2 와 Wireshark `packet-pn.c` (0xB2 "invalid slot/subslot") 는 코드를 주지만,
   p-net 도 I&M 은 slot/subslot 을 보지 않는다 (`pf_cmrdr.c:96-240`). 독립 구현의 거부 동작이 없어 판정 보류.
3. **Control 의 다른 블록 타입·빈 Control·SessionKey.** PrmBegin(0x0118)·0x0112·블록 없음은 ARUUID 를 못 읽어 무응답(`-EPERM`). p-net 은
   `DD 81 40 01` (unknown blocks, `pf_cmrpc.c:2500-2513`) 또는 ArgsLength 오류. SessionKey 99 인 PrmEnd·Release 도 받는다(Release 는 AR 해제).
   Wireshark `packet-pn.c:771` 은 "Error in Parameter SessionKey" (0x14/0x06) 를 두지만 p-net 은 SessionKey 를 보지 않는다. 코드 확정 필요.
4. **송신 IP 불일치·AR 없는 Control/Write, AR 중 다른 ARUUID 의 Read 무응답.** p-net 은 각각 에러 PNIOStatus 로 응답(Read 는 `DE 81 40 02`).
   보안 결정 G4 "fail-closed" 와 CTT PN-B-NEG-008 이 무응답을 고정한다. 응답만 보내도 fail-closed 인지 담당자 결정 필요.
5. **Read RecordDataLength 가 레코드보다 작을 때** (I&M0, RecordDataLength 10·0) 60바이트 전체를 돌려준다. p-net 도 자르지 않는다. 사양 확인 필요.
6. **Write RecordDataLength 가 실제 데이터보다 클 때** (2026-10-04 보고서 확인 필요 1 재확인) — RecordDataLength 60 + 데이터 10바이트가 성공
   (응답 RecordDataLength 10). p-net 은 `DF 80 B4 04` (`pf_cmrpc.c:3292-3360`, ErrorCode2 는 p-net 내부 위치 번호). 사양 코드 확인 필요.
7. **DCE/RPC ping(ptype 1) 무응답** (`-EINVAL`). p-net 은 nocall(ptype 5) 로 답한다 (`pf_cmrpc.c:4593-4630`). 응답이 늘 즉시 나가므로 영향 낮음.

## 선별 결과

| 후보 | 판정 | 이유 |
|---|---|---|
| Read Implicit opnum 5 무응답 | **A20261108-1** | 재현 + p-net·Wireshark. 장치 식별(I&M0) 경로라 우선순위 가장 높음 |
| I&M0 Write 성공 / I&M1–4 길이 미검사 | **A20261108-2** | 재현 + p-net·Wireshark. #174 옆 같은 함수. CTT 시나리오 2개 같이 고침 |
| ControlCommand 미검사 | **A20261108-3** | 재현 + p-net·Wireshark |
| AR 없는 Release 성공·모르는 ARUUID 무응답 | **A20261108-4** | 재현 + p-net·Wireshark. 보안 결정과 겹치는 IP·no-AR Control/Write 는 확인 필요 4 로 분리 |
| EPM lookup 이 inquiry_type·Ifid 필터와 max_ents 0 을 무시 (항상 PNIO 1개, status 0) | 제외 (우선순위) | 재현됨 (`inquiry_type=1/3` 다른 Ifid, `max_ents=0` → `status=0x0 num_ents=1`). p-net `pf_cmrpc_epm.c:350-372` 는 0 이 아닌 inquiry_type·max_ents 0 에 `0x16c9a0d6` not registered. 영향 낮아 이번 라운드 큐에서 뺌. 다음 RPC 라운드 후보 |
| 단편 순서 어긋남·중복 단편 시 재조립 폐기 | 결함 아님 | p-net 도 번호가 다르면 에러 (`pf_cmrpc.c:4476-4490`) |
| I&M NVM (T12-20) | 판정 불가 | pipe DUT 에 `nvm_dir` 없음. 코드 대조에서 결함 없음 (큐 109 가 어댑터 연결 담당) |


## 재현 명령

```
# 기준 DUT: main 24e6de9, BUILD_DAEMON=ON 빌드 (로컬 CI oracle 잡과 같은 설정). 저장소 루트에서
ORACLE_BUILD_DIR=build python -m pytest -q tests/oracle/test_pn_oracle.py \
  -k "read_implicit or write_im0_access or write_im_wrong_length or wrong_control_command or ar_uuid_unknown or unknown_ar_uuid"
# 기대: 13 xfailed (A20261108-1 ×1, -2 ×4, -3 ×4, -4 ×4)

ORACLE_BUILD_DIR=build python -m pytest -q --runxfail tests/oracle/test_pn_oracle.py \
  -k "read_implicit or write_im0_access or write_im_wrong_length or wrong_control_command or ar_uuid_unknown or unknown_ar_uuid"
# 기대: 13 failed — 각 실패 메시지는 위 "재현" 절과 같다
```

새 테스트: `test_record_read_implicit_im0_without_ar` (A20261108-1), `test_record_write_im0_access_denied`,
`test_record_write_im_wrong_length_error[I&M1 payload 10|I&M1 payload 59|I&M2 payload 15]` (A20261108-2),
`test_control_rejects_wrong_control_command[PrmEnd+Done 0x0009|ApplicationReady 0x0002|Release 0x0004|none 0x0000]` (A20261108-3),
`test_release_without_ar_ar_uuid_unknown`, `test_rpc_unknown_ar_uuid_error_response[Release|Control|Write]` (A20261108-4).
이 테스트를 더한 뒤 `test_pn_oracle.py` 전체: 48 passed, 40 xfailed (XPASS 없음).
