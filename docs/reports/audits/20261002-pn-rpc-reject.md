# 감사 2026-10-02 — PROFINET RPC Connect 거부 PNIOStatus

- 영역: PROFINET RPC·레코드 (11단계 제안 선별)
- 출처: PR #74 (T12-1) 본문 "발견한 다른 문제" — 구현 에이전트 제안
  (`reply_pnio_err` 의 상태 값이 여전히 `81 00 00 00`)
- 기준 커밋: `44c411a` (main, PR #74 병합 직후)
- 큐 추가: 1개 (A20261002-1 → 큐 59)

## A20261002-1. 다른 컨트롤러의 Connect 거부 PNIOStatus 가 `ErrorCode=0x00`

**문제:** AR 이 수립된 동안 다른 컨트롤러(다른 IP, 또는 다른 CMInitiatorObjectUUID)가 Connect 를 보내면
스택은 응답을 보내기는 하지만 PNIOStatus 바이트가 `81 00 00 00` 이다. DCE/RPC NDR 의 정수는 헤더의 drep 바이트
순서를 따르고 PNIOStatus 도 32비트 정수로 읽으므로, LE drep 에서는 정수 `0x00000081`
→ ErrorCode `0x00`("OK"), ErrorDecode `0x00`, ErrorCode1 `0x00`, ErrorCode2 `0x81` 로 읽힌다.
컨트롤러는 거부 원인(AR 자원 없음)을 알 수 없고, ErrorCode 만 보는 구현은 "오류 없음 + 블록 없음" 이라는
모순된 응답을 받는다. ArgsLength=0 · 블록 없음은 맞다 (T12-1 에서 고쳐짐).

**근거 (파일:줄, 기준 커밋 `44c411a`):**
- `stacks/profinet/src/pn_rpc.c:482-491` `reply_pnio_err` — `pn_wr_be32(status, 0x81u << 24)` 로 바이트
  `81 00 00 00` 을 고정으로 쓴다. 원인 코드를 받을 인자가 없다.
- `stacks/profinet/src/pn_rpc.c:547-549` — `s->ar.established && !ar_same_controller(...)` 이면 위 함수로 거부.
- 같은 함수를 타는 다른 경로: `:533-535` (자체 HMAC 보안 검증 실패), `:538-540` (블록 파싱 실패 — 현재
  `parse_ar_iocr` 가 항상 0 을 돌려줘서 도달하지 않는다. 큐 16 T5 (PN) 의 짧은 주기 거부가 이 자리에 들어올 예정).
- 현재 값을 못박는 저장소 테스트: `tests/test_pn_rpc.c:630-655` (`test_connect_error_ndr_pniostatus`,
  `expect_u32(pn_rd_be32(stub), 0x81u << 24, ...)`), `tests/fuzz/fuzz_pn_rpc.c:130-140`
  (`last_connect_rejected` 가 `81 00 00 00` 으로 거부를 판별).

**재현 (수정 전, `pn_oracle_pipe` + scapy 2.7.0):** 첫 Connect(`connect_pdu()`) 로 AR 수립 후, ARUUID
`b0b1b2b3-…`, CMInitiatorObjectUUID `dea00000-6c97-11d1-8271-00640002abcd`, MAC `00:11:22:33:44:66`,
스테이션 `other-controller` 로 두 번째 Connect.

```
first connect status 0x0
RSP 0402200010000000 … ffffffff 1400 0000 0000 | 81000000 00000000 00000000 00000000 00000000
drep endian 1 (LE)
PNIOStatus bytes 81000000 -> drep int 0x81
scapy DceRpc4(rsp)[PNIOServiceResPDU].status = 129 (0x00000081), args_length = 0, blocks = []
```

오라클 `tests/oracle/test_pn_oracle.py::test_connect_second_controller_out_of_ar_resources` 를
`--runxfail --tb=line` 으로 돌린 결과:

```
test_pn_oracle.py:375: AssertionError: PNIOStatus 00000081
```

**기대값과 출처:** PNIOStatus = `0xDB814004` (drep 순서 정수. LE drep 에서 바이트 `04 40 81 DB`), ArgsLength 0,
블록 없음, 기존 AR 유지.

| 바이트 | 값 | 의미 | 출처 |
|---|---|---|---|
| ErrorCode | `0xDB` | IODConnectRes | Wireshark `packet-pn.c` `pn_io_error_code` (`{ 0xDB, "IODConnectRsp" }`), p-net `PNET_ERROR_CODE_CONNECT 0xDB` |
| ErrorDecode | `0x81` | PNIO | Wireshark `pn_io_error_decode` (`{ 0x81, "PNIO" }`), p-net `PNET_ERROR_DECODE_PNIO 0x81` |
| ErrorCode1 | `0x40` | CMRPC | Wireshark `pn_io_error_code1_pnio` (`{ 0x40 /* 64*/, "CMRPC" }`), p-net `PNET_ERROR_CODE_1_CMRPC 0x40` |
| ErrorCode2 | `0x04` | Out of AR resources | Wireshark `pn_io_error_code2_pnio_64` (`{ 4, "Out of AR Resources" }`), p-net `PNET_ERROR_CODE_2_CMRPC_NO_AR_RESOURCES 0x04` |

- 바이트 순서: Wireshark `dissect_PNIO_status` 는 `bytemask = (drep[0] & DREP_LITTLE_ENDIAN) ? 3 : 0` 으로
  ErrorCode 를 `offset + (0 ^ bytemask)` 에서 읽는다 (LE 에서 4번째 바이트). scapy `PNIOServiceResPDU.status` 는
  `EField(..., endianness_from=dce_rpc_endianness)`. p-net `pf_put_pnet_status` 는
  `0x01000000*error_code + 0x10000*error_decode + 0x100*code_1 + code_2` 를 `pf_put_uint32(is_big_endian, …)` 로 쓴다.
  세 구현이 같은 규칙이다.
- 상황 대응: p-net `pf_cmrpc_rm_connect_ind` 는 새 ARUUID 의 Connect 에서 AR 슬롯이 없으면
  (`pf_ar_allocate` 실패 또는 `arep == 0`) `CONNECT / PNIO / CMRPC / NO_AR_RESOURCES` 로 거부한다. 이 장치는
  AR 1개만 지원한다(GSDML 에 `NumberOfAR` 없음 → 기본 1). 같은 ARUUID 를 다시 쓰는 Connect 는 p-net 에서
  `CMDEV / STATE_CONFLICT` (`DB 81 3D 00`) 로 다른 경우이며, 이 항목의 오라클은 다른 ARUUID 를 쓴다.
- 저장소 입문서 `docs/protocols/profinet.md` 9.2 표("Connect: AR 자원 부족(이미 AR 있음) `DB 81 40 04`")와도
  일치한다 (입문서는 참고용, 판정 근거는 위 독립 구현).

출처 URL:
- Wireshark: https://gitlab.com/wireshark/wireshark/-/blob/master/plugins/epan/profinet/packet-pn.c
  (`pn_io_error_code`, `pn_io_error_decode`, ErrorCode1 표의 `0x40 CMRPC`, `pn_io_error_code2_pnio_64`, `dissect_PNIO_status`)
- p-net: https://github.com/rtlabs-com/p-net/blob/master/include/pnet_api.h (`PNET_ERROR_CODE_CONNECT`,
  `PNET_ERROR_DECODE_PNIO`, `PNET_ERROR_CODE_1_CMRPC`, `PNET_ERROR_CODE_2_CMRPC_NO_AR_RESOURCES`)
- p-net: https://github.com/rtlabs-com/p-net/blob/master/src/device/pf_cmrpc.c (`pf_cmrpc_rm_connect_ind` "Out of AR resources")
- p-net: https://github.com/rtlabs-com/p-net/blob/master/src/device/pf_block_writer.c (`pf_put_pnet_status`)
- scapy: https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio_rpc.py (`PNIOServiceResPDU`)

**수정 범위:** `stacks/profinet/`, `tests/`.
- `reply_pnio_err` 가 원인별 PNIOStatus(ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2)를 받아 **drep 순서 정수**로
  쓴다 (T12-14 의 BE drep 지원 전까지는 LE). AR 점유 거부는 `DB 81 40 04`.
- 큐 16 T5 (PN) 이 같은 함수에 `DB 81 02 0B` (2026-10-09 정정, 처음에는 `0E` 로 적었다) 를 넣을 예정이므로, 원인 코드를 인자로 받는 형태로 한 번에 정리하는 것이 좋다.
- `tests/test_pn_rpc.c` `test_connect_error_ndr_pniostatus` 의 기대값을 `0xDB814004` (LE 읽기)로 바꾸고,
  `tests/fuzz/fuzz_pn_rpc.c` `last_connect_rejected` 가 바이트 `81 00 00 00` 대신 ErrorCode(정수 최상위 바이트)가
  0 이 아닌지로 거부를 판별하게 바꾼다.
- 자체 HMAC 보안 검증 실패 경로(`:533-535`)의 코드는 이 항목에 포함하지 않는다 (아래 "확인 필요").

**완료 조건:**
- 오라클 `test_connect_second_controller_out_of_ar_resources` 가 통과하고 `@known_defect("A20261002-1", …)` 표시를 지운다
  (PNIOStatus `0xDB814004`, 블록 없음, 거부 뒤 기존 AR 의 RTC1 유지).
- `tests/test_pn_rpc.c`, `tests/fuzz/fuzz_pn_rpc.c` 가 새 값으로 통과하고, 다른 PN 오라클 결과(passed·xfailed 수)가 그대로다.
- 스크래치 검증: `reply_pnio_err` 에 상태 인자를 추가하고 AR 점유 경로만 `pn_wr_le32(status, 0xDB814004)` 로 바꾼
  최소 패치에서 이 테스트만 XPASS(strict) 가 되고 T5 (PN)·T12-18 등 다른 표시는 그대로 xfail 이었다.

## 확인 필요 (큐에 넣지 않음)

- **자체 HMAC 보안 검증 실패 (`pn_rpc.c:533-535`)**: 같은 `81 00 00 00` 으로 거부한다. 그러나 이 보안 블록은
  PI Security Class 1 이 아닌 자체 프로파일(큐 31 T12-9)이라 독립 구현에 대응하는 에러 코드가 없다.
  Wireshark 의 ErrorDecode `0x83` PNIOSEC 은 PI 보안용이다. T12-9 정리 뒤 코드를 정한다.
- **블록 파싱 실패 (`pn_rpc.c:538-540`)**: 현재 도달하지 않는다 (`parse_ar_iocr` 가 항상 0). 블록별
  `DB 81 01..07 nn` 은 해당 블록 검증이 생길 때 그 항목(T5 (PN), T12-4 등)에서 정한다.
- **같은 ARUUID 의 다른 컨트롤러 Connect**: p-net 은 `DB 81 3D 00` (CMDEV state conflict). 스택이 이를 따로
  구분해야 하는지는 IEC 61158-6-10 원문 확인 필요.
