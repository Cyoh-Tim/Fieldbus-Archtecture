# 2026-11-12 — EIP T11-13 PR 의 "발견한 다른 문제" 선별: HMAC 재료 절단, LLDP subtype, TLS 수신 한도

- 영역: EtherNet/IP 스택 (11단계 제안 선별)
- 출처: #201 (T11-13) "발견한 다른 문제" 1–3
- 기준 커밋: `0462150` (main, #200 병합 직후). 1 은 main + #201 병합 트리에서도 같다
- 판단: 검증 담당 (루틴 직접, 스크래치 C 하네스·scapy 재현 + OpENer·IEEE 802.1AB 대조)
- 큐 추가: 3개 (A20261112-1 ~ -3 → 큐 121–123). A20261112-1 은 v0.2.0 게이트 (기준 b)

## A20261112-1. HMAC 무결성 검사가 CIP 본문 앞 568 바이트만 덮는다 (꼬리 변조 수락)

**문제:** 자체 보안 프로파일 (`security_class >= 1`) 의 MAC 은 `HMAC-SHA256(PSK, session || CIP 요청)` 이다. 그런데 MAC 재료 버퍼가
`4 + EIP_EXPLICIT_DATA_MAX (504) + 64` = 572 바이트로 고정이고, `mac_input` 은 더 긴 요청을 이 길이로 **조용히 자른다**.
검증과 생성이 같은 방식으로 잘라서, CIP 본문 568 바이트 뒤는 무결성 보호를 받지 않는다. 568 바이트를 넘는 Set
(큰 Assembly attr 3, 큰 Forward Open 경로 등) 은 한 번 관찰한 MAC 으로 꼬리를 바꿔 다시 보내도 수락된다.
반대로 본문 전체로 MAC 을 계산하는 정상 상대(자체 프로파일을 같은 문서대로 구현한 originator)는 `0x0F` 로 거부된다.

**근거:** `stacks/ethernetip/src/eip_sec.c:45-61` `mac_input` (`if (n > cap) n = cap;`), `:85`·`:106`
`uint8_t material[4 + EIP_EXPLICIT_DATA_MAX + 64];` (검사·생성 둘 다). `eip_types.h:32` `EIP_EXPLICIT_DATA_MAX 504`.
**재현 (스크래치 하네스, mock 스택, `security_class 1`, Assembly 101 출력 1000 바이트, Set_Attribute_Single attr 3 + 1000 바이트):**

```
A full-body HMAC           -> CIP status 0x0f   (본문 전체 MAC 은 거부)
B truncated(572) HMAC      -> CIP status 0x00   (앞 572 바이트 재료 MAC 은 수락)
C tail changed, same B MAC -> CIP status 0x00   (데이터 마지막 100 바이트를 0xEE 로 바꿔도 같은 MAC 으로 수락)
```

main `0462150` 과 main + #201 에서 같은 결과.
**기대값과 출처:** MAC 은 메시지 전체를 덮어야 한다 — 저장소 프로파일 정의 (`docs/protocols/ethernetip.md` 7.3·9.5,
`eip_sec.h` "HMAC-SHA256 PSK on mutating UCMM") 자체가 "session || CIP request" 전체다. 자를 수밖에 없으면 거부해야 한다
(fail-closed). OpenSSL `HMAC_Update` 는 길이 제한이 없어 버퍼 없이 스트리밍으로 계산할 수 있다.
**수정 범위:** `stacks/ethernetip/`, `tests/`. 재료를 고정 버퍼에 복사하지 말고 session 4바이트와 CIP 본문을 순서대로
HMAC 에 넣는다 (또는 길이에 맞는 버퍼). 검사·생성·originator (`eip_client.c`) 모두.
**완료 조건:** 단위 테스트: 1000 바이트 Set 에서 본문 전체 MAC 은 수락, 앞부분만의 MAC 은 `0x0F`, 꼬리를 바꾼 요청은 `0x0F`.
TCP·TLS·originator 경로. (오라클 DUT `eip_oracle_adapter` 는 보안 옵션이 없어 단위 테스트로 본다.)

## A20261112-2. EIP LLDP Chassis ID·Port ID TLV 에 subtype 옥텟이 없다

**문제:** #201 로 LLDP 를 실제로 송신하게 되면서 드러난다. Chassis ID TLV 값이 MAC 6 바이트 그대로, Port ID TLV 값이 인터페이스 이름
그대로라 수신 측은 첫 바이트를 subtype 으로 읽는다. 이웃 장비·토폴로지 툴이 Chassis ID 를 엉뚱한 subtype 의 5바이트로 본다.
**근거:** `stacks/ethernetip/src/eip_lldp.c:52` `tlv(out, cap, off, 1, src, 6)`, `:55` `tlv(out, cap, off, 2, port, strlen(port))`.
**재현 (scapy `contrib.lldp`, `eip_stack_lldp_frame` 출력):**

```
LLDPDUChassisID  _length = 6   subtype = interface alias (0x02)   id = b'\x00\x00\x00\x00\x01'
LLDPDUPortID     _length = 4   subtype = 101 (0x65 'e')           id = b'th0'
```

**기대값과 출처:** IEEE 802.1AB Chassis ID TLV = subtype 1 옥텟 + ID (subtype 4 = MAC address), Port ID TLV = subtype 1 옥텟 + ID
(5 = interface name, 3 = MAC, 7 = locally assigned). scapy `LLDPDUChassisID`/`LLDPDUPortID` 와 Wireshark `packet-lldp.c` 가 같은 형식으로
디섹트한다. 같은 저장소 PROFINET LLDP (T12-11, `stacks/profinet/`) 는 subtype 을 넣는다.
**수정 범위:** `stacks/ethernetip/`, `tests/` (+ CTT `tests/scenarios/ethernetip/lldp_mgmt.yaml` 이 TLV 길이를 고정하면 함께).
**완료 조건:** 단위 테스트 또는 scapy 디코드: Chassis ID subtype 4 + MAC 6 바이트 (길이 7), Port ID subtype 5 + 이름.

## A20261112-3. TLS 경로의 encapsulation 수신 한도가 8192 바이트로 남았다 (낮음)

**문제:** #201 은 평문 TCP 의 수신 한도를 65511 (`EIP_ENCAP_LEN_MAX`) 로 올렸지만, TLS 세션 (`security_class >= 2`) 은 여전히
8192 를 넘는 PDU 에서 연결을 끊는다. 같은 요청이 평문과 TLS 에서 다르게 처리된다.
**근거:** `stacks/ethernetip/include/eip_internal.h:69` `eip_tls_client_t.rx[EIP_TCP_BUF_MAX]`, `stacks/ethernetip/src/eip_sec.c:569`
`if (c->rx_len + (size_t)n > sizeof(c->rx))` → `tls_drop`. 코드 확인 (#201 머리말의 재현과 같음).
**기대값과 출처:** T11-13 완료 조건과 같은 기준 (encapsulation 최대 65511, 연결 유지) — 오라클 `test_large_encapsulation_keeps_session`
의 TLS 판.
**수정 범위:** `stacks/ethernetip/`, `tests/`. **완료 조건:** 단위 테스트: TLS 세션에 9000 바이트 PDU 뒤 세션 유지.

## 선별 결과

| 후보 | 판정 | 이유 |
|---|---|---|
| HMAC 재료 572 바이트 절단 | **A20261112-1**, 게이트 (b) | 재현. 무결성 우회 |
| LLDP Chassis/Port ID subtype 없음 | **A20261112-2** | scapy 디코드 재현. #201 로 실제 송신 |
| TLS rx 8192 | **A20261112-3** | 코드 확인. 평문 경로와 불일치 |
