# 감사 2026-10-13 — EIP UDP 탐색: bind_ip 지정 시 브로드캐스트 ListIdentity 무응답

- 영역: EtherNet/IP 스택 (PR #121 T11-4 검증 중 랩 확인)
- 출처: PR #121 검증 — 독립 스캐너 EIPScanner 의 `DiscoveryManager` 로 veth 랩에서 UDP 탐색을 돌려 봄
- 기준 커밋: `8cee7d5` (main, #121 병합 직후)
- 판단: 검증 담당 (루틴 직접, 랩 재현 + OpENer 소스 대조)
- 큐 추가: 1개 (A20261013-1 → 큐 79)

## A20261013-1. bind_ip 를 유니캐스트 주소로 주면 브로드캐스트 ListIdentity(RSLinx 브라우즈)에 응답하지 않는다

**문제:** #121 (T11-4) 이 추가한 UDP encapsulation 소켓은 `bind_ip` 에 bind 한다. `bind_ip` 가 `0.0.0.0` 이면 문제없지만,
특정 유니캐스트 주소(예: 여러 NIC 중 한 곳만 열려고 `192.168.1.10`)로 주면 Linux 에서 그 소켓은 서브넷 브로드캐스트
(`192.168.1.255`)나 제한 브로드캐스트(`255.255.255.255`)로 온 데이터그램을 받지 못한다. RSLinx·Studio 5000 의 브라우즈는
브로드캐스트 ListIdentity 라서 장치가 보이지 않는다. 유니캐스트 ListIdentity 는 응답한다.
제품 예제 config (`config/example.ethernetip.json`, `example.codesys.ethernetip.json`) 는 `0.0.0.0` 이라 기본 배포에서는 탐색된다.

**근거 (파일:줄, 기준 커밋 `8cee7d5`):**
- `stacks/ethernetip/src/eip_stack.c` `bind_udp_encap` — `addr.sin_addr.s_addr = s->bind_ip_host ? htonl(s->bind_ip_host) : htonl(INADDR_ANY)`.
- 같은 PR 의 단위 테스트 `tests/test_eip_t11_4.c` 의 broadcast 경우는 와일드카드 bind 로만 확인한다.

**재현 (veth + netns, 독립 스캐너 EIPScanner `DiscoveryManager`, `tests/oracle/lab/eipscanner_discover.cpp`):**
DUT `eip_oracle_adapter` 를 namespace 안 `10.78.0.2/24` 에 두고 바깥 veth 에서 탐색.

```
main(#121 이전)             bind 10.78.0.2 / 0.0.0.0 : 브로드캐스트 FOUND 0, 유니캐스트 FOUND 0
#121, bind 0.0.0.0          브로드캐스트 FOUND 1  DEV name=FieldbusOracle … addr=10.78.0.2:44818
                            유니캐스트   FOUND 1  (같음)
#121, bind 10.78.0.2        브로드캐스트 FOUND 0
                            유니캐스트   FOUND 1  DEV name=FieldbusOracle … addr=10.78.0.2:44818
```

오라클 `tests/oracle/test_eip_lab.py::test_lab_eipscanner_discovers_unicast_bound_device_by_broadcast` 를 `--runxfail` 로 돌린 결과:
`AssertionError: []`. 대조군 `…_wildcard_bound_device_by_broadcast` 는 통과한다.

**기대값과 출처:**
- 장치는 `bind_ip` 와 무관하게 자기 인터페이스로 온 브로드캐스트 ListIdentity 에 응답한다 (T11-4 의 목적: "RSLinx/Studio 5000 브라우즈(브로드캐스트 ListIdentity)").
- 독립 구현 OpENer (`d8820ef`) `source/src/ports/generic_networkhandler.c`: 유니캐스트 수신 소켓과 별도로
  `udp_global_broadcast_listener` 를 `INADDR_ANY` + `SO_BROADCAST` 로 bind 한다 (`:173-310`).
- Linux 소켓 동작: 유니캐스트 주소에 bind 한 UDP 소켓에는 브로드캐스트 데이터그램이 전달되지 않는다 (위 랩 결과가 그 재현).

**수정 범위:** `stacks/ethernetip/`, `tests/`.
- 브로드캐스트 수신은 `INADDR_ANY` 소켓으로 받고, `IP_PKTINFO` 의 도착 인터페이스·주소가 `bind_ip` 의 인터페이스와 같을 때만 응답한다
  (다른 NIC 로 온 요청은 무시). `bind_ip` 가 `0.0.0.0` 이면 지금과 같다.
- ListIdentity 응답의 Socket Address 는 지금처럼 도착 인터페이스 주소 (`bind_ip` 와 같아야 한다).
- 같은 포트를 `INADDR_ANY` 와 유니캐스트로 둘 다 bind 하려면 `SO_REUSEADDR` 가 필요하다 (이미 설정).

**완료 조건:** 랩 `test_lab_eipscanner_discovers_unicast_bound_device_by_broadcast` 통과 (`A20261013-1` 표시 삭제), 대조군 그대로.
랩은 CI 에서 건너뛰므로 검증 담당이 랩으로 확인한다. 단위 테스트로는 bind_ip 지정 + `255.255.255.255`/서브넷 브로드캐스트 수신을 보인다.

## 확인 필요 (큐에 넣지 않음)

1. **ListIdentity 응답 지연 (Max Response Delay).** 최근 판 사양은 UDP ListIdentity 요청의 Sender Context 앞 2바이트를 응답 지연 상한(ms)으로
   보고 장치가 그 안에서 무작위로 늦춰 응답하게 한다는 서술이 있다 (`docs/protocols/ethernetip.md:770` 의 "사양서 확인 필요", #121 제안 3).
   사양 원문과 참조 구현 확인 전에는 넣지 않는다. 지금 구현은 즉시 응답한다 (브로드캐스트 폭주 완화 기능이라 상호운용 실패는 아님).

## 문서 (큐 70 비고에 추가)

#121 제안 1·2: `docs/protocols/ethernetip.md` 의 "UDP 44818 소켓 없음"·"sockaddr 0"·"State 0xFF"·"ListInterfaces status 0x0001"
(`:705`, `:803` 절, `:1787`, `:2275`, `:2355`, `:2497`, `:2530`), `tools/ctt/proto/ethernetip/README.md:23`,
`docs/ctt_eip_bundle.md:116`, `:126`, `docs/ctt_odva_matrix.md:51` 의 "ListInterfaces DUT not implemented".
