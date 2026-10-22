# PROFINET Device stack (Fieldbus Architecture)

자체 구현 IO **Device** 스택. 컨트롤러/스캐너는 없다. IRT는 없다.

## 범위

| 항목 | 상태 |
|------|------|
| Conformance Class B 기능 | DCP (Identify/Get/Set/Hello/Signal), RTC1, I&M0–4, Alarm High/Low TX, LLDP, SNMP Get(sysName) |
| RT Class 1 | 비동기 cyclic, `cycle_us` (기본 8ms) |
| vendor integrity extension | HMAC-SHA256 PSK. `security_class`≥1 일 때 DCP Set / CM Connect 에 integrity 필수. 기본 끔. PI Security Class 아님 |
| RT Class 3 / IRT | 구현하지 않음 |
| PI 인증 | 아님 |
| CRA/CE | 제품 프로세스. 스택만으로 통과하지 않음 |

## vendor integrity extension (이 스택)

PI Security Class 가 아니고, PI 옵션 코드를 사칭하지 않는다. 이 저장소 프로파일이다.
config 키는 `security_class` · `psk_hex` 를 그대로 쓴다. 어댑터 기본값은 `security_class` 0 (끔)이다.

- 알고리즘: HMAC-SHA256, 32바이트 태그
- 키: `protocol_params.psk_hex` (64 hex chars). 랩/개발 키를 제품에 두지 말 것
- DCP Set: option `0xF0` / sub `0x01` 블록이 없으면 거부
- Connect: block type `0x0E01` 이 없으면 AR 미수립
- DCP Identify / Get 은 서명하지 않음 (탐색용)

`security_class: 0` (생략 시 기본값)은 HMAC 없는 모드다. 표준 컨트롤러의 Connect·이름 설정이 된다.

생산 빌드는 CMake `-DPN_ENFORCE_SECURITY_CLASS=ON` 또는
`protocol_params.enforce_security_class: true` 로 vendor integrity extension(HMAC)을 강제한다.
그때 unsigned DCP Set 은 거부된다. 랩 기본은 둘 다 끔.

NameOfStation 은 PROFINET/DNS 규칙이다: 라벨 1–63, 전체 ≤240, 소문자 `a-z`/`0-9`/`-`,
라벨 앞뒤 `-` 금지, IPv4 형태 금지, 예약 `port-xyz`(3 hex) 금지. Identify 는
필터 블록과 `ResponseDelay`(10 ms 단위, MAC 하위 16비트 modulo)를 따른다.

## 실행

실제 NIC:

```
sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/multiproto_daemon
./build/multiproto_daemon config/example.profinet.json
```

`iface` 를 실제 인터페이스로 바꾸고, 그 NIC IP 를 DCP/config IP 와 맞출 것. 스택은 기본적으로 OS 주소를 바꾸지 않는다.

단위 테스트 / CTT 는 raw 소켓 없이:

```
./build/test_pn_crypto
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
ctest --test-dir build --output-on-failure
```

## 점대점 매핑

포인트 `address.profinet.byte_offset` 는 cyclic process image 오프셋이다.

- `access: read`  → device → controller (input image)
- `access: write` → controller → device (output image)
