# PROFINET Device stack (Fieldbus Architecture)

자체 구현 IO **Device** 스택. 컨트롤러/스캐너는 없다. IRT는 없다.

## 범위

| 항목 | 상태 |
|------|------|
| Conformance Class B 기능 | DCP (Identify/Get/Set/Hello/Signal), RTC1, I&M0–4, Alarm High/Low TX, LLDP, SNMP Get(sysName) |
| RT Class 1 | 비동기 cyclic, `cycle_us` (기본 8ms) |
| Security Class 1 | HMAC-SHA256 PSK. DCP Set / CM Connect 에 integrity 필수 |
| RT Class 3 / IRT | 구현하지 않음 |
| PI 인증 | 아님 |
| CRA/CE | 제품 프로세스. 스택만으로 통과하지 않음 |

## Security Class 1 프로파일 (이 스택)

PI 옵션 코드를 사칭하지 않는다. 이 저장소 프로파일이다.

- 알고리즘: HMAC-SHA256, 32바이트 태그
- 키: `protocol_params.psk_hex` (64 hex chars). 랩/개발 키를 제품에 두지 말 것
- DCP Set: option `0xF0` / sub `0x01` 블록이 없으면 거부
- Connect: block type `0x0E01` 이 없으면 AR 미수립
- DCP Identify / Get 은 서명하지 않음 (탐색용)

`security_class: 0` 은 랩 전용 unsigned 모드다.

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
