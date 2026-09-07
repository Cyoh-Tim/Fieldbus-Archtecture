# PROFINET Device stack (Fieldbus Architecture)

자체 구현 IO **Device** 스택. 컨트롤러/스캐너는 없다. IRT는 없다.
PI 인증 대상이 아니다.

## 범위

| 항목 | 상태 |
|------|------|
| CM 기동 | Connect → Write(ACK) → PrmEnd → ApplicationReady → cyclic |
| RT Class 1 | 비동기 cyclic. C_SDU 에 데이터+IOPS/IOCS. `SendClock×ReductionRatio` |
| DCP | Identify(필터), Get(요청 속성), Set(Name/IP). Set 시 `apply_os_ip` 이면 OS 주소 적용 |
| Record | I&M0 (`0xAFF0`) |
| LLDP | Chassis/Port/TTL/SysName/MgmtAddr + PN Chassis MAC / Port Status |
| SNMP | Get 에 대해 sysName, request-id 반사 |
| Watchdog | output CR 가 끊기면 AR down, output image 클리어 |
| RT Class 3 / IRT | 구현하지 않음 |
| PI Security Class 1 | 아님. `security_class: 1` 은 스택 로컬 HMAC-SHA256 PSK |
| PI 인증 / CRA/CE | 아님. 제품 프로세스 |

## 랩 기본값

`security_class` 기본은 **0** (unsigned). 실제 PLC/엔지니어링 툴은 스택 로컬 HMAC 블록을 보내지 않는다.

점대점 HMAC 프로파일을 쓰려면:

- 알고리즘: HMAC-SHA256, 32바이트 태그
- 키: `protocol_params.psk_hex` (64 hex chars)
- DCP Set: option `0xF0` / sub `0x01`
- Connect: block type `0x0E01`

## 실행

실제 NIC:

```
sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/multiproto_daemon
./build/multiproto_daemon config/example.profinet.json
```

DCP Set 으로 받은 IP 를 인터페이스에 쓰려면 `apply_os_ip: true` 와 `CAP_NET_ADMIN` 이 필요하다.

단위 테스트는 raw 소켓 없이:

```
./build/test_pn_stack
```

GSDML 은 `stacks/profinet/gsdml/` 에 있다. TIA 등에서 여는 출발점이며 VendorID `0xABCD` 는 PI 할당이 아니다. 최소 사이클은 8ms (`MinDeviceInterval=256`).

## 점대점 매핑

포인트 `address.profinet.byte_offset` 는 cyclic process image 오프셋이다.

- `access: read`  → device → controller (input image)
- `access: write` → controller → device (output image)

Connect 의 ExpectedSubmodule / IOCR FrameOffset 이 있으면 그 레이아웃으로 C_SDU 를 채운다.
