# PROFINET Device stack (Fieldbus Architecture)

자체 구현 IO **Device** 스택. 컨트롤러/스캐너는 없다. IRT는 없다.
PI 인증 대상이 아니다.

## 범위

| 항목 | 상태 |
|------|------|
| CM 기동 | Connect → Write(ACK) → PrmEnd → ApplicationReady → cyclic |
| RT Class 1 | 비동기 cyclic. C_SDU 에 데이터+IOPS/IOCS. `SendClock×ReductionRatio` |
| DCP | Identify(필터), Get(요청 속성), Set(Name/IP). Set 시 `apply_os_ip` 이면 OS 주소 적용 |
| Record | I&M0 (`0xAFF0`), RealIdent (`0xF000`/`0xE001`/`0xC001`/`0x8001`), PDPort/PDInterface Real 스텁. Write / WriteMultiple (`0xE040`) ACK |
| LLDP | Chassis/Port/TTL/SysName/MgmtAddr + PN Chassis MAC / Port Status |
| SNMP | Get 에 대해 sysName / sysDescr / lldpLocSysName / lldpRemSysName |
| Watchdog | output CR 가 끊기면 AR down, output image 클리어 |
| Alarm CR | Connect.res 에 AlarmCRBlockRes. RTA Notify/Ack 시퀀스는 없음 |
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

PLC 없이 Device↔Controller 기동 시퀀스는 veth 위에서 컨트롤러 시뮬레이터가 검증한다:

```
./build/test_pn_stack
bash tests/run_pn_veth.sh
bash tests/run_pn_fulltest.sh
```

`run_pn_fulltest.sh` 는 PI Test Bundle 공개 Readme의 RT Device 그룹을 이 환경에서 돌리는 **랩 프리테스트**다. 공식 ART / SPIRTA / ETS 는 PI 회원 전용·Windows ETS 기반이다. 회원 포털에서 계정 권한이 열리기 전에는 zip을 받을 수 없고, 받아도 이 Linux 에이전트에서 ETS를 실행하지 않는다. PITL 인증을 대체하지 않는다.

공개 Readme 기준으로 여기서 하는 것 / 안 하는 것:

| 그룹 | 랩 프리테스트 | 공식 번들 없이 못 하는 것 |
|------|----------------|---------------------------|
| DCP | Identify All/Name/DeviceID 필터, Get Name/ID/IP, Set Name 왕복 | DCP Set IP를 OS에 쓰는 경우, Hello |
| LLDP | sysName + PN OUI `00:0C:CF` 송신, 이웃 LLDP 수신 | 전체 LLDP-MIB 테이블/LastChange |
| SNMP | sysName, sysDescr, lldpLocSysName, lldpRemSysName | MIB-II 전 객체, SNMP v2c 예외 |
| CM | Connect ARServer + AlarmCR.res, Write / WriteMultiple, I&M0, RealIdent, PDPort/PDIF, unknown index 빈 성공, PrmEnd, AppReady, Release, Reconnect | RTA Alarm Notify/Ack 시퀀스, 공식 TCS |
| RTC1 | cyclic + IOPS GOOD, Release 후 송신 중단, ingress flood 중 cyclic 유지 | 공식 Netload 프로파일, IRT/SPIRTA |
| GSDML | well-formed, VendorID/DeviceID, PDev, RT1, no IRT, SNMP;LLDP, MIB2, NumberOfAR, IO 길이, MAUTypes | TEDCheck / GSD Checker 바이너리 |

시뮬레이터는 DCP Identify → Set Name 왕복 → Connect (ARServerBlock) → Write / WriteMultiple → Read I&M0 / RealIdent / PD* → PrmEnd → ApplicationReady → RTC1 cyclic 을 실제 Ethernet/UDP 로 주고받는다. Siemens TIA 와 같은 CM 순서이며, 벤더 분기는 없다.

GSDML 은 `stacks/profinet/gsdml/` 에 있다. TIA 등에서 여는 출발점이며 VendorID `0xABCD` 는 PI 할당이 아니다. 최소 사이클은 8ms (`MinDeviceInterval=256`).

## 점대점 매핑

포인트 `address.profinet.byte_offset` 는 cyclic process image 오프셋이다.

- `access: read`  → device → controller (input image)
- `access: write` → controller → device (output image)

Connect 의 ExpectedSubmodule / IOCR FrameOffset 이 있으면 그 레이아웃으로 C_SDU 를 채운다.
