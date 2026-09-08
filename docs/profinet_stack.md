# PROFINET Device stack (Fieldbus Architecture)

자체 구현 IO **Device** 스택. 컨트롤러/스캐너는 없다. IRT는 없다.
PI 인증 대상이 아니다.

## 범위

| 항목 | 상태 |
|------|------|
| CM 기동 | Connect → Write(ACK) → PrmEnd → ApplicationReady → cyclic |
| RT Class 1 | 비동기 cyclic. C_SDU 에 데이터+IOPS/IOCS. `SendClock×ReductionRatio` |
| DCP | Identify(필터), Get(요청 속성), Set(Name/IP). 기동 시 Hello. Set 시 `apply_os_ip` 이면 OS 주소 적용 |
| Record | I&M0, RealIdent, PDPort/PDIF, ChannelDiagnosis `0x800A` / ExtChannel `0x8010` / AR Diag `0xE00C`, WriteMultiple |
| LLDP | Chassis/Port/TTL/SysName/MgmtAddr + PN Chassis MAC / Port Status |
| SNMP | MIB-II system + ifTable(1 port) Get/GetNext. LLDP-MIB loc/rem + LastChange |
| Watchdog | output CR 가 끊기면 AR down, output image 클리어 |
| Alarm CR | AlarmCR_REQ 파싱, RTA Data(USI ChannelDiagnosis) + ACK |
| RT Class 3 / IRT | Connect 에서 거부. 구현하지 않음 |
| MRP | 이더타입 `0x88E3` 무시. 링 클라이언트 미구현 |
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

공개 Readme / 이전에 “랩 범위 밖”이던 항목을 **테스트 코드로 대체할 수 있는지**:

| 항목 | 랩에서 하는 일 | 대체 불가능한 것 |
|------|----------------|------------------|
| diagnosis ASE | ChannelDiagnosis USI + record `0x800A`/`0x8010`/`0xE00C` | 전체 diagnosis 상태기계, Maintenance ASE, 공식 TCS |
| IRT / SPIRTA | Connect `RT_CLASS_3` / IRT FrameID **거부** (네거티브 테스트) | 동기 사이클, PTCP, SPIRTA 바이너리, ASIC 타임스탬프 |
| MRP | `0x88E3` 무시 + GSDML 미선언 + flood 중 RTC1 유지 | MRP Client/Manager 링, CC-B(PA) 공식 TCS |
| Netload | unicast junk + MRP ethertype flood 중 cyclic | 공식 Netload 프로파일 / ETS 계측 |
| DCP Hello | 기동·IP Set 후 Hello.req | Hello 타이밍 공식 프로파일 |
| ART / ETS | 공개 그룹을 랩 케이스로 재구현 | Windows ETS, 회원 TCS zip, 시나리오 XML |
| TEDCheck | GSDML well-formed + 필수 필드/IRT·MRP 미선언 | GSD Checker / TEDCheck 바이너리 |
| PITL | 없음. 제품·시험소 프로세스 | 인증서 자체를 테스트로 만들 수 없음 |

| 그룹 | 랩 프리테스트 | 공식 번들 없이 못 하는 것 |
|------|----------------|---------------------------|
| DCP | Identify All/Name/DeviceID, Get Name/ID/IP, Set Name, Hello | DCP Set IP를 OS에 쓰는 경우의 공식 프로파일 |
| LLDP | sysName + PN OUI, 이웃 Chassis/Port/SysName, Port ID `port-001` | 멀티포트, 공식 LLDP 프로파일 |
| SNMP | Get+GetNext: MIB-II system/if, LLDP loc/rem, LastChange, sysUpTime | 전체 MIB-II, SNMP v3, 공식 ART TCS |
| CM | Connect ARServer + AlarmCR, IRT 거부, WriteMultiple, I&M0, RealIdent, PD*, ChannelDiagnosis, PrmEnd, AppReady, RTA Data/USI/Ack, Release, Reconnect | 공식 TCS XML |
| RTC1 | cyclic + IOPS GOOD, Release 후 중단, junk/MRP flood 중 유지 | 공식 Netload, IRT/SPIRTA |
| GSDML | well-formed, PDev, RT1, no IRT/RT3/MRP, SNMP;LLDP, MIB2;LLDP | TEDCheck 바이너리 |

시뮬레이터는 DCP Identify → Set Name 왕복 → Connect (ARServerBlock) → Write / WriteMultiple → Read I&M0 / RealIdent / PD* → PrmEnd → ApplicationReady → RTC1 cyclic 을 실제 Ethernet/UDP 로 주고받는다. Siemens TIA 와 같은 CM 순서이며, 벤더 분기는 없다.

GSDML 은 `stacks/profinet/gsdml/` 에 있다. TIA 등에서 여는 출발점이며 VendorID `0xABCD` 는 PI 할당이 아니다. 최소 사이클은 8ms (`MinDeviceInterval=256`). Interface `SupportedMibs="MIB2;LLDP"` 는 랩 CC-B 선언이다. PITL / ART 인증을 대체하지 않는다.

## 점대점 매핑

포인트 `address.profinet.byte_offset` 는 cyclic process image 오프셋이다.

- `access: read`  → device → controller (input image)
- `access: write` → controller → device (output image)

Connect 의 ExpectedSubmodule / IOCR FrameOffset 이 있으면 그 레이아웃으로 C_SDU 를 채운다.
