# PROFINET Device stack (Fieldbus Architecture)

자체 구현 IO **Device** 스택. 컨트롤러/스캐너는 없다.
랩 목표는 **CC-B 서브셋**. **CC-C(IRT)는 구현하지 않는다.**
PI 인증 대상이 아니다.

## Conformance Class

PI 클래스는 누적이다 (C ⊃ B ⊃ A). 아래는 이 스택의 **랩 구현 범위**이지
인증 클레임이 아니다.

| 클래스 | 공식 구분 | 이 스택 |
|--------|-----------|---------|
| **CC-A** | 비동기 RT Class 1 cyclic, DCP, I&M0, alarm/diagnosis, LLDP 이웃, PDEV | 랩 구현 (CM/RTC1/DCP/I&M0/진단 레코드/AlarmCR/LLDP/PDEV) |
| **CC-B** | CC-A + SNMP (MIB-II + LLDP-MIB) + SNMP/PDEV 토폴로지. **MRP는 옵션**. CC-B(PA)는 프로세스 자동화 **시스템 리던던시**이며 MRP가 아님 | SNMP Get/GetNext/Set/GetBulk, MIB-II system/if/ip/icmp/udp/snmp + LLDP-MIB loc/rem/stats + LLDP-EXT-PNO. PDEV CheckNeighbors/FSU. MRP Client/Manager **미구현** (`0x88E3` 무시). CC-B(PA) 없음 |
| **CC-C** | CC-B + **IRT / RT Class 3**, 하드웨어 대역 예약, PTCP/동기. 공식 IRT 테스터는 **SPIRTA** | **구현하지 않음.** Connect `RT_CLASS_3` / IRT FrameID `0x0100–0x0FFF` 는 NDR로 거부. SPIRTA 대체 아님 |
| (클래스 아님) | ART / ETS / TEDCheck / PITL 는 **인증 프로세스** | 랩 프리테스트만. 시험소·회원 zip 대체 불가 |

IRT / PTCP / SPIRTA 를 “랩 CC-B 스탠드인”으로 부르지 않는다. 그건 CC-C다.
MRP를 CC-C로 부르지 않는다. 진단/알람은 A/B/C 공통이다.

## 범위

| 항목 | 상태 | 클래스 |
|------|------|--------|
| CM 기동 | Connect → Write(ACK) → PrmEnd → ApplicationReady → cyclic | A/B |
| RT Class 1 | 비동기 cyclic. C_SDU 에 데이터+IOPS/IOCS. `SendClock×ReductionRatio` | A |
| DCP | Identify(필터), Get(요청 속성), Set(Name/IP). 기동 시 Hello. Set 시 `apply_os_ip` 이면 OS 주소 적용 | A |
| Record | I&M0–4 (1–4 writable), RealIdent, PDPort/PDIF Real/Adjust/Check/FSU, PD*Statistic, Channel/Ext/Qualified Diagnosis, disappear/process alarm | A/B |
| LLDP | Chassis/Port/TTL/SysName/MgmtAddr + PN Chassis MAC / Port Status | A (이웃), B (LLDP-MIB) |
| SNMP | MIB-II system + ifTable/ifXTable + ipAddrTable + icmp + udp/snmp, LLDP-MIB loc/rem/stats/cap, LLDP-EXT-PNO loc/rem delay. Get/GetNext/Set/GetBulk | **B** |
| Watchdog | output CR 가 끊기면 AR down, output image 클리어 | A |
| Alarm CR | AlarmCR_REQ 파싱, RTA appear → disappear → process Data + ACK | A/B/C |
| RT Class 3 / IRT / PTCP | Connect 에서 거부. 구현하지 않음 | **C — 미구현** |
| MRP | 이더타입 `0x88E3` 무시. 링 클라이언트 미구현 | **B 옵션 — 미구현** |
| PI Security Class 1 | 아님. `security_class: 1` 은 스택 로컬 HMAC-SHA256 PSK | 클래스 아님 |
| PI 인증 / CRA/CE | 아님. 제품 프로세스 | 클래스 아님 |

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

`run_pn_fulltest.sh` 는 PI Test Bundle 공개 Readme의 RT Device 그룹을 이 환경에서 돌리는 **랩 프리테스트**다. 공식 **ART**(주로 CC-A/B) / **SPIRTA**(CC-C IRT) / ETS 는 PI 회원 전용·Windows ETS 기반이다. 회원 포털에서 계정 권한이 열리기 전에는 zip을 받을 수 없고, 받아도 이 Linux 에이전트에서 ETS를 실행하지 않는다. PITL 인증을 대체하지 않는다.

### 랩에서 하는 일 vs 클래스를 바꾸지 않는 것

| 항목 | 클래스 | 랩에서 하는 일 | 그게 아닌 것 |
|------|--------|----------------|--------------|
| diagnosis ASE | A/B/C | Channel + Ext + Qualified + Maintenance demanded 레코드, appear → disappear → process | 전체 상태기계, 공식 TCS |
| SNMP / LLDP-MIB | **B** | Get+GetNext+Set+GetBulk, ifTable/ifXTable, ipAddrTable/icmp/udp/snmp, loc/rem/stats/cap, PNO delays | 전체 MIB-II, SNMPv3, 공식 ART TCS |
| MRP | **B 옵션** | `0x88E3` 무시 + GSDML 미선언 + flood 중 RTC1 유지 | MRP Client/Manager 링. CC-B(PA) TCS도 아님 |
| DCP Hello | A | 기동·IP Set 후 Hello.req | Hello 타이밍 공식 프로파일 |
| Netload | A/B 부하 | unicast junk + MRP ethertype flood 중 cyclic | 공식 Netload 프로파일 / ETS 계측 |
| IRT / PTCP / SPIRTA | **C** | Connect `RT_CLASS_3` **거부** (CC-C 미지원 확인) | IRT 구현이 아님. SPIRTA 바이너리·ASIC·동기 사이클 대체 불가 |
| ART / ETS / TEDCheck / PITL | 클래스 아님 | 공개 그룹을 랩 케이스로 재구현, GSDML well-formed | Windows ETS, 회원 TCS zip, GSD Checker, 인증서 |

| 그룹 | 랩 프리테스트 | 공식 번들 없이 못 하는 것 |
|------|----------------|---------------------------|
| DCP | Identify All/Name/DeviceID, Get Name/ID/IP, Set Name, Hello | DCP Set IP를 OS에 쓰는 경우의 공식 프로파일 |
| LLDP | sysName + PN OUI, 이웃 Chassis/Port/SysName, Port ID `port-001` | 멀티포트, 공식 LLDP 프로파일 |
| SNMP | Get+GetNext+Set+GetBulk: MIB-II system/if/ip/icmp, LLDP loc/rem/cap, LastChange, sysUpTime | 전체 MIB-II, SNMP v3, 공식 ART TCS |
| CM | Connect ARServer + AlarmCR, CC-C IRT Connect 거부, WriteMultiple, I&M0, RealIdent, PD*, ChannelDiagnosis, PrmEnd, AppReady, RTA Data/USI/Ack, Release, Reconnect | 공식 TCS XML |
| RTC1 | cyclic + IOPS GOOD, Release 후 중단, junk/MRP flood 중 유지 | 공식 Netload. IRT/SPIRTA 는 CC-C라 여기 없음 |
| GSDML | well-formed, PDev, RT1, CC-C IRT/RT3 미선언, MRP 미선언, SNMP;LLDP, MIB2;LLDP | TEDCheck 바이너리 |

시뮬레이터는 DCP Identify → Set Name 왕복 → Connect (ARServerBlock) → Write / WriteMultiple → Read I&M0 / RealIdent / PD* → PrmEnd → ApplicationReady → RTC1 cyclic 을 실제 Ethernet/UDP 로 주고받는다. Siemens TIA 와 같은 CM 순서이며, 벤더 분기는 없다.

GSDML 은 `stacks/profinet/gsdml/` 에 있다. TIA 등에서 여는 출발점이며 VendorID `0xABCD` 는 PI 할당이 아니다. 최소 사이클은 8ms (`MinDeviceInterval=256`). Interface `SupportedMibs="MIB2;LLDP"` 는 랩 **CC-B** 선언이다. `IsochroneModeSupported=false` / `RT_CLASS_3` 미기재는 **CC-C를 클레임하지 않는다**는 뜻이지, IRT 테스트를 대체한다는 뜻이 아니다. PITL / ART / SPIRTA 인증을 대체하지 않는다.

## 점대점 매핑

포인트 `address.profinet.byte_offset` 는 cyclic process image 오프셋이다.

- `access: read`  → device → controller (input image)
- `access: write` → controller → device (output image)

Connect 의 ExpectedSubmodule / IOCR FrameOffset 이 있으면 그 레이아웃으로 C_SDU 를 채운다.
