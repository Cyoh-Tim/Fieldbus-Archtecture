# EtherCAT — 이 타깃에서는 구현하지 않음

이 문서는 EtherCAT 어댑터를 **자체 구현/오픈소스 래핑하지 않기로 한 근거**다.
결론만 필요하면 1장을 보면 된다.

## 1. 결론

이 데몬은 PLC에 데이터를 제공하는 **센서(필드 디바이스)** 다.
EtherCAT 네트워크에서 그 역할은 **SubDevice(슬레이브)** 이고, SubDevice는
ETG 규격상 **ESC(EtherCAT Slave Controller)** 가 프레임을 와이어 속도로
on-the-fly 처리해야 한다. ESC는 ASIC(ET1100, LAN9252 등) 또는 FPGA IP 코어다.

현재 타깃은 A-core + 일반 NIC 이고 **ESC ASIC/FPGA가 없다**.
PREEMPT_RT를 켜도 일반 MAC으로는 on-the-fly 처리를 대체할 수 없다.

그래서 EtherCAT은 이 플랫폼에서 **패스**한다. 소프트웨어만으로
“되는 것처럼” 넣는 것은 범용 센서 프레임워크의 확장성을 해친다
(PLC 마스터가 기대하는 토폴로지/타이밍/인증을 만족하지 못함).

재검토 조건은 5장.

## 2. 역할부터 보면 Master는 해당 없음

| 역할 | ASIC 필요 | 이 데몬과의 관계 |
|---|---|---|
| MainDevice (Master) | 없음. SOEM / IgH 등이 일반 NIC로 동작 | PLC가 맡는 역할. 센서가 마스터가 되면 이 프레임워크의 목적(PLC에 센서 데이터를 제공)과 반대다 |
| SubDevice (Slave) | **필수** (ESC ASIC 또는 FPGA) | 바코드/비전 센서가 TwinCAT, Omron NJ/NX 등 EtherCAT 마스터 PLC에 붙는 표준 역할 |

Modbus 서버, PROFINET Device, EtherNet/IP 서버와 같은 축에 놓는다면
EtherCAT도 SubDevice여야 한다. Master 스택(SOEM 등)을 가져오는 것은
“ASIC 없이 된다”는 조건을 만족하지만, **잘못된 역할**이다.

## 3. 왜 소프트웨어 슬레이브로 우회하지 않는가

소프트웨어 ESC 에뮬레이션(SOES+RAM ESC, KickCAT `EmulatedESC`,
STM32 소프트웨어 슬레이브 등)은 존재한다. 다만 공통 제약이 있다.

- 프레임을 **store-and-forward** 한다. EtherCAT의 핵심인 on-the-fly
  (~1 µs/홉)가 아니다. 홉당 지연이 수십~수백 µs로 커진다.
- 보통 **단일 노드 / 말단 노드**만 가능하다. 공장 EtherCAT의
  데이지 체인에 끼워 넣을 수 없다.
- Distributed Clocks(DC) 없음. 동기 응용 불가.
- ETG 적합성(CTT) / 상용 PLC 마스터와의 상호운용을 보장하지 않는다.
  KickCAT의 EmulatedESC는 네트워크 **시뮬레이터** 용도다.
- 이 데몬은 PREEMPT_RT를 쓰지 않는다. 소프트웨어 슬레이브는 프레임이
  도착하는 즉시 처리해야 하므로 RT 커널이 있어도 부족하고, 없으면 더 나쁘다.

PROFINET에서 IRT만 빼고 RT Class 1을 소프트웨어로 구현한 것과는 다르다.
PROFINET RT는 표준 이더넷 프레임 + 사이클 스케줄로 성립한다.
EtherCAT SubDevice에는 “ESC 없는 RT 등급”이 규격에 없다.

범용 센서 프레임워크에 이런 슬레이브를 넣으면 `protocol: "ethercat"` 이
있는 것처럼 보이지만, 실제 라인의 EtherCAT 마스터에는 붙지 않는다.
그건 확장성이 아니라 거짓 지원이다.

## 4. 오픈소스 vs 자체 구현 — ASIC이 있을 때의 판단

지금은 구현하지 않는다. 나중에 ESC 하드웨어가 보드에 올라오면:

- **슬레이브 스택은 자체 구현하지 말고 오픈소스를 래핑한다.**
  CoE 오브젝트 딕셔너리, 메일박스, 상태기계, SII/ESI는 규격 면적이 크고
  상호운용 비용이 높다. ESC가 있으면 스택은 ESC 레지스터/DPRAM만 보면 된다.
- 1순위: [SOES](https://github.com/OpenEtherCATsociety/SOES)
  (BSD-style, C, LAN9252 Linux 드라이버 경로가 이미 있음).
- ETG 멤버십이 있으면 Beckhoff SSC도 후보. 라이선스/멤버십 조건 확인 후.
- 자체 구현은 HAL(ESC read/write)과 `protocol_adapter.h` 번역기,
  JSON 포인트 → PDO/SDO 매핑만 이 저장소에 둔다.
- 위치는 기존 규칙과 같다: `adapters/ethercat/` + 필요 시 `stacks/` 가 아니라
  SOES는 벤더 라이선스가 아니므로 서브모듈/패키지로 두고 어댑터가 감싼다.
  `third_party/` 는 EtherNet/IP 구매 스택 전용.

Master가 필요해지는 별도 제품(센서가 EtherCAT I/O를 수집)이 생기면
그때는 ASIC 없이 [SOEM](https://github.com/OpenEtherCATsociety/SOEM) 래핑이
맞다. 그 경우에도 PREEMPT_RT 없이 8 ms 사이클은 시도 가능하지만,
그건 이 데몬의 센서-to-PLC 역할이 아니다.

## 5. 언제 다시 열어도 되는가

아래가 **모두** 충족될 때 `adapters/ethercat/` 스텁을 SOES 래핑으로 교체한다.

1. 타깃 보드에 ESC ASIC 또는 FPGA ESC IP가 있고, 애플리케이션 프로세서가
   SPI/HBI/온칩 버스로 접근 가능하다.
2. ESI(XML)와 PDO 맵을 config의 `protocol_params` / `points` 로만
   기술할 수 있게 어댑터가 캡슐화한다 (코어는 EtherCAT을 모른다).
3. 실시간 목표는 이 데몬의 기존 범위와 같다: 밀리초 사이클, DC/IRT급
   동기 정밀도는 보장하지 않는다고 README에 명시.

그 전에는 `protocol: "ethercat"` 은 init에서 `-ENOTSUP` 로 실패한다.
CC-Link 스텁(사양 미확정)과 달리, 이 실패는 **할 일이 남아서가 아니라
하드웨어 전제 조건이 없어서**다.
