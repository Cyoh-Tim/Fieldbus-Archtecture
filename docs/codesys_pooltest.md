# CODESYS 전체 프로토콜 풀테스트 + 센서 데모

CODESYS Control SL 이 한 번에 쓰는 역할로, 이 저장소의 **센서 데모**가
실제 값이 변하며 나가는지까지 확인한다.

| 프로토콜 | CODESYS 역할 | 이 저장소 | 풀테스트 |
|---|---|---|---|
| Modbus TCP | Master | 센서 = Server (port 1502) | `pool_master --proto modbus` |
| EtherNet/IP | Scanner (UCMM GetAttribute) | 센서 = Adapter (asm 150) | `pool_master --proto ethernetip` |
| PROFINET | Controller | 센서 = Device (GSDML) | `pn_codesys_beta` (CODESYS 와 같은 CM 순서) |
| SLMP 3E | **없음** (미쓰비시 전용) | 센서 = Client → PLC 시뮬 | `pool_master --proto slmp` |
| CC-Link | 없음 | 스텁 | skip |
| EtherCAT | Master 만 의미 있음 | SubDevice 는 ESC ASIC 필요 | skip |

빈 `codesyscontrol` 프로세스는 필드버스 마스터가 **아니다**. IEC 앱
(이더넷 → PN-Controller / Modbus Master / EIP Scanner) 은 Windows 의
CODESYS Development System 에서 컴파일해 런타임으로 다운로드해야 한다.
이 VM 에서는 그 IDE 가 없으므로:

1. **와이어 레벨**로 CODESYS 와 같은 역할의 마스터를 돌리고 라이브 데이터를 검증한다.
2. IEC 소스는 `tests/codesys/PLC_PRG_pool.st` 이다. 2시간 데모 런타임에 올리는 절차는 아래.

## 한 줄로 돌리기

```
cmake -S . -B build && cmake --build build
bash tests/codesys/run_pooltest.sh
```

센서 프로세스 이미지 (모든 프로토콜 공통):

| 필드 | 레이아웃 | 값 |
|---|---|---|
| barcode | 32 ASCII | `BETA-PN-IN/NNNNNN` (매 사이클 증가) |
| temperature | uint16 BE | 200..350 (0.1 °C) |
| humidity | uint16 BE | 300..700 (0.1 %RH) |
| seq | uint16 BE | 단조 증가 |

`sensor_demo` 가 `/tmp/fieldbus-sensor-demo.json` 에 방금 쓴 값을 남기고,
`pool_master` 가 와이어에서 읽은 값과 대조한다.

## 실제 CODESYS Control SL (2시간 데모)

스토어 계정:

```
export CODESYS_STORE_EMAIL=...
export CODESYS_STORE_PASSWORD=...
bash tests/codesys/try_install_codesys.sh
```

패키지는 `~/.cache/codesys-store/` 에만 받는다. 저장소에 커밋하지 않는다.
스토어 다운로드는 Magento EULA 팝업 뒤에 있다. `download_codesys_store.py` 가
`form_key` 쿠키를 맞춘 뒤 `license/get` → `license/accept` → archive GET 을
탄다. PID 1 이 systemd 가 아니면 스크립트가 CodeMeter / Control / Gateway
바이너리를 직접 기동한다 (cwd `/var/opt/codesys`, 포트 22350 / 11740 / 1217).

CODESYS 는 컨테이너/VM 용으로 출시하지 않는다. 클라우드 VM 에서 2시간 데모
런타임이 떠도, Windows IDE 가 이 사설망의 11740/tcp 에 닿지 않으면 IEC 앱을
다운로드할 수 없다. 빈 런타임은 필드버스 마스터가 아니다.


Windows IDE 쪽 클릭 경로 (약 15분, 기존 `docs/codesys_beta.md` 와 동일 + 풀):

1. Device Repository → Install → `stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`
2. 새 표준 프로젝트, 디바이스 **CODESYS Control for Linux SL**
3. Ethernet 아래 **PN-Controller** / **Modbus TCP Master** / **EtherNet/IP Scanner** 추가
4. PN 디바이스 station name `sensor-line1`, 사이클 ≥ 8 ms, 슬롯 1 IO 모듈
5. Modbus 슬레이브 `127.0.0.1:1502` unit 1, Holding 40001 길이 19
6. EIP 타깃 assembly 150 (T→O) / 101 (O→T)
7. `tests/codesys/PLC_PRG_pool.st` 를 `PLC_PRG` 에 복사, I/O 매핑
8. 리눅스 타깃에서 프로토콜별로 `sensor_demo` 실행 (한 런타임에 필드버스 3종을 켜면 센서 데몬 3개)
9. Login → Download → Run. 2시간 후 런타임 재시작.

SLMP 는 CODESYS 필드버스 목록에 없다. 미쓰비시 PLC 또는
`config/demo.slmp.plc.json` 시뮬레이터를 쓴다.

## 이 PR 에서 돌린 결과

`bash tests/codesys/run_pooltest.sh` (이 클라우드 VM, 2026-09-08, Control SL 기동 후):
**PASS=5 FAIL=0 SKIP=2**

| 항목 | 결과 |
|---|---|
| Modbus TCP Master ← sensor | **PASS** 16 samples, barcode `BETA-PN-IN/…` last seq 442, state_match |
| EtherNet/IP UCMM ← sensor | **PASS** 17 samples, assembly 150 last seq 481, state_match |
| SLMP 3E client → PLC stand-in | **PASS** 15 samples, D100 last seq 106, state_match |
| PROFINET CODESYS-profile Controller | **PASS** 16/16 (DCP Nominate, Connect+AlarmCR, Write, PrmEnd, RTC1 8 ms mean 7999 µs n=145, input `BETA-PN-IN`) |
| CC-Link / EtherCAT | SKIP (스텁 / ESC ASIC) |
| `codesyscontrol` 4.22.0.0 | **PASS** listening 11740. CodeMeter 9.10.8166.500 + Control SL + Edge Gateway. 로그: `CODESYS Control ready`, `no runtime license - running in demo mode(~2 hours)`. Gateway **1217**/tcp, OPC UA **4840**/tcp, CodeMeter **22350**/tcp. 빈 런타임 — IEC 앱 없음, 필드버스 마스터 아님. `/opt/codesys` 는 dpkg 후 770 root:root. XDP/`libxdp.so` 없음은 VM 에서 정상. |

와이어에서 읽은 온도는 200–350 (0.1 °C) 범위에서 매 샘플 바뀌었고, `sensor_demo` 가 쓴 JSON 스냅샷과 일치했다.
