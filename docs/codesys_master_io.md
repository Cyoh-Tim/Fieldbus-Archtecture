# CODESYS SoftPLC를 마스터로 — 우리 DUT가 디바이스

CODESYS **Control for Linux SL** (SoftPLC) 를 **마스터/컨트롤러**로 두고, 이 저장소 런타임을
Modbus TCP 서버 · (패키지가 있으면) EtherNet/IP Adapter · PROFINET Device 로 붙이는 절차다.

**이 문서는 인증이 아니다.** CODESYS / PI / ODVA / Modbus.org 랩 결과가 아니다.
이 클라우드 에이전트 VM 과 GitHub Actions 에서는 SoftPLC 부트 애플리케이션을
다운로드하지 않았다. SoftPLC 가 IO 를 돌렸다고 주장하지 말 것.

CODESYS **없이** 우리 스택에 실제 IO 를 돌리는 경로(Modbus/SLMP/EIP 라이브 루프백,
PROFINET 제외): [`sw_master_io.md`](sw_master_io.md)
(`./examples/run_sw_master_soak.sh`). 이 문서는 SoftPLC 쪽이다.

한 줄 DUT:

```
./examples/run_codesys_dut.sh              # Modbus TCP 서버 + 가짜 센서, Ctrl+C 까지
./examples/run_codesys_dut.sh --stand-in  # 같은 DUT + CODESYS 형태 스탠드인 마스터 (CI)
```

---

## 0. 지금 가능한 것과 막힌 것

| 항목 | 상태 |
|------|------|
| 우리 DUT (Modbus TCP 서버 + `fake_sensor`) | **가능.** 스크립트가 빌드·기동. `PREEMPT_RT` / `CAP_NET_RAW` 없음 |
| 같은 리눅스 박스의 SoftPLC 런타임 | 사용자 박스에 설치·기동은 됨. **이 저장소 CI/에이전트에서는 안 돌림** |
| Windows CODESYS Development System | 에이전트 VM 에 없음. Wine 설치 실패 시 **부트 앱을 못 넣음** |
| SoftPLC 보안 (신규 4.22 계열) | `[CmpApp] SECURITY.UnsignedApplicationFileTransfer=DENY` 가 신규 cfg 기본. 서명되지 않은 앱 전송 거부. 비대칭 인증 |
| 데모 런타임 | 라이선스 없으면 **2시간** 후 종료. 재시작으로 다시 2시간 |
| EIP Scanner / PN Controller | 런타임 패키지에 포함되는 경우가 많음. **IDE 에서 디바이스 트리에 넣어야** 함. 앱 없으면 스캐너/컨트롤러가 DUT 에 붙지 않음 |
| SLMP | CODESYS 에 **네이티브 마스터 없음.** 이 경로의 정본이 아님 |
| EtherCAT / CC-Link | 이 트랙에서 다루지 않음 (미머지) |

스탠드인: [`examples/codesys_shaped_modbus_master.py`](../examples/codesys_shaped_modbus_master.py)
는 SoftPLC 가 아직 앱이 없을 때 **같은 레지스터 맵을 주기 폴링**한다.
**CODESYS 가 아니다.** CI 용.

기존 Windows PN 체크리스트: [`tests/codesys_manual_lab.sh`](../tests/codesys_manual_lab.sh)
(IRT 없음, `CAP_NET_RAW` 랩). 이 문서는 **TCP Modbus 가 최소 경로**다.

---

## 1. DUT 기동 (자동화)

저장소 루트. sudo / 원시 소켓 / `:502` 없음.

```
./examples/run_codesys_dut.sh                 # 루프백 127.0.0.1:15560
./examples/run_codesys_dut.sh --lan           # 0.0.0.0:15560 (LAN / Docker 호스트)
./examples/run_codesys_dut.sh --stand-in --cycles 32
```

| 플래그 | 하는 일 |
|--------|--------|
| (없음) | `fake_sensor_app` 를 Modbus 서버로 띄우고 SoftPLC 가 쓸 IP/포트를 출력. **IDE 쪽은 수동** |
| `--stand-in` | DUT + 스탠드인 마스터 soak. CI 게이트 |
| `--lan` | [`config/example.codesys.modbus.json`](../config/example.codesys.modbus.json) (`0.0.0.0`) |
| `--protocol ethernetip` | Adapter DUT. 소켓 바인드는 `--lan` (live JSON) |
| `--protocol profinet` | mock 프로세스 이미지. **와이어에 컨트롤러를 붙이지 않음** |

스크립트는 CODESYS 프로세스를 시작하지 않는다.

---

## 2. SoftPLC 가 써야 할 IP / 포트

기본은 **특권 포트 502/44818 강제 없음.** Modbus 는 테스트 포트 **15560**.
같은 호스트 SoftPLC → 항상 `127.0.0.1`.

| 토폴로지 | DUT config | SoftPLC 가 넣는 IP:port |
|----------|------------|-------------------------|
| 같은 리눅스 호스트 (권장) | [`config/example.fake_sensor.json`](../config/example.fake_sensor.json) | **`127.0.0.1:15560`** unit 1 |
| DUT 가 0.0.0.0 바인드, SoftPLC 같은 호스트 | [`config/example.codesys.modbus.json`](../config/example.codesys.modbus.json) | **`127.0.0.1:15560`** |
| DUT 호스트, SoftPLC 가 Docker | `--lan` DUT | 브리지 게이트웨이 또는 `host.docker.internal:15560` |
| DUT 가 Docker, SoftPLC 호스트 | 컨테이너 `-p 15560:15560` + `--lan` | **호스트 IP:15560** |
| EIP live Adapter | [`config/example.codesys.ethernetip.json`](../config/example.codesys.ethernetip.json) | **`127.0.0.1:44818`** TCP, UDP IO **2222** |
| EIP mock (소켓 없음) | [`config/example.fake_sensor.ethernetip.json`](../config/example.fake_sensor.ethernetip.json) | SoftPLC 가 붙을 포트 **없음** |
| PN mock | [`config/example.fake_sensor.profinet.json`](../config/example.fake_sensor.profinet.json) / [`example.codesys.profinet.json`](../config/example.codesys.profinet.json) | L2 없음. 컨트롤러는 실 NIC 필요 (`docs/ctt_lab.md`) |

가짜 센서 앱은 1초마다 `barcode_value` / `temperature` 를 `fb_write_*` 로 게시한다.
프로토콜은 JSON 이 고른다. 앱은 [`include/fb_api.h`](../include/fb_api.h) 만 쓴다.

---

## 3. Modbus TCP Master (정본, 패키지 보통 포함)

Linux SL 런타임 패키지는 **Modbus TCP Master / Slave** 를 포함하는 경우가 많다
([Store: Control for Linux SL](https://store.codesys.com/en/codesys-control-linux-sl-1.html)).
라이선스 없는 데모는 2시간.

### 3.1 IDE 가 있을 때 (Windows 엔지니어링 PC)

Development System 이 있어야 애플리케이션을 SoftPLC 에 넣을 수 있다.
이 에이전트는 그 단계를 **수행하지 않았다.**

디바이스 트리 (이름은 설치 패키지에 따라 조금 다를 수 있다):

1. Ethernet 어댑터 (SoftPLC 쪽 NIC. 루프백이면 127.0.0.1 스택)
2. **Modbus TCP Master**
3. **Modbus TCP Slave** 하나 — 우리 DUT

### 3.2 Slave / 채널 설정

CODESYS 채널 **Offset 은 0-based** 다. 우리 JSON 의 `40001` 은 Offset **0**.
(`40017` = Offset 16). 40001 을 Offset 에 그대로 넣지 말 것.

**Slave (일반)**

| 항목 | 값 |
|------|-----|
| IP address | `127.0.0.1` (같은 호스트) 또는 DUT 주소 |
| Port | `15560` |
| Unit ID | `1` (`unit_id_any: false`) |
| Response timeout | 1000 ms 이상 권장 (비-RT SoftPLC) |
| Cycle / trigger | cyclic, 20–50 ms 도 충분. **8 ms RT 를 요구하지 않음** |

**채널 (I/O Mapping 전에 채널 탭)**

| 이름 | Access type | Offset | Length | 우리 포인트 |
|------|------------|--------|--------|-------------|
| barcode | Read Holding Registers (FC03) | `0` | 16 | `barcode_value` 32 ASCII, 레지스터당 2문자, 스왑 없음 |
| temperature | Read Holding Registers (FC03) | `16` | 1 | `temperature` uint16, `× 0.1` → ℃ |
| (선택) trigger | Write Single Coil (FC05) | `0` | 1 | `trigger` — `--lan` JSON 에만 있음 |

한 채널로 FC03 Offset 0 / Length 17 도 된다 (워드 0–15 바코드, 16 온도).

**문자열 디코딩:** 워드의 **하이 바이트가 앞 문자.** `LOT-A-0000` 이면 첫 워드 `0x4C4F` (`L` `O`).
`string_swap` 는 우리 예제에서 false.

**온도:** 매핑 WORD 를 REAL 로 `WORD_TO_REAL(raw) * 0.1`.

### 3.3 POU 힌트 (프로젝트 바이너리 아님)

I/O Mapping 에서 채널 배열을 변수에 연결한 뒤:

```
PROGRAM PLC_PRG
VAR
    (* Map these on the Modbus I/O Mapping tab — do not hard-code AT %IW here. *)
    barcode_w : ARRAY[0..15] OF WORD;
    temperature_raw : WORD;
    temperature_c : REAL;
END_VAR

temperature_c := WORD_TO_REAL(temperature_raw) * 0.1;
```

`.project` / 부트 앱 파일은 이 저장소에 **만들지 않는다** (Proprietary + IDE 필요).

### 3.4 SoftPLC 만 있고 IDE 가 없을 때

1. 런타임이 떠 있어도 **애플리케이션이 없으면** Modbus Master 채널이 DUT 를 폴링하지 않는다.
2. 신규 설치 cfg 는 보통 미서명 앱 전송 **DENY**. IDE 에서 서명하거나
   `CODESYSControl.cfg` 의 `SECURITY.UnsignedApplicationFileTransfer` 를
   랩에서만 완화 (제품 기본 DENY 를 CI 에 넣지 말 것).
3. 그때는 DUT + 스탠드인:

```
./examples/run_codesys_dut.sh --stand-in
```

---

## 4. EtherNet/IP Scanner (패키지·라이선스에 따름)

런타임 패키지에 **EtherNet/IP Scanner / Adapter** 가 들어가는 경우가 많다.
Application-based 라이선스에서는 EtherNet/IP 가 **Complex Fieldbus Instance** 로 잡힌다.
패키지가 없거나 데모 예산이 없으면 Scanner 를 디바이스 트리에 못 넣는다.

우리 DUT:

| 항목 | 값 |
|------|-----|
| 역할 | Adapter (Target). 스캐너는 SoftPLC |
| EDS | [`stacks/ethernetip/eds/FieldbusSensor.eds`](../stacks/ethernetip/eds/FieldbusSensor.eds) |
| Live config | [`config/example.codesys.ethernetip.json`](../config/example.codesys.ethernetip.json) (`mock: false`, `security_class: 0`) |
| TCP | `0.0.0.0:44818` → SoftPLC `127.0.0.1:44818` |
| UDP IO | `2222` |
| Input assembly | 150, 64 bytes: `[0..31]` barcode, float32 LE 온도 @32 |
| Output assembly | 101, 16 bytes |
| RPI | 8000 µs (8 ms). 비-RT SoftPLC 는 RPI 를 20–50 ms 로 늘려도 됨 |
| CIP Security HMAC | **끔** (`security_class: 0`). 우리 기본 예제는 class 1 이라 Scanner 가 FO 를 거절할 수 있음 |
| LLDP TX | live JSON 에서 off. `CAP_NET_RAW` 없음 |

```
./examples/run_codesys_dut.sh --protocol ethernetip --lan
```

IDE: EDS 임포트 → Scanner 아래 Adapter → Exclusive Owner 연결.
Class 1 이 실제로 붙었는지는 **IDE 가 있는 랩에서만** 확인한다.

소켓이 열리는지만 보는 스탠드인 (Scanner 아님):

```
./examples/run_codesys_dut.sh --protocol ethernetip --lan --stand-in
```

`example.fake_sensor.ethernetip.json` 은 `mock: true` 라 **포트가 없다.**

---

## 5. PROFINET Controller (패키지·L2, 이 시간 범위의 약)

런타임에 **PROFINET Controller / Device** 가 들어갈 수 있다. 역시 Complex Fieldbus.
**IRT / CC-C / RT Class 3 는 우리 제품 비목표** — 프로젝트에서 켜지 말 것.

| 항목 | 값 |
|------|-----|
| GSDML | [`stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`](../stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml) |
| NameOfStation | `sensor-line1` |
| VendorID / DeviceID | `0xABCD` / `0x0001` |
| Cycle | 8 ms, **RT Class 1 only** |
| `security_class` | SoftPLC 는 vendor integrity extension(HMAC)을 안 보냄 → 랩 JSON **0** (어댑터 기본값도 0) |
| mock JSON | AF_PACKET 없음. 프로세스 이미지만 |
| 라이브 | 실 NIC + 종종 `CAP_NET_RAW`. **이 헬퍼는 cap 을 요구·설정하지 않음** |

Windows 점대점 체크리스트는 기존 스크립트:

```
tests/codesys_manual_lab.sh
```

비-RT SoftPLC 의 cyclic jitter 는 우리 코어 8 ms 에이징(편차 ~0.1 ms)과 **다른 이야기**다.
PN RT1 스모크는 될 수 있어도 IRT 를 기대해서는 안 된다.

---

## 6. SLMP — SoftPLC 경로 아님

Mitsubishi SLMP Binary 3E 는 CODESYS 필드버스 목록에 없다.
랩 서버 [`config/example.fake_sensor.slmp.json`](../config/example.fake_sensor.slmp.json)
(`127.0.0.1:15561`) 은 CTT/앱 스토리용이다.

```
./examples/run_codesys_dut.sh --protocol slmp   # 거부 (SoftPLC 마스터 없음)
```

같은 박스에서 SLMP 를 쓰려면 우리 스택이 **클라이언트**로 PLC 에 붙는 제품 자세이지,
SoftPLC 가 마스터가 아니다.

---

## 7. CODESYS 형태 스탠드인 (CI, SoftPLC 아님)

[`examples/codesys_shaped_modbus_master.py`](../examples/codesys_shaped_modbus_master.py)

- TCP 마스터, FC03 holding 0..16, (옵션) FC05 coil 0
- 주기 기본 50 ms (SoftPLC 비-RT 폴링에 가깝게. **8 ms RT 클레임 없음**)
- `LOT-A-*` 바코드와 20–40 ℃ 범위만 확인
- 배너에 “not CODESYS” 를 찍음

```
./examples/run_codesys_dut.sh --stand-in --cycles 32
# 또는 DUT 가 이미 떠 있으면
python3 examples/codesys_shaped_modbus_master.py --host 127.0.0.1 --port 15560 --cycles 32
```

CMake 테스트 이름: `codesys_shaped_modbus_standin` (daemon+API 빌드).
GitHub job: `codesys-dut`.

---

## 8. SoftPLC 보안 · 2시간 · IDE 갭 (랩 메모)

신규 Control V3/Linux SL 설치의 `CODESYSControl.cfg` 예 (공식 권고 DENY):

```
[CmpApp]
SECURITY.UnsignedApplicationFileTransfer=DENY
```

| 값 | 의미 |
|----|------|
| `DENY` | 미서명 앱 전송 차단 (신규 기본에 가까움) |
| `ALLOW_WITH_WARNING` | 기존 cfg 호환 기본 |
| `ALLOW` | 허용 (권장하지 않음) |

Wine 으로 Windows Development System 을 못 올리면:

- 런타임만으로는 I/O 매핑이 있는 부트 앱을 만들 수 없다
- 우리 쪽은 DUT 를 띄우고 스탠드인으로 맵을 증명한다
- 사용자가 IDE 있는 Windows PC 에서 이 문서 3장을 따라 앱을 넣는 것이 다음 단계

비대칭 사용자 인증(디바이스 로그인)은 IDE/런타임 설정이다. 이 저장소가 우회하지 않는다.

---

## 9. 실시간 · 하지 않는 것

- **PREEMPT_RT 를 요구하지 않는다.** Modbus TCP 마스터는 일반 Linux 스케줄로 충분하다.
- 코어 8 ms 에이징 수치를 SoftPLC / PN IRT 와 섞지 말 것.
- `CAP_NET_RAW` 를 이 경로에 넣지 않음. PN 라이브는 별도 랩 ([`ctt_lab.md`](ctt_lab.md)).
- `:502` / `:5000` 를 CI 에 바인드하지 않음.
- EtherCAT / CC-Link 를 이 PR 에 넣지 않음.

---

## 10. 관련

| 문서 / 스크립트 | 역할 |
|-----------------|------|
| [`examples/run_codesys_dut.sh`](../examples/run_codesys_dut.sh) | DUT 기동 |
| [`examples/codesys_shaped_modbus_master.py`](../examples/codesys_shaped_modbus_master.py) | 스탠드인 마스터 |
| [`examples/README.md`](../examples/README.md) | fake_sensor / mock 플로 |
| [`docs/modbus_stack.md`](modbus_stack.md) | 주소·FC |
| [`docs/ethernetip_guide.md`](ethernetip_guide.md) | Adapter |
| [`docs/ctt_lab.md`](ctt_lab.md) | veth / Windows CODESYS PN |
| [`tests/codesys_manual_lab.sh`](../tests/codesys_manual_lab.sh) | Windows PN 체크리스트 |
