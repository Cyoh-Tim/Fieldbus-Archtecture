# examples

장비 없이(PLC·NIC·`CAP_NET_RAW` 없음) 제품 스토리를 보여 주는 앱 예제다.

**이건 인증이 아니다.** CTT green 은 PI / ODVA / Modbus.org / Mitsubishi 공인
랩 evidence 가 아니다. 내부 mock 게이트일 뿐이다.

한 화면 데모 스크립트: [`docs/demo.md`](../docs/demo.md).
JSON 애니메이션: [`docs/json-config-flow.html`](../docs/json-config-flow.html).
CTT 커버리지 보드 (인증 아님): [`docs/ctt_board.html`](../docs/ctt_board.html).

앱은 프로토콜 헤더 없이 [`include/fb_api.h`](../include/fb_api.h) 만 포함한다.
포인트 의미는 [`docs/app_api.md`](../docs/app_api.md). 프로토콜은 config JSON
이 고른다. 한 줄 요약: [`docs/demo.md`](../docs/demo.md).
브라우저 인덱스: [`docs/index.html`](../docs/index.html).

## 한 방에 보기 (권장)

저장소 루트에서 **네 프로토콜** (Modbus TCP, SLMP Binary 3E, EtherNet/IP,
PROFINET CC-B):

```
./examples/run_mock_flow.sh
./examples/run_mock_flow.sh all
```

하나만:

```
./examples/run_mock_flow.sh modbus
./examples/run_mock_flow.sh slmp
./examples/run_mock_flow.sh ethernetip
./examples/run_mock_flow.sh profinet
```

이미 구성한 빌드 트리를 재사용할 때:

```
cmake --build build --target run_mock_flow
```

스크립트가 프로토콜마다 하는 일:

1. `BUILD_DAEMON=ON` `BUILD_API=ON` `BUILD_CTT=ON` 으로 데몬/API + `fake_sensor_app` + CTT 를 빌드한다
2. `fake_sensor_app --once <config>` 가 가짜 바코드/온도를 `fb_write_*` 로 게시하고, 같은 세션 `fb_read_*` 로 읽힌 값을 stdout 에 찍는다 (불일치면 non-zero)
3. `ctest -LE soak_ci -L <label>` 로 해당 프로토콜 CTT mock 게이트를 돌린다 (실패 시 non-zero)

| 인자 | config | ctest 라벨 |
|------|--------|------------|
| `modbus` | [`config/example.fake_sensor.json`](../config/example.fake_sensor.json) | `modbus` |
| `slmp` | [`config/example.fake_sensor.slmp.json`](../config/example.fake_sensor.slmp.json) | `slmp` |
| `ethernetip` | [`config/example.fake_sensor.ethernetip.json`](../config/example.fake_sensor.ethernetip.json) | `ethernetip` |
| `profinet` | [`config/example.fake_sensor.profinet.json`](../config/example.fake_sensor.profinet.json) | `profinet` |

CTT 는 떠 있는 `fake_sensor_app` 소켓에 붙지 않는다. DUT 는 in-process
스택이다 (`stacks/modbus/`, `stacks/slmp/`, `stacks/ethernetip/`,
`stacks/profinet/`). 순서는 “앱이 포인트를 읽고 쓴다 → 이어서 같은 스택의
CTT 게이트도 통과한다” 는 **제품 스토리**다.

## fake_sensor_app

한 바이너리, config 로 프로토콜 선택. 가짜 센서 앱이 PLC가 읽을 포인트를
게시한다.

```
cmake -S . -B build -DBUILD_DAEMON=ON -DBUILD_API=ON
cmake --build build --target fake_sensor_app
./build/fake_sensor_app --once config/example.fake_sensor.json
./build/fake_sensor_app --once config/example.fake_sensor.slmp.json
./build/fake_sensor_app --once config/example.fake_sensor.ethernetip.json
./build/fake_sensor_app --once config/example.fake_sensor.profinet.json
./build/fake_sensor_app --seconds 5    # Ctrl+C 로도 종료
```

| 옵션 | 동작 |
|------|------|
| (없음) | `fb_start` 후 1초마다 게시+readback. SIGINT/SIGTERM 으로 정리 종료 |
| `--once` | 한 번 게시+readback 후 종료 (스크립트/CI) |
| `--seconds N` | N초 동안 1초 간격 |
| `--cycles N` | `cycle_ms` 간격으로 N번 |

기본 설정은 기존과 같다: Modbus TCP 서버 루프백
[`config/example.fake_sensor.json`](../config/example.fake_sensor.json)
(`127.0.0.1:15560`, 테스트 포트와 겹치지 않음).

### 프로토콜별 mock 설정

장비 없이 `fb_open` 이 성공하도록 mock/루프백만 쓴다.

| 프로토콜 | 역할 | mock 노브 | 포트/바인드 |
|----------|------|-----------|-------------|
| Modbus TCP | 서버(슬레이브) | 루프백 listen | `127.0.0.1:15560` |
| SLMP Binary 3E | **랩 서버**(시뮬레이터) | 루프백 listen | `127.0.0.1:15561` |
| EtherNet/IP | Adapter | `"mock": true`, `"iface": "mock"` | 소켓 bind 없음 (포트는 문서용) |
| PROFINET CC-B / RT1 | Device | `"iface": "mock"` | AF_PACKET/UDP 없음 |

제품 SLMP 기본 자세는 PLC **클라이언트**다 ([`config/example.slmp.json`](../config/example.slmp.json)).
이 예제만 PLC 없이 로컬 디바이스 맵에 게시하려고 랩 서버를 켠다. ASCII/4E 는
쓰지 않는다.

EtherNet/IP · PROFINET 의 `temperature` 는 프로세스 이미지 **float32** 다
(Modbus/SLMP 는 holding/D 레지스터 `uint16` + `scale: 0.1`). 앱은 둘 다
`fb_write_f32` / `fb_read_f32` 만 쓴다.

PROFINET mock 에는 AR 이 없어서 `health.connected` 가 0 일 수 있다. 입력
프로세스 이미지에 대한 `fb_write_*` / `fb_read_*` 는 그대로 돈다. IRT / CC-C
는 켜지 않는다.

### access (PLC 관점 — 앱이 쓰는 이유)

config `access` 는 PLC 기준이다. `fb_api.h` 와 같다.

| config | PLC | 이 앱 |
|--------|-----|--------|
| `"read"` | 읽음 | `fb_write_string` / `fb_write_f32` 로 **게시**. 같은 세션 `fb_read_*` 로 확인 |
| `"write"` | 씀 | 앱은 `fb_read_*` 만. write → `FB_ERR_PERM` |
| `"readwrite"` | 둘 다 | 둘 다 |

`barcode_value` / `temperature` 는 `"access": "read"` 이다. 센서 앱이 값을 넣고,
PLC가 읽는다. stdout 의 `read  barcode_value=...` 는 그 값이 세션 안에
**실제로 들어 있다**는 뜻이다.

최소 앱은 [`fb_api_demo.c`](fb_api_demo.c) (`fb_open` / list / 선택적 한 포인트
read·write).

## 한계 (CTT 와 라이브 앱)

- CTT 는 라이브 `fake_sensor_app` 에 붙지 않는다. 게이트는 in-process DUT.
- SLMP 제품 클라이언트(원격 PLC) 루프백은 이 플로에 없다. 가장 가까운 경로는
  랩 서버 맵 + `ctest -L slmp`.
- EtherNet/IP Class 1 을 떠 있는 앱 소켓으로 도는 랩은 `mock: false` + 스캐너가
  필요하고 기본 플로가 아니다.
- PROFINET 라이브 AF_PACKET 랩은 `CAP_NET_RAW` 가 필요하며
  `tests/run_ctt_lab.sh` 쪽이다. 기본 플로는 `iface: mock`.

코어에 프로토콜 분기를 넣지 말 것.

## 소프트웨어 마스터 soak (CODESYS 없음)

우리 DUT 스택에 실제 TCP(/UDP) 로 주기 읽기/쓰기. PROFINET 라이브 마스터 없음.

```
./examples/run_sw_master_soak.sh              # Modbus + SLMP + EIP
./examples/run_sw_master_soak.sh modbus --seconds 8
```

문서: [`docs/sw_master_io.md`](../docs/sw_master_io.md).
CODESYS 경로와 다름 (`--stand-in` ≠ SoftPLC). 인증 아님.

## CODESYS SoftPLC 마스터 (DUT 쪽)

SoftPLC 를 Modbus TCP 마스터로 붙일 때 우리 쪽 기동:

```
./examples/run_codesys_dut.sh              # 127.0.0.1:15560, IDE 쪽은 수동
./examples/run_codesys_dut.sh --stand-in  # CI: CODESYS 형태 스탠드인 (SoftPLC 아님)
```

문서: [`docs/codesys_master_io.md`](../docs/codesys_master_io.md).
Windows PN 체크리스트는 [`tests/codesys_manual_lab.sh`](../tests/codesys_manual_lab.sh).

## 인증이 아닌 것

- `ctest -L modbus` green ≠ Modbus.org conformance
- `ctest -L slmp` green ≠ Mitsubishi 공식 인증
- PN/EIP CTT green ≠ PI / ODVA 인증
- 이 예제는 공인 랩·DoC 를 대체하지 않는다
- `--stand-in` green ≠ CODESYS 가 IO 를 돌린 것
- `run_sw_master_soak.sh` green ≠ PI / ODVA / Modbus.org / Mitsubishi / CODESYS 인증
- PROFINET 소프트웨어 마스터 라이브 경로 없음 (mock / 랩 NIC 만)
