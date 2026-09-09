# 소프트웨어 마스터 soak — CODESYS 없이 우리 스택에 실제 IO

이 저장소 **디바이스/서버 스택**을 DUT 로 두고, CODESYS 런타임·IDE 없이
**소프트웨어 마스터**가 주기적으로 읽고 쓴다.

**인증이 아니다.** PI / ODVA / Modbus.org / Mitsubishi / CODESYS 랩 결과가 아니다.
**PREEMPT_RT 없음.** 기본 CI 에 **`CAP_NET_RAW` 없음.** 특권 포트 `:502` / `:5000` /
`:44818` 을 바인드하지 않는다.

한 줄:

```
./examples/run_sw_master_soak.sh              # Modbus + SLMP + EIP (sequential)
./examples/run_sw_master_soak.sh modbus --seconds 8
./examples/run_sw_master_soak.sh all --seconds 3
```

CODESYS SoftPLC 경로(IDE 앱은 수동)는 별문서:
[`codesys_master_io.md`](codesys_master_io.md).

---

## 0. 무엇이 라이브이고 무엇이 아닌가

| 경로 | 마스터 | DUT | 전송 | CI |
|------|--------|-----|------|----|
| **Modbus TCP** | `examples/sw_master.py --protocol modbus` | `fake_sensor_app` + [`config/example.fake_sensor.json`](../config/example.fake_sensor.json) | **라이브 TCP** `127.0.0.1:15560` | 짧음 (초) |
| **SLMP Binary 3E** | 같은 스크립트 `--protocol slmp` | 랩 **서버** [`example.fake_sensor.slmp.json`](../config/example.fake_sensor.slmp.json) | **라이브 TCP** `127.0.0.1:15561` | 짧음 |
| **EtherNet/IP** | `--protocol ethernetip` (기본 Class 1) | 라이브 Adapter [`example.sw_master.ethernetip.json`](../config/example.sw_master.ethernetip.json) (`mock: false`) | **라이브 TCP** `15562` + **Class 1 UDP** `15563` | 짧음 |
| **PROFINET** | **없음** (가짜 SoftPLC / Controller 클레임 없음) | mock Device [`example.fake_sensor.profinet.json`](../config/example.fake_sensor.profinet.json) | in-process CTT mock (`iface: mock`) | `run_mock_flow.sh profinet` |
| CTT mock soak | CTT 플러그인 (마스터 스텁) | in-process `stacks/*` | 소켓 없음 | `tests/run_mock_soak.sh` |

제품 SLMP 기본 자세는 PLC **클라이언트**다 ([`example.slmp.json`](../config/example.slmp.json)).
이 soak 의 DUT 만 PLC 없이 루프백하려고 **랩 서버**를 켠다. ASCII / 4E 는 쓰지 않는다.

EtherNet/IP Originator 스택 API 는 명시적 Get/Set 이 정본이다. 이 마스터는
**파이썬 스캐너**가 Forward Open + Class 1 UDP 를 우리 Adapter 에 붙인다.
`--eip-mode explicit` 는 같은 TCP 세션에서 Assembly 150 을 주기 Get_Attribute_Single
한다 (Class 1 아님 — 배너/결과 줄에 명시).

CTT YAML Class 1 은 **in-process** (`eip_stack_handle_encap` / `handle_io`) 다.
이 문서의 EIP soak 와 섞지 말 것.

---

## 1. 실행

저장소 루트. sudo / 원시 소켓 없음.

```
./examples/run_sw_master_soak.sh                 # 세 프로토콜, 각 4초
./examples/run_sw_master_soak.sh modbus
./examples/run_sw_master_soak.sh slmp --seconds 8
./examples/run_sw_master_soak.sh ethernetip --eip-mode class1
./examples/run_sw_master_soak.sh ethernetip --eip-mode explicit
./examples/run_sw_master_soak.sh profinet         # 라이브 마스터 없음 — mock 안내만
```

이미 구성한 빌드:

```
cmake --build build --target fake_sensor_app
BUILD_DIR=build ./examples/run_sw_master_soak.sh --skip-configure --skip-build all --seconds 3
```

DUT 가 이미 떠 있으면 마스터만:

```
python3 examples/sw_master.py --protocol modbus --host 127.0.0.1 --port 15560 --seconds 4
python3 examples/sw_master.py --protocol slmp --slmp-port 15561 --seconds 4
python3 examples/sw_master.py --protocol ethernetip --eip-port 15562 --eip-udp-port 15563 --seconds 4
```

| 플래그 | 의미 |
|--------|------|
| `--seconds N` | 프로토콜당 마스터 벽시간 (기본 4). CI 는 3 |
| `--cycles N` | 폴 횟수 (`--seconds` 보다 우선하려면 스크립트에 `--cycles` ) |
| `--period-ms N` | 사이클 주기. 기본 **50 ms**. **8 ms RT 클레임 없음** |
| `--eip-mode class1\|explicit` | Class 1 UDP (기본) 또는 명시적 메시징만 |

결과 한 줄 예:

```
sw_master result protocol=modbus transport=tcp_loopback ok=… fail=0 cycles=…
  period_ms=50.0 period_avg_ms=… jitter_max_ms=… elapsed_s=…
```

`ok>0` 이고 `fail=0` 이어야 스크립트가 0 으로 끝난다.
`jitter_max_ms` 는 공유 VM 스파이크가 지배할 수 있다. 인증 수치가 아니다.

가짜 센서는 약 1초마다 `barcode_value=LOT-A-*`, 온도 20–40 ℃ 를 `fb_write_*` 로 게시한다.
마스터는 그 값을 와이어에서 읽는다.

---

## 2. 프로토콜별 맵

### 2.1 Modbus TCP

DUT: 서버/슬레이브. 마스터: TCP 클라이언트.

| 항목 | 값 |
|------|-----|
| 주소 | `127.0.0.1:15560` unit 1 |
| 읽기 | FC03 holding offset 0, 17워드 — 바코드 16 + 온도 1 (`× 0.1` ℃) |
| 쓰기 | FC16 holding offset 20, 1워드 (사이클 카운터) 후 같은 주소 FC03 확인 |

libmodbus 없음. 우리 `stacks/modbus/` 서버.

### 2.2 SLMP Binary 3E

DUT: **랩 서버** (`role: server`). 마스터: Binary 3E **클라이언트** (PLC 가 마스터인
제품 자세의 반대 방향 — 루프백 soak 용).

| 항목 | 값 |
|------|-----|
| 주소 | `127.0.0.1:15561` |
| 프레임 | `0x0050` 요청 / `0x00D0` 응답. ASCII/4E 없음 |
| 읽기 | batch read `0x0401` 디바이스 D(`0xA8`) 선두 100, 16워드 (바코드) + 선두 110, 1워드 (온도 `× 0.1` ℃) |
| 쓰기 | batch write `0x1401` D200, 1워드 후 읽기 확인 |

### 2.3 EtherNet/IP

DUT: Adapter (`mock: false`, `security_class: 0`, LLDP/ACD off).

| 항목 | 값 |
|------|-----|
| TCP | `127.0.0.1:15562` Encapsulation |
| UDP IO | `127.0.0.1:15563` (특권 포트 아님, `CAP_NET_RAW` 없음) |
| Identity | Get_Attribute_Single class 0x01 inst 1 attr 1 → vendor `0xABCD` |
| Class 1 | Forward Open (`0x54`) + O→T / T→O. Input assembly 150 (64 B): 바코드[0..31] + float32 온도 @32 (`fb_api` 는 프로세스 이미지 F32 를 **BE** 로 씀. 마스터는 BE/LE 중 센서 범위에 맞는 쪽을 사용). Output 101 (16 B) 에 사이클 카운터 |
| explicit 모드 | 같은 TCP 세션에서 Assembly 150 attr 3 주기 Get, 101 attr 3 Set. **Class 1 이 아님** |

Class 1 이 실패하면 마스터가 explicit 로 **폴백**하고 결과 `transport=` 에 명시한다.
in-process CTT 로 조용히 바꾸지 않는다.

---

## 3. CODESYS 경로와의 차이

| | 소프트웨어 마스터 (이 문서) | CODESYS ([`codesys_master_io.md`](codesys_master_io.md)) |
|--|------------------------------|----------------------------------------------------------|
| 마스터 프로세스 | `examples/sw_master.py` (CI 가 돌림) | Control for Linux SL + **IDE 부트 앱** (이 CI/에이전트에 없음) |
| 목적 | 우리 서버/Adapter 에 대한 **실제 TCP(/UDP) IO** soak | SoftPLC 가 마스터일 때 DUT 쪽 기동·맵 문서 |
| SLMP | **있다** (Binary 3E 클라이언트) | SoftPLC 네이티브 마스터 **없음** |
| EIP | Class 1 루프백 또는 explicit | Scanner 는 패키지+IDE. 스탠드인은 RegisterSession 프로브만 |
| PN | 라이브 마스터 **없음** (mock 안내) | Controller 는 패키지+실 NIC. 헬퍼는 mock 프로세스 이미지 |
| 스탠드인 스크립트 | `run_sw_master_soak.sh` | `run_codesys_dut.sh --stand-in` (CODESYS 형태 Modbus만) |

`--stand-in` green ≠ SoftPLC 가 IO 를 돌린 것.
이 soak green ≠ CODESYS / 공인 랩.

---

## 4. PROFINET 한계 (가짜 SoftPLC 없음)

PROFINET Device 는 L2 (DCP / RTC1). 소프트웨어 마스터를 TCP 루프백으로
흉내 내면 **컨트롤러가 붙은 것처럼** 보이므로 하지 않는다.

장비 없는 경로:

```
./examples/run_mock_flow.sh profinet
./examples/run_sw_master_soak.sh profinet   # 안내만 출력, 라이브 마스터 없음
```

라이브 RT Class 1 은 실 NIC + 종종 `CAP_NET_RAW` — [`ctt_lab.md`](ctt_lab.md).
**IRT / CC-C 는 제품 비목표.**

---

## 5. CI

CMake 테스트 이름: `sw_master_soak_short` (라벨 `sw_master`, daemon+API 빌드).
GitHub job: `sw-master-soak`.

```
ctest --test-dir build --output-on-failure -L sw_master
```

수 초. 시간 단위 soak 가 아니다. 30s CTT `soak_ci` / nightly mock soak 와 별개.

---

## 6. 하지 않는 것

- PREEMPT_RT / isolcpus / 8 ms 인증 jitter
- `CAP_NET_RAW`, AF_PACKET, 실 NIC
- `:502` / Mitsubishi `:5000` / ODVA `:44818` 를 기본 CI 에 바인드
- CODESYS 런타임·부트 앱
- PROFINET 라이브 컨트롤러 / IRT / CC-C
- CC-Link / EtherCAT
- 공인 인증 클레임

---

## 7. 관련

| 문서 / 스크립트 | 역할 |
|-----------------|------|
| [`examples/sw_master.py`](../examples/sw_master.py) | 세 프로토콜 마스터 |
| [`examples/run_sw_master_soak.sh`](../examples/run_sw_master_soak.sh) | DUT + 마스터 엔트리 |
| [`examples/run_codesys_dut.sh`](../examples/run_codesys_dut.sh) | CODESYS DUT 헬퍼 (스탠드인 ≠ SoftPLC) |
| [`examples/run_mock_flow.sh`](../examples/run_mock_flow.sh) | fb_api + CTT **in-process** mock |
| [`tests/run_mock_soak.sh`](../tests/run_mock_soak.sh) | CTT timed mock soak |
| [`modbus_stack.md`](modbus_stack.md) · [`slmp_stack.md`](slmp_stack.md) · [`ethernetip_guide.md`](ethernetip_guide.md) | 스택 |
