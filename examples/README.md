# examples

장비 없이(PLC·NIC·`CAP_NET_RAW` 없음) 제품 스토리를 보여 주는 앱 예제다.

**이건 인증이 아니다.** CTT green 은 PI / ODVA / Modbus.org 공인 랩 evidence 가
아니다. 내부 mock 게이트일 뿐이다.

앱은 프로토콜 헤더 없이 [`include/fb_api.h`](../include/fb_api.h) 만 포함한다.
포인트 의미는 [`docs/app_api.md`](../docs/app_api.md).

## 한 방에 보기 (권장)

저장소 루트에서:

```
./examples/run_mock_flow.sh
```

또는 이미 구성한 빌드 트리를 재사용할 때:

```
cmake --build build --target run_mock_flow
```

스크립트가 하는 일:

1. `BUILD_DAEMON=ON` `BUILD_API=ON` `BUILD_CTT=ON` 으로 데몬/API + `fake_sensor_app` + CTT 를 빌드한다
2. `fake_sensor_app --once` 가 가짜 바코드/온도를 `fb_write_*` 로 게시하고, 같은 세션 `fb_read_*` 로 읽힌 값을 stdout 에 찍는다 (불일치면 non-zero)
3. `ctest -LE soak_ci -L modbus` 로 **Modbus TCP CTT mock** 게이트를 돌린다 (실패 시 non-zero)

CTT 는 떠 있는 `fake_sensor_app` 소켓에 붙지 않는다. DUT 는 in-process
`stacks/modbus/` (`mb_stack_handle_adu`) 이다. 순서는 “앱이 포인트를 읽고 쓴다 →
이어서 같은 스택의 CTT 게이트도 통과한다” 는 **제품 스토리**다.

## fake_sensor_app

Modbus TCP **서버**(슬레이브) 루프백. 가짜 센서 앱이 PLC가 읽을 포인트를 게시한다.

```
cmake -S . -B build -DBUILD_DAEMON=ON -DBUILD_API=ON
cmake --build build --target fake_sensor_app
./build/fake_sensor_app --once config/example.fake_sensor.json
./build/fake_sensor_app --seconds 5    # Ctrl+C 로도 종료
./build/fake_sensor_app config/example.modbus.json   # 같은 barcode/temperature 포인트
```

| 옵션 | 동작 |
|------|------|
| (없음) | `fb_start` 후 1초마다 게시+readback. SIGINT/SIGTERM 으로 정리 종료 |
| `--once` | 한 번 게시+readback 후 종료 (스크립트/CI) |
| `--seconds N` | N초 동안 1초 간격 |
| `--cycles N` | `cycle_ms` 간격으로 N번 |

기본 설정: [`config/example.fake_sensor.json`](../config/example.fake_sensor.json)
(`127.0.0.1:15560`, 테스트 포트와 겹치지 않음).

### access (PLC 관점 — 앱이 쓰는 이유)

config `access` 는 PLC 기준이다. `fb_api.h` 와 같다.

| config | PLC | 이 앱 |
|--------|-----|--------|
| `"read"` | 읽음 (예: FC03 holding) | `fb_write_string` / `fb_write_f32` 로 **게시**. 같은 세션 `fb_read_*` 로 확인 |
| `"write"` | 씀 | 앱은 `fb_read_*` 만. write → `FB_ERR_PERM` |
| `"readwrite"` | 둘 다 | 둘 다 |

`barcode_value` / `temperature` 는 `"access": "read"` 이다. 센서 앱이 값을 넣고,
PLC(마스터)가 레지스터를 읽는다. stdout 의 `read  barcode_value=...` 는 그 값이
세션 안에 **실제로 들어 있다**는 뜻이다.

최소 앱은 [`fb_api_demo.c`](fb_api_demo.c) (`fb_open` / list / 선택적 한 포인트
read·write).

## 다른 프로토콜 (후속)

기본 경로는 **Modbus TCP 서버 루프백**이 가장 단순하다. SLMP / EtherNet/IP /
PROFINET 도 같은 `fb_api` 포인트 모델이지만, 기본 mock 플로에는 넣지 않았다.

- SLMP 예제 config 는 PLC **클라이언트**라 상대 주소가 필요하다
- EtherNet/IP · PROFINET CTT mock 은 `ctest -L ethernetip` / PN 시나리오 (NIC 없음).
  라이브 앱에 붙는 랩은 `CAP_NET_RAW` 가 필요하고 기본 플로가 아니다

후속에서 프로토콜만 바꿔 같은 앱 패턴을 붙이면 된다. 코어에 프로토콜 분기를
넣지 말 것.

## 인증이 아닌 것

- `ctest -L modbus` green ≠ Modbus.org conformance
- PN/EIP CTT green ≠ PI / ODVA 인증
- 이 예제는 공인 랩·DoC 를 대체하지 않는다
