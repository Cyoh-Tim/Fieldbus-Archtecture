# Application C API (`fb_api`)

Apps talk to **named points**, not to Modbus / SLMP / EtherNet/IP / PROFINET.
Protocol knowledge stays in adapters and stacks. Include only `fb_api.h`.

한 프로세스·한 라이브러리에서 config JSON 의 `"protocol"` 이 **한 개**의
어댑터를 고른다 (`modbus_tcp` | `slmp` | `ethernetip` | `profinet`; `cclink` 스텁).

## English summary

- Open a config with `fb_open`, then `fb_read_*` / `fb_write_*` by point **name**.
- Default cycle model (embedded-safe): **no internal thread**. Call `fb_poll()`
  each cycle, or `fb_run(stop_flag)` to block like the daemon. Optional
  `fb_start()` / `fb_stop()` starts a mutex-protected cycle thread.
- `fb_reload` is an in-process **restart-of-session**: the new file is loaded
  and `init` completes *before* the live adapter is disconnected. Init failure
  keeps the old session. Connect of the new session happens after old
  disconnect (same TCP/NIC bind). If new connect fails, the old adapter is
  started again and `generation` is unchanged. No daemon IPC.
- Typed reads/writes take caller buffers with `cap` / `len`. `FB_ERR_NOSPC`
  if the string/bytes buffer is too small. `FB_ERR_PERM` if the app writes a
  PLC-write-only point (`access: "write"` in config).
- PROFINET: CC-B + RT Class 1 only (no IRT/CC-C). The stack does **not**
  change the OS NIC IP; set the interface address to match config/DCP.

## 앱이 하는 일

```c
#include "fb_api.h"

fb_runtime_t *rt = NULL;
if (fb_open("config/example.modbus.json", &rt) != FB_OK) {
    return 1;
}

char barcode[64];
fb_write_string(rt, "barcode_value", "ABC123");
fb_read_string(rt, "barcode_value", barcode, sizeof(barcode));

float t;
fb_write_f32(rt, "temperature", 25.5f); /* scale/offset 은 어댑터가 적용 */
fb_read_f32(rt, "temperature", &t);

fb_health_t h;
fb_health(rt, &h); /* connected, protocol, cycle_ms, generation, last_error */

size_t n = 0;
fb_list_points(rt, NULL, 0, &n); /* UI/툴용 메타데이터 */

fb_poll(rt);   /* 임베디드: 앱 루프에서 한 사이클 */
fb_close(rt);
```

링크: CMake 타깃 `fieldbus` (데몬과 동일한 코어+어댑터). 공개 헤더는
`include/fb_api.h` 만 설치한다. `protocol_adapter.h` / `stacks/` 는 앱 API가 아니다.

데몬 `multiproto_daemon` 은 이 API 의 얇은 클라이언트다 (`fb_open` + `fb_run` +
`fb_close`).

## 에러 코드

| 코드 | 의미 |
|---|---|
| `FB_OK` | 성공 |
| `FB_ERR_INVAL` | NULL/빈 인자, 경로·이름 길이 초과 |
| `FB_ERR_NOENT` | 없는 포인트 이름 |
| `FB_ERR_IO` | 어댑터 connect/read/write I/O |
| `FB_ERR_TYPE` | 요청 타입과 포인트 `data_type` 불일치 |
| `FB_ERR_PERM` | `access: write`(PLC만 씀) 포인트에 앱이 write |
| `FB_ERR_STATE` | 세션/스레드 수명주기 (예: `fb_run` 중 `fb_start`) |
| `FB_ERR_NOMEM` | 할당 실패 |
| `FB_ERR_NOSPC` | 호출자 버퍼가 작음 (부분 기록 없음) |
| `FB_ERR_CONFIG` | 파일/JSON/`protocol` 레지스트리 |
| `FB_ERR_UNSUPPORTED` | 스텁 프로토콜 등 (`cclink`) |
| `FB_ERR_BUSY` | 예약 (향후 소프트 리로드 충돌) |

`fb_strerror()` 로 고정 문자열을 얻는다. ABI 확장을 위해 `FB_API_VERSION_*`
매크로와 `fb_api_version()` 이 있다. `fb_health_t` / `fb_point_info_t` 는
`reserved[]` 를 둔다.

## access (PLC 관점 — config 와 동일)

| config `access` | PLC | 앱 |
|---|---|---|
| `read` | 읽음 | `fb_write_*` 로 게시, readback 가능 |
| `write` | 씀 | `fb_read_*` 만. write → `FB_ERR_PERM` |
| `readwrite` | 둘 다 | 둘 다 |

## 스레딩

- 모든 세션 API(`fb_open`/`fb_close`/`fb_api_version`/`fb_strerror` 제외의
  핸들 사용)는 런타임 뮤텍스로 어댑터 호출을 직렬화한다.
- **기본값 (임베디드)**: 내부 스레드 없음. 실시간 루프에서 `fb_poll()` 또는
  데몬처럼 `fb_run(&stop)`.
- `fb_start()` 는 `CLOCK_MONOTONIC` + `clock_nanosleep` 로 기존 스케줄러와
  같은 주기 패턴의 스레드를 띄운다. 앱 읽기/쓰기와 동시 호출 가능.
- `fb_run()` 과 `fb_start()` 를 동시에 쓰지 말 것 (`FB_ERR_STATE`).
- 시그널 핸들러에서는 `volatile int stop` 만 세우고, `fb_close` 는 메인에서.

## `fb_reload`

커미셔닝용. 핫 리로드 IPC 는 없다.

1. 새 경로를 `config_load` + 레지스트리 + `adapter->init` 까지 **먼저** 검증.
   실패 시 기존 세션을 그대로 두고 에러 반환 (`generation` 불변).
2. 성공 시에만 락을 잡고 기존 `disconnect` → 새 `connect`.
3. 새 connect 실패 시 기존 어댑터를 다시 `connect` 하고 새 세션은 폐기.
   (기존 reconnect 마저 실패하면 `health.connected==0` 일 수 있음.
   세션 객체는 유지, `generation` 불변.)
4. 성공 시 `generation++`. 향후 소프트/하드 리로드를 구분할 카운터다.

프로토콜을 바꾸는 reload 는 지원하지만, 같은 bind 포트/NIC 를 쓰는 경우
위 2단계의 짧은 disconnect 공백이 있다.

## PROFINET / NIC

- 제품 범위: **CC-B + RT Class 1**. IRT / CC-C 는 영구 비목표.
- `protocol_params.ip` 등은 스택이 광고하는 주소다. **OS NIC IP 를 스택이
  바꾸지 않는다.** `iface` 를 실제 인터페이스로 두고, 그 NIC 주소를
  DCP/config IP 와 맞출 것. 상세: `docs/profinet_stack.md`.

## 빌드

`BUILD_DAEMON=ON` (기본) 이면 API 가 코어에 포함된다.
`BUILD_API=ON` (기본, 데몬과 함께) 이면 `test_fb_api`, `fb_api_demo`,
`fake_sensor_app`, 헤더 install 이 켜진다.

```
cmake -S . -B build-daemon -DBUILD_DAEMON=ON -DBUILD_API=ON
cmake --build build-daemon
./build-daemon/test_fb_api
./build-daemon/fb_api_demo config/example.modbus.json
./build-daemon/fake_sensor_app --once config/example.fake_sensor.json
./build-daemon/fake_sensor_app --once config/example.fake_sensor.slmp.json
./build-daemon/fake_sensor_app --once config/example.fake_sensor.ethernetip.json
./build-daemon/fake_sensor_app --once config/example.fake_sensor.profinet.json
```

장비 없는 게시→readback→CTT mock (Modbus / SLMP / EIP / PROFINET) 한 줄:
[`examples/README.md`](../examples/README.md) (`./examples/run_mock_flow.sh`).

CTT (`BUILD_DAEMON=OFF -DBUILD_CTT=ON`) 는 이 라이브러리를 링크하지 않으며
동작이 바뀌지 않는다.
