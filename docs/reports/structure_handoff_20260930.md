# 구조 분석 결과 — 수정 작업 인수인계 (2026-09-30)

내부 문서. **인증이 아니다.** 대상: `claude/nice-galileo-8l3hc2` @ `c10f32e` 이후.
배경 설명은 [`../protocols/README.md`](../protocols/README.md) 4.6절에 있다.

이 문서는 **수정 작업을 맡을 코딩 에이전트에게 넘기는 작업 목록**이다. 각 작업은
혼자 읽어도 착수할 수 있게 문제, 근거(`path:line`), 재현 방법, 수정 범위,
완료 조건을 담았다. 행 번호는 위 커밋 기준이다.

## 공통 규칙 (반드시 먼저 읽을 것)

- [`../../CLAUDE.md`](../../CLAUDE.md) 를 따른다. 특히:
  - 어댑터 작업은 해당 `adapters/<name>/` 안에서만 한다. 다른 어댑터 디렉토리는 건드리지 않는다.
  - `core/*.c` 에 `if (protocol == ...)` 식 분기를 넣지 않는다. 코어에 프로토콜별
    처리가 필요해 보이면 `include/protocol_adapter.h` 확장을 먼저 제안한다.
  - 에러는 음수 errno 로 반환하고 `LOG_ERROR`/`LOG_WARN` 을 쓴다. `printf` 는 쓰지 않는다.
  - PROFINET IRT / CC-C 는 켜지 않는다.
- 작업 하나당 PR 하나. 각 PR 에 재현 테스트(수정 전에는 실패하고 수정 후 통과)를 넣는다.
- 검증 명령:
  ```
  cmake -S . -B build -DBUILD_DAEMON=ON -DBUILD_CTT=ON -DBUILD_API=ON \
        -DENABLE_PN_TESTS=ON -DENABLE_EIP_TESTS=ON
  cmake --build build -j
  ctest --test-dir build --output-on-failure -LE soak_ci
  ```

## 작업 순서와 의존 관계

```
T0 (결정: 스케일·바이트 순서 책임 소재) ──▶ T1 (EIP 바이트 순서) ──▶ T2 (EIP/PN 스케일)
T3 (클라이언트 모드 블로킹)          ─ 독립
T4 (PN RT 송신 주기) ──▶ T5 (최소 주기 제한)
T6 (scheduler 중복 정리) ──▶ T7 (µs 지연 측정)
T8 (config_loader 정리)              ─ 독립
```

| ID | 우선순위 | 요약 | 결정 필요 |
|---|---|---|---|
| T0 | 선행 | 스케일/바이트 순서를 코어와 어댑터 중 누가 맡는지 정하기 | **예 (사람)** |
| T1 | 높음 | EtherNet/IP 숫자 포인트의 바이트 순서가 뒤집힘 | T0 이후 |
| T2 | 높음 | EIP/PN 포인트에 `scale` 을 주면 값이 깨짐 | T0 이후 |
| T3 | 중간 | Modbus/SLMP 클라이언트 모드의 블로킹이 사이클과 앱 API 를 막음 | 아니오 |
| T4 | 중간 | PROFINET RT 송신 주기에 협상값이 아닌 config 값을 씀 | 아니오 |
| T5 | 중간 | 컨트롤러가 요구하는 주기가 `cycle_ms` 보다 짧을 때 처리 | 아니오 |
| T6 | 낮음 | `core/scheduler.c` 가 쓰이지 않고 루프가 중복됨 | 아니오 |
| T7 | 낮음 | 사이클 지연을 ms 로 잘라서 측정함 | 아니오 |
| T8 | 낮음 | `config_loader.c` 가 로깅 규칙을 어기고 기능 매크로 위치가 틀림 | 아니오 |

---

## T0. 결정: 스케일·바이트 순서는 누구 책임인가

**현재 상태 (세 문서가 서로 다르게 말함):**
- [`../../CLAUDE.md`](../../CLAUDE.md): 코어는 `points` 를 해석하지 않는다.
- [`../design.md`](../design.md) 3.2: `data_type`/`byte_order`/`scale` 은 코어의 값 변환 레이어가 처리한다.
- `include/fb_api.h` 주석과 [`../app_api.md`](../app_api.md): scale/offset 은 어댑터가 적용한다.

**실제 코드:**
- 코어 `parse_points_meta` (`core/fb_api.c:299`)가 `data_type`/`access`/`length`/`scale`/`offset` 을 읽는다.
- 코어 `encode_numeric`/`decode_numeric` (`core/fb_api.c:551`, `:601`)은 숫자를 **항상 빅 엔디안**으로 만들고,
  `scale≠1` 이면 "어댑터가 이미 스케일을 적용한 float32(BE) 4바이트"라고 가정한다.
- 스케일 적용과 wire 순서 변환은 Modbus (`adapters/modbus/modbus_adapter.c:772`, `:819`)와
  SLMP (`adapters/slmp/slmp_adapter.c:840`, `:886`) 어댑터에만 있다.

**선택지:**
- **A (권장, 인터페이스 변경 없음):** "앱↔어댑터 경계의 숫자는 canonical big-endian 이고,
  스케일이 걸린 포인트는 float32(BE) 다. 스케일과 wire 바이트 순서는 **어댑터 책임**이다."
  이렇게 명문화하고, EIP/PN 어댑터를 Modbus/SLMP 와 같은 수준으로 맞춘다 (T1, T2).
  코어는 수정하지 않는다.
- B: 코어가 스케일과 바이트 순서를 전담하고 어댑터는 raw wire 바이트만 다룬다. 이 경우
  코어가 wire 바이트 순서를 알아야 하므로 `protocol_adapter.h` 에 "wire 바이트 순서" 같은
  메타데이터를 추가해야 한다(인터페이스 변경 → 사전 논의 필요). Modbus/SLMP 어댑터의
  기존 스케일 로직도 제거해야 한다.

**완료 조건:** 선택한 규칙을 `CLAUDE.md`, `docs/design.md` 3.2, `docs/app_api.md`,
`include/fb_api.h` 주석에 같은 문장으로 반영한다.

---

## T1. EtherNet/IP 숫자 포인트의 바이트 순서가 뒤집힘

**문제:** 코어가 만든 빅 엔디안 바이트를 EIP 어댑터가 변환 없이 Assembly 에 복사한다
(`adapters/ethernetip/ethernetip_adapter.c:463` `eip_write_point` / 읽기는
`eip_read_point` `:418`). CIP 의 `UINT`/`INT`/`UDINT`/`DINT`/`REAL`/`LREAL` 은
리틀 엔디안이므로 스캐너는 바이트가 뒤집힌 값을 본다. 읽기 방향(스캐너 → O→T 출력
Assembly → 앱)도 같은 이유로 뒤집힌다.

**재현 (수정 전 결과):**

```
config/example.ethernetip.json 의 status_word (uint16, assembly 150, byte_offset 32)
fb_write_u32(rt, "status_word", 300)
→ Assembly 바이트: 01 2C          (기대: 2C 01)
→ 스캐너가 읽는 UINT: 11265       (기대: 300)
```

재현용 하네스 (`protocol_params` 에 `"mock": true` 가 있으면 소켓 없이 동작):

```c
#include <stdio.h>
#include "fb_api.h"
int main(int argc, char **argv) {
    fb_runtime_t *rt = NULL;
    if (fb_open(argv[1], &rt) != FB_OK) return 1;
    fb_write_u32(rt, "status_word", 300);
    unsigned char b[8] = {0}; size_t n = 0;
    fb_read_bytes(rt, "status_word", b, sizeof b, &n);
    printf("%02X %02X -> CIP UINT %u\n", b[0], b[1], b[0] | (b[1] << 8));
    fb_close(rt);
    return 0;
}
```

(`fb_read_bytes` 는 변환 없는 원시 Assembly 바이트를 돌려준다.)

**수정 범위:** `adapters/ethernetip/` 만.
- EIP 포인트 파싱에 `data_type` 을 읽고(현재는 `length` 만 읽음, 약 88–112행),
  숫자 타입이면 write 는 BE→LE, read 는 LE→BE 로 변환한다.
- `string`/`bytes`/`bool` 은 변환하지 않는다.
- Originator 경로(`eip_stack_tag_read` 등 tag/CIP path 읽기·쓰기)도 같은 규칙을 적용한다.

**완료 조건:**
- 위 재현 결과가 `2C 01 -> CIP UINT 300` 이 된다.
- uint16/int16/uint32/int32/float 의 쓰기·읽기 왕복 테스트를 추가한다 (예: `tests/test_eip_adapter.c` 신설).
- 기존 `ctest` 가 모두 통과한다.

---

## T2. EIP/PN 포인트에 `scale` 을 주면 값이 깨짐

**문제:** 코어는 `scale≠1` 또는 `offset≠0` 이면 float32(BE) 4바이트를 어댑터에 넘긴다
(`core/fb_api.c:601` `encode_numeric`, `m->scaled`). EIP/PN 어댑터는 이것을 포인트 `length`
로 잘라서 쓴다 (`ethernetip_adapter.c` 약 472행, `adapters/profinet/profinet_adapter.c:292`).

**재현:** T1 설정의 `status_word` 에 `"scale": 0.1` 을 추가한 뒤

```
fb_write_u32(rt, "status_word", 300)   (공학값 300 → 기대 원시값 3000)
→ Assembly 바이트: 43 96              (float32 300.0 = 43 96 00 00 의 앞 2바이트)
→ 스캐너가 읽는 UINT: 38467           (기대: 3000)
```

**수정 범위 (T0 에서 A 를 선택한 경우):** `adapters/ethernetip/`, `adapters/profinet/` 각각.
Modbus 어댑터의 `apply_scale` 로직(`modbus_adapter.c:315–317`, `:772–790`, `:819–840`)과
같은 규칙으로 구현한다.
- write: float32(BE) 공학값 → `raw = (eng - offset) / scale` → `data_type` 크기의 정수로 → wire 순서 (EIP 는 LE, PN 은 BE)
- read: wire → 정수 → `eng = raw * scale + offset` → float32(BE) 4바이트로 반환
- PN 과 EIP 는 서로 다른 어댑터 디렉토리이므로 **PR 을 나눈다**.

**완료 조건:** EIP 는 위 재현에서 `B8 0B`(3000 LE), PN 은 `0B B8`(3000 BE). 읽기 왕복에서 300.0 이 나온다.

---

## T3. Modbus/SLMP 클라이언트 모드의 블로킹이 사이클과 앱 API 를 막음

**문제:**
- `run_cycle_loop` (`core/fb_api.c:739`)는 런타임 mutex `rt->mu` 를 잡은 채 `poll_cycle` 을 호출한다 (약 750–756행).
- 클라이언트 모드의 `mb_poll_cycle` (`adapters/modbus/modbus_adapter.c:549`)과 `slmp_poll_cycle`
  (`adapters/slmp/slmp_adapter.c:699`)은 포인트마다 동기 요청을 보내고 응답을 기다린다.
  대기 시간은 Modbus `select` 200ms (`stacks/modbus/src/mb_stack.c:699–733`),
  SLMP `poll` 1000ms (`stacks/slmp/src/slmp_stack.c:591–672`)다.
- 상대가 응답하지 않으면 한 사이클이 최대 `타임아웃 × 포인트 수` 만큼 걸리고
  (SLMP 포인트 10개면 약 10초), 그동안 앱의 `fb_read_*`/`fb_write_*` 도 mutex 에서 대기한다.

**재현:** SLMP client config 에 포인트 5개 이상을 넣고 `plc_ip` 를 응답 없는 주소
(예: 닫힌 포트의 로컬 IP)로 둔다. 별도 스레드에서 `fb_write_*` 의 소요 시간을 잰다.

**수정 범위 (1단계, 어댑터 안에서만):** `adapters/modbus/`, `adapters/slmp/` 각각.
- 한 사이클 안에서 첫 타임아웃이나 연결 오류가 나면 나머지 포인트는 건너뛴다(fail-fast).
- 재연결은 백오프(예: 100ms → 최대 2s)로 하고, 백오프 중에는 요청하지 않는다.
- (선택) 주소가 연속된 포인트는 요청 하나로 묶는다.

**2단계 (코어 변경, 사전 논의 필요):** I/O 를 mutex 밖에서 수행한다. 어댑터가 자체
캐시를 두고 `poll_cycle` 동안 코어 잠금을 오래 잡지 않게 하는 구조다. 인터페이스
영향이 있으면 먼저 제안서를 쓴다.

**완료 조건:** 응답 없는 PLC 상황에서 한 사이클 소요 시간이 `timeout_ms` 1회분 이하이고,
앱의 `fb_write_*` 대기 시간이 그 이하로 떨어진다. 이를 확인하는 테스트를 추가한다.

---

## T4. PROFINET RT 송신 주기에 협상값이 아닌 config 값을 씀

**문제:** `pn_rt_send_if_due` (`stacks/profinet/src/pn_rt.c:93`)는 송신 주기로
`cfg.cycle_us` (어댑터 기본 8000, `adapters/profinet/profinet_adapter.c:125`, `:192`)를 쓴다.
Connect 에서 파싱한 `send_clock_factor`/`reduction_ratio` (`stacks/profinet/src/pn_rpc.c:258–259`)는
수신 워치독 `pn_ar_watchdog` (`pn_rt.c:28–60`)에만 쓴다. 사양상 IO Device 는 IOCR 에
협상된 주기(`send_clock_factor × reduction_ratio × 31.25µs`)로 입력 CR 을 송신해야 한다.

**수정 범위:** `stacks/profinet/` (필요하면 `adapters/profinet/`).
- AR 이 수립되면 입력 IOCR 의 협상 주기를 송신 주기로 쓴다. `cfg.cycle_us` 는 AR 이 없을 때의 기본값이나 상한으로만 쓴다.
- 입력 CR 과 출력 CR 의 주기가 다를 수 있으니 CR 별로 저장한다.

**완료 조건:** CTT PROFINET 시나리오에서 협상 주기 16ms 로 Connect 하면 RT 송신 간격이
약 16ms 인지 검증하는 시나리오를 추가한다. `tests/golden/profinet/` 은 필요할 때만 재생성한다.

---

## T5. 컨트롤러가 요구하는 주기가 `cycle_ms` 보다 짧을 때

**문제:** 스택은 자체 스레드가 없어서 `poll_cycle` 이 불릴 때만 송신한다.
PN RT (`pn_rt.c:93`)와 EIP Class 1 (`stacks/ethernetip/src/eip_io.c:105`) 모두 그렇다.
그래서 실제 최소 송신 간격은 `cycle_ms` 다. 컨트롤러가 RPI 나 사이클을 2ms 로 잡으면
실제로는 8ms 마다 나가고, 상대 워치독(RPI × multiplier)이 끊길 수 있다.

**수정 범위:** `stacks/ethernetip/`, `stacks/profinet/`, EDS/GSDML 파일 (각각 별도 PR).
- EIP: Forward Open 에서 요청 RPI 가 설정된 최소 RPI(= `cycle_ms`) 보다 짧으면 표준 에러로
  거부한다. 에러 코드는 CIP Vol 1 Connection Manager 의 RPI 관련 extended status 를 사양서에서
  확인해 쓴다. EDS 의 RPI 최소값도 맞춘다 (`stacks/ethernetip/eds/`).
- PN: Connect 에서 IOCR 주기가 최소 주기보다 짧으면 PNIO 에러로 거부한다. GSDML 의
  `SendClock`/`ReductionRatio` 목록에서 지원하지 않는 값을 뺀다 (`stacks/profinet/gsdml/`).
- 최소 주기를 스택에 알려 줄 config 필드가 필요하면 `protocol_params` 에 추가하고
  `config/config.schema.json` 에도 반영한다.

**완료 조건:** 짧은 RPI/주기 요청이 거부되는 CTT 시나리오를 추가한다.

---

## T6. `core/scheduler.c` 가 쓰이지 않고 루프가 중복됨

**문제:** `scheduler_run` (`core/scheduler.c:28`)은 `CMakeLists.txt:125` 에서 빌드되지만
호출하는 곳이 없다. 실제 루프는 `core/fb_api.c:739` `run_cycle_loop` 이고 로직이 거의 같다.
`CLAUDE.md` 는 스케줄러 회귀를 판단할 파일로 `core/scheduler.c` 를 지목한다.

**수정 범위:** `core/`, `CLAUDE.md`, `CMakeLists.txt`.
- 방법 1: `scheduler.c` 를 제거하고 `CLAUDE.md` 가 `core/fb_api.c` 의 `run_cycle_loop` 를 가리키게 한다.
- 방법 2: `run_cycle_loop` 가 `scheduler.c` 의 타이밍 함수를 쓰게 합치고, 잠금 처리는 콜백으로 넘긴다.

**완료 조건:** 사이클 루프 구현이 한 곳에만 있고, `CLAUDE.md` 가 그 위치를 정확히 가리킨다.

---

## T7. 사이클 지연을 ms 로 잘라서 측정함

**문제:** `timespec_diff_ms` (`core/fb_api.c:712`, `core/scheduler.c:11`)가 ns 를 `/1000000`
으로 버린다. 그래서 `elapsed > cycle_ms` 비교가 정수 ms 단위다 (8.9ms 가 8 로 계산돼 경고가
나지 않는다). 설계 요구(8ms 에서 최대 편차 0.1ms, 지연 로그로 회귀 감지)를 데몬 자체로는
관찰할 수 없다.

**수정 범위:** `core/` (T6 이후 한 곳에서).
- 경과 시간과 기상 지연(목표 시각 대비 실제 시각)을 µs 로 잰다.
- 최대값, 평균, 초과 횟수를 누적한다. `fb_health_t` 의 `reserved[]` 를 쓰면 ABI 를 깨지 않고
  노출할 수 있다 (`FB_API_VERSION_MINOR` 증가).
- 경고 기준을 µs 로 설정할 수 있게 한다 (예: 편차 > 100µs).

**완료 조건:** 인위적으로 9ms 짜리 `poll_cycle` 을 만들면 경고가 나고, `fb_health` 로 최대
지연을 µs 단위로 읽을 수 있다.

---

## T8. `config_loader.c` 가 로깅 규칙을 어기고 기능 매크로 위치가 틀림

**문제:**
- 오류를 `fprintf(stderr, …)` 로 직접 출력한다 (`core/config_loader.c:42`, `:49`, `:57`).
  `CLAUDE.md` 는 `LOG_ERROR`/`LOG_WARN` 을 쓰라고 한다.
- `#define _POSIX_C_SOURCE 200809L` 이 첫 `#include "config_loader.h"` 다음(3행)에 있다.
  기능 매크로는 모든 include 보다 앞에 있어야 하며, 지금 위치에서는 `strdup` 선언이
  보이는지가 libc 설정에 따라 달라진다.
- (참고) `core/main.c:19` 의 사용법 출력 `fprintf` 는 CLI 사용법이라 예외로 둬도 된다.

**수정 범위:** `core/config_loader.c`.

**완료 조건:** `-Wall -Wextra -Werror -std=c11` 빌드가 통과하고, 에러 메시지 형식이
`[ts][ERROR][config] …` 로 통일된다.

---

## T9. Modbus — 사양 차이와 결함 (`docs/protocols/modbus.md` 부록 D 에서)

전체 17항목과 재현 방법은 [`../protocols/modbus.md`](../protocols/modbus.md) 부록 C·D 에 있다.
아래는 수정할 가치가 있는 항목만 추렸다. **(실측)** 표시는 하네스로 재현한 항목이다.
T9-1 과 T9-3 은 이 세션에서도 따로 재현해 확인했다.

| ID | 우선순위 | 문제 | 근거 | 수정 범위 |
|---|---|---|---|---|
| T9-1 | 높음 | **클라이언트: 한 번 타임아웃이 나면 이후 모든 트랜잭션이 영구적으로 `-EIO`.** 늦게 도착한 응답이 소켓에 남아 TID 가 어긋나는데, `connected=1` 이 유지돼 재연결도 하지 않는다 (실측: txn0 `-110`, txn1~4 `-5`) | `stacks/modbus/src/mb_stack.c:710`, `:744-747` | `stacks/modbus/`: 타임아웃이나 TID 불일치가 나면 소켓을 닫고 재연결하거나, TID 가 맞을 때까지 오래된 응답을 버린다 |
| T9-2 | 높음 | **어댑터: bit_count ≤ 8 비트필드 + 2바이트 타입(uint16 등)** 에서 쓰기는 상위 바이트만 쓰고, 읽기는 두 번째 바이트로 초기화되지 않은 스택 메모리를 돌려준다. 예제 config 의 `status_nibble` 이 해당 (실측) | `adapters/modbus/modbus_adapter.c:601-602`, `:634-635`, `:673-676` | `adapters/modbus/` |
| T9-3 | 높음 | **어댑터: 주소 문자열을 `strtol(…, 0)` 으로 파싱해서 앞자리 0 이 8진수로 해석된다.** `"00010"`→PDU 7, `"00009"`→0, `"040001"`→16385 (실측) | `adapters/modbus/modbus_adapter.c:113` | `adapters/modbus/`: 10진 고정(`base 10`). 16진을 허용하려면 `0x` 접두사를 명시적으로 처리 |
| T9-4 | 중간 | FC01~04 에서 **수량 위반(0, 초과)에 예외 02 를 낸다.** 사양은 수량 위반 03, 주소 위반 02. CTT `MB-T-NEG-001` 이 잘못된 값 02 를 기대값으로 고정해 두었다 (실측) | `stacks/modbus/src/mb_stack.c:168`, `:194`; `tests/scenarios/modbus/exception_illegal_address.yaml` | `stacks/modbus/` + 해당 CTT 시나리오 기대값. 다른 FC(15/16/23)의 수량 검사도 같이 점검 |
| T9-5 | 중간 | 클라이언트 `connect()` 가 블로킹이고 타임아웃이 없다. 상대가 SYN 에 응답하지 않으면 사이클 스레드가 커널 기본값(수십 초~분)만큼 멈춘다 | `stacks/modbus/src/mb_stack.c:519` | `stacks/modbus/`: non-blocking connect + `poll` 타임아웃. T3 과 같이 처리 |
| T9-6 | 중간 | 기본 설정에서 **Unit ID 0xFF 요청을 무시**(무응답)한다. TCP 구현 가이드는 직접 연결 장치에 0xFF 를 권고하므로 0xFF 를 보내는 마스터와 연결되지 않는다 (실측) | `stacks/modbus/src/mb_stack.c:149` | `stacks/modbus/`: 0xFF 는 항상 수락 (설정으로 끌 수 있게) |
| T9-7 | 낮음 | 서버 소켓에 `TCP_NODELAY` 가 없어 파이프라인 응답이 Nagle/지연 ACK 로 늦어진다. 한 줄 추가로 해결됨을 확인 (실측) | `stacks/modbus/src/mb_stack.c` accept 경로 | `stacks/modbus/` |
| T9-8 | 낮음 | non-blocking `send` 가 `EAGAIN` 을 내면 연결을 끊는다 | `stacks/modbus/src/mb_stack.c:665-693` | `stacks/modbus/`: 송신 버퍼에 남겨 두고 다음 poll 에서 재시도 |
| T9-9 | 낮음 | TID 카운터가 함수별 `static` 3개다(모두 1부터 시작, 인스턴스 간 공유) | `stacks/modbus/src/mb_stack.c:767`, `:879`, `:949` | `stacks/modbus/`: 스택 인스턴스 필드 하나로 통합 |
| T9-10 | 낮음 | 스키마의 `chars_per_word` 를 어댑터가 읽지 않는다 (`chars_per_register` 계열만 읽음) | `config/config.schema.json:58`, `adapters/modbus/modbus_adapter.c:335-340` | 스키마 또는 어댑터 한쪽으로 통일 |
| T9-11 | 결정 필요 | 작은 숫자 주소의 해석이 테이블마다 다르다 (coil 은 1-based, 나머지는 0-based). 4자리 `4001` 이 PDU 1 이 된다 (전통 4자리 표기에서는 PDU 0) | `adapters/modbus/modbus_adapter.c:160-201` | 주소 표기 규칙을 먼저 정하고 문서화한 뒤 수정 |

**완료 조건 (공통):** 항목마다 재현 테스트를 `tests/test_mb_stack.c` 나 `tests/test_mb_adapter.c` 에 추가하고,
`ctest -L modbus -LE soak_ci` 가 통과한다.

## 이후 추가될 항목

SLMP / EtherNet/IP / PROFINET 문서의 사양 차이와, Fable 사양 검토(PROFINET·EtherNet/IP)
결과가 확인되면 T10 이후로 덧붙인다.
