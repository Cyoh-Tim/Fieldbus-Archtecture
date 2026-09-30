# 구조 분석 결과 — 수정 작업 인수인계 (2026-09-30)

내부 문서. **인증이 아니다.** 대상: `main` @ `c10f32e` 기준 코드 (이 문서는 `claude/nice-galileo-8l3hc2` 에서 작성).
배경 설명은 [`../protocols/README.md`](../protocols/README.md) 4.6절에 있다.

이 문서는 **수정 작업을 맡을 코딩 에이전트에게 넘기는 작업 목록**이다. 각 작업은
혼자 읽어도 착수할 수 있게 문제, 근거(`path:line`), 재현 방법, 수정 범위,
완료 조건을 담았다. 행 번호는 위 커밋 기준이다.

## 공통 규칙 (반드시 먼저 읽을 것)

- **오라클 CI (`tests/oracle/`, 2026-09-30 추가):** 이 문서의 결함 16개(테스트 18개)가 독립 구현체(pymodbus, pymcprotocol,
  pycomm3, scapy) 테스트에 `@known_defect("T..")` strict xfail 로 걸려 있다. 결함을 고치면 그 테스트가 통과(XPASS)해서
  `oracle` job 이 실패한다 (GitHub Actions 는 2026-09-30 부터 꺼져 있고, 검증 담당이 `tools/ci/local_ci.py` 로 같은 job 을 돌린다). **수정 PR 은 해당 `@known_defect` 줄을 지워야 한다.** 지웠는데 결함이 남아 있으면
  테스트가 실패한다. `tests/oracle/` 의 판정 로직은 검증 담당(Claude)이 관리하므로, 구현 PR 은 표시 제거 외에는
  이 폴더를 고치지 않는다. 현재 걸려 있는 항목: T9-4, T9-6, T10-1, T10-5, T10-6, T11-1, T11-3, T11-5, T11-7, T11-9,
  T12-1, T12-2, T12-6, T12-7, T12-11, T12-22.

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
T9 (Modbus 결함) · T10 (SLMP 결함)   ─ T9-5/T10-2 는 T3 과 함께
T11-0 (EIP 독립 오라클) ──▶ T11-1…13 (+T1) ──▶ T5
T12-0 (PN 독립 오라클) ──▶ T12-1…22 ──▶ T4 ──▶ T5
```

| ID | 우선순위 | 요약 | 결정 필요 |
|---|---|---|---|
| T0 | 선행 | 스케일/바이트 순서 책임 — **A안으로 결정됨 (2026-09-30)**. 남은 일: 4개 문서 문구 통일 | 결정 완료 |
| T1 | 높음 | EtherNet/IP 숫자 포인트의 바이트 순서가 뒤집힘 | 아니오 (A안) |
| T2 | 높음 | EIP/PN 포인트에 `scale` 을 주면 값이 깨짐 | 아니오 (A안) |
| T3 | 중간 | Modbus/SLMP 클라이언트 모드의 블로킹이 사이클과 앱 API 를 막음 | 아니오 |
| T4 | 중간 | PROFINET RT 송신 주기에 협상값이 아닌 config 값을 씀 | 아니오 |
| T5 | 중간 | 컨트롤러가 요구하는 주기가 `cycle_ms` 보다 짧을 때 처리 | 아니오 |
| T6 | 낮음 | `core/scheduler.c` 가 쓰이지 않고 루프가 중복됨 | 아니오 |
| T7 | 낮음 | 사이클 지연을 ms 로 잘라서 측정함 | 아니오 |
| T8 | 낮음 | `config_loader.c` 가 `LOG_*` 대신 `fprintf` 를 씀 (사전 검증 완료, 패치 포함) | 아니오 |
| T9 | 높음~낮음 | Modbus 사양 차이·결함 11건 (클라이언트 TID 영구 불일치, 8진 주소 파싱 등) | T9-11 만 예 |
| T10 | **치명**~낮음 | SLMP 사양 차이·결함 7건 (비트 단위 니블 형식, 타임아웃 후 stale 응답 등) | T10-7 만 사양 확인 |
| T11 | **치명**~낮음 | EtherNet/IP 가 표준 스캐너와 연결되지 않는 결함 14건 (Run/Idle 헤더, EDS, FO 오류 형식 등). **T11-0(독립 오라클)부터** | 아니오 |
| T12 | **치명**~낮음 | PROFINET 이 실제 컨트롤러와 연결되지 않는 결함 23건. **T12-0(독립 오라클)부터** | 아니오 |
| T13 | 정리 | **완료 (2026-09-30).** 원격에는 `main` 과 작업 브랜치만 남음. 보관 대상 3개는 태그 대신 PR ref 로 남아 있다 (`refs/pull/1/head`, `refs/pull/5/head`, `refs/pull/6/head`) | — |

---

## T0. 결정: 스케일·바이트 순서는 누구 책임인가

> **결정 (2026-09-30, 저장소 담당자): A안.** 스케일과 wire 바이트 순서는 어댑터 책임이고, 코어·인터페이스는
> 바꾸지 않는다. T1·T2 는 이 결정을 전제로 진행한다. T0 에 남은 일은 아래 "완료 조건" 의 문서 4곳 문구 통일뿐이다.

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

**검증 (2026-09-30, Fable 사양 검토):** 사실이며 사양 위반이 맞다. 실측으로 SCF=32, RR=16(16ms)로
Connect 한 뒤에도 약 8ms 주기로 송신했다. 입력 CR 의 SCF/RR 은 저장조차 되지 않는다 (`pn_rpc.c:272-275`).
CycleCounter 도 프레임마다 +1 이 아니라 `SCF×RR` 씩 증가해야 한다 (T12-15).

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

**PROFINET 쪽 정확한 값 (Fable 사양 검토, 확신 높음, 조항 번호는 사양서 확인 필요):**
- 거부 응답은 Connect.rsp 스텁 `PNIOStatus(4) ArgsLength=0 MaxCount=0 Offset=0 ActualCount=0` (블록 없음).
  **T12-1(응답 NDR 레이아웃) 수정이 전제다.**
- PNIOStatus: ErrorCode `0xDB`(IODConnectRes), ErrorDecode `0x81`(PNIO), ErrorCode1 `0x02`(Faulty IOCRBlockReq),
  ErrorCode2 `0x0D`(SendClockFactor 오류: 지원하지 않는 SendClock) 또는 `0x0E`(ReductionRatio 오류:
  SCF×RR 이 최소 주기 미만). 예: 8ms 장치에 4ms(SCF=32, RR=4) 요청 → `DB 81 02 0E`.
  Wireshark `pn_io_error_code2_pnio_2` 표, p-net `PNET_ERROR_CODE_2_IOCR_SEND_CLOCK_FACTOR/REDUCTION_RATIO` 와 일치.
- 현재 `reply_pnio_err` 의 `0x81<<24` 는 LE drep 에서 ErrorCode=0x00 으로 읽혀 어떤 경우에도 올바른 거부가 아니다.
- GSDML: DAP `MinDeviceInterval="256"` (256×31.25µs = 8ms; 현재 32 = 1ms 로 틀림),
  `InterfaceSubmoduleItem/ApplicationRelations/TimingProperties SendClock="32" ReductionRatio="8 16 32 64 128 256 512"`.
  `cycle_ms` 를 바꾸면 GSDML 도 같이 바꿔야 하므로 GSDML 생성·검증 스크립트를 두는 편이 안전하다.
- RR 은 2의 거듭제곱만 받는다 (상한은 사양서 확인 필요).

**EtherNet/IP 쪽 값 (Fable 사양 검토, 실행 확인):**
- 현재 RPI 500µs Forward Open 도 수락하고 응답 API 에 요청값(`F4 01 00 00`)을 그대로 돌려준다. Originator 는
  T→O 타임아웃을 `API × 4 × 2^N` 으로 계산하므로 8ms 폴링에서는 곧바로 연결 폴트가 난다.
- 거부: General Status `0x01` + Extended `0x0112` "RPI value(s) not acceptable". 추가 상태에 허용값을 **포함해야**
  한다 → Additional Status Size = 6워드: `0x0112`, O→T RPI type(1B) + T→O RPI type(1B), O→T RPI(UDINT), T→O RPI(UDINT).
  RPI type 2 = 최소 허용 RPI → 양방향 모두 type 2 + `cycle_ms×1000`. (`0x0111` 은 허용값 형식이 없는 레거시 코드)
- 응답은 Unsuccessful Forward_Open Response 형식(T11-3: triad + Remaining Path Size)을 따라야 한다.
- 수락할 때 RPI 가 `cycle_ms` 의 배수가 아니면 API 에 실제 생산 주기(올림한 배수)를 넣는다.
- EDS: Connection 항목의 O=>T / T=>O RPI 칸에 Param 참조를 넣고, `[Params]` 에 UDINT(0xC8), 단위 µs,
  min = `cycle_ms×1000` 으로 선언한다. Studio 5000 의 RPI 입력 범위가 그 값으로 제한된다 (T11-2 의 EDS 재작성과 같이).

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

## T8. `config_loader.c` 가 `LOG_*` 대신 `fprintf` 를 씀

**문제:** 오류를 `fprintf(stderr, …)` 로 직접 출력한다 (`core/config_loader.c:42`, `:49`, `:57`).
`CLAUDE.md` 는 `LOG_ERROR`/`LOG_WARN` (`core/logger.h`)을 쓰라고 한다.
(참고) `core/main.c:19` 의 사용법 출력 `fprintf` 는 CLI 사용법 안내라 예외로 둬도 된다.

**`logger.h` 를 써도 되는지 사전 검토 (2026-09-30, 스크래치 복사본에서 확인):**
- 같은 `core/` 의 `fb_api.c`, `main.c`, `scheduler.c` 와 모든 어댑터·스택이 이미 `logger.h` 를 쓴다.
  헤더만으로 된 매크로라 초기화가 필요 없고, 출력도 기존과 같은 `stderr` 로 나간다.
- `config_load()` 가 실패하면 `fb_api.c:393-394` 는 `"config_load failed"` 만 남긴다.
  구체적인 원인은 이 로그에만 있으므로 **메시지 내용은 그대로 유지**해야 한다.
- 로그 문구를 파싱하는 테스트나 스크립트는 없다 (`[config]` 문자열은 문서에만 등장).
- 아래 패치를 적용해 gcc 와 clang 모두 `-Wall -Wextra -Werror` (프로젝트 기본 `gnu11`)로 빌드가
  통과했고, `test_fb_api` 도 OK 였다. 세 오류 경로의 실제 출력:
  ```
  [2026-09-30 01:18:43][ERROR][config] 파일을 열 수 없음: /nonexistent.json
  [2026-09-30 01:18:43][ERROR][config] JSON 파싱 실패: ad
  [2026-09-30 01:18:43][ERROR][config] "protocol" 필드가 없거나 문자열이 아님
  ```

**권장 패치 (검증한 그대로):**
```c
#define _POSIX_C_SOURCE 200809L      /* 파일 맨 위로 이동 */

#include "config_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
...
LOG_ERROR("config", "파일을 열 수 없음: %s", path);
LOG_ERROR("config", "JSON 파싱 실패: %s", ep ? ep : "(unknown)");
LOG_ERROR("config", "\"protocol\" 필드가 없거나 문자열이 아님");
```

**주의:**
1. `config_loader.c` 의 `#define _POSIX_C_SOURCE` 를 **지우지 말 것.** `logger.h` 도 같은 값을
   정의하지만, `<stdio.h>` 뒤에 include 되면 이미 늦다 (`strdup`, `localtime_r` 선언 노출이
   `-std=c11` 에서 달라질 수 있음). 같은 값의 재정의라 경고는 나지 않는다.
2. 현재 3행 위치도 **지금은 실제 버그가 아니다.** `config_loader.h` 가 시스템 헤더를 include 하지
   않기 때문이다. 다만 헤더에 include 가 추가되는 순간 깨지므로 맨 위로 옮긴다.
   (앞선 판에서 "지금 위치에서 선언 노출이 달라진다"고 쓴 것은 과장이었다.)
3. 인자 없는 `LOG_ERROR("config", "리터럴")` 은 `##__VA_ARGS__` (GNU 확장)에 의존한다.
   저장소 전체에 이미 41곳이 같은 형태이고, 기존 코드도 clang `-Wpedantic` 에서는
   `-Wgnu-zero-variadic-macro-arguments` 로 실패한다. 이는 T8 범위 밖이며, `-Wpedantic` 을
   게이트로 쓰려면 `logger.h` 를 따로 고쳐야 한다.
4. `cJSON_GetErrorPtr()` 는 오류 위치부터 **입력의 나머지 전체**를 돌려준다 (위 예시처럼 개행까지 포함).
   큰 설정 파일이면 로그가 길어지므로 `%.40s` 처럼 자르는 것을 권장한다 (선택).

**수정 범위:** `core/config_loader.c` (+ 주석을 고치려면 `core/config_loader.h` 17행의
"stderr 에 원인 로그 출력").

**완료 조건:** gcc/clang `-Wall -Wextra -Werror` 빌드와 `test_fb_api` 가 통과하고, 세 오류 경로가
`[ts][ERROR][config] …` 형식으로 출력된다.

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

## T10. SLMP — 사양 차이와 결함 (`docs/protocols/slmp.md` 부록 D 에서)

전체 14항목과 재현 방법은 [`../protocols/slmp.md`](../protocols/slmp.md) 부록 D 에 있다.
T10-1 과 T10-2 는 이 세션에서 코드를 읽어 다시 확인했다.

| ID | 우선순위 | 문제 | 근거 | 수정 범위 |
|---|---|---|---|---|
| T10-1 | **치명** | **비트 단위(서브커맨드 `0001`) 데이터 형식이 사양과 다르다.** 사양은 1점 = 4비트(니블), 1바이트에 2점, 앞 점이 상위 니블이다. 저장소는 1점 = 1바이트(`00`/`01`)로 처리한다(코드 주석 `/* 1 byte/bit */`). 실 PLC 에서는 1점 ON 쓰기(`01`)가 OFF 로 해석되고, 2점 이상 쓰기는 길이 오류, 2점 이상 읽기는 `-ENOSPC` 가 난다. 워드 단위(`0000`)는 정상 | `stacks/slmp/src/slmp_stack.c:505-506`, `:525-526`, `:750-763`, `:900-906`, `:930-936` | `stacks/slmp/` 인코더·디코더·서버 모두. CTT `encode_batch_read.yaml`(길이 25) 등 비트 프레임 기대값 갱신. 니블 패킹 예제는 `slmp.md` 5장과 8장에 있다 |
| T10-2 | **치명** | **타임아웃 후 이전 요청의 늦은 응답을 다음 요청 결과로 돌려준다.** `client_transact` 는 오류 시 `connected=0` 만 하고 소켓을 유지하며, 재연결하는 곳이 없다. 3E 프레임에는 요청 ID 가 없어서 응답을 구분할 수 없다. 재현: D0 읽기가 타임아웃된 뒤 D1 읽기가 D0 의 값을 반환. 기본값에서 소켓 타임아웃(1s)이 PLC 감시 타이머(4s)보다 짧아 쉽게 발생한다 | `stacks/slmp/src/slmp_stack.c:644-680` | `stacks/slmp/`: 오류가 나면 소켓을 닫고 백오프 재연결한다. 소켓 타임아웃은 감시 타이머보다 길게 잡는다. T3 과 같이 처리 |
| T10-3 | 중간 | `"XA"` 나 `"device_code":"X","start":"A"` 처럼 A~F 로 시작하는 16진 번호가 파싱에 실패하고, 해당 포인트가 **경고 없이 빠진다** (`X0A` 는 동작) | `adapters/slmp/slmp_adapter.c:147-163` | `adapters/slmp/`: 16진 디바이스(X/Y/B/W/SB/SW/DX/DY)는 번호를 16진으로 파싱하고, 실패하면 `LOG_ERROR` 후 init 실패 |
| T10-4 | 중간 | 기본 문자열 바이트 배치가 MELSEC 관례와 반대다(MELSEC 는 앞 문자가 하위 바이트). 32비트 기본 워드 순서도 `ABCD` 로 MELSEC(`CDAB`)와 다르다 | `adapters/slmp/slmp_codec.c:442-445`, `:39-43` | `adapters/slmp/`: 기본값을 MELSEC 관례로 바꾸고 예제·스키마·문서를 함께 갱신 (기존 설정과 호환성 주의) |
| T10-5 | 낮음 | 서버 시뮬레이터가 미지원 커맨드에 `C050` 을 낸다(사양은 `C059`, `C050` 은 ASCII 변환 오류). 이상 응답에 9바이트 에러 정보가 없다. 쓰기 데이터 길이가 틀리면 응답 없이 버린다 | `stacks/slmp/include/slmp_types.h:31`, `stacks/slmp/src/slmp_stack.c:836-858`, `:929-933` | `stacks/slmp/` + CTT `reject_non_3e.yaml` 기대값 |
| T10-6 | 낮음 | 서버 시뮬레이터가 비트 디바이스를 워드 단위로 접근할 때 선두 번호를 워드 인덱스로 해석한다 (M16 → M256~) | `stacks/slmp/src/slmp_stack.c:327-330` | `stacks/slmp/` |
| T10-7 | 확인 필요 | ZR 번호 기수(Q 계열), FX5 의 X/Y 8진 표기. 사양서를 확인한 뒤 처리 | `stacks/slmp/src/slmp_stack.c:53`, `:65` | 사양 확인 후 결정 |

**완료 조건 (공통):** 항목마다 재현 테스트를 `tests/test_slmp_stack.c` 나 `tests/test_slmp_adapter.c` 에 추가하고,
`ctest -R slmp -LE soak_ci` 가 통과한다. T10-1 은 가능하면 실 MELSEC PLC(또는 GX Simulator3)로 확인한다.

## T11. EtherNet/IP — 표준 스캐너와 연결되지 않는 결함들

**출처와 신뢰도:** 두 개의 독립 분석이 같은 결론을 냈다.
(1) [`../protocols/ethernetip.md`](../protocols/ethernetip.md) 부록 D (41건) — 하네스로 요청을 주입해 응답 바이트 확인.
(2) Fable 사양 검토 (EIP-S1–S12) — 스택에 링크한 프로브로 응답 바이트 확인 (P1~P16).
"교차" 는 두 분석이 모두 지적한 항목이다. 실제 Studio 5000 / CODESYS 스캐너로는 아직 확인하지 않았다.

**전제:** CTT 가 저장소 자체 형식(O→T = Assembly+2)으로 요청을 보내므로 T11-1 같은 결함을 잡지 못한다.
T12-0 과 같은 원칙으로, 스택과 가정을 공유하지 않는 기준(Wireshark `enip`/`cip` 디섹터, 또는 OpENer·pycomm3
같은 독립 구현)으로 검증하는 테스트를 먼저 둔다 (**T11-0**).

| ID | 우선순위 | 문제 | 근거 | 교차 |
|---|---|---|---|---|
| T11-0 | **선행** | **오라클 부분 완료 (2026-09-30, CI `oracle` job, [`tests/oracle/`](../../tests/oracle/README.md)).** 남은 일(구현 에이전트): CTT 의 Forward Open 을 Logix 기본 형식(O→T 32-bit Run/Idle 헤더, 0x8001 sockaddr, 전자 키 포함)으로 고친다 | `tools/ctt/proto/ethernetip/` | 교차 |
| T11-1 | **치명** | **O→T 32-bit Run/Idle 헤더 형식을 거부한다.** 표준 O→T 크기는 `data + 2(seq) + 4(Run/Idle)` 인데 `asm` 또는 `asm+2` 만 받는다 → 응답 `D4 00 20 01 09 01`. 받아도 헤더를 벗기지 않아 output 이미지에 헤더 바이트가 들어가고, Run/Idle 비트를 해석하지 않아 **PLC 가 PROGRAM(Idle) 모드여도 출력이 유지된다(안전 문제).** 저장소 EDS(`0x44640405`)는 오히려 32-bit 헤더를 선언해 스택과 모순. **Studio 5000 Generic Ethernet Module / 이 EDS 로 만든 모듈의 Exclusive Owner 연결이 열리지 않는다** | `stacks/ethernetip/src/eip_cm.c:42-45`, `:198-210`; `eip_io.c:64-74`; `eds/FieldbusSensor.eds:58` | 교차 |
| T11-2 | **치명** | **EDS 가 문법·내용 모두 틀렸다.** Connection1 의 RPI 칸에 값 2개(`1000000,8000,`)를 넣어 이후 필드가 모두 밀렸고, 연결 경로 문자열이 없다. Param1 은 타입 0xC1(BOOL)인데 크기 2, `MinRev = 1` 인데 Identity 는 1.0 (전자 키 불일치), Port1 필드 구성 비표준. 어댑터는 `minor_rev = 0` 고정 | `eds/FieldbusSensor.eds:17`, `:25-37`, `:56-66`, `:68-75`; `adapters/ethernetip/ethernetip_adapter.c:161-162` | Fable 단독 (문서는 EDS 해설만) |
| T11-3 | 높음 | **Forward Open/Close 실패 응답 형식이 틀렸다.** General Status 로 0x20/0x05/0x04/0x02 를 쓴다 (CM 오류는 0x01 + Extended). 응답 뒤 Connection Serial·Vendor·Originator Serial·Remaining Path Size 10바이트가 없다. 없는 연결의 Forward Close 가 성공한다 (사양 0x01/0x0107) | `eip_cm.c:8-20`(`cm_err`), `:136`, `:178`, `:184`, `:194`, `:207`, `:224`, `:297-307` | 교차 |
| T11-4 | 높음 | **UDP 44818 수신 소켓이 없어** RSLinx/Studio 5000 브라우즈(브로드캐스트 ListIdentity)에 장치가 안 보인다. ListIdentity 의 sockaddr·Status·State 가 0/0/0xFF 고정, ListInterfaces 가 status 1 | `eip_stack.c:193-215`, `:321-337`; `eip_encap.c:40-62`, `:384-387` | 교차 |
| T11-5 | 높음 | **Exclusive Owner 소유권 검사가 없다.** 다른 triad 의 두 번째 EO Forward Open 도 성공해서 두 PLC 가 같은 출력을 덮어쓴다(안전, 사양 0x01/0x0106). Input Only·Listen Only(heartbeat connection point) 미지원, 멀티캐스트 요청도 수락 후 유니캐스트로 송신 (사양: 구현하거나 0x01/0x0124 로 거절) | `eip_cm.c:34-40`, `:106-125`, `:212-220`; `eip_encap.c:259-283` | 교차 |
| T11-6 | 높음 | **Connection ID·생산 목적지 처리가 사양과 달라 I/O 위조가 가능하다.** O→T ID 를 Target 이 고르지 않고 요청값을 그대로 쓰며 중복 검사도 없다. ID 는 0x20000001 부터 순차. T→O 는 첫 O→T 패킷을 받아야 시작하고, 목적지를 매 O→T 패킷의 출발지로 갱신한다(0x8001 sockaddr 무시, 출발지 IP 검증 없음). ID 를 맞힌 임의 호스트가 출력을 위조하거나 T→O 를 가로챌 수 있다 | `eip_io.c:57-58`, `:111`; `eip_cm.c:228-233`; `eip_stack.c:157`; `eip_encap.c:193-211` | 교차 |
| T11-7 | 높음 | **Transport class/trigger 를 검사하지 않는다.** Class 3 Forward Open 도 Class 1 슬롯으로 수락된다. 반면 Class 3 데이터 경로(SendUnitData 0x70)는 미구현(status 1). 제품 범위에 "Class 3" 이 있으나 실제로는 없다. 미지원 조합은 0x01/0x0103 으로 거부해야 한다 | `eip_cm.c:176`, `:188-196`; `eip_encap.c:384-387` | 교차 |
| T11-8 | 중간 | Class 1 소비 규칙: 순번 비교 없음(UDP 재정렬 시 옛 데이터 적용, 출력 역행), timeout multiplier >7 을 7로 클램프(사양 0x01/0x0133), 전자 키 미검사(0x0114~0x0116), 경로의 Data Segment(0x80, config 데이터) 거부 — EDS 가 Config Assembly 를 선언하므로 EDS-AOP 요청이 즉시 거절될 수 있다 | `eip_io.c:59-67`; `eip_cm.c:61-104`, `:153`, `:243-247`; `eip_internal.h:199-212` | 교차 |
| T11-9 | 중간 | Encapsulation: NOP·UnRegisterSession 에 응답한다(사양: 무응답, Unregister 후 TCP 종료). RegisterSession 버전≠1(→0x0069)·옵션≠0(→0x0003) 미검사, 헤더 Options 필드 미검사, SendUnitData·ListInterfaces 미구현 | `eip_encap.c:302-352`, `:384-387` | 교차 |
| T11-10 | 중간 | 표준 객체 속성 오류: Identity Status 에 Owned(bit0) 대신 Configured(bit2), State 2 를 결함 상태로 오용, Protection Mode 를 attr 17 로 노출(attr 17 은 Geographic_Location; 정확한 번호 사양서 확인 필요). QoS 속성 번호가 3 밀림(attr 1 이 802.1Q Tag Enable 이어야 함), DSCP 를 소켓에 적용 안 함. TCP/IP attr 2 ACD 비트 위치 오류(bit 2 → bit 7), attr 5 없음, attr 10/11 타입 오류, attr 13 없음. Port Type 0(사양 4), 클래스 레벨 속성 없음, 읽기 전용 Set 에 0x05(사양 0x0E) | `stacks/ethernetip/src/eip_cip.c:78`, `:110-170`, `:298-331`, `:375-516`; `eip_stack.c:647` | 교차 |
| T11-11 | 중간 | **"CIP Security Class 1/2" 는 ODVA Vol 8 CIP Security 가 아니다.** 미할당 CPF 항목 0x00C1 에 HMAC-SHA256(session‖CIP) 을 붙이는 독자 방식이고, Get 무인증·세션 내 재전송 가능·UDP I/O 무보호·평문 44818 병존·DTLS 없음. 켜면 표준 Originator 의 Forward Open 이 거절된다. 명칭을 "저장소 무결성 프로파일(비표준)" 으로 바꾸고, 진짜 CIP Security 가 목표면 TLS/DTLS + 0x5D/0x5E/0x5F + ListIdentity 0x0086 부터 재설계 | `stacks/ethernetip/include/eip_sec.h:21`, `src/eip_sec.c:29-184`, `eip_cip.c:519-546` | 교차 |
| T11-12 | 중간 | Originator: tag 읽기·쓰기에 Logix 태그 서비스(0x4C/0x4D) 대신 Get/Set_Attribute_Single 을 쓴다 → Logix 태그 접근 불가. TCP 재조립 없음, 보안 MAC 미부착 | `stacks/ethernetip/src/eip_client.c` | **단독** (문서) |
| T11-13 | 낮음 | FO 직후 워치독이 RPI×배수로 바로 무장(첫 패킷 여유 없음; 관례 10s, 사양 조항 확인 필요). Identity Reset 타입 무시. UCMM 응답 버퍼 568B(큰 Assembly Get 실패). Encap 8KB 초과 시 TCP 종료. LLDP 는 메모리에만 생성되고 실제로 송신되지 않는다 | `eip_cm.c:248-249`; `eip_cip.c:298-308`; `eip_encap.c:244`; `eip_stack.c:498-501`; `eip_lldp.c:40`, `:96-100` | 교차 |

**권장 순서:** T11-0 → T11-1 → T11-2 → T11-3 → (T1: 바이트 순서) → T11-4 → T11-5 → T11-6 → T5 → 나머지.
T11-1·T11-2·T11-3 이 해결돼야 Studio 5000 Generic/EDS 모듈로 Exclusive Owner 연결이 열린다 (Fable 판단).
T1(바이트 순서)은 Fable 검토에서도 실행으로 다시 확인됐다 (`fb_read_u32` 왕복은 300 으로 돌아와 앱 테스트로는 보이지 않고, 스캐너에서만 뒤집힌다).

**범위 주의:** 대부분 `stacks/ethernetip/` 이고, T11-2 의 `minor_rev` 파싱과 T1 은 `adapters/ethernetip/`, T11-0 은 `tools/ctt/`·`tests/` 다.
디렉토리별로 PR 을 나눈다.

**완료 조건:** T11-0 의 독립 오라클 테스트가 각 항목의 수정 전 실패와 수정 후 통과를 보여 준다.
최종 확인은 실제 스캐너(Studio 5000 Generic Ethernet Module / EDS-AOP, 또는 CODESYS EtherNet/IP Scanner) 연결이다.

## T12. PROFINET — 실제 컨트롤러와 연결되지 않는 결함들

**출처와 신뢰도:** 두 개의 독립 분석이 같은 결론을 냈다.
(1) [`../protocols/profinet.md`](../protocols/profinet.md) 11장 D1–D31 — 하네스 실행과 scapy 2.7.0 디섹터로 교차 검증.
(2) Fable 사양 검토 (PN-S1–S20) — 스택에 링크한 프로브로 실제 응답 바이트를 덤프해 확인.
아래 표의 "교차" 는 두 분석이 모두 지적한 항목이다. 실제 PLC 로는 아직 확인하지 않았다.

**가장 중요한 전제 — 먼저 읽을 것:**
현재 스택은 PN 테스트 34개를 모두 통과하지만, **CTT 하네스(`tools/ctt/proto/profinet/pn_plugin.c:813-865`)와
단위 테스트·퍼저·golden 이 스택과 같은 잘못된 가정을 공유한다** (rpc_vers=1, 응답 NDR 첫 워드=길이,
IOCR 블록 없는 Connect, BlockInfo 없는 DCP). 즉 "거울 구현" 상태라서 CTT green 은 사양 적합성의 증거가 아니다.
따라서 **T12-0 을 가장 먼저** 해야 이후 수정을 검증할 수 있다.

| ID | 우선순위 | 문제 | 근거 | 교차 |
|---|---|---|---|---|
| T12-0 | **선행** | **오라클 부분 완료 (2026-09-30, CI `oracle` job, scapy 기반 [`tests/oracle/`](../../tests/oracle/README.md)).** 남은 일(구현 에이전트): CTT 하네스의 Connect/DCP 요청을 사양 형태(rpc_vers=4, IOCRBlockReq·ExpectedSubmoduleBlockReq 포함, BlockInfo 포함)로 고치고, golden(`tests/golden/profinet/`)은 수정 후 재생성한다 | `pn_plugin.c:813-865` | 교차 |
| T12-1 | 치명 | **RPC 응답 NDR 의 첫 워드가 PNIOStatus 가 아니라 길이다.** 응답은 `PNIOStatus · ArgsLength · MaxCount · Offset · ActualCount · Blocks` 인데 요청 레이아웃을 그대로 써서 Connect.rsp 첫 워드가 `0x00000048`. 컨트롤러는 Connect/Control/Read/Write 를 모두 실패로 처리해 **AR 이 성립하지 않는다.** 에러 응답(`reply_pnio_err`)도 같은 문제 | `stacks/profinet/src/pn_rpc.c:415-424`(`ndr_wrap`), 사용처 `:548,:579,:613,:650,:680`, `:459-467` | 교차 |
| T12-2 | 치명 | **DCP Identify/Get 응답 블록에 BlockInfo(2바이트)가 없다.** 표준 도구가 이름 앞 2글자를 잃고("nsor-line1"), IP 가 2바이트 밀려 보인다. TIA/PRONETA 탐색·이름 설정 실패 가능 | `stacks/profinet/src/pn_dcp.c:55-63`(`wr_block`), `:381-409`, `:520-525` | 교차 |
| T12-3 | 치명 | **Read/Write 응답에 IODReadResHeader(0x8009)/IODWriteResHeader(0x8008) 64바이트 블록이 없고, I&M 레코드에 BlockHeader(0x0020~0x0024)가 없다.** 또한 Write 요청의 데이터를 64바이트 헤더 뒤가 아니라 패딩 위치에서 읽어 I&M1 을 0으로 덮어쓴다. TIA 는 Connect 직후 Write 를 보내므로 파라미터화 실패 → AR abort | `pn_rpc.c:648-650`, `:679-680`; `pn_record.c:97-155` | 교차 |
| T12-4 | 치명 | **IOCRBlockReq 의 프레임 오프셋·ExpectedSubmoduleBlockReq 를 무시하고 고정 레이아웃으로 송수신한다.** IODataObject/IOCS 의 FrameOffset 에 따라 DAP·인터페이스·포트 서브모듈의 IOPS 와 출력 서브모듈의 IOCS 를 배치해야 한다. ModuleDiffBlock(0x8104)과 ARServerBlock(0x8106)도 없다. T12-1 을 고쳐도 IO 교환은 되지 않는다 | `pn_rpc.c:249-276`, `:344-382`; `pn_rt.c:78-88`, `:109-130` | 교차 |
| T12-5 | 높음 | **PrmEnd 응답이 0x0111 + 커맨드 echo 다** (사양 0x8110 + Done 0x0008). **ApplicationReady 는 형식이 틀렸다:** rpc_vers=1, UUID 전부 0, 블록 0x0110 (사양: rpc_vers=4, 객체 UUID=CMInitiatorObjectUUID, 인터페이스 UUID=PNIO Controller, 블록 0x0112, `CMInitiatorUDPRTPort` 로 전송, 0x8112 응답 대기와 재전송). Siemens 는 AppReady 를 받기 전까지 출력을 보내지 않는다 | `pn_types.h:56-57`, `pn_rpc.c:426-457`, `:469-477`, `:605-613` | 교차 |
| T12-6 | 높음 | **DataStatus 가 0x25 로 나간다** (정상 0x35). `PN_DATASTATUS_RUN 0x20` 은 실제로 StationProblemIndicator 비트이고, ProviderState(Run)는 0x10 이다. 컨트롤러는 장치를 STOP 으로 본다 | `pn_types.h:76-78`, `pn_rt.c:128-129` | 교차 |
| T12-7 | 높음 | **RTC1 프레임에 최소 길이 패딩이 없다.** C_SDU 최소 40옥텟(VLAN 태그 시 36)으로 IOData 와 APDUStatus 사이를 패딩해야 한다. 지금은 53바이트라 NIC 가 끝에 0을 붙이면 컨트롤러가 끝 4바이트(APDUStatus)를 `00 00 00 00` 으로 읽는다. mock 에서는 재현되지 않는다 | `pn_rt.c:117-138`, `pn_eth.c:490-502` | 교차 |
| T12-8 | 높음 | RTC1·알람 프레임에 802.1Q VLAN 태그(PCP 6, 알람 Low 5)가 없다. IOCRTagHeader 도 파싱하지 않는다 | `pn_rt.c:135-136`, `pn_sec.c:408-409` | 교차 |
| T12-9 | 높음 | **어댑터 기본값이 자체 HMAC "Security Class 1" 을 강제한다** (`cfg.security_class = 1`). PI 의 Security Class 1 은 하드닝(DCP Set 제한, SNMP 쓰기 금지 등)이고 프레임에 HMAC 을 넣지 않는다. 기본 설정으로는 **어떤 표준 컨트롤러도 Connect·이름 설정을 할 수 없다** (CODESYS 예제 config 가 class 0 을 쓰는 이유). 이름을 "vendor integrity extension" 등으로 바꾸고 기본값을 끈다 | `adapters/profinet/profinet_adapter.c:124`, `pn_rpc.c:280-326`, `:508-510`, `pn_dcp.c:227-249` | 교차 |
| T12-10 | 높음 | 알람 RTA-PDU 가 형식상 무효다 (PDUType 버전 0, AddFlags 0, BlockHeader 없음, Endpoint 1 고정, ACK/재전송 없음). AlarmCRBlockReq 를 파싱하지 않는다. AR abort 시 컨트롤러 통지와 출력 안전값 처리도 없다 | `pn_sec.c:384-418`, `pn_rpc.c:234-278` | 교차 |
| T12-11 | 높음 | LLDP: PNO OUI 가 `00-0C-CF` 로 오기 (정답 `00-0E-CF`). PortID 가 MAC (정답 `port-001`), PortStatus·MAC/PHY·MgmtAddr TLV 없음. 토폴로지 검출 불가 | `pn_lldp.c:34-52` | 교차 |
| T12-12 | 높음 | AlarmCRBlockRes 바디가 8바이트 (사양 6). ARBlockRes 의 UDP 포트 값도 확인 필요 (문서 에이전트는 0x8894 → 0x8892 를 지적, Fable 은 언급 없음) | `pn_rpc.c:344-382` | AlarmCR 는 교차, 포트는 **단독** |
| T12-13 | 높음 | GSDML 이 스키마 필수 요소를 갖추지 못했다 (DAP VirtualSubmoduleItem, InterfaceSubmoduleItem 32768, PortSubmoduleItem 32769, TimingProperties, CertificationInfo). `MinDeviceInterval="32"`(1ms) 는 8ms 구현과 모순. GSDML Checker·TIA import 실패 가능. T5 와 같이 처리 | `stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml:30-50` | 교차 |
| T12-14 | 중간 | DCE/RPC 헤더: drep 무시(LE 고정), rpc_vers·인터페이스 UUID·객체 UUID 미검사, 단편화 미지원, EPM(UDP 135) 없음, activity timeout 2s 고정 | `pn_rpc.c:384-395`, `:479-495`, `:694` | 교차 |
| T12-15 | 중간 | CycleCounter 가 프레임당 +1 (사양: 프레임마다 SCF×RR 증가). T4 와 같이 처리 | `pn_rt.c:126` | 교차 |
| T12-16 | 중간 | DCP Set: 블록마다 응답하지 않음, 적용 안 된 블록도 OK, AR 중 이름/IP Set 거부(0x06) 없음, ResetToFactory 없음, 오류 시 ServiceType 0x05 오용 | `pn_dcp.c:480-494`, `:528-568` | 교차 |
| T12-17 | 중간 | 표준 Release(0x0114)를 무시해 연결이 타임아웃까지 유지된다 (CTT 의 0x0101 형태만 동작) | `pn_rpc.c` Release 처리 | **단독** (문서) |
| T12-18 | 중간 | 미지원 레코드 index 에 빈 데이터 응답 (사양: PNIORW 에러 `DE 80 B0 00` / `DF 80 B0 00`). 진단·식별 레코드 부재 | `pn_record.c:157-163`, `:225-226` | 교차 |
| T12-19 | 중간 | SNMP 가 요청과 무관하게 고정 sysName 을 request-id 1 로 응답한다 | `pn_snmp.c:280-333` | 교차 |
| T12-20 | 중간 | DCP 로 받은 IP 가 OS 에 적용되지 않고(`apply_os_ip` 선언만), 이름·I&M 이 재시작 시 사라진다(비휘발 저장 없음) | `pn_dcp.c`, `pn_stack.c` | **단독** (문서) |
| T12-21 | 낮음 | 어댑터가 config 의 slot/subslot/index 를 무시하고 `byte_offset` 만 쓴다. CODESYS·fake-sensor 예제는 입력 40바이트, GSDML 은 32바이트로 불일치 | `adapters/profinet/profinet_adapter.c`, `config/example.*profinet*.json` | **단독** (문서) |
| T12-22 | 낮음 | IOCRBlockRes 의 IOCRReference 1/2 고정, DCP Identify 지연 응답 슬롯 1개, DeviceRole 0x02 (IO-Controller) 로 응답 | `pn_rpc.c:358,364`; `pn_dcp.c:401-404`, `:454-478` | 부분 교차 |

**권장 순서 (Fable 제안):** T12-0 → T12-1 → T12-2 → T12-3 → T12-5 → T12-4 → T12-6/7/8 → T4 → T5(+T12-13) → 나머지.
실제 컨트롤러가 겪는 순서도 DCP(T12-2) → RPC 응답(T12-1) → Write/PrmEnd/AppReady(T12-3, T12-5) → RTC1(T12-4, 6, 7) 이다.

**범위 주의:** 대부분 `stacks/profinet/` 안에서 끝나지만 T12-0 은 `tools/ctt/`·`tests/`, T12-9 와 T12-21 은
`adapters/profinet/`, T12-13 은 GSDML 이다. PR 을 디렉토리별로 나눈다. IRT·CC-C 는 켜지 않는다.

**완료 조건:** T12-0 의 독립 오라클 테스트가 각 항목의 수정 전 실패와 수정 후 통과를 보여 준다.
최종 확인은 실 컨트롤러(TIA Portal 또는 CODESYS Control) 연결이다 (`docs/ctt_lab.md` 절차).

## T13. 저장소 정리 — 남아 있는 원격 브랜치 삭제

> **완료 (2026-09-30).** 원격 브랜치가 `main` 과 작업 브랜치만 남도록 정리됐다. `archive/*` 태그는 만들어지지 않았지만,
> 보관 대상 3개 브랜치의 커밋은 GitHub 이 PR 마다 유지하는 ref 로 남아 있다:
> `git fetch origin refs/pull/1/head` (profinet-cm-rtc1-dcp), `refs/pull/5/head` (skip-ethercat), `refs/pull/6/head` (codesys-pooltest).

**문제:** 원격 브랜치가 48개다. `main` 과 이 문서의 브랜치를 빼면 46개 모두 이미 닫힌 PR 의 브랜치다.
(2026-09-30 확인. Claude 세션은 작업 브랜치 외에는 푸시 권한이 없어 직접 삭제하지 못했다.)

**확인 결과 (이 목록 그대로 써도 된다):**
- **삭제 가능 — 병합된 PR 브랜치 32개.** 브랜치 끝 커밋이 병합된 PR 의 head SHA 와 모두 일치해, 병합 후 추가 작업이 없다.
- **삭제 가능 — 병합 없이 닫혔지만 내용이 `main` 에 흡수된 11개.** 이 브랜치들이 추가·수정한 파일이 모두 `main` 에 있다
  (#14 `ctt-unify-main`, #15 `merge-product-stacks` 로 통합된 것으로 보인다).
- **보관 (태그로 옮긴 뒤 브랜치만 삭제) — 3개.** `main` 에 없는 파일이 있다.
  - `cursor/profinet-cm-rtc1-dcp-eff7` (#1), `cursor/codesys-protocol-pooltest-e12b` (#6):
    `stacks/profinet/src/pn_alarm.c`, `tests/pn_controller_sim.c`, `tests/test_pn_adapter.c`, CODESYS 풀테스트 스크립트 등.
    `pn_controller_sim.c` 는 T12-0 참고 자료가 될 수 있으나 현재 스택과 같은 가정을 공유할 수 있으니 오라클로 그대로 쓰지 말 것.
  - `cursor/skip-ethercat-no-asic-ee42` (#5): EtherCAT 스텁 어댑터 (`main` 에서 의도적으로 뺀 것으로 보임).

**명령 (`git fetch origin` 후 실행):**

```bash
# 1) 삭제 43개
git push origin --delete \
  cursor/pn-fuzz-state-leak-8d74 cursor/eip-encap-fuzz-conn-leak-8e7a cursor/fuzz-pn-harness-8326 \
  cursor/fuzz-harness-audit-8326 cursor/eip-io-stateful-fuzz-8326 cursor/fuzz-longrun-v020-8326 \
  cursor/iec62443-g6-g8-6610 cursor/iec62443-security-fixes-5975 cursor/full-test-report-9a08 \
  cursor/static-dynamic-analysis-b4a9 cursor/wizard-howto-guide cursor/runtime-storyboard-b8ec \
  cursor/config-wizard-2778 cursor/sw-master-soak-8e09 cursor/codesys-master-io-b3ab \
  cursor/soak-abs-jitter-4215 cursor/mock-soak-report-90be cursor/demo-ctt-gaps-6170 \
  cursor/v0.1.0-snapshot-5750 cursor/demo-package-polish-7aa2 cursor/ctt-board-pn-gaps-39a9 \
  cursor/multi-protocol-fake-sensor-eb43 cursor/fake-sensor-ctt-demo-f7c5 cursor/mb-slmp-ctt-bundle-0e3a \
  cursor/eip-ctt-bundle-grade-0e3a cursor/pn-ctt-bundle-grade-896f cursor/ctt-board-matrix-keys-9b1f \
  cursor/ctt-test-board-9b1f cursor/app-facing-fb-api-09b2 docs/json-config-flow-demo \
  cursor/merge-product-stacks-bd6a cursor/ctt-unify-main-2a6d \
  cursor/config-json-viz-bd6a cursor/ctt-fill-pn-gaps-c145 cursor/eip-ctt-plugin-a0b6 \
  cursor/ctt-modbus-slmp-plugins-56eb cursor/ctt-phase3-5427 cursor/ctt-phase2-ad45 \
  cursor/ctt-phase1-e0d7 cursor/docs-ctt-design-8843 cursor/ethernetip-self-stack-5148 \
  cursor/slmp-stack-extensible-c5ee cursor/modbus-stack-server-ed82

# 2) 보관 3개: 태그로 옮기고 브랜치 삭제
for b in profinet-cm-rtc1-dcp-eff7 codesys-protocol-pooltest-e12b skip-ethercat-no-asic-ee42; do
  git push origin "origin/cursor/$b:refs/tags/archive/$b" && git push origin --delete "cursor/$b"
done
```

**재발 방지:** GitHub 저장소 Settings → General → Pull Requests → "Automatically delete head branches" 를 켠다
(저장소 관리자 작업; 켠 뒤 병합되는 PR 부터 적용). 코딩 에이전트는 작업이 끝나 PR 이 병합되면 브랜치를 남기지 않는다.

**완료 조건:** `git ls-remote --heads origin` 에 `main` 과 진행 중인 작업 브랜치만 남고, `archive/*` 태그 3개가 있다.

## 이후 추가될 항목

네 프로토콜 모두 반영 완료. 새로 발견되는 항목은 T14 이후로 덧붙인다.
