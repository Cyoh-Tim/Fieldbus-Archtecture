# EtherNet/IP 입문 가이드 (이 저장소 코드 기준)

프로토콜을 몰라도, **이 데몬이 센서에서 무엇을 하는지**만 이해하면 됩니다.
아래 설명은 전부 `stacks/ethernetip/` · `adapters/ethernetip/` 실제 코드를 기준으로 합니다.

PROFINET 문서(`docs/profinet_stack.md`)와 같은 역할입니다.
차이: EIP는 **TCP/UDP(표준 이더넷)** 위에서 움직이고, PN처럼 raw 이더넷 전용이 아닙니다.

---

## 1. 한 줄 요약

PLC(스캐너)가 주기적으로 센서(어댑터)와 **입·출력 바이트 덩어리(Assembly)** 를 교환합니다.
센서 앱은 Assembly 안에 바코드·상태·트리거를 넣고, config JSON으로 위치만 정합니다.

```
  PLC / Scanner                         Sensor (이 데몬)
  ─────────────                         ────────────────
  TCP 44818  Explicit (설정·조회)  ←→   Identity / Assembly / CM …
  UDP 2222   Class 1 cyclic I/O   ←→   input_assembly / output_assembly
```

역할 이름:

| 이 프로젝트 용어 | CIP 용어 | 하는 일 |
|------------------|----------|---------|
| Adapter (`role: server`) | Target | 센서가 되어 PLC의 연결을 받음 (**기본**) |
| Originator (`role: client`) | Client/Scanner | 센서가 PLC 태그를 읽/씀 |

---

## 2. 핵심 개념 세 가지

### (1) Encapsulation — “편지 봉투”

모든 CIP 메시지는 24바이트 **Encapsulation 헤더** 안에 들어갑니다.
명령 예: `RegisterSession`, `SendRRData`, `ListIdentity`.

구현: `eip_encap_process()` in `stacks/ethernetip/src/eip_encap.c`

### (2) CIP Object — “장치 안의 서류철”

장치는 서류철(Object)들의 집합입니다. PLC는 “Identity 서류철의 Vendor ID 속성을 읽어라”처럼 요청합니다.

| Class | 이름 | 이 스택에서 |
|-------|------|-------------|
| 0x01 | Identity | 벤더/제품명/상태/Protection Mode |
| 0x04 | Assembly | 실제 센서 데이터 버퍼 |
| 0x06 | Connection Manager | Forward Open/Close (주기 통신 시작/종료) |
| 0x48 | QoS | DSCP 값 (CT 기본값 포함) |
| 0xF5 | TCP/IP Interface | IP/ACD 상태 |
| 0x109 | LLDP Management | 링크 이웃 알림(TX) — 신규 인증 필수 |

라우팅: `eip_cip_route()` in `stacks/ethernetip/src/eip_cip.c`

### (3) Class 1 Connection — “8ms마다 주고받는 파이프”

1. PLC가 **Forward Open** 으로 “이 Assembly를 이 RPI(주기)로 교환하자”고 요청  
2. 수락되면 UDP 2222로 **입력/출력 이미지**를 반복 전송  
3. 입력이 끊기면 **워치독**이 연결을 닫음 (실시간성 보호)

```76:110:stacks/ethernetip/src/eip_io.c
void eip_io_produce(eip_stack_t *s)
{
    uint64_t now = eip_now_ns();
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        // ... RPI 주기가 되지 않았으면 skip ...
        // Sequenced Address + Connected Data 로 input_assembly 송신
```

---

## 3. config만으로 센서 붙이기

예제: `config/example.ethernetip.json`

```json
{
  "protocol": "ethernetip",
  "cycle_ms": 8,
  "protocol_params": {
    "role": "server",
    "security_class": 1,
    "psk_hex": "1111...1111",
    "input_assembly": 150,
    "output_assembly": 101,
    "input_size": 512,
    "output_size": 128,
    "lldp_enable": true,
    "acd_enable": true
  },
  "points": [
    {
      "name": "barcode_value",
      "access": "read",
      "length": 32,
      "address": {
        "ethernetip": { "assembly": 150, "byte_offset": 0, "length": 32 }
      }
    }
  ]
}
```

읽는 법:

- `access: read` → 센서가 **채우는** 값 → `input_assembly` (T→O, PLC가 읽음)
- `access: write` → PLC가 **쓰는** 값 → `output_assembly` (O→T, 센서가 읽음)
- `byte_offset` → Assembly 바이트 배열 안에서의 위치

어댑터가 포인트를 파싱해 스택 process image에 연결합니다:

```290:310:adapters/ethernetip/ethernetip_adapter.c
    /* Auto-expand process image if points need more room */
    for (int i = 0; i < ctx->point_count; i++) {
        eip_point_t *pt = &ctx->points[i];
        int end = pt->byte_offset + pt->length;
        // ... input_size / output_size 자동 확장 ...
```

---

## 4. 실시간성 (PROFINET과 같은 주의)

이 데몬의 스케줄러는 **약 8ms**마다 `poll_cycle`을 호출합니다 (`core/scheduler.c`).
에이징 테스트에서 최대 지연 편차 약 0.1ms — **밀리초급 RT**이지, IRT/마이크로초 동기화는 목표 밖입니다.

EtherNet/IP 스택이 지키는 규칙:

1. **RPI에 맞춰** Class 1 송신 (`eip_io_produce`)
2. **워치독**으로 죽은 연결 정리 (`eip_io_watchdog`)
3. **poll 예산** — 한 사이클에 TCP/UDP를 무한히 처리하지 않음 (`EIP_POLL_*_BUDGET`)
4. LLDP 등 비주기 작업은 hot path에서 raw 소켓을 돌리지 않음
5. poll이 7ms를 넘으면 경고 로그

```c
/* eip_stack_poll() 요지 */
accept_clients(budget);
service_tcp(budget);
service_udp(budget);
eip_io_watchdog();
eip_io_produce();   /* RPI 도래분만 */
eip_lldp_poll();    /* 주기 도래 시에만 프레임 생성 */
```

---

## 5. 보안 (Security Class)

| Class | 의미 | 설정 |
|-------|------|------|
| 0 | 랩/개발 open | 기본 비권장 |
| 1 | Integrity — FO/Set 등에 HMAC | `psk_hex` 필수 |
| 2 | 1 + TLS(TCP 2221) | CIP Security 방향 기밀성 |

Class 1에서 MAC이 없으면 Forward Open이 거부됩니다 (`eip_sec_check_ucmm`).
공식 CIP Security CT 전체(인증서 수명주기·DTLS I/O)는 제품 랩에서 이어서 합니다.

---

## 6. “최신 ODVA까지 ship 준비”에 넣은 것

신규 장치 CT(CT21→CT23 계열)에서 자주 막히는 항목을 코드에 반영했습니다.

| 항목 | 코드/문서 |
|------|-----------|
| QoS DSCP 기본값 (Explicit 0x1B 등) | `eip_cip.c` QoS Object |
| ACD + Identity Minor Recoverable Fault | `eip_stack_acd_conflict`, TCP/IP attr 10 |
| LLDP TX + Management Object 0x109 | `eip_lldp.c`, EDS |
| Class 1 timeout | `eip_io_watchdog` |
| EDS / SOC 초안 | `stacks/ethernetip/eds/`, `docs/ethernetip_soc.md` |
| Security Class 1/2 | `eip_sec.c` |

**공식 ODVA Declaration of Conformity** 는 멤버십 + 공인 랩 CT 후에 나옵니다.
스택만으로 인증서가 나오지는 않습니다. PROFINET의 “PI 인증은 제품 프로세스”와 같은 위치입니다.

---

## 7. 실행·테스트

```bash
mkdir -p build && cd build
cmake .. && make
./test_eip_stack          # CT21/23 ship profile 단위 테스트
./multiproto_daemon ../config/example.ethernetip.json
```

실기 PLC 연동 시:

1. `mock` 끄기  
2. `vendor_id` 를 ODVA 할당 값으로  
3. Assembly 번호/크기를 PLC 가이드에 맞추기  
4. Security Class 1이면 스캐너/툴이 integrity MAC item(`0x00C1`)을 붙이는지 확인  

더 짧은 범위 표는 [`ethernetip_stack.md`](ethernetip_stack.md), SOC 초안은 [`ethernetip_soc.md`](ethernetip_soc.md).
