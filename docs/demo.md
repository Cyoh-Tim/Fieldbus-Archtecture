# 장비 없는 제품 데모

PLC / NIC / `CAP_NET_RAW` 없이, 비전문가·내부 데모용 **한 화면** 스크립트다.

**이건 인증이 아니다.** `ctest` green 과 [`ctt_board.html`](ctt_board.html) 의 통과 배지는
PI / ODVA / Modbus.org / Mitsubishi 공인 랩 evidence 가 아니다.
PROFINET 은 **CC-B + RT Class 1** 만. **IRT / CC-C 는 목표 아님.**

한 줄: JSON 이 프로토콜을 고른다 → 가짜 센서가 포인트를 게시한다 → 내부 CTT mock 이 같은 스택을 확인한다.

브라우저 허브: [`docs/index.html`](index.html) (이 폴더를 브라우저로 열 때).

---

## 0. 설정 마법사 (JSON을 처음 만든다면)

```
xdg-open docs/config-wizard.html
```

질문에 답하면 `config.json` 이 만들어집니다. 프로토콜 문서를 읽지 않아도 됩니다.
Modbus / SLMP 은 주소 칸을 일상 말로 묻고, EtherNet/IP · PROFINET 은 예제 기본값을 안내합니다.
확인 화면의 **이 JSON으로 동작 보기** 로 아래 스토리보드에 바로 넘길 수 있습니다.

처음이면 화면으로 따라하기:

```
xdg-open docs/wizard-howto.html
```

Modbus TCP → 별명 기본값 → 우리는 장비 → 데모 / 장비 없음 → + 온도 (×0.1) → `config.json` 받기.
스크린샷 6장입니다. 마법사 자체는 바꾸지 않습니다.

## 0.5 설정 → 동작 스토리보드 (브라우저, 빌드 없음)

```
xdg-open docs/runtime-storyboard.html
```

예제 버튼(Modbus / SLMP / EtherNet/IP / PROFINET) 또는 마법사 JSON 붙여넣기 →
**다음 단계** 또는 **▶ 자동재생**.
`protocol` 파싱 → 어댑터 선택 → 연결(기다림/붙음) → 포인트 표 → 한 사이클 raw/eng 순입니다.
가벼운 탭 데모는 아래 JSON 흐름에 그대로 있습니다.

## 1. JSON → 런타임 (브라우저, 빌드 없음)

```
xdg-open docs/json-config-flow.html
```

또는 파일을 더블클릭. 탭을 **Modbus → SLMP → EtherNet/IP → PROFINET** 순으로 바꾸고
**▶ 동작 보기**. `protocol` 한 줄과 `points` 주소만 바뀌는 모델이다.

앱은 프로토콜 헤더 없이 [`app_api.md`](app_api.md) (`fb_api.h`) 만 쓴다.

## 2. 가짜 센서 → fb_api → CTT mock (터미널)

저장소 루트. 의존성: `cmake`, C 컴파일러, `libssl-dev`, `libcjson-dev`(없으면 CMake 가 가져옴).
**sudo / 원시 소켓 없음.**

```
./examples/run_mock_flow.sh              # 네 프로토콜 (Modbus → SLMP → EIP → PN)
./examples/run_mock_flow.sh modbus       # 하나만 (가장 짧다)
./examples/run_mock_flow.sh profinet
```

이미 구성한 빌드 트리:

```
cmake --build build --target run_mock_flow
```

프로토콜마다 하는 일:

1. `fake_sensor_app --once` 가 가짜 바코드/온도를 `fb_write_*` 로 게시하고, 같은 세션 `fb_read_*` 로 확인
2. `ctest -LE soak_ci -L <proto>` 로 해당 스택의 **in-process** CTT mock 게이트

CTT 는 떠 있는 앱 소켓에 붙지 않는다. 순서는 제품 스토리다:
앱이 포인트를 읽고 쓴다 → 이어서 같은 스택의 mock 게이트도 통과한다.

상세·한계: [`examples/README.md`](../examples/README.md).

## 3. 커버리지 보드 (인증 아님)

```
xdg-open docs/ctt_board.html
```

통과 / 건너뜀 / 갭 / 범위 밖. **이 보드가 공식 인증이 아니다.**
배지 의미: [`ctt_board.md`](ctt_board.md).

---

## 하지 않는 것

| 하지 않음 | 대신 |
|-----------|------|
| PLC·실 NIC·`CAP_NET_RAW` | mock / 루프백 (`iface: mock`, `127.0.0.1`) |
| PI / ODVA / Modbus.org / Mitsubishi 인증 클레임 | 내부 CTT mock + 보드 |
| PROFINET IRT / CC-C | CC-B + RT Class 1 만 |
| 라이브 앱에 CTT 를 붙이기 | in-process DUT (`stacks/`) |

랩(AF_PACKET)은 기본 데모가 아니다: [`ctt_lab.md`](ctt_lab.md), `tests/run_ctt_lab.sh`.
소프트웨어 마스터(CODESYS 없이 라이브 TCP 루프백): [`sw_master_io.md`](sw_master_io.md).
CODESYS SoftPLC 마스터(Modbus 정본, 앱은 IDE 수동): [`codesys_master_io.md`](codesys_master_io.md).

선택 시각화(정본 아님): 필드 의미·메모리 맵 [`config-viz.html`](config-viz.html).
JSON을 처음 만든다면 [`config-wizard.html`](config-wizard.html).
처음이면 화면으로 따라하기: [`wizard-howto.html`](wizard-howto.html).
그 JSON이 데몬을 어떻게 움직이는지: [`runtime-storyboard.html`](runtime-storyboard.html).
가벼운 탭 데모 HTML 은 **`json-config-flow.html`** 이다.

## 다음에 읽을 것

- [`app_api.md`](app_api.md) — 앱 C API
- [`ctt.md`](ctt.md) — CTT 설계 (공통 runner + 플러그인)
- 스택 가이드: [`modbus_stack.md`](modbus_stack.md) · [`slmp_stack.md`](slmp_stack.md) ·
  [`ethernetip_stack.md`](ethernetip_stack.md) · [`profinet_stack.md`](profinet_stack.md)
