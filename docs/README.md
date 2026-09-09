# docs

장비 없는 데모(비전문가·내부용). **인증이 아니다.** PLC / NIC / `CAP_NET_RAW` 없음.
버전: [`VERSION`](../VERSION) · [`CHANGELOG.md`](../CHANGELOG.md) (v0.1.0 내부 스냅샷).

| 열기 | 역할 |
|------|------|
| [`demo.md`](demo.md) | **10분 스크립트** (이 저장소의 “보여 줘”) |
| [`index.html`](index.html) | 브라우저 허브 (이 폴더를 파일로 열 때) |
| [`json-config-flow.html`](json-config-flow.html) | JSON → 런타임 애니메이션 (데모 정본 HTML) |
| [`config-viz.html`](config-viz.html) | (선택) 필드 의미·메모리 맵 시각화 |
| [`ctt_board.html`](ctt_board.html) | CTT 시나리오 현황 보드 (≠ 인증) |
| [`app_api.md`](app_api.md) | 앱은 `fb_api.h` 만 |

터미널 한 줄: `./examples/run_mock_flow.sh` — [`examples/README.md`](../examples/README.md).

## 설계·스택

| 문서 | 내용 |
|------|------|
| [`design.md`](design.md) | 아키텍처 배경 |
| [`modbus_stack.md`](modbus_stack.md) | Modbus TCP (libmodbus 없음) |
| [`slmp_stack.md`](slmp_stack.md) | SLMP Binary 3E (ASCII/4E 제품 목표 아님) |
| [`ethernetip_stack.md`](ethernetip_stack.md) · [`ethernetip_guide.md`](ethernetip_guide.md) | EtherNet/IP Adapter |
| [`profinet_stack.md`](profinet_stack.md) | PROFINET CC-B + RT Class 1 (IRT/CC-C 없음) |

## CTT (내부 게이트, 인증 아님)

| 문서 | 내용 |
|------|------|
| [`ctt.md`](ctt.md) | 공통 runner + 프로토콜 플러그인 |
| [`ctt_board.md`](ctt_board.md) | 보드 배지·데이터 재생성 |
| [`ctt_pn_bundle.md`](ctt_pn_bundle.md) · [`ctt_eip_bundle.md`](ctt_eip_bundle.md) | PN/EIP 내부 bundle-grade (≠ PI/ODVA) |
| [`ctt_mb_bundle.md`](ctt_mb_bundle.md) · [`ctt_slmp_bundle.md`](ctt_slmp_bundle.md) | Modbus/SLMP 내부 bundle-grade |
| [`ctt_pi_matrix.md`](ctt_pi_matrix.md) · [`ctt_odva_matrix.md`](ctt_odva_matrix.md) | 내부 매핑 |
| [`ctt_modbus_matrix.md`](ctt_modbus_matrix.md) · [`ctt_slmp_matrix.md`](ctt_slmp_matrix.md) | FC / 3E 커버리지 |
| [`ctt_lab.md`](ctt_lab.md) | 랩 / AF_PACKET (기본 데모 아님) |
