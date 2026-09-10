# docs

장비 없는 데모(비전문가·내부용). **인증이 아니다.** PLC / NIC / `CAP_NET_RAW` 없음.
버전: [`VERSION`](../VERSION) · [`CHANGELOG.md`](../CHANGELOG.md) (v0.1.0 내부 스냅샷).

| 열기 | 역할 |
|------|------|
| [`demo.md`](demo.md) | **10분 스크립트** (이 저장소의 “보여 줘”) |
| [`sw_master_io.md`](sw_master_io.md) | 소프트웨어 마스터 soak (MB/SLMP/EIP 라이브 루프백; PN 은 mock 만) |
| [`codesys_master_io.md`](codesys_master_io.md) | CODESYS SoftPLC 마스터 ↔ 우리 DUT (Modbus 정본; SoftPLC 앱은 수동) |
| [`index.html`](index.html) | 브라우저 허브 (이 폴더를 파일로 열 때) |
| [`config-wizard.html`](config-wizard.html) | 질문으로 `config.json` 생성 (비전문가 입문) |
| [`wizard-howto.html`](wizard-howto.html) | 설정 마법사 화면 따라하기 (Modbus 스크린샷) |
| [`runtime-storyboard.html`](runtime-storyboard.html) | 내 JSON이 런타임을 움직이는 단계별 스토리보드 |
| [`json-config-flow.html`](json-config-flow.html) | JSON → 런타임 애니메이션 (가벼운 탭 데모) |
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
| [`ctt_lab.md`](ctt_lab.md) | 랩 / AF_PACKET / Windows CODESYS PN (기본 데모 아님) |
| [`soak_report_20260909.md`](soak_report_20260909.md) | 2026-09-09 장비 없는 mock soak (5min×4; **인증 아님**) |
| [`reports/analysis_20260910.md`](reports/analysis_20260910.md) | 2026-09-10 정적+동적 분석 (ASan/UBSan, clang-tidy, cppcheck; **인증 아님**) |
| [`reports/full_test_20260910.md`](reports/full_test_20260910.md) | 2026-09-10 풀테스트 (daemon+API+CTT `ctest` 포함 soak_ci, mock/sw-master/stand-in, ASan; **인증 아님**) |
