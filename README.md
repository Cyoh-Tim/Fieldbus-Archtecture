# Fieldbus Architecture

Modbus / SLMP / CC-Link / EtherNet-IP / PROFINET 중 **한 번에 하나의 프로토콜**을
config.json 설정만으로 선택해 동작시키는 필드버스 런타임.

담당자가 각 프로토콜을 몰라도, 통신 가이드의 주소만 `points`에 채우면 되도록
프로토콜 지식은 어댑터/스택 안에 캡슐화한다.

- **PROFINET**: `stacks/profinet/` 자체 Device 스택 (CC-B + RT Class 1 + Sec Class 1).
  **IRT / CC-C 는 목표 아님.** 상세: [`docs/profinet_stack.md`](docs/profinet_stack.md)
- **Modbus TCP**: `stacks/modbus/` 자체 스택 (기본 서버/슬레이브, **libmodbus 없음**).
  가이드: [`docs/modbus_stack.md`](docs/modbus_stack.md)
- **SLMP**: `stacks/slmp/` 자체 Binary 3E 스택 (제품 범위는 3E batch only; ASCII/4E 예약만).
  가이드: [`docs/slmp_stack.md`](docs/slmp_stack.md)
- **EtherNet/IP**: `stacks/ethernetip/` 자체 Adapter 스택 (구매 스텁 아님).
  가이드: [`docs/ethernetip_stack.md`](docs/ethernetip_stack.md),
  [`docs/ethernetip_guide.md`](docs/ethernetip_guide.md)

전체 설계 배경은 [`docs/design.md`](docs/design.md).
앱은 프로토콜 헤더 없이 [`docs/app_api.md`](docs/app_api.md) 의 포인트 API
(`include/fb_api.h`) 만 사용한다.
CTT 설계(공통 runner + 프로토콜 플러그인)는 [`docs/ctt.md`](docs/ctt.md).
CTT 시나리오 현황 보드: [docs/ctt_board.html](docs/ctt_board.html) (브라우저에서 열기, 인증 아님).
비전문가용 JSON→데몬 동작 애니메이션 데모: [docs/json-config-flow.html](docs/json-config-flow.html) (브라우저에서 열기).

## 디렉토리 구조
```
include/               ProtocolAdapter 공통 인터페이스 + 앱 API (`fb_api.h`)
core/                   코어(설정 로더, 스케줄러, 레지스트리, fb_api, main)
adapters/modbus/        Modbus TCP 어댑터 — 자체 스택 연결
adapters/slmp/          SLMP 어댑터 — 자체 Binary 3E 스택 연결
adapters/cclink/        CC-Link 어댑터 (미확정, 스텁)
adapters/ethernetip/    EtherNet/IP 어댑터 — 자체 스택 연결
adapters/profinet/      PROFINET 어댑터 — 자체 스택 연결 (RT Class 1, IRT 없음)
stacks/modbus/          Modbus TCP 서버/클라이언트 스택 (데몬 + CTT DUT)
stacks/slmp/            SLMP Binary 3E 스택 (데몬 + CTT DUT, ASCII/4E 없음)
stacks/ethernetip/      EtherNet/IP Adapter(+Originator) 스택
stacks/profinet/        PROFINET IO Device 스택 (DCP/LLDP/RPC/RTC1/SNMP/Sec1)
tools/ctt/              Controller Test Tool (공통 runner + proto plugins)
tests/scenarios/        CTT YAML (profinet/, ethernetip/, modbus/, slmp/)
third_party/            (선택) 향후 벤더 EIP 스택 교체 위치 — git 커밋 안 함
config/                 config.schema.json + 예제 설정 파일
docs/design.md          설계 배경 전체 문서
docs/app_api.md         애플리케이션 C API (포인트 읽기/쓰기, 스레드, reload)
docs/ctt.md             CTT 설계 (공통 runner + 프로토콜 플러그인)
docs/ctt_board.html     CTT 시나리오 현황 보드 (통과/건너뜀/갭/범위 밖)
docs/json-config-flow.html  비전문가 JSON 설정 → 데몬 동작 애니메이션 데모
```

## 빌드
데몬(어댑터) + 스택 + CTT:
```
sudo apt install libssl-dev libcjson-dev   # EIP: OpenSSL; 데몬: cJSON (없으면 FetchContent)
mkdir build && cd build
cmake ..   # BUILD_DAEMON=ON, BUILD_API=ON (기본) → 데몬 + fb_api + CTT
make
```
외부 Modbus 라이브러리(libmodbus)는 **필요 없다**.

스택 + Controller Test Tool 만 (cJSON/어댑터 불필요):
```
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON -DENABLE_PN_TESTS=ON -DENABLE_EIP_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure -LE soak_ci
```

## 실행
```
./build/fb_api_demo config/example.modbus.json
./build/multiproto_daemon config/example.modbus.json
./build/multiproto_daemon config/example.slmp.json
./build/multiproto_daemon config/example.ethernetip.json
./build/multiproto_daemon config/example.profinet.json
./build/test_mb_stack
./build/test_slmp_stack
./build/test_eip_stack
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
./build/ctt --scenario tests/scenarios/modbus/fc03_read_holding.yaml
./build/ctt --scenario tests/scenarios/slmp/encode_batch_read.yaml
```
CTT 설계·시나리오 스키마는 [`docs/ctt.md`](docs/ctt.md), 사용법은 [`tools/ctt/README.md`](tools/ctt/README.md).
시나리오 통과/건너뜀/갭 보드는 [`docs/ctt_board.html`](docs/ctt_board.html).
랩/golden 은 [`docs/ctt_lab.md`](docs/ctt_lab.md).
PI 매핑은 [`docs/ctt_pi_matrix.md`](docs/ctt_pi_matrix.md).
PN 내부 bundle-grade 로드맵·TC ID (`PN-B-*`, **≠ PI 인증**):
[`docs/ctt_pn_bundle.md`](docs/ctt_pn_bundle.md).
EIP 내부 bundle-grade 로드맵·TC ID (`EIP-A-*`, **≠ ODVA 인증**):
[`docs/ctt_eip_bundle.md`](docs/ctt_eip_bundle.md).
EIP 내부 ODVA 매핑은 [`docs/ctt_odva_matrix.md`](docs/ctt_odva_matrix.md).
Modbus/SLMP 내부 매트릭스: [`docs/ctt_modbus_matrix.md`](docs/ctt_modbus_matrix.md),
[`docs/ctt_slmp_matrix.md`](docs/ctt_slmp_matrix.md).
Modbus / SLMP 의 같은 여섯 기둥 이식은 EIP-A-v1 다음이다.

## 새 프로토콜(예: EtherCAT) 추가하는 법
1. `adapters/<name>/` 에 `include/protocol_adapter.h` 구현
2. `core/adapter_registry.c` 정적 테이블에 한 줄 등록
3. `config/config.schema.json` 의 `protocol` enum 에 추가
4. `CMakeLists.txt` 에 라이브러리 타깃 추가

코어 코드(`core/*.c`)는 수정하지 않는다.

## 실시간 등급 관련
타깃이 A-core(ASIC 없음)라 PROFINET IRT는 지원 범위 밖이며, RT 등급까지만
목표로 한다. 8ms 사이클 기준 에이징 테스트(1~2시간, PREEMPT_RT 미적용)에서
최대 지연 편차 0.1ms로 확인되어, 현재는 일반 타이머 기반 스케줄러로 충분한
것으로 판단하고 있다. 자세한 내용은 `docs/design.md` 참고.
