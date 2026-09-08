# Fieldbus Architecture

Modbus / SLMP / CC-Link / EtherNet-IP / PROFINET 중 **한 번에 하나의 프로토콜**을
config.json 설정만으로 선택해 동작시키는 필드버스 런타임.

PROFINET 은 구매 스택 래핑이 아니라 `stacks/profinet/` 자체 Device 스택이다.
범위는 **CC-B + RT Class 1 + Security Class 1(HMAC integrity)**. IRT 없음.
자세한 내용은 [`docs/profinet_stack.md`](docs/profinet_stack.md).

전체 설계 배경은 [`docs/design.md`](docs/design.md).

## 디렉토리 구조
```
include/               ProtocolAdapter 공통 인터페이스
core/                   코어(설정 로더, 스케줄러, 어댑터 레지스트리, main)
adapters/modbus/        Modbus TCP 어댑터 — 자체 스택 (libmodbus 없음)
adapters/slmp/          SLMP 어댑터 — Binary 3E 자체 스택
adapters/cclink/        CC-Link 어댑터 (미확정, 스텁)
adapters/ethernetip/    EtherNet/IP 어댑터 — 자체 스택
adapters/profinet/      PROFINET 어댑터 — 자체 스택 (RT Class 1, IRT 없음)
stacks/modbus/          Modbus TCP 서버/클라이언트
stacks/slmp/            SLMP Binary 3E
stacks/ethernetip/      EtherNet/IP Adapter + Originator
stacks/profinet/        PROFINET IO Device (DCP/LLDP/RPC/RTC1/SNMP)
demos/sensor/           라이브 센서 데모 (값이 매 사이클 변함)
tests/codesys/          CODESYS 풀테스트 IEC + 마스터 + 설치 스크립트
config/                 config.schema.json + 예제/데모 설정
docs/design.md          설계 배경 전체 문서
```

## 빌드
```
sudo apt install libcjson-dev libssl-dev
cmake -S . -B build && cmake --build build
```

## 실행
```
./build/multiproto_daemon config/example.modbus.json
./build/test_pn_stack
./build/sensor_demo config/demo.sensor.modbus.json
```

## CODESYS 풀테스트 (센서 라이브 데이터)
```
bash tests/codesys/run_pooltest.sh
```
설명: [`docs/codesys_pooltest.md`](docs/codesys_pooltest.md).
CODESYS Control SL 2시간 데모 설치는 `tests/codesys/try_install_codesys.sh`.
IEC 앱은 `tests/codesys/PLC_PRG_pool.st`.

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
