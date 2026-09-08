# Fieldbus Architecture

Modbus / SLMP / CC-Link / EtherNet-IP / PROFINET 중 **한 번에 하나의 프로토콜**을
config.json 설정만으로 선택해 동작시키는 필드버스 런타임.

PROFINET 은 구매 스택 래핑이 아니라 `stacks/profinet/` 자체 Device 스택이다.
범위는 **CC-B + RT Class 1 + Security Class 1(HMAC integrity)**. IRT 없음.
자세한 내용은 [`docs/profinet_stack.md`](docs/profinet_stack.md).

**EtherCAT 은 이 타깃에서 구현하지 않는다.** SubDevice(슬레이브)는 ESC ASIC
또는 FPGA IP가 필요하고, 현재 보드는 일반 NIC만 있다. 소프트웨어 슬레이브나
Master(SOEM)로 우회하지 않는다. 근거는 [`docs/ethercat.md`](docs/ethercat.md).

전체 설계 배경은 [`docs/design.md`](docs/design.md).

## 디렉토리 구조
```
include/               ProtocolAdapter 공통 인터페이스
core/                   코어(설정 로더, 스케줄러, 어댑터 레지스트리, main)
adapters/modbus/        Modbus TCP 어댑터 (libmodbus) - 벤더 의존성 없음
adapters/slmp/          SLMP 어댑터 (자체 구현, 3E 프레임은 TODO)
adapters/cclink/        CC-Link 어댑터 (미확정, 스텁)
adapters/ethernetip/    EtherNet/IP 어댑터 (구매 스택 래핑, 연동부 TODO)
adapters/profinet/      PROFINET 어댑터 — 자체 스택 연결 (RT Class 1, IRT 없음)
adapters/ethercat/      EtherCAT 어댑터 — ESC 없음, init 시 -ENOTSUP
stacks/profinet/        PROFINET IO Device 스택 (DCP/LLDP/RPC/RTC1/SNMP/Sec1)
third_party/            EtherNet/IP 구매 벤더 스택 배치 위치 (git 커밋 안 함)
config/                 config.schema.json + 예제 설정 파일
docs/design.md          설계 배경 전체 문서
docs/ethercat.md        EtherCAT 을 ASIC 없이 구현하지 않는 근거
```

## 빌드
```
sudo apt install libmodbus-dev   # Modbus 어댑터용
mkdir build && cd build
cmake ..
make
```
EtherNet/IP 구매 스택을 `third_party/`에 배치한 뒤에는:
```
cmake -DENABLE_ETHERNETIP=ON ..
```

## 실행
```
./build/multiproto_daemon config/example.modbus.json
./build/test_pn_stack
./build/test_ethercat_skip
./build/multiproto_daemon config/example.profinet.json
```

## 새 프로토콜 추가하는 법
1. `adapters/<name>/` 에 `include/protocol_adapter.h` 구현
2. `core/adapter_registry.c` 정적 테이블에 한 줄 등록
3. `config/config.schema.json` 의 `protocol` enum 에 추가
4. `CMakeLists.txt` 에 라이브러리 타깃 추가

코어 코드(`core/*.c`)는 수정하지 않는다.
EtherCAT 을 이 목록에 채워 넣는 것은 ESC 하드웨어가 생기기 전에는 하지 않는다
(`docs/ethercat.md`).

## 실시간 등급 관련
타깃이 A-core(ASIC 없음)라 PROFINET IRT는 지원 범위 밖이며, RT 등급까지만
목표로 한다. EtherCAT SubDevice 도 같은 이유로 범위 밖이다(ESC 필요).
8ms 사이클 기준 에이징 테스트(1~2시간, PREEMPT_RT 미적용)에서
최대 지연 편차 0.1ms로 확인되어, 현재는 일반 타이머 기반 스케줄러로 충분한
것으로 판단하고 있다. 자세한 내용은 `docs/design.md` 참고.
