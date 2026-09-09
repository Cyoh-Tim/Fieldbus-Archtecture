# 이 저장소에서 작업할 때 지켜야 할 규칙

이 문서는 Claude Code 등 구현 에이전트가 이 저장소에서 작업할 때 참고한다.
전체 설계 배경은 `docs/design.md`.

## 작업 경계 (매우 중요)
- **어댑터 하나를 구현/수정하는 작업**은 해당 `adapters/<name>/` 디렉토리와
  `include/protocol_adapter.h`(읽기 전용, 인터페이스 변경 필요 시 먼저 논의)
  범위 안에서만 진행한다. 다른 어댑터 디렉토리는 건드리지 않는다.
- **`core/` 는 프로토콜을 몰라야 한다.** 특정 프로토콜을 위해 `core/*.c`에
  `if (protocol == ...)` 같은 분기를 추가하는 것은 설계 위반이다. 코어에서
  프로토콜별 처리가 필요해 보이면, 그건 어댑터 인터페이스가 부족하다는
  신호이므로 `protocol_adapter.h` 확장을 먼저 제안할 것.
- **EtherNet/IP / PROFINET 은 자체 스택** (`stacks/ethernetip/`, `stacks/profinet/`).
  벤더 라이선스 코드를 쓸 때만 `third_party/` 에 둔다(현재 EIP 런타임·CTT DUT는 자체 스택).
- 새 프로토콜(CC-Link 확정, EtherCAT 등) 추가는 README의 "새 프로토콜 추가하는
  법" 절차를 그대로 따른다. `core/adapter_registry.c`에 한 줄 추가하는 것 외에
  코어 파일을 수정하지 않는다.

## 우선순위 (docs/design.md 6장과 동일)
1. 코어 완성/검증 (이미 스캐폴딩됨 — 버그 수정/테스트 위주)
2. Modbus 어댑터 완성 (`adapters/modbus/` — 이미 대부분 구현됨, `poll_cycle`
   에서 read 포인트 일괄 캐싱하도록 확장하는 것이 다음 단계)
3. SLMP 어댑터 — 3E 프레임 인코딩/디코딩이 TODO로 남아있음. 실제 대상 PLC의
   SLMP 통신 가이드 문서(사용자가 제공)를 근거로 구현할 것. 문서 없이 임의로
   프레임 포맷을 추측하지 말 것.
4. EtherNet/IP 어댑터 — 자체 스택 (`stacks/ethernetip/`). Adapter Class 1 +
   Originator explicit + Security Class 1/2(HMAC/TLS-PSK). CTT 플러그인
   `tools/ctt/proto/ethernetip/` (DUT=자체 스택, 구매 스텁 아님).
   공식 ODVA DoC 는 멤버십+랩 제품 프로세스. 상세 `docs/ethernetip_stack.md`,
   `docs/ctt_odva_matrix.md`.
5. PROFINET 어댑터 — 자체 스택 (`stacks/profinet/`). RT Class 1 + Security Class 1.
   IRT 는 켜지 않는다. 인증/CRA 는 제품 프로세스.
6. CC-Link 스텁은 사양이 확정되기 전까지 건드리지 않는다.

## 코딩 컨벤션
- C11, 각 어댑터는 `protocol_adapter_t*`를 반환하는 `<name>_adapter_create()`
  하나만 공개 API로 노출한다.
- 에러는 음수 errno 스타일로 반환하고, 실패 원인은 `LOG_ERROR`/`LOG_WARN`
  (core/logger.h)으로 남긴다. `printf` 직접 호출 금지.
- config의 `protocol_params`/`points`는 어댑터가 cJSON으로 직접 파싱한다.
  코어는 이 내용을 해석하지 않는다 — 이 원칙을 어기는 변경(코어가 특정
  포인트 필드를 미리 해석하는 것)은 하지 않는다.

## 테스트 관련 메모
- 8ms 사이클 기준 에이징 테스트(1~2시간, PREEMPT_RT 미적용) 결과 최대 지연
  편차 0.1ms 확인됨. 스케줄러(`core/scheduler.c`) 관련 변경 시 이 여유 폭을
  참고해 회귀 여부를 판단할 것.
