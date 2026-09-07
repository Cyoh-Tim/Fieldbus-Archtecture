#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "protocol_adapter.h"

/*
 * cycle_ms 주기로 adapter->poll_cycle() 을 호출한다.
 * *stop_flag 가 0이 아니게 되면 루프를 빠져나온다 (시그널 핸들러에서 설정).
 *
 * 실측 결과(에이징 1~2시간, PREEMPT_RT 미적용): 8ms 스펙 기준 최대 지연 편차
 * 0.1ms 로 확인되어 일반 타이머 기반으로 충분한 것으로 판단함. 다만 어댑터가
 * 늘어나거나 장기 운용/부하 조건이 달라지면 재검증이 필요할 수 있으므로,
 * 아래 구현은 사이클마다 실제 소요 시간을 측정해 초과 시 경고 로그를 남긴다.
 */
int scheduler_run(protocol_adapter_t *adapter, int cycle_ms,
                   volatile int *stop_flag);

#endif /* SCHEDULER_H */
