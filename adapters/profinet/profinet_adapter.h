#ifndef PROFINET_ADAPTER_H
#define PROFINET_ADAPTER_H

#include "protocol_adapter.h"

/*
 * 자체 PROFINET IO Device 스택 (stacks/profinet) 어댑터.
 * Device, RT Class 1 cyclic IO. CC-C IRT / RT Class 3 는 지원하지 않는다.
 * HMAC integrity 는 protocol_params.security_class=1 일 때만 (PI SC1 아님).
 * 랩 SC1 서브셋(AR 중 DCP Name/IP Set 거부, SNMP 읽기 전용)은 스택 기본 동작이다.
 */
protocol_adapter_t *profinet_adapter_create(void);

#endif /* PROFINET_ADAPTER_H */
