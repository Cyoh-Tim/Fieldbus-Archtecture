#ifndef PROFINET_ADAPTER_H
#define PROFINET_ADAPTER_H

#include "protocol_adapter.h"

/*
 * 자체 PROFINET IO Device 스택 (stacks/profinet) 어댑터.
 * Device, RT Class 1 cyclic IO. CC-C IRT / RT Class 3 는 지원하지 않는다.
 * HMAC integrity 는 protocol_params.security_class=1 일 때만 (PI Sec Class 1 아님).
 */
protocol_adapter_t *profinet_adapter_create(void);

#endif /* PROFINET_ADAPTER_H */
