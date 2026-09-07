#ifndef PROFINET_ADAPTER_H
#define PROFINET_ADAPTER_H

#include "protocol_adapter.h"

/*
 * 자체 PROFINET IO Device 스택 (stacks/profinet) 어댑터.
 * CC-B + RT Class 1 + Security Class 1 (HMAC-SHA256 integrity).
 * IRT / RT Class 3 는 지원하지 않는다.
 */
protocol_adapter_t *profinet_adapter_create(void);

#endif /* PROFINET_ADAPTER_H */
