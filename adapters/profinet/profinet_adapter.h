#ifndef PROFINET_ADAPTER_H
#define PROFINET_ADAPTER_H

#include "protocol_adapter.h"

/*
 * 자체 PROFINET IO Device 스택 (stacks/profinet) 어댑터.
 * CC-B + RT Class 1. Optional vendor integrity extension (HMAC-SHA256),
 * off unless protocol_params.security_class is set. Not PI Security Class.
 * IRT / RT Class 3 는 지원하지 않는다.
 */
protocol_adapter_t *profinet_adapter_create(void);

#endif /* PROFINET_ADAPTER_H */
