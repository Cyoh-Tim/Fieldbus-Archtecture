#ifndef ADAPTER_REGISTRY_H
#define ADAPTER_REGISTRY_H

#include "protocol_adapter.h"

typedef protocol_adapter_t *(*adapter_ctor_fn)(void);

/*
 * config.json 의 "protocol" 문자열로 어댑터 생성자를 찾는다.
 * 실패 시 NULL. 새 프로토콜 추가 시 adapter_registry.c 의
 * 정적 테이블에 한 줄만 추가하면 된다.
 */
adapter_ctor_fn adapter_registry_lookup(const char *protocol_name);

#endif /* ADAPTER_REGISTRY_H */
