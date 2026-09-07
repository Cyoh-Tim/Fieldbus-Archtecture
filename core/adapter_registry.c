#include "adapter_registry.h"

#include <string.h>

#include "modbus_adapter.h"
#include "slmp_adapter.h"
#include "cclink_adapter.h"
#include "ethernetip_adapter.h"
#include "profinet_adapter.h"

typedef struct {
    const char *protocol_name;
    adapter_ctor_fn ctor;
} registry_entry_t;

/*
 * 여기가 "하나의 프로토콜만 선택해서 동작"의 핵심 지점이다.
 * config.json 의 protocol 필드 값과 정확히 일치하는 항목의 생성자만 호출된다.
 *
 * 새 프로토콜(EtherCAT 등) 추가 시:
 *   1. adapters/<name>/ 에 헤더+구현 추가 (protocol_adapter.h 구현)
 *   2. 아래 테이블에 한 줄 추가
 * 코어의 다른 파일은 수정하지 않는다.
 */
static const registry_entry_t k_registry[] = {
    {"modbus_tcp", modbus_adapter_create},
    {"slmp", slmp_adapter_create},
    {"cclink", cclink_adapter_create},         /* 현재 스텁(NotImplemented) */
    {"ethernetip", ethernetip_adapter_create}, /* 구매 스택 래핑 */
    {"profinet", profinet_adapter_create},     /* 구매 스택 래핑, RT 등급까지만 지원 */
};

adapter_ctor_fn adapter_registry_lookup(const char *protocol_name)
{
    if (!protocol_name) {
        return NULL;
    }
    size_t n = sizeof(k_registry) / sizeof(k_registry[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(k_registry[i].protocol_name, protocol_name) == 0) {
            return k_registry[i].ctor;
        }
    }
    return NULL;
}
