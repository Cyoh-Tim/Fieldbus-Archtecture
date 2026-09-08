#include "adapter_registry.h"

#include <string.h>

#include "modbus_adapter.h"
#include "slmp_adapter.h"
#include "cclink_adapter.h"
#include "ethernetip_adapter.h"
#include "profinet_adapter.h"
#include "ethercat_adapter.h"

typedef struct {
    const char *protocol_name;
    adapter_ctor_fn ctor;
} registry_entry_t;

/*
 * 여기가 "하나의 프로토콜만 선택해서 동작"의 핵심 지점이다.
 * config.json 의 protocol 필드 값과 정확히 일치하는 항목의 생성자만 호출된다.
 *
 * 새 프로토콜 추가 시:
 *   1. adapters/<name>/ 에 헤더+구현 추가 (protocol_adapter.h 구현)
 *   2. 아래 테이블에 한 줄 추가
 * 코어의 다른 파일은 수정하지 않는다.
 *
 * EtherCAT 은 ESC ASIC/FPGA 가 없는 한 구현하지 않는다 (docs/ethercat.md).
 * 레지스트리 항목은 "알 수 없는 protocol" 대신 명확한 -ENOTSUP 를 주기 위한 것이다.
 */
static const registry_entry_t k_registry[] = {
    {"modbus_tcp", modbus_adapter_create},
    {"slmp", slmp_adapter_create},
    {"cclink", cclink_adapter_create},         /* 현재 스텁(NotImplemented) */
    {"ethernetip", ethernetip_adapter_create}, /* 구매 스택 래핑 */
    {"profinet", profinet_adapter_create},     /* 자체 스택, RT Class 1, IRT 없음 */
    {"ethercat", ethercat_adapter_create},     /* ESC 없음 → 구현하지 않음 */
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
