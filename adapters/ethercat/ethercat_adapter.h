#ifndef ETHERCAT_ADAPTER_H
#define ETHERCAT_ADAPTER_H

#include "protocol_adapter.h"

/*
 * EtherCAT SubDevice 어댑터: 이 타깃에는 ESC(ASIC/FPGA)가 없어 구현하지 않는다.
 * config.json 의 protocol 을 "ethercat" 으로 설정하면 init() 이 -ENOTSUP 을
 * 반환한다. 근거와 재검토 조건은 docs/ethercat.md.
 */
protocol_adapter_t *ethercat_adapter_create(void);

#endif /* ETHERCAT_ADAPTER_H */
