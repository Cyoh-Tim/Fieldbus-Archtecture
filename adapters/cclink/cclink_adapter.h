#ifndef CCLINK_ADAPTER_H
#define CCLINK_ADAPTER_H

#include "protocol_adapter.h"

/* CC-Link 어댑터: 아직 스택/사양 미확정.
 * 레지스트리 확장성 검증을 위한 스텁이며, config.json 의 protocol 을
 * "cclink" 로 설정해도 init() 단계에서 명확한 에러로 실패한다. */
protocol_adapter_t *cclink_adapter_create(void);

#endif /* CCLINK_ADAPTER_H */
