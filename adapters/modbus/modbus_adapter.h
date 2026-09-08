#ifndef MODBUS_ADAPTER_H
#define MODBUS_ADAPTER_H

#include "protocol_adapter.h"

/*
 * Modbus TCP adapter — wraps stacks/modbus (자체 구현).
 *
 * protocol_params:
 *   { "role":"server|client", "ip":"...", "port":502, "unit_id":1 }
 *
 * point 공통 (가이드 문서 값을 그대로):
 *   data_type, length, scale, offset, byte_order, word_order
 *
 * address.modbus:
 *   register_type: holding|input|coil|discrete
 *   start:         가이드 주소(40001 등) 또는 0-based
 *   offset:        start 에 더하는 레지스터/비트 오프셋 (기본 0)
 *   byte_offset:   멀티바이트 값 안의 바이트 오프셋 (기본 0)
 *   quantity:      레지스터/비트 개수 (생략 시 data_type/length 로 추론)
 *   bit:           holding/input 안의 비트 번호(0..15), bool 용
 *   zero_based:    true 이면 start 정규화 생략
 *
 * access 의미 (PROFINET과 동일):
 *   "read"  — PLC가 읽는 값 → 앱이 write_point
 *   "write" — PLC가 쓰는 값 → 앱이 read_point
 */
protocol_adapter_t *modbus_adapter_create(void);

#endif /* MODBUS_ADAPTER_H */
