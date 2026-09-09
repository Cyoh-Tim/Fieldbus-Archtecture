#ifndef MODBUS_ADAPTER_H
#define MODBUS_ADAPTER_H

#include "protocol_adapter.h"

/*
 * Modbus TCP adapter — 센서/PLC 통신 가이드의 표기를 최대한 수용.
 *
 * protocol_params:
 *   role, ip|bind_ip|host, port, unit_id, unit_id_any,
 *   client_timeout_ms, max_clients, n_holding, n_input, n_coil, n_discrete
 *
 * point:
 *   data_type (uint8..float64, bool, string, raw, bcd16/32 + 별칭)
 *   length, scale|gain, offset, byte_order, word_order, endian(ABCD|BADC|CDAB|DCBA)
 *   chars_per_register, string_swap, trim_null
 *
 * address.modbus:
 *   register_type|type (holding|hr|4x|input|ir|3x|coil|0x|discrete|1x …)
 *   start|address|register|addr (숫자 또는 "40001" 문자열)
 *   offset|reg_offset, byte_offset, quantity|count, bit|bit_offset, bit_count
 *   zero_based|address_base ("zero"|"pdu"|"modicon")
 *
 * access: read | write | readwrite  (PROFINET과 같은 PLC 관점)
 */
protocol_adapter_t *modbus_adapter_create(void);

#endif /* MODBUS_ADAPTER_H */
