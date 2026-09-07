#ifndef MODBUS_ADAPTER_H
#define MODBUS_ADAPTER_H

#include "protocol_adapter.h"

/* protocol_params 예시:
 *   { "ip": "192.168.0.10", "port": 502, "unit_id": 1 }
 * point.address.modbus 예시:
 *   { "register_type": "holding", "start": 40001 }
 * register_type: "holding" | "input" | "coil" | "discrete"
 */
protocol_adapter_t *modbus_adapter_create(void);

#endif /* MODBUS_ADAPTER_H */
