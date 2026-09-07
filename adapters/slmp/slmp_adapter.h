#ifndef SLMP_ADAPTER_H
#define SLMP_ADAPTER_H

#include "protocol_adapter.h"

/* protocol_params 예시 (3E 프레임, 클라이언트 역할):
 *   { "plc_ip": "192.168.0.20", "port": 5000,
 *     "network_no": 0, "pc_no": 255, "frame": "3E" }
 * point.address.slmp 예시:
 *   { "device_code": "D", "start": 100 }
 */
protocol_adapter_t *slmp_adapter_create(void);

#endif /* SLMP_ADAPTER_H */
