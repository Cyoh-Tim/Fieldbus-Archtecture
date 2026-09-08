#ifndef MODBUS_ADAPTER_H
#define MODBUS_ADAPTER_H

#include "protocol_adapter.h"

/*
 * Modbus TCP adapter — wraps stacks/modbus (자체 구현, libmodbus 없음).
 *
 * 기본 역할: server(slave). PROFINET 디바이스와 같이 PLC가 마스터다.
 *
 * protocol_params 예시 (서버):
 *   { "ip": "0.0.0.0", "port": 502, "unit_id": 1, "role": "server" }
 *
 * protocol_params 예시 (클라이언트 — 원격 슬레이브 폴링):
 *   { "ip": "192.168.0.10", "port": 502, "unit_id": 1, "role": "client" }
 *
 * point.address.modbus — 통신 가이드의 주소를 그대로 기입:
 *   { "register_type": "holding", "start": 40001 }
 * register_type: "holding" | "input" | "coil" | "discrete"
 * start: 가이드 문서 주소(40001 등) 또는 0-based 오프셋 모두 허용.
 *
 * access 의미 (PROFINET과 동일 프레임워크 규칙):
 *   "read"  — PLC가 읽는 값 → 앱이 write_point 로 맵에 넣음
 *   "write" — PLC가 쓰는 값 → 앱이 read_point 로 맵에서 읽음
 */
protocol_adapter_t *modbus_adapter_create(void);

#endif /* MODBUS_ADAPTER_H */
