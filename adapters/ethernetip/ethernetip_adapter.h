#ifndef ETHERNETIP_ADAPTER_H
#define ETHERNETIP_ADAPTER_H

#include "protocol_adapter.h"

/*
 * EtherNet/IP 어댑터 — 자체 스택(stacks/ethernetip/) 연결.
 *
 * 센서 기본 역할: Adapter(target/server). PLC 스캐너가 Class 1 로
 * assembly 를 교환하고, UCMM 으로 Identity/Assembly 속성을 읽는다.
 * role=client 이면 Originator 로 원격 태그/속성 explicit R/W.
 *
 * point.address.ethernetip 예시:
 *   { "assembly": 150, "byte_offset": 0, "length": 32 }
 *   { "tag": "Sensor1.Barcode" }
 *   { "class_id": 4, "instance": 150, "attribute": 3 }
 */
protocol_adapter_t *ethernetip_adapter_create(void);

#endif /* ETHERNETIP_ADAPTER_H */
