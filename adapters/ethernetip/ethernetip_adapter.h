#ifndef ETHERNETIP_ADAPTER_H
#define ETHERNETIP_ADAPTER_H

#include "protocol_adapter.h"

/*
 * 구매한 EtherNet/IP 스택을 이 인터페이스 뒤로 감싸는 어댑터.
 * 벤더 SDK 헤더/라이브러리는 third_party/ethernetip_stack/ 에 배치하고,
 * CMakeLists.txt 의 ETHERNETIP_STACK_DIR 옵션으로 경로를 지정한다.
 *
 * point.address.ethernetip 예시: { "tag": "Sensor1.Barcode" }
 * (스택이 태그 기반 심볼릭 액세스를 지원하는 경우. 스택이 어셈블리
 *  인스턴스/커넥션 포인트 기반이면 protocol_params.assembly_instance 등을
 *  참고해 이 파일에서 매핑을 구현할 것 - 벤더 SDK 매뉴얼 확인 필요)
 */
protocol_adapter_t *ethernetip_adapter_create(void);

#endif /* ETHERNETIP_ADAPTER_H */
