#ifndef PROTOCOL_ADAPTER_H
#define PROTOCOL_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

/*
 * 모든 프로토콜 어댑터(Modbus/SLMP/CC-Link/EtherNet-IP/PROFINET/...)가
 * 구현해야 하는 공통 인터페이스.
 *
 * 코어(core/)는 이 구조체의 함수 포인터만 호출하며, 각 프로토콜의
 * 세부 사항(레지스터 주소 체계, 프레임 포맷, 벤더 SDK API 등)은
 * 전혀 알지 못한다. 새 프로토콜을 추가할 때는
 *  1) adapters/<name>/ 에 이 인터페이스를 구현하고
 *  2) core/adapter_registry.c 에 생성자 함수 1줄만 등록
 * 하면 된다. 코어 코드는 수정하지 않는다.
 */

typedef struct point_value {
    uint8_t *data; /* raw byte 버퍼 (호출자 소유) */
    size_t len;
} point_value_t;

typedef struct protocol_adapter protocol_adapter_t;

struct protocol_adapter {
    const char *name; /* 예: "modbus_tcp", "slmp" */
    void *ctx;         /* 어댑터별 내부 상태 (구현체가 malloc) */

    /* protocol_params_json / points_json 은 config.json 의 해당 서브객체를
     * cJSON_PrintUnformatted 한 문자열이다. 코어는 내용을 해석하지 않고
     * 그대로 넘긴다. 성공 시 0, 실패 시 음수 errno 스타일 값을 반환. */
    int (*init)(protocol_adapter_t *self,
                const char *protocol_params_json,
                const char *points_json);

    int (*connect)(protocol_adapter_t *self);
    void (*disconnect)(protocol_adapter_t *self);

    /* 스케줄러가 cycle_ms 주기로 호출. 어댑터 내부에서 폴링/송수신 수행 */
    void (*poll_cycle)(protocol_adapter_t *self);

    int (*read_point)(protocol_adapter_t *self, const char *point_name,
                       point_value_t *out);
    int (*write_point)(protocol_adapter_t *self, const char *point_name,
                        const point_value_t *value);

    /* connected: 1/0, err_buf 에 마지막 에러 메시지(없으면 빈 문자열) */
    int (*health)(protocol_adapter_t *self, int *connected, char *err_buf,
                  size_t err_buf_len);

    void (*destroy)(protocol_adapter_t *self);
};

#endif /* PROTOCOL_ADAPTER_H */
