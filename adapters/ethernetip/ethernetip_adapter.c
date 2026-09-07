#include "ethernetip_adapter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"

/*
 * TODO(벤더 스택 연동): third_party/ethernetip_stack/ 에 배치된 구매 스택의
 * 헤더를 include 하고, 아래 함수들 안에서 해당 스택의 초기화/폴링/
 * read-write API 를 호출하도록 구현한다.
 *
 * 이 파일의 역할은 "번역기"다: ProtocolAdapter 인터페이스(코어가 아는 것)
 * 와 벤더 스택 API(이 어댑터만 아는 것) 사이를 연결한다. 코어와 config.json
 * 스키마는 스택 종류가 바뀌어도 변하지 않아야 한다.
 */

typedef struct {
    char ip[64];
    int assembly_instance;
    int connected;
    char last_error[128];
    /* TODO: 벤더 스택 핸들/컨텍스트 포인터 추가 */
} eip_ctx_t;

static int eip_init(protocol_adapter_t *self, const char *protocol_params_json,
                     const char *points_json)
{
    (void)points_json; /* TODO: 스택이 태그/어셈블리 매핑을 요구하면 여기서 파싱 */
    eip_ctx_t *ctx = calloc(1, sizeof(eip_ctx_t));
    if (!ctx) return -ENOMEM;

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(params, "ip");
        if (cJSON_IsString(ip))
            snprintf(ctx->ip, sizeof(ctx->ip), "%s", ip->valuestring);
        cJSON *ai =
            cJSON_GetObjectItemCaseSensitive(params, "assembly_instance");
        if (cJSON_IsNumber(ai)) ctx->assembly_instance = ai->valueint;
        cJSON_Delete(params);
    }

    LOG_WARN("ethernetip",
             "init(): 벤더 스택 초기화 미구현 (TODO) - ip=%s instance=%d",
             ctx->ip, ctx->assembly_instance);
    self->ctx = ctx;
    return 0;
}

static int eip_connect(protocol_adapter_t *self)
{
    eip_ctx_t *ctx = self->ctx;
    /* TODO: 벤더 스택 connect/open 호출 */
    LOG_WARN("ethernetip", "connect(): 스텁 - 실제 연결 없음");
    ctx->connected = 1;
    return 0;
}

static void eip_disconnect(protocol_adapter_t *self)
{
    eip_ctx_t *ctx = self->ctx;
    /* TODO: 벤더 스택 close 호출 */
    ctx->connected = 0;
}

static void eip_poll_cycle(protocol_adapter_t *self)
{
    (void)self;
    /* TODO: 벤더 스택이 콜백 기반이면 여기서 스택의 폴링/이벤트 처리 함수를
     * 호출해 코어의 주기 호출 모델에 맞춰준다 (예: EIP_Poll(handle)). */
}

static int eip_read_point(protocol_adapter_t *self, const char *point_name,
                           point_value_t *out)
{
    (void)self; (void)point_name; (void)out;
    return -ENOSYS; /* TODO */
}

static int eip_write_point(protocol_adapter_t *self, const char *point_name,
                            const point_value_t *value)
{
    (void)self; (void)point_name; (void)value;
    return -ENOSYS; /* TODO */
}

static int eip_health(protocol_adapter_t *self, int *connected, char *err_buf,
                       size_t err_buf_len)
{
    eip_ctx_t *ctx = self->ctx;
    *connected = ctx->connected;
    snprintf(err_buf, err_buf_len, "%s", ctx->last_error);
    return 0;
}

static void eip_destroy(protocol_adapter_t *self)
{
    if (!self) return;
    free(self->ctx);
    free(self);
}

protocol_adapter_t *ethernetip_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(protocol_adapter_t));
    if (!a) return NULL;
    a->name = "ethernetip";
    a->init = eip_init;
    a->connect = eip_connect;
    a->disconnect = eip_disconnect;
    a->poll_cycle = eip_poll_cycle;
    a->read_point = eip_read_point;
    a->write_point = eip_write_point;
    a->health = eip_health;
    a->destroy = eip_destroy;
    return a;
}
