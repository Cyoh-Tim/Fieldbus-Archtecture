#include "slmp_adapter.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"

/*
 * SLMP(구 MC프로토콜) 3E 프레임 자체 구현 스켈레톤.
 *
 * 구조적으로는 modbus_adapter.c 와 동일한 패턴(protocol_params 파싱,
 * points 배열 파싱, TCP 소켓 연결/해제, read/write)을 따르되, 실제
 * 프레임 인코딩/디코딩(요청 헤더, 서브헤더 0x0050, network_no/pc_no,
 * 디바이스 코드 D/M/X/Y 등)은 이 파일에 TODO로 남겨둔다.
 *
 * 구현 시 참고할 것: PLC/센서 벤더가 제공하는 SLMP 통신 가이드 문서의
 * "3E 프레임 요청/응답 포맷" 절. 디바이스 코드 표는 point.address.slmp
 * .device_code 로 그대로 받아오므로, 코드 수정 없이 config 만으로
 * D/M/X/Y 등 다양한 디바이스를 다룰 수 있어야 한다.
 */

#define MAX_POINTS 128
#define MAX_NAME 64

typedef struct {
    char name[MAX_NAME];
    char device_code[4]; /* "D", "M", "X", "Y" ... */
    int start;
    char access[8];
} slmp_point_t;

typedef struct {
    int sockfd;
    char plc_ip[64];
    int port;
    int network_no;
    int pc_no;

    slmp_point_t points[MAX_POINTS];
    int point_count;

    int connected;
    char last_error[128];
} slmp_ctx_t;

static int slmp_init(protocol_adapter_t *self, const char *protocol_params_json,
                      const char *points_json)
{
    slmp_ctx_t *ctx = calloc(1, sizeof(slmp_ctx_t));
    if (!ctx) return -ENOMEM;
    ctx->port = 5000;
    ctx->network_no = 0;
    ctx->pc_no = 255;
    ctx->sockfd = -1;

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(params, "plc_ip");
        if (cJSON_IsString(ip))
            snprintf(ctx->plc_ip, sizeof(ctx->plc_ip), "%s", ip->valuestring);
        cJSON *port = cJSON_GetObjectItemCaseSensitive(params, "port");
        if (cJSON_IsNumber(port)) ctx->port = port->valueint;
        cJSON *net = cJSON_GetObjectItemCaseSensitive(params, "network_no");
        if (cJSON_IsNumber(net)) ctx->network_no = net->valueint;
        cJSON *pc = cJSON_GetObjectItemCaseSensitive(params, "pc_no");
        if (cJSON_IsNumber(pc)) ctx->pc_no = pc->valueint;
        cJSON_Delete(params);
    }

    if (!ctx->plc_ip[0]) {
        LOG_ERROR("slmp", "protocol_params.plc_ip 누락");
        free(ctx);
        return -EINVAL;
    }

    cJSON *points = cJSON_Parse(points_json);
    if (cJSON_IsArray(points)) {
        cJSON *p;
        cJSON_ArrayForEach(p, points)
        {
            if (ctx->point_count >= MAX_POINTS) break;
            cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
            cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
            cJSON *address = cJSON_GetObjectItemCaseSensitive(p, "address");
            cJSON *slmp_addr =
                address ? cJSON_GetObjectItemCaseSensitive(address, "slmp")
                        : NULL;
            if (!cJSON_IsString(name) || !slmp_addr) {
                LOG_WARN("slmp",
                         "포인트 정의 누락(name/address.slmp) - 건너뜀");
                continue;
            }
            slmp_point_t *pt = &ctx->points[ctx->point_count++];
            snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
            snprintf(pt->access, sizeof(pt->access), "%s",
                     cJSON_IsString(access) ? access->valuestring : "read");
            cJSON *dc =
                cJSON_GetObjectItemCaseSensitive(slmp_addr, "device_code");
            cJSON *start =
                cJSON_GetObjectItemCaseSensitive(slmp_addr, "start");
            snprintf(pt->device_code, sizeof(pt->device_code), "%s",
                     cJSON_IsString(dc) ? dc->valuestring : "D");
            pt->start = cJSON_IsNumber(start) ? start->valueint : 0;
        }
        cJSON_Delete(points);
    }

    LOG_INFO("slmp", "init 완료: %s:%d points=%d", ctx->plc_ip, ctx->port,
              ctx->point_count);
    self->ctx = ctx;
    return 0;
}

static int slmp_connect(protocol_adapter_t *self)
{
    slmp_ctx_t *ctx = self->ctx;
    /* TODO: socket()/connect() 로 ctx->plc_ip:ctx->port 에 TCP 연결.
     * 연결 성공 시 ctx->connected = 1. */
    LOG_WARN("slmp",
             "connect(): TCP 소켓 연결 미구현 (TODO) - 스텁으로 성공 처리");
    ctx->connected = 1;
    return 0;
}

static void slmp_disconnect(protocol_adapter_t *self)
{
    slmp_ctx_t *ctx = self->ctx;
    /* TODO: close(ctx->sockfd) */
    ctx->connected = 0;
}

static void slmp_poll_cycle(protocol_adapter_t *self)
{
    (void)self;
    /* TODO: 등록된 포인트 일괄 읽기(배치 read 요청 구성 시 3E 프레임
     * "일괄 읽기" 커맨드 사용 권장 - 포인트별 개별 요청은 비효율적) */
}

static int slmp_read_point(protocol_adapter_t *self, const char *point_name,
                            point_value_t *out)
{
    (void)self;
    (void)point_name;
    (void)out;
    /* TODO: 3E 프레임 "디바이스 일괄 읽기" 요청 생성 -> 전송 -> 응답 파싱 */
    return -ENOSYS;
}

static int slmp_write_point(protocol_adapter_t *self, const char *point_name,
                             const point_value_t *value)
{
    (void)self;
    (void)point_name;
    (void)value;
    /* TODO: 3E 프레임 "디바이스 일괄 쓰기" 요청 생성 -> 전송 -> 응답 확인 */
    return -ENOSYS;
}

static int slmp_health(protocol_adapter_t *self, int *connected,
                        char *err_buf, size_t err_buf_len)
{
    slmp_ctx_t *ctx = self->ctx;
    *connected = ctx->connected;
    snprintf(err_buf, err_buf_len, "%s", ctx->last_error);
    return 0;
}

static void slmp_destroy(protocol_adapter_t *self)
{
    if (!self) return;
    free(self->ctx);
    free(self);
}

protocol_adapter_t *slmp_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(protocol_adapter_t));
    if (!a) return NULL;
    a->name = "slmp";
    a->init = slmp_init;
    a->connect = slmp_connect;
    a->disconnect = slmp_disconnect;
    a->poll_cycle = slmp_poll_cycle;
    a->read_point = slmp_read_point;
    a->write_point = slmp_write_point;
    a->health = slmp_health;
    a->destroy = slmp_destroy;
    return a;
}
